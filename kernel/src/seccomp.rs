// SPDX-License-Identifier: MPL-2.0

//! Real `seccomp(2)` BPF filtering.
//!
//! This implements classic-BPF (cBPF) seccomp filters: the small bytecode
//! programs that OCI runtimes (runc) and Kubernetes install to restrict the
//! syscall surface of a container. A program is run over a [`SeccompData`]
//! record describing the attempted syscall and returns an action (allow, fail
//! with an errno, kill the thread/process, or raise `SIGSYS`).
//!
//! Design notes / compatibility:
//! * A thread with **no** installed filter is unaffected — the syscall hot path
//!   checks one relaxed atomic and returns immediately, so existing workloads
//!   (including the zero-C node image, where nothing installs a filter) see no
//!   behavior change.
//! * Filters are immutable once installed and are shared (`Arc`) across the
//!   threads of a process; they are inherited across `clone`/`fork` and
//!   preserved across `execve`, matching Linux semantics.
//! * `runc` applies its filter post-`fork`, pre-`execve` (single-threaded), so
//!   the common `SECCOMP_FILTER_FLAG_TSYNC` case reduces to "the current
//!   thread"; the flag is accepted.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use ostd::sync::SpinLock;

// --- seccomp modes (prctl/seccomp `operation`) ---
pub const SECCOMP_MODE_DISABLED: u32 = 0;
pub const SECCOMP_MODE_STRICT: u32 = 1;
pub const SECCOMP_MODE_FILTER: u32 = 2;

// --- seccomp(2) operations ---
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;

// --- filter return actions (high 16 bits select the action) ---
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Kept for ABI completeness; LOG is treated as ALLOW (with no audit log yet).
#[allow(dead_code)]
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

/// `AUDIT_ARCH_X86_64` — reported in [`SeccompData::arch`] so filters can gate
/// on the calling convention, as libseccomp's programs do.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// The maximum number of cBPF instructions in a single filter (`BPF_MAXINSNS`).
const BPF_MAXINSNS: usize = 4096;

/// The input record a seccomp filter inspects, mirroring `struct seccomp_data`.
/// It is laid out as 64 native-endian bytes (the layout cBPF `BPF_ABS` loads
/// expect): `nr` @0, `arch` @4, `instruction_pointer` @8, `args[0..6]` @16..64.
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

impl SeccompData {
    fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&(self.nr as u32).to_ne_bytes());
        b[4..8].copy_from_slice(&self.arch.to_ne_bytes());
        b[8..16].copy_from_slice(&self.instruction_pointer.to_ne_bytes());
        for i in 0..6 {
            let off = 16 + i * 8;
            b[off..off + 8].copy_from_slice(&self.args[i].to_ne_bytes());
        }
        b
    }
}

/// One classic-BPF instruction (`struct sock_filter`): 8 bytes, no padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// An installed, immutable seccomp filter program.
pub struct SeccompFilter {
    insns: Vec<SockFilter>,
}

impl SeccompFilter {
    /// Builds a filter from the instructions copied out of userspace, rejecting
    /// obviously-malformed programs (empty or over `BPF_MAXINSNS`).
    pub fn new(insns: Vec<SockFilter>) -> Result<Self, &'static str> {
        if insns.is_empty() {
            return Err("empty seccomp filter");
        }
        if insns.len() > BPF_MAXINSNS {
            return Err("seccomp filter too long");
        }
        Ok(Self { insns })
    }

    /// Runs the cBPF program over `data`, returning the raw 32-bit action value.
    ///
    /// Only the instruction subset seccomp filters actually use is implemented
    /// (loads from `seccomp_data` via `BPF_ABS`, immediate ALU, conditional
    /// jumps, scratch memory, and returns). Unknown opcodes or out-of-range
    /// accesses fall through to `SECCOMP_RET_KILL_THREAD`, the safe default.
    fn run(&self, data: &SeccompData) -> u32 {
        // BPF instruction-class and field bits.
        const BPF_LD: u16 = 0x00;
        const BPF_LDX: u16 = 0x01;
        const BPF_ALU: u16 = 0x04;
        const BPF_JMP: u16 = 0x05;
        const BPF_RET: u16 = 0x06;
        const BPF_MISC: u16 = 0x07;

        const BPF_ABS: u16 = 0x20;
        const BPF_IMM: u16 = 0x00;
        const BPF_MEM: u16 = 0x60;
        const BPF_LEN: u16 = 0x80;

        const BPF_X: u16 = 0x08;
        const BPF_A: u16 = 0x10;

        const BPF_JA: u16 = 0x00;
        const BPF_JEQ: u16 = 0x10;
        const BPF_JGT: u16 = 0x20;
        const BPF_JGE: u16 = 0x30;
        const BPF_JSET: u16 = 0x40;

        const BPF_ADD: u16 = 0x00;
        const BPF_SUB: u16 = 0x10;
        const BPF_MUL: u16 = 0x20;
        const BPF_DIV: u16 = 0x30;
        const BPF_OR: u16 = 0x40;
        const BPF_AND: u16 = 0x50;
        const BPF_LSH: u16 = 0x60;
        const BPF_RSH: u16 = 0x70;
        const BPF_XOR: u16 = 0xa0;

        const BPF_TAX: u16 = 0x00;
        const BPF_TXA: u16 = 0x80;

        let bytes = data.to_bytes();
        let load_abs = |k: u32| -> Option<u32> {
            let k = k as usize;
            if k.checked_add(4)? > bytes.len() {
                return None;
            }
            Some(u32::from_ne_bytes([bytes[k], bytes[k + 1], bytes[k + 2], bytes[k + 3]]))
        };

        const BPF_ST: u16 = 0x02;
        const BPF_STX: u16 = 0x03;

        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut mem = [0u32; 16];
        let mut pc: usize = 0;
        // cBPF jumps are forward-only, so the program always terminates; cap the
        // step count at the program length anyway as a belt-and-braces guard.
        let mut steps = 0usize;

        while pc < self.insns.len() {
            steps += 1;
            if steps > self.insns.len() {
                return SECCOMP_RET_KILL_THREAD;
            }
            let insn = self.insns[pc];
            let class = insn.code & 0x07;
            let k = insn.k;
            match class {
                BPF_LD => {
                    let mode = insn.code & 0xe0;
                    match mode {
                        BPF_ABS => match load_abs(k) {
                            Some(v) => a = v,
                            None => return SECCOMP_RET_KILL_THREAD,
                        },
                        BPF_IMM => a = k,
                        BPF_MEM => {
                            if (k as usize) >= mem.len() {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            a = mem[k as usize];
                        }
                        BPF_LEN => a = 64,
                        _ => return SECCOMP_RET_KILL_THREAD,
                    }
                }
                BPF_LDX => {
                    let mode = insn.code & 0xe0;
                    match mode {
                        BPF_IMM => x = k,
                        BPF_MEM => {
                            if (k as usize) >= mem.len() {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            x = mem[k as usize];
                        }
                        BPF_LEN => x = 64,
                        _ => return SECCOMP_RET_KILL_THREAD,
                    }
                }
                BPF_ALU => {
                    let op = insn.code & 0xf0;
                    let src = if (insn.code & BPF_X) != 0 { x } else { k };
                    a = match op {
                        BPF_ADD => a.wrapping_add(src),
                        BPF_SUB => a.wrapping_sub(src),
                        BPF_MUL => a.wrapping_mul(src),
                        BPF_DIV => {
                            if src == 0 {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            a / src
                        }
                        BPF_OR => a | src,
                        BPF_AND => a & src,
                        BPF_LSH => a.wrapping_shl(src),
                        BPF_RSH => a.wrapping_shr(src),
                        BPF_XOR => a ^ src,
                        // BPF_NEG (0x80) has no src.
                        0x80 => (!a).wrapping_add(1),
                        _ => return SECCOMP_RET_KILL_THREAD,
                    };
                }
                BPF_JMP => {
                    let op = insn.code & 0xf0;
                    if op == BPF_JA {
                        pc = pc.wrapping_add(1).wrapping_add(k as usize);
                        continue;
                    }
                    let cmp = if (insn.code & BPF_X) != 0 { x } else { k };
                    let taken = match op {
                        BPF_JEQ => a == cmp,
                        BPF_JGT => a > cmp,
                        BPF_JGE => a >= cmp,
                        BPF_JSET => (a & cmp) != 0,
                        _ => return SECCOMP_RET_KILL_THREAD,
                    };
                    let off = if taken { insn.jt as usize } else { insn.jf as usize };
                    pc = pc + 1 + off;
                    continue;
                }
                BPF_ST => {
                    if (k as usize) >= mem.len() {
                        return SECCOMP_RET_KILL_THREAD;
                    }
                    mem[k as usize] = a;
                }
                BPF_STX => {
                    if (k as usize) >= mem.len() {
                        return SECCOMP_RET_KILL_THREAD;
                    }
                    mem[k as usize] = x;
                }
                BPF_RET => {
                    let src = insn.code & 0x18;
                    return if src == BPF_A { a } else { k };
                }
                BPF_MISC => {
                    let op = insn.code & 0xf8;
                    match op {
                        BPF_TAX => x = a,
                        BPF_TXA => a = x,
                        _ => return SECCOMP_RET_KILL_THREAD,
                    }
                }
                _ => return SECCOMP_RET_KILL_THREAD,
            }
            pc += 1;
        }
        // Fell off the end without a RET — malformed; deny.
        SECCOMP_RET_KILL_THREAD
    }
}

/// The action the syscall entry path must take for an attempted syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompAction {
    /// Proceed with the syscall.
    Allow,
    /// Skip the syscall and return `-errno`.
    Errno(u16),
    /// Raise `SIGSYS` on the calling thread.
    Trap(u16),
    /// Terminate the calling thread (`SIGKILL`).
    KillThread,
    /// Terminate the whole process (`SIGKILL`).
    KillProcess,
}

/// Severity ordering used when multiple filters return different actions: the
/// most severe action wins, matching Linux precedence.
fn action_severity(ret_action: u32) -> u8 {
    match ret_action {
        SECCOMP_RET_KILL_PROCESS => 6,
        SECCOMP_RET_KILL_THREAD => 5,
        SECCOMP_RET_TRAP => 4,
        SECCOMP_RET_ERRNO => 3,
        SECCOMP_RET_USER_NOTIF => 2,
        SECCOMP_RET_TRACE => 1,
        // LOG and ALLOW both permit the syscall.
        _ => 0,
    }
}

/// Per-thread seccomp state: the installed mode plus the (shared, immutable)
/// filter chain. Lives in `PosixThread`.
pub struct SeccompState {
    /// One of `SECCOMP_MODE_*`. Read on every syscall via a relaxed load, so the
    /// no-filter fast path costs a single atomic read.
    mode: AtomicU32,
    /// Installed filters, newest last. Guarded by a spinlock; the lock is held
    /// only to clone the `Arc` list, never while running the interpreter.
    filters: SpinLock<Vec<Arc<SeccompFilter>>>,
}

impl SeccompState {
    pub fn new() -> Self {
        Self {
            mode: AtomicU32::new(SECCOMP_MODE_DISABLED),
            filters: SpinLock::new(Vec::new()),
        }
    }

    /// Whether any seccomp policy is active on this thread (the fast-path check).
    pub fn is_active(&self) -> bool {
        self.mode.load(Ordering::Relaxed) != SECCOMP_MODE_DISABLED
    }

    pub fn mode(&self) -> u32 {
        self.mode.load(Ordering::Relaxed)
    }

    /// Installs a new filter (FILTER mode). Idempotently moves the thread into
    /// FILTER mode.
    pub fn add_filter(&self, filter: Arc<SeccompFilter>) {
        self.filters.lock().push(filter);
        self.mode.store(SECCOMP_MODE_FILTER, Ordering::Relaxed);
    }

    /// Enters STRICT mode (only read/write/exit/rt_sigreturn allowed).
    pub fn set_strict(&self) {
        self.mode.store(SECCOMP_MODE_STRICT, Ordering::Relaxed);
    }

    /// Copies another thread's seccomp policy into this one. Used on
    /// `clone`/`fork` so children inherit the parent's filters (the `Arc`s are
    /// shared, not deep-copied).
    pub fn inherit_from(&self, other: &SeccompState) {
        let mode = other.mode.load(Ordering::Relaxed);
        if mode == SECCOMP_MODE_DISABLED {
            return;
        }
        let parent = other.filters.lock().clone();
        *self.filters.lock() = parent;
        self.mode.store(mode, Ordering::Relaxed);
    }

    /// Evaluates the installed policy for an attempted syscall.
    pub fn evaluate(&self, nr: i32, args: [u64; 6], ip: u64) -> SeccompAction {
        match self.mode.load(Ordering::Relaxed) {
            SECCOMP_MODE_DISABLED => SeccompAction::Allow,
            SECCOMP_MODE_STRICT => evaluate_strict(nr),
            _ => self.evaluate_filters(nr, args, ip),
        }
    }

    fn evaluate_filters(&self, nr: i32, args: [u64; 6], ip: u64) -> SeccompAction {
        let data = SeccompData {
            nr,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: ip,
            args,
        };
        let filters = self.filters.lock().clone();
        // Run every filter; the most severe action wins.
        let mut best: u32 = SECCOMP_RET_ALLOW;
        let mut best_sev: u8 = 0;
        for f in filters.iter() {
            let ret = f.run(&data);
            let sev = action_severity(ret & SECCOMP_RET_ACTION_FULL);
            if sev >= best_sev {
                best_sev = sev;
                best = ret;
            }
        }
        ret_to_action(best)
    }
}

impl Default for SeccompState {
    fn default() -> Self {
        Self::new()
    }
}

fn ret_to_action(ret: u32) -> SeccompAction {
    let data = (ret & SECCOMP_RET_DATA) as u16;
    match ret & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_KILL_PROCESS => SeccompAction::KillProcess,
        SECCOMP_RET_KILL_THREAD => SeccompAction::KillThread,
        SECCOMP_RET_TRAP => SeccompAction::Trap(data),
        SECCOMP_RET_ERRNO => SeccompAction::Errno(data),
        // TRACE with no tracer behaves as ENOSYS in Linux; approximate as allow
        // since astrokube has no ptrace-based supervisor here.
        SECCOMP_RET_TRACE => SeccompAction::Allow,
        // USER_NOTIF without a listener would block forever; treat as allow.
        SECCOMP_RET_USER_NOTIF => SeccompAction::Allow,
        // LOG and ALLOW both permit.
        _ => SeccompAction::Allow,
    }
}

/// STRICT mode policy: only the four syscalls Linux permits.
fn evaluate_strict(nr: i32) -> SeccompAction {
    // x86_64: read=0, write=1, exit=60, rt_sigreturn=15, exit_group=231.
    match nr {
        0 | 1 | 15 | 60 | 231 => SeccompAction::Allow,
        _ => SeccompAction::KillThread,
    }
}
