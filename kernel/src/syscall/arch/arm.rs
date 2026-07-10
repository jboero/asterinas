// SPDX-License-Identifier: MPL-2.0

//! System call dispatch in the ARM (ARMv7-A) architecture.
//!
//! ARM (32-bit) is not an `asm-generic`-numbering architecture: stock ARM
//! binaries (musl, glibc) issue the legacy `arch/arm` system-call numbers via
//! `svc #0` with the number in `r7`. Rather than duplicate the whole table, we
//! keep using the shared `asm-generic` handler table and bridge to it in
//! [`translate_arm_syscall`], which maps each ARM number to the corresponding
//! generic number (adjusting arguments where the ABI differs, e.g. `mmap2` and
//! `clone`). ARM-legacy-only syscalls with no generic number (e.g. `poll`) are
//! given synthetic numbers and dispatched by extra entries in the table below.
//! The ARM-private `__ARM_NR_*` range (e.g. `set_tls`) is handled in
//! [`handle_arm_private_syscall`].

#[path = "./generic.rs"]
mod generic;

use super::poll::sys_poll;

generic::define_syscalls_with_generic_syscall_table! {
    // ARM-legacy syscalls that have an Asterinas handler but no asm-generic
    // number (or whose ARM number collides with a different asm-generic
    // syscall). `translate_arm_syscall` maps the ARM number to these synthetic
    // numbers (0xA0_00xx), which are far above the real asm-generic range.
    SYS_ARM_POLL = 0xA0_0168 => sys_poll(args[..3]);
}

use ostd::arch::cpu::context::UserContext;

/// Handles the ARM-private system-call range (`__ARM_NR_BASE = 0x0f_0000`).
///
/// These numbers are issued via `svc #0` with the number in `r7`, exactly like
/// ordinary syscalls, but they fall outside the unified table. `set_tls` is the
/// critical one: libc calls it during thread setup, and without it the userspace
/// thread pointer is never established (every TLS access then faults near null).
///
/// Returns `Some(ret)` if the number was in the private range (and thus handled),
/// or `None` to let the normal syscall table handle it.
pub(in crate::syscall) fn handle_arm_private_syscall(
    number: u64,
    args: [u64; 6],
    user_ctx: &mut UserContext,
) -> Option<isize> {
    const ARM_NR_BASE: u64 = 0x0f_0000;
    const ARM_NR_CACHEFLUSH: u64 = ARM_NR_BASE + 2;
    const ARM_NR_SET_TLS: u64 = ARM_NR_BASE + 5;
    const ARM_NR_GET_TLS: u64 = ARM_NR_BASE + 6;

    match number {
        ARM_NR_SET_TLS => {
            // Records the thread pointer; `run_user` loads it into TPIDRURW and
            // TPIDRURO on the next entry to userspace.
            user_ctx.set_tls_pointer(args[0] as usize);
            Some(0)
        }
        ARM_NR_GET_TLS => Some(user_ctx.tls_pointer() as isize),
        // Under emulation the I- and D-caches are coherent, so an explicit
        // flush is a no-op. (A real SoC would clean/invalidate [args[0], args[1]).)
        ARM_NR_CACHEFLUSH => Some(0),
        _ => None,
    }
}

/// Translates an ARM EABI (legacy) syscall number + args into the unified
/// asm-generic number the shared syscall table uses. ARM (32-bit) is not an
/// asm-generic-numbering architecture, so stock musl/glibc binaries issue the
/// legacy `arch/arm` numbers; this bridges them to the shared handlers.
///
/// A few syscalls differ in ABI, not just number, and are transformed here
/// (e.g. `mmap2`'s offset is in pages). Unknown numbers pass through unchanged.
pub(in crate::syscall) fn translate_arm_syscall(number: u64, mut args: [u64; 6]) -> (u64, [u64; 6]) {
    // Special-ABI cases first.
    if number == 192 {
        // mmap2(addr, len, prot, flags, fd, pgoffset): offset is in 4 KiB pages.
        args[5] = args[5].wrapping_mul(4096);
        return (222, args); // -> mmap
    }
    // ARM `poll` (168) collides with asm-generic `getcpu` (168); route it to the
    // synthetic `sys_poll` entry instead of letting it fall through.
    if number == 168 {
        return (0xA0_0168, args);
    }
    if number == 120 {
        // ARM `clone` uses the CLONE_BACKWARDS layout
        // (flags, stack, ptid, tls, ctid), whereas the shared handler expects
        // (flags, stack, ptid, ctid, tls). Swap the last two.
        args.swap(3, 4);
        return (220, args); // -> clone
    }
    let generic = match number {
        1 => Some(93), // exit
        3 => Some(63), // read
        4 => Some(64), // write
        6 => Some(57), // close
        19 => Some(62), // lseek
        20 => Some(172), // getpid
        24 => Some(174), // getuid
        37 => Some(129), // kill
        41 => Some(23), // dup
        45 => Some(214), // brk
        54 => Some(29), // ioctl
        55 => Some(25), // fcntl
        64 => Some(173), // getppid
        78 => Some(169), // gettimeofday
        91 => Some(215), // munmap
        125 => Some(226), // mprotect
        136 => Some(92), // personality
        141 => Some(61), // getdents->getdents64
        145 => Some(65), // readv
        146 => Some(66), // writev
        158 => Some(124), // sched_yield
        162 => Some(101), // nanosleep
        163 => Some(216), // mremap
        173 => Some(139), // rt_sigreturn (issued by the vDSO trampoline)
        174 => Some(134), // rt_sigaction
        175 => Some(135), // rt_sigprocmask
        176 => Some(136), // rt_sigpending
        177 => Some(137), // rt_sigtimedwait
        179 => Some(133), // rt_sigsuspend
        180 => Some(67), // pread64
        181 => Some(68), // pwrite64
        183 => Some(17), // getcwd
        185 => Some(90), // capget
        186 => Some(91), // capset
        191 => Some(163), // ugetrlimit->getrlimit
        199 => Some(174), // getuid32->getuid
        200 => Some(176), // getgid32->getgid
        201 => Some(175), // geteuid32->geteuid
        202 => Some(177), // getegid32->getegid
        205 => Some(158), // getgroups32->getgroups
        209 => Some(148), // getresuid32->getresuid
        211 => Some(150), // getresgid32->getresgid
        217 => Some(61), // getdents64
        220 => Some(233), // madvise
        221 => Some(25), // fcntl64->fcntl
        224 => Some(178), // gettid
        226 => Some(5), // setxattr
        229 => Some(8), // getxattr
        232 => Some(11), // listxattr
        235 => Some(14), // removexattr
        238 => Some(130), // tkill
        240 => Some(98), // futex
        241 => Some(122), // sched_setaffinity
        242 => Some(123), // sched_getaffinity
        248 => Some(94), // exit_group
        251 => Some(21), // epoll_ctl
        256 => Some(96), // set_tid_address
        263 => Some(113), // clock_gettime
        265 => Some(115), // clock_nanosleep
        268 => Some(131), // tgkill
        322 => Some(56), // openat
        323 => Some(34), // mkdirat
        328 => Some(35), // unlinkat
        332 => Some(78), // readlinkat
        333 => Some(53), // fchmodat
        334 => Some(48), // faccessat
        335 => Some(72), // pselect6
        336 => Some(73), // ppoll
        338 => Some(99), // set_robust_list
        345 => Some(168), // getcpu
        346 => Some(22), // epoll_pwait
        356 => Some(19), // eventfd2
        357 => Some(20), // epoll_create1
        358 => Some(24), // dup3
        359 => Some(59), // pipe2
        369 => Some(261), // prlimit64
        384 => Some(278), // getrandom
        385 => Some(279), // memfd_create
        392 => Some(286), // preadv2
        393 => Some(287), // pwritev2
        397 => Some(291), // statx
        403 => Some(113), // clock_gettime64->clock_gettime
        407 => Some(115), // clock_nanosleep_time64->clock_nanosleep
        414 => Some(73), // ppoll_time64->ppoll
        422 => Some(98), // futex_time64->futex
        439 => Some(439), // faccessat2
        _ => None,
    };
    (generic.unwrap_or(number), args)
}
