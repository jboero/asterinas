// SPDX-License-Identifier: MPL-2.0

//! CPU execution context control (ARMv7-A).

use core::fmt::Debug;

use ostd_pod::IntoBytes;

use crate::{
    arch::{
        irq::handle_irq,
        trap::{
            RawUserContext, TRAP_KIND_DATA_ABORT, TRAP_KIND_IRQ, TRAP_KIND_PREFETCH_ABORT,
            TRAP_KIND_SYSCALL, TRAP_KIND_UNDEF, TrapFrame,
        },
    },
    cpu::PrivilegeLevel,
    user::{ReturnReason, UserContextApi, UserContextApiInternal},
};

/// General-purpose registers `r0`-`r15`.
///
/// By the ARM procedure call standard, `r13` is the stack pointer (`sp`), `r14`
/// the link register (`lr`) and `r15` the program counter (`pc`). For a user
/// context these are the banked USR-mode values.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneralRegs {
    /// `r0`-`r15`.
    pub r: [usize; 16],
}

/// Userspace CPU context, including general-purpose registers and exception
/// information.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct UserContext {
    user_context: RawUserContext,
    exception: Option<CpuException>,
}

impl Default for UserContext {
    fn default() -> Self {
        let mut user_context = RawUserContext::default();
        // A fresh user thread must start in USR mode (`CPSR.M = 0b10000`),
        // otherwise `run_user`'s `movs pc, lr` would drop into the zero mode
        // and execute user code at PL1, where the user pages' PXN bit forbids
        // instruction fetch (an endless prefetch abort). ARM state (T=0), with
        // IRQs and FIQs unmasked so the thread can be preempted.
        user_context.cpsr = 0x0000_0010;
        Self {
            user_context,
            exception: None,
        }
    }
}

/// ARMv7-A CPU exceptions.
#[derive(Clone, Copy, Debug)]
pub enum CpuException {
    /// Supervisor call (`SVC`/`SWI`), i.e. a system call.
    Syscall,
    /// Prefetch abort (translation/permission fault while fetching).
    InstructionAbort(FaultInfo),
    /// Data abort (translation/permission fault while accessing data).
    DataAbort(FaultInfo),
    /// Undefined instruction.
    UndefinedInstruction,
    /// Any other exception.
    Unknown,
}

/// Fault information decoded from the fault status/address registers
/// (`DFSR`/`DFAR` for data aborts, `IFSR`/`IFAR` for prefetch aborts).
#[derive(Clone, Copy, Debug)]
pub struct FaultInfo {
    /// The faulting virtual address (`DFAR`/`IFAR`).
    pub far: usize,
    /// The raw fault status register (`DFSR`/`IFSR`).
    pub fsr: usize,
}

impl FaultInfo {
    /// Whether the fault was caused by a write access (data aborts only).
    pub fn is_write(&self) -> bool {
        // DFSR.WnR is bit 11.
        (self.fsr & (1 << 11)) != 0
    }

    /// Whether the fault is a translation, access-flag or permission fault (as
    /// opposed to an external abort, alignment fault, etc.).
    pub fn is_page_fault(&self) -> bool {
        // With LPAE (`TTBCR.EAE = 1`) the fault status is the 6-bit long-format
        // status in bits [5:0]: translation (0b0001xx), access flag (0b0010xx)
        // and permission (0b0011xx) faults are the page-fault classes.
        let status = self.fsr & 0b11_1111;
        matches!(status >> 2, 0b0001 | 0b0010 | 0b0011)
    }
}

impl CpuException {
    /// Returns the faulting address if this exception carries one.
    pub fn page_fault_addr(&self) -> Option<usize> {
        match self {
            Self::InstructionAbort(info) | Self::DataAbort(info) if info.is_page_fault() => {
                Some(info.far)
            }
            _ => None,
        }
    }
}

impl UserContext {
    /// Returns a reference to the general registers.
    pub fn general_regs(&self) -> &GeneralRegs {
        &self.user_context.general
    }

    /// Returns a mutable reference to the general registers.
    pub fn general_regs_mut(&mut self) -> &mut GeneralRegs {
        &mut self.user_context.general
    }

    /// Takes the CPU exception out.
    pub fn take_exception(&mut self) -> Option<CpuException> {
        self.exception.take()
    }

    /// Sets the thread-local storage pointer (`TPIDRURW`).
    pub fn set_tls_pointer(&mut self, tls: usize) {
        self.user_context.tls = tls;
    }

    /// Gets the thread-local storage pointer (`TPIDRURW`).
    pub fn tls_pointer(&self) -> usize {
        self.user_context.tls
    }

    /// Gets the value of register `r[i]`.
    pub fn r(&self, i: usize) -> usize {
        self.user_context.general.r[i]
    }

    /// Sets the value of register `r[i]`.
    pub fn set_r(&mut self, i: usize, val: usize) {
        self.user_context.general.r[i] = val;
    }

    /// Gets the current program status register (`CPSR`).
    pub fn cpsr(&self) -> usize {
        self.user_context.cpsr
    }

    /// Sets the current program status register (`CPSR`).
    pub fn set_cpsr(&mut self, cpsr: usize) {
        self.user_context.cpsr = cpsr;
    }
}

impl UserContextApiInternal for UserContext {
    fn execute<F>(&mut self, mut has_kernel_event: F) -> ReturnReason
    where
        F: FnMut() -> bool,
    {
        loop {
            crate::task::scheduler::might_preempt();
            self.user_context.run();

            if self.user_context.trap_kind == TRAP_KIND_IRQ {
                // An interrupt was taken while in userspace. Dispatch it and
                // re-enter userspace unless a kernel event is pending.
                handle_irq(&self.as_trap_frame(), PrivilegeLevel::User);
                crate::arch::irq::enable_local();

                if has_kernel_event() {
                    break ReturnReason::KernelEvent;
                }
                continue;
            }

            let info = FaultInfo {
                far: self.user_context.far,
                fsr: self.user_context.fsr,
            };

            crate::arch::irq::enable_local();

            match self.user_context.trap_kind {
                TRAP_KIND_SYSCALL => {
                    break ReturnReason::UserSyscall;
                }
                TRAP_KIND_DATA_ABORT => {
                    self.exception = Some(CpuException::DataAbort(info));
                    break ReturnReason::UserException;
                }
                TRAP_KIND_PREFETCH_ABORT => {
                    self.exception = Some(CpuException::InstructionAbort(info));
                    break ReturnReason::UserException;
                }
                TRAP_KIND_UNDEF => {
                    self.exception = Some(CpuException::UndefinedInstruction);
                    break ReturnReason::UserException;
                }
                _ => {
                    self.exception = Some(CpuException::Unknown);
                    break ReturnReason::UserException;
                }
            }
        }
    }

    fn as_trap_frame(&self) -> TrapFrame {
        TrapFrame {
            general: self.user_context.general,
            cpsr: self.user_context.cpsr,
            fsr: self.user_context.fsr,
            far: self.user_context.far,
        }
    }
}

impl UserContextApi for UserContext {
    fn trap_number(&self) -> usize {
        self.user_context.trap_kind
    }

    fn trap_error_code(&self) -> usize {
        self.user_context.fsr
    }

    fn instruction_pointer(&self) -> usize {
        // r15 = pc.
        self.user_context.general.r[15]
    }

    fn set_instruction_pointer(&mut self, ip: usize) {
        self.user_context.general.r[15] = ip;
    }

    fn stack_pointer(&self) -> usize {
        // r13 = sp.
        self.user_context.general.r[13]
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.user_context.general.r[13] = sp;
    }
}

/// The FPU context of a user task (VFP/Advanced SIMD state).
///
/// Holds the 32 double-precision VFP/NEON registers `d0`-`d31` (i.e. `q0`-`q15`)
/// and the `FPSCR` status/control register.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Pod)]
pub struct FpuState {
    /// `d0`-`d31`, 64 bits each.
    d: [u64; 32],
    fpscr: u32,
    // Keeps the struct a multiple of the 16-byte alignment with no implicit
    // padding (required by `Pod`).
    _reserved: [u32; 3],
}

impl Default for FpuState {
    fn default() -> Self {
        Self {
            d: [0; 32],
            fpscr: 0,
            _reserved: [0; 3],
        }
    }
}

/// The FPU context of a user task.
#[derive(Clone, Debug, Default)]
pub struct FpuContext {
    state: FpuState,
}

core::arch::global_asm!(include_str!("fpu.S"));

unsafe extern "C" {
    fn arm_save_fpu(state: *mut FpuState);
    fn arm_load_fpu(state: *const FpuState);
}

impl FpuContext {
    /// Creates a new FPU context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Saves the CPU's current FPU context to this instance.
    pub fn save(&mut self) {
        // SAFETY: `state` is a valid, properly aligned `FpuState`.
        unsafe { arm_save_fpu(&mut self.state) };
    }

    /// Loads the CPU's FPU context from this instance.
    pub fn load(&self) {
        // SAFETY: `state` is a valid, properly aligned `FpuState`.
        unsafe { arm_load_fpu(&self.state) };
    }

    /// Returns the FPU context as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.state.as_bytes()
    }

    /// Returns the FPU context as a mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.state.as_mut_bytes()
    }
}
