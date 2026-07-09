// SPDX-License-Identifier: MPL-2.0

//! Low-level trap handling: the exception vector table and register frames.

use core::arch::global_asm;

use crate::arch::cpu::context::GeneralRegs;

global_asm!(include_str!("trap.S"));

/// Installs the exception vector table for the current CPU by programming
/// `VBAR` (CP15 c12, c0, 0).
///
/// # Safety
///
/// On the current CPU, this function must be called
/// - only once, and
/// - before any trap can occur.
pub(super) unsafe fn init_on_cpu() {
    unsafe extern "C" {
        fn exception_vector_table();
        fn arm_setup_exception_stacks();
    }
    // SAFETY: The symbol refers to a correctly aligned 8-entry vector table.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {vbar}, c12, c0, 0", // VBAR
            "isb",
            vbar = in(reg) exception_vector_table as *const () as usize,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Sets the banked stack pointers for the IRQ/ABT/UND modes, which
    // the exception vectors use as scratch. Called once per CPU.
    unsafe { arm_setup_exception_stacks() };
}

/// The saved register state on a kernel trap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    /// General registers (`r0`-`r15`).
    pub general: GeneralRegs,
    /// Saved program status register (the interrupted `CPSR`).
    pub cpsr: usize,
    /// Fault status register (`DFSR`/`IFSR`) captured on the trap.
    pub fsr: usize,
    /// Fault address register (`DFAR`/`IFAR`) captured on the trap.
    pub far: usize,
}

/// The saved register state used to run and return from userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::arch) struct RawUserContext {
    /// General registers (`r0`-`r15`; `r13`/`r14`/`r15` are the banked USR
    /// `sp`/`lr`/`pc`).
    pub(in crate::arch) general: GeneralRegs,
    /// Saved program status register (user `CPSR`).
    pub(in crate::arch) cpsr: usize,
    /// User thread pointer (`TPIDRURW`).
    pub(in crate::arch) tls: usize,
    /// Fault status captured on the last return to the kernel.
    pub(in crate::arch) fsr: usize,
    /// Fault address captured on the last return to the kernel.
    pub(in crate::arch) far: usize,
    /// The kind of trap that returned control to the kernel. Written by the
    /// user exception vectors. See the `TRAP_KIND_*` constants.
    pub(in crate::arch) trap_kind: usize,
}

/// `trap_kind`: a supervisor call (`SVC`) from userspace, i.e. a system call.
pub(in crate::arch) const TRAP_KIND_SYSCALL: usize = 0;
/// `trap_kind`: an IRQ taken from userspace.
pub(in crate::arch) const TRAP_KIND_IRQ: usize = 1;
/// `trap_kind`: a data abort taken from userspace.
pub(in crate::arch) const TRAP_KIND_DATA_ABORT: usize = 2;
/// `trap_kind`: a prefetch abort taken from userspace.
pub(in crate::arch) const TRAP_KIND_PREFETCH_ABORT: usize = 3;
/// `trap_kind`: an undefined-instruction exception taken from userspace.
pub(in crate::arch) const TRAP_KIND_UNDEF: usize = 4;

impl RawUserContext {
    /// Enters userspace with this context, returning when a trap occurs.
    pub(in crate::arch) fn run(&mut self) {
        let guard = crate::irq::disable_local();
        crate::task::call_pre_user_run_handler(&guard);
        // Return to userspace with interrupts disabled; they are re-enabled by
        // the trap handler after switching back to the kernel.
        core::mem::forget(guard);

        // SAFETY: `self` is a valid user context; `run_user` restores it, enters
        // user mode, and writes the trap state back on return.
        unsafe { run_user(self) };
    }
}

unsafe extern "C" {
    unsafe fn run_user(regs: &mut RawUserContext);
}
