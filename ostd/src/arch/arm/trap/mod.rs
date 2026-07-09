// SPDX-License-Identifier: MPL-2.0

//! Handles traps.

#[expect(clippy::module_inception)]
mod trap;

use spin::Once;
pub use trap::TrapFrame;
pub(in crate::arch) use trap::{
    RawUserContext, TRAP_KIND_DATA_ABORT, TRAP_KIND_IRQ, TRAP_KIND_PREFETCH_ABORT,
    TRAP_KIND_SYSCALL, TRAP_KIND_UNDEF,
};

use crate::{
    arch::cpu::context::{CpuException, FaultInfo},
    cpu::PrivilegeLevel,
    ex_table::ExTable,
    mm::MAX_USERSPACE_VADDR,
};

/// Initializes interrupt handling on the current CPU.
///
/// # Safety
///
/// On the current CPU, this function must be called
/// - only once, and
/// - before any trap can occur.
pub(crate) unsafe fn init_on_cpu() {
    // SAFETY: The caller ensures the safety conditions.
    unsafe { trap::init_on_cpu() };
}

/// Handles a data abort taken from the kernel.
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
unsafe extern "C" fn kernel_data_abort_handler(f: &mut TrapFrame) {
    let info = FaultInfo {
        far: f.far,
        fsr: f.fsr,
    };
    handle_kernel_abort(f, CpuException::DataAbort(info), info);
}

/// Handles a prefetch abort taken from the kernel.
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
unsafe extern "C" fn kernel_prefetch_abort_handler(f: &mut TrapFrame) {
    let info = FaultInfo {
        far: f.far,
        fsr: f.fsr,
    };
    handle_kernel_abort(f, CpuException::InstructionAbort(info), info);
}

fn handle_kernel_abort(f: &mut TrapFrame, exception: CpuException, info: FaultInfo) {
    if info.is_page_fault() && (0..MAX_USERSPACE_VADDR).contains(&info.far) {
        handle_user_page_fault(f, &exception);
    } else {
        panic!(
            "Cannot handle kernel exception, exception: {:#x?}, trapframe: {:#x?}.",
            exception, f
        );
    }
}

/// Handles an IRQ taken from the kernel.
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
unsafe extern "C" fn irq_handler(f: &mut TrapFrame) {
    super::irq::handle_irq(f, PrivilegeLevel::Kernel);
}

#[expect(clippy::type_complexity)]
static USER_PAGE_FAULT_HANDLER: Once<fn(&CpuException) -> Result<(), ()>> = Once::new();

/// Injects a custom handler for page faults that occur in the kernel and are
/// caused by a user-space address.
pub fn inject_user_page_fault_handler(handler: fn(info: &CpuException) -> Result<(), ()>) {
    USER_PAGE_FAULT_HANDLER.call_once(|| handler);
}

fn handle_user_page_fault(f: &mut TrapFrame, exception: &CpuException) {
    let handler = USER_PAGE_FAULT_HANDLER
        .get()
        .expect("Page fault handler is missing");

    if handler(exception).is_ok() {
        return;
    }

    // Recover through the exception table if possible. `r[15]` is the faulting
    // PC saved in the trap frame.
    if let Some(addr) = ExTable::find_recovery_inst_addr(f.general.r[15]) {
        f.general.r[15] = addr;
    } else {
        panic!(
            "Failed to handle page fault, exception: {:?}, trapframe: {:#x?}.",
            exception, f
        )
    }
}
