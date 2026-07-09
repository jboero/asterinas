// SPDX-License-Identifier: MPL-2.0

//! Architecture dependent CPU-local information utilities.
//!
//! On ARMv7-A the CPU-local storage base is held in the privileged thread-ID
//! register `TPIDRPRW` (CP15 c13, opc2 4), initialised by the boot assembly to
//! point at `__cpu_local_start`.

pub(crate) fn get_base() -> u64 {
    let base: usize;
    // SAFETY: Reading `TPIDRPRW` has no side effects.
    unsafe {
        core::arch::asm!(
            "mrc p15, 0, {base}, c13, c0, 4",
            base = out(reg) base,
            options(preserves_flags, nostack, nomem),
        );
    }
    base as u64
}
