// SPDX-License-Identifier: MPL-2.0

//! Local interrupt masking via the `CPSR` interrupt-disable flags.
//!
//! On ARMv7-A, `cpsie i` / `cpsid i` clear/set the `CPSR.I` (IRQ disable) bit.

/// Enables local IRQs.
//
// FIXME: Mark this as unsafe. See
// <https://github.com/asterinas/asterinas/issues/1120#issuecomment-2748696592>.
pub(crate) fn enable_local() {
    // SAFETY: Unmasking IRQs is safe here.
    unsafe { core::arch::asm!("cpsie i", options(nostack, preserves_flags)) };
}

/// Enables local IRQs and halts the CPU until an interrupt arrives.
pub(crate) fn enable_local_and_halt() {
    // A pending IRQ wakes `wfi` even while masked, so unmasking afterwards keeps
    // the "no interrupt can occur in between" guarantee.
    // SAFETY: Halting and unmasking IRQs is safe here.
    unsafe {
        core::arch::asm!(
            "wfi",
            "cpsie i",
            options(nostack, preserves_flags),
        )
    };
}

/// Disables local IRQs.
pub(crate) fn disable_local() {
    // SAFETY: Masking IRQs is safe.
    unsafe { core::arch::asm!("cpsid i", options(nostack, preserves_flags)) };
}

/// Disables local IRQs and halts the CPU forever.
pub(crate) fn disable_local_and_halt() -> ! {
    // SAFETY: Masking IRQs is safe.
    unsafe { core::arch::asm!("cpsid i", options(nostack, preserves_flags)) };
    loop {
        // SAFETY: Halting is safe.
        unsafe { core::arch::asm!("wfi", options(nostack, preserves_flags)) };
    }
}

/// Returns whether local IRQs are enabled.
pub(crate) fn is_local_enabled() -> bool {
    let cpsr: usize;
    // SAFETY: Reading `CPSR` has no side effects.
    unsafe { core::arch::asm!("mrs {}, cpsr", out(reg) cpsr, options(nostack, nomem)) };
    // The IRQ disable flag is `CPSR.I` (bit 7); a clear bit means IRQs enabled.
    (cpsr & (1 << 7)) == 0
}
