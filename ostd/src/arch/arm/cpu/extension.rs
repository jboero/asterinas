// SPDX-License-Identifier: MPL-2.0

//! CPU feature detection.
//!
//! TODO: Parse `ID_ISAR*`/`ID_PFR*` to detect optional features.

/// Enables architecture-specific CPU features on the current processor.
pub(crate) fn init() {
    // Enable full access to the VFP/Advanced SIMD (NEON) coprocessors CP10 and
    // CP11 at PL0/PL1 by setting their access bits in `CPACR` (CP15 c1, opc2 2),
    // then enable the FPU via `FPEXC.EN`. Even on the softfloat kernel target,
    // user programs may use FP/SIMD.
    // SAFETY: Programming `CPACR`/`FPEXC` to permit FP/SIMD access is safe.
    unsafe {
        core::arch::asm!(
            "mrc p15, 0, {tmp}, c1, c0, 2",   // read CPACR
            "orr {tmp}, {tmp}, #(0b1111 << 20)", // CP10/CP11 = full access
            "mcr p15, 0, {tmp}, c1, c0, 2",   // write CPACR
            "isb",
            "mov {tmp}, #(1 << 30)",           // FPEXC.EN
            "vmsr fpexc, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}
