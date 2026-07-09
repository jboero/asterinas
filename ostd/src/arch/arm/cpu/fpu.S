/* SPDX-License-Identifier: MPL-2.0 */

// Save and restore the ARMv7-A VFP / Advanced SIMD (NEON) floating-point state.
//
// The `FpuState` layout (see `context.rs`) is:
//   offset 0x000: d0-d31   (32 * 8 = 256 bytes)
//   offset 0x100: fpscr    (u32)
//
// The kernel target is softfloat, so these routines are assembled for a NEON
// core explicitly.

.arch armv7-a
.fpu neon

.section .text

// void arm_save_fpu(FpuState *state)   // r0 = state
.global arm_save_fpu
.type arm_save_fpu, %function
arm_save_fpu:
    vstmia  r0!, {{d0-d15}}
    vstmia  r0!, {{d16-d31}}
    vmrs    r1, fpscr
    str     r1, [r0]                 // r0 now points at offset 0x100 (fpscr)
    bx      lr

// void arm_load_fpu(const FpuState *state)   // r0 = state
.global arm_load_fpu
.type arm_load_fpu, %function
arm_load_fpu:
    vldmia  r0!, {{d0-d15}}
    vldmia  r0!, {{d16-d31}}
    ldr     r1, [r0]                 // r0 now points at offset 0x100 (fpscr)
    vmsr    fpscr, r1
    bx      lr
