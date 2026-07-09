/* SPDX-License-Identifier: MPL-2.0 */

// The boot routine executed by application processors (APs) on ARMv7-A.
//
// APs are started via the PSCI `CPU_ON` call, which enters at `ap_boot_start`
// (a physical address) with r0 = the context ID we passed, which carries the
// Asterinas CPU index.

.arch armv7-a
.arch_extension virt

.section ".ap_boot", "awx", %progbits

.balign 4096
.global ap_boot_start
ap_boot_start:
    // r0 = context ID (the Asterinas CPU index). Preserve it in r4.
    mov     r4, r0

    // Drop to SVC if we entered in HYP mode.
    mrs     r0, cpsr
    and     r0, r0, #0x1f
    cmp     r0, #0x1a
    bne     1f
    mrs     r0, cpsr
    bic     r0, r0, #0x1f
    orr     r0, r0, #0x13
    orr     r0, r0, #0xc0
    msr     spsr_hyp, r0
    adr     r0, 1f
    msr     elr_hyp, r0
    eret
1:
    cpsid   if, #0x13

    // Load the shared boot page-table root (filled by the BSP). The pointer
    // variable lives in `.data` at a high virtual address, so compute its
    // physical location by subtracting the kernel VMA offset (0x8000_0000).
    ldr     r0, =__ap_boot_page_table_pointer
    sub     r0, r0, #0x80000000
    ldr     r0, [r0]                    // r0 = boot page-table root paddr

    // Program the translation registers (identical to the BSP).
    ldr     r1, =0x000000FF
    mcr     p15, 0, r1, c10, c2, 0      // MAIR0
    mov     r1, #0
    mcr     p15, 0, r1, c10, c2, 1      // MAIR1
    ldr     r1, =0x80803500
    mcr     p15, 0, r1, c2, c0, 2       // TTBCR
    mov     r1, #0
    mcrr    p15, 0, r0, r1, c2          // TTBR0

    dsb     ish
    mov     r1, #0
    mcr     p15, 0, r1, c8, c3, 0       // TLBIALLIS
    dsb     ish
    isb

    mrc     p15, 0, r0, c1, c0, 0       // SCTLR
    orr     r0, r0, #(1 << 0)
    orr     r0, r0, #(1 << 2)
    orr     r0, r0, #(1 << 12)
    mcr     p15, 0, r0, c1, c0, 0
    isb

    ldr     r0, =ap_boot_virt
    bx      r0

.data
.balign 8
// Filled by the BSP (`bringup_all_aps`) before starting APs.
.global __ap_boot_page_table_pointer
__ap_boot_page_table_pointer:
    .word 0
.global __ap_boot_info_array_pointer
__ap_boot_info_array_pointer:
    .word 0

.text
ap_boot_virt:
    // r4 = CPU index (context ID). Look up this AP's PerApRawInfo:
    //   info = __ap_boot_info_array_pointer; entry = &info[cpu_id - 1]
    //   PerApRawInfo is 8 bytes on 32-bit: stack_top at +0, cpu_local base at +4.
    ldr     r0, =__ap_boot_info_array_pointer
    ldr     r0, [r0]                    // r0 = &PerApRawInfo[0]
    sub     r1, r4, #1
    lsl     r1, r1, #3                  // (cpu_id - 1) * 8
    add     r0, r0, r1                  // r0 = &PerApRawInfo[cpu_id - 1]
    ldr     sp, [r0, #0]                // stack_top
    ldr     r1, [r0, #4]                // cpu_local base
    mcr     p15, 0, r1, c13, c0, 4      // TPIDRPRW

    mov     r11, #0                     // clear frame pointer

    // Call `ap_early_entry(cpu_id)`.
    mov     r0, r4
    ldr     r1, =ap_early_entry
    bx      r1
