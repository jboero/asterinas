/* SPDX-License-Identifier: MPL-2.0 */

// The boot routine executed by the bootstrap processor (BSP) on ARMv7-A.
//
// On entry (QEMU `virt`, Linux ARM boot protocol via `-kernel`):
//   r0 = 0
//   r1 = machine type (-1 for device tree)
//   r2 = physical address of the Flattened Device Tree (DTB)
//   The CPU may enter in HYP mode (if the board provides virtualization) or in
//   SVC mode; the MMU is off.
//
// This routine drops to SVC if it entered in HYP, installs a temporary LPAE
// boot page table (identity map + kernel linear map via TTBR0), enables the
// MMU, switches to the kernel's virtual addresses, and jumps into the Rust
// entry point `arm_boot(dtb_paddr)`.

.arch armv7-a
.arch_extension virt

// ---- LPAE long-descriptor constants (64-bit) -------------------------------
//
//   bit0      : valid
//   bit1      : 0 = block (L1/L2)
//   bits[4:2] : AttrIndx (MAIR index)  0 = Normal WB, 1 = Device-nGnRnE
//   bits[7:6] : AP                      0b00 = PL1 RW, PL0 none
//   bits[9:8] : SH                      0b11 = inner shareable
//   bit10     : AF (access flag)
//   bit53     : PXN (privileged execute never)
//   bit54     : XN  (execute never)
//
// Normal-memory 1 GiB block, executable at PL1:
//   (1<<10) | (0b11<<8) | (0<<2) | 0b01 = 0x701   (high word 0)
// Device-memory 1 GiB block, no execute (PXN|XN set, high word bits 53/54):
//   low  = (1<<10) | (0<<8) | (1<<2) | 0b01 = 0x405
//   high = (1<<21) | (1<<22) = 0x00600000        (bits 53,54 of the 64-bit word)
NORMAL_BLOCK_LO = 0x00000701
NORMAL_BLOCK_HI = 0x00000000
DEVICE_BLOCK_LO = 0x00000405
DEVICE_BLOCK_HI = 0x00600000

.section ".boot", "awx", %progbits

.global _start
_start:
    // Preserve the DTB pointer (r2) across the whole boot sequence.
    mov     r4, r2

    // ---- Drop to SVC if we entered in HYP mode ----------------------------
    mrs     r0, cpsr
    and     r0, r0, #0x1f
    cmp     r0, #0x1a                // 0x1A = HYP mode
    bne     1f

    // In HYP: return to SVC mode (I/F masked) at label 1 via `eret`.
    mrs     r0, cpsr
    bic     r0, r0, #0x1f
    orr     r0, r0, #0x13            // SVC mode
    orr     r0, r0, #0xc0            // mask IRQ (I) and FIQ (F)
    msr     spsr_hyp, r0
    adr     r0, 1f
    msr     elr_hyp, r0
    eret

1:
    // Ensure SVC mode with IRQ/FIQ masked during boot.
    cpsid   if, #0x13

    // ---- Fill the LPAE L1 root table at runtime ---------------------------
    // With TTBCR.T0SZ = 0, TTBR0 translates the whole 4 GiB through a 4-entry
    // level-1 table, each entry mapping a 1 GiB block:
    //   [1] identity  : PA 0x4000_0000 (Normal) -- keeps PC valid at MMU-enable
    //   [2] linear low: PA 0x0000_0000 (Device) -> VA 0x8000_0000 (MMIO)
    //   [3] linear high:PA 0x4000_0000 (Normal) -> VA 0xC000_0000 (RAM + kernel)
    // Entry [0] (user space) is left absent during boot.
    ldr     r5, =boot_root_l1        // physical address of the root table

    // [1] identity map of the 0x4000_0000 GiB (Normal, executable)
    ldr     r0, =(NORMAL_BLOCK_LO | 0x40000000)
    ldr     r1, =NORMAL_BLOCK_HI
    str     r0, [r5, #(1 * 8)]
    str     r1, [r5, #(1 * 8 + 4)]

    // [2] linear map of PA 0 (Device: GIC/UART/virtio-mmio) -> VA 0x8000_0000
    ldr     r0, =(DEVICE_BLOCK_LO | 0x00000000)
    ldr     r1, =DEVICE_BLOCK_HI
    str     r0, [r5, #(2 * 8)]
    str     r1, [r5, #(2 * 8 + 4)]

    // [3] linear map of PA 0x4000_0000 (Normal: RAM+kernel) -> VA 0xC000_0000
    ldr     r0, =(NORMAL_BLOCK_LO | 0x40000000)
    ldr     r1, =NORMAL_BLOCK_HI
    str     r0, [r5, #(3 * 8)]
    str     r1, [r5, #(3 * 8 + 4)]

    // ---- Program the translation control registers ------------------------
    // MAIR0: Attr0 = Normal WB (0xFF), Attr1 = Device-nGnRnE (0x00). MAIR1 = 0.
    ldr     r0, =0x000000FF
    mcr     p15, 0, r0, c10, c2, 0   // MAIR0 (PRRR under LPAE)
    mov     r0, #0
    mcr     p15, 0, r0, c10, c2, 1   // MAIR1 (NMRR under LPAE)

    // TTBCR: EAE=1 (LPAE), EPD1=1 (disable TTBR1), SH0=inner, IRGN0/ORGN0=WBWA,
    //        T0SZ=0. (1<<31)|(1<<23)|(0b11<<12)|(0b01<<10)|(0b01<<8) = 0x80803500
    ldr     r0, =0x80803500
    mcr     p15, 0, r0, c2, c0, 2    // TTBCR

    // TTBR0 = boot_root_l1 (64-bit write; high half zero).
    mov     r1, #0
    mcrr    p15, 0, r5, r1, c2       // TTBR0 low=r5, high=r1

    // Ensure the table writes are visible and invalidate stale TLBs.
    dsb     ish
    mov     r0, #0
    mcr     p15, 0, r0, c8, c3, 0    // TLBIALLIS
    dsb     ish
    isb

    // ---- Enable the MMU ---------------------------------------------------
    mrc     p15, 0, r0, c1, c0, 0    // read SCTLR
    orr     r0, r0, #(1 << 0)        // M: enable MMU
    orr     r0, r0, #(1 << 2)        // C: data cache
    orr     r0, r0, #(1 << 12)       // I: instruction cache
    mcr     p15, 0, r0, c1, c0, 0    // write SCTLR
    isb

    // We are still executing at the identity-mapped physical PC (entry [1]).
    // Jump to the kernel's high virtual address.
    ldr     r0, =bsp_boot_virt
    bx      r0

// ---- The LPAE L1 root table, populated at runtime --------------------------
// Only entries 0-3 are consulted by the hardware (T0SZ = 0), but a full 4 KiB
// page is reserved so that it can be reused as an Asterinas 512-slot root.
.balign 4096
boot_root_l1:
    .zero 4096

.section ".boot.stack", "aw", %nobits
boot_stack_bottom:
    .balign 4096
    .skip 0x40000                    // 256 KiB
boot_stack_top:

// From here on we execute at kernel virtual addresses.
.text
bsp_boot_virt:
    // Set up the boot stack. `boot_stack_top` lives in the `.boot` section,
    // which is linked at low (physical) addresses, so OR in the linear-mapping
    // offset (0x8000_0000) to obtain its kernel-half alias.
    ldr     r0, =boot_stack_top
    orr     r0, r0, #0x80000000
    mov     sp, r0

    // Initialise the CPU-local base register (TPIDRPRW) with the CPU-local
    // storage start.
    ldr     r0, =__cpu_local_start
    mcr     p15, 0, r0, c13, c0, 4   // TPIDRPRW

    // Call into Rust with the DTB pointer as the first argument.
    mov     r0, r4
    ldr     r1, =arm_boot
    bx      r1
