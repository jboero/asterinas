/* SPDX-License-Identifier: MPL-2.0 */

// ARMv7-A exception vectors and trap entry/exit.
//
// The single `RawUserContext`/`TrapFrame` layout (see `trap.rs`) is:
//   0x00: r0-r15   (16 * 4 = 64 bytes; r13/r14/r15 = user sp/lr/pc)
//   0x40: cpsr
//   0x44: tls            (RawUserContext only)
//   0x48: fsr
//   0x4C: far
//   0x50: trap_kind      (RawUserContext only)
//
// User entry/exit uses two globals (valid for the current single-core boot;
// TODO: make these CPU-local for SMP):
//   RUN_USER_KERNEL_SP  - the SVC sp holding run_user's saved kernel frame
//   RUN_USER_CTX_PTR    - pointer to the active `RawUserContext`

.arch armv7-a

// trap_kind values (must match trap.rs).
.equ TK_SYSCALL,        0
.equ TK_IRQ,            1
.equ TK_DATA_ABORT,     2
.equ TK_PREFETCH_ABORT, 3
.equ TK_UNDEF,          4

.section .text

// ---- Exception vector table (installed into VBAR) --------------------------
// Each entry is one instruction; we branch to the per-exception handler.
.balign 32
.global exception_vector_table
exception_vector_table:
    b       .                       // 0x00 Reset (unused)
    b       vec_undef               // 0x04 Undefined instruction
    b       vec_svc                 // 0x08 Supervisor call (SVC)
    b       vec_prefetch_abort      // 0x0C Prefetch abort
    b       vec_data_abort          // 0x10 Data abort
    b       .                       // 0x14 (reserved)
    b       vec_irq                 // 0x18 IRQ
    b       .                       // 0x1C FIQ (unused)

// ---- Save the user context and return through run_user ---------------------
// Entered in the exception's mode with:
//   r0-r12  = user r0-r12 (shared, not banked in this mode)
//   lr      = mode-banked return address (already adjusted by the caller)
//   spsr    = user CPSR
//   the current mode's banked sp is a small scratch stack.
// On entry `\kind` is the trap_kind to record.
.macro SAVE_USER_AND_RETURN kind
    // Free r0 as scratch using this mode's scratch stack.
    str     r0, [sp, #-4]!
    ldr     r0, =RUN_USER_CTX_PTR
    ldr     r0, [r0]                // r0 = ctx pointer
    stmib   r0, {{r1-r12}}            // ctx->r[1..12] = user r1-r12
    ldr     r1, [sp], #4            // recover user r0
    str     r1, [r0]               // ctx->r[0] = user r0
    add     r1, r0, #(13 * 4)
    stmia   r1, {{r13, r14}}^         // ctx->r[13],r[14] = user sp, lr (banked)
    str     lr, [r0, #(15 * 4)]     // ctx->r[15] = user pc (adjusted lr)
    mrs     r1, spsr
    str     r1, [r0, #0x40]         // ctx->cpsr = user CPSR
    mov     r1, #\kind
    str     r1, [r0, #0x50]         // ctx->trap_kind
    // Return to the kernel: switch to SVC, restore run_user's frame.
    cps     #0x13                   // SVC mode
    ldr     r1, =RUN_USER_KERNEL_SP
    ldr     sp, [r1]
    pop     {{r4-r11, lr}}
    bx      lr
.endm

// Records the current data/instruction fault status+address into the ctx.
.macro SAVE_FAULT_INFO is_data
    ldr     r0, =RUN_USER_CTX_PTR
    ldr     r0, [r0]
.if \is_data
    mrc     p15, 0, r1, c5, c0, 0   // DFSR
    mrc     p15, 0, r2, c6, c0, 0   // DFAR
.else
    mrc     p15, 0, r1, c5, c0, 1   // IFSR
    mrc     p15, 0, r2, c6, c0, 2   // IFAR
.endif
    str     r1, [r0, #0x48]         // ctx->fsr
    str     r2, [r0, #0x4C]         // ctx->far
.endm

// ---- Per-exception vectors -------------------------------------------------

vec_svc:
    // From user: LR_svc already points past the SVC. Kernel SVC (nested) is not
    // expected during boot.
    SAVE_USER_AND_RETURN TK_SYSCALL

// Determines whether the exception came from USR mode without destroying the
// interrupted `r0`: it is saved to this mode's scratch stack across the check
// and restored afterwards (`ldr` does not affect the condition flags, so the
// `cmp` result survives). Without this, a kernel trap would clobber `r0` with
// the saved mode value (0x13 for SVC), corrupting the interrupted context.
.macro CHECK_FROM_USER
    str     r0, [sp, #-4]!         // preserve interrupted r0
    mrs     r0, spsr
    and     r0, r0, #0x1f
    cmp     r0, #0x10               // USR mode?
    ldr     r0, [sp], #4           // restore interrupted r0 (flags preserved)
.endm

vec_irq:
    sub     lr, lr, #4              // IRQ return address = LR - 4
    CHECK_FROM_USER
    bne     kernel_irq_entry
    SAVE_USER_AND_RETURN TK_IRQ

vec_data_abort:
    sub     lr, lr, #8              // data-abort return = LR - 8
    CHECK_FROM_USER
    bne     kernel_abort_entry_data
    SAVE_FAULT_INFO 1
    SAVE_USER_AND_RETURN TK_DATA_ABORT

vec_prefetch_abort:
    sub     lr, lr, #4              // prefetch-abort return = LR - 4
    CHECK_FROM_USER
    bne     kernel_abort_entry_prefetch
    SAVE_FAULT_INFO 0
    SAVE_USER_AND_RETURN TK_PREFETCH_ABORT

vec_undef:
    sub     lr, lr, #4              // return to the undefined instruction
    CHECK_FROM_USER
    bne     .                       // kernel undefined instruction: hang
    SAVE_USER_AND_RETURN TK_UNDEF

// ---- Kernel-mode exception entries -----------------------------------------
// Build a TrapFrame on the SVC stack, call the Rust handler, then restore.
// Entered in the exception mode; `lr` already adjusted. We switch to SVC to run
// on the kernel stack.

// Builds a `TrapFrame` on the current mode's stack (19 words: r0-r15, cpsr,
// fsr, far) with `lr` (already adjusted) as the faulting/return PC and `spsr`
// as the saved CPSR. `r13`/`r14` are approximated (the banked kernel values are
// not needed for page-fault recovery or panic reporting).
.macro BUILD_KERNEL_FRAME
    sub     sp, sp, #(19 * 4)
    stmia   sp, {{r0-r12}}          // r0-r12 -> [sp+0 .. sp+48]
    mov     r0, #0
    str     r0, [sp, #(13 * 4)]     // r13 (approx)
    str     lr, [sp, #(14 * 4)]     // r14 (approx)
    str     lr, [sp, #(15 * 4)]     // r15 = faulting/return PC
    mrs     r0, spsr
    str     r0, [sp, #(16 * 4)]     // cpsr
.endm

// Returns from a kernel-mode exception: restore r0-r12 and the (possibly
// updated) PC, and pop the frame. `movs pc, lr` restores CPSR from spsr.
.macro RET_KERNEL_FRAME
    ldr     lr, [sp, #(15 * 4)]
    ldmia   sp, {{r0-r12}}
    add     sp, sp, #(19 * 4)
    movs    pc, lr
.endm

kernel_irq_entry:
    BUILD_KERNEL_FRAME
    mov     r0, #0
    str     r0, [sp, #(17 * 4)]     // fsr = 0
    str     r0, [sp, #(18 * 4)]     // far = 0
    mov     r0, sp
    bl      irq_handler
    RET_KERNEL_FRAME

kernel_abort_entry_data:
    BUILD_KERNEL_FRAME
    mrc     p15, 0, r0, c5, c0, 0   // DFSR
    str     r0, [sp, #(17 * 4)]
    mrc     p15, 0, r0, c6, c0, 0   // DFAR
    str     r0, [sp, #(18 * 4)]
    mov     r0, sp
    bl      kernel_data_abort_handler
    RET_KERNEL_FRAME

kernel_abort_entry_prefetch:
    BUILD_KERNEL_FRAME
    mrc     p15, 0, r0, c5, c0, 1   // IFSR
    str     r0, [sp, #(17 * 4)]
    mrc     p15, 0, r0, c6, c0, 2   // IFAR
    str     r0, [sp, #(18 * 4)]
    mov     r0, sp
    bl      kernel_prefetch_abort_handler
    RET_KERNEL_FRAME

// ---- run_user(regs) --------------------------------------------------------
// r0 = &RawUserContext. Saves the kernel state, enters USR mode, and returns
// here (via the vectors) when the user traps back.
.global run_user
.type run_user, %function
run_user:
    push    {{r4-r11, lr}}
    ldr     r1, =RUN_USER_KERNEL_SP
    str     sp, [r1]
    ldr     r1, =RUN_USER_CTX_PTR
    str     r0, [r1]

    ldr     r1, [r0, #0x40]         // user CPSR
    msr     spsr_cxsf, r1
    ldr     r1, [r0, #0x44]         // user TLS
    mcr     p15, 0, r1, c13, c0, 2  // TPIDRURW

    add     r1, r0, #(13 * 4)
    ldmia   r1, {{r13, r14}}^         // load user sp, lr into USR-banked regs
    ldr     lr, [r0, #(15 * 4)]     // user pc -> LR_svc
    ldmia   r0, {{r0-r12}}            // user r0-r12
    movs    pc, lr                  // enter USR mode (CPSR <- SPSR)

// ---- Set up the banked stack pointers for the exception modes --------------
// Called once per CPU from `trap::init_on_cpu` (in SVC mode). The scratch
// stacks are used only briefly in each vector prologue before switching to SVC.
// TODO: per-CPU stacks for SMP.
.global arm_setup_exception_stacks
.type arm_setup_exception_stacks, %function
arm_setup_exception_stacks:
    mrs     r0, cpsr
    cpsid   i, #0x12                // IRQ mode
    ldr     sp, =irq_mode_stack_top
    cpsid   i, #0x17                // ABT mode
    ldr     sp, =abt_mode_stack_top
    cpsid   i, #0x1b                // UND mode
    ldr     sp, =und_mode_stack_top
    msr     cpsr_c, r0              // restore the original (SVC) mode
    bx      lr

// ---- Per-mode scratch stacks and the user-entry globals --------------------
.section .bss
.balign 8
irq_mode_stack:
    .zero 0x10000
irq_mode_stack_top:
abt_mode_stack:
    .zero 0x10000
abt_mode_stack_top:
und_mode_stack:
    .zero 0x10000
und_mode_stack_top:

.global RUN_USER_KERNEL_SP
RUN_USER_KERNEL_SP:
    .zero 4
.global RUN_USER_CTX_PTR
RUN_USER_CTX_PTR:
    .zero 4
