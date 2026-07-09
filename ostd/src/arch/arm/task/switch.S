/* SPDX-License-Identifier: MPL-2.0 */

// ARMv7-A kernel task context switch.
//
// `TaskContext` layout (see `mod.rs`):
//   0x00 : sp
//   0x04 : r4   0x08 : r5   0x0C : r6   0x10 : r7
//   0x14 : r8   0x18 : r9   0x1C : r10  0x20 : r11
//   0x24 : lr  (return address)

.arch armv7-a
.text

.global context_switch
.type context_switch, %function
context_switch: // (nxt: r0, cur: r1)
    str     sp, [r1, #0x00]
    stmib   r1, {{r4-r11}}            // r4..r11 -> [r1+4 .. r1+32]
    str     lr, [r1, #0x24]
    // Fallthrough.

.global first_context_switch
.type first_context_switch, %function
first_context_switch: // (nxt: r0)
    ldr     sp, [r0, #0x00]
    ldmib   r0, {{r4-r11}}            // [r0+4 .. r0+32] -> r4..r11
    ldr     lr, [r0, #0x24]
    bx      lr
.size context_switch, .-context_switch
.size first_context_switch, .-first_context_switch

.global kernel_task_entry_wrapper
.type kernel_task_entry_wrapper, %function
kernel_task_entry_wrapper:
    .cfi_startproc
    .cfi_undefined lr               // mark the return address as end of call stack
    bl      kernel_task_entry
    .cfi_endproc
.size kernel_task_entry_wrapper, .-kernel_task_entry_wrapper
