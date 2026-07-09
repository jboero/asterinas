// SPDX-License-Identifier: MPL-2.0

//! The architecture support of context switch.

use crate::task::TaskContextApi;

core::arch::global_asm!(include_str!("switch.S"));

#[repr(C)]
#[derive(Clone, Debug)]
pub(crate) struct TaskContext {
    regs: CalleeRegs,
    lr: usize,
}

impl TaskContext {
    /// Creates a new `TaskContext`.
    pub(crate) const fn new() -> Self {
        TaskContext {
            regs: CalleeRegs::new(),
            lr: 0,
        }
    }
}

/// Callee-saved registers (`r4`-`r11`) and the stack pointer.
#[repr(C)]
#[derive(Clone, Debug)]
struct CalleeRegs {
    sp: usize,
    r4: usize,
    r5: usize,
    r6: usize,
    r7: usize,
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
}

impl CalleeRegs {
    const fn new() -> Self {
        CalleeRegs {
            sp: 0,
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
        }
    }
}

impl TaskContextApi for TaskContext {
    fn set_instruction_pointer(&mut self, ip: usize) {
        self.lr = ip;
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.regs.sp = sp;
    }
}

unsafe extern "C" {
    pub(crate) unsafe fn context_switch(nxt: *const TaskContext, cur: *mut TaskContext);
    pub(crate) unsafe fn first_context_switch(nxt: *const TaskContext);
    pub(crate) unsafe fn kernel_task_entry_wrapper();
}
