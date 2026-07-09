// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    user::UserContextApi,
};

use crate::{
    process::signal::{SignalContext, sig_num::SigNum, signals::fault::FaultSignal},
    thread::exception::ToFaultSignal,
};

impl SignalContext for UserContext {
    fn set_arguments(&mut self, sig_num: SigNum, siginfo_addr: usize, ucontext_addr: usize) {
        // The ARM signal-handler ABI passes arguments in `r0`, `r1`, `r2`.
        self.set_r(0, sig_num.as_u8() as usize);
        self.set_r(1, siginfo_addr);
        self.set_r(2, ucontext_addr);
    }
}

impl ToFaultSignal for CpuException {
    fn to_fault_signal(&self, user_ctx: &UserContext) -> Option<FaultSignal> {
        use CpuException::*;

        use crate::process::signal::constants::*;

        let pc = user_ctx.instruction_pointer() as u64;

        let (num, code, addr) = match self {
            InstructionAbort(info) | DataAbort(info) => {
                if info.is_page_fault() {
                    // FIXME: Use `SEGV_ACCERR` for permission faults within an
                    // existing mapping.
                    (SIGSEGV, SEGV_MAPERR, info.far as u64)
                } else {
                    (SIGBUS, BUS_ADRERR, info.far as u64)
                }
            }
            UndefinedInstruction => (SIGILL, ILL_ILLOPC, pc),
            Unknown => (SIGILL, ILL_ILLTRP, pc),
            // A system call is not a fault.
            Syscall => return None,
        };

        Some(FaultSignal::new(num, code, Some(addr)))
    }
}
