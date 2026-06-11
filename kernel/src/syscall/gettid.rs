// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

pub fn sys_gettid(ctx: &Context) -> Result<SyscallReturn> {
    // The main thread's TID equals the process's PID, so report it in the
    // process's PID namespace (the namespace `init` thread sees TID 1).
    //
    // TODO: Give non-main threads namespace-local TIDs too; they currently
    // report their global TID.
    let tid = if ctx.posix_thread.tid() == ctx.process.pid() {
        ctx.process.vpid()
    } else {
        ctx.posix_thread.tid()
    };
    Ok(SyscallReturn::Return(tid as _))
}
