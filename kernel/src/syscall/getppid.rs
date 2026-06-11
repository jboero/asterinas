// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

pub fn sys_getppid(ctx: &Context) -> Result<SyscallReturn> {
    // Report the parent's PID as seen from the calling process's PID namespace.
    // If the parent lives in an ancestor namespace (e.g. the caller is the `init`
    // of its namespace), it is not visible and the result is 0.
    let ppid = ctx
        .process
        .parent()
        .lock()
        .process()
        .upgrade()
        .and_then(|parent| parent.pid_nr_in(ctx.process.pid_ns()))
        .unwrap_or(0);
    Ok(SyscallReturn::Return(ppid as _))
}
