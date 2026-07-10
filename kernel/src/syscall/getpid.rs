// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

pub fn sys_getpid(ctx: &Context) -> Result<SyscallReturn> {
    // Return the PID as seen from within the process's own PID namespace, so a
    // process that is the `init` of a new namespace sees PID 1.
    let pid = ctx.process.vpid();
    debug!("vpid = {}", pid);
    Ok(SyscallReturn::Return(pid as _))
}
