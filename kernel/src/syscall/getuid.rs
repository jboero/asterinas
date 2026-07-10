// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::Uid};

pub fn sys_getuid(ctx: &Context) -> Result<SyscallReturn> {
    // Report the uid as seen in the caller's user namespace. For the initial
    // namespace (the entire existing system) this is the identity.
    let uid = ctx.posix_thread.credentials().ruid();
    let local = ctx.thread_local.borrow_user_ns().uid_to_ns(uid);

    Ok(SyscallReturn::Return(<Uid as Into<u32>>::into(local) as _))
}
