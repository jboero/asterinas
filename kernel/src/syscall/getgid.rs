// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::Gid};

pub fn sys_getgid(ctx: &Context) -> Result<SyscallReturn> {
    let gid = ctx.posix_thread.credentials().rgid();
    let local = ctx.thread_local.borrow_user_ns().gid_to_ns(gid);

    Ok(SyscallReturn::Return(<Gid as Into<u32>>::into(local) as _))
}
