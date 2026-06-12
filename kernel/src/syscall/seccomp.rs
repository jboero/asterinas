// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::prelude::*;

const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// A permissive `seccomp(2)` stub.
///
/// Asterinas does not yet enforce seccomp BPF filters. OCI runtimes (runc,
/// containerd) unconditionally apply a default seccomp profile and abort if the
/// syscall is unavailable, so this accepts the filter-installing operations and
/// returns success **without installing or enforcing any filter**. This is a
/// clearly-documented limitation to allow container runtimes to run, not a
/// security feature — a real BPF interpreter is future hardening.
pub fn sys_seccomp(
    operation: u32,
    _flags: u32,
    _args: Vaddr,
    _ctx: &Context,
) -> Result<SyscallReturn> {
    match operation {
        SECCOMP_SET_MODE_FILTER | SECCOMP_SET_MODE_STRICT => {
            debug!("seccomp: accepting mode {} without enforcement (stub)", operation);
            Ok(SyscallReturn::Return(0))
        }
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported seccomp operation"),
    }
}
