// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::credentials::capabilities::CapSet,
    seccomp::{
        SeccompFilter, SockFilter, SECCOMP_SET_MODE_FILTER, SECCOMP_SET_MODE_STRICT,
    },
};

// seccomp(2) filter flags. We accept all of them; only TSYNC has practical
// effect and, because runc installs its filter on a single-threaded child just
// before execve, "sync to all threads" reduces to the current thread here.
const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
const KNOWN_FLAGS: u32 = SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH;

/// `seccomp(2)` — install a real BPF filter or enter strict mode.
///
/// Installing a filter is gated like Linux: the caller must hold `CAP_SYS_ADMIN`
/// or have set `no_new_privs` (runc always sets the latter before exec). A
/// thread with no filter installed is completely unaffected by this subsystem.
pub fn sys_seccomp(
    operation: u32,
    flags: u32,
    args: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    match operation {
        SECCOMP_SET_MODE_STRICT => {
            // Strict mode takes no flags and no args.
            do_set_mode_strict(ctx);
            Ok(SyscallReturn::Return(0))
        }
        SECCOMP_SET_MODE_FILTER => {
            if flags & !KNOWN_FLAGS != 0 {
                return_errno_with_message!(Errno::EINVAL, "unknown seccomp filter flags");
            }
            do_set_mode_filter(args, ctx)?;
            debug!("seccomp: installed a BPF filter (flags={:#x})", flags);
            Ok(SyscallReturn::Return(0))
        }
        _ => return_errno_with_message!(Errno::EINVAL, "unsupported seccomp operation"),
    }
}

/// Enters STRICT mode on the current thread (shared by `seccomp(2)` and the
/// legacy `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)`).
pub(super) fn do_set_mode_strict(ctx: &Context) {
    ctx.posix_thread.seccomp().set_strict();
    debug!("seccomp: thread entered STRICT mode");
}

/// Installs a BPF filter from the user `sock_fprog` at `prog_ptr`. Shared by
/// `seccomp(2)` and the legacy `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)`.
/// Authorization mirrors Linux: `CAP_SYS_ADMIN` or `no_new_privs`.
pub(super) fn do_set_mode_filter(prog_ptr: Vaddr, ctx: &Context) -> Result<()> {
    let has_cap = ctx
        .posix_thread
        .credentials()
        .effective_capset()
        .contains(CapSet::SYS_ADMIN);
    if !has_cap && !ctx.posix_thread.no_new_privs() {
        return_errno_with_message!(
            Errno::EACCES,
            "seccomp filter requires CAP_SYS_ADMIN or no_new_privs"
        );
    }

    let filter = read_sock_fprog(prog_ptr, ctx)?;
    ctx.posix_thread.seccomp().add_filter(Arc::new(filter));
    Ok(())
}

/// Reads a `struct sock_fprog { unsigned short len; struct sock_filter *filter; }`
/// and the `len` instructions it points at from userspace.
fn read_sock_fprog(prog_ptr: Vaddr, ctx: &Context) -> Result<SeccompFilter> {
    let user = ctx.user_space();
    // On x86_64 the pointer is 8-byte aligned: len @0, filter-ptr @8.
    let len: u16 = user.read_val(prog_ptr)?;
    let filter_ptr: u64 = user.read_val(prog_ptr + 8)?;
    if len == 0 {
        return_errno_with_message!(Errno::EINVAL, "empty seccomp filter");
    }

    let mut insns: Vec<SockFilter> = Vec::with_capacity(len as usize);
    for i in 0..len as usize {
        let insn: SockFilter = user.read_val(filter_ptr as usize + i * 8)?;
        insns.push(insn);
    }
    SeccompFilter::new(insns).map_err(|msg| Error::with_message(Errno::EINVAL, msg))
}
