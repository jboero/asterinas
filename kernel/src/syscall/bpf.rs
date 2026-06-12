// SPDX-License-Identifier: MPL-2.0

//! A minimal `bpf(2)` stub.
//!
//! Asterinas does not implement eBPF. This stub supports only the three
//! operations a cgroup-v2 container runtime (runc/containerd) needs to install
//! its device-access filter — `BPF_PROG_LOAD`, `BPF_PROG_ATTACH`, and
//! `BPF_PROG_QUERY` — and accepts them WITHOUT loading, attaching, or enforcing
//! any program. The cgroup device filter is therefore NOT enforced: a container
//! can access every device node. This is a clearly-documented limitation to let
//! OCI runtimes start, not a security feature.
//!
//! TODO: real eBPF support — a verifier, maps, program execution, and actual
//! cgroup-device enforcement. Every other `bpf()` command returns `ENOSYS`.

use core::fmt::Display;

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, FileLike, file_table::FdFlags},
        pseudofs::AnonInodeFs,
        vfs::path::Path,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
};

// The `bpf()` commands this stub recognizes.
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_PROG_QUERY: u32 = 16;

/// Byte offset of the `prog_cnt` output field inside `union bpf_attr`'s query
/// member: `target_fd`(4) + `attach_type`(4) + `query_flags`(4) +
/// `attach_flags`(4) + `prog_ids`(8) = 24.
const BPF_QUERY_PROG_CNT_OFFSET: usize = 24;

pub fn sys_bpf(cmd: u32, attr_addr: Vaddr, size: u32, ctx: &Context) -> Result<SyscallReturn> {
    debug!("bpf cmd = {}, size = {}", cmd, size);
    match cmd {
        BPF_PROG_LOAD => {
            // Pretend to load the program: return a real but inert fd so the
            // caller can attach it and then close it cleanly.
            warn!("bpf: BPF_PROG_LOAD accepted without loading a program (stub)");
            let file_table = ctx.thread_local.borrow_file_table();
            let mut file_table_locked = file_table.unwrap().write();
            let fd = file_table_locked.insert(Arc::new(BpfObject::new()), FdFlags::CLOEXEC);
            Ok(SyscallReturn::Return(fd.into()))
        }
        BPF_PROG_ATTACH | BPF_PROG_DETACH => {
            warn!("bpf: BPF_PROG_ATTACH/DETACH accepted without effect (stub)");
            Ok(SyscallReturn::Return(0))
        }
        BPF_PROG_QUERY => {
            // Report zero attached programs so the caller neither reads nor
            // detaches any.
            if (size as usize) >= BPF_QUERY_PROG_CNT_OFFSET + size_of::<u32>() {
                ctx.user_space()
                    .write_val(attr_addr + BPF_QUERY_PROG_CNT_OFFSET, &0u32)?;
            }
            Ok(SyscallReturn::Return(0))
        }
        _ => {
            // TODO: implement real eBPF for the remaining commands (maps,
            // BPF_BTF_LOAD, BPF_OBJ_GET/PIN, BPF_PROG_TEST_RUN, ...).
            return_errno_with_message!(Errno::ENOSYS, "this bpf() command is not implemented");
        }
    }
}

/// An inert object backing a `BPF_PROG_LOAD` file descriptor. It does nothing;
/// it exists only so the returned fd is a valid, closeable file.
struct BpfObject {
    pollee: Pollee,
    pseudo_path: Path,
}

impl BpfObject {
    fn new() -> Self {
        Self {
            pollee: Pollee::new(),
            pseudo_path: AnonInodeFs::new_path(|_| "anon_inode:bpf-prog".to_string()),
        }
    }
}

impl Pollable for BpfObject {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(mask, poller, IoEvents::empty)
    }
}

impl FileLike for BpfObject {
    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        Box::new("anon_inode:bpf-prog\n")
    }
}
