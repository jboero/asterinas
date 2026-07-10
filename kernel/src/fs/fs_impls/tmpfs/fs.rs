// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{
        ramfs::RamFs,
        vfs::{
            file_system::FileSystem,
            registry::{FsCreationCtx, FsProperties, FsType},
        },
    },
    prelude::*,
};

/// The temporary file system (tmpfs) structure.
//
// TODO: `TmpFs` currently aliases `RamFs` and relies on `RamFs::new_tmpfs()`
// to create tmpfs-flavored ramfs instances. In the future we need to
// implement a dedicated tmpfs with tmpfs-specific features such as memory
// limits and swap support.
pub type TmpFs = RamFs;

// FIXME: These defaults are only a rough approximation for tmpfs-over-ramfs.
// A dedicated tmpfs implementation should replace them with real tmpfs limit
// and accounting semantics.
pub(in crate::fs) fn default_max_blocks() -> usize {
    crate::vm::mem_total() / PAGE_SIZE / 2
}
pub(in crate::fs) fn default_max_inodes() -> usize {
    crate::vm::mem_total() / PAGE_SIZE / 2
}

pub(super) struct TmpFsType;

impl FsType for TmpFsType {
    fn name(&self) -> &'static str {
        "tmpfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, _fs_creation_ctx: &FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        Ok(TmpFs::new_tmpfs())
    }

    fn sysnode(&self) -> Option<Arc<dyn aster_systree::SysNode>> {
        None
    }
}

/// The `mqueue` filesystem, used to expose POSIX message queues at
/// `/dev/mqueue`. Container runtimes (runc/containerd) mount it unconditionally,
/// so it must exist for a container to start.
///
/// Asterinas does not yet implement POSIX message-queue semantics, so this is
/// backed by a plain tmpfs: the mount succeeds (letting containers start) but
/// the directory behaves like an ordinary tmpfs rather than a real mqueue.
// TODO: Implement real POSIX message-queue semantics (mq_open/mq_send/...).
pub(super) struct MqueueFsType;

impl FsType for MqueueFsType {
    fn name(&self) -> &'static str {
        "mqueue"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, _fs_creation_ctx: &FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        Ok(TmpFs::new_tmpfs())
    }

    fn sysnode(&self) -> Option<Arc<dyn aster_systree::SysNode>> {
        None
    }
}
