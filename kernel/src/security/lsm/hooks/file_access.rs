// SPDX-License-Identifier: MPL-2.0

//! Hooks for file-access checks — the second astermac MAC domain.
//!
//! Mediates a labeled subject (a tenant) reading/writing/executing a file based
//! on the file's own tenant label, independently of the discretionary uid/gid
//! mode bits. This is the cross-tenant isolation primitive for *shared
//! filesystems*, where namespaces and DAC do not separate tenants (shared
//! volumes, hostPath, the node rootfs).
//!
//! The object's tenant is resolved by the module from the file's `(dev, ino)`
//! identity, so this context only needs to carry the file identity and the
//! subject's tenant.

use super::super::modules;
use crate::prelude::*;

/// Runs file-access hooks in module order.
pub fn on_file_access(context: &FileAccessContext) -> Result<()> {
    for module in modules::active_modules() {
        module.on_file_access(context)?;
    }

    Ok(())
}

/// The inputs for a file-access check: the subject's tenant and the target
/// file's identity (the module maps the identity to the file's tenant label).
pub struct FileAccessContext {
    subject_tenant: u32,
    dev: u64,
    ino: u64,
}

impl FileAccessContext {
    /// Creates a file-access context.
    pub const fn new(subject_tenant: u32, dev: u64, ino: u64) -> Self {
        Self {
            subject_tenant,
            dev,
            ino,
        }
    }

    /// The astermac tenant label of the accessing thread (non-zero here; the
    /// caller skips the hook for unconfined tenant 0).
    pub const fn subject_tenant(&self) -> u32 {
        self.subject_tenant
    }

    /// The encoded device id of the target file.
    pub const fn dev(&self) -> u64 {
        self.dev
    }

    /// The inode number of the target file.
    pub const fn ino(&self) -> u64 {
        self.ino
    }
}
