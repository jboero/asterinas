// SPDX-License-Identifier: MPL-2.0

//! `/proc/sys/kernel/keys/` — the kernel keyring quota knobs.
//!
//! Asterinas has no kernel keyring, but the kubelet's ContainerManager reads
//! `root_maxkeys` and `root_maxbytes` on start. The reported values match the
//! kubelet's expected defaults so it does not attempt to write them.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntry,
            template::{
                ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry,
                listed_entries_from_table, lookup_child_from_table, read_i32_from,
                visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/sys/kernel/keys`.
pub struct KeysDirOps;

impl KeysDirOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        (
            "root_maxkeys",
            InodeType::File,
            RootMaxKeysFileOps::new_inode,
        ),
        (
            "root_maxbytes",
            InodeType::File,
            RootMaxBytesFileOps::new_inode,
        ),
    ];
}

impl ProcDirOps for KeysDirOps {
    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}

/// Represents the inode at `/proc/sys/kernel/keys/root_maxkeys`.
struct RootMaxKeysFileOps;

impl RootMaxKeysFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for RootMaxKeysFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "1000000")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}

/// Represents the inode at `/proc/sys/kernel/keys/root_maxbytes`.
struct RootMaxBytesFileOps;

impl RootMaxBytesFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for RootMaxBytesFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "25000000")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}
