// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntry,
            sys::vm::mmap_min_addr::MmapMinAddrFileOps,
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

mod mmap_min_addr;

/// Represents the inode at `/proc/sys/vm`.
pub struct VmDirOps;

impl VmDirOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/security/min_addr.c#L59>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/mm/mm_init.c>
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        (
            "mmap_min_addr",
            InodeType::File,
            MmapMinAddrFileOps::new_inode,
        ),
        (
            "overcommit_memory",
            InodeType::File,
            OvercommitMemoryFileOps::new_inode,
        ),
        (
            "panic_on_oom",
            InodeType::File,
            PanicOnOomFileOps::new_inode,
        ),
    ];
}

impl ProcDirOps for VmDirOps {
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

/// Represents the inode at `/proc/sys/vm/overcommit_memory`.
///
/// Reported as `1` (always overcommit). The kubelet's ContainerManager reads
/// this on start and only writes if it differs from its expected value, so
/// serving the expected value avoids a write to an unimplemented knob.
struct OvercommitMemoryFileOps;

impl OvercommitMemoryFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for OvercommitMemoryFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "1")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        // Accept and ignore: Asterinas has a single overcommit policy.
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}

/// Represents the inode at `/proc/sys/vm/panic_on_oom`.
struct PanicOnOomFileOps;

impl PanicOnOomFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for PanicOnOomFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "0")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}
