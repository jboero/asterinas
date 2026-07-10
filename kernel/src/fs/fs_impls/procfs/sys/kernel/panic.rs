// SPDX-License-Identifier: MPL-2.0

//! `/proc/sys/kernel/panic` and `/proc/sys/kernel/panic_on_oops`.
//!
//! The kubelet's ContainerManager reads these on start (and only writes if the
//! value differs from its expected default), so the reported values match the
//! kubelet's desired defaults to avoid writing to unimplemented knobs.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps, read_i32_from},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/sys/kernel/panic`.
pub struct PanicFileOps;

impl PanicFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for PanicFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        // Seconds to wait before rebooting after a panic; the kubelet's default.
        writeln!(printer, "10")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}

/// Represents the inode at `/proc/sys/kernel/panic_on_oops`.
pub struct PanicOnOopsFileOps;

impl PanicOnOopsFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for PanicOnOopsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "1")?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (_val, read_bytes) = read_i32_from(reader)?;
        Ok(read_bytes)
    }
}
