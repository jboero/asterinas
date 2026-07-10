// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::{TidDirOps, uid_map::write_id_map};
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    process::IdMapKind,
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/task/[tid]/gid_map` (and also `/proc/[pid]/gid_map`).
pub struct GidMapFileOps(TidDirOps);

impl GidMapFileOps {
    pub fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3403>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for GidMapFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        let map = match self.0.process() {
            Some(process) => process.user_ns().lock().format_gid_map(),
            None => String::new(),
        };
        write!(printer, "{}", map)?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        write_id_map(&self.0, IdMapKind::Gid, reader)
    }
}
