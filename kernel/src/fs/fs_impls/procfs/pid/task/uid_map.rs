// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::TidDirOps;
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    process::{IdMapKind, UserNamespace, posix_thread::AsPosixThread},
    thread::Thread,
};

/// Maximum bytes accepted for a uid_map/gid_map write.
const ID_MAP_WRITE_MAX: usize = 512;

/// Represents the inode at `/proc/[pid]/task/[tid]/uid_map` (and also `/proc/[pid]/uid_map`).
pub struct UidMapFileOps(TidDirOps);

impl UidMapFileOps {
    pub fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/base.c#L3402>
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for UidMapFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        let map = match self.0.process() {
            Some(process) => process.user_ns().lock().format_uid_map(),
            None => String::new(),
        };
        write!(printer, "{}", map)?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        write_id_map(&self.0, IdMapKind::Uid, reader)
    }
}

/// Shared write path for uid_map and gid_map: read the text, resolve the target
/// namespace (the file's owner process) and the writer (the current thread), and
/// install the map.
pub(super) fn write_id_map(
    dir: &TidDirOps,
    kind: IdMapKind,
    reader: &mut VmReader,
) -> Result<usize> {
    let (cstr, read_bytes) = reader.read_cstring_until_end(ID_MAP_WRITE_MAX)?;
    let text = cstr
        .to_str()
        .map_err(|_| Error::with_message(Errno::EINVAL, "id map is not valid UTF-8"))?;

    let target = self_process_user_ns(dir)?;

    let writer_thread = current_thread!();
    let writer_pt = writer_thread
        .as_posix_thread()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "no calling thread"))?;

    UserNamespace::write_id_map(&target, kind, text, writer_pt)?;
    Ok(read_bytes)
}

pub(super) fn self_process_user_ns(dir: &TidDirOps) -> Result<Arc<UserNamespace>> {
    let process = dir
        .process()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "the process does not exist"))?;
    let user_ns = process.user_ns().lock().clone();
    Ok(user_ns)
}
