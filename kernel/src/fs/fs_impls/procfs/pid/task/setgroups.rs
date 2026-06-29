// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use super::{TidDirOps, uid_map::self_process_user_ns};
use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    thread::Thread,
};

/// Represents the inode at `/proc/[pid]/setgroups`. It controls whether
/// `setgroups(2)` is allowed in the process's user namespace; it must be written
/// "deny" before an unprivileged process may write the gid_map.
pub struct SetgroupsFileOps(TidDirOps);

impl SetgroupsFileOps {
    pub fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self(dir.clone()), parent, mkmod!(a+r, u+w))
    }
}

impl ProcFileOps for SetgroupsFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.0.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        let allowed = match self.0.process() {
            Some(process) => process.user_ns().lock().setgroups_allowed(),
            None => true,
        };
        write!(printer, "{}\n", if allowed { "allow" } else { "deny" })?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (cstr, read_bytes) = reader.read_cstring_until_end(16)?;
        let value = cstr
            .to_str()
            .map_err(|_| Error::with_message(Errno::EINVAL, "setgroups: invalid UTF-8"))?
            .trim();
        let allowed = match value {
            "allow" => true,
            "deny" => false,
            _ => return_errno_with_message!(Errno::EINVAL, "setgroups expects \"allow\" or \"deny\""),
        };
        let target = self_process_user_ns(&self.0)?;
        target.set_setgroups_allowed(allowed)?;
        Ok(read_bytes)
    }
}
