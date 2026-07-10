// SPDX-License-Identifier: MPL-2.0

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    net::uts_ns::UtsName,
    prelude::*,
};

/// Represents the inode at `/proc/sys/kernel/osrelease`.
///
/// Reports the kernel release string (the same value `uname -r` returns). Tools
/// such as kube-proxy's nftables proxier read this to verify a minimum kernel
/// version before initializing; without it they abort with "could not check
/// kernel version: failed to read os-release file".
pub struct OsReleaseFileOps;

impl OsReleaseFileOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/sysctl.c#L1727>
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for OsReleaseFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{}", UtsName::RELEASE)?;
        Ok(printer.bytes_written())
    }
}
