// SPDX-License-Identifier: MPL-2.0

//! `/proc/sys/net/ipv4` — IPv4 networking sysctls.
//!
//! The CNI `ptp`/`bridge` plugins enable IP forwarding by writing
//! `/proc/sys/net/ipv4/ip_forward` while wiring up a pod's veth, and abort pod
//! sandbox creation if the file is missing ("Could not enable IP forwarding:
//! open /proc/sys/net/ipv4/ip_forward: no such file or directory"). Asterinas
//! already performs L3 forwarding between its bridge/veth interfaces, so this is
//! a writable stub: it stores and reports the flag but does not gate the
//! (already-active) forwarding datapath. Enough for the plugin to proceed.

use core::sync::atomic::{AtomicU32, Ordering};

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            ProcDir, StaticEntry,
            template::{
                ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry, listed_entries_from_table,
                lookup_child_from_table, read_i32_from, visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
};

// IP forwarding is effectively always on (Asterinas forwards between its
// bridge/veth interfaces), so default the flag to 1 to reflect that.
static IP_FORWARD: AtomicU32 = AtomicU32::new(1);

/// Represents the inode at `/proc/sys/net/ipv4`.
pub struct Ipv4DirOps;

impl Ipv4DirOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] =
        &[("ip_forward", InodeType::File, ip_forward_inode)];
}

impl ProcDirOps for Ipv4DirOps {
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

/// The writable `ip_forward` flag: stores and reports the value written; the
/// actual forwarding datapath is active regardless of this flag.
struct IpForwardFileOps;

impl ProcFileOps for IpForwardFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{}", IP_FORWARD.load(Ordering::Relaxed))?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        let (val, read_bytes) = read_i32_from(reader)?;
        IP_FORWARD.store(val.max(0) as u32, Ordering::Relaxed);
        Ok(read_bytes)
    }
}

fn ip_forward_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    ProcFile::new(IpForwardFileOps, parent, mkmod!(a+r, u+w))
}
