// SPDX-License-Identifier: MPL-2.0

//! `/proc/sys/net/netfilter` — connection-tracking tunables.
//!
//! kube-proxy reads and writes these on startup (e.g. it sets
//! `nf_conntrack_tcp_timeout_established` and `nf_conntrack_max`) and aborts if
//! they are missing. Asterinas has no real conntrack, so these are stub sysctls:
//! writable counters that store and report a value but do not affect any
//! datapath. Enough for kube-proxy to configure conntrack and proceed.

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

// Backing storage for the writable tunables, with Linux's default values.
static NF_CONNTRACK_MAX: AtomicU32 = AtomicU32::new(262144);
static NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED: AtomicU32 = AtomicU32::new(432000);
static NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT: AtomicU32 = AtomicU32::new(60);
static NF_CONNTRACK_TCP_BE_LIBERAL: AtomicU32 = AtomicU32::new(0);

/// Represents the inode at `/proc/sys/net/netfilter`.
pub struct NetfilterDirOps;

impl NetfilterDirOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        ("nf_conntrack_max", InodeType::File, max_inode),
        (
            "nf_conntrack_tcp_timeout_established",
            InodeType::File,
            tcp_established_inode,
        ),
        (
            "nf_conntrack_tcp_timeout_close_wait",
            InodeType::File,
            tcp_close_wait_inode,
        ),
        (
            "nf_conntrack_tcp_be_liberal",
            InodeType::File,
            tcp_be_liberal_inode,
        ),
        ("nf_conntrack_count", InodeType::File, count_inode),
        ("nf_conntrack_buckets", InodeType::File, buckets_inode),
    ];
}

impl ProcDirOps for NetfilterDirOps {
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

/// A writable `u32` sysctl backed by a static counter (no datapath effect).
struct ConntrackValueFileOps {
    value: &'static AtomicU32,
    writable: bool,
}

impl ConntrackValueFileOps {
    fn new_inode(
        value: &'static AtomicU32,
        writable: bool,
        parent: Weak<dyn Inode>,
    ) -> Arc<dyn Inode> {
        let mode = if writable {
            mkmod!(a+r, u+w)
        } else {
            mkmod!(a+r)
        };
        ProcFile::new(Self { value, writable }, parent, mode)
    }
}

impl ProcFileOps for ConntrackValueFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{}", self.value.load(Ordering::Relaxed))?;
        Ok(printer.bytes_written())
    }

    fn write_at(&self, _offset: usize, reader: &mut VmReader) -> Result<usize> {
        if !self.writable {
            return_errno_with_message!(Errno::EPERM, "this conntrack sysctl is read-only");
        }
        let (val, read_bytes) = read_i32_from(reader)?;
        // Conntrack tunables are non-negative; store and report what was written.
        self.value.store(val.max(0) as u32, Ordering::Relaxed);
        Ok(read_bytes)
    }
}

fn max_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_MAX, true, parent)
}

fn tcp_established_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED, true, parent)
}

fn tcp_close_wait_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT, true, parent)
}

fn tcp_be_liberal_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_TCP_BE_LIBERAL, true, parent)
}

fn count_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    // Current tracked-connection count: always zero (no real conntrack).
    static NF_CONNTRACK_COUNT: AtomicU32 = AtomicU32::new(0);
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_COUNT, false, parent)
}

fn buckets_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
    static NF_CONNTRACK_BUCKETS: AtomicU32 = AtomicU32::new(65536);
    ConntrackValueFileOps::new_inode(&NF_CONNTRACK_BUCKETS, false, parent)
}
