// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use aster_systree::{Error, MAX_ATTR_SIZE, Result, SysAttrSetBuilder, SysPerms, SysStr};
use aster_util::printer::VmPrinter;
use ostd::mm::{VmReader, VmWriter};

use crate::util::ReadCString;

/// A sub-controller responsible for memory resource management in the cgroup subsystem.
///
/// The controller stores the configured memory limits (`memory.max`, `memory.high`,
/// `memory.min`, `memory.low`, `memory.swap.max`) so that a container runtime (such as
/// a Kubernetes node agent) can build and configure its cgroup hierarchy. `memory.max`
/// is *enforced* at anonymous-page commit time (see `vm::vmar::vm_mapping`): a process
/// that exceeds a finite, non-root limit is killed. Full usage *accounting* is not yet
/// implemented — `memory.current` still reports `0`, and `memory.high`/`min`/`low` are
/// recorded but do not yet throttle or trigger reclaim. The interface shape matches
/// cgroup v2 so that user space sees a consistent and writable set of files.
///
/// Reference: <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files>
pub struct MemoryController {
    /// The hard memory usage limit (`memory.max`); `u64::MAX` means "max".
    max: AtomicU64,
    /// The memory throttling limit (`memory.high`); `u64::MAX` means "max".
    high: AtomicU64,
    /// The hard memory protection (`memory.min`).
    min: AtomicU64,
    /// The best-effort memory protection (`memory.low`).
    low: AtomicU64,
    /// The hard swap usage limit (`memory.swap.max`); `u64::MAX` means "max".
    swap_max: AtomicU64,
    /// The OOM group flag (`memory.oom.group`, 0 or 1): when set, the cgroup is
    /// killed as a single unit by the OOM killer. Stored for interface
    /// compatibility — runc writes it during container init (a missing file
    /// aborts `runc create`) — but not enforced (no cgroup-aware OOM killer yet).
    oom_group: AtomicU64,
}

/// The sentinel value that the cgroup v2 interface renders as the string "max".
const LIMIT_MAX: u64 = u64::MAX;

impl MemoryController {
    pub(super) fn init_attr_set(builder: &mut SysAttrSetBuilder, is_root: bool) {
        // These attributes only exist on the non-root cgroup nodes.
        //
        // Reference: <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files>
        if !is_root {
            builder.add(
                SysStr::from("memory.current"),
                SysPerms::DEFAULT_RO_ATTR_PERMS,
            );
            builder.add(SysStr::from("memory.min"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("memory.low"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("memory.high"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("memory.max"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(
                SysStr::from("memory.swap.current"),
                SysPerms::DEFAULT_RO_ATTR_PERMS,
            );
            builder.add(
                SysStr::from("memory.swap.max"),
                SysPerms::DEFAULT_RW_ATTR_PERMS,
            );
            builder.add(
                SysStr::from("memory.events"),
                SysPerms::DEFAULT_RO_ATTR_PERMS,
            );
            builder.add(SysStr::from("memory.stat"), SysPerms::DEFAULT_RO_ATTR_PERMS);
            builder.add(
                SysStr::from("memory.oom.group"),
                SysPerms::DEFAULT_RW_ATTR_PERMS,
            );
        }
    }

    /// Returns the configured `memory.max` (`u64::MAX` means unlimited).
    pub(super) fn max_limit(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    fn limit(&self, name: &str) -> Option<&AtomicU64> {
        match name {
            "memory.max" => Some(&self.max),
            "memory.high" => Some(&self.high),
            "memory.min" => Some(&self.min),
            "memory.low" => Some(&self.low),
            "memory.swap.max" => Some(&self.swap_max),
            _ => None,
        }
    }
}

impl super::SubControl for MemoryController {
    fn read_attr_at(&self, name: &str, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        match name {
            "memory.current" | "memory.swap.current" => {
                // Usage accounting is not implemented yet.
                writeln!(printer, "0")?;
            }
            "memory.min" | "memory.low" => {
                let value = self.limit(name).unwrap().load(Ordering::Relaxed);
                writeln!(printer, "{}", value)?;
            }
            "memory.max" | "memory.high" | "memory.swap.max" => {
                let value = self.limit(name).unwrap().load(Ordering::Relaxed);
                if value == LIMIT_MAX {
                    writeln!(printer, "max")?;
                } else {
                    writeln!(printer, "{}", value)?;
                }
            }
            "memory.events" => {
                // No reclaim or OOM events are generated without enforcement.
                writeln!(printer, "low 0")?;
                writeln!(printer, "high 0")?;
                writeln!(printer, "max 0")?;
                writeln!(printer, "oom 0")?;
                writeln!(printer, "oom_kill 0")?;
            }
            "memory.stat" => {
                // A minimal but well-formed subset; all counters are zero until
                // usage accounting lands.
                writeln!(printer, "anon 0")?;
                writeln!(printer, "file 0")?;
                writeln!(printer, "kernel 0")?;
                writeln!(printer, "slab 0")?;
                writeln!(printer, "sock 0")?;
            }
            "memory.oom.group" => {
                writeln!(printer, "{}", self.oom_group.load(Ordering::Relaxed))?;
            }
            _ => return Err(Error::AttributeError),
        }

        Ok(printer.bytes_written())
    }

    fn write_attr(&self, name: &str, reader: &mut VmReader) -> Result<usize> {
        // `memory.oom.group` is a 0/1 flag rather than a byte limit.
        if name == "memory.oom.group" {
            let (content, len) = reader
                .read_cstring_until_end(MAX_ATTR_SIZE)
                .map_err(|_| Error::PageFault)?;
            let value = content
                .to_str()
                .map_err(|_| Error::InvalidOperation)?
                .trim();
            let parsed = value.parse::<u64>().map_err(|_| Error::InvalidOperation)?;
            self.oom_group.store(parsed, Ordering::Relaxed);
            return Ok(len);
        }

        let Some(limit) = self.limit(name) else {
            return Err(Error::AttributeError);
        };

        let (content, len) = reader
            .read_cstring_until_end(MAX_ATTR_SIZE)
            .map_err(|_| Error::PageFault)?;
        let value = content
            .to_str()
            .map_err(|_| Error::InvalidOperation)?
            .trim();

        // `memory.min` and `memory.low` are protections and have no "max" form;
        // the limit files accept the literal "max" sentinel.
        let parsed = if value == "max" && name != "memory.min" && name != "memory.low" {
            LIMIT_MAX
        } else {
            value.parse::<u64>().map_err(|_| Error::InvalidOperation)?
        };

        limit.store(parsed, Ordering::Relaxed);
        Ok(len)
    }
}

impl super::SubControlStatic for MemoryController {
    fn new(_is_root: bool, _is_active: bool) -> Self {
        Self {
            max: AtomicU64::new(LIMIT_MAX),
            high: AtomicU64::new(LIMIT_MAX),
            min: AtomicU64::new(0),
            low: AtomicU64::new(0),
            swap_max: AtomicU64::new(LIMIT_MAX),
            oom_group: AtomicU64::new(0),
        }
    }

    fn type_() -> super::SubCtrlType {
        super::SubCtrlType::Memory
    }

    fn read_from(controller: &super::Controller) -> Arc<super::SubController<Self>> {
        controller.memory.read().get().clone()
    }
}
