// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use aster_systree::{Error, MAX_ATTR_SIZE, Result, SysAttrSetBuilder, SysPerms, SysStr};
use aster_util::{per_cpu_counter::PerCpuCounter, printer::VmPrinter};
use ostd::{
    cpu::CpuId,
    mm::{VmReader, VmWriter},
    sync::{LocalIrqDisabled, SpinLock, Waiter},
    task::atomic_mode::AsAtomicModeGuard,
    timer::Jiffies,
    warn,
};

use crate::{
    error::Errno,
    fs::cgroupfs::systree_node::{CgroupSysNode, CgroupSystem},
    process::{Process, signal::Pause},
    time::{clocks::MonotonicClock, timer::Timeout, wait::ManagedTimeout},
    util::ReadCString,
};

/// A sub-controller responsible for CPU resource management in the cgroup subsystem.
///
/// This controller always exists so that `cpu.stat` remains readable even before `+cpu`
/// is enabled. When inactive, only the base usage fields are exposed and the non-root
/// CPU control files are hidden.
pub struct CpuController {
    /// Persistent CPU usage accounting for this cgroup.
    stats: CpuStats,
    /// Optional CPU resource control attributes exposed only when `+cpu` is active.
    control: Option<CpuControl>,
}

/// CPU usage accounting that survives CPU controller toggles.
struct CpuStats {
    /// A counter accumulates CPU time spent executing user-space code.
    ///
    /// The counter is in units of one [`Jiffies`] per increment.
    user: PerCpuCounter,
    /// A counter accumulates CPU time spent executing kernel code on behalf of tasks.
    ///
    /// The counter is in units of one [`Jiffies`] per increment.
    system: PerCpuCounter,
}

/// CPU resource controls that are reset whenever `+cpu` is re-enabled.
struct CpuControl {
    /// A value stores the configured relative CPU share for scheduler integration.
    weight: AtomicU32,
    /// A value stores the configured CPU bandwidth limit for scheduler integration.
    ///
    /// Locked with IRQs disabled because the bandwidth budget is charged from the
    /// timer interrupt; without this, a process holding the lock could be
    /// interrupted by the timer on the same CPU and deadlock.
    max: SpinLock<CpuMax, LocalIrqDisabled>,
    /// The live bandwidth budget used to enforce `cpu.max`. Locked with IRQs
    /// disabled for the same reason as `max`.
    bandwidth: SpinLock<Bandwidth, LocalIrqDisabled>,
}

/// The live `cpu.max` bandwidth budget for the current period.
struct Bandwidth {
    /// Remaining CPU budget (microseconds) in the current period. May go slightly
    /// negative when a single tick overshoots the quota.
    runtime_remaining_usec: i64,
    /// Start of the current period, in milliseconds since boot. `0` forces a
    /// refill on first use.
    period_start_ms: u64,
}

/// A CPU bandwidth limit.
#[derive(Clone, Copy)]
struct CpuMax {
    /// The configured CPU runtime budget for bandwidth enforcement.
    quota_usec: u64,
    /// The window over which the CPU runtime budget is intended to apply.
    period_usec: u64,
}

/// Specifies the cgroup CPU sub-controller receives one [`Jiffies`] of charge.
#[derive(Clone, Copy)]
pub enum CpuStatKind {
    /// Charges one [`Jiffies`] to `user_usec`.
    User,
    /// Charges one [`Jiffies`] to `system_usec`.
    System,
}

impl CpuController {
    pub(super) fn init_attr_set(builder: &mut SysAttrSetBuilder, is_root: bool) {
        builder.add(SysStr::from("cpu.stat"), SysPerms::DEFAULT_RO_ATTR_PERMS);

        if !is_root {
            builder.add(SysStr::from("cpu.weight"), SysPerms::DEFAULT_RW_ATTR_PERMS);
            builder.add(SysStr::from("cpu.max"), SysPerms::DEFAULT_RW_ATTR_PERMS);
        }
    }

    fn new(is_active: bool) -> Self {
        Self {
            stats: CpuStats::new(),
            control: is_active.then(CpuControl::new),
        }
    }

    /// Initializes CPU usage statistics from the previous sub-controller.
    ///
    /// Toggling `+cpu` must reset some controller attributes such as `cpu.weight`
    /// and `cpu.max`, but `cpu.stat` remains visible and continues to report the
    /// accumulated CPU usage.
    pub(super) fn init_stats(&mut self, previous: &Self) {
        // No one cares which CPU the count is on. Therefore, choose the BSP for simplicity.
        self.stats.user.add_on_cpu(
            CpuId::bsp(),
            isize::try_from(previous.stats.user.sum_all_cpus()).unwrap_or(isize::MAX),
        );
        self.stats.system.add_on_cpu(
            CpuId::bsp(),
            isize::try_from(previous.stats.system.sum_all_cpus()).unwrap_or(isize::MAX),
        );
    }

    fn control(&self) -> Result<&CpuControl> {
        self.control.as_ref().ok_or(Error::AttributeError)
    }

    fn read_cpu_stat(&self, printer: &mut VmPrinter) -> Result<usize> {
        /// Converts a per-CPU counter expressed in jiffies to microseconds.
        fn counter_usec(counter: &PerCpuCounter) -> u64 {
            let jiffies = u64::try_from(counter.sum_all_cpus()).unwrap_or(u64::MAX);
            u64::try_from(Jiffies::new(jiffies).as_duration().as_micros()).unwrap_or(u64::MAX)
        }

        let user_usec = counter_usec(&self.stats.user);
        let system_usec = counter_usec(&self.stats.system);
        writeln!(
            printer,
            "usage_usec {}",
            user_usec.saturating_add(system_usec)
        )?;
        writeln!(printer, "user_usec {}", user_usec)?;
        writeln!(printer, "system_usec {}", system_usec)?;

        if self.control.is_some() {
            // TODO: Support CPU bandwidth control statistics. These fields are reported as `0`
            // for now because the cgroup CPU sub-controller does not yet implement throttling or
            // burst accounting.
            writeln!(printer, "nr_periods 0")?;
            writeln!(printer, "nr_throttled 0")?;
            writeln!(printer, "throttled_usec 0")?;
            writeln!(printer, "nr_bursts 0")?;
            writeln!(printer, "burst_usec 0")?;
        }

        Ok(printer.bytes_written())
    }

    /// Accounts one [`Jiffies`] of CPU time on `cpu`.
    fn account(&self, cpu: CpuId, stat_kind: CpuStatKind) {
        match stat_kind {
            CpuStatKind::User => self.stats.user.add_on_cpu(cpu, 1),
            CpuStatKind::System => self.stats.system.add_on_cpu(cpu, 1),
        }
    }
}

impl CpuControl {
    fn new() -> Self {
        // The default CPU weight is 100 and the default CPU bandwidth limit is
        // unlimited quota with a 100ms period.
        //
        // Reference: <https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files>
        const DEFAULT_WEIGHT: u32 = 100;
        const DEFAULT_QUOTA_USEC: u64 = u64::MAX;
        const DEFAULT_PERIOD_USEC: u64 = 100_000;

        Self {
            weight: AtomicU32::new(DEFAULT_WEIGHT),
            max: SpinLock::new(CpuMax {
                quota_usec: DEFAULT_QUOTA_USEC,
                period_usec: DEFAULT_PERIOD_USEC,
            }),
            bandwidth: SpinLock::new(Bandwidth {
                runtime_remaining_usec: 0,
                period_start_ms: 0,
            }),
        }
    }

    /// The current time in milliseconds since boot.
    fn now_ms() -> u64 {
        Jiffies::elapsed().as_duration().as_millis() as u64
    }

    /// Resets the budget to a full quota if the current period has elapsed.
    fn refill_if_elapsed(bw: &mut Bandwidth, max: &CpuMax, now_ms: u64) {
        let period_ms = (max.period_usec / 1000).max(1);
        if bw.period_start_ms == 0 || now_ms.saturating_sub(bw.period_start_ms) >= period_ms {
            bw.runtime_remaining_usec = max.quota_usec.min(i64::MAX as u64) as i64;
            bw.period_start_ms = now_ms;
        }
    }

    /// Charges `usec` microseconds of CPU time against the bandwidth budget.
    fn charge_bandwidth(&self, usec: u64) {
        let max = *self.max.lock();
        if max.quota_usec == u64::MAX {
            return; // unlimited; nothing to enforce
        }
        let now = Self::now_ms();
        let mut bw = self.bandwidth.lock();
        Self::refill_if_elapsed(&mut bw, &max, now);
        bw.runtime_remaining_usec -= usec as i64;
    }

    /// Returns the time remaining in the current period if the budget is
    /// exhausted (i.e. the cgroup is throttled), or `None` otherwise.
    fn throttle_remaining(&self) -> Option<Duration> {
        let max = *self.max.lock();
        if max.quota_usec == u64::MAX {
            return None; // unlimited; never throttled
        }
        let now = Self::now_ms();
        let mut bw = self.bandwidth.lock();
        Self::refill_if_elapsed(&mut bw, &max, now);
        if bw.runtime_remaining_usec > 0 {
            return None;
        }
        let period_ms = (max.period_usec / 1000).max(1);
        let period_end = bw.period_start_ms + period_ms;
        Some(Duration::from_millis(period_end.saturating_sub(now).max(1)))
    }
}

impl CpuStats {
    fn new() -> Self {
        Self {
            user: PerCpuCounter::new(),
            system: PerCpuCounter::new(),
        }
    }
}

impl super::SubControl for CpuController {
    fn is_attr_absent(&self, name: &str) -> bool {
        matches!(name, "cpu.weight" | "cpu.max") && self.control.is_none()
    }

    fn read_attr_at(&self, name: &str, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);

        match name {
            "cpu.stat" => return self.read_cpu_stat(&mut printer),
            "cpu.weight" => {
                let weight = self.control()?.weight.load(Ordering::Relaxed);
                writeln!(printer, "{}", weight)?;
            }
            "cpu.max" => {
                let max = *self.control()?.max.lock();
                if max.quota_usec == u64::MAX {
                    writeln!(printer, "max {}", max.period_usec)?;
                } else {
                    writeln!(printer, "{} {}", max.quota_usec, max.period_usec)?;
                }
            }
            _ => return Err(Error::AttributeError),
        }

        Ok(printer.bytes_written())
    }

    fn write_attr(&self, name: &str, reader: &mut VmReader) -> Result<usize> {
        match name {
            "cpu.weight" => {
                let control = self.control()?;

                // The cgroup v2 CPU weight is a scheduling weight in the range 1..=10000.
                //
                // Reference: <https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files>
                const MIN_WEIGHT: u32 = 1;
                const MAX_WEIGHT: u32 = 10_000;

                let (content, len) = reader
                    .read_cstring_until_end(MAX_ATTR_SIZE)
                    .map_err(|_| Error::PageFault)?;
                let weight = content
                    .to_str()
                    .map_err(|_| Error::InvalidOperation)?
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| Error::InvalidOperation)?;
                if !(MIN_WEIGHT..=MAX_WEIGHT).contains(&weight) {
                    return Err(Error::InvalidOperation);
                }

                // TODO: Enforce cgroup CPU weight for scheduling and remove this warning.
                warn!(
                    "`cpu.weight` is accepted but not enforced yet; weight = {}",
                    weight
                );
                control.weight.store(weight, Ordering::Relaxed);

                Ok(len)
            }
            "cpu.max" => {
                let control = self.control()?;

                // The cgroup v2 CPU bandwidth limit is `$MAX $PERIOD`, where `$MAX` is
                // either `max` or at least 1ms and `$PERIOD` is in the range 1ms..=1s.
                //
                // Reference: <https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files>
                const MIN_QUOTA_USEC: u64 = 1_000;
                const MIN_PERIOD_USEC: u64 = 1_000;
                const MAX_PERIOD_USEC: u64 = 1_000_000;

                let (content, len) = reader
                    .read_cstring_until_end(MAX_ATTR_SIZE)
                    .map_err(|_| Error::PageFault)?;
                let content = content
                    .to_str()
                    .map_err(|_| Error::InvalidOperation)?
                    .trim();
                let mut tokens = content.split_whitespace();

                let Some(quota_token) = tokens.next() else {
                    return Err(Error::InvalidOperation);
                };
                let period_token = tokens.next();

                // Check whether `quota_usec` is valid.
                let quota_usec = if quota_token == "max" {
                    u64::MAX
                } else if let Ok(quota_usec) = quota_token.parse::<u64>() {
                    if quota_usec < MIN_QUOTA_USEC {
                        return Err(Error::InvalidOperation);
                    }
                    quota_usec
                } else {
                    return Err(Error::InvalidOperation);
                };

                // Check whether `period_usec` is valid.
                let period_usec = if let Some(period_usec) =
                    period_token.and_then(|period_token| period_token.parse::<u64>().ok())
                {
                    if !(MIN_PERIOD_USEC..=MAX_PERIOD_USEC).contains(&period_usec) {
                        return Err(Error::InvalidOperation);
                    }
                    Some(period_usec)
                } else {
                    None
                };

                // TODO: Enforce CPU bandwidth throttling and remove this warning.
                warn!(
                    "`cpu.max` is accepted but not enforced yet; quota = {}, period = {:?}",
                    quota_usec, period_usec
                );
                let mut max = control.max.lock();
                max.quota_usec = quota_usec;
                if let Some(period_usec) = period_usec {
                    max.period_usec = period_usec;
                }

                Ok(len)
            }
            _ => Err(Error::AttributeError),
        }
    }
}

impl super::SubControlStatic for CpuController {
    fn new(is_root: bool, is_active: bool) -> Self {
        Self::new(is_root || is_active)
    }

    fn type_() -> super::SubCtrlType {
        super::SubCtrlType::Cpu
    }

    fn read_from(controller: &super::Controller) -> Arc<super::SubController<Self>> {
        controller.cpu.read().get().clone()
    }
}

impl super::SubController<CpuController> {
    /// Charges `usec` microseconds of CPU bandwidth to this cgroup, if its CPU
    /// control is active.
    fn charge_bandwidth(&self, usec: u64) {
        if let Some(inner) = self.inner.as_ref()
            && let Ok(control) = inner.control()
        {
            control.charge_bandwidth(usec);
        }
    }

    /// Returns the throttle deadline for this cgroup, if it is over its
    /// `cpu.max` budget.
    fn throttle_remaining(&self) -> Option<Duration> {
        self.inner.as_ref()?.control().ok()?.throttle_remaining()
    }

    /// Accounts one [`Jiffies`] of CPU time for this cgroup and all of its ancestors.
    fn account_hierarchy(&self, stat_kind: CpuStatKind) {
        // This is race-free because `charge_cpu_time` holds `cgroup_guard` when
        // invoking this method.
        let cpu = CpuId::current_racy();

        let mut current = Some(self);
        while let Some(node) = current {
            node.inner.as_ref().unwrap().account(cpu, stat_kind);
            current = node.parent.as_deref();
        }
    }
}

impl super::Controller {
    /// Charges one [`Jiffies`] in the CPU sub-controller hierarchy.
    fn charge_cpu_time<G: AsAtomicModeGuard + ?Sized>(&self, guard: &G, stat_kind: CpuStatKind) {
        self.cpu.read_with(guard).account_hierarchy(stat_kind);
    }

    /// Charges `usec` microseconds of CPU bandwidth to this cgroup's `cpu.max`
    /// budget.
    fn charge_cpu_bandwidth(&self, usec: u64) {
        self.cpu.read().get().charge_bandwidth(usec);
    }

    /// Returns the throttle deadline if this cgroup is over its `cpu.max` budget.
    fn cpu_throttle_remaining(&self) -> Option<Duration> {
        self.cpu.read().get().throttle_remaining()
    }
}

/// Charges one [`Jiffies`] of CPU time to `process`'s cgroup hierarchy.
///
/// If `process` is not attached to a non-root cgroup, the charge is applied to the root cgroup.
pub fn charge_cpu_time(process: &Process, stat_kind: CpuStatKind) {
    let cgroup_guard = process.cgroup();

    if let Some(cgroup) = cgroup_guard.get() {
        cgroup
            .controller()
            .charge_cpu_time(&cgroup_guard, stat_kind);
    } else {
        CgroupSystem::singleton()
            .controller()
            .charge_cpu_time(&cgroup_guard, stat_kind);
    }
}

/// Charges `usec` microseconds of CPU bandwidth to `process`'s cgroup for
/// `cpu.max` enforcement. The root cgroup has no quota, so nothing is charged.
pub fn charge_cpu_bandwidth(process: &Process, usec: u64) {
    let cgroup_guard = process.cgroup();
    if let Some(cgroup) = cgroup_guard.get() {
        cgroup.controller().charge_cpu_bandwidth(usec);
    }
}

/// Returns whether `process`'s cgroup is currently over its `cpu.max` budget.
///
/// This is used as a kernel-event condition so that an over-budget task promptly
/// returns from user space to a safe point where it can be throttled, instead of
/// running a full scheduler time slice first. Root and unlimited cgroups are
/// never throttled.
pub fn is_cpu_throttled(process: &Process) -> bool {
    let cgroup_guard = process.cgroup();
    let Some(cgroup) = cgroup_guard.get() else {
        return false;
    };
    cgroup.controller().cpu_throttle_remaining().is_some()
}

/// Blocks the calling thread while `process`'s cgroup is over its `cpu.max`
/// budget, returning once the budget refills (or the sleep is interrupted by a
/// signal). Processes in the root cgroup or with an unlimited `cpu.max` return
/// immediately, so the init process and ordinary processes are never throttled.
pub fn throttle_cpu_if_needed(process: &Process) {
    loop {
        // Compute the throttle deadline without holding the RCU guard across the
        // sleep below.
        let remaining = {
            let cgroup_guard = process.cgroup();
            let Some(cgroup) = cgroup_guard.get() else {
                return;
            };
            cgroup.controller().cpu_throttle_remaining()
        };
        let Some(remaining) = remaining else {
            return; // not throttled
        };

        // Sleep until the period boundary, then re-check; by then the period has
        // elapsed and the budget refills.
        let waiter = Waiter::new_pair().0;
        let res = waiter.pause_until_or_timeout(
            || None::<()>,
            ManagedTimeout::new_with_manager(
                Timeout::After(remaining),
                MonotonicClock::timer_manager(),
            ),
        );
        // A signal (e.g. SIGKILL) must not be swallowed by throttling: let the
        // caller handle it instead of sleeping again.
        if matches!(res, Err(err) if err.error() == Errno::EINTR) {
            return;
        }
    }
}
