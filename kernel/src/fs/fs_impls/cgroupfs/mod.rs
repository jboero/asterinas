// SPDX-License-Identifier: MPL-2.0

pub use cgroup_ns::CgroupNamespace;
pub use controller::{
    cpu::{
        CpuStatKind, charge_cpu_bandwidth, charge_cpu_time, is_cpu_throttled,
        throttle_cpu_if_needed,
    },
    process_memory_max,
};
use fs::CgroupFsType;
pub(in crate::fs) use systree_node::CgroupSystem;
pub use systree_node::{CgroupMembership, CgroupNode, CgroupSysNode};

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "cgroup: "
    };
}

mod cgroup_ns;
mod controller;
mod fs;
mod inode;
mod systree_node;

// This method should be called during kernel file system initialization,
// _after_ `aster_systree::init`.
pub(super) fn init() {
    crate::fs::vfs::registry::register(&CgroupFsType).unwrap();
}
