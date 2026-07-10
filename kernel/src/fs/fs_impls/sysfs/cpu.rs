// SPDX-License-Identifier: MPL-2.0

//! A minimal `/sys/devices/system/cpu` topology.
//!
//! cAdvisor (used by the kubelet) counts CPUs by globbing
//! `/sys/devices/system/cpu/cpu[0-9]*` and reading each one's
//! `topology/physical_package_id` and `core_id`. Without this it reports
//! `NumCores: 0`, and the kubelet then aborts with "could not detect number of
//! cpus". Only the fields those tools require are populated; all CPUs are
//! reported as single-threaded cores of one physical package.

use alloc::{borrow::Cow, format};

use aster_systree::{
    BranchNodeFields, Error as SysTreeError, NormalNodeFields, Result as SysTreeResult,
    SysAttrSetBuilder, SysObj, SysPerms, inherit_sys_branch_node, inherit_sys_leaf_node,
};
use aster_util::printer::VmPrinter;
use ostd::cpu::num_cpus;

use crate::prelude::*;

/// A read-only sysfs directory that can hold children and static attribute files.
#[derive(Debug)]
struct StaticBranch {
    fields: BranchNodeFields<dyn SysObj, Self>,
    values: BTreeMap<String, String>,
}

impl StaticBranch {
    fn new(name: &str, attrs: &[(&str, &str)]) -> Arc<Self> {
        let (attr_set, values) = build_attrs(attrs);
        Arc::new_cyclic(|weak_self| StaticBranch {
            fields: BranchNodeFields::new(name.to_string().into(), attr_set, weak_self.clone()),
            values,
        })
    }

    fn add(&self, child: Arc<dyn SysObj>) {
        self.fields
            .add_child(child)
            .expect("failed to add sysfs child");
    }
}

inherit_sys_branch_node!(StaticBranch, fields, {
    fn read_attr_at(
        &self,
        name: &str,
        offset: usize,
        writer: &mut VmWriter,
    ) -> SysTreeResult<usize> {
        read_static_attr(&self.values, name, offset, writer)
    }

    fn write_attr(&self, _name: &str, _reader: &mut VmReader) -> SysTreeResult<usize> {
        Err(SysTreeError::PermissionDenied)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

/// A read-only sysfs leaf directory holding static attribute files (no children).
#[derive(Debug)]
struct StaticLeaf {
    fields: NormalNodeFields<Self>,
    values: BTreeMap<String, String>,
}

impl StaticLeaf {
    fn new(name: &str, attrs: &[(&str, &str)]) -> Arc<Self> {
        let (attr_set, values) = build_attrs(attrs);
        Arc::new_cyclic(|weak_self| StaticLeaf {
            fields: NormalNodeFields::new(name.to_string().into(), attr_set, weak_self.clone()),
            values,
        })
    }
}

inherit_sys_leaf_node!(StaticLeaf, fields, {
    fn read_attr_at(
        &self,
        name: &str,
        offset: usize,
        writer: &mut VmWriter,
    ) -> SysTreeResult<usize> {
        read_static_attr(&self.values, name, offset, writer)
    }

    fn write_attr(&self, _name: &str, _reader: &mut VmReader) -> SysTreeResult<usize> {
        Err(SysTreeError::PermissionDenied)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

fn build_attrs(attrs: &[(&str, &str)]) -> (aster_systree::SysAttrSet, BTreeMap<String, String>) {
    let mut builder = SysAttrSetBuilder::new();
    let mut values = BTreeMap::new();
    for (key, value) in attrs {
        builder.add(
            Cow::Owned((*key).to_string()),
            SysPerms::DEFAULT_RO_ATTR_PERMS,
        );
        values.insert((*key).to_string(), (*value).to_string());
    }
    let attr_set = builder.build().expect("failed to build sysfs attr set");
    (attr_set, values)
}

fn read_static_attr(
    values: &BTreeMap<String, String>,
    name: &str,
    offset: usize,
    writer: &mut VmWriter,
) -> SysTreeResult<usize> {
    let value = values.get(name).ok_or(SysTreeError::NotFound)?;
    let mut printer = VmPrinter::new_skip(writer, offset);
    write!(printer, "{}\n", value)?;
    Ok(printer.bytes_written())
}

pub(super) fn init() {
    let n = num_cpus().max(1);
    let last = n - 1;
    // A CPU list, e.g. "0" for one CPU or "0-3" for four.
    let list = if last == 0 {
        "0".to_string()
    } else {
        format!("0-{}", last)
    };
    let kernel_max = last.to_string();

    let cpu = StaticBranch::new(
        "cpu",
        &[
            ("online", list.as_str()),
            ("possible", list.as_str()),
            ("present", list.as_str()),
            ("kernel_max", kernel_max.as_str()),
        ],
    );

    // Each CPU is a single-threaded core of one physical package: distinct
    // core_id per CPU, shared physical_package_id, so tools count `n` cores.
    for i in 0..n {
        let core_id = i.to_string();
        let thread_siblings = i.to_string();
        let topology = StaticLeaf::new(
            "topology",
            &[
                ("core_id", core_id.as_str()),
                ("physical_package_id", "0"),
                ("core_siblings_list", list.as_str()),
                ("thread_siblings_list", thread_siblings.as_str()),
            ],
        );
        let cpu_i = StaticBranch::new(&format!("cpu{}", i), &[("online", "1")]);
        cpu_i.add(topology as Arc<dyn SysObj>);
        cpu.add(cpu_i as Arc<dyn SysObj>);
    }

    let system = StaticBranch::new("system", &[]);
    system.add(cpu as Arc<dyn SysObj>);
    let devices = StaticBranch::new("devices", &[]);
    devices.add(system as Arc<dyn SysObj>);

    super::systree_singleton()
        .root()
        .add_child(devices as Arc<dyn SysObj>)
        .expect("failed to register /sys/devices");
}
