// SPDX-License-Identifier: MPL-2.0

//! Creation of bridge interfaces and their member veth ports.
//!
//! A bridge is an L3 forwarding hub (see [`aster_bigtcp::device::BridgeHub`]):
//! veth links carry raw IP packets, so the hub learns and routes by IPv4
//! address rather than by MAC. [`new_bridge`] creates the hub together with the
//! bridge's own interface in the host namespace (which typically owns the
//! gateway address), and [`new_veth_on_bridge`] attaches a pod-end interface to
//! an existing hub.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use aster_bigtcp::{
    device::{BridgeHub, BridgeLocalDevice, BridgePortDevice, WithDevice},
    iface::{InterfaceFlags, InterfaceType},
    wire::{Ipv4Address, Ipv4Cidr},
};
use ostd::sync::SpinLock;
use spin::Once;

use super::{Iface, poll::spawn_poll_thread, sched::PollScheduler, veth::schedule_poll};

/// A `WithDevice` wrapper holding the bridge's local device behind a lock.
struct LocalWrapper(SpinLock<BridgeLocalDevice>);

impl WithDevice for LocalWrapper {
    type Device = BridgeLocalDevice;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        f(&mut self.0.lock())
    }
}

/// A `WithDevice` wrapper holding a bridge port device behind a lock.
struct PortWrapper(SpinLock<BridgePortDevice>);

impl WithDevice for PortWrapper {
    type Device = BridgePortDevice;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        f(&mut self.0.lock())
    }
}

/// Creates a bridge: a forwarding hub plus the bridge's own interface, already
/// driven by its own polling thread and registered for [`bridge_hub_by_index`]
/// lookup.
///
/// The interface starts unaddressed (0.0.0.0/0); the caller assigns the
/// gateway address afterwards. The hub is returned so that the caller can
/// attach pod ports to it via [`new_veth_on_bridge`].
pub(in crate::net) fn new_bridge(name: String) -> (Arc<Iface>, Arc<BridgeHub>) {
    use aster_bigtcp::iface::IpIface;

    let hub = BridgeHub::new();
    let device = hub.local_device();

    // Like veth ends, a bridge is an administratively up software link.
    let flags = InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::LOWER_UP;

    let iface = IpIface::new(
        LocalWrapper(SpinLock::new(device)),
        Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0),
        None,
        name,
        PollScheduler::new(),
        InterfaceType::ETHER,
        flags,
    ) as Arc<Iface>;

    // The local receive queue holds frames toward the bridge's own interface,
    // so its notifier wakes this interface's polling thread.
    let weak = Arc::downgrade(&iface);
    hub.set_local_notifier(Box::new(move || schedule_poll(&weak)));

    spawn_poll_thread(iface.clone());

    register_bridge(iface.index(), hub.clone());

    (iface, hub)
}

/// Attaches a new pod-end interface to `hub` and returns it, already driven by
/// its own polling thread.
///
/// The caller places the returned interface into the pod's network namespace.
pub(in crate::net) fn new_veth_on_bridge(
    hub: &Arc<BridgeHub>,
    pod_name: String,
    pod_cidr: Ipv4Cidr,
) -> Arc<Iface> {
    use aster_bigtcp::iface::IpIface;

    let (port, port_device) = hub.add_port();

    let flags = InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::LOWER_UP;

    let iface = IpIface::new(
        PortWrapper(SpinLock::new(port_device)),
        pod_cidr,
        None,
        pod_name,
        PollScheduler::new(),
        InterfaceType::ETHER,
        flags,
    ) as Arc<Iface>;

    // A port's receive queue holds frames travelling TOWARD the pod, so the
    // port notifier must wake this pod-end interface, not the bridge's.
    let weak = Arc::downgrade(&iface);
    hub.set_port_notifier(port, Box::new(move || schedule_poll(&weak)));

    spawn_poll_thread(iface.clone());

    iface
}

/// All bridge hubs, keyed by the interface index of the bridge's own
/// interface. Bridges are never removed in v1.
static BRIDGES: Once<SpinLock<Vec<(u32, Arc<BridgeHub>)>>> = Once::new();

fn bridges() -> &'static SpinLock<Vec<(u32, Arc<BridgeHub>)>> {
    BRIDGES.call_once(|| SpinLock::new(Vec::new()))
}

fn register_bridge(index: u32, hub: Arc<BridgeHub>) {
    bridges().lock().push((index, hub));
}

/// Looks up the hub of the bridge whose interface has the given index.
pub(in crate::net) fn bridge_hub_by_index(index: u32) -> Option<Arc<BridgeHub>> {
    bridges()
        .lock()
        .iter()
        .find(|(bridge_index, _)| *bridge_index == index)
        .map(|(_, hub)| hub.clone())
}
