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

    // The hub tags every frame it cannot deliver locally with its own id, so the
    // router never forwards a frame back to the bridge it came from.
    hub.set_id(iface.index());
    register_bridge(iface.index(), iface.clone(), hub.clone());
    ensure_router_installed();

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

/// All bridges, keyed by the interface index of the bridge's own interface.
/// Each entry keeps the bridge's interface (so the router can read its live
/// subnet) and its hub. Bridges are never removed in v1.
static BRIDGES: Once<SpinLock<Vec<(u32, Arc<Iface>, Arc<BridgeHub>)>>> = Once::new();

fn bridges() -> &'static SpinLock<Vec<(u32, Arc<Iface>, Arc<BridgeHub>)>> {
    BRIDGES.call_once(|| SpinLock::new(Vec::new()))
}

fn register_bridge(index: u32, iface: Arc<Iface>, hub: Arc<BridgeHub>) {
    bridges().lock().push((index, iface, hub));
}

/// Looks up the hub of the bridge whose interface has the given index.
pub(in crate::net) fn bridge_hub_by_index(index: u32) -> Option<Arc<BridgeHub>> {
    bridges()
        .lock()
        .iter()
        .find(|(bridge_index, _, _)| *bridge_index == index)
        .map(|(_, _, hub)| hub.clone())
}

/// Installs the global inter-bridge L3 router on first use. The router makes the
/// host namespace forward between its bridges: a frame a bridge cannot deliver
/// to one of its own pods is handed to the sibling bridge whose subnet owns the
/// destination, giving pods on different subnets reachability — the foundation
/// for masquerade and multi-node overlays. Idempotent.
fn ensure_router_installed() {
    aster_bigtcp::device::set_router(Box::new(route_between_bridges));
}

/// The router body: forward `frame` to the sibling bridge (not `from_id`) whose
/// subnet contains the frame's IPv4 destination. Returns whether it forwarded.
fn route_between_bridges(from_id: u32, frame: &[u8]) -> bool {
    let Some(dst) = ipv4_dst(frame) else {
        return false;
    };

    // Find a different bridge that owns the destination subnet, clone its hub,
    // and release the registry lock before forwarding (which locks that hub).
    let target = {
        let bridges = bridges().lock();
        bridges
            .iter()
            .find(|(index, iface, _)| *index != from_id && iface_subnet_contains(iface, dst))
            .map(|(_, _, hub)| hub.clone())
    };
    let Some(hub) = target else {
        return false;
    };
    hub.forward_from_local(frame.to_vec());
    true
}

/// The IPv4 destination address of `frame`, or `None` if it is not IPv4 or is
/// too short.
fn ipv4_dst(frame: &[u8]) -> Option<Ipv4Address> {
    if frame.len() < 20 || frame[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Address::new(
        frame[16], frame[17], frame[18], frame[19],
    ))
}

/// Whether `addr` falls within the IPv4 subnet currently configured on `iface`.
fn iface_subnet_contains(iface: &Arc<Iface>, addr: Ipv4Address) -> bool {
    let (Some(local), Some(prefix)) = (iface.ipv4_addr(), iface.prefix_len()) else {
        return false;
    };
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(local) & mask) == (u32::from(addr) & mask)
}
