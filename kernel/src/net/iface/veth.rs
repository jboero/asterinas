// SPDX-License-Identifier: MPL-2.0

//! Creation of veth interface pairs.
//!
//! A veth pair connects two network namespaces: a packet sent out one end is
//! received on the other. This is the mechanism a container runtime uses to wire
//! a pod's network namespace to the host.

use alloc::{boxed::Box, string::String, sync::Arc};

use aster_bigtcp::{
    device::{VethChannel, VethDevice, WithDevice},
    iface::{InterfaceFlags, InterfaceType},
    wire::Ipv4Cidr,
};
use ostd::{sync::SpinLock, timer::Jiffies};

use super::{Iface, poll::spawn_poll_thread, sched::PollScheduler};

/// A `WithDevice` wrapper holding a veth device behind a lock.
struct VethWrapper(SpinLock<VethDevice>);

impl WithDevice for VethWrapper {
    type Device = VethDevice;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        f(&mut self.0.lock())
    }
}

/// Creates a connected veth pair and returns both ends as interfaces, each
/// already driven by its own polling thread.
///
/// A frame transmitted on one end is received on the other. The caller assigns
/// each end to a network namespace.
pub(in crate::net) fn new_veth_pair(
    a_name: String,
    a_cidr: Ipv4Cidr,
    b_name: String,
    b_cidr: Ipv4Cidr,
) -> (Arc<Iface>, Arc<Iface>) {
    use aster_bigtcp::iface::IpIface;

    let channel = VethChannel::new();

    // veth ends are administratively up point-to-point links.
    let flags = InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::LOWER_UP;

    let iface_a = IpIface::new(
        VethWrapper(SpinLock::new(channel.device_a())),
        a_cidr,
        None,
        a_name,
        PollScheduler::new(),
        InterfaceType::ETHER,
        flags,
    ) as Arc<Iface>;
    let iface_b = IpIface::new(
        VethWrapper(SpinLock::new(channel.device_b())),
        b_cidr,
        None,
        b_name,
        PollScheduler::new(),
        InterfaceType::ETHER,
        flags,
    ) as Arc<Iface>;

    // Wire each end's "please poll me" notifier to the peer interface, so a frame
    // transmitted on one end wakes the other end's polling thread.
    let weak_a = Arc::downgrade(&iface_a);
    let weak_b = Arc::downgrade(&iface_b);
    channel.set_notifiers(
        Box::new(move || schedule_poll(&weak_a)),
        Box::new(move || schedule_poll(&weak_b)),
    );

    spawn_poll_thread(iface_a.clone());
    spawn_poll_thread(iface_b.clone());

    (iface_a, iface_b)
}

/// Requests that the interface referenced by `weak` poll as soon as possible.
fn schedule_poll(weak: &alloc::sync::Weak<Iface>) {
    use aster_bigtcp::iface::ScheduleNextPoll;

    if let Some(iface) = weak.upgrade() {
        let now = Jiffies::elapsed().as_duration().as_millis() as u64;
        iface.sched_poll().schedule_next_poll(Some(now));
    }
}
