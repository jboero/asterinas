// SPDX-License-Identifier: MPL-2.0

//! An L3 bridge hub connecting multiple veth-like ports.
//!
//! A [`BridgeHub`] forwards frames between a set of member *ports* (each backed
//! by a [`BridgePortDevice`], typically placed in a pod's network namespace) and
//! one *local* attachment (a [`BridgeLocalDevice`], the bridge's own interface
//! in the host namespace, which usually owns the gateway address).
//!
//! Unlike a classic L2 bridge, this hub operates at L3: veth links in this
//! kernel use [`Medium::Ip`], so frames are raw IPv4/IPv6 packets with no
//! Ethernet headers. There are no MACs to learn and no ARP to answer; instead
//! the hub learns the IPv4 *source addresses* seen on each port and routes by
//! IPv4 *destination address*. Frames the hub cannot route at L3 (including
//! anything that is not IPv4) are handed to the local stack, which can route or
//! discard them.
//!
//! Frames arriving from ports come from untrusted pods, so all parsing is
//! bounds-checked and malformed frames are forwarded to the local stack rather
//! than trusted.
//!
//! Queueing and wakeups mirror [`super::veth`]: each attachment has a receive
//! queue of frames travelling *toward* it and a [`VethNotifier`] that wakes the
//! interface draining that queue. The notifiers are set by the kernel after the
//! interfaces are built.

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use ostd::sync::SpinLock;
use smoltcp::{
    phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use spin::once::Once;

use super::{VethNotifier, veth::VETH_MTU};

/// The maximum number of frames queued toward one attachment.
///
/// Pods can transmit faster than their peers poll, so every receive queue is
/// capped; frames beyond the cap are dropped (tail drop), as the IP layer is
/// allowed to do.
const RX_QUEUE_CAP: usize = 64;

/// The maximum number of IPv4 addresses learned per port.
///
/// The oldest entry is evicted when the cap is reached, so a pod cannot grow
/// the table without bound by spoofing source addresses.
const MAX_LEARNED_ADDRS: usize = 16;

/// The minimum length of an IPv4 header, which is all the hub reads.
const IPV4_MIN_HEADER_LEN: usize = 20;

/// One member port of a [`BridgeHub`].
struct BridgePortInner {
    /// Frames travelling *toward* this port's pod, drained by the pod-end
    /// interface via [`BridgePortDevice::receive`].
    rx: SpinLock<VecDeque<Vec<u8>>>,
    /// Wakes the pod-end interface when `rx` becomes non-empty.
    notify: Once<VethNotifier>,
    /// IPv4 source addresses seen on frames from this port.
    learned: SpinLock<Vec<[u8; 4]>>,
}

impl BridgePortInner {
    fn new() -> Self {
        Self {
            rx: SpinLock::new(VecDeque::new()),
            notify: Once::new(),
            learned: SpinLock::new(Vec::new()),
        }
    }

    /// Records `addr` as reachable via this port, evicting the oldest entry if
    /// the table is full.
    fn learn(&self, addr: [u8; 4]) {
        let mut learned = self.learned.lock();
        if learned.contains(&addr) {
            return;
        }
        if learned.len() >= MAX_LEARNED_ADDRS {
            learned.remove(0);
        }
        learned.push(addr);
    }

    /// Returns whether `addr` has been learned on this port.
    fn knows(&self, addr: [u8; 4]) -> bool {
        self.learned.lock().contains(&addr)
    }

    /// Enqueues `frame` toward this port's pod and wakes its interface.
    fn deliver(&self, frame: Vec<u8>) {
        if enqueue(&self.rx, frame) {
            if let Some(notify) = self.notify.get() {
                notify();
            }
        }
    }
}

/// Pushes `frame` onto `rx` unless the queue is full. Returns whether the
/// frame was enqueued (a full queue tail-drops).
fn enqueue(rx: &SpinLock<VecDeque<Vec<u8>>>, frame: Vec<u8>) -> bool {
    let mut queue = rx.lock();
    if queue.len() >= RX_QUEUE_CAP {
        return false;
    }
    queue.push_back(frame);
    true
}

/// Extracts the IPv4 source and destination addresses of `frame`, or `None`
/// if the frame is too short to be IPv4 or its version nibble is not 4.
fn ipv4_src_dst(frame: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if frame.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    if frame[0] >> 4 != 4 {
        return None;
    }
    let src = [frame[12], frame[13], frame[14], frame[15]];
    let dst = [frame[16], frame[17], frame[18], frame[19]];
    Some((src, dst))
}

/// Returns whether `dst` must be flooded: the limited broadcast address
/// 255.255.255.255 or any multicast address (224.0.0.0/4).
fn is_flood_dst(dst: [u8; 4]) -> bool {
    dst == [255, 255, 255, 255] || dst[0] & 0xF0 == 0xE0
}

/// An L3 forwarding hub between member ports and a local stack attachment.
///
/// See the [module documentation](self) for the forwarding model.
pub struct BridgeHub {
    /// Member ports. Ports are append-only in v1: indices handed out by
    /// [`Self::add_port`] stay valid for the lifetime of the hub.
    ports: SpinLock<Vec<BridgePortInner>>,
    /// Frames travelling toward the bridge's own interface.
    local_rx: SpinLock<VecDeque<Vec<u8>>>,
    /// Wakes the bridge's own interface when `local_rx` becomes non-empty.
    local_notify: Once<VethNotifier>,
    /// Whether [`Self::local_device`] has already been called.
    local_device_taken: AtomicBool,
}

impl BridgeHub {
    /// Creates a new hub with no ports.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ports: SpinLock::new(Vec::new()),
            local_rx: SpinLock::new(VecDeque::new()),
            local_notify: Once::new(),
            local_device_taken: AtomicBool::new(false),
        })
    }

    /// Returns the device backing the bridge's own interface.
    ///
    /// This may be called only once per hub, since exactly one interface may
    /// drain the local receive queue.
    ///
    /// # Panics
    ///
    /// Panics if called a second time on the same hub.
    pub fn local_device(self: &Arc<Self>) -> BridgeLocalDevice {
        let taken = self.local_device_taken.swap(true, Ordering::AcqRel);
        assert!(
            !taken,
            "`BridgeHub::local_device` may only be called once per hub"
        );
        BridgeLocalDevice { hub: self.clone() }
    }

    /// Adds a new member port and returns its index along with the device
    /// backing the pod-end interface.
    pub fn add_port(self: &Arc<Self>) -> (usize, BridgePortDevice) {
        let mut ports = self.ports.lock();
        let index = ports.len();
        ports.push(BridgePortInner::new());
        (
            index,
            BridgePortDevice {
                hub: self.clone(),
                port: index,
            },
        )
    }

    /// Sets the notifier that wakes the bridge's own interface. It can be set
    /// only once.
    pub fn set_local_notifier(&self, notifier: VethNotifier) {
        self.local_notify.call_once(|| notifier);
    }

    /// Sets the notifier that wakes the pod-end interface of `port`. It can be
    /// set only once per port.
    ///
    /// # Panics
    ///
    /// Panics if `port` is not an index returned by [`Self::add_port`].
    pub fn set_port_notifier(&self, port: usize, notifier: VethNotifier) {
        let ports = self.ports.lock();
        ports[port].notify.call_once(|| notifier);
    }

    /// Forwards a frame transmitted by the pod attached to `src_port`.
    ///
    /// Frames from ports are untrusted; anything that does not parse as IPv4
    /// is handed to the local stack instead of being interpreted.
    pub fn forward_from_port(&self, src_port: usize, frame: Vec<u8>) {
        let ports = self.ports.lock();

        let Some((src, dst)) = ipv4_src_dst(&frame) else {
            // Not (plausibly) IPv4. The hub cannot route it, so let the local
            // stack decide what to do with it.
            drop(ports);
            self.deliver_to_local(frame);
            return;
        };

        // Learn the source so that later traffic destined to it can be
        // forwarded straight to this port.
        if let Some(port) = ports.get(src_port) {
            port.learn(src);
        }

        if is_flood_dst(dst) {
            // Broadcast/multicast: every other port and the local stack get a
            // copy.
            for (index, port) in ports.iter().enumerate() {
                if index != src_port {
                    port.deliver(frame.clone());
                }
            }
            drop(ports);
            self.deliver_to_local(frame);
            return;
        }

        // Unicast learned on another port goes straight there.
        for (index, port) in ports.iter().enumerate() {
            if index != src_port && port.knows(dst) {
                port.deliver(frame);
                return;
            }
        }

        // Unknown unicast from a port goes to the local stack: the bridge
        // interface owns the gateway address and routes everything off-bridge.
        drop(ports);
        self.deliver_to_local(frame);
    }

    /// Forwards a frame transmitted by the bridge's own interface.
    ///
    /// Source addresses are not learned here: the local stack is not a port,
    /// and traffic toward it already falls out of the port lookup.
    pub fn forward_from_local(&self, frame: Vec<u8>) {
        let ports = self.ports.lock();

        let Some((_src, dst)) = ipv4_src_dst(&frame) else {
            // Not (plausibly) IPv4; same fallback as for port traffic.
            drop(ports);
            self.deliver_to_local(frame);
            return;
        };

        if is_flood_dst(dst) {
            for port in ports.iter() {
                port.deliver(frame.clone());
            }
            return;
        }

        if let Some(port) = ports.iter().find(|port| port.knows(dst)) {
            port.deliver(frame);
            return;
        }

        // Unknown unicast from the gateway side floods like a hub (v1 choice):
        // the destination pod has not transmitted yet, so it has not been
        // learned; the wrong recipients drop the frame at their IP layer, and
        // the right one will answer and be learned.
        for port in ports.iter() {
            port.deliver(frame.clone());
        }
    }

    /// Enqueues `frame` toward the bridge's own interface and wakes it.
    fn deliver_to_local(&self, frame: Vec<u8>) {
        if enqueue(&self.local_rx, frame) {
            if let Some(notify) = self.local_notify.get() {
                notify();
            }
        }
    }

    fn capabilities() -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = VETH_MTU;
        caps.medium = Medium::Ip;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }
}

/// The pod end of a bridge port, exposed as a smoltcp [`Device`].
///
/// Receiving pops the port's receive queue; transmitting forwards the frame
/// through the hub.
pub struct BridgePortDevice {
    hub: Arc<BridgeHub>,
    port: usize,
}

impl Device for BridgePortDevice {
    type RxToken<'a> = BridgeRxToken;
    type TxToken<'a> = BridgePortTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        BridgeHub::capabilities()
    }

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = {
            let ports = self.hub.ports.lock();
            ports.get(self.port)?.rx.lock().pop_front()?
        };
        let rx = BridgeRxToken { buffer };
        let tx = BridgePortTxToken {
            hub: self.hub.clone(),
            port: self.port,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(BridgePortTxToken {
            hub: self.hub.clone(),
            port: self.port,
        })
    }
}

/// The bridge's own attachment, exposed as a smoltcp [`Device`].
///
/// Receiving pops the hub's local receive queue; transmitting forwards the
/// frame through the hub.
pub struct BridgeLocalDevice {
    hub: Arc<BridgeHub>,
}

impl Device for BridgeLocalDevice {
    type RxToken<'a> = BridgeRxToken;
    type TxToken<'a> = BridgeLocalTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        BridgeHub::capabilities()
    }

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.hub.local_rx.lock().pop_front()?;
        let rx = BridgeRxToken { buffer };
        let tx = BridgeLocalTxToken {
            hub: self.hub.clone(),
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(BridgeLocalTxToken {
            hub: self.hub.clone(),
        })
    }
}

#[doc(hidden)]
pub struct BridgeRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for BridgeRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
pub struct BridgePortTxToken {
    hub: Arc<BridgeHub>,
    port: usize,
}

impl phy::TxToken for BridgePortTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        // A frame transmitted by the pod enters the hub for forwarding.
        self.hub.forward_from_port(self.port, buffer);

        result
    }
}

#[doc(hidden)]
pub struct BridgeLocalTxToken {
    hub: Arc<BridgeHub>,
}

impl phy::TxToken for BridgeLocalTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        // A frame transmitted by the bridge's own stack enters the hub for
        // forwarding toward the ports.
        self.hub.forward_from_local(buffer);

        result
    }
}
