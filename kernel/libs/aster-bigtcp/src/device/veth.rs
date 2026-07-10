// SPDX-License-Identifier: MPL-2.0

//! A virtual Ethernet (veth) device pair.
//!
//! A veth pair is two connected point-to-point devices: a frame transmitted on
//! one end is delivered to the receive queue of the other end. The two ends can
//! live in different network namespaces, which is how a pod's network namespace
//! is wired to the host.
//!
//! Each end is a [`VethDevice`] (a smoltcp [`Device`]). Both share a
//! [`VethChannel`] holding the two receive queues and a per-end *notifier*. When
//! one end transmits, it pushes the frame onto the peer's receive queue and
//! invokes the peer's notifier so the peer's interface gets polled. The notifiers
//! are set by the kernel after the interfaces are built, since they reference the
//! peer interface's poll scheduler.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};

use ostd::sync::SpinLock;
use smoltcp::{
    phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use spin::once::Once;

/// A callback invoked to request that a veth end's interface be polled.
pub type VethNotifier = Box<dyn Fn() + Send + Sync>;

/// The maximum transmission unit of a veth interface.
///
/// Also reused by [`super::bridge`], whose ports are veth-like links.
pub(super) const VETH_MTU: usize = 1500;

/// Identifies one of the two ends of a veth pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    A,
    B,
}

impl End {
    fn peer(self) -> End {
        match self {
            End::A => End::B,
            End::B => End::A,
        }
    }
}

/// The shared link between the two ends of a veth pair.
pub struct VethChannel {
    a_rx: SpinLock<VecDeque<Vec<u8>>>,
    b_rx: SpinLock<VecDeque<Vec<u8>>>,
    a_notify: Once<VethNotifier>,
    b_notify: Once<VethNotifier>,
}

impl VethChannel {
    /// Creates a new, unconnected veth channel.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            a_rx: SpinLock::new(VecDeque::new()),
            b_rx: SpinLock::new(VecDeque::new()),
            a_notify: Once::new(),
            b_notify: Once::new(),
        })
    }

    /// Returns the `A` end as a device.
    pub fn device_a(self: &Arc<Self>) -> VethDevice {
        VethDevice {
            channel: self.clone(),
            end: End::A,
        }
    }

    /// Returns the `B` end as a device.
    pub fn device_b(self: &Arc<Self>) -> VethDevice {
        VethDevice {
            channel: self.clone(),
            end: End::B,
        }
    }

    /// Sets the notifiers that request each end's interface to be polled. Each
    /// notifier can be set only once.
    pub fn set_notifiers(&self, a_notify: VethNotifier, b_notify: VethNotifier) {
        self.a_notify.call_once(|| a_notify);
        self.b_notify.call_once(|| b_notify);
    }

    fn rx_of(&self, end: End) -> &SpinLock<VecDeque<Vec<u8>>> {
        match end {
            End::A => &self.a_rx,
            End::B => &self.b_rx,
        }
    }

    fn notify(&self, end: End) {
        let notifier = match end {
            End::A => self.a_notify.get(),
            End::B => self.b_notify.get(),
        };
        if let Some(notifier) = notifier {
            notifier();
        }
    }
}

/// One end of a veth pair, exposed as a smoltcp [`Device`].
pub struct VethDevice {
    channel: Arc<VethChannel>,
    end: End,
}

impl Device for VethDevice {
    type RxToken<'a> = VethRxToken;
    type TxToken<'a> = VethTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = VETH_MTU;
        caps.medium = Medium::Ip;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.channel.rx_of(self.end).lock().pop_front()?;
        let rx = VethRxToken { buffer };
        let tx = VethTxToken {
            channel: self.channel.clone(),
            end: self.end,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(VethTxToken {
            channel: self.channel.clone(),
            end: self.end,
        })
    }
}

#[doc(hidden)]
pub struct VethRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for VethRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
pub struct VethTxToken {
    channel: Arc<VethChannel>,
    end: End,
}

impl phy::TxToken for VethTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        // A frame transmitted on this end is received on the peer end. Enqueue it
        // there and ask the peer's interface to poll.
        let peer = self.end.peer();
        self.channel.rx_of(peer).lock().push_back(buffer);
        self.channel.notify(peer);

        result
    }
}
