// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_softirq::BottomHalfDisabled;
use ostd::sync::SpinLock;
use smoltcp::{
    iface::Context,
    wire::{IcmpRepr, Icmpv4Repr, IpAddress, IpRepr, Ipv4Repr},
};

use super::common::{Inner, Socket, SocketBg};
use crate::{
    ext::Ext,
    iface::BoundIcmpPort,
    socket::{RawIcmpSocket, event::SocketEvents, unbound::new_icmp_socket},
};

pub type IcmpSocket<E> = Socket<IcmpSocketInner, E>;

/// States needed by [`IcmpSocketBg`].
///
/// An ICMP socket is bound to an echo *identifier* rather than a port; the
/// identifier reuses the port allocation machinery (see [`BoundIcmpPort`]).
pub struct IcmpSocketInner {
    socket: SpinLock<Box<RawIcmpSocket>, BottomHalfDisabled>,
    need_dispatch: AtomicBool,
}

impl<E: Ext> Inner<E> for IcmpSocketInner {
    type BoundPort = BoundIcmpPort<E>;
    type Observer = E::IcmpEventObserver;

    fn on_drop(this: &Arc<SocketBg<Self, E>>) {
        // An ICMP socket can be removed immediately.
        this.bound.iface().common().remove_icmp_socket(this);
    }
}

pub(crate) type IcmpSocketBg<E> = SocketBg<IcmpSocketInner, E>;

impl<E: Ext> IcmpSocketBg<E> {
    /// Tries to process an incoming ICMPv4 message and returns whether it was
    /// accepted by this socket (e.g. an echo reply matching our identifier).
    pub(crate) fn process(
        &self,
        cx: &mut Context,
        ipv4_repr: &Ipv4Repr,
        icmp_repr: &Icmpv4Repr,
    ) -> bool {
        let mut socket = self.inner.socket.lock();

        if !socket.accepts_v4(cx, ipv4_repr, icmp_repr) {
            return false;
        }

        socket.process_v4(cx, ipv4_repr, icmp_repr);

        self.notify_events(SocketEvents::CAN_RECV);

        true
    }

    /// Tries to generate an outgoing packet and dispatches the generated packet.
    pub(crate) fn dispatch<D>(&self, cx: &mut Context, dispatch: D)
    where
        D: FnOnce(&mut Context, &IpRepr, &IcmpRepr),
    {
        let mut socket = self.inner.socket.lock();

        socket
            .dispatch(cx, |cx, (ip_repr, icmp_repr)| {
                dispatch(cx, &ip_repr, &icmp_repr);
                Ok::<(), ()>(())
            })
            .unwrap();

        // Dequeuing a packet means that we can queue more packets.
        self.notify_events(SocketEvents::CAN_SEND);

        self.inner
            .need_dispatch
            .store(socket.send_queue() > 0, Ordering::Relaxed);
    }

    /// Returns whether the socket _may_ generate an outgoing packet.
    pub(crate) fn need_dispatch(&self) -> bool {
        self.inner.need_dispatch.load(Ordering::Relaxed)
    }
}

impl<E: Ext> IcmpSocket<E> {
    /// Binds to the echo identifier carried in `bound`.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn new_bind(
        bound: BoundIcmpPort<E>,
        observer: E::IcmpEventObserver,
    ) -> Result<Self, (BoundIcmpPort<E>, smoltcp::socket::icmp::BindError)> {
        let ident = bound.port();

        let socket = {
            let mut socket = new_icmp_socket();

            if let Err(err) = socket.bind(smoltcp::socket::icmp::Endpoint::Ident(ident)) {
                return Err((bound, err));
            }

            socket
        };

        let inner = IcmpSocketInner {
            socket: SpinLock::new(socket),
            need_dispatch: AtomicBool::new(false),
        };

        let socket = Self::new(bound, inner);
        socket.init_observer(observer);
        socket
            .iface()
            .common()
            .register_icmp_socket(socket.inner().clone());

        Ok(socket)
    }

    /// Sends an assembled ICMP packet (header + payload) to `remote`.
    ///
    /// Polling the iface is _always_ required after this method succeeds.
    pub fn send<F, R>(
        &self,
        size: usize,
        remote: IpAddress,
        f: F,
    ) -> Result<R, smoltcp::socket::icmp::SendError>
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut socket = self.0.inner.socket.lock();

        let buffer = socket.send(size, remote)?;
        let result = f(buffer);

        self.0
            .inner
            .need_dispatch
            .store(socket.send_queue() > 0, Ordering::Relaxed);

        Ok(result)
    }

    /// Receives an ICMP packet (header + payload) and its source address.
    ///
    /// Polling the iface is _not_ required after this method succeeds.
    pub fn recv<F, R>(&self, f: F) -> Result<R, smoltcp::socket::icmp::RecvError>
    where
        F: FnOnce(&[u8], IpAddress) -> R,
    {
        let mut socket = self.0.inner.socket.lock();

        let (data, addr) = socket.recv()?;
        let result = f(data, addr);

        Ok(result)
    }

    /// Calls `f` with an immutable reference to the associated [`RawIcmpSocket`].
    pub fn raw_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&RawIcmpSocket) -> R,
    {
        let socket = self.0.inner.socket.lock();
        f(&socket)
    }
}
