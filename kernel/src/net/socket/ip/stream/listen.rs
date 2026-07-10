// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicUsize, Ordering};

use aster_bigtcp::{
    errors::tcp::ListenError,
    socket::{RawTcpOption, RawTcpSetOption},
    wire::IpEndpoint,
};

use super::{connected::ConnectedStream, observer::StreamObserver};
use crate::{
    events::IoEvents,
    net::iface::{BoundTcpPort, Iface, TcpListener},
    prelude::*,
};

/// A listening stream.
///
/// A wildcard (`0.0.0.0`) bind reserves the port on every interface in the
/// socket's network namespace, so a listener holds one backing TCP listener
/// per bound interface and accepts connections from any of them.
pub(super) struct ListenStream {
    tcp_listeners: Vec<TcpListener>,
    /// Round-robin cursor so `accept` serves all interfaces fairly.
    accept_cursor: AtomicUsize,
}

impl ListenStream {
    pub(super) fn new(
        bound_ports: Vec<BoundTcpPort>,
        backlog: usize,
        option: &RawTcpOption,
        observer: StreamObserver,
    ) -> Result<Self, (Vec<BoundTcpPort>, Error)> {
        const SOMAXCONN: usize = 4096;
        let max_conn = SOMAXCONN.min(backlog);

        let mut tcp_listeners = Vec::with_capacity(bound_ports.len());
        for bound_port in bound_ports {
            match TcpListener::new_listen(bound_port, max_conn, option, observer.clone()) {
                Ok(tcp_listener) => tcp_listeners.push(tcp_listener),
                Err((bound_port, ListenError::AddressInUse)) => {
                    // Ports already turned into listeners cannot be recovered
                    // (`TcpListener` has no `into_bound_port`), so drop them;
                    // the socket keeps only the port that failed to listen.
                    // This can only trigger on a multi-interface (wildcard)
                    // bind racing another listener for the same key.
                    drop(tcp_listeners);
                    return Err((
                        vec![bound_port],
                        Error::with_message(Errno::EADDRINUSE, "listener key conflicts"),
                    ));
                }
                Err((_, err)) => {
                    unreachable!("`new_listen` fails with {:?}, which should not happen", err)
                }
            }
        }

        Ok(Self {
            tcp_listeners,
            accept_cursor: AtomicUsize::new(0),
        })
    }

    pub(super) fn try_accept(&self) -> Result<ConnectedStream> {
        let n = self.tcp_listeners.len();
        let start = self.accept_cursor.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            let listener = &self.tcp_listeners[(start + i) % n];
            if let Some((new_conn, remote_endpoint)) = listener.accept() {
                return Ok(ConnectedStream::new(new_conn, remote_endpoint, false));
            }
        }
        Err(Error::with_message(
            Errno::EAGAIN,
            "no pending connection is available",
        ))
    }

    pub(super) fn local_endpoint(&self) -> IpEndpoint {
        self.tcp_listeners[0].local_endpoint().unwrap()
    }

    pub(super) fn iface(&self) -> &Arc<Iface> {
        self.tcp_listeners[0].iface()
    }

    /// Polls every interface this listener is bound on. A wildcard listener
    /// spans multiple interfaces, so polling only one would delay connections
    /// arriving on the others.
    pub(super) fn poll_ifaces(&self) {
        for listener in self.tcp_listeners.iter() {
            listener.iface().poll();
        }
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        let can_accept = self
            .tcp_listeners
            .iter()
            .any(|listener| listener.can_accept());

        // If network packets come in simultaneously, the socket state may change in the middle.
        // However, the current pollee implementation should be able to handle this race condition.
        if can_accept {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    pub(super) fn set_raw_option<R>(&self, set_option: impl Fn(&dyn RawTcpSetOption) -> R) -> R {
        let mut res = None;
        for listener in self.tcp_listeners.iter() {
            res = Some(set_option(listener));
        }
        res.expect("a listener always has at least one backing TCP listener")
    }

    pub(super) fn into_listeners(self) -> Vec<TcpListener> {
        self.tcp_listeners
    }
}
