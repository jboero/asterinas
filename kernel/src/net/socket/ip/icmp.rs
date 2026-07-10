// SPDX-License-Identifier: MPL-2.0

//! ICMP (ping) sockets.
//!
//! Supports the two ways `ping` creates a socket on Linux:
//! `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` (classic, root) and
//! `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` ("ping sockets").
//!
//! In both modes the caller sends an assembled ICMP packet (header +
//! payload). The socket lazily binds on the first send: the echo
//! *identifier* is taken from the outgoing packet (so replies match what
//! the ping utility expects), and the interface is chosen to suit the
//! remote address, like an ephemeral UDP bind. In raw mode, received
//! packets are prefixed with a synthesized IPv4 header, which `ping`
//! implementations parse to locate the ICMP message.

use core::sync::atomic::{AtomicBool, Ordering};

use aster_bigtcp::{
    iface::BindPortConfig,
    socket::IcmpSendError,
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};

use crate::{
    events::IoEvents,
    fs::{pseudofs::SockFs, vfs::path::Path},
    net::{
        iface::BoundIcmpSocket,
        net_ns::NetNamespace,
        socket::{
            Socket,
            ip::DatagramObserver,
            private::SocketPrivate,
            util::{MessageHeader, SendRecvFlags, SocketAddr},
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    util::{MultiRead, MultiWrite},
};

pub struct IcmpSocket {
    /// The bound socket. `None` until the first send lazily binds.
    inner: RwMutex<Option<BoundIcmpSocket>>,
    /// The default remote address set by `connect`.
    remote: RwMutex<Option<IpAddress>>,
    /// Raw mode (`SOCK_RAW`): prefix received packets with an IPv4 header.
    is_raw: bool,
    is_nonblocking: AtomicBool,
    pollee: Pollee,
    pseudo_path: Path,
}

impl IcmpSocket {
    pub fn new(is_nonblocking: bool, is_raw: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: RwMutex::new(None),
            remote: RwMutex::new(None),
            is_raw,
            is_nonblocking: AtomicBool::new(is_nonblocking),
            pollee: Pollee::new(),
            pseudo_path: SockFs::new_path(),
        })
    }

    /// Binds on the first send: the ICMP echo identifier in `packet` becomes
    /// this socket's identifier, and the interface is picked for `remote`.
    fn bind_for(&self, remote: &IpAddress, packet: &[u8]) -> Result<()> {
        let mut inner = self.inner.write();
        if inner.is_some() {
            return Ok(());
        }

        // For echo messages, the identifier lives at bytes 4..6.
        let ident = u16::from_be_bytes([packet[4], packet[5]]);

        let iface = NetNamespace::current().ephemeral_iface(remote);
        let config = BindPortConfig::new(
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), ident),
            false,
        );
        let bound_port = iface.bind_icmp(config).map_err(Error::from)?;

        let bound =
            BoundIcmpSocket::new_bind(bound_port, DatagramObserver::new(self.pollee.clone()))
                .map_err(|_| Error::with_message(Errno::EINVAL, "cannot bind the ICMP socket"))?;

        *inner = Some(bound);
        Ok(())
    }

    fn try_send(&self, buf: &[u8], remote: &IpAddress) -> Result<usize> {
        let inner = self.inner.read();
        let bound = inner
            .as_ref()
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "the socket is not bound"))?;

        bound
            .send(buf.len(), *remote, |buffer| buffer.copy_from_slice(buf))
            .map_err(|err| match err {
                IcmpSendError::BufferFull => {
                    Error::with_message(Errno::EAGAIN, "the send buffer is full")
                }
                IcmpSendError::Unaddressable => {
                    Error::with_message(Errno::EINVAL, "the remote address is invalid")
                }
            })?;

        let iface = bound.iface().clone();
        drop(inner);

        self.pollee.invalidate();
        iface.poll();

        Ok(buf.len())
    }

    fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<(usize, SocketAddr)> {
        let inner = self.inner.read();
        let bound = inner
            .as_ref()
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "no packet is available"))?;

        let result = bound
            .recv(|data, addr| {
                let copied = if self.is_raw {
                    // Raw ICMP sockets receive the IP header too; synthesize a
                    // minimal one (ping reads `ihl` to find the ICMP message
                    // and `ttl` for display).
                    let mut header = [0u8; 20];
                    header[0] = 0x45; // version 4, ihl 5
                    let total = (20 + data.len()) as u16;
                    header[2..4].copy_from_slice(&total.to_be_bytes());
                    header[8] = 64; // ttl
                    header[9] = 1; // protocol: ICMP
                    if let IpAddress::Ipv4(src) = addr {
                        header[12..16].copy_from_slice(&src.octets());
                    }
                    let mut copied = 0;
                    copied += writer.write(&mut VmReader::from(&header[..])).unwrap_or(0);
                    copied += writer.write(&mut VmReader::from(data)).unwrap_or(0);
                    copied
                } else {
                    writer.write(&mut VmReader::from(data)).unwrap_or(0)
                };
                (copied, addr)
            })
            .map_err(|_| Error::with_message(Errno::EAGAIN, "no packet is available"))?;

        drop(inner);
        self.pollee.invalidate();

        let (copied, addr) = result;
        Ok((copied, IpEndpoint::new(addr, 0).into()))
    }

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::OUT;
        if let Some(bound) = self.inner.read().as_ref()
            && bound.raw_with(|socket| socket.can_recv())
        {
            events |= IoEvents::IN;
        }
        events
    }
}

impl Pollable for IcmpSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }
}

impl SocketPrivate for IcmpSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, is_nonblocking: bool) {
        self.is_nonblocking.store(is_nonblocking, Ordering::Relaxed);
    }
}

impl Socket for IcmpSocket {
    fn bind(&self, _socket_addr: SocketAddr) -> Result<()> {
        // Binding to an address is accepted but has no effect: the echo
        // identifier is taken from the first outgoing packet instead.
        Ok(())
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let endpoint: IpEndpoint = socket_addr.try_into()?;
        *self.remote.write() = Some(endpoint.addr);
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        Ok(IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0).into())
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let remote = self.remote.read();
        let addr = remote
            .as_ref()
            .ok_or_else(|| Error::with_message(Errno::ENOTCONN, "the socket is not connected"))?;
        Ok(IpEndpoint::new(*addr, 0).into())
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let MessageHeader { addr, .. } = message_header;
        let remote = match addr {
            Some(addr) => {
                let endpoint: IpEndpoint = addr.try_into()?;
                endpoint.addr
            }
            None => self.remote.read().ok_or_else(|| {
                Error::with_message(Errno::EDESTADDRREQ, "the destination is not specified")
            })?,
        };

        // The whole ICMP packet is needed up front to read its identifier.
        let len = reader.sum_lens();
        if len < 8 {
            return_errno_with_message!(Errno::EINVAL, "the ICMP packet is too short");
        }
        let mut buf = vec![0u8; len];
        reader
            .read(&mut VmWriter::from(&mut buf[..]))
            .map_err(|_| Error::with_message(Errno::EFAULT, "cannot read the packet"))?;

        self.bind_for(&remote, &buf)?;

        self.try_send(&buf, &remote)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let (received_bytes, peer_addr) = self.block_on(IoEvents::IN, || self.try_recv(writer))?;

        Ok((
            received_bytes,
            MessageHeader::new(Some(peer_addr), Vec::new()),
        ))
    }

    fn set_option(&self, _option: &dyn crate::net::socket::options::SocketOption) -> Result<()> {
        // `ping` sets options like `ICMP_FILTER` and `SO_TIMESTAMP` that do not
        // affect basic echo round-trips; accept them silently.
        Ok(())
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}
