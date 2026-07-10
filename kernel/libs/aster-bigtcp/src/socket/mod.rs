// SPDX-License-Identifier: MPL-2.0

mod bound;
mod event;
mod option;
mod unbound;

pub use bound::{
    ConnectState, IcmpSocket, NeedIfacePoll, RawTcpSocketExt, ReceiveBehavior, TcpConnection,
    TcpListener, UdpSocket,
};
pub(crate) use bound::{
    IcmpSocketBg, TcpConnectionBg, TcpListenerBg, TcpProcessResult, UdpSocketBg,
};
pub use event::{SocketEventObserver, SocketEvents};
pub use option::{RawTcpOption, RawTcpSetOption};
pub use smoltcp::socket::icmp::{
    BindError as IcmpBindError, RecvError as IcmpRecvError, SendError as IcmpSendError,
};
pub use unbound::{
    ICMP_RECV_PAYLOAD_LEN, ICMP_SEND_PAYLOAD_LEN, RawIcmpSocket, RawUdpSocket, TCP_RECV_BUF_LEN,
    TCP_SEND_BUF_LEN, UDP_RECV_PAYLOAD_LEN, UDP_SEND_PAYLOAD_LEN,
};
