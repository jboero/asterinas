// SPDX-License-Identifier: MPL-2.0

mod bridge;
mod broadcast;
mod ext;
mod init;
mod poll;
mod sched;
mod veth;

pub(in crate::net) use bridge::{bridge_hub_by_index, new_bridge, new_veth_on_bridge};
pub use broadcast::is_broadcast_endpoint;
pub(in crate::net) use init::new_loopback;
pub use init::{init, iter_all_ifaces, loopback_iface, virtio_iface};
pub(super) use poll::init_in_first_kthread;
pub(in crate::net) use poll::spawn_poll_thread;
pub(in crate::net) use veth::new_veth_pair;

pub type Iface = dyn aster_bigtcp::iface::Iface<ext::BigtcpExt>;
pub type BoundIcmpSocket = aster_bigtcp::socket::IcmpSocket<ext::BigtcpExt>;
pub type BoundTcpPort = aster_bigtcp::iface::BoundTcpPort<ext::BigtcpExt>;
pub type BoundUdpPort = aster_bigtcp::iface::BoundUdpPort<ext::BigtcpExt>;

pub type RawTcpSocketExt = aster_bigtcp::socket::RawTcpSocketExt<ext::BigtcpExt>;

pub type TcpConnection = aster_bigtcp::socket::TcpConnection<ext::BigtcpExt>;
pub type TcpListener = aster_bigtcp::socket::TcpListener<ext::BigtcpExt>;
pub type UdpSocket = aster_bigtcp::socket::UdpSocket<ext::BigtcpExt>;
