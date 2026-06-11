// SPDX-License-Identifier: MPL-2.0

//! Handle route-related requests.

use super::util::finish_response;
use crate::{
    net::{
        net_ns::NetNamespace,
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{RouteAttr, RouteSegment, RouteSegmentBody, RtnlSegment},
        },
    },
    prelude::*,
};

// Well-known `rtmsg` field values.
//
// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h>.
const AF_INET: u8 = 2;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_KERNEL: u8 = 2;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

/// Handles an `RTM_GETROUTE` dump request by reporting the routes of the
/// calling thread's network namespace:
///
/// - one **connected (on-link) route** per interface with an IPv4 address
///   (loopback excluded, as in the Linux main table), and
/// - a **default route** for any interface that has a gateway configured
///   (e.g. the virtio NIC in the initial namespace).
///
/// This is what `ip route` and container network tooling (e.g. netavark)
/// issue to discover reachability.
pub(super) fn do_get_route(request_segment: &RouteSegment) -> Result<Vec<RtnlSegment>> {
    let dump_all = {
        let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
        flags.contains(GetRequestFlags::DUMP)
    };
    if !dump_all {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETROUTE only supports dump requests");
    }

    let ifaces = NetNamespace::current().all_ifaces();
    let mut response_segments: Vec<RtnlSegment> = Vec::new();

    for iface in ifaces.iter() {
        // The Linux main table does not list loopback's 127.0.0.0/8 (it lives
        // in the local table), so skip loopback to match what tools expect.
        if iface.type_() == aster_bigtcp::iface::InterfaceType::LOOPBACK {
            continue;
        }

        if let (Some(addr), Some(prefix)) = (iface.ipv4_addr(), iface.prefix_len())
            && prefix > 0
        {
            let mask: u32 = u32::MAX << (32 - u32::from(prefix));
            let network = (u32::from(addr) & mask).to_be_bytes();
            response_segments.push(RtnlSegment::NewRoute(connected_route(
                request_segment.header(),
                prefix,
                network,
                addr.octets(),
                iface.index(),
            )));
        }

        if let Some(gateway) = iface.ipv4_gateway() {
            response_segments.push(RtnlSegment::NewRoute(default_route(
                request_segment.header(),
                gateway.octets(),
                iface.index(),
            )));
        }
    }

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

fn new_route_header(request_header: &CMsgSegHdr) -> CMsgSegHdr {
    CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWROUTE as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    }
}

/// An on-link (connected) route: `<network>/<prefix> dev <oif> src <addr>`.
fn connected_route(
    request_header: &CMsgSegHdr,
    prefix: u8,
    network: [u8; 4],
    pref_src: [u8; 4],
    oif: u32,
) -> RouteSegment {
    let body = RouteSegmentBody {
        family: AF_INET,
        dst_len: prefix,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_LINK,
        type_: RTN_UNICAST,
    };
    let attrs = vec![
        RouteAttr::Table(RT_TABLE_MAIN as u32),
        RouteAttr::Dst(network),
        RouteAttr::PrefSrc(pref_src),
        RouteAttr::Oif(oif),
    ];
    RouteSegment::new(new_route_header(request_header), body, attrs)
}

/// A default route: `default via <gateway> dev <oif>`.
fn default_route(request_header: &CMsgSegHdr, gateway: [u8; 4], oif: u32) -> RouteSegment {
    let body = RouteSegmentBody {
        family: AF_INET,
        dst_len: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_UNIVERSE,
        type_: RTN_UNICAST,
    };
    let attrs = vec![
        RouteAttr::Table(RT_TABLE_MAIN as u32),
        RouteAttr::Gateway(gateway),
        RouteAttr::Oif(oif),
    ];
    RouteSegment::new(new_route_header(request_header), body, attrs)
}
