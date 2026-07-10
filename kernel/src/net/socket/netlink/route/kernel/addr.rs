// SPDX-License-Identifier: MPL-2.0

//! Handle address-related requests.

use alloc::borrow::ToOwned;
use core::num::NonZeroU32;

use aster_bigtcp::wire::{Ipv4Address, Ipv4Cidr};

use super::util::finish_response;
use crate::{
    net::{
        iface::Iface,
        net_ns::{self, NetNamespace},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{
                AddrAttr, AddrMessageFlags, AddrSegment, AddrSegmentBody, RtScope, RtnlSegment,
            },
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_addr(request_segment: &AddrSegment) -> Result<Vec<RtnlSegment>> {
    let dump_all = {
        let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
        flags.contains(GetRequestFlags::DUMP)
    };
    if !dump_all {
        return_errno_with_message!(Errno::EOPNOTSUPP, "GETADDR only supports dump requests");
    }

    let ifaces = NetNamespace::current().all_ifaces();
    let mut response_segments: Vec<RtnlSegment> = ifaces
        .iter()
        // GETADDR only supports dump mode, so we're going to report all addresses.
        .filter_map(|iface| iface_to_new_addr(request_segment.header(), iface))
        .map(RtnlSegment::NewAddr)
        .collect();

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

/// Handles an `RTM_NEWADDR` request: assigns an IPv4 address to an interface in
/// the caller's network namespace.
///
/// This is what a CNI plugin (or `ip addr add <ip>/<prefix> dev <iface>`) issues
/// to give a pod's veth end a routable address. The interface is identified by
/// `ifa_index`; the address comes from `IFA_LOCAL` (preferred) or `IFA_ADDRESS`,
/// with the prefix length from the `ifaddrmsg` header.
pub(super) fn do_new_addr(request_segment: &AddrSegment) -> Result<Vec<RtnlSegment>> {
    super::util::require_net_admin()?;

    let body = request_segment.body();

    if body.family != CSocketAddrFamily::AF_INET as i32 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "only IPv4 addresses can be assigned");
    }

    let index = body
        .index
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "an interface index is required"))?
        .get();

    if body.prefix_len > 32 {
        return_errno_with_message!(Errno::EINVAL, "invalid IPv4 prefix length");
    }

    // Prefer IFA_LOCAL (the local address of the interface); fall back to
    // IFA_ADDRESS, which equals IFA_LOCAL for ordinary (non-point-to-point) use.
    let mut local: Option<[u8; 4]> = None;
    let mut address: Option<[u8; 4]> = None;
    for attr in request_segment.attrs() {
        match attr {
            AddrAttr::Local(octets) => local = Some(*octets),
            AddrAttr::Address(octets) => address = Some(*octets),
            AddrAttr::Label(_) => {}
        }
    }

    let octets = local.or(address).ok_or_else(|| {
        Error::with_message(
            Errno::EINVAL,
            "no address attribute (IFA_LOCAL/IFA_ADDRESS) was provided",
        )
    })?;

    let cidr = Ipv4Cidr::new(
        Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]),
        body.prefix_len,
    );

    let ns = NetNamespace::current();
    net_ns::set_iface_addr_v4(&ns, index, cidr)?;

    // No response payload; the kernel socket sends an ACK if one was requested.
    Ok(Vec::new())
}

fn iface_to_new_addr(request_header: &CMsgSegHdr, iface: &Arc<Iface>) -> Option<AddrSegment> {
    let ipv4_addr = iface.ipv4_addr()?;

    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWADDR as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let addr_message = AddrSegmentBody {
        family: CSocketAddrFamily::AF_INET as _,
        prefix_len: iface.prefix_len().unwrap(),
        flags: AddrMessageFlags::PERMANENT,
        scope: RtScope::HOST,
        index: NonZeroU32::new(iface.index()),
    };

    // Attribute order matches Linux's canonical RTM_NEWADDR layout:
    // IFA_ADDRESS, IFA_LOCAL, then IFA_LABEL. The order is load-bearing: Go's
    // net.InterfaceAddrs() (net/interface_linux.go), when IFA_LOCAL is present,
    // skips IFA_ADDRESS and reads the *next* attribute as the 4-byte IPv4
    // address. If IFA_LABEL (the interface name, e.g. "lo" = 3 bytes) comes
    // before IFA_LOCAL, Go reads the label as an address and panics with
    // "index out of range [3] with length 3" — which crashes the kubelet (and
    // any Go program enumerating interface addresses).
    let attrs = vec![
        AddrAttr::Address(ipv4_addr.octets()),
        AddrAttr::Local(ipv4_addr.octets()),
        AddrAttr::Label(iface.name().to_owned()),
    ];

    Some(AddrSegment::new(header, addr_message, attrs))
}
