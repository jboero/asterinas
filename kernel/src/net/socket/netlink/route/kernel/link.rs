// SPDX-License-Identifier: MPL-2.0

//! Handle link-related requests.

use core::num::NonZero;

use aster_bigtcp::{
    iface::InterfaceType,
    wire::{Ipv4Address, Ipv4Cidr},
};

use super::util::finish_response;
use crate::{
    net::{
        iface::{Iface, bridge_hub_by_index, new_bridge, new_veth_on_bridge},
        net_ns::{self, NetNamespace},
        socket::netlink::{
            message::{CMsgSegHdr, CSegmentType, GetRequestFlags, SegHdrCommonFlags},
            route::message::{LinkAttr, LinkSegment, LinkSegmentBody, RtnlSegment},
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    let filter_by = FilterBy::from_request(request_segment)?;

    let ifaces = NetNamespace::current().all_ifaces();
    let mut response_segments: Vec<RtnlSegment> = ifaces
        .iter()
        // Filter to include only requested links.
        .filter(|iface| match &filter_by {
            FilterBy::Index(index) => *index == iface.index(),
            FilterBy::Name(name) => *name == iface.name(),
            FilterBy::Dump => true,
        })
        .map(|iface| iface_to_new_link(request_segment.header(), iface))
        .map(RtnlSegment::NewLink)
        .collect();

    let dump_all = matches!(filter_by, FilterBy::Dump);

    if !dump_all && response_segments.is_empty() {
        return_errno_with_message!(Errno::ENODEV, "no link found");
    }

    finish_response(request_segment.header(), dump_all, &mut response_segments);

    Ok(response_segments)
}

enum FilterBy<'a> {
    Index(u32),
    Name(&'a str),
    Dump,
}

impl<'a> FilterBy<'a> {
    fn from_request(request_segment: &'a LinkSegment) -> Result<Self> {
        let dump_all = {
            let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
            flags.contains(GetRequestFlags::DUMP)
        };
        if dump_all {
            validate_dumplink_request(request_segment.body())?;
            return Ok(Self::Dump);
        }

        validate_getlink_request(request_segment.body())?;

        // `index` takes precedence over `required_name`.

        if let Some(required_index) = request_segment.body().index {
            return Ok(Self::Index(required_index.get()));
        }

        let required_name = request_segment.attrs().iter().find_map(|attr| {
            if let LinkAttr::Name(name) = attr {
                Some(name.to_str().unwrap())
            } else {
                None
            }
        });
        if let Some(required_name) = required_name {
            return Ok(Self::Name(required_name));
        }

        return_errno_with_message!(
            Errno::EINVAL,
            "either interface name or index should be specified for non-dump mode"
        );
    }
}

// The below functions starting with `validate_` should only be enabled in strict mode.
// Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#strict-checking>.

fn validate_getlink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields,
    // but these fields are lost during the conversion of a `CIfInfoMsg` to `LinkSegmentBody`.
    // We should consider including the `change` field in `LinkSegmentBody`.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L4043>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    Ok(())
}

fn validate_dumplink_request(body: &LinkSegmentBody) -> Result<()> {
    // FIXME: The Linux implementation also checks the `padding` and `change` fields.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2378>.
    if !body.flags.is_empty() || body.type_ != InterfaceType::NETROM {
        return_errno_with_message!(Errno::EINVAL, "the flags or the type is not valid");
    }

    // The check is from <https://elixir.bootlin.com/linux/v6.13/source/net/core/rtnetlink.c#L2383>.
    if body.index.is_some() {
        return_errno_with_message!(
            Errno::EINVAL,
            "filtering by interface index is not valid for link dumps"
        );
    }

    Ok(())
}

/// Handles an `RTM_NEWLINK` request.
///
/// Currently this supports creating two link kinds:
///
/// - A **bridge** (`ip link add br0 type bridge`). The bridge is created without
///   an address; like veth ends, it gets its IP later via `RTM_NEWADDR`.
/// - A **veth pair**, which is what a CNI plugin issues to wire a pod's network
///   namespace to the host:
///
/// ```text
/// ip link add <name> type veth peer name <peer> netns <pid>
/// ip link add <name> type veth peer name <peer> netns <pid> master <br-ifindex>
/// ```
///
/// The `<name>` end is placed in the caller's network namespace (or the namespace
/// of `IFLA_NET_NS_PID` if present at the top level); the `<peer>` end is placed
/// in the namespace named by `VETH_INFO_PEER`'s `IFLA_NET_NS_PID` (defaulting to
/// the caller's namespace). Addresses are configured separately via `RTM_NEWADDR`.
///
/// If `IFLA_MASTER` is present (it carries the bridge's interface _index_, not
/// its name), the `<name>` end is created directly as a port of that bridge
/// instead of as a standalone iface, so only the `<peer>` end is visible to
/// `RTM_GETLINK`. Attaching an existing link to a master via `RTM_SETLINK` is
/// not yet supported; the master can only be set at creation time.
/// Handles an `RTM_NEWLINK` that carries no `IFLA_LINKINFO`: a request to modify
/// an existing link rather than create one (e.g. `ip link set <dev> up`).
///
/// Asterinas interfaces are always administratively up, so the flag change
/// (notably `IFF_UP`) is a no-op; the only requirement is that the target link
/// exists in the current namespace. The link is identified by its index, or by
/// `IFLA_IFNAME` when no index is given.
fn modify_existing_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    let target_index = request_segment.body().index.map(|index| index.get());
    let target_name = request_segment.attrs().iter().find_map(|attr| {
        if let LinkAttr::Name(name) = attr {
            name.to_str().ok()
        } else {
            None
        }
    });

    let exists = NetNamespace::current().all_ifaces().iter().any(|iface| {
        if let Some(index) = target_index {
            iface.index() == index
        } else if let Some(name) = target_name {
            iface.name() == name
        } else {
            false
        }
    });

    if !exists {
        return_errno_with_message!(Errno::ENODEV, "no such link to modify");
    }

    // No response payload; the kernel socket sends an ACK if one was requested.
    Ok(Vec::new())
}

pub(super) fn do_new_link(request_segment: &LinkSegment) -> Result<Vec<RtnlSegment>> {
    super::util::require_net_admin()?;

    let mut primary_name: Option<&str> = None;
    let mut primary_ns_pid: Option<u32> = None;
    let mut master_index: Option<u32> = None;
    let mut kind: Option<&str> = None;
    let mut peer = None;

    for attr in request_segment.attrs() {
        match attr {
            LinkAttr::Name(name) => primary_name = name.to_str().ok(),
            LinkAttr::NetNsPid(pid) => primary_ns_pid = Some(*pid),
            LinkAttr::Master(index) => master_index = Some(*index),
            LinkAttr::LinkInfo(info) => {
                kind = info.kind.as_ref().and_then(|k| k.to_str().ok());
                peer = info.veth_peer.as_ref();
            }
            _ => {}
        }
    }

    let Some(kind) = kind else {
        // An `RTM_NEWLINK` without `IFLA_LINKINFO` is not a link creation but a
        // modification of an existing link (for example `ip link set <dev> up`,
        // which runc issues to bring a container's loopback up). Handle it
        // separately rather than rejecting it.
        return modify_existing_link(request_segment);
    };

    if kind != "bridge" && kind != "veth" {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "only bridge and veth links can be created"
        );
    }

    let primary_name = primary_name.ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "a link name (IFLA_IFNAME) is required")
    })?;

    if kind == "bridge" {
        let (iface, _hub) = new_bridge(primary_name.to_string());
        NetNamespace::current().add_iface(iface);
        // No response payload; the kernel socket sends an ACK if one was requested.
        return Ok(Vec::new());
    }

    let peer = peer.ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "a veth requires a peer (VETH_INFO_PEER)")
    })?;
    let peer_name = peer
        .name
        .as_ref()
        .and_then(|n| n.to_str().ok())
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "the veth peer name is required"))?;

    let current_ns = NetNamespace::current();

    let peer_ns = if let Some(pid) = peer.net_ns_pid {
        net_ns::net_ns_of_pid(pid)?
    } else if peer.net_ns_fd.is_some() {
        // Placing the peer via IFLA_NET_NS_FD requires resolving a namespace fd
        // in the caller's file table; use IFLA_NET_NS_PID for now.
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "placing a veth peer by IFLA_NET_NS_FD is not yet supported; use IFLA_NET_NS_PID"
        );
    } else {
        current_ns.clone()
    };

    if let Some(index) = master_index {
        let hub = bridge_hub_by_index(index)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "no such bridge"))?;
        // The `<name>` end becomes a port of the bridge hub rather than a
        // standalone iface, so RTM_GETLINK does not list it (v1; matches
        // creation-time-master CNI flows). The pod end's address is configured
        // separately via RTM_NEWADDR.
        let pod_iface = new_veth_on_bridge(
            &hub,
            peer_name.to_string(),
            Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0),
        );
        peer_ns.add_iface(pod_iface);

        // No response payload; the kernel socket sends an ACK if one was requested.
        return Ok(Vec::new());
    }

    let primary_ns = match primary_ns_pid {
        Some(pid) => net_ns::net_ns_of_pid(pid)?,
        None => current_ns.clone(),
    };

    net_ns::create_veth_pair(
        primary_name.to_string(),
        &primary_ns,
        peer_name.to_string(),
        &peer_ns,
    )?;

    // No response payload; the kernel socket sends an ACK if one was requested.
    Ok(Vec::new())
}

fn iface_to_new_link(request_header: &CMsgSegHdr, iface: &Arc<Iface>) -> LinkSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWLINK as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let link_message = LinkSegmentBody {
        family: CSocketAddrFamily::AF_UNSPEC,
        type_: iface.type_(),
        index: NonZero::new(iface.index()),
        flags: iface.flags(),
    };

    let mut attrs = vec![
        LinkAttr::Name(CString::new(iface.name()).unwrap()),
        LinkAttr::Mtu(iface.mtu() as u32),
    ];
    // IFLA_ADDRESS: the L2 MAC, so userspace (e.g. a DHCP client building its
    // chaddr) can read the interface's hardware address. Loopback has none.
    if let Some(mac) = iface.mac() {
        attrs.push(LinkAttr::Address(mac));
    }

    LinkSegment::new(header, link_message, attrs)
}
