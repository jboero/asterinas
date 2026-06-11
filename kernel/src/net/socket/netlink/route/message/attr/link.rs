// SPDX-License-Identifier: MPL-2.0

use super::IFNAME_SIZE;
use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

/// Link-level attributes.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/if_link.h#L297>.
#[expect(non_camel_case_types)]
#[expect(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum LinkAttrClass {
    UNSPEC = 0,
    ADDRESS = 1,
    BROADCAST = 2,
    IFNAME = 3,
    MTU = 4,
    LINK = 5,
    QDISC = 6,
    STATS = 7,
    COST = 8,
    PRIORITY = 9,
    MASTER = 10,
    /// Wireless Extension event
    WIRELESS = 11,
    /// Protocol specific information for a link
    PROTINFO = 12,
    TXQLEN = 13,
    MAP = 14,
    WEIGHT = 15,
    OPERSTATE = 16,
    LINKMODE = 17,
    LINKINFO = 18,
    NET_NS_PID = 19,
    IFALIAS = 20,
    /// Number of VFs if device is SR-IOV PF
    NUM_VF = 21,
    VFINFO_LIST = 22,
    STATS64 = 23,
    VF_PORTS = 24,
    PORT_SELF = 25,
    AF_SPEC = 26,
    /// Group the device belongs to
    GROUP = 27,
    NET_NS_FD = 28,
    /// Extended info mask, VFs, etc.
    EXT_MASK = 29,
    /// Promiscuity count: > 0 means acts PROMISC
    PROMISCUITY = 30,
    NUM_TX_QUEUES = 31,
    NUM_RX_QUEUES = 32,
    CARRIER = 33,
    PHYS_PORT_ID = 34,
    CARRIER_CHANGES = 35,
    PHYS_SWITCH_ID = 36,
    LINK_NETNSID = 37,
    PHYS_PORT_NAME = 38,
    PROTO_DOWN = 39,
    GSO_MAX_SEGS = 40,
    GSO_MAX_SIZE = 41,
    PAD = 42,
    XDP = 43,
    EVENT = 44,
    NEW_NETNSID = 45,
    IF_NETNSID = 46,
    CARRIER_UP_COUNT = 47,
    CARRIER_DOWN_COUNT = 48,
    NEW_IFINDEX = 49,
    MIN_MTU = 50,
    MAX_MTU = 51,
    PROP_LIST = 52,
    /// Alternative ifname
    ALT_IFNAME = 53,
    PERM_ADDRESS = 54,
    PROTO_DOWN_REASON = 55,
    PARENT_DEV_NAME = 56,
    PARENT_DEV_BUS_NAME = 57,
}

/// The wire size of an `ifinfomsg` body (the header of a `VETH_INFO_PEER`
/// nested attribute). Matches `CIfinfoMsg` in the link segment.
const IFINFOMSG_SIZE: usize = 16;

// Nested attribute type IDs used when creating links.
//
// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/if_link.h#L688> (IFLA_INFO_*)
// and <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/veth.h#L9> (VETH_INFO_PEER).
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

/// The parsed contents of an `IFLA_LINKINFO` nested attribute.
#[derive(Debug, Default)]
pub struct LinkInfoData {
    /// `IFLA_INFO_KIND`, e.g. `"veth"`.
    pub kind: Option<CString>,
    /// The peer specification parsed from `IFLA_INFO_DATA` → `VETH_INFO_PEER`,
    /// present only for `kind == "veth"`.
    pub veth_peer: Option<VethPeer>,
}

/// The peer end of a veth pair, as described by a `VETH_INFO_PEER` nested
/// attribute (an `ifinfomsg` followed by link attributes).
#[derive(Debug, Default)]
pub struct VethPeer {
    /// `IFLA_IFNAME` of the peer end.
    pub name: Option<CString>,
    /// `IFLA_NET_NS_PID`: place the peer end in this process's network namespace.
    pub net_ns_pid: Option<u32>,
    /// `IFLA_NET_NS_FD`: place the peer end in the namespace referred to by this fd.
    pub net_ns_fd: Option<u32>,
}

#[derive(Debug)]
pub enum LinkAttr {
    Name(CString),
    Mtu(u32),
    TxqLen(u32),
    LinkMode(u8),
    ExtMask(RtExtFilter),
    /// `IFLA_MASTER`: enslave the link to the device with this interface index.
    Master(u32),
    /// `IFLA_NET_NS_PID`: place the (primary) link in this process's netns.
    NetNsPid(u32),
    /// `IFLA_NET_NS_FD`: place the (primary) link in this fd's netns.
    NetNsFd(u32),
    /// `IFLA_LINKINFO`: the kind of link to create and its kind-specific data.
    LinkInfo(LinkInfoData),
}

impl LinkAttr {
    fn class(&self) -> LinkAttrClass {
        match self {
            LinkAttr::Name(_) => LinkAttrClass::IFNAME,
            LinkAttr::Mtu(_) => LinkAttrClass::MTU,
            LinkAttr::TxqLen(_) => LinkAttrClass::TXQLEN,
            LinkAttr::LinkMode(_) => LinkAttrClass::LINKMODE,
            LinkAttr::ExtMask(_) => LinkAttrClass::EXT_MASK,
            LinkAttr::Master(_) => LinkAttrClass::MASTER,
            LinkAttr::NetNsPid(_) => LinkAttrClass::NET_NS_PID,
            LinkAttr::NetNsFd(_) => LinkAttrClass::NET_NS_FD,
            LinkAttr::LinkInfo(_) => LinkAttrClass::LINKINFO,
        }
    }
}

impl Attribute for LinkAttr {
    fn type_(&self) -> u16 {
        self.class() as u16
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            LinkAttr::Name(name) => name.as_bytes_with_nul(),
            LinkAttr::Mtu(mtu) => mtu.as_bytes(),
            LinkAttr::TxqLen(txq_len) => txq_len.as_bytes(),
            LinkAttr::LinkMode(link_mode) => link_mode.as_bytes(),
            LinkAttr::ExtMask(ext_filter) => ext_filter.as_bytes(),
            LinkAttr::Master(index) => index.as_bytes(),
            LinkAttr::NetNsPid(pid) => pid.as_bytes(),
            LinkAttr::NetNsFd(fd) => fd.as_bytes(),
            // The kernel never writes `IFLA_LINKINFO` back to user space; this
            // variant only ever appears on the parse (request) path.
            LinkAttr::LinkInfo(_) => &[],
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        let payload_len = header.payload_len();

        // TODO: Currently, `IS_NET_BYTEORDER_MASK` and `IS_NESTED_MASK` are ignored.
        let Ok(class) = LinkAttrClass::try_from(header.type_()) else {
            // Unknown attributes should be ignored.
            // Reference: <https://docs.kernel.org/userspace-api/netlink/intro.html#unknown-attributes>.
            reader.skip_some(payload_len);
            return Ok(ContinueRead::Skipped);
        };

        let res = match (class, payload_len) {
            (LinkAttrClass::IFNAME, 1..=IFNAME_SIZE) => {
                let (name, namelen) =
                    reader.read_cstring_until_end(IFNAME_SIZE.min(payload_len))?;
                if namelen != payload_len {
                    reader.skip_some(payload_len - namelen);
                }
                if name.as_bytes().len() == IFNAME_SIZE {
                    return Ok(ContinueRead::skipped_with_error(
                        Errno::ERANGE,
                        "the link attribute is invalid",
                    ));
                }
                Self::Name(name)
            }
            (LinkAttrClass::MTU, 4) => Self::Mtu(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::TXQLEN, 4) => Self::TxqLen(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::LINKMODE, 1) => Self::LinkMode(reader.read_val_opt::<u8>()?.unwrap()),
            (LinkAttrClass::EXT_MASK, 4) => {
                const { assert!(size_of::<RtExtFilter>() == 4) };
                Self::ExtMask(reader.read_val_opt::<RtExtFilter>()?.unwrap())
            }
            (LinkAttrClass::MASTER, 4) => Self::Master(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::NET_NS_PID, 4) => {
                Self::NetNsPid(reader.read_val_opt::<u32>()?.unwrap())
            }
            (LinkAttrClass::NET_NS_FD, 4) => Self::NetNsFd(reader.read_val_opt::<u32>()?.unwrap()),
            (LinkAttrClass::LINKINFO, _) => Self::LinkInfo(read_link_info(reader, payload_len)?),

            (
                LinkAttrClass::IFNAME
                | LinkAttrClass::MTU
                | LinkAttrClass::TXQLEN
                | LinkAttrClass::LINKMODE
                | LinkAttrClass::EXT_MASK
                | LinkAttrClass::MASTER
                | LinkAttrClass::NET_NS_PID
                | LinkAttrClass::NET_NS_FD,
                _,
            ) => {
                warn!("link attribute `{:?}` contains invalid payload", class);
                reader.skip_some(payload_len);
                return Ok(ContinueRead::skipped_with_error(
                    if class == LinkAttrClass::IFNAME {
                        Errno::ERANGE
                    } else {
                        Errno::EINVAL
                    },
                    "the link attribute is invalid",
                ));
            }

            (_, _) => {
                warn!("link attribute `{:?}` is not supported", class);
                reader.skip_some(payload_len);
                return Ok(ContinueRead::Skipped);
            }
        };

        Ok(ContinueRead::Parsed(res))
    }
}

/// Iterates the sub-attributes packed into the next `budget` bytes of `reader`,
/// invoking `handle(type_, payload_len, reader)` for each. `handle` must consume
/// exactly `payload_len` bytes. Trailing per-attribute padding and any leftover
/// bytes are skipped so that exactly `budget` bytes are consumed overall.
fn for_each_sub_attr(
    reader: &mut dyn MultiRead,
    mut budget: usize,
    mut handle: impl FnMut(u16, usize, &mut dyn MultiRead) -> Result<()>,
) -> Result<()> {
    while budget >= size_of::<CAttrHeader>() {
        let Some(header) = reader.read_val_opt::<CAttrHeader>()? else {
            return Ok(());
        };
        budget -= size_of::<CAttrHeader>();

        // A declared total length below the header size is malformed; bail before
        // `payload_len()` (which subtracts the header size) can underflow.
        if header.total_len() < size_of::<CAttrHeader>() {
            reader.skip_some(budget);
            return Ok(());
        }

        let payload_len = header.payload_len();
        if payload_len > budget {
            // Malformed: the declared payload exceeds the remaining budget.
            reader.skip_some(budget);
            return Ok(());
        }

        handle(header.type_(), payload_len, reader)?;
        budget -= payload_len;

        let padding = budget.min(header.padding_len());
        reader.skip_some(padding);
        budget -= padding;
    }

    if budget > 0 {
        reader.skip_some(budget);
    }
    Ok(())
}

/// Reads a NUL-terminated string of at most `max` bytes from a `payload_len`-byte
/// attribute payload, skipping any remaining payload bytes.
fn read_cstring_field(
    reader: &mut dyn MultiRead,
    payload_len: usize,
    max: usize,
) -> Result<CString> {
    let (string, consumed) = reader.read_cstring_until_end(max.min(payload_len))?;
    if consumed < payload_len {
        reader.skip_some(payload_len - consumed);
    }
    Ok(string)
}

/// Parses an `IFLA_LINKINFO` payload (`IFLA_INFO_KIND` + `IFLA_INFO_DATA`).
fn read_link_info(reader: &mut dyn MultiRead, budget: usize) -> Result<LinkInfoData> {
    let mut data = LinkInfoData::default();
    for_each_sub_attr(reader, budget, |type_, payload_len, reader| {
        match type_ {
            IFLA_INFO_KIND => {
                data.kind = Some(read_cstring_field(reader, payload_len, IFNAME_SIZE)?)
            }
            IFLA_INFO_DATA => data.veth_peer = read_info_data(reader, payload_len)?,
            _ => reader.skip_some(payload_len),
        }
        Ok(())
    })?;
    Ok(data)
}

/// Parses an `IFLA_INFO_DATA` payload, extracting the `VETH_INFO_PEER` if present.
fn read_info_data(reader: &mut dyn MultiRead, budget: usize) -> Result<Option<VethPeer>> {
    let mut peer = None;
    for_each_sub_attr(reader, budget, |type_, payload_len, reader| {
        if type_ == VETH_INFO_PEER {
            peer = Some(read_veth_peer(reader, payload_len)?);
        } else {
            reader.skip_some(payload_len);
        }
        Ok(())
    })?;
    Ok(peer)
}

/// Parses a `VETH_INFO_PEER` payload: an `ifinfomsg` header (ignored) followed by
/// link attributes describing the peer (its name and target network namespace).
fn read_veth_peer(reader: &mut dyn MultiRead, payload_len: usize) -> Result<VethPeer> {
    let mut peer = VethPeer::default();
    if payload_len < IFINFOMSG_SIZE {
        reader.skip_some(payload_len);
        return Ok(peer);
    }
    // The peer's `ifinfomsg` carries flags/index we don't need at creation time.
    reader.skip_some(IFINFOMSG_SIZE);

    for_each_sub_attr(
        reader,
        payload_len - IFINFOMSG_SIZE,
        |type_, len, reader| {
            match type_ {
                IFLA_IFNAME_TYPE => peer.name = Some(read_cstring_field(reader, len, IFNAME_SIZE)?),
                IFLA_NET_NS_PID_TYPE if len == 4 => {
                    peer.net_ns_pid = reader.read_val_opt::<u32>()?
                }
                IFLA_NET_NS_FD_TYPE if len == 4 => peer.net_ns_fd = reader.read_val_opt::<u32>()?,
                _ => reader.skip_some(len),
            }
            Ok(())
        },
    )?;
    Ok(peer)
}

// `IFLA_*` type IDs used inside a `VETH_INFO_PEER`, matching `LinkAttrClass`.
const IFLA_IFNAME_TYPE: u16 = LinkAttrClass::IFNAME as u16;
const IFLA_NET_NS_PID_TYPE: u16 = LinkAttrClass::NET_NS_PID as u16;
const IFLA_NET_NS_FD_TYPE: u16 = LinkAttrClass::NET_NS_FD as u16;

bitflags! {
    /// New extended info filters for [`NlLinkAttr::ExtMask`].
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L819>.
    #[repr(C)]
    #[derive(Pod)]
    pub struct RtExtFilter: u32 {
        const VF = 1 << 0;
        const BRVLAN = 1 << 1;
        const BRVLAN_COMPRESSED = 1 << 2;
        const SKIP_STATS = 1 << 3;
        const MRP = 1 << 4;
        const CFM_CONFIG = 1 << 5;
        const CFM_STATUS = 1 << 6;
        const MST = 1 << 7;
    }
}
