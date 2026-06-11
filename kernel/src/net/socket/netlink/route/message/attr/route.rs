// SPDX-License-Identifier: MPL-2.0

use crate::{
    net::socket::netlink::message::{Attribute, CAttrHeader, ContinueRead},
    prelude::*,
    util::MultiRead,
};

// Route attribute type IDs (`rtattr_type_t` in Linux).
//
// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L344>.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

/// Route-related attributes.
#[derive(Debug)]
pub enum RouteAttr {
    /// `RTA_DST`: the (network) destination address of the route.
    Dst([u8; 4]),
    /// `RTA_GATEWAY`: the gateway of the route.
    Gateway([u8; 4]),
    /// `RTA_PREFSRC`: the preferred source address.
    PrefSrc([u8; 4]),
    /// `RTA_OIF`: the output interface index.
    Oif(u32),
    /// `RTA_TABLE`: the routing table ID.
    Table(u32),
}

impl Attribute for RouteAttr {
    fn type_(&self) -> u16 {
        match self {
            RouteAttr::Dst(_) => RTA_DST,
            RouteAttr::Gateway(_) => RTA_GATEWAY,
            RouteAttr::PrefSrc(_) => RTA_PREFSRC,
            RouteAttr::Oif(_) => RTA_OIF,
            RouteAttr::Table(_) => RTA_TABLE,
        }
    }

    fn payload_as_bytes(&self) -> &[u8] {
        match self {
            RouteAttr::Dst(addr) | RouteAttr::Gateway(addr) | RouteAttr::PrefSrc(addr) => addr,
            RouteAttr::Oif(val) | RouteAttr::Table(val) => val.as_bytes(),
        }
    }

    fn read_from(header: &CAttrHeader, reader: &mut dyn MultiRead) -> Result<ContinueRead<Self>>
    where
        Self: Sized,
    {
        // GETROUTE is currently dump-only; request attributes (filters) are
        // ignored, matching how GETADDR requests are handled.
        reader.skip_some(header.payload_len());
        Ok(ContinueRead::Skipped)
    }
}
