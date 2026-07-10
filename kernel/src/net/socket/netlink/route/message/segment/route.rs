// SPDX-License-Identifier: MPL-2.0

use super::legacy::CRtGenMsg;
use crate::{
    net::socket::netlink::{
        message::{SegmentBody, SegmentCommon},
        route::message::attr::route::RouteAttr,
    },
    prelude::*,
};

pub type RouteSegment = SegmentCommon<RouteSegmentBody, RouteAttr>;

impl SegmentBody for RouteSegmentBody {
    type CLegacyType = CRtGenMsg;
    type CType = CRtMsg;
}

/// `rtmsg` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.13/source/include/uapi/linux/rtnetlink.h#L237>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub struct CRtMsg {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub type_: u8,
    pub flags: u32,
}

/// The validated body of a route segment.
///
/// The fields are kept as raw values: in dump requests they are unused
/// filters, and in responses the kernel fills in well-known constants
/// (see the `RT_*`/`RTN_*`/`RTPROT_*` constants in the kernel handler).
#[derive(Clone, Copy, Debug)]
pub struct RouteSegmentBody {
    pub family: u8,
    pub dst_len: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub type_: u8,
}

impl TryFrom<CRtMsg> for RouteSegmentBody {
    type Error = Error;

    fn try_from(value: CRtMsg) -> Result<Self> {
        Ok(Self {
            family: value.family,
            dst_len: value.dst_len,
            table: value.table,
            protocol: value.protocol,
            scope: value.scope,
            type_: value.type_,
        })
    }
}

impl From<RouteSegmentBody> for CRtMsg {
    fn from(value: RouteSegmentBody) -> Self {
        CRtMsg {
            family: value.family,
            dst_len: value.dst_len,
            src_len: 0,
            tos: 0,
            table: value.table,
            protocol: value.protocol,
            scope: value.scope,
            type_: value.type_,
            flags: 0,
        }
    }
}
