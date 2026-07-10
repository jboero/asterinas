// SPDX-License-Identifier: MPL-2.0

//! Message types for the `NETLINK_NETFILTER` protocol.
//!
//! Unlike the route protocol, which fully parses each segment into a typed body,
//! this is a minimal surface: it parses only the fixed `nlmsghdr` of each request
//! segment and skips the payload (the actual nftables expressions), which is
//! enough to answer the probes that `nft`/`iptables-nft` send (generation,
//! dumps) and to acknowledge rule-programming batches. Translating the payloads
//! into the native NAT datapath is future work.

use align_ext::AlignExt;
use ostd::mm::{VmReader, VmWriter};

use crate::{
    net::socket::netlink::message::{
        CMsgSegHdr, CSegmentType, ContinueRead, ErrorSegment, Message, NLMSG_ALIGN,
        ProtocolSegment, SegHdrCommonFlags,
    },
    prelude::*,
    util::{MultiRead, MultiWrite},
};

/// A netlink netfilter message (one or more [`NfnlSegment`]s).
pub(in crate::net::socket::netlink) type NfnlMessage = Message<NfnlSegment>;

/// A single netfilter netlink segment: the fixed header plus a raw payload.
///
/// The payload is retained (not just skipped): for *requests* it carries the
/// nftables body that the rule translator parses (`super::translate`); for
/// *responses* it carries the hand-built body (e.g. an `nlmsgerr` ack, a
/// `NFT_MSG_NEWGEN` generation message).
#[derive(Debug)]
pub struct NfnlSegment {
    header: CMsgSegHdr,
    payload: Vec<u8>,
}

impl NfnlSegment {
    /// The message body following the fixed header.
    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl NfnlSegment {
    /// Builds a response segment from a type, the originating request header
    /// (for the echoed seq/pid), and a payload; the length is filled in.
    fn response(type_: u16, flags: u16, request: &CMsgSegHdr, payload: Vec<u8>) -> Self {
        let len = (size_of::<CMsgSegHdr>() + payload.len()) as u32;
        Self {
            header: CMsgSegHdr {
                len,
                type_,
                flags,
                seq: request.seq,
                pid: request.pid,
            },
            payload,
        }
    }

    /// An `NLMSG_ERROR` segment. `error_code` is 0 for a plain acknowledgment or
    /// a negative errno for a failure.
    pub(super) fn error(request: &CMsgSegHdr, error_code: i32) -> Self {
        // struct nlmsgerr { int error; struct nlmsghdr msg; }
        let mut payload = Vec::with_capacity(size_of::<i32>() + size_of::<CMsgSegHdr>());
        payload.extend_from_slice(&error_code.to_ne_bytes());
        payload.extend_from_slice(request.as_bytes());
        Self::response(CSegmentType::ERROR as u16, 0, request, payload)
    }

    /// An `NLMSG_DONE` segment terminating a (here always empty) dump.
    pub(super) fn done(request: &CMsgSegHdr) -> Self {
        let payload = 0i32.to_ne_bytes().to_vec();
        Self::response(CSegmentType::DONE as u16, 0, request, payload)
    }

    /// An `NFT_MSG_NEWGEN` segment reporting the ruleset generation number.
    pub(super) fn newgen(request: &CMsgSegHdr, type_: u16, gen_id: u32) -> Self {
        // struct nfgenmsg { __u8 family; __u8 version; __be16 res_id; }
        let mut payload = Vec::new();
        payload.push(0u8); // NFPROTO_UNSPEC
        payload.push(0u8); // NFNETLINK_V0
        payload.extend_from_slice(&0u16.to_be_bytes()); // res_id
        // nlattr { __u16 nla_len; __u16 nla_type; } + __be32 gen id; NFTA_GEN_ID = 1.
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&1u16.to_ne_bytes());
        payload.extend_from_slice(&gen_id.to_be_bytes());
        Self::response(type_, 0, request, payload)
    }
}

impl ProtocolSegment for NfnlSegment {
    fn header(&self) -> &CMsgSegHdr {
        &self.header
    }

    fn header_mut(&mut self) -> &mut CMsgSegHdr {
        &mut self.header
    }

    fn read_from(reader: &mut dyn MultiRead) -> Result<ContinueRead<Self, ErrorSegment>> {
        // Read the fixed header; a short read means there are no more segments.
        let Some(header) = reader.read_val_opt::<CMsgSegHdr>()? else {
            return_errno_with_message!(Errno::EINVAL, "no more netlink netfilter segments");
        };

        // Validate `header.len`, then read the payload (retained for the rule
        // translator) and skip the trailing alignment padding. An invalid length
        // is unrecoverable, so propagate the error to stop parsing.
        let payload_len_with_padding = header.calc_payload_len_with_padding(reader)?;
        let payload_len = (header.len as usize).saturating_sub(size_of::<CMsgSegHdr>());
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            let mut writer = VmWriter::from(payload.as_mut_slice());
            reader.read(&mut writer).map_err(|(err, _)| err)?;
        }
        reader.skip_some(payload_len_with_padding - payload_len);

        Ok(ContinueRead::Parsed(Self { header, payload }))
    }

    fn write_to(&self, writer: &mut dyn MultiWrite) -> Result<()> {
        writer.write_val_trunc(&self.header)?;
        if !self.payload.is_empty() {
            writer.write(&mut VmReader::from(self.payload.as_slice()))?;
        }
        let total = size_of::<CMsgSegHdr>() + self.payload.len();
        let padding = total.align_up(NLMSG_ALIGN) - total;
        writer.skip_some(padding);
        Ok(())
    }
}

// nftables flags helper: detect a dump request (NLM_F_ROOT set on a GET type).
pub(super) fn is_dump_request(header: &CMsgSegHdr) -> bool {
    use crate::net::socket::netlink::message::GetRequestFlags;
    GetRequestFlags::from_bits_truncate(header.flags).contains(GetRequestFlags::ROOT)
}

pub(super) fn wants_ack(header: &CMsgSegHdr) -> bool {
    SegHdrCommonFlags::from_bits_truncate(header.flags).contains(SegHdrCommonFlags::ACK)
}
