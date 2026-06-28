// SPDX-License-Identifier: MPL-2.0

//! The kernel-side handler for `NETLINK_NETFILTER` requests.
//!
//! This is intentionally minimal: it answers the probes that `nft` and
//! `iptables-nft` issue so they run without error against an (empty) ruleset,
//! and acknowledges rule-programming batches. It does not yet enforce any
//! rules — translating the nftables payloads into the native NAT datapath
//! (`aster_bigtcp::nat::nat_table()`, today driven by the `PR_ASTROKUBE_*`
//! prctls) is the next step.

use super::message::{NfnlMessage, NfnlSegment, is_dump_request, wants_ack};
use crate::{
    net::socket::netlink::{
        addr::PortNum,
        message::{CMsgSegHdr, ProtocolSegment},
        table::{NetlinkNetfilterProtocol, SupportedNetlinkProtocol},
    },
    prelude::*,
};

// Netfilter netlink subsystem IDs (high byte of nlmsghdr.type).
const NFNL_SUBSYS_NONE: u16 = 0;
const NFNL_SUBSYS_NFTABLES: u16 = 10;

// Batch control messages (NFNL_SUBSYS_NONE).
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// nftables message types (low byte of nlmsghdr.type), NFNL_SUBSYS_NFTABLES.
const NFT_MSG_NEWGEN: u16 = 15;
const NFT_MSG_GETGEN: u16 = 16;

/// Whether an nftables message type is a (dump-capable) GET request.
fn is_nft_get(msg: u16) -> bool {
    // GETTABLE, GETCHAIN, GETRULE, GETSET, GETSETELEM, GETOBJ, GETOBJ_RESET, GETFLOWTABLE.
    matches!(msg, 1 | 4 | 7 | 10 | 13 | 19 | 21 | 23)
}

/// Handles one request segment by enqueuing any response back to the sender.
pub(super) fn handle_request(segment: &NfnlSegment, dst_port: PortNum) {
    let responses = compute_responses(segment.header());
    if responses.is_empty() {
        return;
    }
    let message = NfnlMessage::new(responses);
    // The sender is bound to `dst_port`; deliver the response to its queue.
    let _ = NetlinkNetfilterProtocol::unicast(dst_port, message);
}

/// Computes the response segments for a single request header.
fn compute_responses(header: &CMsgSegHdr) -> Vec<NfnlSegment> {
    let subsys = header.type_ >> 8;
    let msg = header.type_ & 0xff;

    match subsys {
        NFNL_SUBSYS_NONE => match msg {
            // A batch opens/closes a transaction. We process messages eagerly as
            // they arrive, so BEGIN needs no reply and END is acknowledged.
            NFNL_MSG_BATCH_BEGIN => Vec::new(),
            NFNL_MSG_BATCH_END => ack_if_requested(header),
            _ => ack_if_requested(header),
        },
        NFNL_SUBSYS_NFTABLES => {
            if msg == NFT_MSG_GETGEN {
                let type_ = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWGEN;
                return vec![NfnlSegment::newgen(header, type_, 0)];
            }
            if is_nft_get(msg) {
                // Dump → empty ruleset terminated by NLMSG_DONE; a lookup of a
                // specific object → ENOENT (we hold no objects yet).
                if is_dump_request(header) {
                    return vec![NfnlSegment::done(header)];
                }
                return vec![NfnlSegment::error(header, -(Errno::ENOENT as i32))];
            }
            // NEW*/DEL* rule programming: accepted as a no-op for now.
            ack_if_requested(header)
        }
        _ => ack_if_requested(header),
    }
}

fn ack_if_requested(header: &CMsgSegHdr) -> Vec<NfnlSegment> {
    if wants_ack(header) {
        vec![NfnlSegment::error(header, 0)]
    } else {
        Vec::new()
    }
}
