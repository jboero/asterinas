// SPDX-License-Identifier: MPL-2.0

//! Netlink Netfilter Socket (`NETLINK_NETFILTER`).
//!
//! This is the kernel surface that `nft` and `iptables-nft` talk to. The
//! implementation is minimal — it answers generation/dump probes against an
//! empty ruleset and acknowledges rule-programming batches — so that those
//! tools (and hence the cluster's kube-proxy/kindnet DaemonSets) run on
//! Asterinas without erroring. Enforcing the programmed rules by lowering them
//! into the native NAT datapath is future work.

pub(super) use message::NfnlMessage;

use crate::net::socket::netlink::{common::NetlinkSocket, table::NetlinkNetfilterProtocol};

mod bound;
mod kernel;
mod message;
mod translate;

pub type NetlinkNetfilterSocket = NetlinkSocket<NetlinkNetfilterProtocol>;
