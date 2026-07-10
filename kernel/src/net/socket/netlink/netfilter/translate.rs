// SPDX-License-Identifier: MPL-2.0

//! Lowering kube-proxy's nftables ruleset into the native NAT datapath.
//!
//! kube-proxy (nftables mode) programs Service load-balancing as an nftables
//! ruleset. We don't run a general nft engine; instead we extract just the
//! Service ClusterIP -> backend mapping from the messages it sends and install
//! it into `aster_bigtcp::nat::nat_table()` (the same fast datapath the
//! `PR_ASTERKUBE_DNAT` prctl drives). This is control-plane translation, not
//! per-packet interpretation.
//!
//! Two pieces of kube-proxy's ruleset carry everything we need, and both are
//! plain names/values (no nft expression bytecode):
//!   - the `service-ips` set: each element maps `VIP . proto . port` to a
//!     verdict `goto service-<hash>-<ns>/<svc>/<proto>/<port>`;
//!   - the per-endpoint chains, named
//!     `endpoint-<hash>-<ns>/<svc>/<proto>/<port>__<backend-ip>/<backend-port>`.
//! They share the `<ns>/<svc>/<proto>/<port>` "service identity", so we join on
//! it: VIP:port (from the set) -> backends (from the endpoint chain names).

use spin::Mutex;

use crate::{net::socket::netlink::message::CMsgSegHdr, prelude::*};

// Netfilter subsystem / message types (see netfilter/kernel.rs for the rest).
const NFNL_SUBSYS_NONE: u16 = 0;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_END: u16 = 17;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWSETELEM: u16 = 12;

// nftables attribute types we read.
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CHAIN: u16 = 2;

/// Accumulated kube-proxy Service state, joined on the service identity.
struct State {
    /// service identity -> backend (ipv4, port) list.
    endpoints: BTreeMap<String, Vec<([u8; 4], u16)>>,
    /// service identity -> (VIP, proto, vport).
    services: BTreeMap<String, ([u8; 4], u8, u16)>,
}

impl State {
    const fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }
}

static STATE: Mutex<State> = Mutex::new(State::new());

/// Observes one nftables request, accumulating Service state and (on a batch
/// commit) reprogramming the NAT table.
pub(super) fn observe(header: &CMsgSegHdr, payload: &[u8]) {
    let subsys = header.type_ >> 8;
    let msg = header.type_ & 0xff;

    if subsys == NFNL_SUBSYS_NONE && msg == NFNL_MSG_BATCH_END {
        reprogram();
        return;
    }
    if subsys != NFNL_SUBSYS_NFTABLES || payload.len() < 4 {
        return;
    }
    // Skip the 4-byte `nfgenmsg`; the attributes follow.
    let attrs = &payload[4..];
    match msg {
        NFT_MSG_NEWCHAIN => observe_chain(attrs),
        NFT_MSG_NEWSETELEM => observe_setelem(attrs),
        _ => {}
    }
}

/// An endpoint chain name carries a backend; record it under its identity.
fn observe_chain(attrs: &[u8]) {
    let Some(name) = find_attr(attrs, NFTA_CHAIN_NAME).map(attr_str) else {
        return;
    };
    // endpoint-<8-char hash>-<identity>__<ip>/<port>
    let Some(rest) = name.strip_prefix("endpoint-") else {
        return;
    };
    if rest.len() < 9 {
        return;
    }
    let after_hash = &rest[9..]; // skip the 8-char hash and its '-'
    let Some((identity, backend)) = after_hash.split_once("__") else {
        return;
    };
    let Some((ip_str, port_str)) = backend.split_once('/') else {
        return;
    };
    let (Some(ip), Ok(port)) = (parse_ipv4(ip_str), port_str.parse::<u16>()) else {
        return;
    };

    let mut state = STATE.lock();
    let eps = state.endpoints.entry(identity.to_string()).or_default();
    if !eps.contains(&(ip, port)) {
        eps.push((ip, port));
    }
}

/// The `service-ips` set maps VIP.proto.port -> goto service chain.
fn observe_setelem(attrs: &[u8]) {
    let Some(set_name) = find_attr(attrs, NFTA_SET_ELEM_LIST_SET).map(attr_str) else {
        return;
    };
    if set_name != "service-ips" {
        return;
    }
    let Some(elements) = find_attr(attrs, NFTA_SET_ELEM_LIST_ELEMENTS) else {
        return;
    };
    for (typ, elem) in NlaIter::new(elements) {
        if typ == NFTA_LIST_ELEM {
            observe_service_elem(elem);
        }
    }
}

fn observe_service_elem(elem: &[u8]) {
    // Key: a `ipv4_addr . inet_proto . inet_service` concatenation, each field
    // padded to a 4-byte register: [ip0..3][proto,_,_,_][port_be,_,_].
    let Some(key) = find_attr(elem, NFTA_SET_ELEM_KEY).and_then(|k| find_attr(k, NFTA_DATA_VALUE))
    else {
        return;
    };
    if key.len() < 10 {
        return;
    }
    let vip = [key[0], key[1], key[2], key[3]];
    let proto = key[4];
    let vport = u16::from_be_bytes([key[8], key[9]]);

    // Data: a verdict whose chain is `service-<hash>-<identity>`.
    let Some(chain) = find_attr(elem, NFTA_SET_ELEM_DATA)
        .and_then(|d| find_attr(d, NFTA_DATA_VERDICT))
        .and_then(|v| find_attr(v, NFTA_VERDICT_CHAIN))
        .map(attr_str)
    else {
        return;
    };
    let Some(rest) = chain.strip_prefix("service-") else {
        return;
    };
    if rest.len() < 9 {
        return;
    }
    let identity = &rest[9..]; // skip the 8-char hash and its '-'

    STATE
        .lock()
        .services
        .insert(identity.to_string(), (vip, proto, vport));
}

/// Reinstalls the NAT table from the accumulated Service state (idempotent:
/// `add_dnat` deduplicates).
fn reprogram() {
    let state = STATE.lock();
    let nat = aster_bigtcp::nat::nat_table();
    let mut backends = 0usize;
    for (identity, &(vip, proto, vport)) in state.services.iter() {
        let Some(eps) = state.endpoints.get(identity) else {
            continue;
        };
        for &(backend, bport) in eps.iter() {
            nat.add_dnat(vip, vport, proto, backend, bport);
            backends += 1;
            ostd::early_println!(
                "astrokube nat: {}.{}.{}.{}:{}/{} -> {}.{}.{}.{}:{}  [{}]",
                vip[0], vip[1], vip[2], vip[3], vport, proto_name(proto),
                backend[0], backend[1], backend[2], backend[3], bport, identity
            );
        }
    }
    if backends > 0 {
        ostd::early_println!(
            "astrokube nat: programmed {} Service backend(s) from kube-proxy nftables",
            backends
        );
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for octet in octets.iter_mut() {
        *octet = parts.next()?.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// A trailing-NUL-terminated string attribute as a `&str`.
fn attr_str(val: &[u8]) -> &str {
    let end = val.iter().position(|&b| b == 0).unwrap_or(val.len());
    core::str::from_utf8(&val[..end]).unwrap_or("")
}

/// Finds the first attribute of the given type in an attribute buffer.
fn find_attr(buf: &[u8], typ: u16) -> Option<&[u8]> {
    NlaIter::new(buf).find(|(t, _)| *t == typ).map(|(_, v)| v)
}

/// Iterates `nlattr` TLVs in a buffer, yielding `(type, value)` with the nested
/// / byte-order flags masked off the type.
struct NlaIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NlaIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for NlaIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let nla_len =
            u16::from_ne_bytes([self.buf[self.pos], self.buf[self.pos + 1]]) as usize;
        let nla_type =
            u16::from_ne_bytes([self.buf[self.pos + 2], self.buf[self.pos + 3]]) & 0x3fff;
        if nla_len < 4 || self.pos + nla_len > self.buf.len() {
            return None;
        }
        let value = &self.buf[self.pos + 4..self.pos + nla_len];
        self.pos += (nla_len + 3) & !3; // advance with 4-byte alignment
        Some((nla_type, value))
    }
}
