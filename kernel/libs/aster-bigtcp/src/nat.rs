// SPDX-License-Identifier: MPL-2.0

//! A minimal IPv4 NAT engine for Service (ClusterIP) destination NAT.
//!
//! This is the datapath underneath Kubernetes Services: a virtual IP
//! (`VIP:vport`) is rewritten to a backend `backend:bport` on the way in
//! (DNAT), and the backend's reply has its source rewritten back to the VIP on
//! the way out, so the client only ever sees the VIP. A small connection-
//! tracking table remembers each translated flow so the reverse rewrite can be
//! applied to replies.
//!
//! The engine operates on raw IPv4 frame bytes and is consulted from the bridge
//! forwarding path (see [`crate::device::BridgeHub`]). It is intentionally
//! small: a global rule/conntrack table, IPv4 + UDP/TCP only, no general
//! prerouting hook and no SNAT/masquerade yet. The control surface that
//! programs rules is, for now, an `astrokube` `prctl` extension; the
//! `nftables`-compatible netlink surface is future work.

use alloc::{collections::vec_deque::VecDeque, vec::Vec};

use ostd::sync::SpinLock;
use spin::Once;

/// IPv4 protocol numbers we rewrite.
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// A destination-NAT rule: `vip:vport/proto` → `backend:bport`.
#[derive(Clone, Copy, Debug)]
pub struct DnatRule {
    pub vip: [u8; 4],
    pub vport: u16,
    pub proto: u8,
    pub backend: [u8; 4],
    pub bport: u16,
}

/// A tracked, DNAT-translated flow, used to reverse-translate replies.
///
/// The reply travels `backend:bport → client:cport`; matching it lets us
/// rewrite the source back to `vip:vport`.
#[derive(Clone, Copy)]
struct Conntrack {
    proto: u8,
    backend: [u8; 4],
    bport: u16,
    client: [u8; 4],
    cport: u16,
    vip: [u8; 4],
    vport: u16,
}

const MAX_CONNTRACK: usize = 512;

/// The global NAT table.
pub struct NatTable {
    rules: SpinLock<Vec<DnatRule>>,
    conntrack: SpinLock<VecDeque<Conntrack>>,
}

impl NatTable {
    fn new() -> Self {
        Self {
            rules: SpinLock::new(Vec::new()),
            conntrack: SpinLock::new(VecDeque::new()),
        }
    }

    /// Installs (or replaces) a DNAT rule.
    pub fn add_dnat(&self, rule: DnatRule) {
        let mut rules = self.rules.lock();
        if let Some(existing) = rules
            .iter_mut()
            .find(|r| r.vip == rule.vip && r.vport == rule.vport && r.proto == rule.proto)
        {
            *existing = rule;
        } else {
            rules.push(rule);
        }
    }

    /// Whether any rule is installed (a cheap fast-path gate for the datapath).
    pub fn is_empty(&self) -> bool {
        self.rules.lock().is_empty()
    }

    /// Applies NAT to an IPv4 frame in place. Returns `true` if the frame was
    /// rewritten. Tries the reverse (reply) translation first, then forward DNAT.
    pub fn apply(&self, frame: &mut [u8]) -> bool {
        let Some(p) = Packet::parse(frame) else {
            return false;
        };

        // Reverse path: a reply from a known backend → rewrite source to the VIP.
        {
            let mut ct = self.conntrack.lock();
            if let Some(entry) = ct.iter().find(|e| {
                e.proto == p.proto
                    && e.backend == p.src
                    && e.bport == p.sport
                    && e.client == p.dst
                    && e.cport == p.dport
            }) {
                let (vip, vport) = (entry.vip, entry.vport);
                drop(ct);
                rewrite_src(frame, &p, vip, vport);
                return true;
            }
        }

        // Forward path: a packet to a VIP → rewrite destination to the backend
        // and remember the flow.
        let rule = {
            let rules = self.rules.lock();
            rules
                .iter()
                .find(|r| r.proto == p.proto && r.vip == p.dst && r.vport == p.dport)
                .copied()
        };
        let Some(rule) = rule else {
            return false;
        };

        self.record(Conntrack {
            proto: p.proto,
            backend: rule.backend,
            bport: rule.bport,
            client: p.src,
            cport: p.sport,
            vip: rule.vip,
            vport: rule.vport,
        });
        rewrite_dst(frame, &p, rule.backend, rule.bport);
        true
    }

    fn record(&self, entry: Conntrack) {
        let mut ct = self.conntrack.lock();
        // Refresh an identical flow instead of duplicating it.
        if ct.iter().any(|e| {
            e.proto == entry.proto
                && e.backend == entry.backend
                && e.bport == entry.bport
                && e.client == entry.client
                && e.cport == entry.cport
        }) {
            return;
        }
        if ct.len() >= MAX_CONNTRACK {
            ct.pop_front();
        }
        ct.push_back(entry);
    }
}

/// Returns the global NAT table.
pub fn nat_table() -> &'static NatTable {
    static TABLE: Once<NatTable> = Once::new();
    TABLE.call_once(NatTable::new)
}

/// A parsed view of the fixed offsets in an IPv4 + UDP/TCP frame.
struct Packet {
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    /// Offset of the L4 header (IPv4 header length).
    l4: usize,
}

impl Packet {
    fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() < 20 || (frame[0] >> 4) != 4 {
            return None;
        }
        let ihl = ((frame[0] & 0x0f) as usize) * 4;
        if ihl < 20 || frame.len() < ihl + 4 {
            return None;
        }
        let proto = frame[9];
        if proto != PROTO_TCP && proto != PROTO_UDP {
            return None;
        }
        let src = [frame[12], frame[13], frame[14], frame[15]];
        let dst = [frame[16], frame[17], frame[18], frame[19]];
        let sport = u16::from_be_bytes([frame[ihl], frame[ihl + 1]]);
        let dport = u16::from_be_bytes([frame[ihl + 2], frame[ihl + 3]]);
        Some(Self {
            proto,
            src,
            dst,
            sport,
            dport,
            l4: ihl,
        })
    }
}

fn rewrite_dst(frame: &mut [u8], p: &Packet, addr: [u8; 4], port: u16) {
    frame[16..20].copy_from_slice(&addr);
    frame[p.l4 + 2..p.l4 + 4].copy_from_slice(&port.to_be_bytes());
    fix_checksums(frame, p);
}

fn rewrite_src(frame: &mut [u8], p: &Packet, addr: [u8; 4], port: u16) {
    frame[12..16].copy_from_slice(&addr);
    frame[p.l4..p.l4 + 2].copy_from_slice(&port.to_be_bytes());
    fix_checksums(frame, p);
}

/// Recomputes the IPv4 header checksum and the L4 (UDP/TCP) checksum after an
/// address/port rewrite. Recomputed from scratch for simplicity and safety.
fn fix_checksums(frame: &mut [u8], p: &Packet) {
    // IPv4 header checksum (bytes 10..12), over the `l4`-byte header.
    frame[10] = 0;
    frame[11] = 0;
    let ip_csum = checksum(&frame[..p.l4]);
    frame[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // L4 checksum over the pseudo-header + L4 segment.
    let l4_len = frame.len() - p.l4;
    let csum_off = match p.proto {
        PROTO_UDP => p.l4 + 6,
        PROTO_TCP => p.l4 + 16,
        _ => return,
    };
    if frame.len() < csum_off + 2 {
        return;
    }
    frame[csum_off] = 0;
    frame[csum_off + 1] = 0;

    let mut sum = pseudo_header_sum(frame, p.proto, l4_len as u16);
    sum += sum_words(&frame[p.l4..]);
    let mut folded = fold(sum);
    if p.proto == PROTO_UDP && folded == 0 {
        // A zero UDP checksum means "no checksum"; the real value 0 is sent as
        // 0xFFFF.
        folded = 0xffff;
    }
    frame[csum_off..csum_off + 2].copy_from_slice(&folded.to_be_bytes());
}

fn pseudo_header_sum(frame: &[u8], proto: u8, l4_len: u16) -> u32 {
    let mut sum = 0u32;
    // src and dst addresses (bytes 12..20).
    sum += sum_words(&frame[12..20]);
    sum += proto as u32;
    sum += l4_len as u32;
    sum
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum(data: &[u8]) -> u16 {
    fold(sum_words(data))
}
