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
//! A VIP may have several backends (Kubernetes endpoints); a new flow is
//! pinned to one of them by hashing the client's address and port, and the
//! choice is remembered in the conntrack entry so every later packet of that
//! flow reaches the same backend (per-connection stickiness, like kube-proxy).
//!
//! The engine operates on raw IPv4 frame bytes and is consulted from the bridge
//! forwarding path (see [`crate::device::BridgeHub`]). It is intentionally
//! small: a global rule/conntrack table, IPv4 + UDP/TCP only, no general
//! prerouting hook and no SNAT/masquerade yet. The control surface that
//! programs rules is, for now, an `astrokube` `prctl` extension; the
//! `nftables`-compatible netlink surface is future work.

use alloc::{collections::vec_deque::VecDeque, vec, vec::Vec};

use ostd::sync::SpinLock;
use spin::Once;

/// IPv4 protocol numbers we rewrite.
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// One backend endpoint of a Service: an address and port to DNAT toward.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Backend {
    addr: [u8; 4],
    port: u16,
}

/// A destination-NAT rule: `vip:vport/proto` → one of `backends`.
///
/// A rule carries a *set* of backends (Service endpoints). Which one a given
/// flow uses is chosen once, when the flow is first seen, and pinned in the
/// conntrack entry thereafter.
#[derive(Clone, Debug)]
struct DnatRule {
    vip: [u8; 4],
    vport: u16,
    proto: u8,
    backends: Vec<Backend>,
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

/// A masqueraded (source-NAT) flow.
///
/// When a pod's packet egresses toward a network the cluster does not own, its
/// source address is rewritten to the egress interface's address (`masq_addr`),
/// so the outside host replies to the node rather than to an unroutable pod
/// address. The port is left unchanged, so `sport` doubles as the demux key for
/// replies. This entry lets the reply (`remote:rport → masq_addr:sport`) have
/// its destination rewritten back to the original pod (`orig_src:sport`).
#[derive(Clone, Copy)]
struct Masq {
    proto: u8,
    orig_src: [u8; 4],
    sport: u16,
    masq_addr: [u8; 4],
    remote: [u8; 4],
    rport: u16,
}

/// The global NAT table.
pub struct NatTable {
    rules: SpinLock<Vec<DnatRule>>,
    conntrack: SpinLock<VecDeque<Conntrack>>,
    masq: SpinLock<VecDeque<Masq>>,
}

impl NatTable {
    fn new() -> Self {
        Self {
            rules: SpinLock::new(Vec::new()),
            conntrack: SpinLock::new(VecDeque::new()),
            masq: SpinLock::new(VecDeque::new()),
        }
    }

    /// Adds a backend endpoint to the `vip:vport/proto` Service, creating the
    /// rule if it does not exist yet. Calling this repeatedly for one VIP builds
    /// up its backend set; a duplicate backend is ignored.
    pub fn add_dnat(&self, vip: [u8; 4], vport: u16, proto: u8, backend: [u8; 4], bport: u16) {
        let endpoint = Backend {
            addr: backend,
            port: bport,
        };
        let mut rules = self.rules.lock();
        if let Some(existing) = rules
            .iter_mut()
            .find(|r| r.vip == vip && r.vport == vport && r.proto == proto)
        {
            if !existing.backends.contains(&endpoint) {
                existing.backends.push(endpoint);
            }
        } else {
            rules.push(DnatRule {
                vip,
                vport,
                proto,
                backends: vec![endpoint],
            });
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

        // Masquerade reverse path: a reply to a masqueraded flow
        // (`remote:rport → masq_addr:sport`) → rewrite destination back to the
        // original pod address.
        {
            let masq = self.masq.lock();
            if let Some(entry) = masq.iter().find(|e| {
                e.proto == p.proto
                    && e.masq_addr == p.dst
                    && e.sport == p.dport
                    && e.remote == p.src
                    && e.rport == p.sport
            }) {
                let orig_src = entry.orig_src;
                drop(masq);
                rewrite_dst_addr(frame, &p, orig_src);
                return true;
            }
        }

        // Reverse path: a reply from a known backend → rewrite source to the VIP.
        {
            let ct = self.conntrack.lock();
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

        // Forward path: a packet to a VIP → pick a backend, rewrite the
        // destination to it, and remember the flow.
        let backend = {
            let rules = self.rules.lock();
            rules
                .iter()
                .find(|r| r.proto == p.proto && r.vip == p.dst && r.vport == p.dport)
                .and_then(|rule| {
                    // Pin this flow to one backend by hashing the client. The
                    // same client address+port always maps to the same backend,
                    // so a flow stays sticky even before its conntrack exists.
                    let n = rule.backends.len();
                    if n == 0 {
                        return None;
                    }
                    let idx = (flow_hash(p.src, p.sport) as usize) % n;
                    Some(rule.backends[idx])
                })
        };
        let Some(backend) = backend else {
            return false;
        };

        self.record(Conntrack {
            proto: p.proto,
            backend: backend.addr,
            bport: backend.port,
            client: p.src,
            cport: p.sport,
            vip: p.dst,
            vport: p.dport,
        });
        rewrite_dst(frame, &p, backend.addr, backend.port);
        true
    }

    /// Whether the engine has any state, so the datapath knows it must consult
    /// [`Self::apply`]. (A masquerade reply is reversed there.)
    pub fn is_active(&self) -> bool {
        !self.rules.lock().is_empty() || !self.masq.lock().is_empty()
    }

    /// Masquerades an outbound frame: rewrites its source address to `masq_addr`
    /// (leaving the port) and records the flow so the reply can be reversed.
    /// Returns whether the frame was an IPv4 UDP/TCP packet that was rewritten.
    pub fn masquerade(&self, frame: &mut [u8], masq_addr: [u8; 4]) -> bool {
        let Some(p) = Packet::parse(frame) else {
            return false;
        };
        // Already from this address (e.g. node-originated): nothing to do.
        if p.src == masq_addr {
            return false;
        }
        self.record_masq(Masq {
            proto: p.proto,
            orig_src: p.src,
            sport: p.sport,
            masq_addr,
            remote: p.dst,
            rport: p.dport,
        });
        rewrite_src_addr(frame, &p, masq_addr);
        true
    }

    fn record_masq(&self, entry: Masq) {
        let mut masq = self.masq.lock();
        if masq.iter().any(|e| {
            e.proto == entry.proto
                && e.orig_src == entry.orig_src
                && e.sport == entry.sport
                && e.remote == entry.remote
                && e.rport == entry.rport
        }) {
            return;
        }
        if masq.len() >= MAX_CONNTRACK {
            masq.pop_front();
        }
        masq.push_back(entry);
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
    /// Total IPv4 packet length from the header, used to bound checksum
    /// recomputation. A received Ethernet frame may carry padding past the IP
    /// packet (minimum frame size), which must not be folded into the checksum.
    total_len: usize,
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
        // Trust the IP total-length field, but never read past the buffer; fall
        // back to the buffer length if it is absent or implausible.
        let declared = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        let total_len = if declared >= ihl + 4 && declared <= frame.len() {
            declared
        } else {
            frame.len()
        };
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
            total_len,
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

/// Rewrites only the source address (used by masquerade, which keeps the port).
fn rewrite_src_addr(frame: &mut [u8], p: &Packet, addr: [u8; 4]) {
    frame[12..16].copy_from_slice(&addr);
    fix_checksums(frame, p);
}

/// Rewrites only the destination address (used by masquerade reverse).
fn rewrite_dst_addr(frame: &mut [u8], p: &Packet, addr: [u8; 4]) {
    frame[16..20].copy_from_slice(&addr);
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

    // L4 checksum over the pseudo-header + L4 segment. Bound by the IP total
    // length so trailing Ethernet padding on received frames is excluded.
    let l4_len = p.total_len - p.l4;
    let csum_off = match p.proto {
        PROTO_UDP => p.l4 + 6,
        PROTO_TCP => p.l4 + 16,
        _ => return,
    };
    if p.total_len < csum_off + 2 {
        return;
    }
    frame[csum_off] = 0;
    frame[csum_off + 1] = 0;

    let mut sum = pseudo_header_sum(frame, p.proto, l4_len as u16);
    sum += sum_words(&frame[p.l4..p.total_len]);
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

/// Hashes a client `addr:port` to pick a backend. A small FNV-1a-style mix is
/// enough to spread distinct client ports across the backend set while keeping
/// any single flow pinned to one backend.
fn flow_hash(addr: [u8; 4], port: u16) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in addr {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    for b in port.to_be_bytes() {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    h
}
