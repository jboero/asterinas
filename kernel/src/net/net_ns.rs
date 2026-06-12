// SPDX-License-Identifier: MPL-2.0

//! The network namespace abstraction.
//!
//! A network namespace isolates the set of network interfaces, routing tables,
//! port number space and sockets that a group of processes sees. Kubernetes
//! relies on it to give every pod its own network stack.
//!
//! Each namespace owns its own set of interfaces. The **initial** namespace owns
//! the boot-time interfaces (loopback plus any virtio NICs) managed by the global
//! registry in [`super::iface`]; the interface-resolution methods on it delegate
//! to that registry so the initial namespace behaves exactly as before. A
//! **created** namespace gets its own fresh loopback interface, isolated from the
//! initial namespace — so, for example, two namespaces can each bind
//! `127.0.0.1:<port>` independently.
//!
//! Socket operations resolve interfaces through the **current** namespace
//! ([`NetNamespace::current`]). Physical NICs are not yet movable between
//! namespaces, so a created namespace has only loopback (matching a Linux netns
//! before any veth is added); per-namespace routing tables, broadcast handling
//! and netlink enumeration of created namespaces are follow-up refinements.

use aster_bigtcp::wire::{IpAddress, Ipv4Address, Ipv4Cidr};
use spin::Once;

use super::iface::{self, Iface};
use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::{AsPosixThread, PosixThread},
    },
};

/// The network namespace.
pub struct NetNamespace {
    /// Whether this is the initial namespace. The initial namespace uses the
    /// global interface registry in [`super::iface`]; created namespaces use
    /// [`Self::ifaces`].
    is_init: bool,
    /// The interfaces owned by a created namespace (index 0 is always loopback).
    /// Empty and unused for the initial namespace.
    ifaces: RwMutex<Vec<Arc<Iface>>>,
    owner: Arc<UserNamespace>,
    stashed_dentry: StashedDentry,
}

impl NetNamespace {
    /// Returns a reference to the singleton initial network namespace.
    pub fn get_init_singleton() -> &'static Arc<NetNamespace> {
        static INIT: Once<Arc<NetNamespace>> = Once::new();

        INIT.call_once(|| {
            let owner = UserNamespace::get_init_singleton().clone();
            Arc::new(Self {
                is_init: true,
                ifaces: RwMutex::new(Vec::new()),
                owner,
                stashed_dentry: StashedDentry::new(),
            })
        })
    }

    /// Returns the network namespace of the current thread.
    ///
    /// Falls back to the initial namespace outside of a thread context (for
    /// example in early boot or kernel threads).
    pub fn current() -> Arc<NetNamespace> {
        let Some(task) = ostd::task::Task::current() else {
            return Self::get_init_singleton().clone();
        };
        let Some(thread_local) = task.as_thread_local() else {
            return Self::get_init_singleton().clone();
        };
        thread_local.borrow_ns_proxy().unwrap().net_ns().clone()
    }

    /// Clones a new network namespace from `self`.
    ///
    /// Creating a network namespace requires `CAP_SYS_ADMIN` in the owning user
    /// namespace, matching Linux. The new namespace is given its own loopback
    /// interface, driven by a dedicated polling thread.
    pub fn new_clone(
        &self,
        owner: Arc<UserNamespace>,
        posix_thread: &PosixThread,
    ) -> Result<Arc<Self>> {
        owner.check_cap(CapSet::SYS_ADMIN, posix_thread)?;

        let loopback = iface::new_loopback();
        iface::spawn_poll_thread(loopback.clone());

        Ok(Arc::new(Self {
            is_init: false,
            ifaces: RwMutex::new(vec![loopback]),
            owner,
            stashed_dentry: StashedDentry::new(),
        }))
    }

    /// Runs `op` with this namespace's interface set. For the initial namespace
    /// this is the global boot interfaces plus any added at runtime (e.g. a veth
    /// host end); for a created namespace it is the namespace's own interfaces.
    fn with_ifaces<R>(&self, op: impl FnOnce(&[Arc<Iface>]) -> R) -> R {
        if self.is_init {
            let mut ifaces: Vec<Arc<Iface>> = iface::iter_all_ifaces().cloned().collect();
            ifaces.extend(self.ifaces.read().iter().cloned());
            op(&ifaces)
        } else {
            op(&self.ifaces.read())
        }
    }

    /// Adds an interface to this namespace. Used to place a veth end into a
    /// namespace after the pair is created.
    pub(in crate::net) fn add_iface(&self, iface: Arc<Iface>) {
        self.ifaces.write().push(iface);
    }

    /// Returns the interface in this namespace with the given index, if any.
    pub(in crate::net) fn find_iface_by_index(&self, index: u32) -> Option<Arc<Iface>> {
        self.with_ifaces(|ifaces| ifaces.iter().find(|i| i.index() == index).cloned())
    }

    /// Returns a snapshot of all interfaces visible in this namespace.
    ///
    /// Used by the netlink route `RTM_GETLINK`/`RTM_GETADDR` dump handlers so a
    /// process enumerates the interfaces in *its* network namespace (e.g. a pod
    /// sees its own veth end, not the host's interfaces).
    pub(in crate::net) fn all_ifaces(&self) -> Vec<Arc<Iface>> {
        self.with_ifaces(|ifaces| ifaces.to_vec())
    }

    /// Returns the interface in this namespace whose local address equals
    /// `ip_addr`, if any. Used to bind a socket to a specific local address.
    pub(in crate::net) fn iface_to_bind(&self, ip_addr: &IpAddress) -> Option<Arc<Iface>> {
        self.with_ifaces(|ifaces| match *ip_addr {
            IpAddress::Ipv4(addr) => ifaces
                .iter()
                .find(|iface| iface.ipv4_addr() == Some(addr))
                .cloned(),
            IpAddress::Ipv6(addr) => ifaces
                .iter()
                .find(|iface| iface.ipv6_addr() == Some(addr))
                .cloned(),
        })
    }

    /// Returns a suitable interface for reaching `remote` when the socket is not
    /// bound to a specific interface. Prefers an interface that owns the remote
    /// address (loopback) and otherwise falls back to this namespace's default.
    pub(in crate::net) fn ephemeral_iface(&self, remote: &IpAddress) -> Arc<Iface> {
        // If some interface owns the remote address (e.g. loopback owns
        // 127.0.0.1), send from that interface.
        if let Some(iface) = self.iface_to_bind(remote) {
            return iface;
        }
        // Route via an interface whose subnet contains the remote address. This
        // is how traffic to a peer namespace egresses the local veth end (its
        // address is on the veth's /N subnet, but no local interface *owns* it).
        if let IpAddress::Ipv4(remote_v4) = remote
            && let Some(iface) = self.with_ifaces(|ifaces| {
                ifaces
                    .iter()
                    .find(|i| subnet_contains(i, *remote_v4))
                    .cloned()
            })
        {
            return iface;
        }
        // Off-subnet IPv4: route via an interface that has a default gateway
        // (a default route was programmed, e.g. a pod's `default via <bridge>`).
        // Without this, off-subnet traffic — a Service VIP, the internet —
        // falls through to the namespace default, which for a created namespace
        // is loopback.
        if matches!(remote, IpAddress::Ipv4(_))
            && let Some(iface) = self
                .with_ifaces(|ifaces| ifaces.iter().find(|i| i.ipv4_gateway().is_some()).cloned())
        {
            return iface;
        }
        // For IPv6, prefer any interface that has an IPv6 address.
        if matches!(remote, IpAddress::Ipv6(_))
            && let Some(iface) =
                self.with_ifaces(|ifaces| ifaces.iter().find(|i| i.ipv6_addr().is_some()).cloned())
        {
            return iface;
        }
        self.default_iface()
    }

    /// Returns this namespace's default interface for external traffic. The
    /// initial namespace prefers virtio over loopback; a created namespace has
    /// only loopback.
    fn default_iface(&self) -> Arc<Iface> {
        if self.is_init {
            iface::virtio_iface()
                .cloned()
                .unwrap_or_else(|| iface::loopback_iface().clone())
        } else {
            self.ifaces.read()[0].clone()
        }
    }
}

/// Returns whether `addr` is within the IPv4 subnet of `iface`.
fn subnet_contains(iface: &Arc<Iface>, addr: Ipv4Address) -> bool {
    let (Some(local), Some(prefix)) = (iface.ipv4_addr(), iface.prefix_len()) else {
        return false;
    };
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(local) & mask) == (u32::from(addr) & mask)
}

/// Resolves the network namespace of the process identified by `pid`.
///
/// This backs `IFLA_NET_NS_PID`: a CNI plugin names a target process (the pod's
/// pause/init process) and the kernel places the new link in that process's
/// network namespace.
pub fn net_ns_of_pid(pid: u32) -> Result<Arc<NetNamespace>> {
    let process = crate::process::pid_table::pid_table_mut()
        .get_process(pid)
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "no such process for netns lookup"))?;
    let thread = process.main_thread();
    let posix_thread = thread
        .as_posix_thread()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "target is not a POSIX thread"))?;
    let proxy = posix_thread.ns_proxy().lock();
    let proxy = proxy
        .as_ref()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "target process has exited"))?;
    Ok(proxy.net_ns().clone())
}

/// Creates a veth pair and places each end into a network namespace, with no
/// addresses assigned (addresses are configured separately via `RTM_NEWADDR`).
///
/// The `name` end is placed in `current_ns` (the caller's namespace) and the
/// `peer_name` end in `peer_ns`. Both ends start administratively up. This is
/// the kernel side of `RTM_NEWLINK ... type veth peer name ...`. Returns the
/// interface indices of the two ends, `(name_index, peer_index)`.
pub fn create_veth_pair(
    name: String,
    current_ns: &Arc<NetNamespace>,
    peer_name: String,
    peer_ns: &Arc<NetNamespace>,
) -> Result<(u32, u32)> {
    // veth ends are created without an address; the prefix is irrelevant until
    // `RTM_NEWADDR` assigns the real address.
    let unspecified = Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0);

    let (iface_a, iface_b) = iface::new_veth_pair(name, unspecified, peer_name, unspecified);
    let a_index = iface_a.index();
    let b_index = iface_b.index();

    current_ns.add_iface(iface_a);
    peer_ns.add_iface(iface_b);

    Ok((a_index, b_index))
}

/// Assigns an IPv4 address to the interface with `index` in `ns`, replacing any
/// existing IPv4 address. This is the kernel side of `RTM_NEWADDR`.
pub fn set_iface_addr_v4(ns: &Arc<NetNamespace>, index: u32, cidr: Ipv4Cidr) -> Result<()> {
    let iface = ns
        .find_iface_by_index(index)
        .ok_or_else(|| Error::with_message(Errno::ENODEV, "no such interface in namespace"))?;
    iface.set_ipv4_cidr(cidr);
    Ok(())
}

/// Adds an IPv4 route `cidr via gateway` in `ns`. This is the kernel side of
/// `RTM_NEWROUTE` — what a CNI plugin issues to program a pod's default route
/// (`ip route add default via <host veth>`). The output interface is chosen by
/// `oif` index when given, otherwise by which interface's subnet contains the
/// gateway (the gateway must be directly reachable).
pub fn add_iface_route_v4(
    ns: &Arc<NetNamespace>,
    oif: Option<u32>,
    cidr: Ipv4Cidr,
    gateway: Ipv4Address,
) -> Result<()> {
    let iface = match oif {
        Some(index) => ns.find_iface_by_index(index),
        None => ns.with_ifaces(|ifaces| {
            ifaces
                .iter()
                .find(|iface| subnet_contains(iface, gateway))
                .cloned()
        }),
    }
    .ok_or_else(|| {
        Error::with_message(
            Errno::ENETUNREACH,
            "no interface can reach the route gateway",
        )
    })?;

    iface.add_ipv4_route(cidr, gateway);
    Ok(())
}

impl NsCommonOps for NetNamespace {
    const TYPE: NsType = NsType::Net;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        Some(&self.owner)
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        return_errno_with_message!(
            Errno::EINVAL,
            "a network namespace does not have a parent namespace"
        );
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
