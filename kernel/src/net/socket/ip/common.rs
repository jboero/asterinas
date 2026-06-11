// SPDX-License-Identifier: MPL-2.0

use aster_bigtcp::{
    errors::BindError,
    iface::BindPortConfig,
    wire::{IpAddress, IpEndpoint},
};

use crate::{
    net::{iface::Iface, net_ns::NetNamespace, socket::util::check_port_privilege},
    prelude::*,
};

pub(super) fn resolve_bind_iface_and_config(
    endpoint: &IpEndpoint,
    can_reuse: bool,
) -> Result<(Arc<Iface>, BindPortConfig)> {
    check_port_privilege(endpoint.port)?;

    // Resolve the interface within the calling thread's network namespace, so a
    // socket binds to the loopback (and other interfaces) of its own namespace.
    let iface = match NetNamespace::current().iface_to_bind(&endpoint.addr) {
        Some(iface) => iface,
        None => {
            return_errno_with_message!(
                Errno::EADDRNOTAVAIL,
                "the address is not available from the local machine"
            );
        }
    };

    let bind_port_config = BindPortConfig::new(*endpoint, can_reuse);

    Ok((iface, bind_port_config))
}

/// Reserves `endpoint`'s port on every interface of the calling thread's
/// network namespace, for a wildcard (`0.0.0.0`) bind: a connection or
/// datagram may then arrive via any interface. Already-acquired ports are
/// released (dropped) if any interface fails.
pub(super) fn bind_port_on_all_ifaces_with<B>(
    endpoint: &IpEndpoint,
    can_reuse: bool,
    bind_one: impl Fn(&Arc<Iface>, BindPortConfig) -> core::result::Result<B, BindError>,
) -> Result<Vec<B>> {
    let ifaces = NetNamespace::current().all_ifaces();

    let mut bound = Vec::with_capacity(ifaces.len());
    for iface in ifaces.iter() {
        let config = BindPortConfig::new(*endpoint, can_reuse);
        bound.push(bind_one(iface, config).map_err(Error::from)?);
    }

    if bound.is_empty() {
        return_errno_with_message!(Errno::EADDRNOTAVAIL, "no interface to bind to");
    }

    Ok(bound)
}

impl From<BindError> for Error {
    fn from(value: BindError) -> Self {
        match value {
            BindError::Exhausted => {
                Error::with_message(Errno::EAGAIN, "no ephemeral port is available")
            }
            BindError::InUse => {
                Error::with_message(Errno::EADDRINUSE, "the address is already in use")
            }
        }
    }
}

pub(super) fn get_ephemeral_endpoint(remote_endpoint: &IpEndpoint) -> Option<IpEndpoint> {
    let iface = NetNamespace::current().ephemeral_iface(&remote_endpoint.addr);
    match remote_endpoint.addr {
        IpAddress::Ipv4(_) => {
            let ip_addr = iface.ipv4_addr()?;
            Some(IpEndpoint::new(IpAddress::Ipv4(ip_addr), 0))
        }
        IpAddress::Ipv6(_) => {
            let ipv6_addr = iface.ipv6_addr()?;
            Some(IpEndpoint::new(IpAddress::Ipv6(ipv6_addr), 0))
        }
    }
}
