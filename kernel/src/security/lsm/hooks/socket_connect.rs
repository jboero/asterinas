// SPDX-License-Identifier: MPL-2.0

//! Hooks for socket connect — the third astromac MAC domain (network).
//!
//! Mediates a labeled subject (a tenant) initiating a connection to a network
//! endpoint based on the destination IP's tenant label. This is the cross-tenant
//! isolation primitive for *shared networks* — pods sit on a shared bridge and
//! can reach each other's IPs, which namespaces alone do not prevent.
//!
//! The destination's tenant is resolved by the module from the destination IPv4
//! address, so this context carries only the subject's tenant and the dst IP.

use super::super::modules;
use crate::prelude::*;

/// Runs socket-connect hooks in module order.
pub fn on_socket_connect(context: &SocketConnectContext) -> Result<()> {
    for module in modules::active_modules() {
        module.on_socket_connect(context)?;
    }

    Ok(())
}

/// The inputs for a socket-connect check: the subject's tenant and the
/// destination IPv4 address (network byte order as a `u32`, i.e.
/// `u32::from_be_bytes(octets)`).
pub struct SocketConnectContext {
    subject_tenant: u32,
    dst_ipv4: u32,
}

impl SocketConnectContext {
    /// Creates a socket-connect context.
    pub const fn new(subject_tenant: u32, dst_ipv4: u32) -> Self {
        Self {
            subject_tenant,
            dst_ipv4,
        }
    }

    /// The astromac tenant label of the connecting thread (non-zero here; the
    /// caller skips the hook for unconfined tenant 0).
    pub const fn subject_tenant(&self) -> u32 {
        self.subject_tenant
    }

    /// The destination IPv4 address as `u32::from_be_bytes(octets)`.
    pub const fn dst_ipv4(&self) -> u32 {
        self.dst_ipv4
    }
}
