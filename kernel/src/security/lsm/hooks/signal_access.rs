// SPDX-License-Identifier: MPL-2.0

//! Hooks for signal-delivery access checks.
//!
//! This is the first Mandatory Access Control (MAC) hook point in astrokube: it
//! lets an LSM module gate one process signaling another based on a security
//! label (the astermac tenant), independently of the discretionary uid/CAP_KILL
//! checks. It is the cross-tenant isolation primitive for the multi-tenant
//! security posture.

use super::super::modules;
use crate::prelude::*;

/// Runs signal-access hooks in module order.
pub fn on_signal_access(context: &SignalAccessContext) -> Result<()> {
    for module in modules::active_modules() {
        module.on_signal_access(context)?;
    }

    Ok(())
}

/// The inputs for a signal-access check through the LSM stack: the security
/// labels of the sending and target threads.
pub struct SignalAccessContext {
    sender_tenant: u32,
    target_tenant: u32,
}

impl SignalAccessContext {
    /// Creates a signal-access context from the sender and target tenant labels.
    pub const fn new(sender_tenant: u32, target_tenant: u32) -> Self {
        Self {
            sender_tenant,
            target_tenant,
        }
    }

    /// The astermac tenant label of the signal sender (0 = unconfined).
    pub const fn sender_tenant(&self) -> u32 {
        self.sender_tenant
    }

    /// The astermac tenant label of the signal target (0 = unconfined).
    pub const fn target_tenant(&self) -> u32 {
        self.target_tenant
    }
}
