// SPDX-License-Identifier: MPL-2.0

//! LSM hook points.

mod alien_access;
mod capability;
mod file_access;
mod signal_access;
mod socket_connect;

pub use self::{
    alien_access::{AlienAccessContext, on_alien_access},
    capability::{CapableContext, on_capable},
    file_access::{FileAccessContext, on_file_access},
    signal_access::{SignalAccessContext, on_signal_access},
    socket_connect::{SocketConnectContext, on_socket_connect},
};
use crate::prelude::*;

pub(super) trait LsmAlienAccessHook: Sync {
    /// Handles an alien access attempt.
    fn on_alien_access(&self, _context: &AlienAccessContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmCapabilityHook: Sync {
    /// Checks whether a thread holds a capability in a user namespace.
    fn on_capable(&self, _context: &CapableContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmSignalAccessHook: Sync {
    /// Handles a signal-delivery access attempt.
    fn on_signal_access(&self, _context: &SignalAccessContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmFileAccessHook: Sync {
    /// Handles a file-access attempt.
    fn on_file_access(&self, _context: &FileAccessContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmSocketConnectHook: Sync {
    /// Handles a socket-connect attempt.
    fn on_socket_connect(&self, _context: &SocketConnectContext) -> Result<()> {
        Ok(())
    }
}
