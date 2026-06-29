// SPDX-License-Identifier: MPL-2.0

//! LSM hook points.

mod alien_access;
mod file_access;
mod signal_access;

pub use self::{
    alien_access::{AlienAccessContext, on_alien_access},
    file_access::{FileAccessContext, on_file_access},
    signal_access::{SignalAccessContext, on_signal_access},
};
use crate::prelude::*;

pub(super) trait LsmAlienAccessHook: Sync {
    /// Handles an alien access attempt.
    fn on_alien_access(&self, _context: &AlienAccessContext) -> Result<()> {
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
