// SPDX-License-Identifier: MPL-2.0

//! astromac — a native, label-based Mandatory Access Control (MAC) module.
//!
//! This is the astrokube experiment in framekernel-native MAC: rather than
//! porting SELinux's context/policy/AVC machinery, every process carries a small
//! unforgeable **tenant** label (see `PosixThread::mac_tenant`), and the kernel
//! mediates cross-tenant operations directly in Rust.
//!
//! Default-compatible by construction:
//! * Tenant `0` is *unconfined* — it is never restricted and may interact with
//!   anything. Unlabeled processes (all of an unmodified Kubernetes node — the
//!   kubelet, containerd, ordinary pods) stay tenant 0, so the policy is a no-op
//!   for them.
//! * Only when a pod launcher explicitly assigns a non-zero tenant does the MAC
//!   apply, and even then the module defaults to **permissive** (log, don't
//!   deny). Enforcing mode is opt-in.
//!
//! v1 mediates one operation: a process of one tenant signaling a process of a
//! different tenant (the cross-tenant isolation primitive). The framework is
//! built to grow more hooks (file, socket) over time.

use core::sync::atomic::{AtomicU32, Ordering};

use super::super::{
    LsmFlags, LsmModule,
    hooks::{LsmAlienAccessHook, LsmSignalAccessHook, SignalAccessContext},
};
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
};

pub static ASTROMAC_LSM: AstroMacLsm = AstroMacLsm;

/// The astromac MAC module.
pub struct AstroMacLsm;

/// astromac enforcement mode.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub enum MacMode {
    /// MAC is off; no cross-tenant checks at all.
    Disabled = 0,
    /// Cross-tenant violations are logged but allowed. The default — safe for
    /// existing Kubernetes workloads.
    Permissive = 1,
    /// Cross-tenant violations are denied with `EPERM`.
    Enforcing = 2,
}

static ASTROMAC_MODE: AtomicU32 = AtomicU32::new(MacMode::Permissive as u32);

/// Returns the current astromac mode.
pub fn mode() -> MacMode {
    MacMode::try_from(ASTROMAC_MODE.load(Ordering::Relaxed)).unwrap_or(MacMode::Permissive)
}

/// Sets the astromac mode. Requires `CAP_SYS_ADMIN` in the init user namespace.
pub fn set_mode(new_mode: MacMode) -> Result<()> {
    UserNamespace::get_init_singleton()
        .check_cap(CapSet::SYS_ADMIN, current_thread!().as_posix_thread().unwrap())?;
    ASTROMAC_MODE.store(new_mode as u32, Ordering::Relaxed);
    info!("[astromac] mode set to {:?}", new_mode);
    Ok(())
}

impl LsmSignalAccessHook for AstroMacLsm {
    fn on_signal_access(&self, context: &SignalAccessContext) -> Result<()> {
        let mode = mode();
        if mode == MacMode::Disabled {
            return Ok(());
        }

        let sender = context.sender_tenant();
        let target = context.target_tenant();

        // Tenant 0 is unconfined; only two *different* non-zero tenants conflict.
        let cross_tenant = sender != 0 && target != 0 && sender != target;
        if !cross_tenant {
            return Ok(());
        }

        match mode {
            MacMode::Enforcing => {
                return_errno_with_message!(
                    Errno::EPERM,
                    "astromac: cross-tenant signal denied"
                );
            }
            MacMode::Permissive => {
                warn!(
                    "[astromac] PERMISSIVE: would deny cross-tenant signal (sender tenant {}, target tenant {})",
                    sender, target
                );
                Ok(())
            }
            MacMode::Disabled => Ok(()),
        }
    }
}

// astromac does not gate alien access (ptrace); that stays with Yama.
impl LsmAlienAccessHook for AstroMacLsm {}

impl LsmModule for AstroMacLsm {
    fn name(&self) -> &'static str {
        "astromac"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::empty()
    }
}
