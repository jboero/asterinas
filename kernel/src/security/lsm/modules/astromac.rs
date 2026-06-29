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

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use ostd::sync::SpinLock;

use super::super::{
    LsmFlags, LsmModule,
    hooks::{
        FileAccessContext, LsmAlienAccessHook, LsmFileAccessHook, LsmSignalAccessHook,
        LsmSocketConnectHook, SignalAccessContext, SocketConnectContext,
    },
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

// --- Object (file) tenant labels ---
//
// Files are labeled by their `(dev, ino)` identity in an in-kernel table. This
// keeps file labeling independent of any particular filesystem's xattr support
// and avoids touching every inode. The fast-path check is a single atomic load
// of the label count, so an unlabeled system (every unmodified node) pays almost
// nothing on the file-access hot path.

static FILE_LABELS: SpinLock<BTreeMap<(u64, u64), u32>> = SpinLock::new(BTreeMap::new());
static FILE_LABEL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Whether any file carries a tenant label. The file-access hot path checks this
/// first and skips all work when it is false (the default).
pub fn has_file_labels() -> bool {
    FILE_LABEL_COUNT.load(Ordering::Relaxed) != 0
}

/// Labels (or, with `tenant == 0`, unlabels) a file identified by `(dev, ino)`.
pub fn label_file(dev: u64, ino: u64, tenant: u32) {
    let mut labels = FILE_LABELS.lock();
    if tenant == 0 {
        if labels.remove(&(dev, ino)).is_some() {
            FILE_LABEL_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
    } else if labels.insert((dev, ino), tenant).is_none() {
        FILE_LABEL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Returns the tenant label of a file, or 0 if it is unlabeled.
fn file_tenant(dev: u64, ino: u64) -> u32 {
    FILE_LABELS.lock().get(&(dev, ino)).copied().unwrap_or(0)
}

impl LsmFileAccessHook for AstroMacLsm {
    fn on_file_access(&self, context: &FileAccessContext) -> Result<()> {
        let mode = mode();
        if mode == MacMode::Disabled {
            return Ok(());
        }

        let subject = context.subject_tenant();
        let object = file_tenant(context.dev(), context.ino());

        // Tenant 0 is unconfined; only two different non-zero tenants conflict.
        let cross_tenant = subject != 0 && object != 0 && subject != object;
        if !cross_tenant {
            return Ok(());
        }

        match mode {
            MacMode::Enforcing => {
                return_errno_with_message!(Errno::EPERM, "astromac: cross-tenant file access denied");
            }
            MacMode::Permissive => {
                warn!(
                    "[astromac] PERMISSIVE: would deny cross-tenant file access (subject tenant {}, file tenant {}, ino {})",
                    subject,
                    object,
                    context.ino()
                );
                Ok(())
            }
            MacMode::Disabled => Ok(()),
        }
    }
}

// --- Endpoint (IPv4) tenant labels ---
//
// Network endpoints are labeled by their IPv4 address (network byte order as a
// `u32`). A labeled subject connecting to a differently-labeled address is a
// cross-tenant network access. Same fast-path discipline as file labels.

static IP_LABELS: SpinLock<BTreeMap<u32, u32>> = SpinLock::new(BTreeMap::new());
static IP_LABEL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Whether any IPv4 endpoint carries a tenant label (socket-connect fast path).
pub fn has_ip_labels() -> bool {
    IP_LABEL_COUNT.load(Ordering::Relaxed) != 0
}

/// Labels (or, with `tenant == 0`, unlabels) an IPv4 endpoint. `ipv4` is
/// `u32::from_be_bytes(octets)`.
pub fn label_ip(ipv4: u32, tenant: u32) {
    let mut labels = IP_LABELS.lock();
    if tenant == 0 {
        if labels.remove(&ipv4).is_some() {
            IP_LABEL_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
    } else if labels.insert(ipv4, tenant).is_none() {
        IP_LABEL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

fn ip_tenant(ipv4: u32) -> u32 {
    IP_LABELS.lock().get(&ipv4).copied().unwrap_or(0)
}

impl LsmSocketConnectHook for AstroMacLsm {
    fn on_socket_connect(&self, context: &SocketConnectContext) -> Result<()> {
        let mode = mode();
        if mode == MacMode::Disabled {
            return Ok(());
        }

        let subject = context.subject_tenant();
        let object = ip_tenant(context.dst_ipv4());

        let cross_tenant = subject != 0 && object != 0 && subject != object;
        if !cross_tenant {
            return Ok(());
        }

        match mode {
            MacMode::Enforcing => {
                return_errno_with_message!(
                    Errno::EPERM,
                    "astromac: cross-tenant network connect denied"
                );
            }
            MacMode::Permissive => {
                warn!(
                    "[astromac] PERMISSIVE: would deny cross-tenant connect (subject tenant {}, dst tenant {})",
                    subject, object
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
