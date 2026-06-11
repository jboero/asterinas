// SPDX-License-Identifier: MPL-2.0

//! The PID namespace abstraction.
//!
//! A PID namespace isolates the process-ID number space: the first process in a
//! new PID namespace becomes its `init` (PID 1), and processes inside see PIDs
//! numbered independently from the parent namespace. Kubernetes relies on this
//! to give each pod its own PID 1 and process view.
//!
//! PID namespaces are hierarchical: every one except the initial namespace has a
//! parent, and a process has a distinct PID number in its own namespace and in
//! each ancestor. Asterinas keeps the process's number in the **initial**
//! namespace as the canonical global PID (the key of the global PID table); this
//! module adds the namespace-local numbering on top.
//!
//! Current scope: a process records its own PID namespace and its number there
//! (see `Process::vpid`). `getpid`/`getppid`/`gettid` return namespace-local
//! numbers. The common one-level case used by container runtimes (host namespace
//! plus one pod namespace) is fully handled. Translating numbers across more than
//! one nesting level for `wait`/`kill`/`/proc`, and per-namespace process
//! enumeration, are follow-up refinements.

use core::sync::atomic::{AtomicU32, Ordering};

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{Pid, UserNamespace, credentials::capabilities::CapSet, posix_thread::PosixThread},
};

/// The PID of the first process (the `init`) in any PID namespace.
pub(in crate::process) const INIT_PID: Pid = 1;

/// A PID namespace.
pub struct PidNamespace {
    /// The parent PID namespace, or `None` for the initial namespace.
    parent: Option<Arc<PidNamespace>>,
    /// The nesting level; the initial namespace is level 0.
    level: u32,
    /// The namespace-local PID allocator. Allocation starts at [`INIT_PID`] so
    /// that the first process created in the namespace becomes its `init`.
    next_pid: AtomicU32,
    /// The owner user namespace.
    owner: Arc<UserNamespace>,
    /// Stashed dentry for nsfs.
    stashed_dentry: StashedDentry,
}

impl PidNamespace {
    /// Returns a reference to the singleton initial PID namespace.
    pub fn get_init_singleton() -> &'static Arc<PidNamespace> {
        static INIT: Once<Arc<PidNamespace>> = Once::new();

        INIT.call_once(|| {
            let owner = UserNamespace::get_init_singleton().clone();
            Arc::new(Self {
                parent: None,
                level: 0,
                // Numbers in the initial namespace are the global PIDs, allocated
                // by the global TID allocator, so this counter is unused here.
                next_pid: AtomicU32::new(INIT_PID),
                owner,
                stashed_dentry: StashedDentry::new(),
            })
        })
    }

    /// Creates a child PID namespace nested under `self`.
    ///
    /// Requires `CAP_SYS_ADMIN` in the owning user namespace, matching Linux.
    pub(in crate::process) fn new_child(
        self: &Arc<Self>,
        owner: Arc<UserNamespace>,
        posix_thread: &PosixThread,
    ) -> Result<Arc<Self>> {
        owner.check_cap(CapSet::SYS_ADMIN, posix_thread)?;
        Ok(Arc::new(Self {
            parent: Some(self.clone()),
            level: self.level + 1,
            next_pid: AtomicU32::new(INIT_PID),
            owner,
            stashed_dentry: StashedDentry::new(),
        }))
    }

    /// Returns whether this is the initial (top-level) PID namespace.
    pub(in crate::process) fn is_init(&self) -> bool {
        self.parent.is_none()
    }

    /// Allocates the next namespace-local PID.
    ///
    /// The first call in a fresh namespace returns [`INIT_PID`], so that the
    /// first process becomes the namespace's `init`.
    pub(in crate::process) fn alloc_local_pid(&self) -> Pid {
        self.next_pid.fetch_add(1, Ordering::Relaxed)
    }
}

impl NsCommonOps for PidNamespace {
    const TYPE: NsType = NsType::Pid;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        Some(&self.owner)
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        self.parent.as_ref().ok_or_else(|| {
            Error::with_message(
                Errno::EINVAL,
                "the initial PID namespace has no parent namespace",
            )
        })
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
