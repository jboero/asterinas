// SPDX-License-Identifier: MPL-2.0

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{Uid, credentials::capabilities::CapSet, posix_thread::PosixThread},
};

/// Linux's `MAX_USER_NS_LEVEL` — the deepest user-namespace nesting allowed.
const MAX_USER_NS_LEVEL: u32 = 32;

/// The user namespace.
///
/// User namespaces form a tree rooted at the initial namespace (level 0). A new
/// namespace records its parent, its nesting level, and the uid that created it
/// (its owner). NOTE (astrokube Stage 0/1): capabilities are not yet scoped to
/// the namespace — `check_cap` still tests the thread's single global capability
/// set, so creating a user namespace grants no new privilege. ID mapping and
/// ns-aware capability checks are later stages (see astrokube/USER-NAMESPACES.md).
pub struct UserNamespace {
    stashed_dentry: StashedDentry,
    /// The parent namespace, or `None` for the initial (root) namespace.
    parent: Option<Arc<UserNamespace>>,
    /// Nesting depth; the initial namespace is level 0.
    level: u32,
    /// The uid that created this namespace (root for the initial namespace).
    owner_uid: Uid,
}

impl UserNamespace {
    /// Returns a reference to the singleton initial user namespace.
    pub fn get_init_singleton() -> &'static Arc<UserNamespace> {
        static INIT: Once<Arc<UserNamespace>> = Once::new();

        INIT.call_once(|| {
            Arc::new(Self {
                stashed_dentry: StashedDentry::new(),
                parent: None,
                level: 0,
                owner_uid: Uid::new_root(),
            })
        })
    }

    /// Creates a new child user namespace owned by `owner_uid`, nested under
    /// `parent`. Fails if the nesting limit would be exceeded.
    pub fn new_child(parent: &Arc<UserNamespace>, owner_uid: Uid) -> Result<Arc<UserNamespace>> {
        if parent.level >= MAX_USER_NS_LEVEL {
            return_errno_with_message!(Errno::EINVAL, "user namespace nesting too deep");
        }
        Ok(Arc::new(Self {
            stashed_dentry: StashedDentry::new(),
            parent: Some(parent.clone()),
            level: parent.level + 1,
            owner_uid,
        }))
    }

    /// The nesting depth of this namespace (0 for the initial namespace).
    pub fn level(&self) -> u32 {
        self.level
    }

    /// Checks whether `posix_thread` holds `required` over a resource owned by
    /// this user namespace (`self`).
    ///
    /// This is the user-namespace capability boundary — what makes "root in a
    /// container" powerless on the host. Two ways to hold the capability:
    ///
    /// 1. **Owner of the namespace subtree.** A process is effectively root
    ///    *within a user namespace it created and that namespace's descendants*
    ///    (but never the initial namespace): it may act on resources owned by
    ///    that subtree. This is what lets an unprivileged process create its own
    ///    namespaces (rootless containers).
    /// 2. **Holds the capability in its effective set**, with its own user
    ///    namespace an ancestor of (or equal to) the resource's.
    ///
    /// Crucially, rule 1 grants nothing through the *global* capability set, so
    /// the direct `effective_capset()` checks elsewhere (DAC_OVERRIDE, setuid,
    /// the astrokube prctls, ...) are unaffected: an unprivileged container root
    /// still fails them against host resources. That keeps the boundary safe
    /// without ns-scoping every capability check individually.
    ///
    /// For the initial namespace — the entire existing system — `actor_ns` is
    /// the init namespace, which is an ancestor of every resource, so this
    /// reduces to the previous behavior (`effective_capset().contains`).
    pub fn check_cap(self: &Arc<Self>, required: CapSet, posix_thread: &PosixThread) -> Result<()> {
        let actor_ns = posix_thread.process().user_ns().lock().clone();
        let init_ns = Self::get_init_singleton();

        // Rule 1: root within your own (non-initial) user-namespace subtree.
        if !Arc::ptr_eq(&actor_ns, init_ns) && actor_ns.is_same_or_ancestor_of(self) {
            return Ok(());
        }

        // Rule 2: hold the capability in the effective set, scoped by ns ancestry.
        if actor_ns.is_same_or_ancestor_of(self)
            && posix_thread.credentials().effective_capset().contains(required)
        {
            return Ok(());
        }

        return_errno_with_message!(
            Errno::EPERM,
            "the thread does not have the required capability"
        )
    }

    /// Returns the owner UID of the user namespace.
    pub fn owner_uid(&self) -> Result<Uid> {
        Ok(self.owner_uid)
    }

    /// Returns whether this namespace is the same as, or an ancestor of, the
    /// other namespace, by walking the other's parent chain.
    pub fn is_same_or_ancestor_of(self: &Arc<Self>, other: &Arc<Self>) -> bool {
        let mut current = other.clone();
        loop {
            if Arc::ptr_eq(self, &current) {
                return true;
            }
            let Some(parent) = current.parent.clone() else {
                return false;
            };
            current = parent;
        }
    }
}

impl NsCommonOps for UserNamespace {
    const TYPE: NsType = NsType::User;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        // For user namespaces, `NS_GET_USERNS` returns the parent user namespace
        // rather than an "owner". The initial user namespace has no parent.
        // Reference: <https://elixir.bootlin.com/linux/v6.19/source/kernel/user_namespace.c#L1406>
        None
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        // User namespaces do not support `NS_GET_PARENT`.
        // Reference: <https://elixir.bootlin.com/linux/v6.19/source/kernel/user_namespace.c#L1407>
        return_errno_with_message!(Errno::EPERM, "user namespaces do not support NS_GET_PARENT");
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
