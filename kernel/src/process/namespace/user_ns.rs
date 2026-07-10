// SPDX-License-Identifier: MPL-2.0

use alloc::format;
use core::{
    fmt::Write as _,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{Gid, Uid, credentials::capabilities::CapSet, posix_thread::PosixThread},
};

/// Linux's `MAX_USER_NS_LEVEL` — the deepest user-namespace nesting allowed.
const MAX_USER_NS_LEVEL: u32 = 32;

/// The maximum number of ranges in a single uid/gid map (Linux uses 340; a small
/// bound is plenty for astrokube and keeps parsing trivially safe).
const MAX_ID_MAP_ENTRIES: usize = 8;

/// One line of a uid_map/gid_map: ids `[inner, inner+count)` inside this
/// namespace map to `[outer, outer+count)` in the parent namespace.
#[derive(Clone, Copy, Debug)]
pub struct IdMapEntry {
    pub inner: u32,
    pub outer: u32,
    pub count: u32,
}

/// Which id map is being written (selects the capability and the writer's id).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdMapKind {
    Uid,
    Gid,
}

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
    /// The uid map, set once via `/proc/[pid]/uid_map`. `None` until written.
    uid_map: Mutex<Option<Vec<IdMapEntry>>>,
    /// The gid map, set once via `/proc/[pid]/gid_map`.
    gid_map: Mutex<Option<Vec<IdMapEntry>>>,
    /// Whether `setgroups(2)` is allowed; must be denied before an unprivileged
    /// gid_map is written (Linux rule). Default allowed.
    setgroups_allowed: AtomicBool,
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
                uid_map: Mutex::new(None),
                gid_map: Mutex::new(None),
                setgroups_allowed: AtomicBool::new(true),
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
            uid_map: Mutex::new(None),
            gid_map: Mutex::new(None),
            setgroups_allowed: AtomicBool::new(true),
        }))
    }

    /// The nesting depth of this namespace (0 for the initial namespace).
    pub fn level(&self) -> u32 {
        self.level
    }

    /// Whether this is the initial (root) user namespace.
    pub fn is_init(&self) -> bool {
        self.parent.is_none()
    }

    /// The parent user namespace, or `None` for the initial namespace.
    pub fn parent_ns(&self) -> Option<&Arc<UserNamespace>> {
        self.parent.as_ref()
    }

    /// Whether `setgroups(2)` is currently allowed in this namespace.
    pub fn setgroups_allowed(&self) -> bool {
        self.setgroups_allowed.load(Ordering::Relaxed)
    }

    /// Sets the `setgroups` policy. Only permitted before a gid_map is written.
    pub fn set_setgroups_allowed(&self, allowed: bool) -> Result<()> {
        if self.gid_map.lock().is_some() {
            return_errno_with_message!(Errno::EPERM, "gid_map already set");
        }
        self.setgroups_allowed.store(allowed, Ordering::Relaxed);
        Ok(())
    }

    /// Translates an init-namespace (global) uid into this namespace's local uid,
    /// returning the overflow uid if it is not mapped. The initial namespace is
    /// the identity, so this is a no-op for the entire existing system.
    pub fn uid_to_ns(&self, kuid: Uid) -> Uid {
        if self.is_init() {
            return kuid;
        }
        let parent_local = self.parent.as_ref().unwrap().uid_to_ns(kuid);
        let p = u32::from(parent_local);
        if let Some(entries) = self.uid_map.lock().as_ref() {
            for e in entries {
                if p >= e.outer && (p - e.outer) < e.count {
                    return Uid::new(e.inner + (p - e.outer));
                }
            }
        }
        Uid::OVERFLOW
    }

    /// Translates an init-namespace (global) gid into this namespace's local gid.
    pub fn gid_to_ns(&self, kgid: Gid) -> Gid {
        if self.is_init() {
            return kgid;
        }
        let parent_local = self.parent.as_ref().unwrap().gid_to_ns(kgid);
        let p = u32::from(parent_local);
        if let Some(entries) = self.gid_map.lock().as_ref() {
            for e in entries {
                if p >= e.outer && (p - e.outer) < e.count {
                    return Gid::new(e.inner + (p - e.outer));
                }
            }
        }
        Gid::OVERFLOW
    }

    /// Formats a stored id map for `/proc/[pid]/{uid,gid}_map`. The initial
    /// namespace reports the identity map.
    fn format_map(&self, kind: IdMapKind) -> String {
        if self.is_init() {
            let invalid = match kind {
                IdMapKind::Uid => u32::from(Uid::INVALID),
                IdMapKind::Gid => u32::from(Gid::INVALID),
            };
            return format!("{:>10} {:>10} {:>10}\n", 0, 0, invalid);
        }
        let guard = match kind {
            IdMapKind::Uid => self.uid_map.lock(),
            IdMapKind::Gid => self.gid_map.lock(),
        };
        let mut out = String::new();
        if let Some(entries) = guard.as_ref() {
            for e in entries {
                let _ = writeln!(out, "{:>10} {:>10} {:>10}", e.inner, e.outer, e.count);
            }
        }
        out
    }

    /// Formats the uid map for procfs read.
    pub fn format_uid_map(&self) -> String {
        self.format_map(IdMapKind::Uid)
    }

    /// Formats the gid map for procfs read.
    pub fn format_gid_map(&self) -> String {
        self.format_map(IdMapKind::Gid)
    }

    /// Parses, authorizes and installs a uid/gid map written to
    /// `/proc/[pid]/{uid,gid}_map` of a process in `target`. `writer` is the
    /// thread performing the write.
    ///
    /// Authorization mirrors Linux: the writer either holds the relevant
    /// capability (CAP_SETUID / CAP_SETGID) in the parent namespace, or — the
    /// unprivileged rootless case — writes a single line mapping exactly its own
    /// id; an unprivileged gid_map additionally requires `setgroups` to be denied.
    pub fn write_id_map(
        target: &Arc<UserNamespace>,
        kind: IdMapKind,
        text: &str,
        writer: &PosixThread,
    ) -> Result<()> {
        let Some(parent) = target.parent.as_ref() else {
            return_errno_with_message!(Errno::EPERM, "cannot map the initial user namespace");
        };

        let entries = parse_id_map(text)?;
        validate_id_map(&entries)?;

        let cap = match kind {
            IdMapKind::Uid => CapSet::SETUID,
            IdMapKind::Gid => CapSet::SETGID,
        };
        let privileged = parent.check_cap(cap, writer).is_ok();
        if !privileged {
            // Unprivileged: a single line mapping exactly the writer's own id.
            if entries.len() != 1 || entries[0].count != 1 {
                return_errno_with_message!(
                    Errno::EPERM,
                    "unprivileged id map must be a single one-to-one mapping"
                );
            }
            let writer_id = match kind {
                IdMapKind::Uid => u32::from(writer.credentials().euid()),
                IdMapKind::Gid => u32::from(writer.credentials().egid()),
            };
            if entries[0].outer != writer_id {
                return_errno_with_message!(
                    Errno::EPERM,
                    "unprivileged id map must map the writer's own id"
                );
            }
            if kind == IdMapKind::Gid && target.setgroups_allowed() {
                return_errno_with_message!(
                    Errno::EPERM,
                    "setgroups must be denied before an unprivileged gid_map"
                );
            }
        }

        let mut slot = match kind {
            IdMapKind::Uid => target.uid_map.lock(),
            IdMapKind::Gid => target.gid_map.lock(),
        };
        if slot.is_some() {
            return_errno_with_message!(Errno::EPERM, "id map is already set");
        }
        *slot = Some(entries);
        Ok(())
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

/// Parses uid_map/gid_map text: whitespace-separated `inner outer count` triples,
/// one per line.
fn parse_id_map(text: &str) -> Result<Vec<IdMapEntry>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let inner = it.next().and_then(|s| s.parse::<u32>().ok());
        let outer = it.next().and_then(|s| s.parse::<u32>().ok());
        let count = it.next().and_then(|s| s.parse::<u32>().ok());
        let (Some(inner), Some(outer), Some(count)) = (inner, outer, count) else {
            return_errno_with_message!(Errno::EINVAL, "malformed id map line");
        };
        if it.next().is_some() {
            return_errno_with_message!(Errno::EINVAL, "trailing data in id map line");
        }
        if entries.len() >= MAX_ID_MAP_ENTRIES {
            return_errno_with_message!(Errno::EINVAL, "too many id map entries");
        }
        entries.push(IdMapEntry {
            inner,
            outer,
            count,
        });
    }
    if entries.is_empty() {
        return_errno_with_message!(Errno::EINVAL, "empty id map");
    }
    Ok(entries)
}

/// Validates id-map ranges: positive counts, no integer overflow, and no
/// overlapping inner or outer ranges.
fn validate_id_map(entries: &[IdMapEntry]) -> Result<()> {
    for (i, e) in entries.iter().enumerate() {
        if e.count == 0 {
            return_errno_with_message!(Errno::EINVAL, "id map range count must be positive");
        }
        if e.inner.checked_add(e.count).is_none() || e.outer.checked_add(e.count).is_none() {
            return_errno_with_message!(Errno::EINVAL, "id map range overflows");
        }
        for other in &entries[..i] {
            if ranges_overlap(e.inner, e.count, other.inner, other.count)
                || ranges_overlap(e.outer, e.count, other.outer, other.count)
            {
                return_errno_with_message!(Errno::EINVAL, "overlapping id map ranges");
            }
        }
    }
    Ok(())
}

fn ranges_overlap(a_start: u32, a_count: u32, b_start: u32, b_count: u32) -> bool {
    let a_start = a_start as u64;
    let b_start = b_start as u64;
    let a_end = a_start + a_count as u64;
    let b_end = b_start + b_count as u64;
    a_start < b_end && b_start < a_end
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
