// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    fs::file::file_table::{RawFileDesc, get_file_fast},
    prelude::*,
    process::{
        credentials::{SecureBits, capabilities::CapSet},
        posix_thread::{ContextPthreadAdminApi, MAX_THREAD_NAME_LEN},
        signal::sig_num::SigNum,
    },
};

pub fn sys_prctl(
    option: i32,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let prctl_cmd = PrctlCmd::from_args(option, arg2, arg3, arg4, arg5)?;
    debug!("prctl_cmd = {:x?}", prctl_cmd);

    match prctl_cmd {
        PrctlCmd::PR_SET_PDEATHSIG(signum) => {
            ctx.process.set_parent_death_signal(signum);
        }
        PrctlCmd::PR_GET_PDEATHSIG(write_to_addr) => {
            let write_val = match ctx.process.parent_death_signal() {
                None => 0i32,
                Some(signum) => signum.as_u8() as i32,
            };
            ctx.user_space().write_val(write_to_addr, &write_val)?;
        }
        PrctlCmd::PR_GET_DUMPABLE => {
            // TODO: When coredump is supported, return the actual value.
            return Ok(SyscallReturn::Return(Dumpable::Disable as _));
        }
        PrctlCmd::PR_SET_DUMPABLE(dumpable) => {
            if dumpable != Dumpable::Disable && dumpable != Dumpable::User {
                return_errno_with_message!(Errno::EINVAL, "invalid dumpable attribute");
            }
            // TODO: Implement coredump.
        }
        PrctlCmd::PR_GET_KEEPCAPS => {
            let keep_cap = {
                let credentials = ctx.posix_thread.credentials();
                if credentials.keep_capabilities() {
                    1
                } else {
                    0
                }
            };
            return Ok(SyscallReturn::Return(keep_cap as _));
        }
        PrctlCmd::PR_SET_KEEPCAPS(keep_cap) => {
            if keep_cap > 1 {
                return_errno_with_message!(Errno::EINVAL, "invalid keep-capabilities flag");
            }
            let credentials = ctx.credentials_mut();
            credentials.set_keep_capabilities(keep_cap != 0)?;
        }
        PrctlCmd::PR_SET_NAME(read_addr) => {
            let new_thread_name = ctx
                .user_space()
                .read_cstring(read_addr, MAX_THREAD_NAME_LEN)?;
            let mut thread_name = ctx.posix_thread.thread_name().lock();
            thread_name.set_name(&new_thread_name);
        }
        PrctlCmd::PR_GET_NAME(write_to_addr) => {
            let thread_name = ctx.posix_thread.thread_name().lock();
            ctx.user_space()
                .write_bytes(write_to_addr, thread_name.name().to_bytes_with_nul())?;
        }
        PrctlCmd::PR_CAPBSET_READ(capability) => {
            let credentials = ctx.posix_thread.credentials();
            let is_in_bounding_set = credentials.bounding_capset().contains(capability);
            return Ok(SyscallReturn::Return(is_in_bounding_set as _));
        }
        PrctlCmd::PR_CAPBSET_DROP(capability) => {
            let credentials = ctx.credentials_mut();
            credentials.drop_bounding_capability(capability)?;
        }
        PrctlCmd::PR_GET_SECUREBITS => {
            let credentials = ctx.posix_thread.credentials();
            let securebits = credentials.securebits();
            return Ok(SyscallReturn::Return(securebits.bits() as _));
        }
        PrctlCmd::PR_SET_SECUREBITS(securebits) => {
            let credentials = ctx.credentials_mut();
            credentials.set_securebits(securebits)?;
        }
        PrctlCmd::PR_SET_TIMERSLACK(slack_ns) => {
            // Negative values are invalid.
            if (slack_ns as i64) < 0 {
                return_errno_with_message!(Errno::EINVAL, "invalid timer slack");
            }
            // In Linux, a value of 0 means "use default slack".
            if slack_ns == 0 {
                ctx.posix_thread.reset_timer_slack_to_default();
            } else {
                ctx.posix_thread.set_timer_slack_ns(slack_ns);
            }
        }
        PrctlCmd::PR_GET_TIMERSLACK => {
            let slack_ns = ctx.posix_thread.timer_slack_ns();
            return Ok(SyscallReturn::Return(slack_ns as _));
        }
        PrctlCmd::PR_SET_CHILD_SUBREAPER(is_set) => {
            let process = ctx.process.as_ref();
            if is_set {
                process.set_child_subreaper();
            } else {
                process.unset_child_subreaper();
            }
        }
        PrctlCmd::PR_GET_CHILD_SUBREAPER(write_addr) => {
            let process = ctx.process.as_ref();
            ctx.user_space()
                .write_val(write_addr, &(process.is_child_subreaper() as u32))?;
        }
        PrctlCmd::PR_SET_NO_NEW_PRIVS => {
            ctx.posix_thread.set_no_new_privs();
        }
        PrctlCmd::PR_GET_NO_NEW_PRIVS => {
            return Ok(SyscallReturn::Return(ctx.posix_thread.no_new_privs() as _));
        }
        PrctlCmd::PR_GET_SECCOMP => {
            // Report the calling thread's actual seccomp mode (0 = disabled,
            // 1 = strict, 2 = filter). Returning a value (rather than EINVAL) is
            // also what makes a container runtime's "is seccomp supported?"
            // probe conclude seccomp is available — which the kubelet requires,
            // since it pins the pod sandbox (pause) to the RuntimeDefault
            // profile and containerd rejects a node that reports no seccomp.
            return Ok(SyscallReturn::Return(ctx.posix_thread.seccomp().mode() as _));
        }
        PrctlCmd::PR_SET_SECCOMP { mode, filter_ptr } => {
            // Legacy filter-install path. Modern runtimes use the seccomp(2)
            // syscall, but honor prctl too so older tooling enforces as well.
            const SECCOMP_MODE_STRICT: u64 = 1;
            const SECCOMP_MODE_FILTER: u64 = 2;
            match mode {
                SECCOMP_MODE_STRICT => super::seccomp::do_set_mode_strict(ctx),
                SECCOMP_MODE_FILTER => super::seccomp::do_set_mode_filter(filter_ptr, ctx)?,
                _ => return_errno_with_message!(Errno::EINVAL, "unsupported seccomp mode"),
            }
        }
        PrctlCmd::PR_ASTROKUBE_DNAT {
            vip,
            backend,
            ports,
            proto,
        } => {
            // Temporary scaffolding to drive the Service DNAT datapath until the
            // nftables-compatible netlink surface exists. Requires CAP_NET_ADMIN.
            if !ctx
                .posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::NET_ADMIN)
            {
                return_errno_with_message!(
                    Errno::EPERM,
                    "installing a DNAT rule requires CAP_NET_ADMIN"
                );
            }
            // Each call adds one backend endpoint; repeated calls for the same
            // VIP build up its backend set (load-balanced Service endpoints).
            aster_bigtcp::nat::nat_table().add_dnat(
                vip.to_be_bytes(),
                (ports >> 16) as u16,
                proto as u8,
                backend.to_be_bytes(),
                (ports & 0xffff) as u16,
            );
        }
        PrctlCmd::PR_ASTROKUBE_MASQ { bridge_index } => {
            // Temporary scaffolding to mark a bridge as a masquerade uplink.
            // Requires CAP_NET_ADMIN.
            if !ctx
                .posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::NET_ADMIN)
            {
                return_errno_with_message!(
                    Errno::EPERM,
                    "marking a masquerade uplink requires CAP_NET_ADMIN"
                );
            }
            crate::net::iface::mark_bridge_uplink(bridge_index);
        }
        PrctlCmd::PR_ASTROKUBE_SETTENANT(tenant) => {
            // Assign the calling thread's astromac tenant label (multi-tenant
            // MAC). Requires CAP_SYS_ADMIN — only a pod launcher labels pods.
            if !ctx
                .posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::SYS_ADMIN)
            {
                return_errno_with_message!(
                    Errno::EPERM,
                    "setting an astromac tenant label requires CAP_SYS_ADMIN"
                );
            }
            ctx.posix_thread.set_mac_tenant(tenant);
        }
        PrctlCmd::PR_ASTROKUBE_MAC_MODE(mode) => {
            // Set the global astromac enforcement mode. set_mode performs its own
            // CAP_SYS_ADMIN check against the init user namespace.
            let mode = crate::security::lsm::astromac::MacMode::try_from(mode)
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid astromac mode"))?;
            crate::security::lsm::astromac::set_mode(mode)?;
        }
        PrctlCmd::PR_ASTROKUBE_LABEL_FD { fd, tenant } => {
            // Assign (or clear, with tenant 0) the astromac tenant label of the
            // file referred to by `fd`. Requires CAP_SYS_ADMIN.
            if !ctx
                .posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::SYS_ADMIN)
            {
                return_errno_with_message!(
                    Errno::EPERM,
                    "labeling a file requires CAP_SYS_ADMIN"
                );
            }
            let metadata = {
                let mut file_table = ctx.thread_local.borrow_file_table_mut();
                let file = get_file_fast!(&mut file_table, (fd as RawFileDesc).try_into()?);
                file.path().metadata()
            };
            crate::security::lsm::astromac::label_file(
                metadata.container_dev_id.as_encoded_u64(),
                metadata.ino,
                tenant,
            );
        }
        PrctlCmd::PR_ASTROKUBE_ACPI => {
            // Arm the ACPI power-button monitor so an orderly host poweroff
            // (QEMU `system_powerdown` / virsh shutdown) is delivered to PID 1
            // as SIGINT for graceful node drain. Spawning the monitor thread
            // from this fully-scheduled syscall context avoids the early-boot
            // deadlock of spawning a self-blocking thread before the idle loop.
            // Requires CAP_SYS_BOOT (the init holds it).
            if !ctx
                .posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::SYS_BOOT)
            {
                return_errno_with_message!(
                    Errno::EPERM,
                    "arming the ACPI power-button monitor requires CAP_SYS_BOOT"
                );
            }
            crate::arch::init_late();
        }
    }

    Ok(SyscallReturn::Return(0))
}

const PR_SET_PDEATHSIG: i32 = 1;
const PR_GET_PDEATHSIG: i32 = 2;
const PR_GET_DUMPABLE: i32 = 3;
const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_KEEPCAPS: i32 = 7;
const PR_SET_KEEPCAPS: i32 = 8;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const PR_GET_SECCOMP: i32 = 21;
const PR_SET_SECCOMP: i32 = 22;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_GET_SECUREBITS: i32 = 27;
const PR_SET_SECUREBITS: i32 = 28;
const PR_SET_TIMERSLACK: i32 = 29;
const PR_GET_TIMERSLACK: i32 = 30;
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const PR_GET_CHILD_SUBREAPER: i32 = 37;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// A non-Linux astrokube extension: install a Service (ClusterIP) DNAT rule.
/// `arg2`/`arg3` are the VIP and backend IPv4 addresses as big-endian `u32`,
/// `arg4` packs `(vport << 16) | bport`, `arg5` is the IP protocol. Temporary
/// scaffolding that drives the kernel NAT datapath until the nftables-compatible
/// netlink surface exists.
const PR_ASTROKUBE_DNAT: i32 = 0x4b55_4244; // "KUBD"

/// A non-Linux astrokube extension: mark a bridge (by its interface index in
/// `arg2`) as a masquerade uplink, so traffic forwarded onto it is source-NATed
/// to the uplink's address. Temporary scaffolding alongside [`PR_ASTROKUBE_DNAT`].
const PR_ASTROKUBE_MASQ: i32 = 0x4b55_424d; // "KUBM"

/// A non-Linux astrokube extension: arm the ACPI power-button monitor so an
/// orderly host poweroff is delivered to PID 1 as SIGINT for a graceful node
/// drain. Called once by the init after the node is up; takes no arguments.
const PR_ASTROKUBE_ACPI: i32 = 0x4b55_4143; // "KUAC"
/// astrokube: set the calling thread's astromac tenant label (arg2 = tenant id).
const PR_ASTROKUBE_SETTENANT: i32 = 0x4b55_544e; // "KUTN"
/// astrokube: set the global astromac mode (arg2 = MacMode: 0/1/2).
const PR_ASTROKUBE_MAC_MODE: i32 = 0x4b55_4d4d; // "KUMM"
/// astrokube: label the file at fd (arg2 = fd) with a tenant (arg3 = tenant).
const PR_ASTROKUBE_LABEL_FD: i32 = 0x4b55_464c; // "KUFL"

#[expect(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum PrctlCmd {
    PR_SET_PDEATHSIG(SigNum),
    PR_GET_PDEATHSIG(Vaddr),
    PR_GET_DUMPABLE,
    PR_SET_DUMPABLE(Dumpable),
    PR_GET_KEEPCAPS,
    PR_SET_KEEPCAPS(u32),
    PR_SET_NAME(Vaddr),
    PR_GET_NAME(Vaddr),
    PR_CAPBSET_READ(CapSet),
    PR_CAPBSET_DROP(CapSet),
    PR_GET_SECUREBITS,
    PR_SET_SECUREBITS(SecureBits),
    PR_SET_TIMERSLACK(u64),
    PR_GET_TIMERSLACK,
    PR_SET_CHILD_SUBREAPER(bool),
    PR_GET_CHILD_SUBREAPER(Vaddr),
    PR_SET_NO_NEW_PRIVS,
    PR_GET_NO_NEW_PRIVS,
    PR_GET_SECCOMP,
    PR_SET_SECCOMP { mode: u64, filter_ptr: Vaddr },
    PR_ASTROKUBE_DNAT {
        vip: u32,
        backend: u32,
        ports: u32,
        proto: u32,
    },
    PR_ASTROKUBE_MASQ {
        bridge_index: u32,
    },
    PR_ASTROKUBE_ACPI,
    PR_ASTROKUBE_SETTENANT(u32),
    PR_ASTROKUBE_MAC_MODE(u32),
    PR_ASTROKUBE_LABEL_FD { fd: u32, tenant: u32 },
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
pub enum Dumpable {
    Disable = 0, /* No setuid dumping */
    User = 1,    /* Dump as user of process */
    Root = 2,    /* Dump as root */
}

impl PrctlCmd {
    fn from_args(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<PrctlCmd> {
        match option {
            PR_SET_PDEATHSIG => {
                let signum = SigNum::try_from(arg2 as u8)?;
                Ok(PrctlCmd::PR_SET_PDEATHSIG(signum))
            }
            PR_GET_PDEATHSIG => Ok(PrctlCmd::PR_GET_PDEATHSIG(arg2 as _)),
            PR_GET_DUMPABLE => Ok(PrctlCmd::PR_GET_DUMPABLE),
            PR_SET_DUMPABLE => Ok(PrctlCmd::PR_SET_DUMPABLE(Dumpable::try_from(arg2)?)),
            PR_GET_KEEPCAPS => Ok(PrctlCmd::PR_GET_KEEPCAPS),
            PR_SET_KEEPCAPS => Ok(PrctlCmd::PR_SET_KEEPCAPS(arg2 as _)),
            PR_SET_NAME => Ok(PrctlCmd::PR_SET_NAME(arg2 as _)),
            PR_GET_NAME => Ok(PrctlCmd::PR_GET_NAME(arg2 as _)),
            PR_CAPBSET_READ => Ok(PrctlCmd::PR_CAPBSET_READ(parse_capability(arg2)?)),
            PR_CAPBSET_DROP => Ok(PrctlCmd::PR_CAPBSET_DROP(parse_capability(arg2)?)),
            PR_GET_SECUREBITS => Ok(PrctlCmd::PR_GET_SECUREBITS),
            PR_SET_SECUREBITS => Ok(PrctlCmd::PR_SET_SECUREBITS(SecureBits::try_from(
                arg2 as u16,
            )?)),
            PR_SET_TIMERSLACK => Ok(PrctlCmd::PR_SET_TIMERSLACK(arg2)),
            PR_GET_TIMERSLACK => Ok(PrctlCmd::PR_GET_TIMERSLACK),
            PR_SET_CHILD_SUBREAPER => Ok(PrctlCmd::PR_SET_CHILD_SUBREAPER(arg2 > 0)),
            PR_GET_CHILD_SUBREAPER => Ok(PrctlCmd::PR_GET_CHILD_SUBREAPER(arg2 as _)),
            PR_SET_NO_NEW_PRIVS => {
                // Linux only allows turning the flag on (arg2 must be 1, and
                // arg3..arg5 must be 0).
                if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return_errno_with_message!(Errno::EINVAL, "invalid PR_SET_NO_NEW_PRIVS args");
                }
                Ok(PrctlCmd::PR_SET_NO_NEW_PRIVS)
            }
            PR_GET_NO_NEW_PRIVS => Ok(PrctlCmd::PR_GET_NO_NEW_PRIVS),
            PR_GET_SECCOMP => Ok(PrctlCmd::PR_GET_SECCOMP),
            PR_SET_SECCOMP => Ok(PrctlCmd::PR_SET_SECCOMP {
                mode: arg2,
                filter_ptr: arg3 as _,
            }),
            PR_ASTROKUBE_DNAT => Ok(PrctlCmd::PR_ASTROKUBE_DNAT {
                vip: arg2 as u32,
                backend: arg3 as u32,
                ports: arg4 as u32,
                proto: arg5 as u32,
            }),
            PR_ASTROKUBE_MASQ => Ok(PrctlCmd::PR_ASTROKUBE_MASQ {
                bridge_index: arg2 as u32,
            }),
            PR_ASTROKUBE_ACPI => Ok(PrctlCmd::PR_ASTROKUBE_ACPI),
            PR_ASTROKUBE_SETTENANT => Ok(PrctlCmd::PR_ASTROKUBE_SETTENANT(arg2 as u32)),
            PR_ASTROKUBE_MAC_MODE => Ok(PrctlCmd::PR_ASTROKUBE_MAC_MODE(arg2 as u32)),
            PR_ASTROKUBE_LABEL_FD => Ok(PrctlCmd::PR_ASTROKUBE_LABEL_FD {
                fd: arg2 as u32,
                tenant: arg3 as u32,
            }),
            _ => {
                debug!("prctl cmd number: {}", option);
                return_errno_with_message!(Errno::EINVAL, "unsupported prctl command");
            }
        }
    }
}

fn parse_capability(capability: u64) -> Result<CapSet> {
    CapSet::from_capability_number(capability)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid capability number"))
}
