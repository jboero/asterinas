// SPDX-License-Identifier: MPL-2.0

//! System call handlers.

#![cfg_attr(
    any(
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "aarch64",
        target_arch = "arm"
    ),
    expect(dead_code)
)]

pub use clock_gettime::ClockId;
use ostd::arch::cpu::context::UserContext;
pub use timer_create::create_timer;

use crate::{cpu::LinuxAbi, prelude::*};

#[cfg_attr(target_arch = "x86_64", path = "arch/x86.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv.rs")]
#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64.rs")]
#[cfg_attr(target_arch = "arm", path = "arch/arm.rs")]
mod arch;

mod accept;
mod access;
mod alarm;
#[cfg(target_arch = "x86_64")]
mod arch_prctl;
mod bind;
mod bpf;
mod brk;
mod capget;
mod capset;
mod chdir;
mod chmod;
mod chown;
mod chroot;
mod clock_gettime;
mod clone;
mod close;
mod connect;
mod constants;
mod dup;
mod epoll;
mod eventfd;
mod execve;
mod exit;
mod exit_group;
mod fadvise64;
mod fallocate;
mod fcntl;
mod flock;
mod fork;
mod fsync;
mod futex;
mod get_ioprio;
mod get_priority;
mod getcpu;
mod getcwd;
mod getdents64;
mod getegid;
mod geteuid;
mod getgid;
mod getgroups;
mod getpeername;
mod getpgid;
mod getpgrp;
mod getpid;
mod getppid;
mod getrandom;
mod getresgid;
mod getresuid;
mod getrusage;
mod getsid;
mod getsockname;
mod getsockopt;
mod gettid;
mod gettimeofday;
mod getuid;
mod getxattr;
mod inotify;
mod ioctl;
mod kill;
mod link;
mod listen;
mod listxattr;
mod lseek;
mod madvise;
mod memfd_create;
mod mkdir;
mod mknod;
mod mmap;
mod mount;
mod mprotect;
mod mremap;
mod msync;
mod munmap;
mod nanosleep;
mod open;
mod pause;
mod personality;
mod pidfd_getfd;
mod pidfd_open;
mod pidfd_send_signal;
mod pipe;
mod pivot_root;
mod poll;
mod ppoll;
mod prctl;
mod pread64;
mod preadv;
mod prlimit64;
mod pselect6;
mod ptrace;
mod pwrite64;
mod pwritev;
mod read;
mod readlink;
mod reboot;
mod recvfrom;
mod recvmsg;
mod removexattr;
mod rename;
mod rmdir;
mod rt_sigaction;
mod rt_sigpending;
mod rt_sigprocmask;
mod rt_sigreturn;
mod rt_sigsuspend;
mod rt_sigtimedwait;
mod sched_affinity;
mod sched_get_priority_max;
mod sched_get_priority_min;
mod sched_getattr;
mod sched_getparam;
mod sched_getscheduler;
mod sched_setattr;
mod sched_setparam;
mod sched_setscheduler;
mod sched_yield;
mod seccomp;
mod select;
mod semctl;
mod semget;
mod semop;
mod sendfile;
mod sendmmsg;
mod sendmsg;
mod sendto;
mod set_ioprio;
mod set_priority;
mod set_robust_list;
mod set_tid_address;
mod setdomainname;
mod setfsgid;
mod setfsuid;
mod setgid;
mod setgroups;
mod sethostname;
mod setitimer;
mod setns;
mod setpgid;
mod setregid;
mod setresgid;
mod setresuid;
mod setreuid;
mod setsid;
mod setsockopt;
mod setuid;
mod setxattr;
mod shutdown;
mod sigaltstack;
mod signalfd;
mod socket;
mod socketpair;
mod stat;
mod statfs;
mod statx;
mod symlink;
mod sync;
mod sysinfo;
mod tgkill;
mod time;
mod timer_create;
mod timer_settime;
mod timerfd_create;
mod timerfd_gettime;
mod timerfd_settime;
mod truncate;
mod umask;
mod umount;
mod uname;
mod unlink;
mod unshare;
mod utimens;
mod wait4;
mod waitid;
mod write;

/// This macro is used to define syscall handler.
/// The first param is the number of parameters,
/// The second param is the function name of syscall handler,
/// The third is optional, means the args(if parameter number > 0),
/// The fourth is optional, means if cpu ctx is required.
macro_rules! syscall_handler {
    (0, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($ctx)
    };
    (0, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($ctx, $user_ctx)
    };

    (1, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $ctx)
    };
    (1, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $ctx, $user_ctx)
    };

    (2, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $ctx)
    };
    (2, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $ctx, $user_ctx)
    };

    (3, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $args[2] as _, $ctx)
    };
    (3, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $args[2] as _, $ctx, $user_ctx)
    };

    (4, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $ctx,
        )
    };
    (4, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $ctx,
            $user_ctx,
        )
    };

    (5, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $ctx,
        )
    };
    (5, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $ctx,
            $user_ctx,
        )
    };

    (6, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $args[5] as _,
            $ctx,
        )
    };
    (6, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $args[5] as _,
            $ctx,
            $user_ctx,
        )
    };
}

macro_rules! dispatch_fn_inner {
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] ) ) => {
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx)
    };
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] , &user_ctx ) ) => {
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx, &$user_ctx)
    };
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] , &mut user_ctx ) ) => {
        // `$user_ctx` is already of type `&mut ostd::cpu::UserContext`,
        // so no need to take `&mut` again
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx, $user_ctx)
    };
}

macro_rules! impl_syscall_nums_and_dispatch_fn {
    // $args, $user_ctx, and $dispatcher_name are needed since Rust macro is hygienic
    ( $( $name: ident = $num: literal => $handler: ident $args: tt );* $(;)? ) => {
        // First, define the syscall numbers
        $(
            pub const $name: u64 = $num;
        )*

        // Then, define the dispatcher function
        pub fn syscall_dispatch(
            syscall_number: u64,
            args: [u64; 6],
            ctx: &crate::context::Context,
            user_ctx: &mut ostd::arch::cpu::context::UserContext,
        ) -> $crate::prelude::Result<$crate::syscall::SyscallReturn> {
            match syscall_number {
                $(
                    $num => {
                        $crate::syscall::log_syscall_entry!($name);
                        $crate::syscall::dispatch_fn_inner!(args, ctx, user_ctx, $handler $args)
                    }
                )*
                _ => {
                    ostd::warn!("Unimplemented syscall number: {}", syscall_number);
                    $crate::error::return_errno_with_message!(
                        $crate::error::Errno::ENOSYS,
                        "Syscall was unimplemented"
                    );
                }
            }
        }
    }
}

// Export macros to sub-modules
use dispatch_fn_inner;
use impl_syscall_nums_and_dispatch_fn;
use syscall_handler;

pub struct SyscallArgument {
    syscall_number: u64,
    args: [u64; 6],
}

/// Syscall return
#[derive(Clone, Copy, Debug)]
pub enum SyscallReturn {
    /// return isize, this value will be used to set rax
    Return(isize),
    /// does not need to set rax
    NoReturn,
}

impl SyscallArgument {
    fn new_from_context(user_ctx: &UserContext) -> Self {
        let syscall_number = user_ctx.syscall_num() as u64;
        let args = user_ctx.syscall_args().map(|x| x as u64);
        Self {
            syscall_number,
            args,
        }
    }
}

pub fn handle_syscall(ctx: &Context, user_ctx: &mut UserContext) {
    #[allow(unused_mut)]
    let mut syscall_frame = SyscallArgument::new_from_context(user_ctx);

    // Seccomp enforcement: if the calling thread installed a filter, evaluate it
    // before the syscall runs. The no-filter fast path is one relaxed atomic
    // load, so threads without seccomp (the entire zero-C node image) are
    // unaffected. Seccomp filters match on the architecture-native syscall
    // number, so this runs before the ARM number translation below.
    if ctx.posix_thread.seccomp().is_active()
        && seccomp_intercept(ctx, user_ctx, &syscall_frame)
    {
        return;
    }

    #[cfg(target_arch = "arm")]
    {
        // The ARM-private range (`__ARM_NR_*`, e.g. set_tls) is handled inline.
        if let Some(ret) = arch::handle_arm_private_syscall(
            syscall_frame.syscall_number,
            syscall_frame.args,
            user_ctx,
        ) {
            user_ctx.set_syscall_ret(ret as usize);
            return;
        }
        // Stock ARM binaries use the legacy `arch/arm` numbering; bridge it to
        // the unified asm-generic table the shared handlers are written against.
        let (number, args) =
            arch::translate_arm_syscall(syscall_frame.syscall_number, syscall_frame.args);
        syscall_frame.syscall_number = number;
        syscall_frame.args = args;
    }
    let syscall_return = arch::syscall_dispatch(
        syscall_frame.syscall_number,
        syscall_frame.args,
        ctx,
        user_ctx,
    );

    match syscall_return {
        Ok(return_value) => {
            if let SyscallReturn::Return(return_value) = return_value {
                user_ctx.set_syscall_ret(return_value as usize);
            }
        }
        Err(err) => {
            debug!("syscall return error: {:?}", err);
            let errno = err.error() as i32;
            user_ctx.set_syscall_ret((-errno) as usize)
        }
    }
}

/// Evaluates the calling thread's seccomp policy for an attempted syscall.
/// Returns `true` if the syscall was intercepted (denied/killed) and must NOT be
/// dispatched; `false` if it is allowed to proceed.
fn seccomp_intercept(
    ctx: &Context,
    user_ctx: &mut UserContext,
    frame: &SyscallArgument,
) -> bool {
    use crate::{
        process::signal::{
            constants::{SIGKILL, SIGSYS},
            signals::kernel::KernelSignal,
        },
        seccomp::SeccompAction,
    };

    // The instruction pointer is not consulted by libseccomp-generated filters,
    // so pass 0 rather than threading the arch-specific accessor through here.
    let action = ctx.posix_thread.seccomp().evaluate(
        frame.syscall_number as i32,
        frame.args,
        0,
    );
    match action {
        SeccompAction::Allow => false,
        SeccompAction::Errno(errno) => {
            user_ctx.set_syscall_ret((-(errno as i32)) as usize);
            true
        }
        SeccompAction::Trap(_) => {
            ctx.posix_thread
                .enqueue_signal(Box::new(KernelSignal::new(SIGSYS)));
            user_ctx.set_syscall_ret((-(Errno::ENOSYS as i32)) as usize);
            true
        }
        SeccompAction::KillThread => {
            ctx.posix_thread
                .enqueue_signal(Box::new(KernelSignal::new(SIGKILL)));
            true
        }
        SeccompAction::KillProcess => {
            ctx.process
                .enqueue_signal(Box::new(KernelSignal::new(SIGKILL)));
            true
        }
    }
}

macro_rules! log_syscall_entry {
    ($syscall_name: tt) => {
        if ostd::log_enabled!(ostd::log::Level::Info) {
            let syscall_name_str = stringify!($syscall_name);
            let pid = $crate::context::current!().pid();
            let tid = {
                use $crate::process::posix_thread::AsPosixThread;
                $crate::context::current_thread!()
                    .as_posix_thread()
                    .unwrap()
                    .tid()
            };
            ostd::info!(
                "[pid={}][tid={}][id={}][{}]",
                pid,
                tid,
                $syscall_name,
                syscall_name_str
            );
        }
    };
}

use log_syscall_entry;
