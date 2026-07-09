// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    cpu::PinCurrentCpu,
    task::DisabledPreemptGuard,
    user::UserContextApi,
};

use crate::{
    cpu::LinuxAbi,
    vm::{perms::VmPerms, vmar::PageFaultInfo},
};

impl LinuxAbi for UserContext {
    fn syscall_num(&self) -> usize {
        // The ARM EABI Linux syscall number is passed in `r7`.
        self.r(7)
    }

    fn syscall_ret(&self) -> usize {
        self.r(0)
    }

    fn set_syscall_ret(&mut self, ret: usize) {
        self.set_r(0, ret)
    }

    fn syscall_args(&self) -> [usize; 6] {
        // ARM EABI passes the six syscall arguments in `r0`-`r5`.
        [
            self.r(0),
            self.r(1),
            self.r(2),
            self.r(3),
            self.r(4),
            self.r(5),
        ]
    }
}

/// Represents the context of a signal handler.
///
/// This contains the context saved before a signal handler is invoked; it will
/// be restored by `sys_rt_sigreturn`.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/arm/include/uapi/asm/sigcontext.h>
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub struct SigContext {
    /// `trap_no`.
    trap_no: u32,
    /// `error_code`.
    error_code: u32,
    /// `oldmask`.
    oldmask: u32,
    /// General-purpose registers `r0`-`r15` (`arm_r0`-`arm_pc`), then `cpsr`
    /// and `fault_address` (`arm_r0` .. `arm_cpsr`, `fault_address`).
    regs: [u32; 16],
    cpsr: u32,
    fault_address: u32,
}

impl SigContext {
    pub fn copy_user_regs_to(&self, dst: &mut UserContext) {
        let gp_regs = dst.general_regs_mut();
        for (i, reg) in self.regs.iter().enumerate() {
            gp_regs.r[i] = *reg as usize;
        }
        dst.set_cpsr(self.cpsr as usize);
    }

    pub fn copy_user_regs_from(&mut self, src: &UserContext) {
        let gp_regs = src.general_regs();
        for (i, reg) in gp_regs.r.iter().enumerate() {
            self.regs[i] = *reg as u32;
        }
        self.cpsr = src.cpsr() as u32;
    }
}

impl TryFrom<&CpuException> for PageFaultInfo {
    // [`Err`] indicates that the [`CpuException`] is not a page fault, with no
    // additional error information.
    type Error = ();

    fn try_from(value: &CpuException) -> Result<Self, ()> {
        use CpuException::*;

        match value {
            InstructionAbort(info) if info.is_page_fault() => {
                Ok(PageFaultInfo::new(info.far, VmPerms::EXEC))
            }
            DataAbort(info) if info.is_page_fault() => {
                let perms = if info.is_write() {
                    VmPerms::WRITE
                } else {
                    VmPerms::READ
                };
                Ok(PageFaultInfo::new(info.far, perms))
            }
            _ => Err(()),
        }
    }
}

/// CPU information to be shown in `/proc/cpuinfo`.
//
// TODO: Populate with `MIDR`-derived fields (implementer, part, etc.).
pub struct CpuInformation {
    processor: u32,
}

impl CpuInformation {
    /// Constructs the information for the current CPU.
    pub fn new(guard: &DisabledPreemptGuard) -> Self {
        Self {
            processor: guard.current_cpu().into(),
        }
    }
}

impl fmt::Display for CpuInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "processor\t: {}", self.processor)
    }
}
