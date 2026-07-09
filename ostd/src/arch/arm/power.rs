// SPDX-License-Identifier: MPL-2.0

//! Power management via the PSCI firmware interface.
//!
//! TODO: Read the PSCI conduit (`hvc`/`smc`) from the device tree instead of
//! assuming `hvc`, which is the QEMU `virt` default when EL2 is present.

use crate::power::{ExitCode, inject_poweroff_handler, inject_restart_handler};

// 32-bit PSCI function IDs (SMC32/HVC32 calling convention).
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

fn psci_call(function: u32) {
    // SAFETY: Issuing a PSCI call has no memory-safety implications; on success
    // it does not return.
    unsafe {
        core::arch::asm!(
            ".arch_extension virt",
            "hvc #0",
            in("r0") function,
            options(nostack, nomem),
        );
    }
}

fn try_poweroff(_code: ExitCode) {
    psci_call(PSCI_SYSTEM_OFF);
}

fn try_restart(_code: ExitCode) {
    psci_call(PSCI_SYSTEM_RESET);
}

pub(super) fn init() {
    inject_poweroff_handler(try_poweroff);
    inject_restart_handler(try_restart);
}
