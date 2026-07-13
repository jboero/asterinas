// SPDX-License-Identifier: MPL-2.0

//! GSP (GPU System Processor) bring-up — **P1** of the CUDA plan.
//!
//! On Ampere (GA10x) the GSP is an NV-RISCV "Peregrine" core with a Falcon v4
//! front-end, sitting in BAR0 at `NV_PGSP = 0x0011_0000`. Booting it is the path
//! to driving the GPU's engines (and thus CUDA). This module currently
//! implements **P1.1**: map the GSP microprocessor register block and read its
//! core state (identity, halt/run, memory sizes, mailboxes) over BAR0 — the
//! foundation the rest of the boot sequence (WPR, firmware DMA, RPC) builds on.
//!
//! Register offsets are taken from NVIDIA `open-gpu-kernel-modules`
//! (`dev_falcon_v4.h`, `dev_riscv_pri.h` for `ampere/ga102`) and cross-checked
//! against the in-tree `nova-core`/`nouveau` Rust re-derivations. See
//! `kernel/comps/nvidia/P1-GSP-BOOT.md`.

use ostd::{io::IoMem, mm::VmIoOnce};

use crate::chip::{Architecture, ChipInfo};

/// Base of the GSP engine in the BAR0 MMIO aperture (`NV_PGSP`).
const NV_PGSP: usize = 0x0011_0000;
/// Base of the Peregrine RISC-V register window (`NV_PGSP + 0x1000`).
const NV_PRISCV: usize = NV_PGSP + 0x1000;

// --- Falcon v4 front-end registers (offsets from NV_PGSP) ---
/// IRQ status.
const FALCON_IRQSTAT: usize = NV_PGSP + 0x008;
/// Primary boot-handshake / error-code mailbox.
const FALCON_MAILBOX0: usize = NV_PGSP + 0x040;
/// Secondary mailbox.
const FALCON_MAILBOX1: usize = NV_PGSP + 0x044;
/// OS/ucode version scratch (programmed during boot).
const FALCON_OS: usize = NV_PGSP + 0x080;
/// HW config 2 — bit 10 (`_RISCV`) advertises the RISC-V core; also carries
/// reset-ready / mem-scrubbing status.
const FALCON_HWCFG2: usize = NV_PGSP + 0x0f4;
/// Falcon CPU control (HALTED at bit 4, STARTCPU at bit 1).
const FALCON_CPUCTL: usize = NV_PGSP + 0x100;
/// HW config — IMEM size in `[8:0]`, DMEM size in `[17:9]`, each in 256-byte blocks.
const FALCON_HWCFG: usize = NV_PGSP + 0x108;

// --- Peregrine RISC-V registers (offsets from NV_PRISCV) ---
/// RISC-V core control (start/halt/active state).
const RISCV_CPUCTL: usize = NV_PRISCV + 0x388;
/// Boot-config control — written to kick the RISC-V core into secure/BROM boot.
const RISCV_BCR_CTRL: usize = NV_PRISCV + 0x668;

/// GFW (GPU firmware / devinit) boot-progress scratch. Boot is complete when the
/// low byte reads `0xff` (`GFW_BOOT_PROGRESS_COMPLETED`). Must be waited on
/// before touching the GSP. `NV_PGC6_AON_SECURE_SCRATCH_GROUP_05`.
const GFW_BOOT_STATUS: usize = 0x0011_8234;

/// `NV_PFALCON_FALCON_HWCFG2_RISCV` — the RISC-V-present bit.
const HWCFG2_RISCV_BIT: u32 = 1 << 10;
/// `NV_PFALCON_FALCON_CPUCTL_HALTED` — the Falcon-halted bit.
const CPUCTL_HALTED_BIT: u32 = 1 << 4;
/// `INTERRUPT_PROCESSOR_SUSPENDED_VALUE` — a mailbox0 with this set means the
/// ucode faulted/halted rather than booted.
const MAILBOX0_SUSPENDED: u32 = 0x8000_0000;

/// A snapshot of the GSP microprocessor's state, read over BAR0. Raw register
/// values are kept alongside decoded fields so the exact hardware readout is
/// always available even where a bitfield decode is approximate.
#[derive(Debug, Clone, Copy)]
pub struct GspCoreState {
    /// `NV_PGC6_AON_SECURE_SCRATCH_GROUP_05` — the GFW boot-progress scratch.
    pub gfw_boot: u32,
    /// True when GFW/devinit finished (`gfw_boot & 0xff == 0xff`).
    pub gfw_boot_complete: bool,
    /// Raw `FALCON_HWCFG` (IMEM/DMEM sizes).
    pub hwcfg: u32,
    /// Raw `FALCON_HWCFG2`.
    pub hwcfg2: u32,
    /// Decoded from `HWCFG2` bit 10 — the GSP exposes a RISC-V core.
    pub riscv_present: bool,
    /// Falcon IMEM size in bytes (`HWCFG[8:0]` × 256).
    pub imem_bytes: u32,
    /// Falcon DMEM size in bytes (`HWCFG[17:9]` × 256).
    pub dmem_bytes: u32,
    /// Raw `FALCON_CPUCTL`.
    pub cpuctl: u32,
    /// Decoded from `CPUCTL` bit 4 — the Falcon core is halted (expected before boot).
    pub falcon_halted: bool,
    /// Raw `RISCV_CPUCTL`.
    pub riscv_cpuctl: u32,
    /// Raw `RISCV_BCR_CTRL` (BROM boot-config).
    pub riscv_bcr_ctrl: u32,
    /// `FALCON_MAILBOX0` — boot handshake / error code.
    pub mailbox0: u32,
    /// `FALCON_MAILBOX1`.
    pub mailbox1: u32,
    /// `FALCON_OS` — ucode/OS version scratch.
    pub falcon_os: u32,
    /// `FALCON_IRQSTAT`.
    pub irqstat: u32,
}

impl GspCoreState {
    /// True if `mailbox0` carries the processor-suspended sentinel (a halted /
    /// faulted ucode), which during a boot window indicates an error.
    pub fn mailbox0_suspended(&self) -> bool {
        self.mailbox0 & MAILBOX0_SUSPENDED != 0
    }
}

/// Read the GSP microprocessor's state from BAR0 (the register aperture). This
/// is **P1.1**: it proves the GSP falcon/RISC-V register block is reachable and
/// reports the core's identity and pre-boot state, without yet booting it. Safe
/// (read-only) on any Ampere+ GPU.
pub(crate) fn probe_state(regs: &IoMem) -> Option<GspCoreState> {
    let gfw_boot = regs.read_once::<u32>(GFW_BOOT_STATUS).ok()?;
    let hwcfg = regs.read_once::<u32>(FALCON_HWCFG).ok()?;
    let hwcfg2 = regs.read_once::<u32>(FALCON_HWCFG2).ok()?;
    let cpuctl = regs.read_once::<u32>(FALCON_CPUCTL).ok()?;
    let riscv_cpuctl = regs.read_once::<u32>(RISCV_CPUCTL).ok()?;
    let riscv_bcr_ctrl = regs.read_once::<u32>(RISCV_BCR_CTRL).ok()?;
    let mailbox0 = regs.read_once::<u32>(FALCON_MAILBOX0).ok()?;
    let mailbox1 = regs.read_once::<u32>(FALCON_MAILBOX1).ok()?;
    let falcon_os = regs.read_once::<u32>(FALCON_OS).ok()?;
    let irqstat = regs.read_once::<u32>(FALCON_IRQSTAT).ok()?;

    // FALCON_HWCFG: IMEM size in [8:0], DMEM size in [17:9], each × 256 bytes.
    let imem_bytes = (hwcfg & 0x1ff) * 256;
    let dmem_bytes = ((hwcfg >> 9) & 0x1ff) * 256;

    Some(GspCoreState {
        gfw_boot,
        gfw_boot_complete: (gfw_boot & 0xff) == 0xff,
        hwcfg,
        hwcfg2,
        riscv_present: hwcfg2 & HWCFG2_RISCV_BIT != 0,
        imem_bytes,
        dmem_bytes,
        cpuctl,
        falcon_halted: cpuctl & CPUCTL_HALTED_BIT != 0,
        riscv_cpuctl,
        riscv_bcr_ctrl,
        mailbox0,
        mailbox1,
        falcon_os,
        irqstat,
    })
}

/// The GSP firmware image an architecture needs. Ampere (the RTX A4000/A5000,
/// GA10x) uses `gsp_ga10x.bin`; Turing uses `gsp_tu10x.bin`. These are NVIDIA's
/// signed HS RISC-V firmware blobs (from `linux-firmware`); they cannot be
/// authored or replaced, only shipped — the one non-negotiable vendor dependency
/// of the otherwise-Rust boot path. (Loading is P1.2.)
pub(super) fn firmware_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::Turing => "gsp_tu10x.bin",
        _ => "gsp_ga10x.bin",
    }
}

/// P1 entry point (currently P1.1): now that the chip is identified as
/// GSP-capable, this is where the boot sequence will live (WPR → firmware DMA →
/// RISC-V kick → RPC init-done). For now it is read-only register bring-up.
pub(super) fn boot_stub(chip: &ChipInfo) {
    ostd::info!(
        "  P1: GSP bring-up target {:?} (firmware {})",
        chip.architecture,
        firmware_name(chip.architecture),
    );
}
