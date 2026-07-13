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

use ostd::{
    io::IoMem,
    mm::{HasDaddr, PAGE_SIZE, VmIo, VmIoOnce, dma::DmaCoherent},
};
use spin::Once;

use crate::chip::{Architecture, ChipInfo};

/// The DMA-coherent sysmem buffer holding the staged GSP-RM `.fwimage` (P1.5a).
/// Kept alive for the life of the system so its guest-physical address stays
/// valid for the GPU to DMA from.
static STAGED_FW: Once<DmaCoherent> = Once::new();

/// Result of staging the firmware into GPU-DMA-able sysmem (P1.5a).
#[derive(Debug, Clone, Copy)]
pub struct StagedFirmware {
    /// GPU-visible (guest-physical) address of the buffer — what the GSP booter /
    /// RISC-V core will DMA the firmware from. (No guest vIOMMU, so daddr==GPA.)
    pub daddr: usize,
    /// Bytes copied.
    pub bytes: usize,
    /// First/last 8 bytes read back from the DMA buffer matched the source.
    pub verified: bool,
}

/// **P1.5a** — copy the GSP-RM `.fwimage` into a DMA-coherent sysmem buffer and
/// return its GPU-visible (guest-physical) address. This is the substrate the
/// GSP boot needs: the passed-through GPU DMAs using guest-physical addresses
/// (no guest vIOMMU), so `daddr` is exactly where the booter/RISC-V core reads
/// the firmware. Returns `None` if the contiguous DMA allocation fails (e.g. the
/// image is too large to allocate contiguously — the real path scatters it via
/// radix3 page tables, P1.5b).
pub(crate) fn stage_firmware_dma(image: &[u8]) -> Option<StagedFirmware> {
    if image.is_empty() {
        return None;
    }
    let nframes = image.len().div_ceil(PAGE_SIZE);
    let dma = DmaCoherent::alloc(nframes, true).ok()?;
    dma.write_bytes(0, image).ok()?;

    // Verify the copy landed: round-trip the first and last 8 bytes.
    let mut head = [0u8; 8];
    let mut tail = [0u8; 8];
    let tail_off = image.len().saturating_sub(8);
    let verified = dma.read_bytes(0, &mut head).is_ok()
        && dma.read_bytes(tail_off, &mut tail).is_ok()
        && head == image[..8]
        && tail == image[tail_off..];

    let daddr = dma.daddr();
    STAGED_FW.call_once(|| dma);
    Some(StagedFirmware {
        daddr,
        bytes: image.len(),
        verified,
    })
}

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

/// Falcon engine reset (`NV_PGSP_FALCON_ENGINE`): bit 0 `_RESET` (1=assert).
const FALCON_ENGINE: usize = NV_PGSP + 0x3c0;
/// DMA control — bit 1 `DMEM_SCRUBBING`, bit 2 `IMEM_SCRUBBING`; both 0 = done.
/// This is what the RM polls to know a falcon reset finished (not HWCFG2).
const FALCON_DMACTL: usize = NV_PGSP + 0x10c;

// --- Peregrine RISC-V registers (offsets from NV_PRISCV) ---
/// RISC-V core control — bit 7 `ACTIVE_STAT` (1=running), bit 4 `HALTED`.
const RISCV_CPUCTL: usize = NV_PRISCV + 0x388;
/// Boot-config control — written `0x111` (CORE_SELECT_RISCV | VALID | BRFETCH)
/// to kick the RISC-V core into secure/BROM boot; bit 0 `VALID` is RO status.
const RISCV_BCR_CTRL: usize = NV_PRISCV + 0x668;

/// `NV_PGSP_FALCON_ENGINE_RESET` — assert-reset bit.
const ENGINE_RESET: u32 = 1 << 0;
/// `NV_PFALCON_FALCON_HWCFG2_RESET_READY` (bit 31) — 1 = ready for reset.
const HWCFG2_RESET_READY: u32 = 1 << 31;
/// DMACTL IMEM+DMEM scrubbing mask (bits 1,2); == 0 means scrub done.
const DMACTL_SCRUB_MASK: u32 = 0x6;
/// Number of ENGINE read-backs used as the reset propagation delay
/// (`FLCN_RESET_PROPAGATION_DELAY_COUNT`).
const RESET_PROPAGATION_READS: usize = 10;
/// PRI priv-lockdown sentinel: a register read of `0xbadf_____` (high 16 bits ==
/// `0xbadf`) means the register is locked / access-denied rather than real data.
/// GA10x locks the Falcon front-end PRI after reset-into-RISC-V.
const PRI_LOCKDOWN_MASK: u32 = 0xffff_0000;
const PRI_LOCKDOWN_VALUE: u32 = 0xbadf_0000;

/// True if a register read is the `0xbadf____` priv-lockdown sentinel.
fn is_pri_locked(v: u32) -> bool {
    v & PRI_LOCKDOWN_MASK == PRI_LOCKDOWN_VALUE
}

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

/// Outcome of a GSP falcon reset (**P1.3** — the first *control* of the GSP core).
#[derive(Debug, Clone, Copy)]
pub struct GspResetOutcome {
    /// `HWCFG2.RESET_READY` (bit 31) was observed set during the pre-reset wait.
    pub reset_ready_seen: bool,
    /// After reset, DMACTL IMEM+DMEM scrubbing completed (bits 1,2 == 0) — the
    /// RM's actual "reset finished, core ready" condition. Only meaningful when
    /// `falcon_pri_locked` is false.
    pub scrub_done: bool,
    /// After reset the Falcon front-end PRI read back the `0xbadf____` lockdown
    /// sentinel — the expected GA10x "reset into RISC-V mode" state (the boot
    /// then proceeds via SEC2 + the RISC-V window, not this locked front-end).
    pub falcon_pri_locked: bool,
    /// Post-reset `FALCON_CPUCTL` (`0xbadf____` if the front-end locked).
    pub post_cpuctl: u32,
    /// Post-reset `FALCON_DMACTL`.
    pub post_dmactl: u32,
    /// Post-reset `RISCV_CPUCTL` (expect not-ACTIVE).
    pub post_riscv_cpuctl: u32,
}

/// Reset the GSP falcon core into a clean pre-boot state — the first *write*-path
/// control of the GSP. Mirrors `kflcnResetIntoRiscv_GA102` steps 1–3 for GA10x:
/// pre-reset wait on `HWCFG2.RESET_READY`, toggle `NV_PGSP_FALCON_ENGINE.RESET`
/// with the 10-read-back propagation delay, then poll `DMACTL` scrubbing done.
///
/// It deliberately does **not** arm the RISC-V BROM (`BCR_CTRL`) — that starts a
/// boot, which needs the firmware staged in WPR2 (P1.5). Safe here: the GSP is
/// halted and running nothing. Timeouts are bounded read-loops (the RM's
/// RESET_READY timeout is itself non-fatal).
pub(crate) fn reset(regs: &IoMem) -> Option<GspResetOutcome> {
    // 1. Pre-reset wait: HWCFG2.RESET_READY (bit 31) -> 1. Non-fatal if it never
    //    sets (HW erratum; the RM proceeds regardless).
    let mut reset_ready_seen = false;
    for _ in 0..100_000 {
        if regs.read_once::<u32>(FALCON_HWCFG2).ok()? & HWCFG2_RESET_READY != 0 {
            reset_ready_seen = true;
            break;
        }
    }

    // 2. Falcon engine reset: RESET=1, 10 ENGINE read-backs (propagation delay),
    //    RESET=0, 10 read-backs.
    regs.write_once(FALCON_ENGINE, &ENGINE_RESET).ok()?;
    for _ in 0..RESET_PROPAGATION_READS {
        regs.read_once::<u32>(FALCON_ENGINE).ok()?;
    }
    regs.write_once(FALCON_ENGINE, &0u32).ok()?;
    for _ in 0..RESET_PROPAGATION_READS {
        regs.read_once::<u32>(FALCON_ENGINE).ok()?;
    }

    // 3. Wait for reset to finish: DMACTL IMEM/DMEM scrubbing done (bits 1,2 == 0).
    //    On GA10x the Falcon front-end may PRI-lock (0xbadf sentinel) as it drops
    //    into RISC-V mode — detect that rather than misreading it as scrub-done.
    let mut scrub_done = false;
    let mut falcon_pri_locked = false;
    for _ in 0..1_000_000 {
        let dmactl = regs.read_once::<u32>(FALCON_DMACTL).ok()?;
        if is_pri_locked(dmactl) {
            falcon_pri_locked = true;
            break;
        }
        if dmactl & DMACTL_SCRUB_MASK == 0 {
            scrub_done = true;
            break;
        }
    }

    Some(GspResetOutcome {
        reset_ready_seen,
        scrub_done,
        falcon_pri_locked,
        post_cpuctl: regs.read_once::<u32>(FALCON_CPUCTL).ok()?,
        post_dmactl: regs.read_once::<u32>(FALCON_DMACTL).ok()?,
        post_riscv_cpuctl: regs.read_once::<u32>(RISCV_CPUCTL).ok()?,
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
