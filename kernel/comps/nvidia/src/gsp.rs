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

/// Base of the SEC2 falcon in BAR0 — the engine that runs the HS "Booter Load"
/// ucode which sets up WPR2 and boots the GSP RISC-V core (P1.5c). Falcon v4
/// register offsets are shared with the GSP falcon.
const NV_PSEC2: usize = 0x0084_0000;

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

/// State of the SEC2 falcon — the engine that runs the Booter (P1.5c). Read over
/// BAR0 at `NV_PSEC2`; falcon v4 register offsets, same as the GSP falcon.
#[derive(Debug, Clone, Copy)]
pub struct Sec2State {
    /// `FALCON_HWCFG2`.
    pub hwcfg2: u32,
    /// `FALCON_CPUCTL`.
    pub cpuctl: u32,
    /// SEC2 IMEM size (bytes) from `HWCFG[8:0]`.
    pub imem_bytes: u32,
    /// SEC2 DMEM size (bytes) from `HWCFG[17:9]`.
    pub dmem_bytes: u32,
    /// `FALCON_MAILBOX0` — the Booter's result register (0 = success after run).
    pub mailbox0: u32,
    /// `FALCON_MAILBOX1`.
    pub mailbox1: u32,
    /// `CPUCTL.HALTED` (bit 4) — the Booter signals done by halting.
    pub halted: bool,
}

/// Read the SEC2 falcon's pre-boot state over BAR0 (**P1.5c** groundwork). Proves
/// the SEC2 register block — where the Booter runs — is reachable, and reports
/// its memory sizes and mailboxes. Read-only; safe. The full Booter DMA-load +
/// run (into SEC2 IMEM/DMEM via `DMATRFCMD`, then `MAILBOX0/1`=WPR-meta phys,
/// `CPUCTL.STARTCPU`, poll `HALTED` + `MAILBOX0==0`) is the next step.
pub(crate) fn sec2_probe_state(regs: &IoMem) -> Option<Sec2State> {
    let hwcfg = regs.read_once::<u32>(NV_PSEC2 + 0x108).ok()?;
    let hwcfg2 = regs.read_once::<u32>(NV_PSEC2 + 0x0f4).ok()?;
    let cpuctl = regs.read_once::<u32>(NV_PSEC2 + 0x100).ok()?;
    let mailbox0 = regs.read_once::<u32>(NV_PSEC2 + 0x040).ok()?;
    let mailbox1 = regs.read_once::<u32>(NV_PSEC2 + 0x044).ok()?;
    Some(Sec2State {
        hwcfg2,
        cpuctl,
        imem_bytes: (hwcfg & 0x1ff) * 256,
        dmem_bytes: ((hwcfg >> 9) & 0x1ff) * 256,
        mailbox0,
        mailbox1,
        halted: cpuctl & CPUCTL_HALTED_BIT != 0,
    })
}

/// `NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE` (BAR0) — encodes usable FB size:
/// `LOWER_MAG` in `[27:4]`, `LOWER_SCALE` in `[3:0]`; `fbSize = MAG << (SCALE +
/// 20)`. Mirrors `kmemsysReadUsableFbSize_GP102` (Ampere inherits the offset).
const NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE: usize = 0x0010_0ce0;

/// Read the GPU's usable framebuffer size (bytes) from BAR0, returning the
/// decoded size and the raw register (for logging). The WPR2 layout (P1.5c) is
/// computed top-down from this. Read-only; safe.
pub(crate) fn read_fb_size(regs: &IoMem) -> Option<(u64, u32)> {
    let raw = regs.read_once::<u32>(NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE).ok()?;
    let mag = ((raw >> 4) & 0x00ff_ffff) as u64; // LOWER_MAG [27:4]
    let scale = (raw & 0xf) as u64; // LOWER_SCALE [3:0]
    Some((mag << (scale + 20), raw))
}

/// `NV_PFB_PRI_MMU_LOCK_ADDR_{LO,HI}` + its PLM (BAR0). If the VBIOS locked a
/// region (top of FB), WPR2 must stay below `lo`. `addr = VAL[31:4] << 12`.
const NV_PFB_PRI_MMU_LOCK_ADDR_LO: usize = 0x001f_a82c;
const NV_PFB_PRI_MMU_LOCK_ADDR_HI: usize = 0x001f_a830;
const NV_PFB_PRI_MMU_LOCK_ADDR_LO_PLM: usize = 0x001f_a7c8;

/// Read the VBIOS MMU-lock region `[lo, hi)` if present + readable, else `None`
/// (mirrors `memmgrReadMmuLock_GA100`). The WPR2 end is clamped below `lo`.
pub(crate) fn read_mmu_lock(regs: &IoMem) -> Option<(u64, u64)> {
    // Read protection must be enabled (level-0) for the lock values to be valid.
    if regs.read_once::<u32>(NV_PFB_PRI_MMU_LOCK_ADDR_LO_PLM).ok()? & 1 == 0 {
        return None;
    }
    let lo = regs.read_once::<u32>(NV_PFB_PRI_MMU_LOCK_ADDR_LO).ok()?;
    let hi = regs.read_once::<u32>(NV_PFB_PRI_MMU_LOCK_ADDR_HI).ok()?;
    let lock_lo = (((lo >> 4) & 0x0fff_ffff) as u64) << 12;
    let lock_hi = (((hi >> 4) & 0x0fff_ffff) as u64) << 12;
    (lock_hi > lock_lo).then_some((lock_lo, lock_hi))
}

/// The staged GSP RISC-V bootloader DMA buffer, kept alive for the life of the
/// system so its guest-physical address stays valid for the Booter to DMA from.
static STAGED_BOOTLOADER: Once<DmaCoherent> = Once::new();

/// Stage the GSP RISC-V bootloader image (`gsprmboot.img`) into a DMA-coherent
/// sysmem buffer and return its GPU-visible (guest-physical) address — this goes
/// into `GspFwWprMeta.sysmem_addr_of_bootloader`. **P1.5c.**
pub(crate) fn stage_bootloader_dma(image: &[u8]) -> Option<usize> {
    if image.is_empty() {
        return None;
    }
    let nframes = image.len().div_ceil(PAGE_SIZE);
    let dma = DmaCoherent::alloc(nframes, true).ok()?;
    dma.write_bytes(0, image).ok()?;
    let daddr = dma.daddr();
    STAGED_BOOTLOADER.call_once(|| dma);
    Some(daddr)
}

// --- SEC2 Booter execution (P1.5c): DMA the signed HS ucode into SEC2, run it
// against our WPR meta, and check it authenticated (MAILBOX0==0). Register
// offsets from `ampere/ga102/dev_falcon_v4.h` / `dev_falcon_second_pri.h` /
// `dev_fbif_v4.h`; sequence from `kgspExecuteHsFalcon_GA102`. ---
const NV_PSEC2_FBIF: usize = NV_PSEC2 + 0x600; // FBIF register block
const NV_PSEC2_BROM: usize = NV_PSEC2 + 0x1000; // NV_FALCON2_SEC (BROM/riscv regs)
// Falcon v4 register offsets (add NV_PSEC2).
const F_MAILBOX0: usize = 0x040;
const F_MAILBOX1: usize = 0x044;
const F_CPUCTL: usize = 0x100;
const F_BOOTVEC: usize = 0x104;
const F_DMACTL: usize = 0x10c;
const F_DMATRFBASE: usize = 0x110;
const F_DMATRFMOFFS: usize = 0x114;
const F_DMATRFCMD: usize = 0x118;
const F_DMATRFFBOFFS: usize = 0x11c;
const F_DMATRFBASE1: usize = 0x128;
const F_CPUCTL_ALIAS: usize = 0x130;
const F_ENGINE: usize = 0x3c0;
// FBIF (add NV_PSEC2_FBIF).
const FBIF_TRANSCFG0: usize = 0x00;
const FBIF_CTL: usize = 0x24;
// BROM (add NV_PSEC2_BROM).
const BROM_MOD_SEL: usize = 0x180;
const BROM_CURR_UCODE_ID: usize = 0x198;
const BROM_ENGIDMASK: usize = 0x19c;
const BROM_PARAADDR0: usize = 0x210;
// Field bits.
const DMATRFCMD_FULL: u32 = 1 << 0;
const DMATRFCMD_IDLE: u32 = 1 << 1;
const CPUCTL_STARTCPU: u32 = 1 << 1;
const CPUCTL_ALIAS_EN: u32 = 1 << 6;
/// DMA command for IMEM: `SIZE_256B(6<<8) | IMEM(1<<4) | SEC(1<<2)`.
const IMEM_DMA_CMD: u32 = (6 << 8) | (1 << 4) | (1 << 2);
/// DMA command for DMEM: `SIZE_256B` only (non-secure, no dmtag; dmemVa invalid).
const DMEM_DMA_CMD: u32 = 6 << 8;
/// Falcon DMA block size (`FLCN_BLK_ALIGNMENT`).
const FLCN_BLK: usize = 256;
/// `NV_FUSE_OPT_FPF_SEC2_UCODE1_VERSION` — per-ucode fuse version array (BAR0).
const NV_FUSE_OPT_FPF_SEC2_UCODE1_VERSION: usize = 0x0082_4140;

/// Read the SEC2 ucode fuse version for `ucode_id` (`ksec2ReadUcodeFuseVersion_GA100`):
/// the fuse is a thermometer code; version = highest-set-bit index + 1 (0 if unset).
pub(crate) fn read_ucode_fuse_version(regs: &IoMem, ucode_id: u32) -> u32 {
    let idx = ucode_id.saturating_sub(1) as usize;
    let v = regs
        .read_once::<u32>(NV_FUSE_OPT_FPF_SEC2_UCODE1_VERSION + 4 * idx)
        .unwrap_or(0);
    if v == 0 {
        0
    } else {
        (31 - v.leading_zeros()) + 1
    }
}

/// The signed, patched SEC2 booter image, DMA-staged so SEC2 can fetch it.
static STAGED_BOOTER: Once<DmaCoherent> = Once::new();
/// The DMA-staged `GspFwWprMeta` the booter reads (its phys addr goes in MAILBOX).
static STAGED_META: Once<DmaCoherent> = Once::new();

/// Stage an arbitrary byte image into a fresh DMA-coherent buffer and return its
/// guest-physical address. Used for the patched booter image and the WPR meta.
fn stage_bytes(store: &Once<DmaCoherent>, bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let nframes = bytes.len().div_ceil(PAGE_SIZE);
    let dma = DmaCoherent::alloc(nframes, true).ok()?;
    dma.write_bytes(0, bytes).ok()?;
    let daddr = dma.daddr();
    store.call_once(|| dma);
    Some(daddr)
}

/// Stage the patched booter image (SEC2 will DMA its IMEM/DMEM from here).
pub(crate) fn stage_booter_image(image: &[u8]) -> Option<usize> {
    stage_bytes(&STAGED_BOOTER, image)
}
/// Stage the 256-byte `GspFwWprMeta` for the booter; returns its phys address.
pub(crate) fn stage_wpr_meta(meta_bytes: &[u8]) -> Option<usize> {
    stage_bytes(&STAGED_META, meta_bytes)
}

/// The GSP-RM firmware signature (`.fwsignature_<chip>`) the Booter verifies.
static STAGED_SIGNATURE: Once<DmaCoherent> = Once::new();
/// Stage the GSP firmware signature; its phys addr goes in `sysmem_addr_of_signature`.
pub(crate) fn stage_signature(bytes: &[u8]) -> Option<usize> {
    stage_bytes(&STAGED_SIGNATURE, bytes)
}

/// The result of running the SEC2 Booter.
#[derive(Debug, Clone, Copy)]
pub struct BooterOutcome {
    /// `MAILBOX0` after halt — **0 == success** (WPR2 set up); nonzero = error code.
    pub mailbox0: u32,
    pub mailbox1: u32,
    /// The falcon halted (booter finished) within the timeout.
    pub halted: bool,
    /// `WPR2_ADDR_HI` read-back (nonzero once the booter brought WPR2 up).
    pub wpr2_hi: u32,
    /// `CPUCTL` after the SEC2 reset (diagnostic: `0xbadf…` = still PRI-locked).
    pub cpuctl_reset: u32,
    /// `CPUCTL` after issuing STARTCPU (diagnostic).
    pub cpuctl_start: u32,
}

/// `NV_PFB_PRI_MMU_WPR2_ADDR_HI` (BAR0) — nonzero once the booter sets up WPR2.
const NV_PFB_PRI_MMU_WPR2_ADDR_HI: usize = 0x001f_a828;

fn dma_wait_not_full(regs: &IoMem) {
    for _ in 0..1_000_000 {
        if regs.read_once::<u32>(NV_PSEC2 + F_DMATRFCMD).unwrap_or(DMATRFCMD_FULL) & DMATRFCMD_FULL
            == 0
        {
            return;
        }
    }
}

/// DMA `size` bytes from sysmem `src_phys` into the SEC2 falcon IMEM/DMEM,
/// mirroring `s_dmaTransfer_GA102` (256-byte blocks, BASE/MOFFS/FBOFFS/CMD).
fn sec2_dma(regs: &IoMem, mut dest: u32, mut mem_off: u32, src_phys: u64, size: usize, cmd: u32) {
    dma_wait_not_full(regs);
    let base = src_phys >> 8;
    let _ = regs.write_once(NV_PSEC2 + F_DMATRFBASE, &((base & 0xffff_ffff) as u32));
    let _ = regs.write_once(NV_PSEC2 + F_DMATRFBASE1, &(((base >> 32) as u32) & 0x1ff));
    let mut xfer = 0usize;
    while xfer < size {
        dma_wait_not_full(regs);
        let _ = regs.write_once(NV_PSEC2 + F_DMATRFMOFFS, &(dest & 0x00ff_ffff));
        let _ = regs.write_once(NV_PSEC2 + F_DMATRFFBOFFS, &mem_off);
        let _ = regs.write_once(NV_PSEC2 + F_DMATRFCMD, &cmd);
        xfer += FLCN_BLK;
        dest += FLCN_BLK as u32;
        mem_off += FLCN_BLK as u32;
    }
    for _ in 0..1_000_000 {
        if regs.read_once::<u32>(NV_PSEC2 + F_DMATRFCMD).unwrap_or(0) & DMATRFCMD_IDLE != 0 {
            break;
        }
    }
}

/// Reset the SEC2 falcon engine (`kflcnReset`) into a clean state before loading
/// the Booter. Falcon `ENGINE.RESET` toggle with the propagation delay.
fn sec2_reset(regs: &IoMem) {
    let _ = regs.write_once(NV_PSEC2 + F_ENGINE, &ENGINE_RESET);
    for _ in 0..RESET_PROPAGATION_READS {
        let _ = regs.read_once::<u32>(NV_PSEC2 + F_ENGINE);
    }
    let _ = regs.write_once(NV_PSEC2 + F_ENGINE, &0u32);
    for _ in 0..RESET_PROPAGATION_READS {
        let _ = regs.read_once::<u32>(NV_PSEC2 + F_ENGINE);
    }
    // Wait for reset to finish: HWCFG2.MEM_SCRUBBING (bit 12) == 0
    // (kflcnWaitForResetToFinish).
    const HWCFG2_MEM_SCRUBBING: u32 = 1 << 12;
    for _ in 0..1_000_000 {
        if regs.read_once::<u32>(NV_PSEC2 + 0xf4).unwrap_or(HWCFG2_MEM_SCRUBBING) & HWCFG2_MEM_SCRUBBING
            == 0
        {
            break;
        }
    }
    // Switch the SEC2 core to FALCON mode — this *releases the priv lockdown*
    // (kflcnSwitchToFalcon_GA102). Write BCR_CTRL.CORE_SELECT=FALCON (=0), then
    // poll VALID (bit 0). Without this the falcon front-end stays 0xbadf-locked
    // and every control write (incl. STARTCPU) is dropped.
    let bcr = NV_PSEC2_BROM + 0x668; // NV_PRISCV_RISCV_BCR_CTRL
    let _ = regs.write_once(bcr, &0u32);
    for _ in 0..1_000_000 {
        if regs.read_once::<u32>(bcr).unwrap_or(0) & 1 != 0 {
            break;
        }
    }
}

/// Run the SEC2 HS Booter (P1.5c): reset SEC2, disable ctx + point FBIF at
/// physical coherent sysmem, DMA the (already signature-patched) booter image's
/// IMEM/DMEM in, program the BROM PKC params, hand it the WPR-meta phys via the
/// mailboxes, start it, and wait for halt. `MAILBOX0 == 0` means it authenticated
/// and set up WPR2. Mirrors `kgspExecuteHsFalcon_GA102`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_booter(
    regs: &IoMem,
    booter_phys: u64,
    imem_va: u32,
    imem_size: u32,
    code_offset: u32,
    data_offset: u32,
    dmem_size: u32,
    hs_sig_dmem_addr: u32,
    ucode_id: u32,
    engine_id_mask: u32,
    wpr_meta_phys: u64,
) -> Option<BooterOutcome> {
    sec2_reset(regs);

    // Disable ctx req: FBIF_CTL.ALLOW_PHYS_NO_CTX = ALLOW; DMACTL = 0.
    let ctl = regs.read_once::<u32>(NV_PSEC2_FBIF + FBIF_CTL).ok()? | (1 << 7);
    regs.write_once(NV_PSEC2_FBIF + FBIF_CTL, &ctl).ok()?;
    regs.write_once(NV_PSEC2 + F_DMACTL, &0u32).ok()?;

    // FBIF_TRANSCFG(0): TARGET_COHERENT_SYSMEM | MEM_TYPE_PHYSICAL (bits [2:0]=0b101).
    let tc = (regs.read_once::<u32>(NV_PSEC2_FBIF + FBIF_TRANSCFG0).ok()? & !0x7) | 0x5;
    regs.write_once(NV_PSEC2_FBIF + FBIF_TRANSCFG0, &tc).ok()?;

    // DMA IMEM: src = booter_phys + codeOffset - imemVa; dest=imemPa(0); memOff=imemVa.
    sec2_dma(
        regs,
        0,
        imem_va,
        booter_phys + code_offset as u64 - imem_va as u64,
        imem_size as usize,
        IMEM_DMA_CMD,
    );
    // DMA DMEM: src = booter_phys + dataOffset; dest=dmemPa(0); memOff=0 (dmemVa invalid).
    sec2_dma(
        regs,
        0,
        0,
        booter_phys + data_offset as u64,
        dmem_size as usize,
        DMEM_DMA_CMD,
    );

    // BROM PKC signature-validation params.
    regs.write_once(NV_PSEC2_BROM + BROM_PARAADDR0, &hs_sig_dmem_addr).ok()?;
    regs.write_once(NV_PSEC2_BROM + BROM_ENGIDMASK, &engine_id_mask).ok()?;
    regs.write_once(NV_PSEC2_BROM + BROM_CURR_UCODE_ID, &(ucode_id & 0xff)).ok()?;
    regs.write_once(NV_PSEC2_BROM + BROM_MOD_SEL, &1u32).ok()?; // ALGO = RSA3K

    // BOOTVEC = start of secure code; mailboxes = WPR-meta phys.
    regs.write_once(NV_PSEC2 + F_BOOTVEC, &imem_va).ok()?;
    regs.write_once(NV_PSEC2 + F_MAILBOX0, &((wpr_meta_phys & 0xffff_ffff) as u32)).ok()?;
    regs.write_once(NV_PSEC2 + F_MAILBOX1, &((wpr_meta_phys >> 32) as u32)).ok()?;

    // Start the SEC2 CPU. On GA10x the falcon front-end PRI is locked
    // (`0xbadf…`), so STARTCPU is issued through CPUCTL_ALIAS (kflcnStartCpu uses
    // ALIAS_EN, which is the norm here). Write both to be safe.
    let cpuctl_reset = regs.read_once::<u32>(NV_PSEC2 + F_CPUCTL).unwrap_or(0);
    let use_alias = cpuctl_reset & CPUCTL_ALIAS_EN != 0 || is_pri_locked(cpuctl_reset);
    if use_alias {
        regs.write_once(NV_PSEC2 + F_CPUCTL_ALIAS, &CPUCTL_STARTCPU).ok()?;
    } else {
        regs.write_once(NV_PSEC2 + F_CPUCTL, &CPUCTL_STARTCPU).ok()?;
    }

    // Wait for halt (CPUCTL.HALTED bit4).
    let mut halted = false;
    for _ in 0..10_000_000 {
        let c = regs.read_once::<u32>(NV_PSEC2 + F_CPUCTL).unwrap_or(0);
        if !is_pri_locked(c) && c & CPUCTL_HALTED_BIT != 0 {
            halted = true;
            break;
        }
    }
    Some(BooterOutcome {
        mailbox0: regs.read_once::<u32>(NV_PSEC2 + F_MAILBOX0).unwrap_or(0xffff_ffff),
        mailbox1: regs.read_once::<u32>(NV_PSEC2 + F_MAILBOX1).unwrap_or(0),
        halted,
        wpr2_hi: regs.read_once::<u32>(NV_PFB_PRI_MMU_WPR2_ADDR_HI).unwrap_or(0),
        cpuctl_reset,
        cpuctl_start: regs.read_once::<u32>(NV_PSEC2 + F_CPUCTL).unwrap_or(0),
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
