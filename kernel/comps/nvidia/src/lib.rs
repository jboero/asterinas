// SPDX-License-Identifier: MPL-2.0

//! Native NVIDIA GPU driver for Asterinas (compute, headless).
//!
//! This is the Asterinas-side, C-free scaffolding for the plan in
//! `asterkube/docs/GPU-CUDA-PORT-PLAN.md`: run a CUDA stack inside an Asterinas
//! guest by driving a passed-through NVIDIA GPU natively. It currently
//! implements **P0**: enumerate the GPU on the PCI bus, read `NV_PMC_BOOT_0`
//! from BAR0 and decode the real chip identity (architecture / implementation /
//! revision — see [`chip`]), confirm it is GSP-capable (Turing or newer, the
//! only GPUs `nvidia-open` supports), and acquire its MSI-X capability. The
//! **P1** step — loading GSP firmware and completing the RM/GSP handshake via
//! the vendored `nvidia-open` Resource Manager — is stubbed at [`gsp`].
//!
//! Nothing here is C: the RM core is introduced later as an optional, separately
//! compiled unit behind this same feature, so a default Asterinas build never
//! pulls it in.

#![no_std]

extern crate alloc;

/// Set this crate's log prefix for `ostd::log`. This MUST be defined before any
/// `mod` declaration (and before this file's own `info!` calls) so textual
/// macro scoping can resolve it — otherwise the whole crate's log output
/// silently vanishes. Mirrors `aster-input` / `aster-pci`.
macro_rules! __log_prefix {
    () => {
        "nvidia: "
    };
}

use alloc::sync::Arc;

use aster_pci::{
    PCI_BUS, PciDeviceId,
    bus::{PciDevice, PciDriver},
    cfg_space::Bar,
    common_device::PciCommonDevice,
};
use component::{ComponentInitError, init_component};
use ostd::{bus::BusProbeError, io::IoMem, mm::VmIoOnce};

use crate::chip::ChipInfo;
pub use crate::boot::{GspFwWprMeta, Radix3, RiscvUcodeDesc};
pub use crate::fw::FwContainer;
pub use crate::gsp::{GspCoreState, GspResetOutcome, Sec2State, StagedFirmware};

mod boot;
mod chip;
mod fw;
mod gsp;

/// Build the radix3 page table over the staged firmware (returns the level-0
/// root guest-physical address for `GspFwWprMeta.sysmem_addr_of_radix3_elf`).
/// **P1.5b.**
pub fn build_radix3(fw_daddr: usize, fw_size: usize) -> Option<Radix3> {
    boot::build_radix3(fw_daddr, fw_size)
}

/// Parse a GSP firmware blob (`gsp_ga10x.bin`) into its container layout
/// (`.fwimage` / `.fwversion` / `.fwsignature*`). C-free; see [`fw`]. **P1.4.**
pub fn parse_firmware(blob: &[u8]) -> Option<FwContainer> {
    fw::parse(blob)
}

/// Stage the GSP-RM `.fwimage` into a DMA-coherent sysmem buffer, returning its
/// GPU-visible (guest-physical) address for the GSP boot to DMA from. **P1.5a.**
pub fn stage_firmware(image: &[u8]) -> Option<StagedFirmware> {
    gsp::stage_firmware_dma(image)
}

/// Stage the GSP RISC-V bootloader image into DMA-coherent sysmem; returns its
/// GPU-visible address for `GspFwWprMeta.sysmem_addr_of_bootloader`. **P1.5c.**
pub fn stage_bootloader(image: &[u8]) -> Option<usize> {
    gsp::stage_bootloader_dma(image)
}

/// Read the GPU's usable framebuffer size (bytes) + raw range register from
/// BAR0, if a GPU has been probed. Drives the WPR2 layout. **P1.5c.**
pub fn read_fb_size() -> Option<(u64, u32)> {
    gsp::read_fb_size(REG_IO_MEM.get()?)
}

/// Read the VBIOS MMU-lock region `[lo,hi)` (WPR2 must stay below `lo`), if a GPU
/// has been probed and the lock is present + readable. **P1.5c.**
pub fn read_mmu_lock() -> Option<(u64, u64)> {
    gsp::read_mmu_lock(REG_IO_MEM.get()?)
}

/// Locate a named section (offset, size) in a GSP firmware ELF container.
pub fn find_fw_section(blob: &[u8], name: &str) -> Option<(usize, usize)> {
    fw::find_section(blob, name).map(|s| (s.offset, s.size))
}

/// DMA-stage the GSP firmware signature; returns its GPU-visible address for
/// `GspFwWprMeta.sysmem_addr_of_signature`. **P1.5c.**
pub fn stage_signature(bytes: &[u8]) -> Option<usize> {
    gsp::stage_signature(bytes)
}

pub use crate::gsp::BooterOutcome;

/// Run the SEC2 HS Booter to authenticate our WPR meta and bring up WPR2
/// (**P1.5c**). Given the raw booter blobs (`booter_load.{img,sig,hdr}`), the
/// patch metadata (`patch_loc`, `ucode_id`, `engine_id`, `num_sigs`), and the
/// populated `GspFwWprMeta`: select the fuse-matched signature, patch it into the
/// image, DMA-stage the image + meta, and run the booter. `MAILBOX0 == 0` (and
/// `verified == 0xa0a0…` written back into the meta in FB) means success.
#[allow(clippy::too_many_arguments)]
pub fn run_booter(
    booter_img: &[u8],
    booter_sig: &[u8],
    booter_hdr: &[u8],
    patch_loc: u32,
    ucode_id: u32,
    engine_id: u32,
    num_sigs: u32,
    meta: &GspFwWprMeta,
) -> Option<BooterOutcome> {
    let regs = REG_IO_MEM.get()?;
    // Booter HS header: 9 little-endian u32. BootFromHs uses the app-code region
    // for IMEM and the os-data region for DMEM.
    let h = |i: usize| -> Option<u32> {
        Some(u32::from_le_bytes(booter_hdr.get(i * 4..i * 4 + 4)?.try_into().ok()?))
    };
    let code_offset = h(5)?; // appCodeOffset -> imemVa
    let imem_size = h(6)?; // appCodeSize
    let data_offset = h(2)?; // osDataOffset
    let dmem_size = h(3)?; // osDataSize
    let imem_va = code_offset;

    // Select the fuse-matched signature and patch it into a private copy of the
    // image at `patch_loc` (`s_patchBooterUcodeSignature`).
    let fuse = gsp::read_ucode_fuse_version(regs, ucode_id);
    let sig_size = booter_sig.len() / num_sigs.max(1) as usize;
    let sig_index = (num_sigs.saturating_sub(1)).saturating_sub(fuse) as usize;
    let mut patched = booter_img.to_vec();
    let (ploc, sstart) = (patch_loc as usize, sig_index * sig_size);
    patched
        .get_mut(ploc..ploc + sig_size)?
        .copy_from_slice(booter_sig.get(sstart..sstart + sig_size)?);

    let booter_phys = gsp::stage_booter_image(&patched)? as u64;
    let meta_phys = gsp::stage_wpr_meta(meta.as_bytes())? as u64;
    let hs_sig_dmem = patch_loc - data_offset;

    ostd::info!(
        "  booter: fuse_ver={} sig_idx={}/{} sigSz={} imem@{:#x} sz={:#x} dmem@{:#x} sz={:#x} hsSig@{:#x} img@{:#x} meta@{:#x}",
        fuse, sig_index, num_sigs, sig_size, imem_va, imem_size, data_offset, dmem_size,
        hs_sig_dmem, booter_phys, meta_phys,
    );
    gsp::run_booter(
        regs, booter_phys, imem_va, imem_size, code_offset, data_offset, dmem_size,
        hs_sig_dmem, ucode_id, engine_id, meta_phys,
    )
}

/// PCI vendor ID assigned to NVIDIA Corporation.
const PCI_VENDOR_NVIDIA: u16 = 0x10de;
/// PCI base class 0x03 = Display controller (VGA-compatible / 3D controller).
const PCI_CLASS_DISPLAY: u8 = 0x03;
/// `NV_PMC_BOOT_0` lives at BAR0 offset 0.
const NV_PMC_BOOT_0: usize = 0x0;

/// A claimed NVIDIA GPU. For P0 this holds the identity and decoded chip info;
/// P1 attaches the RM/GSP state.
#[derive(Debug)]
pub struct NvidiaGpu {
    device_id: PciDeviceId,
    chip: ChipInfo,
}

impl NvidiaGpu {
    /// The chip identity decoded from `NV_PMC_BOOT_0` (authoritative — read from
    /// the hardware, not guessed from the PCI ID).
    pub fn chip(&self) -> ChipInfo {
        self.chip
    }
}

impl PciDevice for NvidiaGpu {
    fn device_id(&self) -> PciDeviceId {
        self.device_id
    }
}

/// The PCI driver that claims NVIDIA display-class devices.
#[derive(Debug)]
struct NvidiaGpuDriver;

impl PciDriver for NvidiaGpuDriver {
    fn probe(
        &self,
        mut device: PciCommonDevice,
    ) -> Result<Arc<dyn PciDevice>, (BusProbeError, PciCommonDevice)> {
        PROBED_COUNT.fetch_add(1, Ordering::Relaxed);
        let id = *device.device_id();

        // Match only NVIDIA display controllers. The GPU's HDA audio function
        // (class 0x04) and any non-NVIDIA device fall through to other drivers.
        if id.vendor_id != PCI_VENDOR_NVIDIA || id.class != PCI_CLASS_DISPLAY {
            return Err((BusProbeError::DeviceNotMatch, device));
        }
        // Acquire the BAR0 register aperture once. Decode NV_PMC_BOOT_0 (offset 0)
        // for the chip identity — proving the aperture is mapped and answering
        // "can we drive it?" — and retain a clone in REG_IO_MEM for the GSP boot
        // path. A failed read yields a zero-decode (Unknown) rather than dropping
        // the device, so the report still records that we saw it.
        let reg_io = match device.bar_manager_mut().bar_mut(0) {
            Some(Bar::Memory(mem)) => mem.acquire().ok().cloned(),
            _ => None,
        };
        let chip = reg_io
            .as_ref()
            .and_then(|io| io.read_once::<u32>(NV_PMC_BOOT_0).ok())
            .map(ChipInfo::from_boot0)
            .unwrap_or_else(|| ChipInfo::from_boot0(0));
        let msix_vectors = match device.acquire_msix_capability() {
            Ok(Some(msix)) => msix.table_size(),
            _ => 0,
        };
        let gsp_capable = chip.architecture.is_gsp_capable();
        // P1.1: for GSP-capable chips, read the GSP microprocessor state (falcon /
        // RISC-V core, over BAR0).
        let gsp_state = if gsp_capable {
            reg_io.as_ref().and_then(gsp::probe_state)
        } else {
            None
        };
        // P1.3: reset the GSP falcon core (the first write-path control of the
        // GSP) and confirm it re-scrubs into a clean pre-boot state. Does not
        // boot it; independent of the BAR1 VRAM path used below.
        let gsp_reset = if gsp_capable {
            reg_io.as_ref().and_then(gsp::reset)
        } else {
            None
        };
        // P1.5c: read the SEC2 falcon state (the engine that runs the Booter).
        let sec2_state = if gsp_capable {
            reg_io.as_ref().and_then(gsp::sec2_probe_state)
        } else {
            None
        };
        // Acquire the BAR1 VRAM window once. We (a) round-trip a test pattern to
        // prove Asterinas can use GPU memory, and (b) retain a clone of the
        // `IoMem` so the kernel can expose it to userspace as `/dev/nvidia0`
        // (a container process can then read/write GPU VRAM). The clones keep the
        // MMIO mappings alive after `device` is dropped below.
        let vram_io = match device.bar_manager_mut().bar_mut(1) {
            Some(Bar::Memory(mem)) => mem.acquire().ok().cloned(),
            _ => None,
        };
        let vram_rw = vram_io.as_ref().map(test_vram_rw);
        if let Some(io) = vram_io {
            VRAM_IO_MEM.call_once(|| io);
        }
        if let Some(io) = reg_io {
            REG_IO_MEM.call_once(|| io);
        }
        let bar_bytes = bar_sizes(&device);

        // Record the full hardware inventory the driver read off the GPU over its
        // vfio BARs. The kernel logs this (this crate's own `info!` is silent on
        // x86); recorded before the GSP gate so pre-GSP cards are captured too.
        record_report(GpuReport {
            device_id: id.device_id,
            chip,
            gsp_capable,
            bar_bytes,
            msix_vectors,
            vram_rw,
            gsp_state,
            gsp_reset,
            sec2_state,
        });

        // Crate-local logs (silent on x86; kept for when that's fixed / other archs).
        ostd::info!(
            "found NVIDIA GPU {:04x}:{:04x} at {:?}; NV_PMC_BOOT_0={:#010x} -> {:?} impl {:#x} rev {}.{}, MSI-X {} vectors",
            id.vendor_id, id.device_id, device.location(),
            chip.boot0, chip.architecture, chip.implementation, chip.major_rev, chip.minor_rev, msix_vectors,
        );

        if !gsp_capable {
            // Enumerable, but `nvidia-open` cannot drive a GSP-less GPU (pre-Turing).
            ostd::warn!("  no GSP; nvidia-open cannot drive it — enumerated, not claimed");
            return Err((BusProbeError::DeviceNotMatch, device));
        }

        // P1 milestone lives here: hand the mapped GPU to the RM and boot GSP.
        gsp::boot_stub(&chip);

        Ok(Arc::new(NvidiaGpu {
            device_id: id,
            chip,
        }))
    }
}

/// The size (bytes) of each BAR the GPU exposes; index = BAR number, 0 = absent.
/// For an NVIDIA GPU: BAR0 = the register aperture, BAR1 = the VRAM window,
/// BAR3 = a secondary aperture.
fn bar_sizes(device: &PciCommonDevice) -> [u64; 6] {
    let mut sizes = [0u64; 6];
    for idx in 0..6u8 {
        if let Some(Bar::Memory(mem)) = device.bar_manager().bar(idx) {
            sizes[idx as usize] = mem.size();
        }
    }
    sizes
}

/// Attempt to use GPU VRAM: round-trip a test pattern through the BAR1 VRAM
/// window. Returns `true` if the read-back matched (Asterinas can read/write the
/// GPU's memory). Uses two offsets to guard against a stuck bus returning a
/// constant. Returns `false` on any MMIO error.
fn test_vram_rw(io: &IoMem) -> bool {
    let mut ok = true;
    for (off, pat) in [(0x1000usize, 0xa5c3_1e7fu32), (0x2000, 0x0f1e_2d3c)] {
        if io.write_once(off, &pat).is_err() {
            return false;
        }
        match io.read_once::<u32>(off) {
            Ok(v) => ok &= v == pat,
            Err(_) => return false,
        }
    }
    ok
}

use core::sync::atomic::{AtomicUsize, Ordering};

use spin::{Mutex, Once};

use crate::chip::Architecture;

static REGISTERED: Once<()> = Once::new();

/// The GPU's BAR1 VRAM-window `IoMem`, retained after probe so the kernel can
/// surface it to userspace as `/dev/nvidia0` (mirrors `aster-framebuffer`'s
/// `FRAMEBUFFER` global). A clone keeps the MMIO mapping alive independently of
/// the `PciCommonDevice`. `None` until a GPU with a BAR1 is probed.
pub static VRAM_IO_MEM: Once<IoMem> = Once::new();

/// The GPU VRAM aperture (BAR1) as an `IoMem`, if a GPU has been probed. The
/// kernel wraps this in a char device so a userspace/container process can
/// `read`/`write`/`mmap` GPU memory. C-free; needs no GSP.
pub fn vram_io_mem() -> Option<IoMem> {
    VRAM_IO_MEM.get().cloned()
}

/// The GPU's BAR0 register aperture `IoMem`, retained after probe. This is the
/// GPU's control surface — the GSP microprocessor, engine registers, etc. — and
/// the substrate the P1 GSP boot path drives. `None` until a GPU is probed.
pub static REG_IO_MEM: Once<IoMem> = Once::new();

/// The GPU register aperture (BAR0) as an `IoMem`, if a GPU has been probed.
pub fn reg_io_mem() -> Option<IoMem> {
    REG_IO_MEM.get().cloned()
}

/// Total number of PCI devices our driver was asked to probe (any vendor). Lets
/// the kernel confirm the PCI bus was enumerated before we registered.
pub static PROBED_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The hardware inventory the driver read off the passed-through GPU over its
/// vfio BARs. Surfaced to the kernel's (working) logger via [`report`] — the
/// crate's own `info!` output does not reach the console on x86.
#[derive(Debug, Clone, Copy)]
pub struct GpuReport {
    pub device_id: u16,
    pub chip: ChipInfo,
    pub gsp_capable: bool,
    /// BAR sizes in bytes (index = BAR number; 0 if the BAR is absent).
    pub bar_bytes: [u64; 6],
    /// Number of MSI-X interrupt vectors the GPU exposes (0 if none).
    pub msix_vectors: u16,
    /// VRAM round-trip through the BAR1 window: `Some(true)` if a pattern written
    /// to GPU memory read back correctly (the driver can *use* GPU VRAM),
    /// `Some(false)` if it didn't, `None` if BAR1 is absent / not acquirable.
    pub vram_rw: Option<bool>,
    /// GSP microprocessor state read over BAR0 (P1.1). `Some` for GSP-capable
    /// chips where the register block was reachable; `None` otherwise.
    pub gsp_state: Option<GspCoreState>,
    /// Outcome of the GSP falcon reset (P1.3). `Some` for GSP-capable chips.
    pub gsp_reset: Option<GspResetOutcome>,
    /// SEC2 falcon state (P1.5c) — the engine that runs the GSP Booter.
    pub sec2_state: Option<Sec2State>,
}

static REPORT: Mutex<Option<GpuReport>> = Mutex::new(None);

pub(crate) fn record_report(r: GpuReport) {
    *REPORT.lock() = Some(r);
}

/// Kernel-facing report: `(probed_count, the GPU inventory | None)`.
pub fn report() -> (usize, Option<GpuReport>) {
    (PROBED_COUNT.load(Ordering::Relaxed), *REPORT.lock())
}

/// Registers the GPU driver with the PCI bus (idempotent). The bus probes
/// already-enumerated devices and any that appear later. On a machine with no
/// NVIDIA GPU passed through, this is a no-op.
///
/// This is called both from the `#[init_component]` hook and directly from the
/// kernel's `driver::init`, because the component hook's link-section
/// registration is unreliable for this crate; the direct call guarantees it runs.
#[inline(never)]
pub fn ensure_linked() {
    REGISTERED.call_once(|| {
        ostd::info!("ensure_linked() ENTER — registering PCI driver");
        PCI_BUS
            .lock()
            .register_driver(Arc::new(NvidiaGpuDriver) as Arc<dyn PciDriver>);
        ostd::info!("driver registered (P0: enumerate + decode NV_PMC_BOOT_0)");
    });
}

#[init_component]
fn nvidia_init() -> Result<(), ComponentInitError> {
    ensure_linked();
    Ok(())
}
