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
pub use crate::gsp::GspCoreState;

mod chip;
mod gsp;

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
        // RISC-V core, over BAR0). Read-only; the boot sequence comes next.
        let gsp_state = if gsp_capable {
            reg_io.as_ref().and_then(gsp::probe_state)
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
