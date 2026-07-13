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

use alloc::sync::Arc;

use aster_pci::{
    PCI_BUS, PciDeviceId,
    bus::{PciDevice, PciDriver},
    cfg_space::Bar,
    common_device::PciCommonDevice,
};
use component::{ComponentInitError, init_component};
use ostd::{bus::BusProbeError, mm::VmIoOnce};

use crate::chip::ChipInfo;

mod chip;

/// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "nvidia: "
    };
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
        // Record the match immediately (before the BAR0 read, which could fault)
        // so the kernel can report it even if register reads fail.
        record_match(id.device_id, 0);

        ostd::info!(
            "found NVIDIA GPU {:04x}:{:04x} at {:?}",
            id.vendor_id,
            id.device_id,
            device.location(),
        );
        report_bars(&device);

        // Read NV_PMC_BOOT_0 and decode the real chip identity. This both proves
        // the register aperture is mapped and answers "can we drive it?".
        let chip = match read_boot0(&mut device) {
            Ok(chip) => chip,
            Err(e) => {
                ostd::warn!("  BAR0/NV_PMC_BOOT_0 read failed ({:?}); not claiming", e);
                return Err((BusProbeError::DeviceNotMatch, device));
            }
        };
        record_match(id.device_id, chip.boot0);
        ostd::info!(
            "  NV_PMC_BOOT_0 = {:#010x} -> {:?} impl {:#x} rev {}.{}",
            chip.boot0,
            chip.architecture,
            chip.implementation,
            chip.major_rev,
            chip.minor_rev,
        );

        if !chip.architecture.is_gsp_capable() {
            // Enumerable, but `nvidia-open` (and thus this port) cannot drive a
            // GSP-less GPU. Leave it unclaimed rather than pretend.
            ostd::warn!("  no GSP (pre-Turing/unknown); nvidia-open cannot drive it — not claiming");
            return Err((BusProbeError::DeviceNotMatch, device));
        }

        match device.acquire_msix_capability() {
            Ok(Some(msix)) => {
                ostd::info!("  MSI-X: {} vectors (GSP RPC + engine interrupts)", msix.table_size())
            }
            Ok(None) => ostd::warn!("  no MSI-X capability (GSP RPC needs MSI-X)"),
            Err(e) => ostd::warn!("  MSI-X acquire failed: {:?}", e),
        }

        // P1 milestone lives here: hand the mapped GPU to the RM and boot GSP.
        gsp::boot_stub(&chip);

        Ok(Arc::new(NvidiaGpu {
            device_id: id,
            chip,
        }))
    }
}

/// Log every BAR the GPU exposes — the P1 RM/GSP bring-up needs these addresses.
fn report_bars(device: &PciCommonDevice) {
    for idx in 0..6u8 {
        if let Some(bar) = device.bar_manager().bar(idx) {
            ostd::info!("  BAR{}: {:?}", idx, bar);
        }
    }
}

/// Read and decode `NV_PMC_BOOT_0` from BAR0 (the chip's identity register the
/// NVIDIA RM reads first). Proves the register aperture is mapped and MMIO reads
/// work; P1 replaces this with the RM's real register programming.
fn read_boot0(device: &mut PciCommonDevice) -> ostd::Result<ChipInfo> {
    let Some(Bar::Memory(mem_bar)) = device.bar_manager_mut().bar_mut(0) else {
        return Err(ostd::Error::InvalidArgs);
    };
    let io_mem = mem_bar.acquire()?;
    let boot0: u32 = io_mem.read_once(NV_PMC_BOOT_0)?;
    Ok(ChipInfo::from_boot0(boot0))
}

/// P1: GSP firmware load + RM handshake. Not yet implemented — this is the next
/// milestone in `GPU-CUDA-PORT-PLAN.md` (§3 P1), and where the vendored C RM is
/// linked in behind this same feature.
mod gsp {
    use crate::chip::{Architecture, ChipInfo};

    /// The GSP firmware image each architecture needs (matched at boot). Ampere
    /// (the RTX A4000) uses `gsp_ga10x.bin`; Turing uses `gsp_tu10x.bin`.
    pub(super) fn firmware_name(arch: Architecture) -> &'static str {
        match arch {
            Architecture::Turing => "gsp_tu10x.bin",
            _ => "gsp_ga10x.bin",
        }
    }

    pub(super) fn boot_stub(chip: &ChipInfo) {
        ostd::info!(
            "  P1 TODO: load GSP firmware {} + RM handshake ({:?})",
            firmware_name(chip.architecture),
            chip.architecture,
        );
    }
}

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use spin::Once;

static REGISTERED: Once<()> = Once::new();

/// Total number of PCI devices our driver was asked to probe (any vendor). Lets
/// the kernel confirm the PCI bus was enumerated before we registered.
pub static PROBED_COUNT: AtomicUsize = AtomicUsize::new(0);
/// The last NVIDIA GPU we matched, packed as `(1<<63) | (device_id<<32) | boot0`
/// (0 = none). Read back by the kernel to log via its own (working) logger.
pub static MATCHED: AtomicU64 = AtomicU64::new(0);

/// Records that we matched an NVIDIA GPU (device id + decoded `NV_PMC_BOOT_0`).
pub(crate) fn record_match(device_id: u16, boot0: u32) {
    MATCHED.store(
        (1u64 << 63) | ((device_id as u64) << 32) | (boot0 as u64),
        Ordering::Relaxed,
    );
}

/// Kernel-facing report: `(probed_count, Some((device_id, boot0)) | None)`.
pub fn report() -> (usize, Option<(u16, u32)>) {
    let m = MATCHED.load(Ordering::Relaxed);
    let found = if m & (1u64 << 63) != 0 {
        Some((((m >> 32) & 0xffff) as u16, (m & 0xffff_ffff) as u32))
    } else {
        None
    };
    (PROBED_COUNT.load(Ordering::Relaxed), found)
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
