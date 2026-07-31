// SPDX-License-Identifier: MPL-2.0

//! `/dev/nvidia0` — a userspace-facing window onto a passed-through NVIDIA GPU.
//!
//! The `aster-nvidia` component probes the GPU and retains its BAR1 VRAM-window
//! `IoMem` (see [`aster_nvidia::vram_io_mem`]). This module wraps that aperture
//! in a character device so an ordinary userspace process — including one
//! confined to a container — can `open("/dev/nvidia0")` and `read`/`write`/`mmap`
//! GPU memory. This is the C-free, GSP-independent path to *using* the GPU from
//! a container; it works on any enumerated GPU (Kepler through Ampere), unlike
//! the full CUDA/RM stack which needs GSP (Turing+).
//!
//! Structurally identical to the framebuffer device ([`super::fb`]): both expose
//! a PCI-BAR `IoMem` via read/write and `Mappable::IoMem`.

use device_id::{DeviceId, MajorId, MinorId};
use ostd::mm::HasSize;

use super::{Device, DeviceType, DevtmpfsInodeMeta, registry::char};
use crate::{
    events::IoEvents,
    fs::{
        file::{Mappable, PerOpenFileOps, StatusFlags, mkmod},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

/// The GPU character device (`/dev/nvidia0`). Linux uses major 195 for NVIDIA.
#[derive(Debug)]
struct NvidiaGpu0;

/// A per-open handle holding a clone of the GPU's BAR1 VRAM-window `IoMem`.
#[derive(Debug)]
struct NvidiaGpu0Handle {
    vram: ostd::io::IoMem,
}

impl Device for NvidiaGpu0 {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        // Same major as Linux's NVIDIA driver (195); minor 0 = first GPU.
        DeviceId::new(MajorId::new(195), MinorId::new(0))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        // Read+write so a container process can both read and write GPU VRAM
        // (and map it writably).
        Some(DevtmpfsInodeMeta::with_mode("nvidia0", mkmod!(a+rw)))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let Some(vram) = aster_nvidia::vram_io_mem() else {
            return Err(Error::with_message(
                Errno::ENODEV,
                "no NVIDIA GPU VRAM aperture is present",
            ));
        };
        Ok(Box::new(NvidiaGpu0Handle { vram }))
    }
}

impl Pollable for NvidiaGpu0Handle {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        (IoEvents::IN | IoEvents::OUT) & mask
    }
}

impl FileOps for NvidiaGpu0Handle {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if !writer.has_avail() {
            return Ok(0);
        }
        let size = self.vram.size();
        if offset >= size {
            return Ok(0);
        }
        let len = writer.avail().min(size - offset);
        if len == 0 {
            return Ok(0);
        }
        let mut new_writer = writer.clone_exclusive();
        new_writer.limit(len);

        let copied = match self.vram.read_fallible(offset, &mut new_writer) {
            Ok(copied) => copied,
            Err((_err, copied)) if copied > 0 => copied,
            Err((err, _)) => return Err(err.into()),
        };
        writer.skip(copied);
        Ok(copied)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if !reader.has_remain() {
            return Ok(0);
        }
        let size = self.vram.size();
        if offset >= size {
            return_errno_with_message!(Errno::ENOSPC, "the write offset is beyond GPU VRAM");
        }
        let len = reader.remain().min(size - offset);
        if len == 0 {
            return Ok(0);
        }
        let mut new_reader = reader.clone();
        new_reader.limit(len);

        let copied = match self.vram.write_fallible(offset, &mut new_reader) {
            Ok(copied) => copied,
            Err((_err, copied)) if copied > 0 => copied,
            Err((err, _)) => return Err(err.into()),
        };
        reader.skip(copied);
        Ok(copied)
    }
}

impl PerOpenFileOps for NvidiaGpu0Handle {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }

    fn mappable(&self) -> Result<Mappable> {
        // Map the GPU's VRAM window straight into the process address space.
        Ok(Mappable::IoMem(self.vram.clone()))
    }
}

pub(super) fn init_in_first_kthread() {
    if aster_nvidia::vram_io_mem().is_none() {
        return;
    }
    char::register(Arc::new(NvidiaGpu0)).expect("failed to register /dev/nvidia0 char device");
}

/// Candidate initramfs paths for the GSP-RM firmware image (P1.4). The driver
/// probe runs before any filesystem exists, so the firmware is read here, after
/// rootfs mount, and parsed to locate the `.fwimage` payload the GSP boot will
/// DMA into VRAM (P1.5).
const GSP_FW_PATHS: &[&str] = &["/gsp_ga10x.bin", "/lib/firmware/gsp_ga10x.bin"];

/// Read an entire file from the (mounted) initramfs into a buffer, or `None` if
/// it is absent. Used to pull the GSP boot ucodes staged alongside the firmware.
fn read_initramfs(
    path_resolver: &crate::fs::vfs::path::PathResolver,
    path: &str,
) -> Option<alloc::vec::Vec<u8>> {
    use crate::fs::vfs::path::FsPath;
    let fp = FsPath::try_from(path).ok()?;
    let dentry = path_resolver.lookup(&fp).ok()?;
    let size = dentry.size();
    let mut buf = alloc::vec![0u8; size];
    let n = dentry.inode().read_bytes_at(0, &mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// P1.4: locate, read, and parse a staged GSP firmware image. Non-fatal — if no
/// firmware was baked into the initramfs, this just logs that and returns.
pub(super) fn load_gsp_firmware(path_resolver: &crate::fs::vfs::path::PathResolver) {
    use crate::fs::vfs::path::FsPath;

    let mut path = None;
    for p in GSP_FW_PATHS {
        if let Ok(fp) = FsPath::try_from(*p) {
            if let Ok(found) = path_resolver.lookup(&fp) {
                path = Some((*p, found));
                break;
            }
        }
    }
    let Some((name, path)) = path else {
        info!("nvidia: no GSP firmware staged in initramfs (P1.4 skipped)");
        return;
    };

    let size = path.size();
    let mut buf = alloc::vec![0u8; size];
    let n = match path.inode().read_bytes_at(0, &mut buf) {
        Ok(n) => n,
        Err(e) => {
            info!("nvidia: failed to read GSP firmware {}: {:?}", name, e);
            return;
        }
    };
    let blob = &buf[..n];

    match aster_nvidia::parse_firmware(blob) {
        Some(fw) => {
            info!(
                "nvidia: GSP firmware {} parsed (P1.4): {} bytes, machine={:#x} (0xf3=RISC-V), {} sections, {} signatures",
                name, n, fw.machine, fw.section_count, fw.signature_count,
            );
            info!(
                "nvidia:   .fwimage={} bytes, .fwversion={:?}",
                fw.image.map(|s| s.size).unwrap_or(0),
                fw.version_str(blob),
            );
            // P1.5a: stage the .fwimage into GPU-DMA-able sysmem.
            if let Some(img) = fw.image {
                if let Some(image) = blob.get(img.offset..img.offset + img.size) {
                    match aster_nvidia::stage_firmware(image) {
                        Some(s) => {
                            info!(
                                "nvidia:   .fwimage staged for DMA (P1.5a): {} bytes at GPU-phys {:#x}, verified={}",
                                s.bytes, s.daddr, s.verified,
                            );
                            // P1.5b: build the radix3 page table over the staged
                            // firmware + the byte-exact WPR descriptor the Booter reads.
                            if let Some(rx) = aster_nvidia::build_radix3(s.daddr, s.bytes) {
                                info!(
                                    "nvidia:   radix3 built (P1.5b): root@{:#x}, {} fw pages via {} L2 pages, verified={}",
                                    rx.root_daddr, rx.fw_pages, rx.l2_pages, rx.verified,
                                );
                                // P1.5c: stage the GSP RISC-V bootloader, read the
                                // usable FB size, and build the full WPR2 layout the
                                // SEC2 Booter reads. The ucodes are baked into the
                                // initramfs next to gsp_ga10x.bin.
                                let boot_desc = read_initramfs(path_resolver, "/gsprmboot.desc")
                                    .and_then(|d| aster_nvidia::RiscvUcodeDesc::parse(&d));
                                let boot_img = read_initramfs(path_resolver, "/gsprmboot.img");
                                let bl_daddr = boot_img
                                    .as_ref()
                                    .and_then(|i| aster_nvidia::stage_bootloader(i));
                                let fb = aster_nvidia::read_fb_size();
                                match (boot_desc.as_ref(), boot_img.as_ref(), bl_daddr, fb) {
                                    (Some(desc), Some(img), Some(bl), Some((fb_size, fb_raw))) => {
                                        let mmu_lock = aster_nvidia::read_mmu_lock();
                                        let mut meta = aster_nvidia::GspFwWprMeta::populate(
                                            fb_size,
                                            rx.root_daddr as u64,
                                            s.bytes as u64,
                                            bl as u64,
                                            img.len() as u64,
                                            desc,
                                            mmu_lock.map(|(lo, _)| lo),
                                        );
                                        // P1.5c: stage the GA10x GSP-RM firmware signature the
                                        // Booter verifies (sysmem_addr_of_signature).
                                        if let Some((soff, ssz)) =
                                            aster_nvidia::find_fw_section(blob, ".fwsignature_ga10x")
                                        {
                                            if let Some(sd) = blob
                                                .get(soff..soff + ssz)
                                                .and_then(aster_nvidia::stage_signature)
                                            {
                                                meta.sysmem_addr_of_signature = sd as u64;
                                                meta.size_of_signature = ssz as u64;
                                                info!("nvidia:   staged .fwsignature_ga10x ({} B) @{:#x}", ssz, sd);
                                            }
                                        }
                                        info!("nvidia:   mmu_lock={:x?} vgaWorkspace@{:#x}", mmu_lock, meta.vga_workspace_offset);
                                        info!("nvidia:   meta[256]={:02x?}", meta.as_bytes());
                                        info!(
                                            "nvidia:   FB {:#x} ({} MB) [LOCAL_MEMORY_RANGE={:#010x}]; bootloader @{:#x} ({} B) code@{:#x} data@{:#x} manifest@{:#x} appVer={}",
                                            fb_size, fb_size >> 20, fb_raw, bl, img.len(),
                                            desc.monitor_code_offset, desc.monitor_data_offset,
                                            desc.manifest_offset, desc.app_version,
                                        );
                                        info!(
                                            "nvidia:   WPR2 layout (P1.5c): wprStart={:#x} wprEnd={:#x} heap={:#x}/{:#x} fwOff={:#x} bootBin={:#x} frts={:#x}/{:#x} nonWprHeap={:#x}/{:#x} radix3@{:#x}",
                                            meta.gsp_fw_wpr_start, meta.gsp_fw_wpr_end,
                                            meta.gsp_fw_heap_offset, meta.gsp_fw_heap_size,
                                            meta.gsp_fw_offset, meta.boot_bin_offset,
                                            meta.frts_offset, meta.frts_size,
                                            meta.non_wpr_heap_offset, meta.non_wpr_heap_size,
                                            meta.sysmem_addr_of_radix3_elf,
                                        );
                                        // P1.5c: run the SEC2 HS booter against this meta.
                                        let booter = read_initramfs(path_resolver, "/booter_load.img");
                                        let bsig = read_initramfs(path_resolver, "/booter_load.sig");
                                        let bhdr = read_initramfs(path_resolver, "/booter_load.hdr");
                                        match (booter, bsig, bhdr) {
                                            (Some(b), Some(s2), Some(h)) => {
                                                // patch metadata decoded from the 610.43.02 GA102 booter
                                                // bindata (scripts/extract-gsp-booter.py): patchLoc=0x8a10,
                                                // ucodeId=3, engineId=1, numSigs=2.
                                                match aster_nvidia::run_booter(&b, &s2, &h, 0x8a10, 3, 1, 2, &meta) {
                                                    Some(o) => info!(
                                                        "nvidia:   SEC2 booter ran: halted={} MAILBOX0={:#010x} MAILBOX1={:#010x} WPR2_HI={:#010x} cpuctl(reset={:#010x} start={:#010x}) => {}",
                                                        o.halted, o.mailbox0, o.mailbox1, o.wpr2_hi, o.cpuctl_reset, o.cpuctl_start,
                                                        if o.mailbox0 == 0 && o.wpr2_hi != 0 {
                                                            "AUTHENTICATED — WPR2 up (GSP boot proceeds)"
                                                        } else {
                                                            "not yet — iterate WPR meta/layout vs MAILBOX0"
                                                        },
                                                    ),
                                                    None => info!("nvidia:   SEC2 booter run: staging/reg error"),
                                                }
                                            }
                                            _ => info!("nvidia:   booter blobs missing (/booter_load.img|sig|hdr)"),
                                        }
                                    }
                                    _ => info!(
                                        "nvidia:   P1.5c: missing inputs (desc={} img={} fb={}) — bake gsprmboot.* into the initramfs",
                                        boot_desc.is_some(), boot_img.is_some(), fb.is_some(),
                                    ),
                                }
                            }
                        }
                        None => info!(
                            "nvidia:   .fwimage DMA staging failed ({} bytes)",
                            img.size,
                        ),
                    }
                }
            }
        }
        None => info!(
            "nvidia: GSP firmware {} present ({} bytes) but not a valid ELF container",
            name, n
        ),
    }
}
