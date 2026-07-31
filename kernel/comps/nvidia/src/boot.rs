// SPDX-License-Identifier: MPL-2.0

//! GSP boot data structures — **P1.5b**.
//!
//! Byte-exact Rust transcriptions of the version-locked structures the SEC2
//! Booter and the GSP RISC-V core read out of sysmem during boot. These are
//! ABI-locked to the firmware version (`gsp_ga10x.bin` 595.80 here) and are
//! taken verbatim from NVIDIA `open-gpu-kernel-modules`
//! (`gsp_fw_wpr_meta.h`) — transcribed to Rust, no vendored C.
//!
//! Only the data-plane structures live here; wiring them into a live boot (WPR2
//! layout, SEC2 HS booter execution, RPC) is P1.5c–P1.7.

use ostd::mm::{HasDaddr, VmIo, dma::DmaCoherent};
use spin::Once;

/// `GSP_FW_WPR_META_MAGIC` — the Booter checks this to validate the descriptor.
pub const GSP_FW_WPR_META_MAGIC: u64 = 0xdc3a_ae21_371a_60b3;
/// `GSP_FW_WPR_META_REVISION`.
pub const GSP_FW_WPR_META_REVISION: u64 = 1;

/// `GspFwWprMeta` — the Write-Protected-Region descriptor the CPU builds in
/// sysmem and the SEC2 Booter reads to set up WPR2 and place/authenticate the
/// GSP-RM firmware. Byte-exact (256 bytes) transcription of the nvidia-open
/// struct; unions are flattened to their primary (non-crash-report) variant.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GspFwWprMeta {
    pub magic: u64,                    // 0x00
    pub revision: u64,                 // 0x08
    pub sysmem_addr_of_radix3_elf: u64, // 0x10 — root of the radix3 page table over .fwimage
    pub size_of_radix3_elf: u64,       // 0x18
    pub sysmem_addr_of_bootloader: u64, // 0x20
    pub size_of_bootloader: u64,       // 0x28
    pub bootloader_code_offset: u64,   // 0x30
    pub bootloader_data_offset: u64,   // 0x38
    pub bootloader_manifest_offset: u64, // 0x40
    pub sysmem_addr_of_signature: u64, // 0x48 (union)
    pub size_of_signature: u64,        // 0x50 (union)
    pub gsp_fw_rsvd_start: u64,        // 0x58
    pub non_wpr_heap_offset: u64,      // 0x60
    pub non_wpr_heap_size: u64,        // 0x68
    pub gsp_fw_wpr_start: u64,         // 0x70
    pub gsp_fw_heap_offset: u64,       // 0x78
    pub gsp_fw_heap_size: u64,         // 0x80
    pub gsp_fw_offset: u64,            // 0x88
    pub boot_bin_offset: u64,          // 0x90
    pub frts_offset: u64,              // 0x98
    pub frts_size: u64,                // 0xa0
    pub gsp_fw_wpr_end: u64,           // 0xa8
    pub fb_size: u64,                  // 0xb0
    pub vga_workspace_offset: u64,     // 0xb8
    pub vga_workspace_size: u64,       // 0xc0
    pub boot_count: u64,               // 0xc8
    pub partition_rpc_addr: u64,       // 0xd0 (union)
    pub partition_rpc_request_offset: u16, // 0xd8
    pub partition_rpc_reply_offset: u16, // 0xda
    pub elf_code_offset: u32,          // 0xdc
    pub elf_data_offset: u32,          // 0xe0
    pub elf_code_size: u32,            // 0xe4
    pub elf_data_size: u32,            // 0xe8
    pub ls_ucode_version: u32,         // 0xec
    pub gsp_fw_heap_vf_partition_count: u8, // 0xf0
    pub flags: u8,                     // 0xf1
    pub padding: [u8; 2],              // 0xf2
    pub pmu_reserved_size: u32,        // 0xf4
    pub verified: u64,                 // 0xf8  (set to a magic by the Booter on success)
}

impl GspFwWprMeta {
    /// A zeroed descriptor with the magic + revision filled in — the starting
    /// point the CPU populates with the WPR2 layout before handing it to the
    /// Booter.
    pub fn new() -> Self {
        let mut m: Self = unsafe { core::mem::zeroed() };
        m.magic = GSP_FW_WPR_META_MAGIC;
        m.revision = GSP_FW_WPR_META_REVISION;
        m
    }
}

impl Default for GspFwWprMeta {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile-time check: the descriptor must be exactly 256 bytes to match the ABI.
const _: () = assert!(core::mem::size_of::<GspFwWprMeta>() == 256);

/// GSP page geometry (`GSP_PAGE_SHIFT`=12): 4 KiB pages, 8-byte PTEs, 512/page.
const GSP_PAGE_SIZE: usize = 4096;
const PTES_PER_PAGE: usize = GSP_PAGE_SIZE / 8;

/// The radix3 page-table DMA buffers, kept alive for the life of the system so
/// the GSP can DMA-walk them. (lvl0, lvl1, lvl2-contiguous).
static RADIX3: Once<(DmaCoherent, DmaCoherent, DmaCoherent)> = Once::new();

/// A built radix3 page table over the staged firmware (**P1.5b**).
#[derive(Debug, Clone, Copy)]
pub struct Radix3 {
    /// Guest-physical address of the level-0 root page — goes into
    /// `GspFwWprMeta.sysmem_addr_of_radix3_elf`.
    pub root_daddr: usize,
    /// Number of firmware 4 KiB pages mapped.
    pub fw_pages: usize,
    /// Number of level-2 pages used.
    pub l2_pages: usize,
    /// Read-back verification: L0[0]==L1 pa, L1[0]==L2 pa, L2[0]==fw base.
    pub verified: bool,
}

/// Build the 3-level radix page table the GSP Booter walks to reconstruct the
/// firmware ELF from sysmem, per nouveau `nvkm_gsp_radix3_sg`. The staged
/// firmware is one contiguous DMA buffer, so level-2 PTE `j` = `fw_daddr +
/// j*4096` and the level-2 pages are themselves contiguous. All PTEs are bare
/// 8-byte little-endian guest-physical addresses. **P1.5b**, pure Rust.
pub fn build_radix3(fw_daddr: usize, fw_size: usize) -> Option<Radix3> {
    let fw_pages = fw_size.div_ceil(GSP_PAGE_SIZE);
    let l2_pages = fw_pages.div_ceil(PTES_PER_PAGE);

    let lvl0 = DmaCoherent::alloc(1, true).ok()?;
    let lvl1 = DmaCoherent::alloc(1, true).ok()?;
    let lvl2 = DmaCoherent::alloc(l2_pages, true).ok()?;

    // Level 2: PTE j -> firmware page j (contiguous fw buffer).
    for j in 0..fw_pages {
        let pte = (fw_daddr + j * GSP_PAGE_SIZE) as u64;
        lvl2.write_bytes(j * 8, &pte.to_le_bytes()).ok()?;
    }
    // Level 1: PTE m -> level-2 page m (contiguous lvl2 buffer).
    let lvl2_base = lvl2.daddr();
    for m in 0..l2_pages {
        let pte = (lvl2_base + m * GSP_PAGE_SIZE) as u64;
        lvl1.write_bytes(m * 8, &pte.to_le_bytes()).ok()?;
    }
    // Level 0: PTE 0 -> level-1 page.
    lvl0.write_bytes(0, &(lvl1.daddr() as u64).to_le_bytes()).ok()?;

    // Verify by read-back: walk L0[0] -> L1[0] -> L2[0].
    let rd = |dma: &DmaCoherent, off: usize| -> Option<u64> {
        let mut b = [0u8; 8];
        dma.read_bytes(off, &mut b).ok()?;
        Some(u64::from_le_bytes(b))
    };
    let verified = rd(&lvl0, 0)? == lvl1.daddr() as u64
        && rd(&lvl1, 0)? == lvl2_base as u64
        && rd(&lvl2, 0)? == fw_daddr as u64;

    let root_daddr = lvl0.daddr();
    RADIX3.call_once(|| (lvl0, lvl1, lvl2));
    Some(Radix3 {
        root_daddr,
        fw_pages,
        l2_pages,
        verified,
    })
}
