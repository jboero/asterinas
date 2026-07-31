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

/// The WPR-relevant fields of `RM_RISCV_UCODE_DESC` (the 84-byte descriptor
/// shipped with the GSP bootloader, `gsprmboot.desc`), decoded from its
/// little-endian `u32` array (`rmRiscvUcode.h`; this build is version 5).
#[derive(Debug, Clone, Copy, Default)]
pub struct RiscvUcodeDesc {
    pub app_version: u32,
    pub manifest_offset: u32,
    pub monitor_data_offset: u32,
    pub monitor_code_offset: u32,
}

impl RiscvUcodeDesc {
    /// Decode from the raw 84-byte descriptor. Field indices per `RM_RISCV_UCODE_DESC`:
    /// `appVersion`=7, `manifestOffset`=8, `monitorDataOffset`=10, `monitorCodeOffset`=12.
    pub fn parse(desc: &[u8]) -> Option<Self> {
        let u = |i: usize| -> Option<u32> {
            let o = i * 4;
            Some(u32::from_le_bytes(desc.get(o..o + 4)?.try_into().ok()?))
        };
        Some(Self {
            app_version: u(7)?,
            manifest_offset: u(8)?,
            monitor_data_offset: u(10)?,
            monitor_code_offset: u(12)?,
        })
    }
}

// --- WPR2 / GSP-FW-heap layout constants (gsp_init_args.h, gsp_fw_heap.h) ---
const MB: u64 = 1 << 20;
/// `WPR_ALIGNMENT = RM_PAGE_SIZE_128K`.
const WPR_ALIGNMENT: u64 = 0x20000;
/// `kgspGetFrtsSize_TU102` = 1 MB.
const FRTS_SIZE: u64 = MB;
/// `DRF_SIZE(NV_PRAMIN)` = 1 MB (top-of-FB VGA/PRAMIN workspace).
const NV_PRAMIN_SIZE: u64 = MB;
/// `GSP_FW_HEAP_PARAM_OS_SIZE_LIBOS3_BAREMETAL` (22 MB).
const OS_CARVEOUT_LIBOS3_BAREMETAL: u64 = 22 * MB;
/// `GSP_FW_HEAP_PARAM_BASE_RM_SIZE_TU10X` (8 MB, Turing..Ada).
const BASE_RM_SIZE_TU10X: u64 = 8 * MB;
/// `GSP_FW_HEAP_PARAM_SIZE_PER_GB` (96 KB per GB of FB).
const HEAP_PARAM_SIZE_PER_GB: u64 = 96 << 10;
/// `GSP_FW_HEAP_PARAM_CLIENT_ALLOC_SIZE` (48 KB × 2048 channels).
const CLIENT_ALLOC_SIZE: u64 = (48 << 10) * 2048;
/// Non-WPR heap estimate — refine against the Booter's MAILBOX0 on hardware.
const NON_WPR_HEAP_SIZE: u64 = MB;

const fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}
const fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

impl GspFwWprMeta {
    /// Populate the full WPR2 FB layout the SEC2 Booter reads, computed top-down
    /// from the usable FB size — a Rust transcription of
    /// `kgspPopulateWprMeta_TU102`. **P1.5c.**
    ///
    /// Simplifying assumptions for the headless-passthrough compute case (each
    /// verified/refined against the Booter's `MAILBOX0` error code on hardware):
    /// no display VGA-workspace base and no VBIOS MMU-lock (so
    /// `vbiosReservedOffset == vgaWorkspaceOffset`), and `wprEndMargin == 0`
    /// (registry default on the first populate).
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        fb_size: u64,
        radix3_root: u64,
        radix3_size: u64,
        bootloader_daddr: u64,
        bootloader_size: u64,
        desc: &RiscvUcodeDesc,
        mmu_lock_lo: Option<u64>,
    ) -> Self {
        let mem_gb = align_up(fb_size, 1 << 30) >> 30;
        let fw_heap_size = OS_CARVEOUT_LIBOS3_BAREMETAL
            + BASE_RM_SIZE_TU10X
            + align_up(HEAP_PARAM_SIZE_PER_GB * mem_gb, MB)
            + align_up(CLIENT_ALLOC_SIZE, MB);
        let wpr_meta_sz = align_up(core::mem::size_of::<Self>() as u64, MB); // -> 1 MB
        let non_wpr_heap = align_up(NON_WPR_HEAP_SIZE, MB);

        let mut m = Self::new();
        m.fb_size = fb_size;
        m.vga_workspace_offset = fb_size - NV_PRAMIN_SIZE;
        m.vga_workspace_size = fb_size - m.vga_workspace_offset;
        // The WPR2 end must stay below any VBIOS MMU-locked region.
        let vbios_reserved = match mmu_lock_lo {
            Some(lo) => lo.min(m.vga_workspace_offset),
            None => m.vga_workspace_offset,
        };

        m.size_of_radix3_elf = radix3_size;
        m.gsp_fw_wpr_end = align_down(vbios_reserved, WPR_ALIGNMENT); // - wprEndMargin(0)
        m.frts_size = FRTS_SIZE;
        m.frts_offset = m.gsp_fw_wpr_end - m.frts_size;
        m.size_of_bootloader = bootloader_size;
        m.boot_bin_offset = align_down(m.frts_offset - m.size_of_bootloader, 0x1000);
        m.gsp_fw_offset = align_down(m.boot_bin_offset - m.size_of_radix3_elf, 0x10000);

        m.gsp_fw_heap_offset = align_down(m.gsp_fw_offset - fw_heap_size, MB);
        m.gsp_fw_heap_size = align_down(m.gsp_fw_offset - m.gsp_fw_heap_offset, MB);
        m.gsp_fw_wpr_start = m.gsp_fw_heap_offset - wpr_meta_sz;
        m.non_wpr_heap_size = non_wpr_heap;
        m.non_wpr_heap_offset = m.gsp_fw_wpr_start - m.non_wpr_heap_size;
        m.gsp_fw_rsvd_start = m.non_wpr_heap_offset;

        m.sysmem_addr_of_radix3_elf = radix3_root;
        m.sysmem_addr_of_bootloader = bootloader_daddr;
        m.bootloader_code_offset = desc.monitor_code_offset as u64;
        m.bootloader_data_offset = desc.monitor_data_offset as u64;
        m.bootloader_manifest_offset = desc.manifest_offset as u64;
        m.boot_count = 0;
        m.verified = 0;
        m
    }

    /// The raw 256 bytes of this descriptor, for DMA-staging to the Booter.
    pub fn as_bytes(&self) -> &[u8] {
        // Safety: `GspFwWprMeta` is `#[repr(C)]`, 256 bytes, all-POD fields.
        unsafe {
            core::slice::from_raw_parts(self as *const Self as *const u8, core::mem::size_of::<Self>())
        }
    }
}
