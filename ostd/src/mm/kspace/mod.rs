// SPDX-License-Identifier: MPL-2.0

//! Kernel memory space management.
//!
//! The kernel memory space is currently managed as follows, if the
//! address width is 48 bits (with 47 bits kernel space).
//!
//! TODO: the cap of linear mapping (the start of vm alloc) are raised
//! to workaround for high IO in TDX. We need actual vm alloc API to have
//! a proper fix.
//!
//! ```text
//! +-+ <- the highest used address (0xffff_ffff_ffff_0000)
//! | |         For the kernel code, 1 GiB.
//! +-+ <- 0xffff_ffff_8000_0000
//! | |
//! | |         Unused hole.
//! +-+ <- 0xffff_e100_0000_0000
//! | |         For frame metadata, 1 TiB.
//! +-+ <- 0xffff_e000_0000_0000
//! | |         For [`KVirtArea`], 32 TiB.
//! +-+ <- the middle of the higher half (0xffff_c000_0000_0000)
//! | |
//! | |
//! | |
//! | |         For linear mappings, 64 TiB.
//! | |         Mapped physical addresses are untracked.
//! | |
//! | |
//! | |
//! +-+ <- the base of high canonical address (0xffff_8000_0000_0000)
//! ```
//!
//! If the address width is (according to [`crate::arch::mm::PagingConsts`])
//! 39 bits or 57 bits, the memory space just adjust proportionally.

#![cfg_attr(target_arch = "loongarch64", expect(unused_imports))]

pub(crate) mod kvirt_area;

use core::ops::Range;

use spin::Once;

#[cfg(ktest)]
mod test;

use super::{
    Frame, HasSize, Paddr, PagingConstsTrait, Vaddr,
    frame::{
        Segment,
        meta::{AnyFrameMeta, MetaPageMeta, mapping},
    },
    page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    page_table::{PageTable, PageTableConfig},
};
use crate::{
    arch::mm::{PageTableEntry, PagingConsts},
    boot::memory_region::MemoryRegionType,
    const_assert, info,
    mm::{HasPaddr, PAGE_SIZE, PagingLevel, frame::FrameRef, page_table::largest_pages},
    task::disable_preempt,
};

// The shortest supported address width is 39 bits. So the literal
// values are written for 39 bits address width and we adjust the values
// by arithmetic left shift.
//
// ARMv7-A (`target_arch = "arm"`) is the exception: it has a 32-bit virtual
// address space, so it defines its own explicit 32-bit layout below rather than
// sharing the 39-bit-derived one. See the `arm` blocks throughout this module.
#[cfg(not(target_arch = "arm"))]
const_assert!(PagingConsts::ADDRESS_WIDTH >= 39);
#[cfg(not(target_arch = "arm"))]
const ADDR_WIDTH_SHIFT: usize = PagingConsts::ADDRESS_WIDTH - 39;

/// Start of the kernel address space.
#[cfg(not(any(target_arch = "loongarch64", target_arch = "arm")))]
pub const KERNEL_BASE_VADDR: Vaddr = 0xffff_ffc0_0000_0000 << ADDR_WIDTH_SHIFT;
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_BASE_VADDR: Vaddr = 0x9000_0000_0000_0000;
// ARMv7-A: a 2 GiB/2 GiB user/kernel split. The kernel half begins on the 1 GiB
// LPAE root-index boundary (index 2), which keeps user and kernel in disjoint
// top-level table entries.
#[cfg(target_arch = "arm")]
pub const KERNEL_BASE_VADDR: Vaddr = 0x8000_0000;
/// End of the kernel address space (non inclusive).
#[cfg(not(target_arch = "arm"))]
pub const KERNEL_END_VADDR: Vaddr = 0xffff_ffff_ffff_0000;
#[cfg(target_arch = "arm")]
pub const KERNEL_END_VADDR: Vaddr = 0xffff_0000;

/// The maximum virtual address of user space (non inclusive).
///
/// A typical way to reserve half of the address space for the kernel is
/// to use the highest `ADDRESS_WIDTH`-bit virtual address space.
///
/// Also, the top page is not regarded as usable since it's a workaround
/// for some x86_64 CPUs' bugs. See
/// <https://github.com/torvalds/linux/blob/480e035fc4c714fb5536e64ab9db04fedc89e910/arch/x86/include/asm/page_64.h#L68-L78>
/// for the rationale.
#[cfg(not(target_arch = "arm"))]
pub const MAX_USERSPACE_VADDR: Vaddr = (0x0000_0040_0000_0000 << ADDR_WIDTH_SHIFT) - PAGE_SIZE;
// ARMv7-A: user space is the low 2 GiB (translated through `TTBR0`).
#[cfg(target_arch = "arm")]
pub const MAX_USERSPACE_VADDR: Vaddr = 0x8000_0000 - PAGE_SIZE;

/// The kernel address space.
///
/// They are the high canonical addresses (i.e., the negative part of the
/// address space, with the most significant bits in the addresses set).
pub const KERNEL_VADDR_RANGE: Range<Vaddr> = KERNEL_BASE_VADDR..KERNEL_END_VADDR;

/// The kernel code is linear mapped to this address.
///
/// FIXME: This offset should be randomly chosen by the loader or the
/// boot compatibility layer. But we disabled it because OSTD
/// doesn't support relocatable kernel yet.
pub fn kernel_loaded_offset() -> usize {
    KERNEL_CODE_BASE_VADDR
}

#[cfg(target_arch = "x86_64")]
const KERNEL_CODE_BASE_VADDR: usize = 0xffff_ffff_8000_0000;
#[cfg(target_arch = "riscv64")]
const KERNEL_CODE_BASE_VADDR: usize = 0xffff_ffff_0000_0000;
#[cfg(target_arch = "loongarch64")]
const KERNEL_CODE_BASE_VADDR: usize = 0x9000_0000_0000_0000;
#[cfg(target_arch = "aarch64")]
const KERNEL_CODE_BASE_VADDR: usize = 0xffff_ffff_0000_0000;
// ARMv7-A: the kernel image runs inside the linear mapping, so its code base is
// the linear-mapping offset. Phys 0x4020_0000 maps to virt 0xC020_0000.
#[cfg(target_arch = "arm")]
const KERNEL_CODE_BASE_VADDR: usize = 0x8000_0000;

#[cfg(not(target_arch = "arm"))]
const FRAME_METADATA_CAP_VADDR: Vaddr = 0xffff_fff0_8000_0000 << ADDR_WIDTH_SHIFT;
#[cfg(not(target_arch = "arm"))]
const FRAME_METADATA_BASE_VADDR: Vaddr = 0xffff_fff0_0000_0000 << ADDR_WIDTH_SHIFT;
// ARMv7-A 32-bit kernel layout (all within 0x8000_0000..=0xFFFF_FFFF):
//   linear map      0x8000_0000 .. 0xE000_0000  (phys 0 .. 0x6000_0000)
//   vmalloc/ioremap 0xE000_0000 .. 0xF800_0000
//   frame metadata  0xF800_0000 .. 0xFE00_0000
#[cfg(target_arch = "arm")]
const FRAME_METADATA_CAP_VADDR: Vaddr = 0xFE00_0000;
#[cfg(target_arch = "arm")]
const FRAME_METADATA_BASE_VADDR: Vaddr = 0xF800_0000;
pub(in crate::mm) const FRAME_METADATA_RANGE: Range<Vaddr> =
    FRAME_METADATA_BASE_VADDR..FRAME_METADATA_CAP_VADDR;

#[cfg(not(target_arch = "arm"))]
const VMALLOC_BASE_VADDR: Vaddr = 0xffff_ffe0_0000_0000 << ADDR_WIDTH_SHIFT;
#[cfg(target_arch = "arm")]
const VMALLOC_BASE_VADDR: Vaddr = 0xE000_0000;
pub const VMALLOC_VADDR_RANGE: Range<Vaddr> = VMALLOC_BASE_VADDR..FRAME_METADATA_BASE_VADDR;

/// The base address of the linear mapping of all physical
/// memory in the kernel address space.
#[cfg(not(any(target_arch = "loongarch64", target_arch = "arm")))]
pub const LINEAR_MAPPING_BASE_VADDR: Vaddr = 0xffff_ffc0_0000_0000 << ADDR_WIDTH_SHIFT;
#[cfg(target_arch = "loongarch64")]
pub const LINEAR_MAPPING_BASE_VADDR: Vaddr = 0x9000_0000_0000_0000;
// ARMv7-A: the linear map begins at physical address 0, offset into the kernel
// half. So `paddr_to_vaddr(pa) = pa + 0x8000_0000`, exactly as on the 64-bit
// arches (offset equals range start), and MMIO (e.g. the PL011 at 0x0900_0000)
// is reachable through it just like RAM.
#[cfg(target_arch = "arm")]
pub const LINEAR_MAPPING_BASE_VADDR: Vaddr = 0x8000_0000;
pub const LINEAR_MAPPING_VADDR_RANGE: Range<Vaddr> = LINEAR_MAPPING_BASE_VADDR..VMALLOC_BASE_VADDR;

/// Convert physical address to virtual address using offset, only available inside `ostd`
pub fn paddr_to_vaddr(pa: Paddr) -> usize {
    debug_assert!(pa < VMALLOC_BASE_VADDR - LINEAR_MAPPING_BASE_VADDR);
    pa + LINEAR_MAPPING_BASE_VADDR
}

/// The kernel page table instance.
///
/// It manages the kernel mapping of all address spaces by sharing the kernel part. And it
/// is unlikely to be activated.
pub(super) static KERNEL_PAGE_TABLE: Once<PageTable<KernelPtConfig>> = Once::new();

#[derive(Clone, Debug)]
pub(super) struct KernelPtConfig {}

// We use the first available PTE bit to mark the frame as tracked.
// SAFETY: `item_raw_info`, `item_into_raw`, `item_from_raw`, and
// `item_ref_from_raw` are correctly implemented with respect to the `Item` and
// `ItemRef` types.
unsafe impl PageTableConfig for KernelPtConfig {
    // On 64-bit arches the 512-entry root splits 256/256 (user/kernel). On
    // ARMv7-A LPAE the root (level 3) has only 4 populated entries, each mapping
    // 1 GiB; the kernel half (0x8000_0000..=0xFFFF_FFFF) is entries 2 and 3.
    #[cfg(not(target_arch = "arm"))]
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 256..512;
    #[cfg(target_arch = "arm")]
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 2..4;
    const TOP_LEVEL_CAN_UNMAP: bool = false;

    type E = PageTableEntry;
    type C = PagingConsts;

    type Item = MappedItem;
    type ItemRef<'a> = MappedItemRef<'a>;

    fn item_raw_info(item: &Self::Item) -> (Paddr, PagingLevel, PageProperty) {
        match *item {
            MappedItem::Tracked(ref frame, mut prop) => {
                debug_assert!(!prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1));
                prop.priv_flags |= PrivilegedPageFlags::AVAIL1;
                let level = frame.map_level();
                let paddr = frame.paddr();
                (paddr, level, prop)
            }
            MappedItem::Untracked(ref pa, ref level, mut prop) => {
                debug_assert!(!prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1));
                prop.priv_flags -= PrivilegedPageFlags::AVAIL1;
                (*pa, *level, prop)
            }
        }
    }

    unsafe fn item_from_raw(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self::Item {
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            debug_assert_eq!(level, 1);
            // SAFETY: The caller ensures safety.
            let frame = unsafe { Frame::<dyn AnyFrameMeta>::from_raw(paddr) };
            MappedItem::Tracked(frame, prop)
        } else {
            MappedItem::Untracked(paddr, level, prop)
        }
    }

    unsafe fn item_ref_from_raw<'a>(
        paddr: Paddr,
        level: PagingLevel,
        prop: PageProperty,
    ) -> Self::ItemRef<'a> {
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            debug_assert_eq!(level, 1);
            // SAFETY: The caller ensures that the frame outlives `'a` and that
            // the type matches the frame.
            let frame = unsafe { FrameRef::<dyn AnyFrameMeta>::borrow_paddr(paddr) };
            MappedItemRef::Tracked(frame, prop)
        } else {
            MappedItemRef::Untracked(paddr, level, prop)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MappedItem {
    Tracked(Frame<dyn AnyFrameMeta>, PageProperty),
    Untracked(Paddr, PagingLevel, PageProperty),
}

#[derive(Debug)]
pub(crate) enum MappedItemRef<'a> {
    #[cfg_attr(not(ktest), expect(dead_code))]
    Tracked(FrameRef<'a, dyn AnyFrameMeta>, PageProperty),
    #[cfg_attr(not(ktest), expect(dead_code))]
    Untracked(Paddr, PagingLevel, PageProperty),
}

/// Initializes the kernel page table.
///
/// This function should be called after:
///  - the page allocator and the heap allocator are initialized;
///  - the memory regions are initialized.
///
/// This function should be called before:
///  - any initializer that modifies the kernel page table.
pub fn init_kernel_page_table(meta_pages: Segment<MetaPageMeta>) {
    info!("Initializing the kernel page table");

    // Start to initialize the kernel page table.
    let kpt = PageTable::<KernelPtConfig>::new_kernel_page_table();
    let preempt_guard = disable_preempt();

    // In LoongArch64, we don't need to do linear mappings for the kernel because of DMW0.
    #[cfg(not(target_arch = "loongarch64"))]
    // Do linear mappings for the kernel.
    {
        let max_paddr = crate::mm::frame::max_paddr();
        let from = LINEAR_MAPPING_BASE_VADDR..LINEAR_MAPPING_BASE_VADDR + max_paddr;
        // On ARMv7 the kernel image executes inside the linear mapping (its code
        // base coincides with the linear-map base), so the linear mapping must be
        // executable and the separate kernel-code mapping below is skipped. Other
        // arches keep the linear mapping non-executable (W^X).
        #[cfg(not(target_arch = "arm"))]
        let flags = PageFlags::RW;
        #[cfg(target_arch = "arm")]
        let flags = PageFlags::RWX;

        let mut cursor = kpt.cursor_mut(&preempt_guard, &from).unwrap();
        for (pa, level) in largest_pages::<KernelPtConfig>(from.start, 0, max_paddr) {
            // On ARMv7 the linear map also covers the low physical MMIO window
            // (the PL011 UART, GIC, etc. below the RAM base at 0x4000_0000);
            // those pages must be Device (uncacheable), not Normal Writeback,
            // or device accesses through the linear map after the switch are
            // silently cached. RAM stays Writeback.
            #[cfg(target_arch = "arm")]
            let cache = if pa < 0x4000_0000 {
                CachePolicy::Uncacheable
            } else {
                CachePolicy::Writeback
            };
            #[cfg(not(target_arch = "arm"))]
            let cache = CachePolicy::Writeback;

            let prop = PageProperty {
                flags,
                cache,
                priv_flags: PrivilegedPageFlags::GLOBAL,
            };
            // SAFETY: we are doing the linear mapping for the kernel.
            unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
        }
    }

    // Map the metadata pages.
    {
        let start_va = mapping::frame_to_meta::<PagingConsts>(0);
        let from = start_va..start_va + meta_pages.size();
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let mut cursor = kpt.cursor_mut(&preempt_guard, &from).unwrap();
        // We use untracked mapping so that we can benefit from huge pages.
        // We won't unmap them anyway, so there's no leaking problem yet.
        // TODO: support tracked huge page mapping.
        let pa_range = meta_pages.into_raw();
        for (pa, level) in
            largest_pages::<KernelPtConfig>(from.start, pa_range.start, pa_range.len())
        {
            // SAFETY: We are doing the metadata mappings for the kernel.
            unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
        }
    }

    // In LoongArch64, we don't need to do linear mappings for the kernel code
    // because of DMW0. On ARMv7 the kernel code is already covered (executably)
    // by the linear mapping above, so a separate mapping would double-map it.
    #[cfg(not(any(target_arch = "loongarch64", target_arch = "arm")))]
    // Map for the kernel code itself.
    // TODO: set separated permissions for each segments in the kernel.
    {
        let regions = &crate::boot::EARLY_INFO.get().unwrap().memory_regions;
        let region = regions
            .iter()
            .find(|r| r.typ() == MemoryRegionType::Kernel)
            .unwrap();
        let offset = kernel_loaded_offset();
        let from = region.base() + offset..region.end() + offset;
        let prop = PageProperty {
            flags: PageFlags::RWX,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let mut cursor = kpt.cursor_mut(&preempt_guard, &from).unwrap();
        for (pa, level) in largest_pages::<KernelPtConfig>(from.start, region.base(), from.len()) {
            // SAFETY: we are doing the kernel code mapping.
            unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
        }
    }

    KERNEL_PAGE_TABLE.call_once(|| kpt);
}

/// Activates the kernel page table.
///
/// All address translation of symbols in the boot sections must be manually
/// done from now on.
///
/// # Safety
///
/// This function must only be called once per CPU.
pub unsafe fn activate_kernel_page_table() {
    let kpt = KERNEL_PAGE_TABLE
        .get()
        .expect("The kernel page table is not initialized yet");
    // SAFETY: the kernel page table is initialized properly.
    unsafe {
        kpt.first_activate_unchecked();
        crate::arch::mm::tlb_flush_all_including_global();
    }
}
