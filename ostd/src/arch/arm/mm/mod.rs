// SPDX-License-Identifier: MPL-2.0

//! Page table entry and memory management for ARMv7-A with the Large Physical
//! Address Extension (LPAE): 4 KiB granule, 3-level long-descriptor tables, a
//! 32-bit virtual address space and up to 40-bit physical addresses.
//!
//! The LPAE long-descriptor format is deliberately close to AArch64's
//! VMSAv8-64 stage-1 descriptors, so this mirrors `arch::aarch64::mm`. The two
//! salient differences are:
//!  - descriptors are 64-bit even though the pointer/`usize` width is 32-bit, so
//!    [`PageTableEntry`] wraps a [`u64`] and sets `PteTrait::Repr = u64`; and
//!  - system registers are accessed through the CP15 coprocessor
//!    (`mcr`/`mrc`/`mcrr`/`mrrc`) rather than AArch64 `msr`/`mrs`.

use core::ops::Range;

pub(crate) use util::{
    __atomic_cmpxchg_fallible, __atomic_load_fallible, __memcpy_fallible, __memset_fallible,
};

use crate::mm::{
    PAGE_SIZE, Paddr, PagingConstsTrait, PagingLevel, PodOnce, Vaddr,
    dma::DmaDirection,
    page_prop::{
        CachePolicy, PageFlags, PageProperty, PageTableFlags, PrivilegedPageFlags as PrivFlags,
    },
    page_table::{PteScalar, PteTrait},
};

mod util;

#[derive(Clone, Debug, Default)]
pub(crate) struct PagingConsts {}

impl PagingConstsTrait for PagingConsts {
    const BASE_PAGE_SIZE: usize = 4096;
    // LPAE with a 32-bit VA is a 3-level walk: level 3 (Asterinas root) is the
    // LPAE level 1 (only 4 entries used, 1 GiB each), level 2 is LPAE level 2
    // (2 MiB blocks) and level 1 is LPAE level 3 (4 KiB pages).
    const NR_LEVELS: PagingLevel = 3;
    const ADDRESS_WIDTH: usize = 32;
    const VA_SIGN_EXT: bool = false;
    // Allow 4 KiB pages (level 1) and 2 MiB blocks (level 2). We do not use
    // 1 GiB blocks at the root level.
    const HIGHEST_TRANSLATION_LEVEL: PagingLevel = 2;
    const PTE_SIZE: usize = size_of::<PageTableEntry>();
}

/// The MAIR attribute index for Normal write-back memory.
const MAIR_IDX_NORMAL: u64 = 0;
/// The MAIR attribute index for Device-nGnRnE memory.
const MAIR_IDX_DEVICE: u64 = 1;

// Long-descriptor bit positions (LPAE stage-1, 4 KiB granule). These match the
// AArch64 stage-1 layout.
const PTE_VALID: u64 = 1 << 0;
/// At levels 1-2: 1 = table, 0 = block. At level 3 (page): must be 1.
const PTE_TABLE_OR_PAGE: u64 = 1 << 1;
const PTE_ATTR_INDX_SHIFT: u64 = 2;
const PTE_AP_EL0: u64 = 1 << 6; // AP[1]: allow unprivileged (PL0) access
const PTE_AP_RO: u64 = 1 << 7; // AP[2]: read-only
const PTE_SH_INNER: u64 = 0b11 << 8;
const PTE_AF: u64 = 1 << 10; // access flag
const PTE_NG: u64 = 1 << 11; // not global
const PTE_PXN: u64 = 1 << 53; // privileged execute never
const PTE_UXN: u64 = 1 << 54; // unprivileged execute never
// Software-reserved bits [58:55] used to carry Asterinas metadata.
const PTE_SW_DIRTY: u64 = 1 << 55;
const PTE_SW_PG_AVAIL1: u64 = 1 << 56;
const PTE_SW_PG_AVAIL2: u64 = 1 << 57;
const PTE_SW_PRIV_AVAIL1: u64 = 1 << 58;

/// Output-address mask: LPAE physical addresses are up to 40 bits.
const PTE_ADDR_MASK: u64 = 0x0000_00ff_ffff_f000;

fn tlbi_barrier_before() {
    // SAFETY: A data-synchronization barrier has no memory-safety implications.
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
}

fn tlbi_barrier_after() {
    // SAFETY: Barriers have no memory-safety implications.
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
}

pub(crate) fn tlb_flush_addr(vaddr: Vaddr) {
    tlbi_barrier_before();
    // TLBIMVAAIS: invalidate unified TLB by MVA, all ASIDs, inner-shareable
    // (`mcr p15, 0, Rt, c8, c3, 3`). The MVA is the page-aligned virtual address.
    // SAFETY: Invalidating the TLB is always safe.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {}, c8, c3, 3",
            in(reg) vaddr & !0xfff,
            options(nostack, preserves_flags),
        )
    };
    tlbi_barrier_after();
}

pub(crate) fn tlb_flush_addr_range(range: &Range<Vaddr>) {
    for vaddr in range.clone().step_by(PAGE_SIZE) {
        tlb_flush_addr(vaddr);
    }
}

pub(crate) fn tlb_flush_all_excluding_global() {
    tlbi_barrier_before();
    // TLBIALLIS: invalidate entire unified TLB, inner-shareable.
    // SAFETY: Invalidating the TLB is always safe.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {}, c8, c3, 0",
            in(reg) 0usize,
            options(nostack, preserves_flags),
        )
    };
    tlbi_barrier_after();
}

pub(crate) fn tlb_flush_all_including_global() {
    tlb_flush_all_excluding_global();
}

pub(crate) fn can_sync_dma() -> bool {
    // QEMU `virt` presents coherent DMA; cache maintenance is a no-op for now.
    false
}

/// # Safety
///
/// The caller must ensure that the virtual address range and DMA direction
/// correspond correctly to a DMA region and that `can_sync_dma()` is `true`.
pub(crate) unsafe fn sync_dma_range<D: DmaDirection>(_range: Range<Vaddr>) {
    // TODO: Implement cache maintenance for non-coherent DMA. Currently
    // unreachable because `can_sync_dma()` returns `false`.
    unreachable!("cache maintenance for non-coherent DMA is not implemented");
}

/// Activates the given root-level page table.
///
/// LPAE splits translation between `TTBR0` (low VA) and `TTBR1` (high VA) via
/// `TTBCR`. Asterinas maintains a single root whose low entries describe user
/// space and whose high entries describe kernel space, so we configure `TTBCR`
/// with `T0SZ = 0` at boot (making `TTBR0` cover the entire 4 GiB) and point
/// `TTBR0` at the single root; `TTBR1` is unused.
///
/// # Safety
///
/// Changing the root-level page table can violate memory safety by changing the
/// page mapping.
pub(crate) unsafe fn activate_page_table(root_paddr: Paddr, _root_pt_cache: CachePolicy) {
    assert!(root_paddr.is_multiple_of(PagingConsts::BASE_PAGE_SIZE));

    // SAFETY: The caller guarantees that `root_paddr` refers to a valid root
    // page table describing a memory-safe address space. `mcrr ... c2` writes
    // the 64-bit `TTBR0`; the high half is zero since our PAs are below 4 GiB.
    unsafe {
        core::arch::asm!(
            "mcrr p15, 0, {root}, {zero}, c2", // TTBR0 = root_paddr
            "dsb ish",
            "mcr p15, 0, {zero}, c8, c3, 0",   // TLBIALLIS
            "dsb ish",
            "isb",
            root = in(reg) root_paddr,
            zero = in(reg) 0usize,
            options(nostack, preserves_flags),
        )
    };
}

pub(crate) fn current_page_table_paddr() -> Paddr {
    let ttbr0_lo: usize;
    let _ttbr0_hi: usize;
    // SAFETY: Reading `TTBR0` has no side effects. `mrrc ... c2` reads the
    // 64-bit `TTBR0` into a register pair.
    unsafe {
        core::arch::asm!(
            "mrrc p15, 0, {lo}, {hi}, c2",
            lo = out(reg) ttbr0_lo,
            hi = out(reg) _ttbr0_hi,
            options(nostack, nomem),
        )
    };
    ttbr0_lo & (PTE_ADDR_MASK as usize)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct PageTableEntry(u64);

impl PageTableEntry {
    fn paddr(&self) -> Paddr {
        (self.0 & PTE_ADDR_MASK) as Paddr
    }

    /// Whether this entry is a leaf (block/page) rather than a next-level table.
    fn is_last(&self, level: PagingLevel) -> bool {
        // Level 1 (LPAE L3): a valid entry is always a page.
        // Higher levels: bit 1 clear means a block (leaf); set means a table.
        level == 1 || (self.0 & PTE_TABLE_OR_PAGE) == 0
    }

    fn prop(&self) -> PageProperty {
        let raw = self.0;

        let is_user = (raw & PTE_AP_EL0) != 0;
        let writable = (raw & PTE_AP_RO) == 0;
        let executable = if is_user {
            (raw & PTE_UXN) == 0
        } else {
            (raw & PTE_PXN) == 0
        };

        let mut flags = PageFlags::R;
        if writable {
            flags |= PageFlags::W;
        }
        if executable {
            flags |= PageFlags::X;
        }
        if (raw & PTE_AF) != 0 {
            flags |= PageFlags::ACCESSED;
        }
        if (raw & PTE_SW_DIRTY) != 0 {
            flags |= PageFlags::DIRTY;
        }
        if (raw & PTE_SW_PG_AVAIL2) != 0 {
            flags |= PageFlags::AVAIL2;
        }

        let mut priv_flags = PrivFlags::empty();
        if is_user {
            priv_flags |= PrivFlags::USER;
        }
        if (raw & PTE_NG) == 0 {
            priv_flags |= PrivFlags::GLOBAL;
        }
        if (raw & PTE_SW_PRIV_AVAIL1) != 0 {
            priv_flags |= PrivFlags::AVAIL1;
        }

        let attr_indx = (raw >> PTE_ATTR_INDX_SHIFT) & 0b111;
        let cache = if attr_indx == MAIR_IDX_DEVICE {
            CachePolicy::Uncacheable
        } else {
            CachePolicy::Writeback
        };

        PageProperty {
            flags,
            cache,
            priv_flags,
        }
    }

    fn pt_flags(&self) -> PageTableFlags {
        let mut flags = PageTableFlags::empty();
        if (self.0 & PTE_SW_PG_AVAIL1) != 0 {
            flags |= PageTableFlags::AVAIL1;
        }
        if (self.0 & PTE_SW_PG_AVAIL2) != 0 {
            flags |= PageTableFlags::AVAIL2;
        }
        flags
    }

    fn new_page(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self {
        let mut raw = (paddr as u64 & PTE_ADDR_MASK) | PTE_VALID | PTE_AF;

        // Level 1 (LPAE L3) leaves are pages and must set bit 1; blocks at
        // higher levels leave it clear.
        if level == 1 {
            raw |= PTE_TABLE_OR_PAGE;
        }

        let is_user = prop.priv_flags.contains(PrivFlags::USER);
        let executable = prop.flags.contains(PageFlags::X);

        if !prop.flags.contains(PageFlags::W) {
            raw |= PTE_AP_RO;
        }
        if is_user {
            raw |= PTE_AP_EL0;
        }

        // Execute-never bits: forbid execution wherever it is not requested.
        if is_user {
            raw |= PTE_PXN; // never executable at PL1
            if !executable {
                raw |= PTE_UXN;
            }
        } else {
            raw |= PTE_UXN; // never executable at PL0
            if !executable {
                raw |= PTE_PXN;
            }
        }

        if !prop.priv_flags.contains(PrivFlags::GLOBAL) {
            raw |= PTE_NG;
        }
        if prop.flags.contains(PageFlags::DIRTY) {
            raw |= PTE_SW_DIRTY;
        }
        if prop.flags.contains(PageFlags::AVAIL2) {
            raw |= PTE_SW_PG_AVAIL2;
        }
        if prop.priv_flags.contains(PrivFlags::AVAIL1) {
            raw |= PTE_SW_PRIV_AVAIL1;
        }

        match prop.cache {
            CachePolicy::Writeback => {
                raw |= MAIR_IDX_NORMAL << PTE_ATTR_INDX_SHIFT;
                raw |= PTE_SH_INNER;
            }
            CachePolicy::Uncacheable => {
                raw |= MAIR_IDX_DEVICE << PTE_ATTR_INDX_SHIFT;
                // Shareability is ignored for Device memory.
            }
            _ => panic!("unsupported cache policy"),
        }

        Self(raw)
    }

    fn new_pt(paddr: Paddr, flags: PageTableFlags) -> Self {
        let mut raw = (paddr as u64 & PTE_ADDR_MASK) | PTE_VALID | PTE_TABLE_OR_PAGE;
        if flags.contains(PageTableFlags::AVAIL1) {
            raw |= PTE_SW_PG_AVAIL1;
        }
        if flags.contains(PageTableFlags::AVAIL2) {
            raw |= PTE_SW_PG_AVAIL2;
        }
        Self(raw)
    }
}

impl PodOnce for PageTableEntry {}

// SAFETY: The implementation is correct because:
//  - `from_raw`/`as_raw` are not overridden;
//  - `from_repr`/`to_repr` are inverse operations at a given level;
//  - a zeroed PTE (bit 0 clear) represents an absent entry.
unsafe impl PteTrait for PageTableEntry {
    // LPAE descriptors are 64-bit even though `usize` is 32-bit.
    type Repr = u64;

    fn from_repr(repr: &PteScalar, level: PagingLevel) -> Self {
        match repr {
            PteScalar::Absent => PageTableEntry(0),
            PteScalar::PageTable(paddr, flags) => Self::new_pt(*paddr, *flags),
            PteScalar::Mapped(paddr, prop) => Self::new_page(*paddr, level, *prop),
        }
    }

    fn to_repr(&self, level: PagingLevel) -> PteScalar {
        if self.0 & PTE_VALID == 0 {
            return PteScalar::Absent;
        }

        if self.is_last(level) {
            PteScalar::Mapped(self.paddr(), self.prop())
        } else {
            PteScalar::PageTable(self.paddr(), self.pt_flags())
        }
    }
}
