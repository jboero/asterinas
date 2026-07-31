// SPDX-License-Identifier: MPL-2.0

//! GSP firmware container parsing — **P1.4**.
//!
//! NVIDIA ships the GSP-RM firmware (`gsp_ga10x.bin`) as an **ELF64 relocatable,
//! RISC-V** object whose payload lives in named sections rather than PT_LOAD
//! segments (the file has zero program headers). The sections we care about:
//!   - `.fwimage`     — the GSP-RM code/data image (radix3-paged) to place in WPR2.
//!   - `.fwversion`   — an ASCII version string.
//!   - `.fwsignature*`— per-signing-key signatures (one is selected by fuse state).
//!
//! This module walks the section headers and locates those, entirely in Rust —
//! no vendored C. It only *parses* the (vendor, signed) blob; it does not and
//! cannot author it. Verified against a real `gsp_ga10x.bin` (driver 595.80).

use core::str;

/// A located section of the firmware container (byte range within the image).
#[derive(Debug, Clone, Copy)]
pub struct FwSection {
    /// Byte offset of the section's data within the firmware blob.
    pub offset: usize,
    /// Section data length in bytes.
    pub size: usize,
}

/// The parsed GSP firmware container.
#[derive(Debug, Clone, Copy, Default)]
pub struct FwContainer {
    /// Total blob length.
    pub total_len: usize,
    /// ELF `e_machine` (expect `0xf3` = RISC-V).
    pub machine: u16,
    /// Number of ELF sections.
    pub section_count: u16,
    /// `.fwimage` — the GSP-RM image to load into WPR2.
    pub image: Option<FwSection>,
    /// `.fwversion` — ASCII version string section.
    pub version: Option<FwSection>,
    /// Count of `.fwsignature*` sections found.
    pub signature_count: u16,
}

// --- minimal little-endian readers with bounds checks ---
fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

/// ELF64 section-header field offsets (relative to a 64-byte entry).
const SH_NAME: usize = 0x00; // u32 — index into shstrtab
const SH_OFFSET: usize = 0x18; // u64
const SH_SIZE: usize = 0x20; // u64
const SH_ENTSIZE: usize = 64; // size of one section header

/// Read a NUL-terminated name from the section-header string table.
fn sh_name<'a>(blob: &'a [u8], shstrtab_off: usize, name_idx: u32) -> Option<&'a str> {
    let start = shstrtab_off.checked_add(name_idx as usize)?;
    let rest = blob.get(start..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    str::from_utf8(&rest[..end]).ok()
}

/// Parse a GSP firmware ELF container, locating the `.fwimage`, `.fwversion`,
/// and `.fwsignature*` sections. Returns `None` if the blob is not a valid
/// ELF64 (bad magic/class or truncated headers).
pub fn parse(blob: &[u8]) -> Option<FwContainer> {
    // ELF magic + 64-bit class (EI_CLASS == 2).
    if blob.get(0..4)? != b"\x7fELF" || blob.get(4)? != &2 {
        return None;
    }
    let machine = rd_u16(blob, 0x12)?; // e_machine
    let e_shoff = rd_u64(blob, 0x28)? as usize; // section header table offset
    let e_shentsize = rd_u16(blob, 0x3a)? as usize;
    let e_shnum = rd_u16(blob, 0x3c)?;
    let e_shstrndx = rd_u16(blob, 0x3e)? as usize;
    if e_shentsize < SH_ENTSIZE || e_shnum == 0 {
        return None;
    }

    // The section-header string table gives us section names.
    let shstr_hdr = e_shoff.checked_add(e_shstrndx.checked_mul(e_shentsize)?)?;
    let shstrtab_off = rd_u64(blob, shstr_hdr.checked_add(SH_OFFSET)?)? as usize;

    let mut out = FwContainer {
        total_len: blob.len(),
        machine,
        section_count: e_shnum,
        ..Default::default()
    };

    for i in 0..e_shnum as usize {
        let hdr = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
        let name_idx = rd_u32(blob, hdr.checked_add(SH_NAME)?)?;
        let offset = rd_u64(blob, hdr.checked_add(SH_OFFSET)?)? as usize;
        let size = rd_u64(blob, hdr.checked_add(SH_SIZE)?)? as usize;
        let Some(name) = sh_name(blob, shstrtab_off, name_idx) else {
            continue;
        };
        let sec = FwSection { offset, size };
        match name {
            ".fwimage" => out.image = Some(sec),
            ".fwversion" => out.version = Some(sec),
            n if n.starts_with(".fwsignature") => {
                out.signature_count = out.signature_count.saturating_add(1)
            }
            _ => {}
        }
    }
    Some(out)
}

/// Locate a named section (e.g. `.fwsignature_ga10x`) in the firmware ELF
/// container and return its byte range. The GSP boot needs the chip-family
/// signature (`sysmem_addr_of_signature`) the Booter verifies.
pub fn find_section(blob: &[u8], want: &str) -> Option<FwSection> {
    if blob.get(0..4)? != b"\x7fELF" || blob.get(4)? != &2 {
        return None;
    }
    let e_shoff = rd_u64(blob, 0x28)? as usize;
    let e_shentsize = rd_u16(blob, 0x3a)? as usize;
    let e_shnum = rd_u16(blob, 0x3c)?;
    let e_shstrndx = rd_u16(blob, 0x3e)? as usize;
    if e_shentsize < SH_ENTSIZE || e_shnum == 0 {
        return None;
    }
    let shstr_hdr = e_shoff.checked_add(e_shstrndx.checked_mul(e_shentsize)?)?;
    let shstrtab_off = rd_u64(blob, shstr_hdr.checked_add(SH_OFFSET)?)? as usize;
    for i in 0..e_shnum as usize {
        let hdr = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
        let name_idx = rd_u32(blob, hdr.checked_add(SH_NAME)?)?;
        if sh_name(blob, shstrtab_off, name_idx) == Some(want) {
            return Some(FwSection {
                offset: rd_u64(blob, hdr.checked_add(SH_OFFSET)?)? as usize,
                size: rd_u64(blob, hdr.checked_add(SH_SIZE)?)? as usize,
            });
        }
    }
    None
}

impl FwContainer {
    /// The firmware version string, if the `.fwversion` section is present and
    /// valid ASCII.
    pub fn version_str<'a>(&self, blob: &'a [u8]) -> Option<&'a str> {
        let v = self.version?;
        let raw = blob.get(v.offset..v.offset.checked_add(v.size)?)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        str::from_utf8(&raw[..end]).ok().map(str::trim)
    }
}

/// The NVIDIA `.bin` container magic (`nvfw_bin_hdr.bin_magic`, little-endian
/// `0x10de` = the NVIDIA PCI vendor ID) used by the booter/bootloader ucode
/// blobs (`booter_load-*.bin`, `bootloader-*.bin`).
pub const NVFW_BIN_MAGIC: u32 = 0x10de;

/// A parsed NVIDIA HS (heavy-secured) ucode container — the `booter_load` /
/// `booter_unload` ACR ucode that runs on SEC2 to set up WPR2, and the RISC-V
/// `bootloader`. Layout: `nvfw_bin_hdr` then, at `header_offset`, an
/// `nvfw_hs_header_v2`; the actual ucode image is at `data_offset`. **P1.5c.**
#[derive(Debug, Clone, Copy)]
pub struct HsUcode {
    /// `bin_ver`.
    pub version: u32,
    /// Byte range of the ucode image (code+data) within the blob.
    pub data: FwSection,
    /// Byte range of the production signature within the blob.
    pub sig_prod: FwSection,
    /// Number of signatures (`num_sig`).
    pub num_sig: u32,
}

/// Parse an NVIDIA HS ucode `.bin` container (booter / bootloader). Verified
/// against real `booter_load-570.144.bin` (magic `0x10de`, ver 1).
pub fn parse_hs_ucode(blob: &[u8]) -> Option<HsUcode> {
    // nvfw_bin_hdr: bin_magic, bin_ver, bin_size, header_offset, data_offset, data_size
    if rd_u32(blob, 0x00)? != NVFW_BIN_MAGIC {
        return None;
    }
    let version = rd_u32(blob, 0x04)?;
    let header_offset = rd_u32(blob, 0x0c)? as usize;
    let data_offset = rd_u32(blob, 0x10)? as usize;
    let data_size = rd_u32(blob, 0x14)? as usize;

    // nvfw_hs_header_v2 at header_offset: sig_prod_offset, sig_prod_size,
    // patch_loc, patch_sig, meta_data_offset, meta_data_size, num_sig, ...
    let sig_prod_offset = rd_u32(blob, header_offset.checked_add(0x00)?)? as usize;
    let sig_prod_size = rd_u32(blob, header_offset.checked_add(0x04)?)? as usize;
    let num_sig = rd_u32(blob, header_offset.checked_add(0x18)?)?;

    Some(HsUcode {
        version,
        data: FwSection {
            offset: data_offset,
            size: data_size,
        },
        sig_prod: FwSection {
            offset: sig_prod_offset,
            size: sig_prod_size,
        },
        num_sig,
    })
}
