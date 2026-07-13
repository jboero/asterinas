// SPDX-License-Identifier: MPL-2.0

//! GPU chip identification from `NV_PMC_BOOT_0`.
//!
//! `NV_PMC_BOOT_0` is the register at BAR0 offset 0 that every NVIDIA GPU
//! answers with its architecture / implementation / revision. The RM reads it
//! first to identify the chip. Field layout and architecture codes are taken
//! verbatim from `nvidia-open`'s `src/common/inc/swref/published/nv_ref.h`:
//!
//! ```text
//! MINOR_REVISION   3:0
//! MAJOR_REVISION   7:4
//! ARCHITECTURE_1   8:8      (high bit of the architecture field)
//! IMPLEMENTATION  23:20
//! ARCHITECTURE_0  28:24     (low 5 bits of the architecture field)
//! architecture = (ARCHITECTURE_1 << 5) | ARCHITECTURE_0
//! ```

/// The GPU microarchitecture, decoded from `NV_PMC_BOOT_0.ARCHITECTURE`.
///
/// Values are the `NV_PMC_BOOT_0_ARCHITECTURE_*` codes from `nvidia-open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Architecture {
    /// Kepler (`GK10x`, e.g. the Quadro K4200) — pre-GSP, not drivable.
    Kepler = 0x0e,
    /// Kepler2 (`GK110`) — pre-GSP.
    Kepler2 = 0x0f,
    /// Maxwell first-gen (`GM10x`) — pre-GSP.
    Maxwell1 = 0x11,
    /// Maxwell second-gen (`GM20x`) — pre-GSP.
    Maxwell2 = 0x12,
    /// Pascal (`GP10x`) — pre-GSP, not drivable by nvidia-open.
    Pascal = 0x13,
    /// Volta (`GV100`, e.g. the Quadro GV100) — pre-GSP, not drivable by
    /// nvidia-open (there is no `gsp_gv100.bin`). Recognized so it identifies
    /// correctly rather than as `Unknown`.
    Volta = 0x14,
    /// Turing (`TU10x`/`TU11x`) — the first GSP generation.
    Turing = 0x16,
    /// Ampere (`GA100`/`GA10x`, e.g. the RTX A4000 `GA104`).
    Ampere = 0x17,
    /// Hopper (`GH100`).
    Hopper = 0x18,
    /// Ada Lovelace (`AD10x`).
    Ada = 0x19,
    /// Blackwell (`GB100`).
    BlackwellGb100 = 0x1a,
    /// Blackwell (`GB200`).
    BlackwellGb200 = 0x1b,
    /// A GSP-less or unrecognized architecture code.
    Unknown = 0xff,
}

impl Architecture {
    fn from_code(code: u32) -> Self {
        match code {
            0x0e => Architecture::Kepler,
            0x0f => Architecture::Kepler2,
            0x11 => Architecture::Maxwell1,
            0x12 => Architecture::Maxwell2,
            0x13 => Architecture::Pascal,
            0x14 => Architecture::Volta,
            0x16 => Architecture::Turing,
            0x17 => Architecture::Ampere,
            0x18 => Architecture::Hopper,
            0x19 => Architecture::Ada,
            0x1a => Architecture::BlackwellGb100,
            0x1b => Architecture::BlackwellGb200,
            _ => Architecture::Unknown,
        }
    }

    /// `nvidia-open` (and therefore this port) drives only GSP-based GPUs, i.e.
    /// Turing (`0x16`) and newer. Pascal/Volta are recognized but pre-GSP, so
    /// they are identified yet not drivable.
    pub fn is_gsp_capable(self) -> bool {
        match self {
            Architecture::Kepler
            | Architecture::Kepler2
            | Architecture::Maxwell1
            | Architecture::Maxwell2
            | Architecture::Pascal
            | Architecture::Volta
            | Architecture::Unknown => false,
            Architecture::Turing
            | Architecture::Ampere
            | Architecture::Hopper
            | Architecture::Ada
            | Architecture::BlackwellGb100
            | Architecture::BlackwellGb200 => true,
        }
    }
}

/// A decoded `NV_PMC_BOOT_0` value: the chip's identity as the hardware reports
/// it (authoritative, unlike a guess from the PCI device ID).
#[derive(Debug, Clone, Copy)]
pub struct ChipInfo {
    /// Raw `NV_PMC_BOOT_0` register value.
    pub boot0: u32,
    /// Decoded architecture.
    pub architecture: Architecture,
    /// `IMPLEMENTATION` field (bits 23:20) — distinguishes chips within an arch
    /// (e.g. GA102 vs GA104).
    pub implementation: u8,
    /// `MAJOR_REVISION` (bits 7:4).
    pub major_rev: u8,
    /// `MINOR_REVISION` (bits 3:0).
    pub minor_rev: u8,
}

impl ChipInfo {
    /// Decode `NV_PMC_BOOT_0` per the field layout above.
    pub fn from_boot0(boot0: u32) -> Self {
        let arch_1 = (boot0 >> 8) & 0x1; // ARCHITECTURE_1  8:8
        let arch_0 = (boot0 >> 24) & 0x1f; // ARCHITECTURE_0 28:24
        let arch_code = (arch_1 << 5) | arch_0;
        ChipInfo {
            boot0,
            architecture: Architecture::from_code(arch_code),
            implementation: ((boot0 >> 20) & 0xf) as u8,
            major_rev: ((boot0 >> 4) & 0xf) as u8,
            minor_rev: (boot0 & 0xf) as u8,
        }
    }
}
