// SPDX-License-Identifier: MPL-2.0

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "acpi: "
    };
}

pub(in crate::arch) mod dmar;
pub(in crate::arch) mod remapping;

use core::{num::NonZeroU8, ptr::NonNull};

use acpi::{
    AcpiHandler, AcpiTables,
    address::AddressSpace,
    fadt::{Fadt, IaPcBootArchFlags},
    mcfg::Mcfg,
    rsdp::Rsdp,
};
use spin::Once;

use crate::{
    boot::{self, BootloaderAcpiArg},
    info,
    mm::paddr_to_vaddr,
    warn,
};

#[derive(Clone, Debug)]
pub(crate) struct AcpiMemoryHandler {}

impl AcpiHandler for AcpiMemoryHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> acpi::PhysicalMapping<Self, T> {
        let virtual_address = NonNull::new(paddr_to_vaddr(physical_address) as *mut T).unwrap();

        // SAFETY: The caller should guarantee that `physical_address..physical_address + size` is
        // part of the ACPI table. Then the memory region is mapped to `virtual_address` and is
        // valid for read and immutable dereferencing.
        // FIXME: The caller guarantee only holds if we trust the hardware to provide a valid ACPI
        // table. Otherwise, if the table is corrupted, it may reference arbitrary memory regions.
        unsafe {
            acpi::PhysicalMapping::new(physical_address, virtual_address, size, size, self.clone())
        }
    }

    fn unmap_physical_region<T>(_region: &acpi::PhysicalMapping<Self, T>) {}
}

struct SyncAcpiTables(Option<AcpiTables<AcpiMemoryHandler>>);

// SAFETY: This relies on the current implementation of `AcpiTables`,
// which provides thread-safe access to read-only ACPI table data,
// so `Sync` is sound for the wrapper.
// FIXME: It depends on implementation details of `AcpiTables`, which should be avoided.
unsafe impl Sync for SyncAcpiTables {}

static ACPI_TABLES: Once<SyncAcpiTables> = Once::new();

pub(crate) fn get_acpi_tables() -> Option<&'static AcpiTables<AcpiMemoryHandler>> {
    let acpi_tables = ACPI_TABLES.call_once(|| {
        let acpi_tables = match boot::EARLY_INFO.get().unwrap().acpi_arg {
            BootloaderAcpiArg::Rsdp(addr) => unsafe {
                AcpiTables::from_rsdp(AcpiMemoryHandler {}, addr).unwrap()
            },
            BootloaderAcpiArg::Rsdt(addr) => unsafe {
                AcpiTables::from_rsdt(AcpiMemoryHandler {}, 0, addr).unwrap()
            },
            BootloaderAcpiArg::Xsdt(addr) => unsafe {
                AcpiTables::from_rsdt(AcpiMemoryHandler {}, 1, addr).unwrap()
            },
            BootloaderAcpiArg::NotProvided => {
                // We search by ourselves if the bootloader decides not to provide a rsdp location.
                let rsdp = unsafe { Rsdp::search_for_on_bios(AcpiMemoryHandler {}) };
                match rsdp {
                    Ok(map) => unsafe {
                        AcpiTables::from_rsdp(AcpiMemoryHandler {}, map.physical_start()).unwrap()
                    },
                    Err(_) => {
                        warn!("ACPI info not found!");
                        return SyncAcpiTables(None);
                    }
                }
            }
        };

        SyncAcpiTables(Some(acpi_tables))
    });

    acpi_tables.0.as_ref()
}

/// The platform information provided by the ACPI tables.
///
/// Currently, this structure contains only a limited set of fields, far fewer than those in all
/// ACPI tables. However, the goal is to expand it properly to keep the simplicity of the OSTD code
/// while enabling OSTD users to safely retrieve information from the ACPI tables.
#[derive(Debug)]
pub struct AcpiInfo {
    /// The RTC CMOS RAM index to the century of data value; the "CENTURY" field in the FADT.
    pub century_register: Option<NonZeroU8>,
    /// IA-PC Boot Architecture Flags; the "IAPC_BOOT_ARCH" field in the FADT.
    pub boot_flags: Option<IaPcBootArchFlags>,
    /// An I/O port to reset the machine by writing the specified value.
    pub reset_port_and_val: Option<(u16, u8)>,
    /// The I/O port of the PM1a event register block (the "PM1a_EVT_BLK" field in
    /// the FADT). The PM1 status register lives at this port; its `PWRBTN_STS`
    /// bit reports an ACPI power-button (e.g. QEMU `system_powerdown`) event.
    pub pm1a_event_block: Option<u16>,
    /// The I/O port of the PM1a control register block (the "PM1a_CNT_BLK" field
    /// in the FADT). Its `SCI_EN` bit (bit 0) reports whether the OS owns ACPI.
    pub pm1a_control_block: Option<u16>,
    /// `(SMI_CMD port, ACPI_ENABLE value)` from the FADT: writing the value to the
    /// port hands ACPI ownership to the OS (`SCI_EN` becomes 1), which is what
    /// makes the platform post power-button events to the OS-visible registers.
    /// `None` if the platform exposes no SMI command port (already OS-owned).
    pub acpi_enable_command: Option<(u16, u8)>,
    /// A memory region that is stolen for PCI configuration space.
    pub pci_ecam_region: Option<PciEcamRegion>,
}

/// A memory region that is stolen for PCI configuration space.
#[derive(Debug)]
pub struct PciEcamRegion {
    /// The base address of the memory region.
    pub base_address: u64,
    /// The start of the bus number.
    pub bus_start: u8,
    /// The end of the bus number.
    pub bus_end: u8,
}

/// The [`AcpiInfo`] singleton.
pub static ACPI_INFO: Once<AcpiInfo> = Once::new();

pub(in crate::arch) fn init() {
    let mut acpi_info = AcpiInfo {
        century_register: None,
        boot_flags: None,
        reset_port_and_val: None,
        pm1a_event_block: None,
        pm1a_control_block: None,
        acpi_enable_command: None,
        pci_ecam_region: None,
    };

    let Some(acpi_tables) = get_acpi_tables() else {
        ACPI_INFO.call_once(|| acpi_info);
        return;
    };

    if let Ok(fadt) = acpi_tables.find_table::<Fadt>() {
        // A zero means that the century register does not exist.
        acpi_info.century_register = NonZeroU8::new(fadt.century);
        acpi_info.boot_flags = Some(fadt.iapc_boot_arch);
        if let Ok(reset_reg) = fadt.reset_register()
            && reset_reg.address_space == AddressSpace::SystemIo
            && let Ok(reset_port) = reset_reg.address.try_into()
        {
            acpi_info.reset_port_and_val = Some((reset_port, fadt.reset_value));
        }
        if let Ok(pm1a_evt) = fadt.pm1a_event_block()
            && pm1a_evt.address_space == AddressSpace::SystemIo
            && let Ok(pm1a_port) = pm1a_evt.address.try_into()
        {
            acpi_info.pm1a_event_block = Some(pm1a_port);
        }
        if let Ok(pm1a_cnt) = fadt.pm1a_control_block()
            && pm1a_cnt.address_space == AddressSpace::SystemIo
            && let Ok(pm1a_cnt_port) = pm1a_cnt.address.try_into()
        {
            acpi_info.pm1a_control_block = Some(pm1a_cnt_port);
        }
        // A zero SMI command port (or zero enable value) means the platform is
        // already in ACPI mode and needs no hand-off.
        if fadt.smi_cmd_port != 0
            && fadt.acpi_enable != 0
            && let Ok(smi_port) = u16::try_from(fadt.smi_cmd_port)
        {
            acpi_info.acpi_enable_command = Some((smi_port, fadt.acpi_enable));
        }
    };

    if let Ok(mcfg) = acpi_tables.find_table::<Mcfg>()
        // TODO: Support multiple PCIe segment groups instead of assuming only one
        // PCIe segment group is in use.
        && let Some(mcfg_entry) = mcfg.entries().first()
    {
        acpi_info.pci_ecam_region = Some(PciEcamRegion {
            base_address: mcfg_entry.base_address,
            bus_start: mcfg_entry.bus_number_start,
            bus_end: mcfg_entry.bus_number_end,
        });
    }

    info!("Collected information {:?}", acpi_info);

    ACPI_INFO.call_once(|| acpi_info);
}
