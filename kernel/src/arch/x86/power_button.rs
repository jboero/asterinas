// SPDX-License-Identifier: MPL-2.0

//! ACPI power-button (graceful shutdown) support.
//!
//! When the host requests an orderly poweroff — QEMU `system_powerdown` or
//! `virsh shutdown` — the ACPI hardware sets the `PWRBTN_STS` bit in the PM1
//! status register. A low-frequency kernel poll of that register notices the
//! event and delivers `SIGINT` to PID 1 (the astrokube init), which then drains
//! and powers the node off gracefully — what a Kubernetes node should do on an
//! orderly shutdown, rather than being hard-killed.
//!
//! We poll `PWRBTN_STS` rather than wiring the ACPI SCI as a real IRQ, which
//! keeps this simple and self-contained. Two preconditions are arranged first:
//! the OS must own ACPI (`SCI_EN`, normally already set by firmware), and the
//! power-button enable bit (`PWRBTN_EN`) must be set — QEMU only posts the
//! status bit when its enable bit is set. With only `PWRBTN_EN` enabled, no
//! other ACPI event can assert the (unhandled) SCI line.

use alloc::boxed::Box;
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use ostd::{
    arch::{device::io_port::ReadWriteAccess, kernel::ACPI_INFO},
    io::IoPort,
    sync::WaitQueue,
};

use crate::{
    process::{
        pid_table,
        signal::{constants::SIGINT, signals::kernel::KernelSignal},
    },
    thread::kernel_thread::ThreadOptions,
    time::wait::WaitTimeout,
};

/// `PWRBTN_STS` — the power-button-pressed bit in the PM1 status register.
const PWRBTN_STS: u16 = 1 << 8;

/// `SCI_EN` — bit 0 of the PM1 control register; set when the OS owns ACPI.
const SCI_EN: u16 = 1 << 0;

/// `PWRBTN_EN` — the power-button enable bit in the PM1 enable register (same
/// bit position as `PWRBTN_STS`). QEMU only posts a power-button status when
/// this enable bit is set, so we must arm it for `system_powerdown` to be seen.
const PWRBTN_EN: u16 = 1 << 8;

/// The init process owns orderly node shutdown.
const INIT_PID: u32 = 1;

/// How often to poll the PM1 status register.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Set once the monitor thread has been spawned, so repeated arm requests are
/// no-ops rather than spawning duplicate monitors.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Spawns the power-button monitor, if the platform exposes a PM1a event block.
/// Must be called after the scheduler is up (it spawns a kernel thread); the
/// astrokube init arms it via prctl once the node is live.
pub(super) fn init() {
    if ARMED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(acpi_info) = ACPI_INFO.get() else {
        ostd::early_println!("acpi: no ACPI info; power-button shutdown disabled");
        return;
    };
    let Some(port_num) = acpi_info.pm1a_event_block else {
        ostd::early_println!("acpi: no PM1a event block; power-button shutdown disabled");
        return;
    };
    let port: IoPort<u16, ReadWriteAccess> = match IoPort::acquire(port_num) {
        Ok(port) => port,
        Err(e) => {
            ostd::early_println!(
                "acpi: could not acquire PM1a event block 0x{:x} ({:?}); \
                 power-button shutdown disabled",
                port_num,
                e
            );
            return;
        }
    };

    // Arm the power button: QEMU only posts PWRBTN_STS when PWRBTN_EN is set, so
    // we enable exactly that bit (and nothing else) in PM1a_EN. We rely on
    // polling PWRBTN_STS rather than the SCI; the SCI line for unused ACPI events
    // stays quiet because no other enable bits are set.
    take_acpi_ownership(
        port_num,
        acpi_info.pm1a_control_block,
        acpi_info.acpi_enable_command,
    );

    ostd::early_println!(
        "acpi: power-button monitor armed on PM1a_EVT_BLK=0x{:x}",
        port_num
    );

    ThreadOptions::new(move || monitor(port)).spawn();
}

/// Arms the power button (sets `PWRBTN_EN`, the gate QEMU checks before posting
/// a status) and, if firmware has not already, hands ACPI ownership to the OS
/// (`SCI_EN`) so power-button events become visible. Only `PWRBTN_EN` is enabled,
/// leaving every other ACPI SCI source masked.
fn take_acpi_ownership(
    evt_port_num: u16,
    control_block: Option<u16>,
    enable_command: Option<(u16, u8)>,
) {
    // PM1a_EN sits two bytes above the PM1a status register. Enable *only* the
    // power button there: that is the gate QEMU checks before posting a
    // power-button status, while leaving every other ACPI SCI source masked.
    if let Ok(en_port) = IoPort::<u16, ReadWriteAccess>::acquire(evt_port_num + 2) {
        en_port.write(PWRBTN_EN);
    }

    let Some(cnt_port_num) = control_block else {
        return;
    };
    let Ok(cnt_port) = IoPort::<u16, ReadWriteAccess>::acquire(cnt_port_num) else {
        ostd::early_println!("acpi: could not acquire PM1a_CNT_BLK 0x{:x}", cnt_port_num);
        return;
    };
    if cnt_port.read() & SCI_EN != 0 {
        // Firmware already handed ACPI ownership to the OS; nothing to do.
        return;
    }
    let Some((smi_port_num, enable_val)) = enable_command else {
        ostd::early_println!("acpi: SCI_EN clear and no SMI command port; power button may be inert");
        return;
    };
    let Ok(smi_port) = IoPort::<u8, ReadWriteAccess>::acquire(smi_port_num) else {
        ostd::early_println!("acpi: could not acquire SMI command port 0x{:x}", smi_port_num);
        return;
    };
    smi_port.write(enable_val);
    for _ in 0..100_000 {
        if cnt_port.read() & SCI_EN != 0 {
            ostd::early_println!("acpi: took ACPI ownership (SCI_EN set)");
            return;
        }
    }
    ostd::early_println!("acpi: ACPI enable did not take (SCI_EN still clear)");
}

/// Polls the PM1 status register; on a power-button event, asks PID 1 to shut
/// the node down and then exits.
fn monitor(port: IoPort<u16, ReadWriteAccess>) {
    let sleep = WaitQueue::new();
    loop {
        if port.read() & PWRBTN_STS != 0 {
            // Acknowledge the event: writing 1 to a PM1 status bit clears it.
            port.write(PWRBTN_STS);
            request_init_shutdown();
            return;
        }
        let _ = sleep.wait_until_or_timeout(|| -> Option<()> { None }, &POLL_INTERVAL);
    }
}

/// Delivers `SIGINT` to PID 1 so it shuts the node down gracefully.
fn request_init_shutdown() {
    if let Some(init) = pid_table::pid_table_mut().get_process(INIT_PID) {
        init.enqueue_signal(Box::new(KernelSignal::new(SIGINT)));
        ostd::early_println!(
            "acpi: power button pressed -> SIGINT to PID 1 (graceful node shutdown)"
        );
    }
}
