// SPDX-License-Identifier: MPL-2.0

use ostd::info;

pub fn init() {
    for device in aster_input::all_devices() {
        info!("Found an input device, name: {}", device.name());
    }

    // FIXME: Currently, we have to do this manually to ensure the crates containing the input
    // devices are linked and their `#[init_component]` hooks can run to register the devices with
    // the input core. We should find a way to avoid this in the future.
    #[expect(unused_imports)]
    use aster_i8042::*;

    // Same reason: force-link the NVIDIA GPU driver and register it with the PCI
    // bus. `black_box` on the function pointer prevents the optimizer from
    // eliding the call cross-crate. The pure-Rust P0 driver is always linked
    // (C-free); the C RM comes later behind the `nvidia_gpu` feature.
    let f: fn() = aster_nvidia::ensure_linked;
    core::hint::black_box(f)();

    // Report the GPU inventory the driver read off the hardware, via the
    // kernel's own logger (the aster-nvidia crate's log output does not reach
    // the console on x86 — under investigation).
    let (probed, found) = aster_nvidia::report();
    match found {
        Some(r) => {
            info!(
                "nvidia: GPU enumerated inside Asterinas — 10de:{:04x}, NV_PMC_BOOT_0={:#010x} => {:?} impl {:#x} rev {}.{} (probed {} PCI devices)",
                r.device_id, r.chip.boot0, r.chip.architecture,
                r.chip.implementation, r.chip.major_rev, r.chip.minor_rev, probed,
            );
            info!(
                "nvidia:   BARs (MiB): BAR0(regs)={} BAR1(VRAM window)={} BAR3={}; MSI-X vectors={}; GSP-drivable={}",
                r.bar_bytes[0] >> 20, r.bar_bytes[1] >> 20, r.bar_bytes[3] >> 20,
                r.msix_vectors, r.gsp_capable,
            );
            if r.gsp_capable {
                info!("nvidia:   GSP-capable → next milestone: load GSP firmware + RM handshake (P1)");
            } else {
                info!("nvidia:   pre-GSP architecture → enumerated + identified, but not drivable by nvidia-open");
            }
        }
        None => info!(
            "nvidia: no NVIDIA GPU matched (driver probed {} PCI devices)",
            probed,
        ),
    }
}
