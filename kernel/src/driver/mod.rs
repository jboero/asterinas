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

    // Report the result via the kernel's own logger (the aster-nvidia crate's
    // own log output does not appear on the console — under investigation).
    let (probed, found) = aster_nvidia::report();
    match found {
        Some((device_id, boot0)) => info!(
            "nvidia: GPU enumerated inside Asterinas — 10de:{:04x}, NV_PMC_BOOT_0={:#010x} (probed {} PCI devices)",
            device_id, boot0, probed,
        ),
        None => info!(
            "nvidia: no NVIDIA GPU matched (driver probed {} PCI devices)",
            probed,
        ),
    }
}
