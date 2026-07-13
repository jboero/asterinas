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
            match r.vram_rw {
                Some(true) => info!(
                    "nvidia:   VRAM read/write via BAR1: OK — Asterinas can use the GPU's memory"
                ),
                Some(false) => info!(
                    "nvidia:   VRAM read/write via BAR1: no round-trip (aperture not mapped to VRAM without RM init)"
                ),
                None => {}
            }
            if r.gsp_capable {
                info!("nvidia:   GSP-capable → P1 GSP bring-up (booting the GPU System Processor)");
                if let Some(g) = r.gsp_state {
                    info!(
                        "nvidia:   GSP core: RISC-V={} IMEM={}KiB DMEM={}KiB falcon_halted={} GFW_boot_complete={}",
                        g.riscv_present, g.imem_bytes / 1024, g.dmem_bytes / 1024,
                        g.falcon_halted, g.gfw_boot_complete,
                    );
                    info!(
                        "nvidia:   GSP regs: HWCFG={:#010x} HWCFG2={:#010x} CPUCTL={:#010x} RISCV_CPUCTL={:#010x} MBOX0={:#010x} MBOX1={:#010x}",
                        g.hwcfg, g.hwcfg2, g.cpuctl, g.riscv_cpuctl, g.mailbox0, g.mailbox1,
                    );
                } else {
                    info!("nvidia:   GSP core: register block not reachable (BAR0 unavailable)");
                }
                if let Some(rst) = r.gsp_reset {
                    info!(
                        "nvidia:   GSP reset (P1.3): reset_ready={} scrub_done={} falcon_pri_locked={} (0xbadf = reset-into-RISC-V, expected)",
                        rst.reset_ready_seen, rst.scrub_done, rst.falcon_pri_locked,
                    );
                    info!(
                        "nvidia:   GSP post-reset: CPUCTL={:#010x} DMACTL={:#010x} RISCV_CPUCTL={:#010x}",
                        rst.post_cpuctl, rst.post_dmactl, rst.post_riscv_cpuctl,
                    );
                }
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
