#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
#
# Build and boot the full Asterinas kernel on 32-bit ARM (ARMv7-A, QEMU `virt`),
# running a minimal C-free userspace `/init` from an initramfs to demonstrate
# end-to-end boot, ELF loading, and system calls.
#
# Requirements: the pinned Rust nightly with the `armv7a-none-eabi` target,
# `cargo-osdk` built with `OSDK_LOCAL_DEV=1`, and `qemu-system-arm`.
#
# The `cortex-a15` CPU provides the features the port relies on: LPAE (long
# descriptor page tables), the ARMv7 generic timer, and GICv2.
#
# QEMU does not populate the device tree's `linux,initrd-start` for a directly
# booted ELF, so the initramfs is loaded at a fixed address via `-device loader`
# and its location is passed on the kernel command line as `initrd=<paddr>,<size>`
# (parsed by the ARM boot code).

set -e

ASTER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INITRAMFS="${INITRAMFS:-$ASTER_DIR/build/armv7-initramfs.cpio.gz}"
INITRD_ADDR="0x48000000"

if [ ! -f "$INITRAMFS" ]; then
    echo "==> Building the C-free /init initramfs"
    OUT="$INITRAMFS" "$ASTER_DIR/tools/build_arm_init.sh"
fi

echo "==> Building the ARMv7-A kernel image via cargo-osdk"
( cd "$ASTER_DIR/kernel" && OSDK_TARGET_ARCH=arm \
    cargo osdk build --target-arch arm --scheme arm )

KERNEL="$ASTER_DIR/target/osdk/aster-kernel-osdk-bin.qemu_elf"
INITRD_SIZE="$(stat -c%s "$INITRAMFS")"

echo "==> Booting in QEMU (initramfs @ $INITRD_ADDR, size $INITRD_SIZE)"
exec qemu-system-arm \
    -machine virt,gic-version=2 \
    -cpu cortex-a15 \
    -m 512M \
    -smp 1 \
    -nographic \
    -no-reboot \
    -kernel "$KERNEL" \
    -device "loader,file=$INITRAMFS,addr=$INITRD_ADDR,force-raw=on" \
    -append "console=ttyS0 init=/init initrd=$INITRD_ADDR,$INITRD_SIZE"
