#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
#
# Build a *real*, stock, statically-linked Linux/ARM ELF program and run it on
# the 32-bit Asterinas kernel in QEMU (`virt`, cortex-a15). Unlike the C-free
# `/init` demo (tools/run_arm_demo.sh), this exercises a full libc: musl startup,
# argv/envp/auxv parsing, TLS, the heap, buffered stdio, threads, and futexes —
# via the stock ARM EABI syscall numbers, unmodified.
#
# The *kernel* remains C-free (Rust + assembly); the C here (musl) lives entirely
# in the user program, which is exactly the point — an ordinary Linux binary runs
# on the Rust kernel.
#
# Requirements: the pinned Rust nightly with the `armv7-unknown-linux-musleabi`
# target (rustup will fetch it), `cargo-osdk` (OSDK_LOCAL_DEV=1), qemu-system-arm.
#
# You can run your own binary instead of the built-in demo by setting PROG=/path
# to a statically-linked armv7 (soft-float) Linux executable.
set -e

ASTER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="armv7-unknown-linux-musleabi"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

if [ -n "${PROG:-}" ]; then
    BIN="$PROG"
    echo "==> Using provided program: $BIN"
else
    echo "==> Building the demo Linux/ARM program (musl, static)"
    rustup target add --toolchain nightly-2026-04-03 "$TARGET" >/dev/null 2>&1 || true
    mkdir -p "$WORK/src"
    cat > "$WORK/Cargo.toml" <<'EOF'
[package]
name = "aster-arm-demo"
version = "0.1.0"
edition = "2021"
[[bin]]
name = "demo"
path = "src/main.rs"
[profile.release]
opt-level = "z"
panic = "abort"
strip = true
EOF
    cat > "$WORK/src/main.rs" <<'EOF'
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
fn main() {
    println!("Hello from a REAL static Linux ELF on Asterinas/ARMv7!");
    let v: Vec<u32> = (1..=10).collect();
    println!("heap Vec 1..=10 sums to {}", v.iter().sum::<u32>());
    let counter = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..4).map(|_| {
        let c = Arc::clone(&counter);
        std::thread::spawn(move || {
            let s: u64 = (0..25_000u64).sum();
            c.fetch_add(s, Ordering::SeqCst);
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
    println!("4 threads summed to {}", counter.load(Ordering::SeqCst));
    println!("SUCCESS: libc + TLS + heap + threads + atomics all work");
    std::process::exit(0);
}
EOF
    # rust-lld links the ARM ELF without needing a C cross-toolchain; soft-float
    # (no NEON/VFP) since the port does not save FP context yet.
    ( cd "$WORK" && RUSTFLAGS="-C target-feature=+crt-static,-neon,-vfp2,-vfp3 -C relocation-model=static -C linker=rust-lld -C linker-flavor=ld.lld" \
        cargo +nightly-2026-04-03 build --release --target "$TARGET" >/dev/null )
    BIN="$WORK/target/$TARGET/release/demo"
fi

echo "==> Packing $BIN as /init into an initramfs"
mkdir -p "$WORK/root"/{dev,proc,sys,tmp}
cp "$BIN" "$WORK/root/init"
( cd "$WORK/root" && find . | cpio -o -H newc --quiet | gzip ) > "$WORK/initramfs.cpio.gz"
INITRD_SIZE="$(stat -c%s "$WORK/initramfs.cpio.gz")"

echo "==> Building the ARMv7-A kernel image via cargo-osdk"
( cd "$ASTER_DIR/kernel" && OSDK_TARGET_ARCH=arm \
    cargo osdk build --target-arch arm --scheme arm )
KERNEL="$ASTER_DIR/target/osdk/aster-kernel-osdk-bin.qemu_elf"

echo "==> Booting in QEMU (program initramfs @ 0x48000000, size $INITRD_SIZE)"
exec qemu-system-arm \
    -machine virt,gic-version=2 \
    -cpu cortex-a15 \
    -m 512M \
    -smp 1 \
    -nographic \
    -no-reboot \
    -kernel "$KERNEL" \
    -device "loader,file=$WORK/initramfs.cpio.gz,addr=0x48000000,force-raw=on" \
    -append "console=ttyS0 init=/init initrd=0x48000000,$INITRD_SIZE"
