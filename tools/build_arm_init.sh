#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
#
# Builds a minimal, C-free `/init` for the ARMv7-A userspace demo and packs it
# into a gzip-compressed `newc` cpio initramfs.
#
# The program is `no_std`/`no_main` Rust: it issues raw `write(2)`/`exit(2)`
# system calls via `svc #0` (Linux asm-generic ABI, syscall number in `r7`).
# There is no libc and no C anywhere in the image.
#
# A plain `-Ttext=0x10000` makes rust-lld emit a separate read-only segment for
# the ELF header that overlaps the executable .text at the same page, which the
# kernel then maps non-executable. The linker script below emits a single R+E
# PT_LOAD that includes the headers, keeping the whole image executable.
#
# Output: $OUT (default: build/armv7-initramfs.cpio.gz under the repo root).
set -e

ASTER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ASTER_DIR/build/armv7-initramfs.cpio.gz}"
TARGET="armv7a-none-eabi"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > init.rs <<'EOF'
#![no_std]
#![no_main]
core::arch::global_asm!(
    ".section .text",
    ".global _start",
    "_start:",
    "    mov  r0, #1",     // fd = stdout
    "    adr  r1, msg",    // buf
    "    mov  r2, #41",    // len (bytes of msg)
    "    mov  r7, #64",    // __NR_write (asm-generic)
    "    svc  #0",
    "    mov  r0, #0",     // status = 0
    "    mov  r7, #93",    // __NR_exit (asm-generic)
    "    svc  #0",
    "1:  b 1b",
    ".balign 4",
    "msg:",
    "    .ascii \"Hello from ARMv7 userspace on Asterinas!\\n\"",
);
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }
EOF

cat > init.ld <<'EOF'
ENTRY(_start)
PHDRS {
    text PT_LOAD FILEHDR PHDRS FLAGS(0x5); /* PF_R | PF_X */
}
SECTIONS {
    . = 0x10000 + SIZEOF_HEADERS;
    .text : { *(.text*) *(.rodata*) } :text
    /DISCARD/ : {
        *(.ARM.exidx*) *(.ARM.attributes) *(.comment) *(.note*) *(.eh_frame*)
    }
}
EOF

LLD="$(find "$(rustc --print sysroot)" -name rust-lld | head -1)"

rustc --edition 2021 --target "$TARGET" --crate-type bin \
    -C panic=abort -C opt-level=2 --emit obj -o init.o init.rs
"$LLD" -flavor gnu -static -T init.ld -o init init.o

mkdir -p root/{sbin,bin,dev,proc,sys,tmp}
cp init root/init

mkdir -p "$(dirname "$OUT")"
( cd root && find . | cpio -o -H newc --quiet | gzip ) > "$OUT"

echo "==> Wrote $OUT ($(stat -c%s "$OUT") bytes); /init entry $(readelf -h init | awk '/Entry/{print $NF}')"
