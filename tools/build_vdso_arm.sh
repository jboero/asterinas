#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
#
# Rebuilds `kernel/src/vdso_arm.so`, the ARMv7-A vDSO.
#
# The vDSO is a tiny hand-written assembly shared object provided by the kernel
# to userspace. It contains no C and links no libc. Built once and checked in.
#
# NOTE: The port speaks the stock ARM EABI syscall ABI, so `__NR_rt_sigreturn`
# is 173 (the legacy `arch/arm` number), issued via `svc #0` with the number in
# `r7`.
set -e
ASTER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ASTER_DIR/kernel/src/vdso_arm.so"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > vdso.rs <<'EOF'
#![no_std]
#![no_main]
core::arch::global_asm!(
    ".section .text",
    ".balign 16",
    ".global __vdso_rt_sigreturn",
    ".global __kernel_rt_sigreturn",
    ".type __vdso_rt_sigreturn, %function",
    "__vdso_rt_sigreturn:",
    "__kernel_rt_sigreturn:",
    "    mov r7, #173", // __NR_rt_sigreturn (ARM EABI)
    "    svc #0",
);
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }
EOF
cat > vdso.ver <<'EOF'
LINUX_2.6 {
global:
  __vdso_rt_sigreturn;
  __kernel_rt_sigreturn;
local: *;
};
EOF
rustc --target armv7a-none-eabi --edition 2021 --emit obj -O \
    -C panic=abort -o vdso.o vdso.rs
LLD="$(find "${RUSTUP_HOME:-$HOME/.rustup}" -name rust-lld | head -1)"
"$LLD" -flavor gnu -shared -Bsymbolic --build-id=none --hash-style=sysv \
    --version-script=vdso.ver -soname=linux-vdso.so.1 \
    -z max-page-size=4096 -z noseparate-code --no-rosegment \
    -o "$OUT" vdso.o
echo -n "__VDSO_RT_SIGRETURN_OFFSET = "
readelf -sW "$OUT" | awk '/__vdso_rt_sigreturn$/ {print "0x"$2; exit}'
truncate -s 4096 "$OUT"
echo "Wrote $OUT (padded to 4096 bytes)"
