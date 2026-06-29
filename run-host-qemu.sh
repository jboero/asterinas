#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
#
# run-host-qemu.sh — boot prebuilt Asterinas artifacts with plain QEMU on the
# host, as an unprivileged user. No container, no root, no cargo-osdk.
#
#   ./run-host-qemu.sh astrokube        boot the self-contained astrokube node ISO
#                                       (kernel+initramfs); runs pods, powers off.
#   ./run-host-qemu.sh astrokube-qcow2  same self-contained node, as a QCOW2 disk.
#   ./run-host-qemu.sh nixos            boot the Asterinas NixOS qcow2 (aster_systemd
#                                       as PID 1); interactive, exit with Ctrl-A X.
#
# Artifacts (produced by the dev-container build):
#   target/osdk/aster-kernel-osdk-bin.iso        <- cargo osdk build / astrokube-run.sh
#   test/initramfs/build/{ext2,exfat}.qcow2      <- qemu-img convert of the raw disks
#   target/nixos/asterinas-nixos.qcow2           <- qemu-img convert of target/nixos/asterinas.img
#
# The ISO produced by the dev container is EFI-only (no BIOS El Torito), so both
# modes boot through OVMF. Requires: qemu-system-x86_64, edk2-ovmf, and (for KVM)
# membership in the `kvm` group.
set -euo pipefail
cd "$(dirname "$0")"

MODE=${1:-astrokube}
OVMF_CODE=${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}
OVMF_VARS_SRC=${OVMF_VARS_SRC:-/usr/share/edk2/ovmf/OVMF_VARS.fd}
VARS="$(mktemp /tmp/asterinas-OVMF_VARS.XXXXXX.fd)"
cp "$OVMF_VARS_SRC" "$VARS"

# The guest firmware and OS write raw escape sequences to this terminal
# (OVMF window-resize, a full-terminal reset from NixOS stage 2, charset
# switches). Save the tty state and restore it — plus a soft terminal reset —
# no matter how QEMU exits, so the shell is usable afterwards.
SAVED_STTY=""
[ -t 0 ] && SAVED_STTY=$(stty -g 2>/dev/null || true)

# virtio-fs: the finished astrokube image is SELF-CONTAINED — the container
# runtime is baked into the initramfs — so no share is needed and this is OFF by
# default. It remains available as a dev escape hatch (VIRTIOFS=on) to inject
# binaries/images at runtime without rebaking the initramfs.
VIRTIOFS=${VIRTIOFS:-off}
VIRTIOFS_SHARE=${VIRTIOFS_SHARE:-/tmp/astrokube-vfs}
VIRTIOFS_TAG=${VIRTIOFS_TAG:-astrokubevfs}
VIRTIOFSD=${VIRTIOFSD:-/usr/libexec/virtiofsd}
VIRTIOFS_SOCK="$(mktemp -u /tmp/astrokube-vfs.XXXXXX.sock)"
VIRTIOFSD_PID=""

cleanup() {
  rm -f "$VARS"
  [ -n "$VIRTIOFSD_PID" ] && kill "$VIRTIOFSD_PID" 2>/dev/null || true
  rm -f "$VIRTIOFS_SOCK"
  if [ -n "$SAVED_STTY" ]; then
    stty "$SAVED_STTY" 2>/dev/null || stty sane 2>/dev/null || true
    # DECSTR soft reset; bracketed paste off; ASCII charset; SGR reset; cursor on
    printf '\033[!p\033[?2004l\033(B\033[m\033[?25h'
  fi
}
trap cleanup EXIT INT TERM

# Build the QEMU args that attach the virtio-fs device, starting virtiofsd first.
VIRTIOFS_ARGS=()
maybe_start_virtiofs() {
  [ "$VIRTIOFS" = "on" ] || { echo "==> virtio-fs disabled"; return; }
  if [ ! -x "$VIRTIOFSD" ]; then echo "==> virtio-fs: $VIRTIOFSD not found, skipping"; return; fi
  mkdir -p "$VIRTIOFS_SHARE"
  echo "==> virtio-fs: sharing $VIRTIOFS_SHARE (tag=$VIRTIOFS_TAG) via $VIRTIOFSD"
  "$VIRTIOFSD" --socket-path="$VIRTIOFS_SOCK" --shared-dir="$VIRTIOFS_SHARE" \
    --sandbox none >virtiofsd.log 2>&1 &
  VIRTIOFSD_PID=$!
  # Wait briefly for the socket to appear.
  for _ in $(seq 1 50); do [ -S "$VIRTIOFS_SOCK" ] && break; sleep 0.1; done
  if [ ! -S "$VIRTIOFS_SOCK" ]; then
    echo "==> virtio-fs: virtiofsd did not create a socket (see virtiofsd.log), skipping"
    VIRTIOFSD_PID=""; return
  fi
  VIRTIOFS_ARGS=(
    -object memory-backend-memfd,id=mem0,size=8G,share=on
    -numa node,memdev=mem0
    -chardev socket,id=vfschar0,path="$VIRTIOFS_SOCK"
    -device vhost-user-fs-pci,chardev=vfschar0,tag="$VIRTIOFS_TAG"
  )
}

ACCEL="-accel kvm"; [ -w /dev/kvm ] || { echo "==> no /dev/kvm, using TCG"; ACCEL="-accel tcg"; }

COMMON=(
  -machine q35,kernel-irqchip=split $ACCEL -cpu Icelake-Server,+x2apic -m 8G -smp 1
  --no-reboot -nographic
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
  -drive if=pflash,format=raw,file="$VARS"
  -chardev stdio,id=mux,mux=on,signal=off,logfile=qemu-host.log
  -device virtio-serial-pci,disable-legacy=on,disable-modern=off
  -device virtconsole,chardev=mux
  -monitor chardev:mux -serial file:qemu-serial-host.log
  -qmp unix:astrokube-qmp.sock,server,nowait
  -object rng-random,id=rng0,filename=/dev/urandom
  -device virtio-rng-pci,rng=rng0,disable-legacy=on,disable-modern=off
)

rc=0
case "$MODE" in
  astrokube)
    maybe_start_virtiofs
    # User-mode (slirp) NIC so the guest's eth0 has outbound connectivity (the
    # host is reachable from the guest at 10.0.2.2). virtio-net flags mirror
    # tools/qemu_args.sh, which the Asterinas virtio-net driver expects.
    qemu-system-x86_64 "${COMMON[@]}" "${VIRTIOFS_ARGS[@]}" \
      -cdrom target/osdk/aster-kernel-osdk-bin.iso -boot d \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
      -drive if=none,format=qcow2,id=x0,file=test/initramfs/build/ext2.qcow2 \
      -drive if=none,format=qcow2,id=x1,file=test/initramfs/build/exfat.qcow2 \
      -device virtio-blk-pci,bus=pcie.0,addr=0x6,drive=x0,serial=vext2,disable-legacy=on,disable-modern=off \
      -device virtio-blk-pci,bus=pcie.0,addr=0x7,drive=x1,serial=vexfat,disable-legacy=on,disable-modern=off \
      -netdev user,id=net01 \
      -device virtio-net-pci,netdev=net01,disable-legacy=on,disable-modern=off,mrg_rxbuf=off,ctrl_rx=off,ctrl_rx_extra=off,ctrl_vlan=off,ctrl_vq=off,ctrl_guest_offloads=off,ctrl_mac_addr=off,event_idx=off,queue_reset=off,guest_announce=off,indirect_desc=off \
      || rc=$?
    # 33 = the guest signalled a clean poweroff via isa-debug-exit
    [ "$rc" -eq 33 ] && rc=0
    ;;
  astrokube-qcow2)
    # The self-contained node as a QCOW2 disk (built by astrokube/build-qcow2.sh
    # from the isohybrid ISO). Same image, booted as a virtio-blk disk instead of
    # a CD-ROM — no initramfs= needed, no share. Powers off when the demo is done.
    QCOW=${QCOW:-test/initramfs/build/astrokube-node.qcow2}
    [ -f "$QCOW" ] || { echo "missing $QCOW — build it: ./astrokube/build-qcow2.sh" >&2; exit 1; }
    qemu-system-x86_64 "${COMMON[@]}" \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
      -drive if=none,format=qcow2,id=disk0,file="$QCOW" \
      -device virtio-blk-pci,drive=disk0,bootindex=0,disable-legacy=on,disable-modern=off \
      -netdev user,id=net01 \
      -device virtio-net-pci,netdev=net01,disable-legacy=on,disable-modern=off,mrg_rxbuf=off,ctrl_rx=off,ctrl_rx_extra=off,ctrl_vlan=off,ctrl_vq=off,ctrl_guest_offloads=off,ctrl_mac_addr=off,event_idx=off,queue_reset=off,guest_announce=off,indirect_desc=off \
      || rc=$?
    [ "$rc" -eq 33 ] && rc=0
    ;;
  nixos)
    # User-mode (slirp) networking so the guest can reach the internet
    # (e.g. `podman run docker.io/library/alpine`); device flags mirror
    # tools/qemu_args.sh, which the Asterinas virtio-net driver expects.
    qemu-system-x86_64 "${COMMON[@]}" \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
      -drive if=none,format=qcow2,id=u0,file=target/nixos/asterinas-nixos.qcow2 \
      -device virtio-blk-pci,drive=u0,bootindex=0,disable-legacy=on,disable-modern=off \
      -netdev user,id=net01,hostfwd=tcp::8080-:8080 \
      -device virtio-net-pci,netdev=net01,disable-legacy=on,disable-modern=off,mrg_rxbuf=off,ctrl_rx=off,ctrl_rx_extra=off,ctrl_vlan=off,ctrl_vq=off,ctrl_guest_offloads=off,ctrl_mac_addr=off,event_idx=off,queue_reset=off,guest_announce=off,indirect_desc=off \
      || rc=$?
    [ "$rc" -eq 33 ] && rc=0
    ;;
  *)
    echo "usage: $0 [astrokube|astrokube-qcow2|nixos]" >&2; exit 1
    ;;
esac
exit "$rc"
