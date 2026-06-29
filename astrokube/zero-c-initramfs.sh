#!/bin/bash
# zero-c-initramfs.sh — build a ZERO-C node image: a bootable initramfs that
# contains no C runtime at all (no glibc/musl shared objects, no dynamically
# linked or C-static binaries). Only the static, CGO-free Go init remains.
#
# It takes the normal staged initramfs and:
#   * swaps in a fresh CGO_ENABLED=0 astrokube-init,
#   * deletes /lib64 + /lib (the glibc closure),
#   * deletes every dynamically-linked binary (e.g. the upstream runc),
#   * verifies NOTHING ELF-dynamic survives,
# then repacks the cpio and rebuilds the bootable ISO.
#
# The init detects the absent libc at boot (pureGoMode) and runs only its
# pure-Go path: mounts, capability probes, and the node agent that launches
# real namespaced + cgroup-limited containers via clone() directly — no runc,
# no containerd, no C.
#
# Usage: astrokube/zero-c-initramfs.sh [path-to-kubelet-repo]
set -euo pipefail
cd "$(dirname "$0")/.."                       # asterinas/
KUBELET=${1:-/home/jboero/code/asterinas_experiment/kubelet}
BUILD=test/initramfs/build
CPIO="$BUILD/initramfs.cpio.gz"
WORK=$(mktemp -d /tmp/astrokube-zeroc.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# INIT_BIN lets us drop in a pre-built binary — e.g. the COMBINED zero-C kubelet
# (real upstream kubelet + our init), built by build-zeroc-kubelet.sh. Otherwise
# build the lightweight standalone init/node-agent from this module.
if [ -n "${INIT_BIN:-}" ]; then
  echo "==> using pre-built init binary: $INIT_BIN"
  cp "$INIT_BIN" "$WORK/init-bin"; chmod 0755 "$WORK/init-bin"
else
  echo "==> building astrokube-init (static, CGO_ENABLED=0) from $KUBELET"
  ( cd "$KUBELET" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -ldflags="-s -w" -o "$WORK/init-bin" ./cmd/astrokube-init )
fi

echo "==> extracting staged initramfs $CPIO"
mkdir -p "$WORK/root"
( cd "$WORK/root" && gzip -dc "$OLDPWD/$CPIO" | cpio -idm --quiet )

# /sbin/init -> ../usr/bin/kubelet, so the init binary lives there. We ship ONE
# binary (no duplicate): `kubelet` is our static, CGO-free init/node-agent, and
# it is also the OCI runtime, mount/umount applet, etc. via argv[0] multi-call.
echo "==> swapping in fresh static init (single binary, no duplicate)"
install -m 0755 "$WORK/init-bin" "$WORK/root/usr/bin/kubelet"
rm -f "$WORK/root/usr/bin/astrokube-init"

echo "==> removing the C runtime (glibc closure) and any dynamic binaries"
rm -rf "$WORK/root/lib64" "$WORK/root/lib"
# Walk every regular file; drop anything that is a dynamically-linked ELF or a
# C-static binary that still carries an interpreter/NEEDED entry.
removed=0
while IFS= read -r -d '' f; do
  head -c4 "$f" 2>/dev/null | grep -q $'\x7fELF' || continue
  if readelf -d "$f" 2>/dev/null | grep -q NEEDED || \
     readelf -l "$f" 2>/dev/null | grep -q INTERP; then
    echo "    drop dynamic: ${f#$WORK/root}"
    rm -f "$f"; removed=$((removed+1))
  fi
done < <(find "$WORK/root" -type f -print0)
echo "    removed $removed dynamic binaries"

echo "==> verifying NOTHING C/dynamic remains"
bad=0
while IFS= read -r -d '' f; do
  head -c4 "$f" 2>/dev/null | grep -q $'\x7fELF' || continue
  if readelf -d "$f" 2>/dev/null | grep -q NEEDED || \
     readelf -l "$f" 2>/dev/null | grep -q INTERP; then
    echo "    !! STILL DYNAMIC: ${f#$WORK/root}"; bad=$((bad+1))
  fi
done < <(find "$WORK/root" -type f -print0)
if [ -d "$WORK/root/lib64" ] || [ -d "$WORK/root/lib" ]; then
  echo "    !! lib/ or lib64/ still present"; bad=$((bad+1))
fi
if [ "$bad" -ne 0 ]; then echo "==> FAILED: $bad C/dynamic artifacts remain"; exit 1; fi
echo "    OK — every ELF in the image is static and CGO-free; no lib64/."

echo "==> ELF inventory of the zero-C image:"
while IFS= read -r -d '' f; do
  head -c4 "$f" 2>/dev/null | grep -q $'\x7fELF' || continue
  printf "    %-28s %s\n" "${f#$WORK/root/}" "$(file -b "$f" | grep -oE 'statically linked')"
done < <(find "$WORK/root" -type f -print0)

echo "==> repacking $CPIO"
( cd "$WORK/root" && find . -print0 \
    | cpio --null -o -H newc --owner=0:0 --quiet | gzip -9 ) > "$CPIO"
echo "==> initramfs done:"; ls -lh "$CPIO"

if [ "${SKIP_ISO:-0}" != "1" ]; then
  echo "==> rebuilding ISO in the dev container"
  docker start astrokube >/dev/null 2>&1 || true
  docker exec astrokube bash -lc \
    'git config --global --add safe.directory /root/asterinas; cd /root/asterinas/kernel && cargo osdk build --release --strip-elf --grub-boot-protocol=multiboot2' \
    2>&1 | tail -2
  echo "==> ISO:"; ls -lh target/osdk/aster-kernel-osdk-bin.iso
fi
