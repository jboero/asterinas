# P1 — GSP boot + Resource Manager (the road to CUDA)

This is the design + milestone tracker for **P1** of the NVIDIA-in-Asterinas
plan (`asterkube/docs/GPU-CUDA-PORT-PLAN.md`). P0 is done and proven on real
hardware: the C-free driver enumerates a passed-through GPU, reads its identity,
uses its VRAM, and exposes `/dev/nvidia0` to a container. P1 turns "use the GPU's
memory" into "run work on the GPU's engines" by booting the **GSP** (GPU System
Processor) and standing up enough of the **Resource Manager (RM)** to allocate
contexts, channels, and submit compute — the substrate CUDA needs.

Target GPU: **Ampere GA10x (GA104)** — the RTX A4000 / A5000. GSP-capable
(`GSP-drivable=true`, proven on the A5000).

## Why this is large, and the honest scope

The GSP on Ampere is a RISC-V "Peregrine" core with a Falcon front-end. Booting
it and talking to GSP-RM is the bulk of NVIDIA's `open-gpu-kernel-modules`
(nvidia-open) — millions of lines of C. Realistically P1 spans many sessions.
The strategy is incremental and **verifiable at each step on real hardware**:
poke the GSP microprocessor registers, set up the firmware, boot it, and only
then layer the RPC/RM protocol on top.

**The C question.** The user's constraint is "try not to include any C in the
final result." P0 is fully C-free. The RPC struct/ABI definitions and firmware
image layout come from nvidia-open (C). At the **RPC boundary (P1.6)** we choose:
- **Hybrid:** vendor nvidia-open's RM core as a static lib behind the existing
  `nvidia_gpu` cargo feature (default build stays C-free); fastest path to real
  CUDA. The C is isolated and optional.
- **C-free:** transcribe the (stable, versioned) RPC ABI + boot image layout
  into Rust and drive GSP-RM directly. Much larger, research-grade, but keeps
  the final result C-free. Everything up to P1.5 is C-free regardless.

## Milestones

- **P1.1 — GSP microprocessor register substrate.** Map the GSP falcon/RISC-V
  register block in BAR0; read core identity/state (HWCFG IMEM/DMEM sizes,
  CPUCTL halt/run, mailboxes). Pure Rust. Verifiable: print the GSP core state
  on the A5000. *(foundation for everything below)*
- **P1.2 — GSP firmware loading scaffold.** Locate/embed `gsp_ga10x.bin` + the
  booter ucode; parse the image; expose a firmware provider. Pure Rust.
- **P1.3 — WPR + firmware DMA.** Reserve a Write-Protected Region in VRAM,
  build the radix3 page tables, DMA the firmware image in. Pure Rust (uses the
  BAR1 VRAM window + Asterinas DMA).
- **P1.4 — RPC message queue.** Shared-memory command/status queues; message
  header format. This is where the nvidia-open ABI enters.
- **P1.5 — Boot GSP + handshake.** Kick the RISC-V bootloader, detect
  "GSP booted" via the mailbox/status. Milestone: **GSP running under Asterinas.**
- **P1.6 — RM strategy decision** (hybrid vs C-free) and first RM control call.

Then: **P2** (UVM / unified memory), **P3** (uAPI: the ioctls CUDA userspace
issues), **Track 2** (CGO-free CUDA userspace).

## Status log

- **P1.1 — DONE (verified on RTX A5000, GA104 Ampere), commit `7a715a711`.**
  The driver retains BAR0 and reads the GSP core state over it:
  `RISC-V=true, IMEM=64KiB, falcon_halted=true, GFW_boot_complete=true,
  HWCFG2=0x47f7 (RISCV bit set), CPUCTL/RISCV_CPUCTL=0x10 (halted), MBOX0/1=0` —
  the correct pre-boot state. `gsp.rs` holds the cited register map.

- **P1.2 — firmware located + characterized.** On a driver-595.80 host:
  `/lib/firmware/nvidia/595.80/gsp_ga10x.bin` is a **72.8 MB RISC-V ELF**
  (`e_machine=0xf3`) — the monolithic GSP-RM image (radix3 ELF). The GA104 set
  also ships split under `/lib/firmware/nvidia/ga104/gsp/`: `gsp-<ver>.bin.xz`
  (GSP-RM), `bootloader` (RISC-V bootloader), `booter_load`/`booter_unload`
  (HS ACR ucode). These signed blobs are the one non-negotiable vendor
  dependency; everything else stays Rust.

  **Key architectural finding for P1.2+:** the GSP boot **must not** run in the
  PCI probe. Probe happens at early PCI init, long before any filesystem is
  mounted, so the driver cannot `request_firmware` there, and a 72 MB embed is
  unacceptable kernel bloat. The boot must be a **deferred operation** —
  triggered after rootfs/initramfs is up (e.g. via an ioctl on `/dev/nvidia0`,
  or a kthread post-fs-init) — with the firmware delivered through the initramfs
  (or a virtio-fs/host share during dev). P1.2 therefore = (a) a `GspFirmware`
  provider abstraction the kernel fills from the initramfs, (b) parse the
  gsp_ga10x ELF/container layout, (c) move `gsp::boot()` out of probe into a
  deferred entry point.

## Test rig

The A5000 (Ampere/GSP) on the Precision laptop is the P1 dev target (display on
the iGPU, so the GPU frees to vfio via runtime teardown — see
`asterkube/scripts/a5000-bind-vfio.sh` + `a5000-boot.sh`). No reboots (all
machines are LUKS-encrypted); prefer runtime teardown.
