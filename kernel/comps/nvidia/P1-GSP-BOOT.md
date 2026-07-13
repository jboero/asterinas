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

## Test rig

The A5000 (Ampere/GSP) on the Precision laptop is the P1 dev target (display on
the iGPU, so the GPU frees to vfio via runtime teardown — see
`asterkube/scripts/a5000-bind-vfio.sh` + `a5000-boot.sh`). No reboots (all
machines are LUKS-encrypted); prefer runtime teardown.
