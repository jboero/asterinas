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

## Status: P1.1–P1.5b done, hardware-verified. Commits on branch `cuda-p1`.

**Full chain re-verified on the actual RTX A5000 (GA104 Ampere, GSP-capable) in
one boot:** GSP core read (RISC-V=true, GFW-complete) → reset (0xbadf
reset-into-RISC-V) → firmware parse (72.8MB, 595.80) → `.fwimage` staged @
`0x210000000` (verified) → radix3 root@`0x2145e5000`, 17778 pages/35 L2 pages
(verified) → GspFwWprMeta 256B magic ok → GPU-IN-CONTAINER PASS. This is the
A4000's own silicon family — strongest verification short of the literal A4000.

- **P1.5b — hardware-verified (K4200, local; the radix3/WPR-meta path is
  GPU-independent sysmem work so it runs on any enumerated GPU).** From a real
  boot: `.fwimage` staged at GPU-phys `0x210000000` (verified); **radix3 built:
  root@`0x2145e5000`, 17778 fw pages via 35 L2 pages, verified=true** (in-guest
  L0→L1→L2 read-back walk); **GspFwWprMeta: 256 bytes, magic
  `0xdc3aae21371a60b3` rev 1**. Page math exact (72,818,688 B = 17,778×4K;
  ⌈17778/512⌉ = 35 L2 pages). Commit `b8236980f`.

- **P1.5c SEC2 substrate — DONE, verified A5000 (commit `153a08128`).** SEC2
  falcon (`NV_PSEC2=0x840000`) reachable (HWCFG2=0x67f7, IMEM/DMEM=64KiB) but
  `CPUCTL=0xbadf5620` (priv-locked). Proven on silicon: **SEC2 is heavy-secured;
  the Booter must load via the HS secure-DMA + BROM path, not plain STARTCPU.**

### Remaining: the full Booter run + boot handoff (procedure fully mapped)

Exact sequence (nouveau r535, v6.9), SEC2-base `0x840000` relative unless noted:
1. **Version-match the firmware.** The Booter authenticates the GSP image, so
   both must be the same version. Switch off the 595.80 monolithic `gsp_ga10x.bin`
   to the self-consistent **570.144 split set** (`gsp-570.144` + `bootloader-570.144`
   + `booter_load-570.144` + `booter_unload-570.144`, all staged in scratchpad/fw).
2. **HS-patch the booter** (`parse_hs_ucode` gives the container): read
   `nvfw_hs_header_v2`, patch the selected production signature at `patch_loc`
   (`nvkm_falcon_fw_sign`); `boot_addr = start_tag << 8`.
3. **Reset SEC2 falcon**, DMA-load booter code(secure)/data into SEC2 IMEM/DMEM
   from sysmem: per transfer write `DMATRFBASE(0x110)=phys>>8`, `DMATRFBASE1(0x128)=0`,
   `DMATRFMOFFS(0x114)=dst`, `DMATRFFBOFFS(0x11c)=src`, `DMATRFCMD(0x118)=cmd`
   (`cmd=(ilog2(len)-2)<<8`, `|0x10`=IMEM, `|0x4`=secure); poll `0x118 & 0x2`=idle.
4. **BROM sig regs** (addr2=0x1000): `0x841210`=dmem_sign, `0x84119c`=engine_id,
   `0x841198`=ucode_id, `0x841180`=1 (enable).
5. **Kick**: `MAILBOX0(0x840040)=wpr_meta_phys_lo`, `MAILBOX1(0x840044)=hi`,
   `BOOTVEC(0x840104)=boot_addr`, `CPUCTL(0x840100)=0x2` (STARTCPU).
6. **Poll**: SEC2 `CPUCTL(0x840100) & 0x10` (HALTED, 2s); success iff
   `MAILBOX0(0x840040)==0`. The booter has now set up WPR2 **and booted the GSP
   RISC-V itself** (CPU does NOT touch GSP BCR_CTRL/CPUCTL).
7. **Verify GSP RISC-V active**: write `gsp.boot.app_version` to GSP falcon
   `0x110080`; check GSP `0x111388 & 0x80` (RISC-V active).
8. **Fill `GspFwWprMeta` fully** (P1.5b has magic/radix3; add the WPR2 FB-layout
   fields: `gspFwWprStart/HeapOffset/HeapSize/gspFwOffset/bootBinOffset/frtsOffset/
   frtsSize` = FB physical addrs at top of FB, 128KB-aligned; `sysmemAddrOf*` =
   host DMA addrs). Bootloader code/data/manifest offsets from `bootloader-570.144`.
9. **RPC msgqueue** (P1.6): shared region = 2× `0x40000` (cmd+status); tx header
   `version=0,size=0x40000,entryOff=0x1000,msgSize=0x1000,writePtr=0,flags=1`;
   deliver `sharedMemPhysAddr`+offsets via the `GSP_ARGUMENTS_CACHED` rmargs page.
10. **Boot-done** (P1.7): block until a status-queue RPC arrives with
    `function == 0x1001` (`NV_VGPU_MSG_EVENT_GSP_INIT_DONE`) and `rpc_result==0`.

Risk: version-locked, HS-signed, silent-fail, no HW debug. This is the
multi-week core; nova-core/nouveau r535 are the reference impls.

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

- **P1.3 (reset/control) — DONE, verified on A5000.** `gsp::reset()` performs the
  GA10x falcon reset (`kflcnResetIntoRiscv_GA102` steps 1–3): pre-reset wait on
  `HWCFG2.RESET_READY` (bit 31), toggle `NV_PGSP_FALCON_ENGINE.RESET` (0x1103c0
  bit 0) with the 10-read-back propagation delay, poll `DMACTL` (bits 1,2) for
  scrub-done. Real-HW finding: after reset the **Falcon front-end PRI-locks**
  (`CPUCTL/DMACTL = 0xbadf5620`, the `0xbadf____` lockdown sentinel) as the core
  drops into RISC-V mode — expected GA10x behavior; the RISC-V window stays live
  (`RISCV_CPUCTL=0x10`, halted). `reset_ready` never sets (HW erratum, non-fatal,
  matches the RM). Container test still passes after reset (GPU undisturbed).
  The BROM kick (`BCR_CTRL=0x111`) is deferred to P1.5 (needs firmware in WPR).
  Register bitfields cited in `gsp.rs`.

  *Milestone renumber:* remaining steps are P1.4 firmware delivery + ELF parse,
  P1.5 WPR2 + firmware DMA, P1.6 RPC msgqueue, P1.7 BROM kick + `GSP_INIT_DONE`.

- **P1.4 — DONE, verified on A5000 (commit `92c4b3281`).** `fw.rs` — a no_std
  ELF64 section-header parser — locates the GSP-RM container's `.fwimage`,
  `.fwversion`, `.fwsignature*`. The kernel reads the firmware from the initramfs
  in `device::init_in_first_process` (post-rootfs; the probe is far too early).
  Verified with the real `gsp_ga10x.bin` (595.80) baked into the initramfs:
  kernel read 72,861,680 bytes, decoded machine `0xf3` (RISC-V), 17 sections, 10
  signatures, `.fwimage`=72,818,688 bytes, `.fwversion`="595.80". C-free.

**Front half of GSP boot (read state → reset → deliver firmware → parse) is DONE
and hardware-verified.** Remaining is the deep, version-locked back half:

- **P1.5a — DONE, verified on A5000 (commit `480fd9456`).** The guest-DMA
  substrate: `gsp::stage_firmware_dma()` allocates a DMA-coherent sysmem buffer
  (ostd `DmaCoherent`), copies the parsed `.fwimage` in, and exposes its
  GPU-visible guest-physical address. No guest vIOMMU → `daddr == GPA`, exactly
  where the GSP booter/RISC-V core reads firmware. Verified: full 72,818,688-byte
  `.fwimage` staged at GPU-phys `0x230000000`, round-trip `verified=true`. The
  passed-through GPU can now DMA the firmware from sysmem.

- **P1.5b/c (the version-locked core, in progress):** allocate WPR2 in VRAM; build the
  `GspFwWprMeta` descriptor (magic `0xdc3aae21371a60b3`, rev 1); build radix3
  page tables for `.fwimage`; run the `booter_load` HS ACR ucode on SEC2 (base
  `0x840000`) to authenticate + place the image in WPR2; DMA it in. This needs
  **guest-DMA infrastructure** (DMA-able buffers + GPU-visible physical addrs via
  the vfio IOMMU) and the version-locked descriptor/booter ABI. Not verifiable in
  small increments — WPR + booter + DMA must all land before anything observable.
- **P1.6:** RPC message queue (shared-mem cmd/status rings, MCTP/NVDM framing,
  checksum/seqNum) — `msgqTxHeader`/`GSP_MSG_QUEUE_ELEMENT`/`rpc_message_header_v`.
- **P1.7:** program libos boot args, write `BCR_CTRL=0x111` (CORE_SELECT_RISCV |
  VALID | BRFETCH), poll for `GSP_INIT_DONE` on the status queue = **GSP booted.**

## Test rig

The A5000 (Ampere/GSP) on the Precision laptop is the P1 dev target (display on
the iGPU, so the GPU frees to vfio via runtime teardown — see
`asterkube/scripts/a5000-bind-vfio.sh` + `a5000-boot.sh`). No reboots (all
machines are LUKS-encrypted); prefer runtime teardown.
