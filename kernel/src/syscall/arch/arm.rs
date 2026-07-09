// SPDX-License-Identifier: MPL-2.0

//! System call dispatch in the ARM (ARMv7-A) architecture.
//!
//! NOTE: For this proof-of-concept port we reuse the Linux `asm-generic`
//! unified system-call table (as AArch64/RISC-V/LoongArch do), rather than the
//! ARM legacy `arch/arm` numbering. The custom `no_std` `/init` used to
//! demonstrate userspace issues the matching generic numbers via `svc`.
//!
//! TODO: Provide the real ARM EABI system-call table so that stock ARM
//! binaries (e.g. musl) run unmodified.

#[path = "./generic.rs"]
mod generic;

generic::define_syscalls_with_generic_syscall_table! {
    // TODO: Add ARM-specific syscalls here.
}
