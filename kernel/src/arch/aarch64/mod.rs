// SPDX-License-Identifier: MPL-2.0

pub mod cpu;
pub mod signal;

pub fn init() {}

/// Late architecture init that must run after the scheduler and process system
/// are up. On ARM/AArch64 there is no ACPI power-button monitor wired up yet, so
/// this is a no-op (the astrokube ACPI graceful-shutdown prctl has no effect).
pub fn init_late() {}
