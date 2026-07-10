// SPDX-License-Identifier: MPL-2.0

pub mod cpu;
mod power;
mod power_button;
pub mod ptrace;
pub mod signal;

pub fn init() {
    power::init();
}

/// Late architecture init that must run after the scheduler and process system
/// are up (it spawns a kernel thread). Called from the kernel init sequence.
pub fn init_late() {
    power_button::init();
}
