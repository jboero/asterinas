// SPDX-License-Identifier: MPL-2.0

//! `/dev/nvidia0` — a userspace-facing window onto a passed-through NVIDIA GPU.
//!
//! The `aster-nvidia` component probes the GPU and retains its BAR1 VRAM-window
//! `IoMem` (see [`aster_nvidia::vram_io_mem`]). This module wraps that aperture
//! in a character device so an ordinary userspace process — including one
//! confined to a container — can `open("/dev/nvidia0")` and `read`/`write`/`mmap`
//! GPU memory. This is the C-free, GSP-independent path to *using* the GPU from
//! a container; it works on any enumerated GPU (Kepler through Ampere), unlike
//! the full CUDA/RM stack which needs GSP (Turing+).
//!
//! Structurally identical to the framebuffer device ([`super::fb`]): both expose
//! a PCI-BAR `IoMem` via read/write and `Mappable::IoMem`.

use device_id::{DeviceId, MajorId, MinorId};
use ostd::mm::HasSize;

use super::{Device, DeviceType, DevtmpfsInodeMeta, registry::char};
use crate::{
    events::IoEvents,
    fs::{
        file::{Mappable, PerOpenFileOps, StatusFlags, mkmod},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

/// The GPU character device (`/dev/nvidia0`). Linux uses major 195 for NVIDIA.
#[derive(Debug)]
struct NvidiaGpu0;

/// A per-open handle holding a clone of the GPU's BAR1 VRAM-window `IoMem`.
#[derive(Debug)]
struct NvidiaGpu0Handle {
    vram: ostd::io::IoMem,
}

impl Device for NvidiaGpu0 {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        // Same major as Linux's NVIDIA driver (195); minor 0 = first GPU.
        DeviceId::new(MajorId::new(195), MinorId::new(0))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        // Read+write so a container process can both read and write GPU VRAM
        // (and map it writably).
        Some(DevtmpfsInodeMeta::with_mode("nvidia0", mkmod!(a+rw)))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let Some(vram) = aster_nvidia::vram_io_mem() else {
            return Err(Error::with_message(
                Errno::ENODEV,
                "no NVIDIA GPU VRAM aperture is present",
            ));
        };
        Ok(Box::new(NvidiaGpu0Handle { vram }))
    }
}

impl Pollable for NvidiaGpu0Handle {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        (IoEvents::IN | IoEvents::OUT) & mask
    }
}

impl FileOps for NvidiaGpu0Handle {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if !writer.has_avail() {
            return Ok(0);
        }
        let size = self.vram.size();
        if offset >= size {
            return Ok(0);
        }
        let len = writer.avail().min(size - offset);
        if len == 0 {
            return Ok(0);
        }
        let mut new_writer = writer.clone_exclusive();
        new_writer.limit(len);

        let copied = match self.vram.read_fallible(offset, &mut new_writer) {
            Ok(copied) => copied,
            Err((_err, copied)) if copied > 0 => copied,
            Err((err, _)) => return Err(err.into()),
        };
        writer.skip(copied);
        Ok(copied)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if !reader.has_remain() {
            return Ok(0);
        }
        let size = self.vram.size();
        if offset >= size {
            return_errno_with_message!(Errno::ENOSPC, "the write offset is beyond GPU VRAM");
        }
        let len = reader.remain().min(size - offset);
        if len == 0 {
            return Ok(0);
        }
        let mut new_reader = reader.clone();
        new_reader.limit(len);

        let copied = match self.vram.write_fallible(offset, &mut new_reader) {
            Ok(copied) => copied,
            Err((_err, copied)) if copied > 0 => copied,
            Err((err, _)) => return Err(err.into()),
        };
        reader.skip(copied);
        Ok(copied)
    }
}

impl PerOpenFileOps for NvidiaGpu0Handle {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }

    fn mappable(&self) -> Result<Mappable> {
        // Map the GPU's VRAM window straight into the process address space.
        Ok(Mappable::IoMem(self.vram.clone()))
    }
}

pub(super) fn init_in_first_kthread() {
    if aster_nvidia::vram_io_mem().is_none() {
        return;
    }
    char::register(Arc::new(NvidiaGpu0)).expect("failed to register /dev/nvidia0 char device");
}
