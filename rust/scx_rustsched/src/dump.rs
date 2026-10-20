// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The scheduler's lines in the kernel's debug dump, which the kernel
//! takes when it ejects the scheduler and the loader prints: ops.dump()
//! for the scheduler as a whole, ops.dump_cid() for each CID and
//! ops.dump_task() for each runnable task call `dump!`.

use crate::{config, kfuncs::scx_bpf_dump_bstr, ops::scx_dump_ctx, uei::field};

/// When the dump was taken, the first argument of the dump callbacks.
#[repr(transparent)]
pub struct DumpCtx(scx_dump_ctx);

impl DumpCtx {
    /// # Safety
    /// `dump` must be the context the kernel passed to a dump callback.
    #[inline(always)]
    pub unsafe fn from_ptr<'dump>(dump: *mut scx_dump_ctx) -> &'dump DumpCtx {
        unsafe { &*dump.cast::<DumpCtx>() }
    }

    /// The time of the dump on `time::now()`'s clock, in nanoseconds.
    #[inline(always)]
    pub fn at_ns(&self) -> u64 {
        unsafe {
            field(
                (self as *const DumpCtx).cast(),
                config::get(config::DUMP_AT_NS),
            )
        }
    }

    /// The time of the dump in jiffies, the clock of `Task::runnable_at()`.
    #[inline(always)]
    pub fn at_jiffies(&self) -> u64 {
        unsafe {
            field(
                (self as *const DumpCtx).cast(),
                config::get(config::DUMP_AT_JIFFIES),
            )
        }
    }
}

/// A format as scx_bpf_dump_bstr() takes it: NUL-terminated, in writable
/// data, since the kfunc's parameter is a plain char pointer.
pub const fn format<const N: usize>(text: &str) -> [u8; N] {
    let bytes = text.as_bytes();
    assert!(bytes.len() < N);
    let mut format = [0; N];
    let mut index = 0;
    while index < bytes.len() {
        format[index] = bytes[index];
        index += 1;
    }
    format
}

/// # Safety
/// `format` must be a NUL-terminated format with one conversion for each
/// value of `data`, and the caller a dump callback.
#[inline(always)]
pub unsafe fn line<const N: usize>(format: *mut u8, data: &[u64; N]) {
    unsafe { scx_bpf_dump_bstr(format, data.as_ptr(), (N * 8) as u32) };
}

/// Add a line to the debug dump, from a dump callback:
///
/// ```ignore
/// scx::dump!("vtime=%llu weight=%llu", state.vtime.get(), task.weight());
/// ```
///
/// The format is the kernel's printf, and every value is passed as a
/// `u64`, so the conversions are `%llu`, `%lld` and `%llx`. There must be
/// at least one value. The line's end is added.
#[macro_export]
macro_rules! dump {
    ($format:literal, $($value:expr),+ $(,)?) => {{
        const LEN: usize = $format.len() + 2;
        #[unsafe(link_section = ".data.dumpfmt")]
        static mut FORMAT: [u8; LEN] = $crate::dump::format::<LEN>(concat!($format, "\n"));
        let data = [$($value as u64),+];
        #[allow(unused_unsafe)]
        unsafe {
            $crate::dump::line((&raw mut FORMAT).cast(), &data)
        }
    }};
}
