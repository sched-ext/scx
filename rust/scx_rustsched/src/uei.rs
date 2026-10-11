// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! What the scheduler leaves behind when it exits, as scx's UEI_RECORD()
//! records it: ops.exit() copies the kernel's exit record, struct
//! scx_exit_info, into UEI, laid out as scx's struct user_exit_info, and
//! the debug dump into UEI_DUMP, which the loader sizes to the dump length
//! the ops ask for. The loader reports both the way scx_utils'
//! UserExitInfo::report() does. The field offsets come from kernel BTF.

use core::{
    intrinsics::{AtomicOrdering, atomic_xchg},
    ptr::read_volatile,
};

use crate::{config, helpers};

/// UEI_REASON_LEN and UEI_MSG_LEN, and SCX_EXIT_DUMP_DFL_LEN.
const REASON_LEN: usize = 128;
const MSG_LEN: usize = 1024;
pub const DUMP_LEN: usize = 32768;

/// CONFIG words: offsets in struct scx_exit_info of exit_cpu plus one (0
/// when the kernel has none), exit_code, reason, msg and dump; the length
/// of UEI_DUMP; offsets of scx_dump_ctx.at_jiffies and .at_ns,
/// task_struct.scx.runnable_at and .pid; and of scx_exit_info.kind.

/// struct user_exit_info.
#[repr(C)]
pub struct UserExitInfo {
    kind: i32,
    exit_cpu: i32,
    exit_code: i64,
    reason: [u8; REASON_LEN],
    msg: [u8; MSG_LEN],
}

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.uei")]
pub static mut UEI: UserExitInfo = UserExitInfo {
    kind: 0,
    exit_cpu: -1,
    exit_code: 0,
    reason: [0; REASON_LEN],
    msg: [0; MSG_LEN],
};

/// The kernel's debug dump, resized by the loader to the dump length.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.uei_dump")]
pub static mut UEI_DUMP: [u8; DUMP_LEN] = [0; DUMP_LEN];

#[inline(always)]
pub unsafe fn field<T: Copy>(base: *const u8, offset: u64) -> T {
    unsafe { read_volatile(base.add(offset as usize).cast::<T>()) }
}

/// bpf_probe_read_kernel_str() of the string `source` into `size` bytes at
/// `destination`.
#[inline(always)]
unsafe fn read_str(destination: *mut u8, size: u32, source: u64) {
    if source == 0 {
        return;
    }
    unsafe { helpers::probe_read_kernel_str(destination.cast(), size, source) };
}

/// UEI_RECORD(): the exit record, with its kind stored last, so that the
/// loader sees the rest once it sees an exit.
#[unsafe(no_mangle)]
#[unsafe(link_section = "struct_ops/exit")]
pub unsafe extern "C" fn rust_exit(context: *const u64) -> u64 {
    crate::pool::touch();
    unsafe {
        let info = *context as *const u8;
        let uei = &raw mut UEI;
        read_str(
            (&raw mut (*uei).reason).cast(),
            REASON_LEN as u32,
            field::<u64>(info, config::get(config::EXIT_REASON)),
        );
        read_str(
            (&raw mut (*uei).msg).cast(),
            MSG_LEN as u32,
            field::<u64>(info, config::get(config::EXIT_MSG)),
        );
        let size = config::get(config::DUMP_LEN) as u32;
        if size != 0 {
            read_str(
                (&raw mut UEI_DUMP).cast(),
                size,
                field::<u64>(info, config::get(config::EXIT_DUMP)),
            );
        }
        (*uei).exit_code = field::<i64>(info, config::get(config::EXIT_CODE));
        let cpu = config::get(config::EXIT_CPU);
        (*uei).exit_cpu = if cpu != 0 {
            field::<i32>(info, cpu - 1)
        } else {
            -1
        };
        atomic_xchg::<i32, { AtomicOrdering::SeqCst }>(
            &raw mut (*uei).kind,
            field::<i32>(info, config::get(config::EXIT_KIND)),
        );
    }
    0
}
