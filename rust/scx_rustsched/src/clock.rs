// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! rq_clock_task(): the clock update_curr() charges service in. It is the
//! runqueue's clock less the IRQ and steal time that CPU has lost, so a
//! task is not charged for interrupts that land on its CPU, or for time a
//! hypervisor took from its vCPU.
//!
//! Everything in a CID's virtual time is in its task clock: the stamp a
//! run is charged from, the projections of the running task's progress,
//! the distance an hrtick waits for. Everything measured between CPUs
//! stays on the rq clock, scx_bpf_now(): running averages, cache hotness,
//! idle time, balance intervals.
//!
//! The task clock is read only by an op that holds the runqueue's lock,
//! owned(), which also records its offset from the rq clock. Everything
//! else converts the rq clock it holds through that offset, at(), and never
//! touches another CPU's runqueue. The offset moves by the interrupt time
//! the CPU takes between two owned reads. NO_TASK_CLOCK charges wall
//! time instead: both return `now`.
//!
//! The clock is rq->clock_task, read through the per-CPU runqueues ksym at
//! the offset the loader takes from kernel BTF, so no layout is assumed.

use core::{ffi::c_void, hint::black_box, ptr::read_volatile};

use crate::{cids, config, helpers};

// The per-CPU runqueues, read as a ksym, see build.rs.
unsafe extern "C" {
    static runqueues: u8;
}

/// The rq clock less the task clock at `cid`'s last owned read, which
/// capacity pressure follows the growth of too.
#[inline(always)]
pub fn offset(cid: i32) -> u64 {
    cids::get(cid, cids::CLOCK_OFF)
}

#[inline(always)]
fn enabled() -> bool {
    config::get(config::RUNTIME_OPTIONS) & config::runtime::NO_TASK_CLOCK == 0
}

/// rq_clock_task() of `cid`'s CPU, read in the raw, `now` if unreadable.
#[inline(always)]
unsafe fn read(cid: i32, now: u64) -> u64 {
    unsafe {
        let offset = config::get(config::RQ_CLOCK_TASK).min(1 << 20) as usize;
        let base = black_box(&raw const runqueues).cast::<c_void>();
        if offset == 0 || base.is_null() {
            return now;
        }
        let runqueue: *const u8 = helpers::per_cpu_ptr(base, crate::cid_idle::cpu(cid) as u32);
        if runqueue.is_null() {
            return now;
        }
        let clock = read_volatile(runqueue.add(offset).cast::<u64>());
        if clock == 0 || clock > now {
            return now;
        }
        clock
    }
}

/// The task clock of `cid` at `now`, its rq clock, from an op holding that
/// runqueue's lock, cid_clock_task_owned(); the offset is recorded for
/// at(). With NO_TASK_CLOCK, `now`. Always records the offset for
/// capacity pressure, which counts its growth as IRQ and steal time.
pub unsafe fn owned(cid: i32, now: u64) -> u64 {
    if !cids::valid(cid) {
        return now;
    }
    unsafe {
        let clock = read(cid, now);
        cids::set(cid, cids::CLOCK_OFF, now - clock);
        if enabled() { clock } else { now }
    }
}

/// The task clock of `cid` at `now`, its rq clock, through the offset the
/// last owned read recorded, cid_clock_task_at().
#[inline(always)]
pub fn at(cid: i32, now: u64) -> u64 {
    if !enabled() || !cids::valid(cid) {
        return now;
    }
    now.saturating_sub(offset(cid))
}
