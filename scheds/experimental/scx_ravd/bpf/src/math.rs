// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! LAVD's arithmetic, as functions of numbers alone: the averages, the
//! logarithm, the latency criticality, the greedy penalty, the virtual
//! deadline and the time slice. The policy modules feed them what they
//! read from tasks and CPUs.
//!
//! Nothing here touches the kernel or the arena, so tests/math.rs builds
//! this file on the host and checks it.

use crate::lavd::*;

/// __calc_avg(): an exponential weighted moving average in which `old`
/// keeps 1 - 1/2^decay. Values too small for the shift move by halves.
#[inline(always)]
pub fn ewma(old: u64, new: u64, decay: u32) -> u64 {
    let threshold = 1 << decay;
    if old < threshold || new < threshold {
        if old == 1 && new == 0 {
            0
        } else {
            (old - (old >> 1)) + (new >> 1)
        }
    } else {
        (old - (old >> decay)) + (new >> decay)
    }
}

/// calc_avg(): 0.875 * old + 0.125 * new.
#[inline(always)]
pub fn calc_avg(old: u64, new: u64) -> u64 {
    ewma(old, new, 3)
}

/// calc_asym_avg(): rise fast, decay slowly.
#[inline(always)]
pub fn calc_asym_avg(old: u64, new: u64) -> u64 {
    if old < new {
        ewma(new, old, 2)
    } else {
        ewma(old, new, 3)
    }
}

/// calc_avg_freq(): the average of a frequency per second, with a new
/// interval measured.
#[inline(always)]
pub fn calc_avg_freq(old_freq: u64, interval: u64) -> u64 {
    let new_freq = LAVD_TIME_ONE_SEC.checked_div(interval).unwrap_or(0);
    ewma(old_freq, new_freq, 3)
}

#[inline(always)]
fn log2_u32(value: u32) -> u32 {
    let mut v = value;
    let mut r = u32::from(v > 0xffff) << 4;
    v >>= r;
    let mut shift = u32::from(v > 0xff) << 3;
    v >>= shift;
    r |= shift;
    shift = u32::from(v > 0xf) << 2;
    v >>= shift;
    r |= shift;
    shift = u32::from(v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r | (v >> 1)
}

/// log2_u64() of common.bpf.h, which lavd's log2x() is: one more than the
/// floor of the logarithm, and 1 for 0.
#[inline(always)]
pub fn log2x(value: u64) -> u64 {
    let high = (value >> 32) as u32;
    u64::from(if high != 0 {
        log2_u32(high) + 32 + 1
    } else {
        log2_u32(value as u32) + 1
    })
}

/// time_delta(): `after - before`, 0 if the clock went back.
#[inline(always)]
pub fn time_delta(after: u64, before: u64) -> u64 {
    after.saturating_sub(before)
}

/// A load weight, 1024 at nice 0, as sched_ext gives it in p->scx.weight:
/// 100 at nice 0, within [1, 10000]. lavd's arithmetic is calibrated to it.
#[inline(always)]
pub fn scx_weight_of(weight: u64) -> u64 {
    ((weight * 100 + 512) / 1024).clamp(1, 10_000)
}

/// The latency criticality of a task from its factors, the core of
/// calc_lat_cri(): `wait_ft`, `wake_ft`, `runtime_ft` and `weight_ft`,
/// and what its waker and wakees handed over, `giver`. Returns the
/// criticality, in 16 bits as lavd keeps it, and log2x(wait * wake),
/// which the performance criticality reuses.
#[inline(always)]
pub fn lat_cri_of(
    wait_ft: u64,
    wake_ft: u64,
    runtime_ft: u64,
    weight_ft: u64,
    giver: u64,
) -> (u64, u64) {
    // Waking and waiting frequencies say how much the task is a producer
    // and a consumer: both high is the middle of a task chain. The ratio
    // follows an exponentially skewed distribution: take the logarithm.
    let log_wwf = log2x(wait_ft.saturating_mul(wake_ft));
    let mut lat_cri = log_wwf + log2x(runtime_ft.saturating_mul(weight_ft));

    // Amplify, to tell latency-critical tasks from the others.
    lat_cri *= lat_cri;

    // Forward propagation keeps the waker's momentum into the wakee, and
    // backward propagation boosts a low-priority waker the next time,
    // priority inversion. It decays geometrically and is capped, so that
    // a cycle cannot inflate it without bound.
    if giver > 2 * lat_cri {
        let giver_inh = (giver - 2 * lat_cri) >> LAVD_LC_INH_GIVER_SHIFT;
        let receiver_max = lat_cri >> LAVD_LC_INH_RECEIVER_SHIFT;
        lat_cri += giver_inh.min(receiver_max);
    }
    (lat_cri & 0xffff, log_wwf)
}

/// The reverse runtime factor: the shorter the invariant runtime, the
/// more latency-critical.
#[inline(always)]
pub fn reverse_runtime_factor(avg_runtime_invr: u64) -> u64 {
    if LAVD_LC_RUNTIME_MAX > avg_runtime_invr {
        return (LAVD_LC_RUNTIME_MAX - avg_runtime_invr) / LAVD_SLICE_MIN_NS_DFL + 1;
    }
    1
}

/// What calc_greedy_penalty() decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Greedy {
    /// The deadline penalty, in [1024, 2048]: 100% to 200%.
    pub penalty: u64,
    /// Has the task had more than its share?
    pub greedy: bool,
    /// The service time a long sleeper is brought up to, so that it is
    /// owed no more than lag_max.
    pub svc_time_iwgt: u64,
}

/// calc_greedy_penalty(): the lag of a task with `svc_time_iwgt` against
/// the system's average `avg`, bound by `lag_max`.
#[inline(always)]
pub fn greedy_penalty(avg: u64, svc_time_iwgt: u64, lag_max: u64) -> Greedy {
    let lag_max = lag_max.max(1);
    let lag_max_signed = lag_max as i64;
    let mut lag = avg.wrapping_sub(svc_time_iwgt) as i64;
    let mut svc = svc_time_iwgt;
    let greedy = lag < 0;
    if !greedy {
        // A long sleeper is not owed more than lag_max.
        if lag > lag_max_signed {
            svc = avg.wrapping_sub(lag_max);
            lag = lag_max_signed;
        }
    } else if lag < -lag_max_signed {
        // A debt is paid back gradually.
        lag = -lag_max_signed;
    }
    let penalty = (((lag_max_signed - lag) as u64) << LAVD_SHIFT)
        .checked_div(lag_max)
        .unwrap_or(0);
    Greedy {
        penalty: LAVD_SCALE + (penalty >> LAVD_LC_GREEDY_SHIFT),
        greedy,
        svc_time_iwgt: svc,
    }
}

/// calc_virtual_deadline_delta() from its parts: how far ahead of the
/// logical clock the deadline is. A task that just woke, little
/// `acc_runtime_invr`, is preferred over one that has run without a
/// break, within a bound so that CPU-bound tasks do not starve.
#[inline(always)]
pub fn deadline_delta(acc_runtime_invr: u64, penalty: u64, lat_cri: u64) -> u64 {
    let adjusted_runtime = LAVD_ACC_RUNTIME_MAX + acc_runtime_invr.min(LAVD_ACC_RUNTIME_MAX);
    let deadline = adjusted_runtime * penalty;
    deadline.checked_div(lat_cri).unwrap_or(deadline) >> LAVD_SHIFT
}

/// calc_compete_window(): it shrinks with how oversubscribed the system
/// is, so that the logical clock is not held back.
#[inline(always)]
pub fn compete_window(nr_queued: u64, nr_cpus: u64) -> u64 {
    if nr_queued > nr_cpus {
        return (LAVD_DL_COMPETE_WINDOW * nr_cpus)
            .checked_div(nr_queued)
            .unwrap_or(0);
    }
    LAVD_DL_COMPETE_WINDOW
}

/// The step of advance_cur_logical_clk(): toward `deadline`, slower the
/// more tasks wait. The clock does not go back.
#[inline(always)]
pub fn advance_clock(clock: u64, deadline: u64, nr_queued: u64) -> u64 {
    if (clock.wrapping_sub(deadline) as i64) >= 0 {
        return clock;
    }
    let step = deadline.wrapping_sub(clock);
    clock.wrapping_add(step.checked_div(nr_queued).unwrap_or(step))
}

/// calc_sys_time_slice() without the averaging: a slice to run every
/// queued task once within the targeted latency on the active CPUs.
#[inline(always)]
pub fn sys_time_slice(nr_queued: u64, nr_active: u64, min: u64, max: u64) -> u64 {
    match (LAVD_TARGETED_LATENCY_NS * nr_active).checked_div(nr_queued) {
        Some(slice) => slice.max(min).min(max.max(min)),
        None => max,
    }
}

/// The latency criticality a task needs to preempt another: within the
/// top 1/2^shift of the spread between the average and the maximum.
#[inline(always)]
pub fn thr_lat_cri(max: u64, avg: u64, shift: u64) -> u64 {
    max - (max.saturating_sub(avg) >> shift.min(63))
}

/// update_thr_perf_cri(): the performance criticality above which a task
/// goes to a big core, so that the big cores' share of the capacity,
/// `big_core_scale` of 1024, gets that share of the tasks.
#[inline(always)]
pub fn thr_perf_cri(big_core_scale: u64, min: u64, avg: u64, max: u64) -> u64 {
    if big_core_scale == 0 {
        return max;
    }
    if big_core_scale >= LAVD_SCALE {
        return 0;
    }
    let little_core_scale = LAVD_SCALE - big_core_scale;
    if little_core_scale < p2s(50) {
        min + (avg.saturating_sub(min) * little_core_scale) / (LAVD_SCALE >> 1)
    } else {
        avg + (max.saturating_sub(avg) * (little_core_scale - p2s(50))) / (LAVD_SCALE >> 1)
    }
}
