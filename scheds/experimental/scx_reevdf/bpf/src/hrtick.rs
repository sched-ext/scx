// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! A per-CID hrtick: a timer that ends the running task's request on time.
//!
//! A request is otherwise only enforced from the tick: a task whose request
//! runs out between two ticks holds the CPU until the next one, and a task
//! that woke behind it and lost the preemption test waits that long. fair.c
//! arms an hrtimer for exactly this, HRTICK, at every pick with company and
//! whenever a task joins a lone runner. sched_ext has none, so this is a
//! bpf_timer per CID. It fires at the running task's deadline and kicks the
//! CPU if the CID still has something queued, which is the reschedule; the
//! dispatch that follows asks keep_running(), which is the pick.
//!
//! Every op runs with interrupts off, so Timer::start() cannot touch the
//! hrtimer from there: bpf_timer_start() queues an irq_work, a self-IPI per arming. That is
//! why it is armed only with company, and why a timer that is already due
//! early enough is left alone. The timer cannot be cancelled from an op
//! either, so one left behind by a task that blocked fires once for nothing.
//!
//! Counterpart in scx_eevdf: preempt.bpf.c.

use scx_rustsched::sched::Cid;
use scx_rustsched::sched::KickFlags;
use scx_rustsched::time;

use crate::{
    accounting::time_before,
    pack,
    timer::{Timer, TimerMap},
};

/// Shortest an hrtick is armed for, as hrtick_start() in core.c floors it.
const HRTICK_MIN_NS: u64 = 10_000;

// One hrtick per CID. The loader sizes it to the CID space.
scx_rustsched::timer_map!(pub hrticks: HrtickMap, entries: 1, callback: fire);

/// Does `cid` have a task queued behind the one it runs?
#[inline(always)]
fn has_company(cid: Cid) -> bool {
    cid.has_queued()
}

/// Set up `cid`'s timer, from `init`.
pub fn init(cid: Cid) -> i32 {
    HrtickMap::init(cid.index())
}

/// Arm `cid`'s hrtick for the deadline of the task running there, or kick
/// it if that deadline has passed, hrtick_start_fair(). Callers check that
/// the CID has company.
pub fn start(cid: Cid, now: u64) {
    if !crate::features::hrtick() || !pack::running(cid) {
        return;
    }
    let delta = pack::curr_deadline_in(cid, now);
    if delta == 0 {
        cid.kick(KickFlags::PREEMPT);
        return;
    }
    let delta = delta.max(HRTICK_MIN_NS);
    let at = now + delta;
    pack::pack(cid).hrtick_due().set(at);
    pack::pack(cid)
        .hrtick_run_at()
        .set(pack::curr_charged_at(cid));
    // A timer still pending for no later than this fires early for this
    // task and is armed again for the deadline from there, for nothing.
    // Moving it from here is an irq_work and a self-IPI every time.
    let armed = pack::pack(cid).hrtick_at().get();
    if time_before(now, armed) && !time_before(at + HRTICK_MIN_NS, armed) {
        return;
    }
    let Some(hrtick) = HrtickMap::get(cid.index()) else {
        return;
    };
    pack::pack(cid).hrtick_at().set(at);
    hrtick.start(delta);
}

/// `cid`'s hrtick fired: ask the running task to give the CPU up if it has
/// company and its request is due, hrtick() in core.c. A timer that fires
/// early for the run it was armed for, or that a newer pick has outlived,
/// is armed again for the running task's deadline, which can be done here
/// directly with interrupts on.
fn fire(key: u32, hrtick: &Timer) {
    let cid = Cid(key as i32);
    if !pack::valid(cid) || !pack::running(cid) || !has_company(cid) {
        return;
    }
    let now = time::now();
    // The due time stands for the run it was armed for, which is asked
    // to reschedule when it comes, as entity_tick() does for a queued
    // tick. A timer left from another run measures the running task's
    // own distance to its deadline instead.
    let delta = if pack::pack(cid).hrtick_run_at().get() == pack::curr_charged_at(cid) {
        pack::pack(cid).hrtick_due().get().wrapping_sub(now) as i64
    } else {
        pack::curr_deadline_in(cid, now) as i64
    };
    if delta > HRTICK_MIN_NS as i64 {
        pack::pack(cid).hrtick_at().set(now + delta as u64);
        hrtick.start(delta as u64);
        return;
    }
    cid.kick(KickFlags::PREEMPT);
}

/// Arm `cid`'s hrtick if it has company, for a pick or a wakeup that queued
/// behind the running task, set_next_task_fair() and hrtick_update().
#[inline(always)]
pub fn start_with_company(cid: Cid, now: u64) {
    if has_company(cid) {
        start(cid, now);
    }
}
