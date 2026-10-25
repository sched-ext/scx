// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The BPF program of scx_reevdf: the sched_ext callbacks and, at the end
//! of the file, the `#[scheduler]` block that registers them.
//!
//! The policy is in the modules. A callback takes its arguments from the
//! kernel, finds the task's context and calls into them:
//!
//! ```text
//! select_cid    where a waking or forked task goes        idle.rs
//! enqueue       place the task in its CID's pack; run it  pack.rs
//!               at once, preempt for it, or queue it      preempt.rs
//! dispatch      keep the running task or take the first   preempt.rs
//!               eligible queued one; when there is none,  balance.rs
//!               take what a balancer chose or pull some   active.rs
//!                                                         newidle.rs
//! running       publish the task as the CID's running one pack.rs
//! stopping      charge the service the task took          pack.rs
//! quiescent     save the task's lag as it leaves its pack pack.rs
//! tick          load and pressure, group weights, cpu.max load.rs
//!               and the two balancers                     pressure.rs
//!                                                         cgroup.rs
//!                                                         bandwidth.rs
//!                                                         balance.rs
//!                                                         active.rs
//! update_idle   mirror the CID's idle state               scx_rustsched's cid_idle
//! init          allocate the per-CID tables and timers
//! init_task     give a task its context, exit_task takes  taskctx.rs
//!               it back
//! ```
//!
//! The remaining callbacks are short: yield, enable, dequeue, set_cmask
//! and core_sched_before here, dump_task in debug.rs, and the cgroup ones
//! in cgroup.rs and bandwidth.rs. ops.exit() is the runtime's.
//!
//! Each callback is a function over the kernel's raw arguments. The
//! `#[scheduler]` block gives each its entry point, which references the
//! arena first, as the verifier needs once per program before any arena
//! access, and converts the typed arguments.
//!
//! The file also has what several modules need of a task's request: its
//! size, task_request(), and the weight the task is queued at,
//! effective_weight().
//!
//! Counterpart in scx_eevdf: main.bpf.c.

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

use scx_rustsched::var::Var;

use scx_rustsched::prelude::{
    Cgroup, CgroupArgs, Cid, DeqFlags, Dsq, DumpCtx, Edq, EnqFlags, Error, InitTaskArgs, Task,
    WakeFlags, dsq,
};
use scx_rustsched::sched::KickFlags;
use scx_rustsched::time;

// The runtime, see rust/scx_rustsched: its modules under the names the policy
// modules use.
pub use scx_rustsched::{
    cid_idle, cid_table, cids, clock, config, helpers, kfuncs, loops, mem, ops, pool, ravg, slots,
    task, task_struct, tiers, timer,
};

mod accounting;
mod active;
mod balance;
mod balance_state;
mod bandwidth;
mod cgroup;
mod debug;
mod features;
mod hrtick;
mod idle;
mod load;
mod newidle;
mod pack;
mod preempt;
mod pressure;
mod taskctx;

pub(crate) use task::{
    SCHED_BATCH, SCHED_IDLE, WEIGHT_IDLEPRIO, allowed_on, pinned, runs_on, task_policy,
    task_queued, task_weight,
};

pub use config::CONFIG;

// The tunables: one for each option of `Opts` in the loader,
// ../src/main.rs, named as the option in upper case, a time in
// microseconds as _NS.
scx_rustsched::opts!();

scx_rustsched::params! {
    /// The kernel has no cgroup callbacks: the loader finds out.
    NO_CGROUP_OPS: bool = false;
}

use crate::idle::Placement;
use accounting::time_before;
use preempt::{keep_charge, keep_running, should_preempt};

scx_rustsched::shared! {
    /// The default request, set by `init`.
    pub static DEFAULT_REQUEST_NS in ".data.slice": Var<u64> = Var::new(0);
}

#[inline(always)]
fn slice_ns() -> u64 {
    DEFAULT_REQUEST_NS.get()
}

/// fair.c's sysctl_sched_base_slice as update_sysctl() scales it: the
/// normalized 700 us times 1 + ilog2(min(nr_cpus, 8)). nr_cpu_ids counts
/// possible CPUs where fair.c counts online ones, which differs only on a
/// machine with fewer than eight possible CPUs and some of them offline.
#[inline(always)]
fn base_slice_ns(nr_cpus: u32) -> u64 {
    let factor = match nr_cpus {
        0..=1 => 1,
        2..=3 => 2,
        4..=7 => 3,
        _ => 4,
    };
    factor * 700_000
}

/// What is left of the task's slice, task_struct.scx.slice.
#[inline(always)]
fn scx_slice(task: &Task) -> u64 {
    task.slice()
}

/// The task's request: sched_attr.sched_runtime when the task set one, which
/// the kernel keeps in se.slice and flags in se.custom_slice, or the default.
#[inline(always)]
pub(crate) fn task_request(task: &Task) -> u64 {
    let request = task.custom_slice();
    if request == 0 { slice_ns() } else { request }
}

/// The request a task's lag is bounded by: the larger of its own and the
/// default, which stands in for cfs_rq_max_slice(), plus a tick.
#[inline(always)]
pub(crate) fn lag_request(task: &Task) -> u64 {
    task_request(task).max(slice_ns()) + config::get(config::TICK_NS)
}

#[inline(always)]
pub(crate) fn prepare_request(task: &Task, state: &taskctx::Context) {
    let mut request = state.request();
    let initial = state.initial().get();
    if request.prepare(
        state.vtime().get(),
        task_request(task),
        effective_weight(task, state),
        initial,
    ) && initial
    {
        state.initial().set(false);
    }
    state.set_request(request);
}

/// What the task weighs in packs: its share of its cgroup hierarchy, or its
/// nice weight outside of one, see cgroup.rs.
#[inline(always)]
pub(crate) fn effective_weight(task: &Task, state: &taskctx::Context) -> u64 {
    cgroup::weight(state, task_weight(task))
}

/// Why the kernel handed `task` back, its SCX_TASK_REENQ_* reason, for an
/// enqueue that is a re-enqueue, or None.
#[inline(always)]
fn reenq_reason(task: &Task, enq_flags: EnqFlags) -> Option<u64> {
    let reenq = config::get(config::ENQ_REENQ);
    if reenq == 0 || enq_flags.raw() & reenq == 0 {
        return None;
    }
    Some(u64::from(task.scx_flags()) & config::get(config::REENQ_MASK))
}

/// Was `task` handed back because a direct dispatch of it was refused,
/// SCX_TASK_REENQ_IMMED? Its CID is still a fine place for it.
#[inline(always)]
fn reenq_immed(task: &Task, enq_flags: EnqFlags) -> bool {
    let reason = config::get(config::REENQ_IMMED);
    reason != 0 && reenq_reason(task, enq_flags) == Some(reason)
}

/// Was `task` pushed off its CID by a higher scheduling class, with slice
/// left, SCX_TASK_REENQ_PREEMPTED? The kernel hands an IMMED task back for
/// that, and the CID is taken for an unknown time.
#[inline(always)]
fn reenq_preempted(task: &Task, enq_flags: EnqFlags) -> bool {
    let reason = config::get(config::REENQ_PREEMPTED);
    reason != 0 && reenq_reason(task, enq_flags) == Some(reason)
}

/// Should ops.enqueue() look for an idle CID for `task`, task_should_migrate()?
/// Only if ops.select_cid() did not place it and it is not running. A wakeup
/// can get here without that call because the kernel queued it on the CPU it
/// was still running on, ttwu_queue_wakelist(): fair.c leaves such a task on
/// the runqueue it is about to have to itself, and so does this. A task
/// that cannot migrate is left to the search, a single test of its own CID.
#[inline(always)]
fn should_migrate(task: &Task, cid: Cid, enq_flags: EnqFlags) -> bool {
    if enq_flags.contains(EnqFlags::WAKEUP)
        && reenq_reason(task, enq_flags).is_none()
        && !pinned(task)
        && cid_idle::allowed_by_mask(task, cid)
    {
        return false;
    }
    !enq_flags.cid_selected() && !task.running()
}

/// Charge the service `task` has taken on `cid` since it started running or
/// was last charged, as update_curr() does, and fold it into its pack and
/// its cgroups' cpu.max. `tnow` is the CID's task clock, see clock.rs.
#[inline(always)]
pub(crate) fn charge(task: &Task, state: &taskctx::Context, cid: Cid, tnow: u64) {
    let now = tnow;
    let delta = now.wrapping_sub(state.last_run_at().get()) as i64;
    if delta > 0 {
        let service = (delta as u64 * accounting::NICE_0_WEIGHT)
            .checked_div(effective_weight(task, state))
            .unwrap_or(0);
        state.vtime().set(state.vtime().get().wrapping_add(service));
        pack::charge(state);
        bandwidth::charge(state, cid, delta as u64);
    }
    state.last_run_at().set(now);
}

/// ops.select_cid(): where a waking or forked task goes, see idle.rs. A
/// task that still owes the pack it blocked in goes back to that CID
/// without a search, as ttwu_runnable() requeues a delayed task. A wakeup
/// that claimed an idle CID is inserted on its local DSQ from here, so
/// that the kernel does not call ops.enqueue() for it.
#[inline(always)]
fn select_cid(task: &Task, previous: Cid, wake_flags: WakeFlags) -> Cid {
    let Some(state) = taskctx::lookup(task) else {
        return previous;
    };
    let now = time::now();
    if wake_flags.contains(WakeFlags::TTWU) {
        load::task_woke(&state, now);
    }
    // A task whose cgroup is out of bandwidth waits for its next
    // period: nothing here is of use to it, and an idle CID woken for it
    // would go back to sleep. Its enqueue puts it aside.
    if bandwidth::throttled(&state, previous, now, false).is_some() {
        return previous;
    }
    // A task still owing the pack it blocked in goes back to it, and is
    // queued there by enqueue, as ttwu_runnable() requeues a delayed
    // task. A changed affinity takes it off that runqueue.
    if let Some(cid) = pack::requeue_cid(&state, effective_weight(task, &state), now)
        && runs_on(task, Cid(cid).cpu())
    {
        return Cid(cid);
    }
    match idle::select_cid(task, &state, previous, wake_flags, now) {
        // A fork placed on a claimed CID is left to enqueue, which
        // joins it to the pack before it inserts it there to run at
        // once: inserted from here it would weigh nothing until it
        // runs, and a burst of forks would all see the same group as
        // the emptiest.
        Placement::Claimed(cid) => {
            if wake_flags.contains(WakeFlags::TTWU) {
                direct_dispatch(task, &state, Cid(cid), now);
            }
            Cid(cid)
        }
        Placement::Queued(cid) => Cid(cid),
    }
}

/// Run a wakee on `cid`, which ops.select_cid() claimed idle for it, at
/// once: straight to the CID's local DSQ from here, so that the kernel
/// does not call ops.enqueue() for it, direct_dispatch_local(). IMMED has
/// the kernel hand the task back through ops.enqueue() if the CPU is taken
/// in the meantime, or if a task is waiting on the CID, which then puts it
/// in deadline order. Testing the CID's queue here instead read a line of
/// the CID's on the waker's path for every claimed wakeup.
///
/// The CID's pack is empty more often than not, and a placement against an
/// empty pack does not depend on what the task weighs, so it is left to
/// ops.running() on the CID, where the pack's lines are the CPU's own.
/// Done from here they were read and written across CPUs on the waker's
/// path. A pack with a member gives the placement an offset, and the task
/// is placed against it here.
#[inline(always)]
fn direct_dispatch(task: &Task, state: &taskctx::Context, cid: Cid, now: u64) {
    if pack::weight(cid) != 0 {
        pack::place(state, cid, lag_request(task), task_weight(task), now, true);
        prepare_request(task, state);
    }
    dsq::insert(
        task,
        Dsq::Local,
        task_request(task),
        EnqFlags(config::get(config::ENQ_IMMED)),
    );
}

/// ops.update_idle(): mirror the CID's idle state in the idle masks, and
/// note when it went idle or that its idle period ended, which the idle
/// pull budgets by, see newidle.rs.
#[inline(always)]
fn update_idle(cid: Cid, idle: bool) {
    cid_idle::update(cid, idle);
    let now = time::now();
    if idle {
        load::set_idle_stamp(cid, now);
        // The tick stops with the CPU: record the empty pack now, or the
        // idle period is averaged in at the weight of the last tick.
        load::cid_load_accumulate(cid, now);
    } else {
        newidle::idle_ended(cid, now);
    }
}

/// Sample the pack's weight into the CID's load average, from the CID's own
/// CPU, as fair.c's PELT updates the runqueue's load from its tick, and
/// pass the CID's utilization on to cpufreq.
#[inline(always)]
fn tick(task: &Task) {
    let cid = task.cid();
    let now = time::now();
    load::cid_load_accumulate(cid, now);
    // A task that keeps the CPU passes through ops.running() only once:
    // refresh the governor from the tick, as task_tick_fair() does
    // through update_load_avg().
    if !DISABLE_CPUFREQ.get() {
        load::update_cpufreq(cid, now, false);
    }
    pressure::update(cid, now);
    newidle::decay(cid, now);
    // The share a task's groups give it moves with the tasks that come
    // and go in them: take the running task over to it, as
    // task_tick_fair() does through update_cfs_group() and
    // reweight_eevdf(), charging what it ran at the old weight first.
    if cgroup::enabled() {
        cgroup::group_sweep(now);
        if let Some(state) = taskctx::lookup(task)
            && let Some(weight) = cgroup::tick(&state, task_weight(task), now)
        {
            keep_charge(task, &state, cid, now);
            pack::reweight(&state, weight, now);
            keep_charge(task, &state, cid, now);
        }
        // Bring the bandwidth of its groups up to date and end its slice
        // if they have run out, entity_tick() asking
        // check_cfs_rq_runtime(). The dispatch that follows gives the
        // task up.
        if bandwidth::enabled()
            && let Some(state) = taskctx::lookup(task)
            && state.group().get().is_some()
        {
            keep_charge(task, &state, cid, now);
            if bandwidth::throttled(&state, cid, now, true).is_some() {
                task.set_slice(0);
            }
        }
    }
    if !balance::tick(cid, now) {
        active::tick(task, cid, now);
    }
}

/// ops.enqueue(): place the task in its CID's pack and decide how it gets
/// to run. A CID with nothing of ours running or queued gets it on its
/// local DSQ at once. Otherwise a task that is not the one that was
/// running is tested for wakeup preemption, see preempt.rs, and a winner
/// goes straight to the local DSQ with SCX_ENQ_PREEMPT_LAZY, or
/// SCX_ENQ_PREEMPT where the kernel lacks it. Everything else goes in the
/// CID's queue.
///
/// A task whose cgroup is out of cpu.max runtime is parked instead, see
/// bandwidth.rs, and a task a balancer asked for is handed to the CID that
/// asked, see active.rs. A task enqueued with SCX_ENQ_LAST, the only work
/// of a CPU going idle, gets an idle peer kicked to pull it if it is alone
/// in the queue, and its own CID kicked otherwise.
#[inline(always)]
fn enqueue(task: &Task, enq_flags: EnqFlags) {
    let cid = task.cid();
    let Some(state) = taskctx::lookup(task) else {
        dsq::insert(task, Dsq::LocalOn(cid), task_request(task), enq_flags);
        return;
    };
    let now = time::now();
    // ops.enqueue() holds the runqueue lock of the task's CID: refresh
    // the clock offset the placement and the preemption test convert by.
    clock::owned(cid, now);
    if enq_flags.contains(EnqFlags::WAKEUP) {
        load::task_woke(&state, now);
    }
    // A task whose cgroup is out of cpu.max bandwidth waits for its
    // next period instead of being queued, before every shortcut below,
    // which all put the task somewhere it would run from.
    if let Some(out) = bandwidth::throttled(&state, cid, now, true)
        && bandwidth::park(task, &state, out, cid, now)
    {
        let _ = state.take_migrate();
        if !enq_flags.contains(EnqFlags::WAKEUP) && task.running() {
            dsq::queued_check(cid);
        }
        return;
    }
    let migrate = state.take_migrate();
    // A proxy-execution donor that has just blocked on a mutex is put back
    // on its own CID with the vruntime and deadline it had, as fair.c
    // leaves it on its runqueue: blocking does not dequeue it there. None
    // of the shortcuts below apply. Each of them moves the task, and only
    // proxy execution moves a donor, to the CID of the mutex owner, where
    // it arrives here again and is queued the same way. The donor's wakeup
    // when the mutex is handed over does not come through here: the task
    // is still queued and only its dispatch is reconsidered.
    let blocked = enq_flags.blocked();
    // A task displaced on a CID capacity pressure reduces joins the
    // queue of the CID chosen for it, in deadline order like any other.
    if let Some((dst, true)) = migrate
        && !blocked
        && !enq_flags.contains(EnqFlags::WAKEUP)
        && dst != cid.raw()
        && cid_idle::allowed_by_mask(task, Cid(dst))
    {
        pack::place(
            &state,
            Cid(dst),
            lag_request(task),
            task_weight(task),
            now,
            false,
        );
        prepare_request(task, &state);
        let deadline = state.deadline().get();
        let request = task_request(task);
        // A task that cannot be queued goes to dst's local DSQ.
        if dsq::insert_deadline(
            task,
            Edq::Cid(Cid(dst)),
            request,
            state.vtime().get(),
            deadline,
            enq_flags,
        ) {
            newidle::note_queued(Cid(dst));
            if Cid(dst).is_idle() {
                Cid(dst).kick(KickFlags::IDLE);
            }
        }
        // The requeue dispatch expected on this CID went elsewhere.
        dsq::queued_check(cid);
        if task.running() {
            pressure::resumed(cid, clock::owned(cid, now));
            pressure::demand(cid, cid.has_queued(), now);
        }
        return;
    }
    // A task an active balance moves goes to its idle destination.
    if let Some((dst, false)) = migrate
        && !blocked
        && !enq_flags.contains(EnqFlags::WAKEUP)
        && active::hand_over(task, &state, Cid(dst), cid)
    {
        prepare_request(task, &state);
        let request = task_request(task);
        dsq::insert(
            task,
            Dsq::LocalOn(Cid(dst)),
            request,
            enq_flags | EnqFlags(config::get(config::ENQ_IMMED)),
        );
        return;
    }
    // A task ops.select_cid() did not place gets the idle search here,
    // and so does one a higher class pushed off a CID that is still
    // busy. A re-enqueue whose direct dispatch was refused stays: its
    // CID is a fine place for it. A CID found idle runs the task at
    // once, IMMED, so the kernel hands it back if the CPU is taken.
    if !blocked
        && ((should_migrate(task, cid, enq_flags) && !reenq_immed(task, enq_flags))
            || (reenq_preempted(task, enq_flags) && scx_slice(task) != 0 && !cid.is_idle()))
    {
        if let Some(dst) = idle::enqueue_pick(task, state, cid, now).get() {
            pack::place(
                &state,
                dst,
                lag_request(task),
                task_weight(task),
                now,
                enq_flags.contains(EnqFlags::WAKEUP),
            );
            prepare_request(task, &state);
            dsq::insert(
                task,
                Dsq::LocalOn(dst),
                task_request(task),
                enq_flags | EnqFlags(config::get(config::ENQ_IMMED)),
            );
            if !enq_flags.contains(EnqFlags::WAKEUP) && task.running() {
                dsq::queued_check(cid);
            }
            return;
        }
    }
    pack::place(
        &state,
        cid,
        lag_request(task),
        task_weight(task),
        now,
        enq_flags.contains(EnqFlags::WAKEUP),
    );
    // A task that is still running and goes back in the queue, at the
    // end of its slice, is the one that would be preempted.
    let displaced = !enq_flags.contains(EnqFlags::WAKEUP) && task.running();
    // A dispatch that takes the head would pick an over-served task
    // that is put back with what is left of its request by its
    // deadline. Reissue it from where the task's vruntime has reached,
    // as update_deadline() does once a request is consumed.
    if displaced
        && features::eligibility()
        && !features::eligible_scan()
        && time_before(pack::reference_at(cid, now), state.vtime().get())
    {
        state.end_request();
    }
    prepare_request(task, &state);
    let deadline = state.deadline().get();
    // A donor goes on with the request it was in, as it does in fair.c,
    // where blocking on the mutex leaves it on the runqueue in the middle
    // of its slice: the deadline was kept by pack::place(), and so is what
    // is left of the slice. One that used its slice up starts a new one,
    // which is where fair.c would have issued a new request.
    let request = if blocked && scx_slice(task) != 0 {
        scx_slice(task)
    } else {
        task_request(task)
    };
    // Insert the winner straight into the local DSQ so the kernel ends
    // the running task's slice under the rq lock. Only while that DSQ is
    // empty: it is FIFO, and a second winner would jump the first
    // without comparing deadlines. A later wakee keeps its order here.
    if !displaced
        && should_preempt(cid, task, &state, deadline, now)
        && dsq::nr_queued(Dsq::LocalOn(cid)) == 0
    {
        // PREEMPT_SHORT overrides the running task's protection, and
        // takes it away: cancel_protect_slice().
        if features::preempt_short() && task_request(task) < pack::curr_request(cid) {
            pack::shorten_protect(cid, now, 0);
        }
        // The reschedule is a lazy one, as fair.c asks for,
        //
        //	preempt:
        //		...
        //		resched_curr_lazy(rq);
        //
        // which follows the kernel's preemption model: under lazy
        // preemption the running task gives the CPU up at its next
        // return to user space or tick, under full preemption at once.
        // Without SCX_ENQ_PREEMPT_LAZY, SCX_ENQ_PREEMPT stands in.
        let preempt = match config::get(config::ENQ_PREEMPT_LAZY) {
            0 => EnqFlags::PREEMPT,
            lazy => EnqFlags(lazy),
        };
        dsq::insert(task, Dsq::LocalOn(cid), request, enq_flags | preempt);
        return;
    }
    // A CID with nothing of ours running and nothing queued, such as one
    // select_cid().raw() claimed idle, runs the task at once: straight to its
    // local DSQ, now that the task weighs in its pack.
    //
    // Not a task enqueued with SCX_ENQ_LAST: its CPU has already picked
    // a lower class and is going idle, and nothing would reschedule it
    // for a task on its local DSQ, which no other CPU can take either.
    // A dispatch that ended the slice for an active balance whose
    // destination was taken in the meantime got there, and the task
    // waited for the watchdog. It is queued instead, as scx_eevdf
    // queues it, and a kick below sees that it is dispatched.
    if !pack::running(cid)
        && !enq_flags.last()
        && !cid.has_queued()
        && dsq::nr_queued(Dsq::LocalOn(cid)) == 0
    {
        dsq::insert(task, Dsq::LocalOn(cid), request, enq_flags);
        return;
    }
    // A task that cannot be queued goes to cid's local DSQ.
    if !dsq::insert_deadline(
        task,
        Edq::Cid(cid),
        request,
        state.vtime().get(),
        deadline,
        enq_flags,
    ) {
        return;
    }
    newidle::note_queued(cid);
    // A task displaced while another runs finds nothing published as
    // running, ops.stopping() having cleared it. One the kernel reports
    // as running while another task runs, as it does for the tasks it
    // puts back on leaving bypass mode after the scheduler attaches,
    // must still have the running task asked again: that one may have
    // been restored with a slice it was never issued. A woken task that
    // lost had it armed by should_preempt().
    if displaced {
        hrtick::start(cid, now);
    }
    // SCX_ENQ_LAST: the CPU has picked the idle task and leaves the
    // follow-up scheduling event to us. A task alone in the queue has
    // an idle peer told to pull it, unbudgeted, so that the CPU it
    // could not run on is not left idle beside it. Without one, the
    // CID itself is kicked: once idle, its dispatch takes the task
    // back. As scx_eevdf does.
    if enq_flags.last() {
        let peer = if cid.nr_queued() == 1 {
            active::idle_peer(task, cid).raw()
        } else {
            -1
        };
        if peer >= 0 && peer != cid.raw() {
            newidle::force_steal(Cid(peer));
            Cid(peer).kick(KickFlags::IDLE);
        } else {
            cid.kick(KickFlags::IDLE);
        }
    }
}

/// Move the first eligible task of `cid`'s own queue to this CPU, or its
/// head without the eligible scan. `requeue` says the task that was
/// running goes back in the queue once this returns.
#[inline(always)]
fn dispatch_own(cid: Cid, requeue: bool) -> bool {
    let head = !features::eligible_scan();
    let reference = pack::reference(cid);
    dsq::move_to_local_with(Edq::Cid(cid), cid, (!head).then_some(reference), requeue)
}

/// ops.dispatch(): the pick. The running task keeps the CPU while it is
/// eligible and no eligible queued task has an earlier deadline, see
/// preempt::keep_running(), and gets a new slice. Otherwise the first
/// eligible task of the CID's own queue runs, or the earliest deadline if
/// none is eligible, to keep the queue moving. With nothing of its own the
/// CID takes what a balancer selected for it, see balance.rs and
/// active.rs, or pulls from its neighbours, see newidle.rs, and rearms its
/// idle bit when it comes back with nothing.
#[inline(always)]
fn dispatch(cid: Cid, prev: Option<&Task>) {
    // A request for a task that is gone is dropped, see active::drop_request().
    if !prev.is_some_and(task_queued) {
        active::drop_request(cid);
    }
    let now = time::now();
    clock::owned(cid, now);
    // Tasks that waited on their cgroup's cpu.max go back in the queues
    // first, so that the pick below sees them.
    if bandwidth::any_parked() {
        bandwidth::bw_unpark(now);
    }
    // A destination kicked for an active balance pulls unbudgeted, and
    // asks for a running task if nothing is queued to pull.
    let kicked = active::take_pending(cid);
    let prev_state = if let Some(prev) = prev
        && task_queued(prev)
    {
        taskctx::lookup(prev)
    } else {
        None
    };
    // An idle destination asked for the task running here: let its
    // slice end, and its enqueue hand it over.
    let mut migrate = false;
    if let Some(state) = &prev_state {
        // A task whose cgroup has run out of bandwidth may not go on,
        // whatever it is owed: its slice ends and its enqueue puts it
        // aside, what check_cfs_rq_runtime() does to the task of a
        // throttled cfs_rq.
        if bandwidth::throttled(state, cid, now, true).is_some() {
            migrate = true;
        } else if let Some(prev) = prev
            && let Some(dst) = active::target(prev, cid).get()
        {
            state.set_migrate(dst);
            migrate = true;
        }
    }
    let keep = match &prev_state {
        Some(state) if !migrate => match prev {
            Some(prev) => keep_running(prev, state, cid, now),
            None => false,
        },
        _ => false,
    };
    // A periodic balance selection drains here, a task at a time and
    // only one that wins this CID's pick against the running task, if
    // that one is in it, and the head of its own queue.
    // The rival is computed only when there is a selection to drain:
    // the head of the queue costs a trylock and a tree walk.
    if balance::pending(cid) {
        let mut rival = 0;
        if keep && let Some(state) = &prev_state {
            rival = state.deadline().get();
        }
        if let Some(head) = preempt::head(cid, pack::reference(cid)).deadline
            && (rival == 0 || time_before(head, rival))
        {
            rival = head;
        }
        if balance::dispatch(cid, rival, now) {
            return;
        }
    }
    if !keep && dispatch_own(cid, prev_state.is_some() && !migrate) {
        return;
    }
    // The running task keeps the CPU, either because it won the pick or
    // because nothing else can run here. It was charged above, and gets
    // another slice to hold the CPU with.
    // Either means there is a previous task: its context was found.
    if migrate {
        if let Some(prev) = prev {
            prev.set_slice(0);
        }
        return;
    }
    if prev_state.is_some() {
        if let Some(prev) = prev {
            prev.set_slice(task_request(prev));
        }
        hrtick::start_with_company(cid, now);
        return;
    }
    if newidle::try_steal(cid, kicked) {
        if kicked {
            active::complete(cid, active::MOVED);
        }
    } else {
        cid_idle::rearm(cid, config::get(config::TASK_FLAGS) as usize);
        if kicked {
            active::request(cid, now);
        } else {
            active::newidle_request(cid, now);
        }
    }
}

/// ops.running(): the task has the CPU. One that runs on a CID other than
/// its pack's moves into this CID's pack, carrying its lag. It is stamped
/// with where its service is charged from and published as the CID's
/// running task, which wakeup preemption reads.
#[inline(always)]
fn running(task: &Task) {
    if let Some(state) = taskctx::lookup(task) {
        let cid = task.cid();
        let now = time::now();
        let tnow = clock::owned(cid, now);
        // A task that belongs to no pack is one whose wakeup a direct
        // dispatch left to this op to place, or a new one; one that
        // belongs to another pack has moved, partway through a request.
        let sleep = state.member().get() == 0;
        let placed = pack::place(
            &state,
            cid,
            lag_request(task),
            task_weight(task),
            now,
            sleep,
        );
        // A task in a group is picked at the share its hierarchy gives
        // it now, set_next_task_fair() running reweight_eevdf(). One
        // placed just above joined at that share. Without this, a task
        // whose runs end before a tick lands keeps the share it joined
        // with for good.
        if !placed
            && let Some(weight) = cgroup::member_weight(&state)
            && weight != state.joined_weight().get()
        {
            pack::reweight(&state, weight, now);
        }
        let weight = effective_weight(task, &state);
        let idle = task_policy(task) == SCHED_IDLE;
        pack::set_class(
            cid,
            idle,
            idle || (state.group().get().is_some() && cgroup::in_idle_group(&state)),
        );
        prepare_request(task, &state);
        state.last_run_at().set(tnow);
        pressure::resumed(cid, tnow);
        pressure::demand(cid, true, now);
        load::task_running(&state, true, now);
        load::cid_running(cid, true, now);
        if !DISABLE_CPUFREQ.get() {
            load::update_cpufreq(cid, now, placed);
        }
        let request = task_request(task);
        pack::publish(cid, &state, weight, request, now, true, cid.min_slice());
        hrtick::start_with_company(cid, now);
    }
}

/// ops.stopping(): charge the time the task ran since it started or was
/// last charged, `delta * NICE_0_WEIGHT / weight`, to its vruntime and to
/// the pack's reference, and withdraw it as the CID's running task.
#[inline(always)]
fn stopping(task: &Task, runnable: bool) {
    let Some(state) = taskctx::lookup(task) else {
        return;
    };
    let now = time::now();
    let cid = task.cid();
    let tnow = clock::owned(cid, now);
    charge(task, &state, cid, tnow);
    pack::unpublish(cid);
    load::task_running(&state, false, now);
    load::cid_running(cid, false, now);
    state.last_stop_at().set(now);
    pressure::demand(cid, runnable || cid.has_queued(), now);
    // Stopped with slice left, the task did not end its turn: a higher
    // class took the CPU. Once that has reduced the CID enough, it is
    // queued elsewhere instead.
    if runnable && scx_slice(task) != 0 {
        pressure::displaced(cid, tnow);
        if pressure::enabled() {
            if let Some(target) = pressure::pressure_target(task, cid, now).get() {
                state.set_pressure_migrate(target);
                task.set_slice(0);
            }
        }
    }
    if !runnable {
        state.end_request();
    }
}

/// `from` gives up the CPU, sched_yield(), which is yield_task_fair():
///
/// ```text
/// if (entity_eligible(cfs_rq, se)) {
///     se->vruntime = se->deadline;
///     update_deadline(cfs_rq, se);
/// }
/// ```
///
/// A yield costs the rest of the request the task is in the middle of. Its
/// vruntime moves to its deadline as if it had run all of it, and a new
/// deadline is issued from there, so a task that yields in a loop falls
/// behind at the rate its forfeits say. The eligibility test guards against
/// running the vruntime away. Whether the CPU changes hands is then the
/// pick's question, so the slice ends only when keep-prev would not hand the
/// CPU straight back. Without this op the kernel zeroes the slice, and the
/// yielder is charged only the time it ran.
///
/// A directed yield, yield_to(), is refused: fair.c honours it with a buddy
/// that nothing here would read. Nothing else queued on the CID means
/// nobody to forfeit to, fair.c's nr_running == 1 test.
#[inline(always)]
fn yield_task(from: &Task, to: Option<&Task>) -> bool {
    let cid = from.cid();
    if to.is_some() || !pack::valid(cid) {
        return false;
    }
    let local = dsq::nr_queued(Dsq::Local) > 0;
    if !local && !cid.has_queued() {
        return false;
    }
    let Some(state) = taskctx::lookup(from) else {
        return false;
    };
    let now = time::now();
    keep_charge(from, &state, cid, now);
    if !time_before(pack::reference(cid), state.vtime().get()) {
        // The jump is service to the pack and a consumed request.
        state.vtime().set(state.deadline().get());
        pack::charge(&state);
        keep_charge(from, &state, cid, now);
    }
    if local || !keep_running(from, &state, cid, now) {
        from.set_slice(0);
    }

    false
}

/// ops.enable(): the task joins the scheduler with zero lag, so it is
/// placed at the reference of the first CID it joins. The runtime keeps
/// its context's address in the task from here on, see taskctx.rs.
#[inline(always)]
fn enable(task: &Task) {
    if let Some(state) = taskctx::lookup(task) {
        pack::leave(&state);
        state.group().set(cgroup::task_group(task));
        state.vtime().set(0);
        state.lag().set(0);
        state.set_delay([0; 4]);
        state.set_request(accounting::Request::default());
    }
}

/// The task leaves BPF custody, see dsq::dequeue().
/// core_sched_before(): of two tasks picked independently by the
/// runqueues of one core, which has had less of its share? Each vruntime is
/// measured from its pack's origin, see pack::core_vtime(). A task outside
/// a pack is ordered as the kernel's default would: a waiting task before
/// a running one, then by how long it has been runnable.
#[inline(always)]
fn core_sched_before(a: &Task, b: &Task) -> bool {
    let (a_running, b_running) = (a.running(), b.running());
    let now = time::now();
    if let (Some(a_state), Some(b_state)) = (taskctx::lookup(a), taskctx::lookup(b))
        && let (Some(a_vtime), Some(b_vtime)) = (
            pack::core_vtime(&a_state, a_running, now),
            pack::core_vtime(&b_state, b_running, now),
        )
    {
        return time_before(a_vtime, b_vtime);
    }
    if a_running != b_running {
        return !a_running;
    }
    time_before(a.runnable_at(), b.runnable_at())
}

/// The task's affinity changed. The kernel moves a queued or running task
/// off a CPU it may no longer use, and placement and balance read the
/// affinity afresh. What it cannot reach is a sleeper's delayed debt to the
/// pack it blocked in: there is no entity left on that runqueue for the
/// affinity change to dequeue. Settle the debt where it stands once that
/// CID is excluded; if it is still allowed, fair.c leaves the delayed
/// entity there too. p->cpus_ptr already holds the mask the cmask argument
/// is built from.
#[inline(always)]
fn set_cmask(task: &Task) {
    if let Some(state) = taskctx::lookup(task)
        && let Some(cid) = pack::delay_cid(&state)
        && !cid_idle::allowed_by_mask(task, Cid(cid))
    {
        pack::settle_delay(&state, effective_weight(task, &state), time::now());
    }
}

/// ops.dequeue(): the kernel takes a queued task back, for a sleep or a
/// property change. The custody protocol makes a pop in flight give the
/// task up, see scx_rustsched's queue.
#[inline(always)]
fn dequeue(task: &Task, deq_flags: DeqFlags) {
    if let Some(state) = taskctx::lookup(task) {
        // A task leaving custody from a cpu.max backlog was taken out of
        // it there, so it is this side that stops counting it.
        if dsq::dequeue(task, deq_flags) {
            bandwidth::unparked(&state);
        }
    }
}

/// ops.quiescent(): the task stops being runnable. Its lag is saved and
/// it leaves its pack. A task that blocks over-served leaves a debt that
/// its next placement settles, DELAY_DEQUEUE.
///
/// There is no ops.set_weight(): the kernel dequeues a task around a
/// weight change, so the lag saved here at the old weight is rescaled, with
/// the request, by the placement that follows.
#[inline(always)]
fn quiescent(task: &Task, deq_flags: DeqFlags) {
    if let Some(state) = taskctx::lookup(task) {
        let sleep = deq_flags.contains(DeqFlags::SLEEP);
        let now = time::now();
        let cid = task.cid();
        clock::owned(cid, now);
        // update_curr() first: dequeue_entity() charges the service
        // the task has taken before it measures the lag. A task that
        // blocks while running has been charged by ops.stopping()
        // already, which the kernel calls before this op, and finds
        // nothing left to add here. One that has not stopped yet is
        // charged now, or its lag would be taken against a reference
        // with its last run projected in, from a vruntime without it.
        // It is charged only: keep_charge() would publish it again as
        // the CID's running task, which ops.stopping() has withdrawn.
        let member = state.member().get();
        if member != 0 && (member >> 32) as i64 - 1 == i64::from(cid.raw()) && task.running() {
            charge(task, &state, cid, clock::owned(cid, now));
        }
        load::task_quiesce(&state, sleep, now);
        pack::quiesce(&state, lag_request(task), now, sleep);
    }
}

/// ops.init(): allocate the per-CID tables in the arena, read the
/// topology, and set up each CID's queue and timer. Sleepable.
#[inline(always)]
fn init() -> i32 {
    let result = cid_idle::init();
    if result != 0 {
        return result;
    }
    // After cid_idle::init(), which reads nr_cpu_ids into the CID table.
    let slice = if SLICE_NS.get() != 0 {
        SLICE_NS.get()
    } else {
        base_slice_ns(Cid::nr_cpus())
    };
    DEFAULT_REQUEST_NS.set(slice);
    cid_idle::set_scan_bounded(balance::sis_util());
    let count = Cid::count();
    let result = pack::init(count);
    if result != 0 {
        return result;
    }
    let result = cgroup::init(count);
    if result != 0 {
        return result;
    }
    let result = bandwidth::init();
    if result != 0 {
        return result;
    }
    let result = load::init(count);
    if result != 0 {
        return result;
    }
    let result = tiers::init(count);
    if result != 0 {
        return result;
    }
    let result = newidle::init(count);
    if result != 0 {
        return result;
    }
    let mut result = 0;
    for value in crate::loops::range(0, count) {
        newidle::init_cid(Cid(value as i32));
        pressure::init_cid(Cid(value as i32));
        result = hrtick::init(Cid(value as i32));
        if result != 0 {
            break;
        }
    }
    result
}

/// ops.init_task(): the runtime has given the task its context, see
/// taskctx.rs, growing the slot pool if it had to, or failed the task
/// rather than let it run without one. Note what the context starts with.
#[inline(always)]
fn init_task(task: &Task, args: &InitTaskArgs) {
    if let Some(state) = taskctx::lookup(task) {
        // A forked task's first request is halved.
        state.initial().set(args.fork());
    }
}

/// ops.exit_task(): the task leaves the scheduler. It is taken out of its
/// pack here. The runtime then takes it out of its queue and returns its
/// context, once nothing holds its queue node any more.
#[inline(always)]
fn exit_task(task: &Task) {
    if let Some(state) = taskctx::lookup(task) {
        pack::leave(&state);
        bandwidth::unparked(&state);
        state.group().set(None);
    }
}

/// The callbacks as the kernel calls them, each handing the kernel's
/// arguments to the function of its name above or in cgroup.rs,
/// bandwidth.rs and debug.rs. The scheduler does its own idle tracking:
/// dispatch re-arms a CID only on the path that found nothing to run.
#[scx_rustsched::scheduler(
    name = "reevdf",
    flags = TID_TO_TASK | ENQ_LAST | ENQ_EXITING | ENQ_MIGRATION_DISABLED | ALLOW_QUEUED_WAKEUP,
    task_slot = taskctx::Context,
    idle_tracking = false
)]
impl Reevdf {
    #[inline(always)]
    fn init() -> Result<(), Error> {
        Error::check(init())
    }

    #[inline(always)]
    fn init_task(task: &Task, args: &InitTaskArgs) {
        init_task(task, args)
    }

    #[inline(always)]
    fn exit_task(task: &Task) {
        exit_task(task)
    }

    #[inline(always)]
    fn enable(task: &Task) {
        enable(task)
    }

    #[inline(always)]
    fn select_cid(task: &Task, previous: Cid, flags: WakeFlags) -> Cid {
        select_cid(task, previous, flags)
    }

    #[inline(always)]
    fn enqueue(task: &Task, flags: EnqFlags) {
        enqueue(task, flags)
    }

    #[inline(always)]
    fn dequeue(task: &Task, flags: DeqFlags) {
        dequeue(task, flags)
    }

    #[inline(always)]
    fn dispatch(cid: Cid, prev: Option<&Task>) {
        dispatch(cid, prev)
    }

    #[inline(always)]
    fn tick(task: &Task) {
        tick(task)
    }

    #[inline(always)]
    fn running(task: &Task) {
        running(task)
    }

    #[inline(always)]
    fn stopping(task: &Task, runnable: bool) {
        stopping(task, runnable)
    }

    #[inline(always)]
    fn quiescent(task: &Task, flags: DeqFlags) {
        quiescent(task, flags)
    }

    #[inline(always)]
    fn yield_task(from: &Task, to: Option<&Task>) -> bool {
        yield_task(from, to)
    }

    #[inline(always)]
    fn core_sched_before(a: &Task, b: &Task) -> bool {
        core_sched_before(a, b)
    }

    #[inline(always)]
    fn set_cmask(task: &Task) {
        set_cmask(task)
    }

    #[inline(always)]
    fn update_idle(cid: Cid, idle: bool) {
        update_idle(cid, idle)
    }

    #[inline(always)]
    fn dump_task(dump: &DumpCtx, task: &Task) {
        debug::dump_task(dump, task)
    }

    #[inline(always)]
    fn cgroup_init(cgroup: &Cgroup, args: &CgroupArgs) -> Result<(), Error> {
        Error::check(cgroup::cpuctl_init(cgroup, args))
    }

    #[inline(always)]
    fn cgroup_exit(cgroup: &Cgroup) {
        cgroup::cpuctl_exit(cgroup)
    }

    #[inline(always)]
    fn cgroup_move(task: &Task, _from: &Cgroup, to: &Cgroup) {
        cgroup::cpuctl_move(task, to)
    }

    #[inline(always)]
    fn cgroup_set_weight(cgroup: &Cgroup, weight: u32) {
        cgroup::cpuctl_set_weight(cgroup, weight)
    }

    #[inline(always)]
    fn cgroup_set_idle(cgroup: &Cgroup, idle: bool) {
        cgroup::cpuctl_set_idle(cgroup, idle)
    }

    #[inline(always)]
    fn cgroup_set_bandwidth(cgroup: &Cgroup, period_us: u64, quota_us: u64, burst_us: u64) {
        bandwidth::cpuctl_set_bandwidth(cgroup, period_us, quota_us, burst_us)
    }
}
