// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The BPF program of scx_rake: scx_cake's policy on the Rust BPF runtime.
//!
//! The callbacks are at the end of the file, in the `#[scheduler]` block.
//! The policy is in the modules:
//!
//! ```text
//! select_cid    serial handoff, seat retake, warm home,   place.rs
//!               claimed idle CID, or nothing decided
//! enqueue       kernel-thread wakes, wakes routed by      place.rs
//!               starvation, continuations on the owner's
//!               queue, forced requeues and collisions to
//!               the LLC's pool
//! dispatch      offers from other LLCs, own queue and     serve.rs
//!               pool by virtual time, seat deferral,
//!               steals, rescue of other LLCs' pools
//! running       the run stamp, the seat, the frontier     here
//! stopping      the charge, the seat hold, the handoff    here
//!               hint
//! ```
//!
//! The arithmetic is policy.rs, which the loader's tests check on the host.
//!
//! Three kinds of queue, as in scx_cake. A task admitted to a CID goes to
//! that CID's local DSQ. A continuation waits on its CID's own queue, an
//! `Edq::Cid` in the arena, which other CIDs of the LLC steal from. A
//! wakeup that waits longer than it runs, or that finds its CID taken by
//! an equally served task, goes to its LLC's pool, an `Edq::User`, which
//! every CID of the LLC serves. All are ordered by virtual time, which is
//! charged in ops.stopping() from the runtime the kernel accounted,
//! scaled by a fixed-point reciprocal of the task's weight.
//!
//! Counterpart in scx_cake: cake.bpf.c.

#![no_std]
#![no_main]

use scx::prelude::*;
use scx_rustsched as scx;
use scx_rustsched::{config, helpers};

mod place;
mod policy;
mod seat;
mod seat_word;
mod serve;

// The tunables: one for each option of the loader, ../src/main.rs.
scx::opts!();

/// The pools rake keeps, one per LLC up to this many. More LLCs, or
/// --single-pool, make it one pool for the machine.
pub const MAX_LLCS: u32 = 16;

scx::arena_struct! {
    /// What rake keeps per task.
    pub struct TaskCtx {
        /// The task's virtual time, the key it is queued with. The kernel's
        /// dsq_vtime is the runtime's, which keeps the slot's address there.
        vtime: u64,
        /// The runtime the kernel had accounted at the last charge, see
        /// stopping().
        charged: u64,
        /// The seat the task holds, its CID plus one, 0 for none, and the
        /// pid and generation it took it with, see seat.rs.
        seat_cid: u32,
        seat_pid: u32,
        seat_seq: u64,
    }
}

impl scx::slots::TaskSlot for TaskCtx {}

scx::arena_struct! {
    /// What rake keeps per CID.
    pub struct CidCtx {
        /// When the running task got the CID, on the CID's clock.
        stamp: u64,
        /// The pid ops.running() stamped, 0 from ops.stopping() until the
        /// next running. A remote reader whose occupant has another pid
        /// sees a CID in the middle of a switch and prices nothing.
        pid: u64,
        /// The slice ops.running() granted, for a remote reader to price
        /// what is left of it.
        grant: u64,
        /// The serial-handoff hint, see policy::hint_after().
        hint: u64,
        /// The seat's holder was just placed behind a stranger: the
        /// stranger goes to the pool when it comes back. ops.running()
        /// clears it.
        retake: u64,
        /// The seat, see seat.rs.
        seat: u64,
        /// A pool another LLC offered this idle CID, its index plus one,
        /// for its next dispatch.
        offer: u64,
        /// The pool of the CID's LLC.
        pool: u32,
        /// Is the CID idle, as ops.update_idle() last said?
        idle: u64,
        /// In the first CID of an LLC: how many of the LLC's CIDs are
        /// idle, see update_idle().
        nr_idle: u64,
    }
}

/// The global virtual-time frontier, advanced by ops.running() in grains:
/// what a waking task's key is clamped against.
pub static FRONTIER: Var<u64> = Var::new(0);

/// The number of pools.
pub static NR_POOLS: Var<u32> = Var::new(1);

/// When each pool was last served, on the clock of the CID that served it.
pub static POOL_SERVED: [Var<u64>; MAX_LLCS as usize] = [const { Var::new(0) }; MAX_LLCS as usize];

/// Are there several pools? Every path that looks into another LLC's
/// pool tests it first.
#[inline(always)]
pub fn multi_pool() -> bool {
    NR_POOLS.get() > 1
}

/// The pool of `cid`'s LLC.
#[inline(always)]
pub fn pool_of(cid: Cid) -> u32 {
    match cid.slot::<CidCtx>() {
        Some(ctx) => ctx.pool().get(),
        None => 0,
    }
}

/// SCX_ENQ_IMMED, 0 on a kernel without it: an insert on a local DSQ the
/// kernel hands back through ops.enqueue() if the CID is taken before the
/// task runs, or by a higher class while it runs.
#[inline(always)]
pub fn immed() -> EnqFlags {
    EnqFlags(config::get(config::ENQ_IMMED))
}

/// Is this enqueue the kernel handing a task back, SCX_ENQ_REENQ?
#[inline(always)]
pub fn reenq(flags: EnqFlags) -> bool {
    let reenq = config::get(config::ENQ_REENQ);
    reenq != 0 && flags.raw() & reenq != 0
}

/// The task's age, on the clock of its creation time.
#[inline(always)]
fn task_age(task: &Task) -> u64 {
    policy::time_delta(helpers::ktime_get_ns(), task.start_time())
}

/// Is the task a stage: a mean burst of at least SEAT_BURST_MIN_NS?
#[inline(always)]
pub fn is_stage(task: &Task) -> bool {
    policy::stage(task.sum_exec_runtime(), task.nvcsw())
}

/// Is the task's mean burst shorter than a handoff?
#[inline(always)]
pub fn is_subhandoff(task: &Task) -> bool {
    policy::subhandoff(task.sum_exec_runtime(), task.nvcsw())
}

/// Does the task wait longer than it runs, or with `turn` longer than one
/// turn of its own? Never on a kernel without sched_info.
#[inline(always)]
pub fn is_starved(task: &Task, turn: bool) -> bool {
    let Some(info) = task.sched_info() else {
        return false;
    };
    policy::starved(
        task.sum_exec_runtime(),
        task.nvcsw(),
        info.run_delay,
        info.pcount,
        turn,
    )
}

/// The task's adaptive slice.
#[inline(always)]
pub fn task_slice(task: &Task) -> u64 {
    policy::task_slice(task.sum_exec_runtime(), task_age(task), task.nvcsw())
}

/// The task's virtual time, the frontier for a task rake has no slot for.
#[inline(always)]
pub fn vtime_of(task: &Task) -> u64 {
    match task.slot::<TaskCtx>() {
        Some(ctx) => ctx.vtime().get(),
        None => FRONTIER.get(),
    }
}

/// Make `vtime` the task's key.
#[inline(always)]
pub fn set_vtime(task: &Task, vtime: u64) {
    if let Some(ctx) = task.slot::<TaskCtx>() {
        ctx.vtime().set(vtime);
    }
}

/// A wakeup's slice and key, see policy::admit(). The key is returned to
/// the caller: the insert that ends the route stamps it.
#[inline(always)]
pub fn admit(task: &Task) -> (u64, u64) {
    policy::admit(
        task.sum_exec_runtime(),
        task_age(task),
        task.nvcsw(),
        is_starved(task, false),
        FRONTIER.get(),
        vtime_of(task),
    )
}

/// admit() for a task inserted on a local DSQ, where no key goes with the
/// insert: the key is stamped here, so that a long sleeper admitted
/// directly does not keep an arbitrarily old one.
#[inline(always)]
pub fn admit_direct(task: &Task) -> u64 {
    let (slice, vtime) = admit(task);
    set_vtime(task, vtime);
    slice
}

/// Is `a` the same task as `b`?
#[inline(always)]
pub fn same_task(a: &Task, b: &Task) -> bool {
    core::ptr::eq(a.as_ptr(), b.as_ptr())
}

/// What the task running on a CID is worth to a wakeup: how long it has
/// run and its virtual time with that run charged. `live` is 0 when there
/// is nothing to price: no task of rake's, or a CID in mid-switch.
#[derive(Clone, Copy)]
pub struct Price {
    pub live: u64,
    pub ran: u64,
}

const NO_PRICE: Price = Price { live: 0, ran: 0 };

/// Price `curr`, the task running on `cid`, at `now` on `cid`'s clock.
/// The pid is read before the stamp, the reverse of the order ops.running()
/// writes them in, so a stamp that matches the pid belongs to this run.
#[inline(always)]
pub fn price(curr: &Task, cid: Cid, now: u64) -> Price {
    if !curr.queued() {
        return NO_PRICE;
    }
    let Some(task) = curr.slot_optional::<TaskCtx>() else {
        return NO_PRICE;
    };
    let Some(here) = cid.slot::<CidCtx>() else {
        return NO_PRICE;
    };
    let vtime = task.vtime().get();
    if here.pid().get() != u64::from(curr.pid() as u32) {
        return NO_PRICE;
    }
    let ran = policy::time_delta(now, here.stamp().get());
    Price {
        live: policy::scale_vtime_add(vtime, ran, policy::reciprocal(curr.weight())),
        ran,
    }
}

/// The frontier candidate of a task that runs `vtime` ahead: an ordinary
/// advance stands, and an outlier more than a slice ahead is capped by the
/// live virtual time of what runs on the other CIDs, so that one task back
/// from a long lead does not drag everybody's wake floor with it.
#[scx::global]
fn frontier_candidate(vtime: u64, here: Cid, now: u64) -> u64 {
    let frontier = FRONTIER.get();
    let mut vtime = vtime;
    if !policy::frontier_outlier(frontier, vtime) {
        return vtime;
    }
    for cid in Cid::all() {
        if cid == here {
            continue;
        }
        let Some(curr) = cid.curr() else {
            continue;
        };
        let price = price(&curr, cid, now);
        if price.live != 0 && policy::time_before(price.live, vtime) {
            vtime = price.live;
            if !policy::frontier_outlier(frontier, vtime) {
                break;
            }
        }
    }
    vtime
}

/// The LLCs init() has met so far. A global rather than a local: the
/// verifier tracks a local counter exactly, and a loop that increments one
/// is a new state at every iteration, which it cannot prune.
static LLCS_SEEN: Var<u64> = Var::new(0);

/// Is `cid` the first CID of its LLC?
#[inline(always)]
fn llc_first(cid: Cid) -> bool {
    let (_, base) = cid.llc_span();
    cid.index() == base
}

/// ops.init(): number the pools by LLC, create them, and seed each LLC's
/// idle count.
#[inline(always)]
fn init() -> Result<(), Error> {
    LLCS_SEEN.set(0);
    for cid in Cid::all() {
        if llc_first(cid) {
            LLCS_SEEN.add(1);
        }
    }
    let llcs = LLCS_SEEN.get();
    let pools = if SINGLE_POOL.get() || llcs > u64::from(MAX_LLCS) {
        1
    } else {
        llcs.max(1) as u32
    };
    NR_POOLS.set(pools);
    // The LLCs are contiguous in CID order: the pool of a CID is the
    // number of LLCs that began before it.
    LLCS_SEEN.set(0);
    for cid in Cid::all() {
        if llc_first(cid) {
            LLCS_SEEN.add(1);
        }
        let Some(ctx) = cid.slot::<CidCtx>() else {
            continue;
        };
        let pool = if pools > 1 {
            LLCS_SEEN.get().saturating_sub(1) as u32
        } else {
            0
        };
        ctx.pool().set(pool);
        if cid.is_idle() {
            ctx.idle().set(1);
            if let Some(first) = llc_base(cid).slot::<CidCtx>() {
                first.nr_idle().add(1);
            }
        }
    }
    for index in scx::loops::range(0, pools) {
        dsq::create(Edq::User(u64::from(index)))?;
    }
    Ok(())
}

/// The first CID of `cid`'s LLC, whose slot keeps the LLC's idle count.
#[inline(always)]
pub fn llc_base(cid: Cid) -> Cid {
    let (_, base) = cid.llc_span();
    Cid(base as i32)
}

/// ops.update_idle(): keep the LLC's idle count. The CID's flag changes
/// only here, on its own CPU, so a plain store does; the count is shared
/// by the LLC and changes by atomic adds. The runtime keeps its own idle
/// tracking whether or not this is defined: this is the occupancy the
/// serial handoff weighs, scx_cake's idle census, not what a claim
/// takes.
#[inline(always)]
fn update_idle(cid: Cid, idle: bool) {
    let Some(here) = cid.slot::<CidCtx>() else {
        return;
    };
    let delta = policy::census_delta(here.idle().get() != 0, idle);
    if delta == 0 {
        return;
    }
    here.idle().set(u64::from(idle));
    if let Some(first) = llc_base(cid).slot::<CidCtx>() {
        first.nr_idle().add(delta);
    }
}

/// Serial tests that found an LLC's idle count past its size, for the
/// dump: the count is broken, see place.rs.
pub static CENSUS_BROKEN: Var<u64> = Var::new(0);

/// ops.running(): stamp the run, clear the seat and advance the frontier.
#[inline(always)]
fn running(task: &Task) {
    let cid = task.cid();
    let now = time::now();
    let pid = task.pid() as u32;
    if let Some(here) = cid.slot::<CidCtx>() {
        here.stamp().set(now);
        here.retake().set(0);
        here.grant().set(task.slice());
        // Stamp before owner, see price().
        here.pid().set(u64::from(pid));
    }
    let Some(ctx) = task.slot::<TaskCtx>() else {
        return;
    };
    // A holder that runs elsewhere gives its seat back, and whatever runs
    // on a held seat clears it.
    seat::retire(ctx, pid, OptCid::some(cid));
    if seat::held(cid) {
        seat::run(cid);
    }
    // The conditional store: this is the hottest shared word, and a store
    // of every run would make every CID's next read a miss.
    let vtime = ctx.vtime().get();
    if policy::frontier_moves(FRONTIER.get(), vtime) {
        let vtime = frontier_candidate(vtime, cid, now);
        if policy::frontier_moves(FRONTIER.get(), vtime) {
            FRONTIER.set(vtime);
        }
    }
}

/// ops.stopping(): charge the runtime the kernel accounted since the last
/// charge, take a seat for a stage that blocks, and learn the handoff
/// hint.
///
/// scx_cake charges the runtime since its CPU's ops.running(). The kernel
/// can start a task without that call, when a property change catches it
/// while the runqueue is unlocked for a dispatch, and the CPU's stamp then
/// belongs to another task. The task's own last charge is exact whatever
/// the kernel skips, and the same as the stamp when it skips nothing.
#[inline(always)]
fn stopping(task: &Task, runnable: bool) {
    let cid = task.cid();
    let Some(here) = cid.slot::<CidCtx>() else {
        return;
    };
    // The CID is vacant until the next running stamps it.
    here.pid().set(0);
    let Some(ctx) = task.slot::<TaskCtx>() else {
        return;
    };
    let runtime = task.sum_exec_runtime();
    let used = runtime.saturating_sub(ctx.charged().get());
    ctx.charged().set(runtime);
    // Plain loads and stores rather than update() with a closure: a closure
    // that captures may be outlined, see serve.rs.
    here.hint()
        .set(policy::hint_after(here.hint().get(), runnable, used));
    if !runnable && is_stage(task) {
        seat::take(ctx, task.pid() as u32, cid);
    }
    let recip = policy::reciprocal(task.weight());
    ctx.vtime()
        .set(policy::scale_vtime_add(ctx.vtime().get(), used, recip));
}

#[scx::scheduler(
    name = "rake",
    flags = ALLOW_QUEUED_WAKEUP,
    task_slot = TaskCtx,
    cid_slot = CidCtx
)]
impl Rake {
    fn init() -> Result<(), Error> {
        init()
    }

    fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid {
        place::select_cid(task, prev, flags)
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        place::enqueue(task, flags)
    }

    fn dispatch(cid: Cid, prev: Option<&Task>) {
        serve::dispatch(cid, prev)
    }

    fn running(task: &Task) {
        running(task)
    }

    fn stopping(task: &Task, runnable: bool) {
        stopping(task, runnable)
    }

    fn update_idle(cid: Cid, idle: bool) {
        update_idle(cid, idle)
    }

    /// A fresh task starts at the frontier, neither starved nor ahead,
    /// charged for nothing it ran before.
    fn enable(task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            ctx.vtime().set(FRONTIER.get());
            ctx.charged().set(task.sum_exec_runtime());
        }
    }

    /// A holder that leaves the class while blocked gives its seat back.
    fn disable(task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            seat::retire(ctx, task.pid() as u32, OptCid::NONE);
        }
    }

    /// So does a holder that exits.
    fn exit_task(task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            seat::retire(ctx, task.pid() as u32, OptCid::NONE);
        }
    }

    fn dump(_dump: &DumpCtx) {
        scx::dump!(
            "rake frontier=%llu pools=%llu seat_lost=%llu census_broken=%llu",
            FRONTIER.get(),
            u64::from(NR_POOLS.get()),
            seat::lost(),
            CENSUS_BROKEN.get()
        );
    }

    fn dump_task(_dump: &DumpCtx, task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            scx::dump!(
                "rake vtime=%llu seat=%llu",
                ctx.vtime().get(),
                u64::from(ctx.seat_cid().get())
            );
        }
    }
}
