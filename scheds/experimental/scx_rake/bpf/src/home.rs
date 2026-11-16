// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! Fixed homes: a busy thread owns one core and returns to it on every
//! wakeup.
//!
//! A thread that ran a fifth of a CPU over a window of at least 64 ms, as
//! sampled at one block in 64, takes a core as its home: the best-ranked
//! core it may run on that nobody owns, or the one it ran on when that is
//! among the best. ops.select_cid() sends the owner home on every wakeup,
//! after only the serial handoff: an idle claim, or a head insert that
//! preempts a movable occupant. The occupant of a home that is its own
//! keeps it when its grant runs out. A home is given up under a tenth of a
//! CPU, on exit, and while busy threads outnumber the cores; one its owner
//! has not refreshed for 2 s may be taken.
//!
//! A home is one word in the slot of its core's first CID, the owner's pid
//! and the CID it homes to, changed by compare and exchange: a claim from
//! 0, a drop to 0 from the word it read. The task keeps the CID it homes
//! to, and the home is its own only while the core's word still names it,
//! so a home taken over is gone from its old owner without a write to it.
//! scx_cake keeps a table of 64 homes hashed by pid, a word of owned
//! cores and a value per CPU, all on hosts whose CPUs fit one 64-bit word;
//! one word per core does for any host.
//!
//! Counterpart in scx_cake: cake_home_sample(), cake_home_drop(),
//! cake_home_cpu() and the home branch of cake_select_cpu().

use scx_rustsched::cid_idle::scope_cids;
use scx_rustsched::helpers;
use scx_rustsched::prelude::*;

use crate::policy;
use crate::{CidCtx, TaskCtx};

/// Busy samples in the current census, when it began, and whether the
/// last census found more busy threads than cores.
static CENSUS: Var<u64> = Var::new(0);
static CENSUS_START: Var<u64> = Var::new(0);
static CROWDED: Var<u64> = Var::new(0);

/// The online cores, counted by init().
pub static NR_CORES: Var<u64> = Var::new(0);

/// The first CID of `cid`'s core, whose slot keeps the core's home.
#[inline(always)]
pub fn core_base(cid: Cid) -> Cid {
    let (base, _) = scope_cids(cid, Scope::Core);
    Cid(base as i32)
}

/// Is `cid` the first CID of its core?
#[inline(always)]
pub fn core_first(cid: Cid) -> bool {
    core_base(cid) == cid
}

/// The home word of `cid`'s core.
#[inline(always)]
fn word(cid: Cid) -> u64 {
    match core_base(cid).slot::<CidCtx>() {
        Some(base) => base.home().get(),
        None => 0,
    }
}

/// Are homes off: did the last census find more busy threads than cores?
#[inline(always)]
pub fn crowded() -> bool {
    CROWDED.get() != 0
}

/// The CID the task homes to, if the home is still its own. A task the
/// scheduler has no slot for, such as one of a higher class, has none.
#[inline(always)]
pub fn home_of(task: &Task) -> OptCid {
    let Some(ctx) = task.slot_optional::<TaskCtx>() else {
        return OptCid::NONE;
    };
    let home = ctx.home().get();
    if home == 0 {
        return OptCid::NONE;
    }
    let cid = Cid(home as i32 - 1);
    if word(cid) != policy::home_word(task.pid() as u32, cid.index()) {
        return OptCid::NONE;
    }
    OptCid::some(cid)
}

/// Is `cid` the home of the task running there, homes being on?
#[inline(always)]
pub fn at_home(task: &Task, cid: Cid) -> bool {
    !crowded() && home_of(task) == OptCid::some(cid)
}

/// Drop `cid`'s core's home if it is still `seen`.
#[inline(always)]
fn drop_home(cid: Cid, seen: u64) {
    if seen == 0 {
        return;
    }
    if let Some(base) = core_base(cid).slot::<CidCtx>() {
        base.home().compare_exchange(seen, 0);
    }
}

/// The task gives its home up, if it has one: it went quiet, homes are
/// crowded, it exits or it leaves the class.
#[inline(always)]
pub fn leave(task: &Task) {
    if let Some(cid) = home_of(task).get() {
        drop_home(cid, policy::home_word(task.pid() as u32, cid.index()));
    }
    if let Some(ctx) = task.slot_optional::<TaskCtx>() {
        ctx.home().set(0);
    }
}

/// Is the home kept in `base`, a core's first CID, free to take: nobody's,
/// or not refreshed by its owner for HOME_STALE_NS?
#[inline(always)]
fn free(base: &CidCtx, now: u64) -> bool {
    base.home().get() == 0
        || policy::time_delta(now, base.home_seen().get()) > policy::HOME_STALE_NS
}

/// The CID a task that runs on `here` takes as its home: the first CID of
/// the best-ranked core it may run on that is free, or `here` when its
/// core is among the best. None when every core is owned.
///
/// The best rank and its CID are kept in `here`'s slot as the walk goes, not
/// in locals: the verifier tracks a local the loop assigns exactly, a new
/// state at every CID.
#[scx_rustsched::global]
fn best_free(task: &Task, here: Cid, now: u64) -> OptCid {
    let Some(scratch) = here.slot::<CidCtx>() else {
        return OptCid::NONE;
    };
    scratch.best_rank().set(u64::MAX);
    scratch.best_cid().set(0);
    for cid in Cid::all() {
        if !core_first(cid) || !task.allowed_on(cid) {
            continue;
        }
        let Some(base) = cid.slot::<CidCtx>() else {
            continue;
        };
        if !free(&base, now) {
            continue;
        }
        let rank = policy::home_rank(cid.capacity_tier(), cid.place_tier());
        if rank < scratch.best_rank().get() {
            scratch.best_rank().set(rank);
            scratch.best_cid().set(u64::from(cid.index()) + 1);
        }
    }
    let best = scratch.best_cid().get();
    if best == 0 {
        return OptCid::NONE;
    }
    // Its own core, when that ranks with the best: a task seated on the
    // same cores at every launch, not wherever it first ran.
    let own = core_base(here);
    let own_rank = policy::home_rank(own.capacity_tier(), own.place_tier());
    if own_rank == scratch.best_rank().get()
        && task.allowed_on(here)
        && let Some(base) = own.slot::<CidCtx>()
        && free(&base, now)
    {
        return OptCid::some(here);
    }
    OptCid::some(Cid(best as i32 - 1))
}

/// Count a sample in the census, and every HOME_CENSUS_WINDOWS windows
/// close it: homes go off while more threads were busy than the cores can
/// home.
#[inline(always)]
fn census(busy: bool, now: u64) {
    let span = policy::HOME_CENSUS_WINDOWS * policy::HOME_WINDOW_NS;
    if policy::time_delta(now, CENSUS_START.get()) > span {
        let crowded = policy::homes_crowded(CENSUS.get(), NR_CORES.get());
        CROWDED.set(u64::from(crowded));
        CENSUS.set(0);
        CENSUS_START.set(now);
    }
    if busy {
        CENSUS.add(1);
    }
}

/// The share sample, at a block on `cid`: a task busy enough takes a home,
/// one gone quiet gives it up, an owner refreshes it.
#[scx_rustsched::global]
pub fn sample(task: &Task, cid: Cid) {
    let Some(ctx) = task.slot::<TaskCtx>() else {
        return;
    };
    let now = helpers::ktime_get_ns();
    let window = now.wrapping_sub(ctx.window_start().get());
    if window < policy::HOME_WINDOW_NS {
        return;
    }
    let runtime = task.sum_exec_runtime();
    let ran = runtime.wrapping_sub(ctx.window_runtime().get());
    ctx.window_start().set(now);
    ctx.window_runtime().set(runtime);
    let busy = policy::home_busy(ran, window);
    census(busy, now);
    if let Some(home) = home_of(task).get() {
        if policy::home_quiet(ran, window) || crowded() {
            leave(task);
        } else if let Some(base) = core_base(home).slot::<CidCtx>() {
            base.home_seen().set(now);
        }
        return;
    }
    if !busy || crowded() || task.nr_cpus_allowed() <= 1 {
        return;
    }
    let Some(target) = best_free(task, cid, now).get() else {
        return;
    };
    let Some(base) = core_base(target).slot::<CidCtx>() else {
        return;
    };
    // From the word the search saw free: nobody's, or a stale owner's,
    // which is taken over without a write to the old owner.
    let seen = base.home().get();
    if !free(&base, now) {
        return;
    }
    let mine = policy::home_word(task.pid() as u32, target.index());
    if base.home().compare_exchange(seen, mine) != seen {
        return;
    }
    base.home_seen().set(now);
    ctx.home().set(target.index() + 1);
}

/// The home the task's wakeup goes to: its own, homes being on, if it may
/// run there now.
#[inline(always)]
pub fn wake_home(task: &Task) -> OptCid {
    if crowded() {
        return OptCid::NONE;
    }
    let Some(home) = home_of(task).get() else {
        return OptCid::NONE;
    };
    if !task.allowed_on(home) {
        return OptCid::NONE;
    }
    OptCid::some(home)
}

/// How the owner goes to its home `home` when the idle claim lost: to the
/// head of the local DSQ, preempting a movable occupant, the idle task that
/// lost the claim to an insert, or an occupant it cannot read in the middle
/// of a switch, which then goes to the pool when it comes back, as a seat's
/// stranger does. Behind itself or a pinned occupant it queues.
#[inline(always)]
pub fn evict(task: &Task, home: Cid) -> EnqFlags {
    let evicts = match home.curr() {
        None => true,
        Some(curr) => !crate::same_task(&curr, task) && (!curr.pinned() || curr.idle_task()),
    };
    if !evicts {
        return EnqFlags::NONE;
    }
    if let Some(here) = home.slot::<CidCtx>() {
        here.retake().set(1);
    }
    EnqFlags::PREEMPT
}

/// Count the cores, for the census.
#[inline(always)]
pub fn init() {
    NR_CORES.set(0);
    for cid in Cid::all() {
        if core_first(cid) {
            NR_CORES.add(1);
        }
    }
    CENSUS_START.set(helpers::ktime_get_ns());
}
