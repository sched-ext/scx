// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! Seats: the CID a stage task blocked on, held for its return.
//!
//! A stage, a task whose mean burst is at least SEAT_BURST_MIN_NS, that
//! blocks takes a seat on its CID. While the seat is held other wakeups
//! pass the CID over if anything else is idle, and a dispatch there leaves
//! pool work to an unheld CID. Whatever runs on the CID clears the held
//! bit, and the holder keeps its identity there, so that when it wakes and
//! finds a stranger on its seat it takes it back at once.
//!
//! A seat is one word in the CID's slot, pid, held bit and generation, see
//! seat_word.rs. scx_cake keeps the three in separate words and serializes
//! their changes with a BPF spin lock per CPU. Here each change is one
//! compare and exchange of the whole word from the value it read, so a
//! change is applied whole or not at all, and a release whose generation
//! no longer matches does nothing, which is what the lock and the sequence
//! number did in C.
//!
//! The word has two kinds of writer: the CID's own runqueue, which holds in
//! ops.stopping() and clears in ops.running(), one at a time under its
//! lock, and the holder releasing it from wherever it runs. An exchange
//! fails only when the other kind wrote the word in between, so it loses
//! only to a runqueue that completes transitions inside its window. The
//! retries are bounded, as BPF needs: a change that runs out of them is
//! not made, is counted in lost(), and a release that is not made keeps
//! the task's record of its seat, so that its next running, disable or
//! exit tries again. tests/seat.rs explores every interleaving of the two
//! writers.
//!
//! Counterpart in scx_cake: cake_seat_update(), cake_seat_retire() and the
//! seat tests of cake.bpf.c.

use scx_rustsched::loops;
use scx_rustsched::prelude::*;

use crate::seat_word::{self, CAS_TRIES};
use crate::{CidCtx, TaskCtx};

/// Changes that ran out of tries, for the dump.
static LOST: Var<u64> = Var::new(0);

/// How many seat changes ran out of tries.
#[inline(always)]
pub fn lost() -> u64 {
    LOST.get()
}

#[inline(always)]
fn word(cid: Cid) -> u64 {
    match cid.slot::<CidCtx>() {
        Some(ctx) => ctx.seat().get(),
        None => 0,
    }
}

/// The pid of the task that holds or held `cid`'s seat, 0 for none.
#[inline(always)]
pub fn owner(cid: Cid) -> u32 {
    seat_word::owner(word(cid))
}

/// Is `cid`'s seat held: has nothing run there since its holder blocked?
#[inline(always)]
pub fn held(cid: Cid) -> bool {
    seat_word::held(word(cid))
}

/// Is `cid` a seat held by a task other than the one with `pid`?
#[inline(always)]
pub fn blocks(cid: Cid, pid: u32) -> bool {
    let seat = word(cid);
    seat_word::held(seat) && seat_word::owner(seat) != pid
}

/// Is the task with `pid` the owner of `cid`'s seat, held or not?
#[inline(always)]
pub fn owns(cid: Cid, pid: u32) -> bool {
    pid != 0 && owner(cid) == pid
}

/// Take `cid`'s seat for the task with `pid`, from ops.stopping() on that
/// CID. Returns the generation, 0 when the change was not made.
#[inline(always)]
fn hold(cid: Cid, pid: u32) -> u64 {
    let Some(ctx) = cid.slot::<CidCtx>() else {
        return 0;
    };
    for _ in loops::range(0, CAS_TRIES) {
        let old = ctx.seat().get();
        let new = seat_word::hold(old, pid);
        if ctx.seat().compare_exchange(old, new) == old {
            return seat_word::seq(new);
        }
    }
    LOST.add(1);
    0
}

/// Something runs on `cid`: the seat is no longer held, and its owner
/// stays recorded for a retake. From ops.running() on that CID.
#[inline(always)]
pub fn run(cid: Cid) {
    let Some(ctx) = cid.slot::<CidCtx>() else {
        return;
    };
    for _ in loops::range(0, CAS_TRIES) {
        let old = ctx.seat().get();
        let Some(new) = seat_word::run(old) else {
            return;
        };
        if ctx.seat().compare_exchange(old, new) == old {
            return;
        }
    }
    LOST.add(1);
}

/// Give `cid`'s seat back, if it is still the hold of `pid` with
/// generation `seq`. True when the seat is no longer that hold, by this
/// release or before it; false when the change ran out of tries.
#[inline(always)]
fn release(cid: Cid, pid: u32, seq: u64) -> bool {
    let Some(ctx) = cid.slot::<CidCtx>() else {
        return true;
    };
    for _ in loops::range(0, CAS_TRIES) {
        let old = ctx.seat().get();
        let Some(new) = seat_word::release(old, pid, seq) else {
            return true;
        };
        if ctx.seat().compare_exchange(old, new) == old {
            return true;
        }
    }
    LOST.add(1);
    false
}

/// Release the seat `ctx` records, unless it is `keep` held under `pid`:
/// a task that runs elsewhere, exits or leaves the class gives its seat
/// back, so that a recycled pid does not inherit it. The record goes only
/// with the seat: a release that was not made is tried again next time.
/// False when the seat is still recorded.
#[inline(always)]
pub fn retire(ctx: TaskCtx, pid: u32, keep: OptCid) -> bool {
    let seat = ctx.seat_cid().get();
    if seat == 0 {
        return true;
    }
    if seat as i32 == keep.raw() + 1 && ctx.seat_pid().get() == pid {
        return true;
    }
    let cid = Cid(seat as i32 - 1);
    if !release(cid, ctx.seat_pid().get(), ctx.seat_seq().get()) {
        return false;
    }
    ctx.seat_cid().set(0);
    true
}

/// A stage that blocked on `cid` takes its seat there, giving back the one
/// it held elsewhere. While that one cannot be given back, it takes no new
/// one: a task records one seat.
#[inline(always)]
pub fn take(ctx: TaskCtx, pid: u32, cid: Cid) {
    if !retire(ctx, pid, OptCid::some(cid)) {
        return;
    }
    let seq = hold(cid, pid);
    if seq == 0 {
        return;
    }
    ctx.seat_seq().set(seq);
    ctx.seat_cid().set(cid.index() + 1);
    ctx.seat_pid().set(pid);
}
