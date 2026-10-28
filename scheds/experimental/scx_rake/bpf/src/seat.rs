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
//! A seat is one word in the CID's slot:
//!
//! ```text
//!   63         33  32  31          0
//!  [ generation   |held|    pid     ]
//! ```
//!
//! scx_cake keeps the pid, the generation and the held bit in three words
//! and serializes their changes with a BPF spin lock per CPU. Here they are
//! one word, changed by compare and exchange: a hold, the clear by the task
//! that runs there and a release by the holder from another CPU each move
//! the word from the value they read, and a release whose generation no
//! longer matches does nothing, which is what the lock and the sequence
//! number did in C. No helper runs between the read and the exchange, so
//! a retry loop of a few tries is enough to win the race against the one
//! other writer the word can have at a time.
//!
//! Counterpart in scx_cake: cake_seat_update(), cake_seat_retire() and the
//! seat tests of cake.bpf.c.

use scx_rustsched::loops;
use scx_rustsched::prelude::*;

use crate::{CidCtx, TaskCtx};

const PID_MASK: u64 = 0xffff_ffff;
const HELD: u64 = 1 << 32;
const SEQ_SHIFT: u32 = 33;

/// Tries of a compare and exchange before a transition gives up. A seat
/// has at most two writers at a time, the CID's own runqueue and one
/// holder releasing from elsewhere.
const CAS_TRIES: u32 = 4;

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
    (word(cid) & PID_MASK) as u32
}

/// Is `cid`'s seat held: has nothing run there since its holder blocked?
#[inline(always)]
pub fn held(cid: Cid) -> bool {
    word(cid) & HELD != 0
}

/// Is `cid` a seat held by a task other than the one with `pid`?
#[inline(always)]
pub fn blocks(cid: Cid, pid: u32) -> bool {
    let seat = word(cid);
    seat & HELD != 0 && (seat & PID_MASK) as u32 != pid
}

/// Is the task with `pid` the owner of `cid`'s seat, held or not?
#[inline(always)]
pub fn owns(cid: Cid, pid: u32) -> bool {
    pid != 0 && owner(cid) == pid
}

/// Take `cid`'s seat for the task with `pid`, from ops.stopping() on that
/// CID. Returns the generation, 0 if the exchange kept losing.
#[inline(always)]
fn hold(cid: Cid, pid: u32) -> u64 {
    let Some(ctx) = cid.slot::<CidCtx>() else {
        return 0;
    };
    for _ in loops::range(0, CAS_TRIES) {
        let old = ctx.seat().get();
        let seq = ((old >> SEQ_SHIFT) + 1) & (u64::MAX >> SEQ_SHIFT);
        let seq = if seq == 0 { 1 } else { seq };
        let new = (seq << SEQ_SHIFT) | HELD | u64::from(pid);
        if ctx.seat().compare_exchange(old, new) == old {
            return seq;
        }
    }
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
        if old & HELD == 0 {
            return;
        }
        if ctx.seat().compare_exchange(old, old & !HELD) == old {
            return;
        }
    }
}

/// Give `cid`'s seat back, if it is still the acquisition of `pid` with
/// generation `seq`: a later hold by another task stays.
#[inline(always)]
fn release(cid: Cid, pid: u32, seq: u64) {
    let Some(ctx) = cid.slot::<CidCtx>() else {
        return;
    };
    for _ in loops::range(0, CAS_TRIES) {
        let old = ctx.seat().get();
        if (old & PID_MASK) as u32 != pid || old >> SEQ_SHIFT != seq {
            return;
        }
        if ctx.seat().compare_exchange(old, seq << SEQ_SHIFT) == old {
            return;
        }
    }
}

/// Release the seat `ctx` records, unless it is `keep` held under `pid`:
/// a task that runs elsewhere, exits or leaves the class gives its seat
/// back, so that a recycled pid does not inherit it.
#[inline(always)]
pub fn retire(ctx: TaskCtx, pid: u32, keep: OptCid) {
    let seat = ctx.seat_cid().get();
    if seat == 0 {
        return;
    }
    let keep = keep.raw() + 1;
    if seat as i32 == keep && ctx.seat_pid().get() == pid {
        return;
    }
    release(
        Cid(seat as i32 - 1),
        ctx.seat_pid().get(),
        ctx.seat_seq().get(),
    );
    ctx.seat_cid().set(0);
}

/// A stage that blocked on `cid` takes its seat there, giving back the one
/// it held elsewhere.
#[inline(always)]
pub fn take(ctx: TaskCtx, pid: u32, cid: Cid) {
    retire(ctx, pid, OptCid::some(cid));
    let seq = hold(cid, pid);
    if seq == 0 {
        return;
    }
    ctx.seat_seq().set(seq);
    ctx.seat_cid().set(cid.index() + 1);
    ctx.seat_pid().set(pid);
}
