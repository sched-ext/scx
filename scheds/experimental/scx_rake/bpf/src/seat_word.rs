// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The seat word and its transitions, over plain numbers, so that the
//! loader's tests can check them on the host, tests/seat.rs:
//!
//! ```text
//!   63         33  32  31          0
//!  [ generation   |held|    pid     ]
//! ```
//!
//! Each transition takes the word it read and returns the word to swap in,
//! or None when there is nothing to do. seat.rs applies them by compare and
//! exchange.

/// Tries of a compare and exchange before a change gives up. An exchange
/// loses only to a write by the word's other writer, so a change runs out
/// only when the runqueue completes this many transitions inside one
/// release, which tests/seat.rs shows.
pub const CAS_TRIES: u32 = 8;

pub const PID_MASK: u64 = 0xffff_ffff;
pub const HELD: u64 = 1 << 32;
pub const SEQ_SHIFT: u32 = 33;
/// The generation's mask, after the shift.
pub const SEQ_MASK: u64 = u64::MAX >> SEQ_SHIFT;

/// The pid of the task that holds or held the seat, 0 for none.
#[inline(always)]
pub fn owner(word: u64) -> u32 {
    (word & PID_MASK) as u32
}

/// Is the seat held: has nothing run on the CID since its holder blocked?
#[inline(always)]
pub fn held(word: u64) -> bool {
    word & HELD != 0
}

/// The generation of the last hold.
#[inline(always)]
pub fn seq(word: u64) -> u64 {
    word >> SEQ_SHIFT
}

/// A hold by `pid`: the next generation, never 0, which no release
/// records.
#[inline(always)]
pub fn hold(word: u64, pid: u32) -> u64 {
    let next = (seq(word) + 1) & SEQ_MASK;
    let next = if next == 0 { 1 } else { next };
    (next << SEQ_SHIFT) | HELD | u64::from(pid)
}

/// Something ran on the CID: the held bit goes and the owner stays, for a
/// retake. None when the seat is not held.
#[inline(always)]
pub fn run(word: u64) -> Option<u64> {
    if held(word) { Some(word & !HELD) } else { None }
}

/// The release of the hold `pid` made with generation `seq`: no owner and
/// not held, the generation kept. None when the seat is no longer that
/// hold, which a later hold replaced or a release already undid.
#[inline(always)]
pub fn release(word: u64, pid: u32, seq_taken: u64) -> Option<u64> {
    if owner(word) != pid || seq(word) != seq_taken {
        return None;
    }
    Some(seq_taken << SEQ_SHIFT)
}
