// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Loops, after scx's bpf_arena_for().
//!
//! The numeric iterator, bpf_for(), calls bpf_iter_num_next() on every
//! iteration, so nothing here uses it. This is a counted loop bounded by
//! may_goto, can_loop, which the verifier lets run for at most
//! BPF_MAX_LOOPS iterations per program run. A counter the
//! verifier tracked as a precise constant would keep a may_goto loop from
//! converging: every iteration would be a new state, unrolled until the
//! budget runs out. So the step is loaded from a writable global, LOOP_ONE,
//! which the verifier sees as an unknown scalar while its value is always
//! one, as bpf_arena_loop_one is.

use core::{
    arch::asm,
    ptr::{addr_of, read_volatile},
};

/// The loop step, always one; see the module comment. Never changed.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.loopone")]
pub static mut LOOP_ONE: u32 = 1;

/// may_goto: false once the program has used up its loop budget. The jump
/// stays inside one asm block, which skips setting the flag when the budget
/// is out: LLVM's BPF backend misallocated registers across an asm goto
/// with a label operand, keeping a value in a register a call clobbers.
#[inline(always)]
pub fn can_loop() -> bool {
    let left: u64;
    unsafe {
        asm!(
            "{left} = 0",
            "may_goto 2f",
            "{left} = 1",
            "2:",
            left = out(reg) left,
            options(nostack),
        );
    }
    left != 0
}

/// Run `body` for each `index` from `start` to `end`, until it returns
/// false or the loop budget runs out. Returns whether `body` stopped it.
#[inline(always)]
pub fn arena_for(start: u32, end: u32, mut body: impl FnMut(u32) -> bool) -> bool {
    let mut index = start;
    while index < end && can_loop() {
        if !body(index) {
            return true;
        }
        index = index.wrapping_add(unsafe { read_volatile(addr_of!(LOOP_ONE)) });
    }
    false
}

/// The numbers of `start..end`, one at a time, until the loop budget runs
/// out: bpf_arena_for() for a `for` loop.
pub struct Range {
    next: u32,
    end: u32,
}

/// `for index in range(start, end)`, scx's bpf_arena_for(index, start, end).
#[inline(always)]
pub fn range(start: u32, end: u32) -> Range {
    Range { next: start, end }
}

impl Iterator for Range {
    type Item = u32;

    #[inline(always)]
    fn next(&mut self) -> Option<u32> {
        if self.next < self.end && can_loop() {
            let index = self.next;
            self.next = index.wrapping_add(unsafe { read_volatile(addr_of!(LOOP_ONE)) });
            Some(index)
        } else {
            None
        }
    }
}
