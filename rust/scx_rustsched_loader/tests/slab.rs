// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

#[path = "../../scx_rustsched/src/edq.rs"]
#[allow(dead_code)]
mod edq;
#[path = "../../scx_rustsched/src/slab.rs"]
mod slab;

use std::{cell::RefCell, collections::HashSet};

use edq::{Memory, View};

/// Word-addressed memory with no address 0, standing in for the arena.
struct Heap(RefCell<Vec<u64>>);

impl View for &Heap {
    fn load(&self, address: u64) -> u64 {
        assert!(address.is_multiple_of(8) && address != 0);
        self.0.borrow()[(address / 8) as usize]
    }
}

impl Memory for &Heap {
    fn store(&self, address: u64, value: u64) {
        assert!(address.is_multiple_of(8) && address != 0);
        self.0.borrow_mut()[(address / 8) as usize] = value;
    }
    fn release(&self, address: u64, value: u64) {
        self.store(address, value);
    }
    fn cas(&self, address: u64, old: u64, new: u64) -> u64 {
        let previous = self.load(address);
        if previous == old {
            self.store(address, new);
        }
        previous
    }
    fn add(&self, address: u64, value: u64) {
        self.store(address, self.load(address).wrapping_add(value));
    }
    fn repeat(&self, limit: u32, mut body: impl FnMut() -> bool) -> bool {
        (0..limit).any(|_| !body())
    }
}

const HEAD: u64 = 8;
const SIZE: u64 = 512;
const LINK: u64 = 504;
const FIRST: u64 = 4096;

fn heap(slots: u64) -> Heap {
    let heap = Heap(RefCell::new(vec![0; ((FIRST + slots * SIZE) / 8) as usize]));
    (&heap).store(HEAD, slab::empty());
    heap
}

/// Carve `count` slots from `first` as pool.rs does.
fn carve(m: &Heap, first: u64, count: u64) -> bool {
    for index in 0..count - 1 {
        slab::link_next(m, first, index, SIZE, LINK);
    }
    slab::push_chain(m, HEAD, first, first + (count - 1) * SIZE, LINK)
}

#[test]
fn empty_pops_nothing() {
    let heap = heap(1);
    assert_eq!(slab::pop(&heap, HEAD, LINK), 0);
}

#[test]
fn single_slots_are_last_in_first_out() {
    let heap = heap(3);
    for slot in 0..3 {
        assert!(slab::push(&heap, HEAD, FIRST + slot * SIZE, LINK));
    }
    for slot in (0..3).rev() {
        assert_eq!(slab::pop(&heap, HEAD, LINK), FIRST + slot * SIZE);
    }
    assert_eq!(slab::pop(&heap, HEAD, LINK), 0);
}

#[test]
fn a_carved_run_yields_every_slot_once() {
    let heap = heap(64);
    assert!(carve(&heap, FIRST, 64));
    let mut seen = HashSet::new();
    while let slot @ 1.. = slab::pop(&heap, HEAD, LINK) {
        assert!((slot - FIRST).is_multiple_of(SIZE) && slot < FIRST + 64 * SIZE);
        assert!(seen.insert(slot), "slot {slot:#x} popped twice");
    }
    assert_eq!(seen.len(), 64);
}

#[test]
fn a_run_goes_on_top_of_what_is_free() {
    let heap = heap(9);
    assert!(slab::push(&heap, HEAD, FIRST + 8 * SIZE, LINK));
    assert!(carve(&heap, FIRST, 8));
    let popped: Vec<_> = (0..9).map(|_| slab::pop(&heap, HEAD, LINK)).collect();
    assert_eq!(popped[0], FIRST);
    assert_eq!(popped[8], FIRST + 8 * SIZE);
    assert_eq!(slab::pop(&heap, HEAD, LINK), 0);
}

#[test]
fn a_recycled_head_does_not_match_a_stale_read() {
    // A pop reads the head, A with successor B, and stalls. Meanwhile A
    // and B are popped and A is pushed back: the offset is A again, but
    // the generation is not, so the stalled compare fails rather than
    // install B, which is in use.
    let heap = heap(2);
    let (a, b) = (FIRST, FIRST + SIZE);
    assert!(slab::push(&heap, HEAD, b, LINK));
    assert!(slab::push(&heap, HEAD, a, LINK));
    let stale = (&heap).load(HEAD);
    assert_eq!(slab::pop(&heap, HEAD, LINK), a);
    assert_eq!(slab::pop(&heap, HEAD, LINK), b);
    assert!(slab::push(&heap, HEAD, a, LINK));
    let current = (&heap).load(HEAD);
    assert_eq!(current & u64::from(u32::MAX), stale & u64::from(u32::MAX));
    assert_ne!(current, stale);
    assert_eq!(slab::pop(&heap, HEAD, LINK), a);
    assert_eq!(slab::pop(&heap, HEAD, LINK), 0);
}
