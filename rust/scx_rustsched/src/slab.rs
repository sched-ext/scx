// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The free list of task context slots: a lock-free stack in the arena,
//! generic over the memory it runs on so that the host can test it.
//!
//! The pool grows by carving freshly allocated pages into slots and never
//! gives a page back. A context address therefore stays mapped for the
//! scheduler's lifetime, which a remote reader holding a queued node relies
//! on, and no page is ever recycled under a reader the way arena frees can
//! publish a range before its TLB flush.
//!
//! The head is one word, `generation << 32 | offset`. An arena never
//! crosses a 4 GiB boundary, so the low 32 bits of an address locate it
//! and the head's own upper bits supply the rest. Every push and pop bumps
//! the generation, so a pop that read a head, lost the CPU while that slot
//! was popped and pushed back, and then compares, fails instead of
//! installing a stale successor: the ABA problem a bare pointer has.
//! Slots are 512-byte aligned, so no offset is all ones, which marks the
//! empty stack.

use crate::edq::Memory;

/// The offset of an empty stack.
pub const EMPTY: u64 = u32::MAX as u64;
/// Compare-and-exchange attempts before an operation gives up.
pub const RETRIES: u32 = 1024;

const LOW: u64 = u32::MAX as u64;

/// The head word of an empty stack.
pub const fn empty() -> u64 {
    EMPTY
}

#[inline(always)]
fn next_head(head: u64, offset: u64) -> u64 {
    (head & !LOW).wrapping_add(1 << 32) | offset
}

/// Push the chain `first` to `last`, already linked through the word at
/// `link` bytes into each slot, onto the stack whose head is at `head`.
/// Returns false if the head stayed contended through every retry.
///
/// # Safety
/// `head` and the chain must be valid for `m`, and the chain private to
/// the caller.
pub unsafe fn push_chain<M: Memory + Copy>(
    m: M,
    head: u64,
    first: u64,
    last: u64,
    link: u64,
) -> bool {
    m.repeat(RETRIES, || unsafe {
        let old = m.load(head);
        m.store(last + link, old & LOW);
        m.cas(head, old, next_head(old, first & LOW)) != old
    })
}

/// Push one `slot`, see [`push_chain`].
///
/// # Safety
/// As [`push_chain`].
pub unsafe fn push<M: Memory + Copy>(m: M, head: u64, slot: u64, link: u64) -> bool {
    unsafe { push_chain(m, head, slot, slot, link) }
}

/// Pop a slot from the stack at `head`: its address, or 0 if the stack is
/// empty or stayed contended through every retry.
///
/// The successor is read from a slot another CPU may have popped in the
/// meantime. Its page is never freed, so the read is safe, and the
/// generation makes the compare fail if the value read was stale.
///
/// # Safety
/// `head` and every slot on the stack must be valid for `m`.
pub unsafe fn pop<M: Memory + Copy>(m: M, head: u64, link: u64) -> u64 {
    let base = head & !LOW;
    let mut popped = 0;
    m.repeat(RETRIES, || unsafe {
        let old = m.load(head);
        let offset = old & LOW;
        if offset == EMPTY {
            return false;
        }
        let slot = base | offset;
        let next = m.load(slot + link) & LOW;
        if m.cas(head, old, next_head(old, next)) == old {
            popped = slot;
            return false;
        }
        true
    });
    popped
}

/// Link slot `index` of a fresh run of `size`-byte slots from `first` to
/// the one after it, through the word at `link` bytes into it. A caller
/// links all but the last, then pushes the run with [`push_chain`]. The
/// loop over the run is the caller's, for BPF to bound it with may_goto.
///
/// # Safety
/// The run must be valid for `m` and private to the caller.
#[inline(always)]
pub unsafe fn link_next<M: Memory + Copy>(m: M, first: u64, index: u64, size: u64, link: u64) {
    let slot = first + index * size;
    unsafe { m.store(slot + link, (slot + size) & LOW) };
}
