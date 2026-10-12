// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Eligible Deadline Queue: an intrusive AVL tree, a port of scx_eevdf's
//! lib/edq.bpf.c.
//!
//! The tree is ordered by deadline, ties broken by insertion order, and every
//! node caches the minimum eligibility and the shortest slice of its subtree.
//! The first eligible task in deadline order, which is what pick_eevdf()
//! searches for, is then one descent from the root, and the shortest queued
//! request is read off the root.
//!
//! Nodes and queues are addressed by plain `u64` addresses, 0 for none, and
//! every access goes through [`Memory`]. In BPF that is the arena, cast at
//! each access, with loops bounded by may_goto, which the verifier does not
//! unroll.
//! The host tests run the same code on ordinary memory.
//!
//! A queued task is its node followed by a hold count and its membership,
//! the address of its queue, 0, or [`DEAD`]. The queue has a lock of its
//! own. Its owner CID takes it in its callbacks, which already hold the rq
//! lock, so the only other holders are remote CIDs peeking or stealing, and
//! those only try it. Lockless snapshots of the first deadline and the
//! shortest slice serve decisions that tolerate a stale value.
//!
//! The snapshots need only [`View`], the loads of [`Memory`]. An observer
//! outside the scheduler, such as the loader reading the arena it mapped,
//! implements that alone: it can read a queue's words and can neither
//! change them nor take the lock.

/// Membership of a task that may never be queued again.
pub const DEAD: u64 = 1;

// Node words.
const PARENT: u64 = 0;
const LEFT: u64 = 1;
const RIGHT: u64 = 2;
const DEADLINE: u64 = 3;
const ELIGIBILITY: u64 = 4;
const MIN_ELIGIBILITY: u64 = 5;
const SLICE: u64 = 6;
const MIN_SLICE: u64 = 7;
const SEQ: u64 = 8;
const HEIGHT: u64 = 9;
// Task words, after the node.
const HOLD: u64 = 10;
const MEMBER: u64 = 11;
/// Words in a queued task.
pub const TASK_WORDS: u64 = 12;

// Queue words.
const ROOT: u64 = 0;
const FIRST: u64 = 1;
const FIRST_DEADLINE: u64 = 2;
const QUEUE_MIN_SLICE: u64 = 3;
const LOCK: u64 = 4;
const NR: u64 = 5;
const QUEUE_SEQ: u64 = 6;
/// Words in a queue.
pub const QUEUE_WORDS: u64 = 7;
/// Bytes a queue takes in a table of them, a cache line each.
pub const QUEUE_BYTES: u64 = 64;
const _: () = assert!(QUEUE_WORDS * 8 <= QUEUE_BYTES);

/// Bound on a walk from the root to a leaf. An AVL tree of 2^40 nodes is
/// shallower than this.
const MAX_DEPTH: u32 = 64;
/// Spinning for a queue lock, or for holders to drop a task, is bounded by
/// can_loop alone, as lib/edq's is. On JITs with timed may_goto, x86 and
/// arm64 among them, that is a quarter of a second per program run, not
/// BPF_MAX_LOOPS iterations. A holder can be held up for milliseconds, by
/// an interrupt or, on a virtual machine, by the host descheduling its
/// vCPU.
///
/// The lock's spin runs in lock_slow(), whose frame is small. With
/// CONFIG_EXT_SUB_SCHED, ops.dispatch() runs on a private stack, which the
/// verifier gives every subprogram of 64 bytes of stack or more, and x86's
/// arch_bpf_timed_may_goto() looks for its timestamp off %rbp rather than
/// the private frame pointer: it reads garbage there and ends the loop
/// after its first 0xffff iterations. Inlined into dispatch's frames, the
/// spin gave up after a few hundred microseconds under steal contention
/// in a 64-vCPU guest, where lib/edq's, in small subprograms, waited.
const MAX_SPINS: u32 = u32::MAX;
const LOCK_SPINS: u32 = u32::MAX;

pub const EINVAL: i32 = -22;
pub const EALREADY: i32 = -114;
pub const ECANCELED: i32 = -125;
pub const E2BIG: i32 = -7;
pub const EBUSY: i32 = -16;
pub const ENOENT: i32 = -2;
pub const ETIMEDOUT: i32 = -110;

/// Read-only word access to queues and tasks.
pub trait View {
    /// Load the word at `address`.
    fn load(&self, address: u64) -> u64;
    /// Load the word at `word` of the node or queue at `base`. A memory
    /// that translates addresses can translate `base` once for all of a
    /// node's words.
    #[inline(always)]
    fn load_word(&self, base: u64, word: u64) -> u64 {
        self.load(base + word * 8)
    }
}

/// Word access to queues and tasks.
pub trait Memory: View {
    /// Store `value` to the word at `address`.
    fn store(&self, address: u64, value: u64);
    /// Store with release ordering.
    fn release(&self, address: u64, value: u64);
    /// Compare and exchange, returning the previous value.
    fn cas(&self, address: u64, old: u64, new: u64) -> u64;
    /// Atomically add a nonzero `value`, discarding the result.
    fn add(&self, address: u64, value: u64);
    /// Store to the word at `word` of `base`, see [`View::load_word`].
    #[inline(always)]
    fn store_word(&self, base: u64, word: u64, value: u64) {
        self.store(base + word * 8, value)
    }
    /// Run `body` until it returns false, at most `limit` times. Returns
    /// whether it stopped by itself.
    fn repeat(&self, limit: u32, body: impl FnMut() -> bool) -> bool;
    /// The tree and a membership disagree, a corruption rather than a race.
    fn corrupt(&self) {}
}

impl<T: View> View for &T {
    fn load(&self, address: u64) -> u64 {
        (**self).load(address)
    }
}

impl<T: Memory> Memory for &T {
    fn store(&self, address: u64, value: u64) {
        (**self).store(address, value)
    }
    fn release(&self, address: u64, value: u64) {
        (**self).release(address, value)
    }
    fn cas(&self, address: u64, old: u64, new: u64) -> u64 {
        (**self).cas(address, old, new)
    }
    fn add(&self, address: u64, value: u64) {
        (**self).add(address, value)
    }
    fn repeat(&self, limit: u32, body: impl FnMut() -> bool) -> bool {
        (**self).repeat(limit, body)
    }
    fn corrupt(&self) {
        (**self).corrupt()
    }
}

/// A resumable position in deadline order, which survives the nodes it
/// passed leaving the tree.
#[derive(Clone, Copy, Default)]
pub struct Cursor {
    pub deadline: u64,
    pub seq: u64,
    /// [`CURSOR_START`], [`CURSOR_AFTER`] or [`CURSOR_AT`] the key.
    pub valid: u64,
}

impl Cursor {
    /// A cursor at the first task. Not `Cursor::default()`: LLVM merges the
    /// zero stores into a memset, which the BPF backend cannot emit.
    #[inline(always)]
    pub fn start() -> Self {
        Self {
            deadline: core::hint::black_box(0),
            seq: core::hint::black_box(0),
            valid: core::hint::black_box(CURSOR_START),
        }
    }
}

/// A cursor that starts at the first task.
pub const CURSOR_START: u64 = 0;
/// A cursor that resumes after its key.
pub const CURSOR_AFTER: u64 = 1;
/// A cursor that resumes at its key, the task it names included.
pub const CURSOR_AT: u64 = 2;

#[inline(always)]
fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}

#[inline(always)]
fn get<M: View + Copy>(m: M, base: u64, word: u64) -> u64 {
    m.load_word(base, word)
}

#[inline(always)]
fn put<M: Memory + Copy>(m: M, base: u64, word: u64, value: u64) {
    m.store_word(base, word, value)
}

#[inline(always)]
fn height<M: Memory + Copy>(m: M, node: u64) -> u64 {
    if node == 0 { 0 } else { get(m, node, HEIGHT) }
}

#[inline(always)]
fn less<M: Memory + Copy>(m: M, a: u64, b: u64) -> bool {
    let (first, second) = (get(m, a, DEADLINE), get(m, b, DEADLINE));
    if first != second {
        time_before(first, second)
    } else {
        get(m, a, SEQ) < get(m, b, SEQ)
    }
}

#[inline(always)]
fn eligible(eligibility: u64, cutoff: u64) -> bool {
    !time_before(cutoff, eligibility)
}

/// Refresh the cached height and subtree minima of `node`.
#[inline(always)]
fn update<M: Memory + Copy>(m: M, node: u64) {
    let (left, right) = (get(m, node, LEFT), get(m, node, RIGHT));
    put(m, node, HEIGHT, height(m, left).max(height(m, right)) + 1);
    let mut min_eligibility = get(m, node, ELIGIBILITY);
    let mut min_slice = get(m, node, SLICE);
    for child in [left, right] {
        if child != 0 {
            let eligibility = get(m, child, MIN_ELIGIBILITY);
            if time_before(eligibility, min_eligibility) {
                min_eligibility = eligibility;
            }
            min_slice = min_slice.min(get(m, child, MIN_SLICE));
        }
    }
    put(m, node, MIN_ELIGIBILITY, min_eligibility);
    put(m, node, MIN_SLICE, min_slice);
}

#[inline(always)]
fn balance<M: Memory + Copy>(m: M, node: u64) -> i64 {
    height(m, get(m, node, LEFT)) as i64 - height(m, get(m, node, RIGHT)) as i64
}

#[inline(always)]
fn replace_child<M: Memory + Copy>(m: M, queue: u64, parent: u64, old: u64, new: u64) {
    if parent == 0 {
        put(m, queue, ROOT, new);
    } else if get(m, parent, LEFT) == old {
        put(m, parent, LEFT, new);
    } else {
        put(m, parent, RIGHT, new);
    }
    if new != 0 {
        put(m, new, PARENT, parent);
    }
}

/// Rotate `node` down to the side `down`, raising its child on the other
/// side, and return that child.
#[inline(always)]
fn rotate<M: Memory + Copy>(m: M, queue: u64, node: u64, down: u64) -> u64 {
    let up = if down == LEFT { RIGHT } else { LEFT };
    let pivot = get(m, node, up);
    replace_child(m, queue, get(m, node, PARENT), node, pivot);
    let inner = get(m, pivot, down);
    put(m, node, up, inner);
    if inner != 0 {
        put(m, inner, PARENT, node);
    }
    put(m, pivot, down, node);
    put(m, node, PARENT, pivot);
    update(m, node);
    update(m, pivot);
    pivot
}

/// Recompute the cached values from `node` up to the root, rotating where
/// the AVL balance is lost. With `may_exit` the walk stops at the first node
/// whose cached values did not change and that was not rotated: nothing
/// above it can change either. That holds only while every node on the path
/// still caches its pre-change values.
#[inline(never)]
fn rebalance_from<M: Memory + Copy>(m: M, queue: u64, node: u64, may_exit: bool) -> i32 {
    let mut node = node;
    m.repeat(MAX_DEPTH, || {
        if node == 0 {
            return false;
        }
        let old = (
            get(m, node, HEIGHT),
            get(m, node, MIN_ELIGIBILITY),
            get(m, node, MIN_SLICE),
        );
        update(m, node);
        let skew = balance(m, node);
        let mut root = node;
        if skew > 1 {
            let left = get(m, node, LEFT);
            if balance(m, left) < 0 {
                rotate(m, queue, left, LEFT);
            }
            root = rotate(m, queue, node, RIGHT);
        } else if skew < -1 {
            let right = get(m, node, RIGHT);
            if balance(m, right) > 0 {
                rotate(m, queue, right, RIGHT);
            }
            root = rotate(m, queue, node, LEFT);
        }
        if may_exit
            && root == node
            && old
                == (
                    get(m, node, HEIGHT),
                    get(m, node, MIN_ELIGIBILITY),
                    get(m, node, MIN_SLICE),
                )
        {
            node = 0;
            return false;
        }
        node = get(m, root, PARENT);
        true
    });
    if node == 0 { 0 } else { E2BIG }
}

/// The leftmost node under `node`, or 0 if the walk ran out.
#[inline(never)]
fn leftmost<M: Memory + Copy>(m: M, node: u64) -> u64 {
    let mut node = node;
    let done = m.repeat(MAX_DEPTH, || {
        let left = get(m, node, LEFT);
        if left == 0 {
            return false;
        }
        node = left;
        true
    });
    if done { node } else { 0 }
}

#[inline(always)]
fn clear_links<M: Memory + Copy>(m: M, node: u64) {
    put(m, node, PARENT, 0);
    put(m, node, LEFT, 0);
    put(m, node, RIGHT, 0);
}

#[inline(never)]
fn remove_locked<M: Memory + Copy>(m: M, queue: u64, task: u64, dead: bool) -> i32 {
    let node = task;
    if get(m, task, MEMBER) != queue {
        return EINVAL;
    }
    let first = get(m, queue, FIRST) == node;
    let mut next_first = 0;
    if first {
        let right = get(m, node, RIGHT);
        if right != 0 {
            next_first = leftmost(m, right);
            if next_first == 0 {
                return E2BIG;
            }
        } else {
            // The leftmost node is its parent's left child.
            next_first = get(m, node, PARENT);
        }
    }
    let (left, right, parent) = (
        get(m, node, LEFT),
        get(m, node, RIGHT),
        get(m, node, PARENT),
    );
    let rebalance;
    let mut may_exit = true;
    if left == 0 || right == 0 {
        rebalance = parent;
        replace_child(m, queue, parent, node, if left != 0 { left } else { right });
    } else {
        let successor = leftmost(m, right);
        if successor == 0 {
            return E2BIG;
        }
        let old_parent = get(m, successor, PARENT);
        if old_parent != node {
            replace_child(m, queue, old_parent, successor, get(m, successor, RIGHT));
            put(m, successor, RIGHT, right);
            put(m, right, PARENT, successor);
            rebalance = old_parent;
        } else {
            rebalance = successor;
        }
        replace_child(m, queue, parent, node, successor);
        put(m, successor, LEFT, left);
        put(m, left, PARENT, successor);
        // The successor stands where the node stood, with cached values
        // its new parent has not seen, and the nodes between its old
        // parent and here still count it below them. The early exit
        // compares cached values and could stop short of them.
        update(m, successor);
        may_exit = false;
    }
    put(m, queue, NR, get(m, queue, NR) - 1);
    if first {
        put(m, queue, FIRST, next_first);
        let deadline = if next_first != 0 {
            get(m, next_first, DEADLINE)
        } else {
            0
        };
        put(m, queue, FIRST_DEADLINE, deadline);
    }
    clear_links(m, node);
    put(m, node, HEIGHT, 1);
    put(m, node, MIN_ELIGIBILITY, get(m, node, ELIGIBILITY));
    put(m, node, MIN_SLICE, get(m, node, SLICE));
    let result = rebalance_from(m, queue, rebalance, may_exit);
    refresh_min_slice(m, queue);
    // Publish the membership last: an insertion into another queue takes
    // that queue's lock, not this one, and claims a free membership at
    // once. Publishing it earlier would let this cleanup overwrite a
    // node already inserted elsewhere.
    m.release(task + MEMBER * 8, if dead { DEAD } else { 0 });
    result
}

#[inline(always)]
fn refresh_min_slice<M: Memory + Copy>(m: M, queue: u64) {
    let root = get(m, queue, ROOT);
    let slice = if root != 0 {
        get(m, root, MIN_SLICE)
    } else {
        0
    };
    put(m, queue, QUEUE_MIN_SLICE, slice);
}

/// Take `queue`'s lock, spinning a bounded time.
pub fn lock<M: Memory + Copy>(m: M, queue: u64) -> i32 {
    // A free lock is taken without setting up the spin.
    if trylock(m, queue) == 0 {
        return 0;
    }
    lock_slow(m, queue)
}

/// The spin of [`lock`], in a function of its own: see LOCK_SPINS.
#[inline(never)]
fn lock_slow<M: Memory + Copy>(m: M, queue: u64) -> i32 {
    let mut taken = false;
    m.repeat(LOCK_SPINS, || {
        taken = get(m, queue, LOCK) == 0 && m.cas(queue + LOCK * 8, 0, 1) == 0;
        !taken
    });
    if taken {
        0
    } else {
        m.corrupt();
        ETIMEDOUT
    }
}

/// Take `queue`'s lock if it is free.
pub fn trylock<M: Memory + Copy>(m: M, queue: u64) -> i32 {
    // Avoid a locked RMW and a cacheline bounce on visible contention.
    if get(m, queue, LOCK) == 0 && m.cas(queue + LOCK * 8, 0, 1) == 0 {
        0
    } else {
        EBUSY
    }
}

pub fn unlock<M: Memory + Copy>(m: M, queue: u64) {
    m.release(queue + LOCK * 8, 0);
}

/// Queue `task` on `queue`. Fails with [`EALREADY`] if it is queued
/// anywhere, and [`ECANCELED`] once it is dead.
pub fn insert<M: Memory + Copy>(
    m: M,
    queue: u64,
    task: u64,
    deadline: u64,
    eligibility: u64,
    slice: u64,
) -> i32 {
    let result = lock(m, queue);
    if result != 0 {
        return result;
    }
    let old = m.cas(task + MEMBER * 8, 0, queue);
    if old != 0 {
        unlock(m, queue);
        return if old == DEAD { ECANCELED } else { EALREADY };
    }
    let node = task;
    clear_links(m, node);
    put(m, node, DEADLINE, deadline);
    put(m, node, ELIGIBILITY, eligibility);
    put(m, node, MIN_ELIGIBILITY, eligibility);
    put(m, node, SLICE, slice);
    put(m, node, MIN_SLICE, slice);
    let seq = get(m, queue, QUEUE_SEQ);
    put(m, node, SEQ, seq);
    put(m, queue, QUEUE_SEQ, seq + 1);
    put(m, node, HEIGHT, 1);

    let mut parent = 0;
    let mut cur = get(m, queue, ROOT);
    m.repeat(MAX_DEPTH, || {
        if cur == 0 {
            return false;
        }
        parent = cur;
        cur = get(m, cur, if less(m, node, cur) { LEFT } else { RIGHT });
        true
    });
    if cur != 0 {
        put(m, task, MEMBER, 0);
        unlock(m, queue);
        return E2BIG;
    }
    put(m, node, PARENT, parent);
    if parent == 0 {
        put(m, queue, ROOT, node);
    } else if less(m, node, parent) {
        put(m, parent, LEFT, node);
    } else {
        put(m, parent, RIGHT, node);
    }
    let first = get(m, queue, FIRST);
    if first == 0 || less(m, node, first) {
        put(m, queue, FIRST, node);
        put(m, queue, FIRST_DEADLINE, deadline);
    }
    put(m, queue, NR, get(m, queue, NR) + 1);
    let result = rebalance_from(m, queue, parent, true);
    refresh_min_slice(m, queue);
    unlock(m, queue);
    result
}

/// Take `task` out of `queue`. [`EINVAL`] if it is not queued there.
pub fn remove<M: Memory + Copy>(m: M, queue: u64, task: u64) -> i32 {
    let result = lock(m, queue);
    if result != 0 {
        return result;
    }
    let result = remove_locked(m, queue, task, false);
    unlock(m, queue);
    result
}

/// As [`remove`], but [`EBUSY`] if the queue is contended.
pub fn try_remove<M: Memory + Copy>(m: M, queue: u64, task: u64) -> i32 {
    let result = trylock(m, queue);
    if result != 0 {
        return result;
    }
    let result = remove_locked(m, queue, task, false);
    unlock(m, queue);
    result
}

/// The first node in deadline order whose eligibility is at or before
/// `cutoff`, or 0: one descent guided by the subtree minima.
#[inline(never)]
fn first_eligible<M: Memory + Copy>(m: M, queue: u64, cutoff: u64) -> u64 {
    let mut node = get(m, queue, ROOT);
    if node == 0 || !eligible(get(m, node, MIN_ELIGIBILITY), cutoff) {
        return 0;
    }
    let mut found = 0;
    m.repeat(MAX_DEPTH, || {
        let left = get(m, node, LEFT);
        if left != 0 && eligible(get(m, left, MIN_ELIGIBILITY), cutoff) {
            node = left;
            return true;
        }
        if eligible(get(m, node, ELIGIBILITY), cutoff) {
            found = node;
            return false;
        }
        let right = get(m, node, RIGHT);
        if right != 0 && eligible(get(m, right, MIN_ELIGIBILITY), cutoff) {
            node = right;
            return true;
        }
        false
    });
    found
}

#[inline(always)]
fn pop_locked<M: Memory + Copy>(m: M, queue: u64, node: u64, hold: bool) -> u64 {
    if node == 0 {
        return 0;
    }
    if hold {
        hold_task(m, node);
    }
    if remove_locked(m, queue, node, false) != 0 {
        // The node came from this queue's own tree under its lock.
        if hold {
            drop_task(m, node);
        }
        m.corrupt();
        return 0;
    }
    node
}

/// Remove and return the first task whose eligibility is at or before
/// `cutoff`, or else the first task, or 0 if the queue is empty. With
/// `hold`, the task is held for the caller.
pub fn pop_first_eligible_or_first<M: Memory + Copy>(
    m: M,
    queue: u64,
    cutoff: u64,
    hold: bool,
) -> u64 {
    if lock(m, queue) != 0 {
        return 0;
    }
    let mut node = first_eligible(m, queue, cutoff);
    if node == 0 {
        node = get(m, queue, FIRST);
    }
    let task = pop_locked(m, queue, node, hold);
    unlock(m, queue);
    task
}

/// Remove and return the first task by deadline, or 0 if the queue is empty.
/// With `hold`, the task is held for the caller.
pub fn pop_first<M: Memory + Copy>(m: M, queue: u64, hold: bool) -> u64 {
    if lock(m, queue) != 0 {
        return 0;
    }
    let task = pop_locked(m, queue, get(m, queue, FIRST), hold);
    unlock(m, queue);
    task
}

/// The deadline of the first eligible task and the shortest queued slice,
/// without removing anything. [`ENOENT`] when nothing queued is eligible,
/// [`EBUSY`] when the queue is contended.
pub fn try_first_eligible_deadline<M: Memory + Copy>(
    m: M,
    queue: u64,
    cutoff: u64,
) -> (i32, u64, u64) {
    let result = trylock(m, queue);
    if result != 0 {
        return (result, 0, 0);
    }
    let root = get(m, queue, ROOT);
    let min_slice = if root != 0 {
        get(m, root, MIN_SLICE)
    } else {
        0
    };
    let node = first_eligible(m, queue, cutoff);
    let found = if node != 0 {
        (0, get(m, node, DEADLINE), min_slice)
    } else {
        (ENOENT, 0, min_slice)
    };
    unlock(m, queue);
    found
}

/// Hold the next task in deadline order after `cursor` and advance it, so
/// that a bounded scan can resume even after the tasks it passed have left.
/// Returns 0 with no task at the end, [`EBUSY`] when contended.
pub fn try_peek_next_hold<M: Memory + Copy>(m: M, queue: u64, cursor: &mut Cursor) -> (i32, u64) {
    let result = trylock(m, queue);
    if result != 0 {
        return (result, 0);
    }
    let mut next = 0;
    let mut result = 0;
    if cursor.valid == CURSOR_START {
        next = get(m, queue, FIRST);
    } else {
        let include = cursor.valid == CURSOR_AT;
        let mut node = get(m, queue, ROOT);
        let done = m.repeat(MAX_DEPTH, || {
            if node == 0 {
                return false;
            }
            let deadline = get(m, node, DEADLINE);
            let after = if cursor.deadline != deadline {
                time_before(cursor.deadline, deadline)
            } else {
                let seq = get(m, node, SEQ);
                cursor.seq < seq || (include && cursor.seq == seq)
            };
            if after {
                next = node;
                node = get(m, node, LEFT);
            } else {
                node = get(m, node, RIGHT);
            }
            true
        });
        if !done {
            result = E2BIG;
        }
    }
    let task = if result == 0 && next != 0 {
        hold_task(m, next);
        cursor.deadline = get(m, next, DEADLINE);
        cursor.seq = get(m, next, SEQ);
        cursor.valid = CURSOR_AFTER;
        next
    } else {
        if result == 0 {
            cursor.valid = CURSOR_START;
        }
        0
    };
    unlock(m, queue);
    (result, task)
}

/// The deadline, eligibility and insertion order a queued task was
/// keyed with.
pub fn key<M: View + Copy>(m: M, task: u64) -> (u64, u64, u64) {
    (
        get(m, task, DEADLINE),
        get(m, task, ELIGIBILITY),
        get(m, task, SEQ),
    )
}

/// How many pops and peeks hold `task`, for debugging dumps.
pub fn hold_count<M: View + Copy>(m: M, task: u64) -> i64 {
    get(m, task, HOLD) as i64
}

/// Lockless snapshot of the first deadline, or `None` when empty.
pub fn first_deadline<M: View + Copy>(m: M, queue: u64) -> Option<u64> {
    if get(m, queue, NR) == 0 {
        None
    } else {
        Some(get(m, queue, FIRST_DEADLINE))
    }
}

/// Lockless snapshot of the shortest queued slice, 0 when empty.
pub fn min_slice<M: View + Copy>(m: M, queue: u64) -> u64 {
    get(m, queue, QUEUE_MIN_SLICE)
}

pub fn nr_queued<M: View + Copy>(m: M, queue: u64) -> u64 {
    get(m, queue, NR)
}

/// Lockless snapshot of how many tasks were ever queued on `queue`.
pub fn nr_inserted<M: View + Copy>(m: M, queue: u64) -> u64 {
    get(m, queue, QUEUE_SEQ)
}

/// Lockless snapshot of whether `queue`'s lock is held.
pub fn locked<M: View + Copy>(m: M, queue: u64) -> bool {
    get(m, queue, LOCK) != 0
}

/// The queue `task` is a member of: its address, 0, or [`DEAD`].
#[allow(dead_code, reason = "read by the host tests")]
pub fn membership<M: View + Copy>(m: M, task: u64) -> u64 {
    get(m, task, MEMBER)
}

pub fn hold_task<M: Memory + Copy>(m: M, task: u64) {
    m.add(task + HOLD * 8, 1);
}

pub fn drop_task<M: Memory + Copy>(m: M, task: u64) {
    m.add(task + HOLD * 8, u64::MAX);
}

/// Is `task` held by a pop or a peek that has not dropped it yet?
pub fn held<M: View + Copy>(m: M, task: u64) -> bool {
    get(m, task, HOLD) as i64 > 0
}

/// Take `task` out of the queue it is in, if any. Returns 1 if it was
/// queued, 0 if not, or an error.
pub fn task_fini<M: Memory + Copy>(m: M, task: u64) -> i32 {
    let mut result = E2BIG;
    m.repeat(MAX_DEPTH, || {
        let queue = get(m, task, MEMBER);
        if queue == 0 || queue == DEAD {
            result = 0;
            return false;
        }
        // A membership that moved between the read and the lock is retried.
        result = remove(m, queue, task);
        if result == EINVAL {
            return true;
        }
        if result == 0 {
            result = 1;
        }
        false
    });
    result
}

/// Bring a fresh task to the state of one queued nowhere and held by
/// nobody, word by word.
pub fn task_init<M: Memory + Copy>(m: M, task: u64) {
    for word in 0..TASK_WORDS {
        put(m, task, word, 0);
    }
}

/// Take `task` out of whatever queue it is in for good, then wait for the
/// holders to drop it, so that its memory can be reused.
pub fn task_detach<M: Memory + Copy>(m: M, task: u64) -> i32 {
    let mut result = 0;
    let done = m.repeat(MAX_DEPTH, || {
        let queue = get(m, task, MEMBER);
        if queue == DEAD {
            return false;
        }
        if queue == 0 {
            return m.cas(task + MEMBER * 8, 0, DEAD) != 0;
        }
        result = lock(m, queue);
        if result != 0 {
            return false;
        }
        if get(m, task, MEMBER) != queue {
            unlock(m, queue);
            return true;
        }
        result = remove_locked(m, queue, task, true);
        unlock(m, queue);
        false
    });
    if result != 0 {
        return result;
    }
    if !done {
        return E2BIG;
    }
    let released = m.repeat(MAX_SPINS, || get(m, task, HOLD) as i64 > 0);
    if released { 0 } else { E2BIG }
}

/// Initialize an empty queue.
pub fn queue_init<M: Memory + Copy>(m: M, queue: u64) {
    for word in 0..QUEUE_WORDS {
        put(m, queue, word, 0);
    }
}
