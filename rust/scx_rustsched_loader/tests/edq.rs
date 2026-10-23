// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

#[path = "../../scx_rustsched/src/edq.rs"]
#[allow(dead_code)]
mod edq;

use std::cell::RefCell;

use edq::{
    Cursor, DEAD, EALREADY, ECANCELED, EINVAL, ENOENT, Memory, QUEUE_WORDS, TASK_WORDS, View,
};

/// Word-addressed memory with no address 0, standing in for the arena.
struct Heap(RefCell<Vec<u64>>);

impl Heap {
    fn new(words: usize) -> Self {
        Self(RefCell::new(vec![0; words + 1]))
    }
}

impl View for Heap {
    fn load(&self, address: u64) -> u64 {
        assert!(address.is_multiple_of(8) && address != 0);
        self.0.borrow()[(address / 8) as usize]
    }
}

impl Memory for Heap {
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
    fn corrupt(&self) {
        panic!("EDQ corruption");
    }
}

/// Words per node as the tree lays them out, see edq.rs.
const PARENT: u64 = 0;
const LEFT: u64 = 1;
const RIGHT: u64 = 2;
const DEADLINE: u64 = 3;
const ELIGIBILITY: u64 = 4;
const MIN_ELIGIBILITY: u64 = 5;
const SLICE: u64 = 6;
const MIN_SLICE: u64 = 7;
const SEQ: u64 = 8;
const COLOR: u64 = 9;
const BLACK: u64 = 1;

struct Fixture {
    heap: Heap,
    queues: u64,
    tasks: u64,
}

impl Fixture {
    fn new(queues: u64, tasks: u64) -> Self {
        let words = (queues * QUEUE_WORDS + tasks * TASK_WORDS) as usize;
        let fixture = Self {
            heap: Heap::new(words),
            queues,
            tasks,
        };
        for queue in 0..queues {
            edq::queue_init(&fixture.heap, fixture.queue(queue));
        }
        for task in 0..tasks {
            edq::task_init(&fixture.heap, fixture.task(task));
        }
        fixture
    }
    fn queue(&self, index: u64) -> u64 {
        8 + index * QUEUE_WORDS * 8
    }
    fn task(&self, index: u64) -> u64 {
        8 + (self.queues * QUEUE_WORDS + index * TASK_WORDS) * 8
    }
    fn index(&self, task: u64) -> u64 {
        (task - self.task(0)) / (TASK_WORDS * 8)
    }
    fn word(&self, base: u64, word: u64) -> u64 {
        self.heap.load(base + word * 8)
    }

    /// Check every invariant of `queue` against the model's (deadline, seq,
    /// eligibility, slice) entries, and return the nodes in order.
    fn check(&self, queue: u64, model: &[Entry]) -> Vec<u64> {
        let root = self.word(queue, 0);
        let mut order = Vec::new();
        if root != 0 {
            assert_eq!(self.word(root, PARENT), 0);
            assert_eq!(self.word(root, COLOR), BLACK, "red root");
            self.walk(root, &mut order);
        }
        assert_eq!(order.len(), model.len());
        for (node, &(task, deadline, seq, eligibility, slice)) in order.iter().zip(model) {
            assert_eq!(*node, self.task(task));
            assert_eq!(self.word(*node, DEADLINE), deadline);
            assert_eq!(self.word(*node, SEQ), seq);
            assert_eq!(self.word(*node, ELIGIBILITY), eligibility);
            assert_eq!(self.word(*node, SLICE), slice);
            assert_eq!(edq::membership(&self.heap, *node), queue);
        }
        assert_eq!(self.word(queue, 1), order.first().copied().unwrap_or(0));
        assert_eq!(edq::nr_queued(&self.heap, queue), order.len() as u64);
        assert_eq!(
            edq::first_deadline(&self.heap, queue),
            model.first().map(|entry| entry.1)
        );
        assert_eq!(
            edq::min_slice(&self.heap, queue),
            model.iter().map(|entry| entry.4).min().unwrap_or(0)
        );
        order
    }

    /// Check a subtree; returns its black height, min eligibility and min
    /// slice.
    fn walk(&self, node: u64, order: &mut Vec<u64>) -> (u64, u64, u64) {
        let red = self.word(node, COLOR) != BLACK;
        let mut black_height = (1, 1);
        let mut min_eligibility = self.word(node, ELIGIBILITY);
        let mut min_slice = self.word(node, SLICE);
        for (side, child) in [(0, self.word(node, LEFT)), (1, self.word(node, RIGHT))] {
            if side == 1 {
                order.push(node);
            }
            if child == 0 {
                continue;
            }
            assert_eq!(self.word(child, PARENT), node);
            assert!(!red || self.word(child, COLOR) == BLACK, "red under red");
            let (h, e, s) = self.walk(child, order);
            if side == 0 {
                black_height.0 = h
            } else {
                black_height.1 = h
            }
            if (e.wrapping_sub(min_eligibility) as i64) < 0 {
                min_eligibility = e;
            }
            min_slice = min_slice.min(s);
        }
        assert_eq!(black_height.0, black_height.1, "black heights differ");
        assert_eq!(self.word(node, MIN_ELIGIBILITY), min_eligibility);
        assert_eq!(self.word(node, MIN_SLICE), min_slice);
        (black_height.0 + u64::from(!red), min_eligibility, min_slice)
    }
}

/// A queued task as the model sees it: (task, deadline, seq, eligibility,
/// slice), kept in deadline order.
type Entry = (u64, u64, u64, u64, u64);

/// xorshift, so the test needs no crates.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}

/// The model's first eligible entry, as pick_eevdf() would find it.
fn model_first_eligible(model: &[Entry], cutoff: u64) -> Option<usize> {
    model.iter().position(|entry| !time_before(cutoff, entry.3))
}

#[test]
fn random_operations_keep_every_invariant() {
    for (seed, base) in [(1, 0), (7, u64::MAX - 5_000), (42, 1 << 40)] {
        let fixture = Fixture::new(2, 300);
        let heap = &fixture.heap;
        let mut random = Random(0x9e37_79b9_7f4a_7c15 ^ seed);
        // Per queue: entries (task, deadline, seq, eligibility, slice) in
        // deadline order, and the next seq.
        let mut models: Vec<(Vec<Entry>, u64)> = vec![(Vec::new(), 0); 2];
        let mut queued: Vec<Option<usize>> = vec![None; fixture.tasks as usize];
        for _ in 0..20_000 {
            let task = random.below(fixture.tasks);
            let index = random.below(2) as usize;
            let queue = fixture.queue(index as u64);
            match (random.below(4), queued[task as usize]) {
                (0 | 1, None) => {
                    // Deadlines collide often to exercise the seq tiebreak.
                    let deadline = base.wrapping_add(random.below(2_000));
                    let eligibility = base.wrapping_add(random.below(2_000));
                    let slice = 1 + random.below(50);
                    let result = {
                        edq::insert(
                            heap,
                            queue,
                            fixture.task(task),
                            deadline,
                            eligibility,
                            slice,
                        )
                    };
                    assert_eq!(result, 0);
                    let (model, seq) = &mut models[index];
                    let at = model
                        .iter()
                        .position(|e| time_before(deadline, e.1))
                        .unwrap_or(model.len());
                    model.insert(at, (task, deadline, *seq, eligibility, slice));
                    *seq += 1;
                    queued[task as usize] = Some(index);
                }
                (0 | 1, Some(_)) => {
                    let result = edq::insert(heap, queue, fixture.task(task), 0, 0, 1);
                    assert_eq!(result, EALREADY);
                }
                (2, Some(member)) => {
                    let other = fixture.queue(1 - member as u64);
                    assert_eq!(edq::remove(heap, other, fixture.task(task)), EINVAL);
                    let own = fixture.queue(member as u64);
                    assert_eq!(edq::remove(heap, own, fixture.task(task)), 0);
                    models[member].0.retain(|e| e.0 != task);
                    queued[task as usize] = None;
                }
                _ => {
                    let cutoff = base.wrapping_add(random.below(2_200));
                    let model = &mut models[index].0;
                    let expected = model_first_eligible(model, cutoff);
                    let (result, deadline, _) =
                        edq::try_first_eligible_deadline(heap, queue, cutoff);
                    match expected {
                        Some(at) => assert_eq!((result, deadline), (0, model[at].1)),
                        None => assert_eq!(result, ENOENT),
                    }
                    let popped = edq::pop_first_eligible_or_first(heap, queue, cutoff, true);
                    let at = expected.or(if model.is_empty() { None } else { Some(0) });
                    match at {
                        Some(at) => {
                            let entry = model.remove(at);
                            assert_eq!(popped, fixture.task(entry.0));
                            edq::drop_task(heap, popped);
                            queued[entry.0 as usize] = None;
                        }
                        None => assert_eq!(popped, 0),
                    }
                }
            }
            for (index, (model, _)) in models.iter().enumerate() {
                fixture.check(fixture.queue(index as u64), model);
            }
        }
        // Detach drains whatever is left and marks the tasks dead.
        for task in 0..fixture.tasks {
            assert_eq!(edq::task_detach(heap, fixture.task(task)), 0);
            assert_eq!(edq::membership(heap, fixture.task(task)), DEAD);
        }
        for index in 0..2 {
            fixture.check(fixture.queue(index), &[]);
        }
        assert_eq!(
            edq::insert(heap, fixture.queue(0), fixture.task(0), 0, 0, 1),
            ECANCELED
        );
    }
}

#[test]
fn cursor_scans_in_order_across_removals() {
    let fixture = Fixture::new(1, 64);
    let heap = &fixture.heap;
    let queue = fixture.queue(0);
    for task in 0..64 {
        // Pairs of equal deadlines, tied by insertion order.
        let result = edq::insert(heap, queue, fixture.task(task), 1000 + task / 2, 0, 10);
        assert_eq!(result, 0);
    }
    let mut cursor = Cursor::default();
    let mut seen = Vec::new();
    loop {
        let (result, task) = edq::try_peek_next_hold(heap, queue, &mut cursor);
        assert_eq!(result, 0);
        if task == 0 {
            break;
        }
        seen.push(fixture.index(task));
        edq::drop_task(heap, task);
        // Removing what was just seen does not lose the position.
        if seen.len() % 3 == 0 {
            assert_eq!(edq::remove(heap, queue, task), 0);
        }
    }
    assert_eq!(seen, (0..64).collect::<Vec<_>>());
}

#[test]
fn contended_queue_is_reported_busy() {
    let fixture = Fixture::new(1, 1);
    let heap = &fixture.heap;
    let queue = fixture.queue(0);
    assert_eq!(edq::trylock(heap, queue), 0);
    assert_eq!(
        edq::try_first_eligible_deadline(heap, queue, 0).0,
        edq::EBUSY
    );
    assert_eq!(edq::try_remove(heap, queue, fixture.task(0)), edq::EBUSY);
    edq::unlock(heap, queue);
    assert_eq!(edq::try_first_eligible_deadline(heap, queue, 0).0, ENOENT);
}

/// A memory that can only load, as the loader's view of the arena is.
struct Observer<'a>(&'a Heap);

impl View for Observer<'_> {
    fn load(&self, address: u64) -> u64 {
        self.0.load(address)
    }
}

#[test]
fn read_only_view_follows_the_queue() {
    let fixture = Fixture::new(1, 3);
    let heap = &fixture.heap;
    let observer = &Observer(heap);
    let queue = fixture.queue(0);
    for task in 0..3 {
        assert_eq!(
            edq::insert(heap, queue, fixture.task(task), 10 - task, 0, 1 + task),
            0
        );
    }
    assert_eq!(edq::pop_first(heap, queue, false), fixture.task(2));
    assert_eq!(edq::nr_queued(observer, queue), 2);
    assert_eq!(edq::nr_inserted(observer, queue), 3);
    assert_eq!(edq::first_deadline(observer, queue), Some(9));
    assert_eq!(edq::min_slice(observer, queue), 1);
    assert!(!edq::locked(observer, queue));
    assert_eq!(edq::trylock(heap, queue), 0);
    assert!(edq::locked(observer, queue));
    edq::unlock(heap, queue);
    assert!(!edq::locked(observer, queue));
}

#[test]
fn fini_takes_a_task_out_and_holds_are_counted() {
    let fixture = Fixture::new(1, 2);
    let heap = &fixture.heap;
    let queue = fixture.queue(0);
    let (task, other) = (fixture.task(0), fixture.task(1));
    assert_eq!(edq::insert(heap, queue, task, 5, 0, 1), 0);
    assert_eq!(edq::insert(heap, queue, other, 6, 0, 1), 0);
    assert_eq!(edq::task_fini(heap, task), 1);
    assert_eq!(edq::task_fini(heap, task), 0);
    assert_eq!(edq::membership(heap, task), 0);
    fixture.check(queue, &[(1, 6, 1, 0, 1)]);
    assert!(!edq::held(heap, other));
    edq::hold_task(heap, other);
    assert!(edq::held(heap, other));
    edq::drop_task(heap, other);
    assert!(!edq::held(heap, other));
}

#[test]
fn cursor_can_resume_at_its_key() {
    let fixture = Fixture::new(1, 4);
    let heap = &fixture.heap;
    let queue = fixture.queue(0);
    for task in 0..4 {
        assert_eq!(
            edq::insert(heap, queue, fixture.task(task), 100 + task, 0, 1),
            0
        );
    }
    let (deadline, _, seq) = edq::key(heap, fixture.task(2));
    let mut cursor = Cursor {
        deadline,
        seq,
        valid: edq::CURSOR_AT,
    };
    let (result, task) = edq::try_peek_next_hold(heap, queue, &mut cursor);
    assert_eq!((result, fixture.index(task)), (0, 2));
    edq::drop_task(heap, task);
    let (_, task) = edq::try_peek_next_hold(heap, queue, &mut cursor);
    assert_eq!(fixture.index(task), 3);
    edq::drop_task(heap, task);
}
