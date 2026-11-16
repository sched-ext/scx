// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The seat protocol, bpf/src/seat_word.rs applied as bpf/src/seat.rs
//! applies it, under every interleaving of the word's two writers.
//!
//! The runqueue of the seat's CID runs a sequence of holds and clears, one
//! at a time. The task that took the first hold releases it from another
//! CPU, after that hold, as a task's own callbacks are ordered. Each change
//! is a load and a compare and exchange, retried CAS_TRIES times, and the
//! two writers interleave at every load and every exchange. The test walks
//! every interleaving and checks that:
//!
//! - every run ends in a word some serial order of the changes gives, with
//!   the release anywhere after the hold it releases;
//! - a hold leaves the seat held by its pid, and a clear leaves it unheld,
//!   at the instant each completes;
//! - the release loses at most two exchanges and each change of the
//!   runqueue at most one, so CAS_TRIES never runs out, whatever the
//!   runqueue does meanwhile.
//!
//! The bound: the release swaps only a word that is still its hold, the
//! holder's pid with the generation it took. The runqueue can rewrite such
//! a word in one way that keeps it so, a clear, which takes the held bit,
//! and every hold changes the generation, after which the release has
//! nothing to do. So the release loses to at most a clear and a hold. The
//! releaser writes once, so a change of the runqueue loses at most once.

use std::collections::HashSet;

#[path = "../bpf/src/seat_word.rs"]
#[allow(dead_code)]
mod seat_word;

use seat_word::{CAS_TRIES, held, hold, owner, release, run, seq};

const HOLDER: u32 = 100;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Op {
    Hold(u32),
    Run,
}

/// Where a writer is in its current change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Step {
    Load { tries: u32 },
    Swap { old: u64, new: u64, tries: u32 },
}

/// The releasing task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Release {
    /// Its hold has not completed yet.
    Waiting,
    Running(Step),
    /// Done: whether the word is no longer its hold.
    Done(bool),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct State {
    word: u64,
    /// The runqueue's next change and where it is in it.
    next: usize,
    step: Step,
    /// The generation of the hold being released, once it completed.
    taken: Option<u64>,
    release: Release,
}

/// The word a serial order gives, the release after change `after`.
fn serial(ops: &[Op], after: usize, released: bool) -> u64 {
    let mut word = 0;
    let mut taken = 0;
    for (index, op) in ops.iter().enumerate() {
        word = match *op {
            Op::Hold(pid) => hold(word, pid),
            Op::Run => run(word).unwrap_or(word),
        };
        if index == 0 {
            taken = seq(word);
        }
        if released && index == after {
            word = release(word, HOLDER, taken).unwrap_or(word);
        }
    }
    word
}

struct Explorer<'a> {
    ops: &'a [Op],
    seen: HashSet<State>,
    /// Final words of the runs, with whether the release was made.
    finals: HashSet<(u64, bool)>,
    release_ran_out: bool,
    /// The most exchanges a release and a runqueue change lost.
    release_lost: u32,
    runqueue_lost: u32,
}

impl Explorer<'_> {
    fn walk(&mut self, state: State) {
        if !self.seen.insert(state.clone()) {
            return;
        }
        let runqueue_done = state.next == self.ops.len();
        let release_done = matches!(state.release, Release::Done(_));
        if runqueue_done && release_done {
            let Release::Done(made) = state.release else {
                unreachable!()
            };
            self.finals.insert((state.word, made));
            return;
        }
        if !runqueue_done {
            let next = self.runqueue_step(state.clone());
            self.walk(next);
        }
        if let Some(next) = self.release_step(&state) {
            self.walk(next);
        }
    }

    /// One load or exchange of the runqueue's current change.
    fn runqueue_step(&mut self, mut state: State) -> State {
        let op = self.ops[state.next];
        match state.step {
            Step::Load { tries } => {
                let old = state.word;
                let new = match op {
                    Op::Hold(pid) => Some(hold(old, pid)),
                    Op::Run => run(old),
                };
                match new {
                    Some(new) => state.step = Step::Swap { old, new, tries },
                    None => self.complete(&mut state, op),
                }
            }
            Step::Swap { old, new, tries } => {
                if state.word == old {
                    state.word = new;
                    if state.next == 0 {
                        state.taken = Some(seq(new));
                        state.release = Release::Running(Step::Load { tries: 0 });
                    }
                    self.complete(&mut state, op);
                } else {
                    // The releaser writes once, so the runqueue cannot lose
                    // CAS_TRIES times.
                    assert!(tries + 1 < CAS_TRIES, "the runqueue ran out of tries");
                    state.step = Step::Load { tries: tries + 1 };
                    self.runqueue_lost = self.runqueue_lost.max(tries + 1);
                }
            }
        }
        state
    }

    /// The runqueue's change completed: check what it promises.
    fn complete(&self, state: &mut State, op: Op) {
        match op {
            Op::Hold(pid) => {
                assert!(
                    held(state.word) && owner(state.word) == pid,
                    "{op:?} left {state:?}"
                );
            }
            Op::Run => assert!(!held(state.word), "{op:?} left {state:?}"),
        }
        state.next += 1;
        state.step = Step::Load { tries: 0 };
    }

    /// One load or exchange of the release, once its hold completed.
    fn release_step(&mut self, state: &State) -> Option<State> {
        let Release::Running(step) = state.release else {
            return None;
        };
        let taken = state.taken?;
        let mut state = state.clone();
        match step {
            Step::Load { tries } => match release(state.word, HOLDER, taken) {
                None => state.release = Release::Done(true),
                Some(new) => {
                    state.release = Release::Running(Step::Swap {
                        old: state.word,
                        new,
                        tries,
                    })
                }
            },
            Step::Swap { old, new, tries } => {
                if state.word == old {
                    state.word = new;
                    state.release = Release::Done(true);
                } else if tries + 1 == CAS_TRIES {
                    self.release_lost = self.release_lost.max(tries + 1);
                    self.release_ran_out = true;
                    state.release = Release::Done(false);
                } else {
                    self.release_lost = self.release_lost.max(tries + 1);
                    state.release = Release::Running(Step::Load { tries: tries + 1 });
                }
            }
        }
        Some(state)
    }
}

/// What the walk found: the most exchanges lost, by the release and by a
/// change of the runqueue, and whether the release ever ran out.
struct Found {
    finals: HashSet<(u64, bool)>,
    release_lost: u32,
    runqueue_lost: u32,
    ran_out: bool,
}

/// Walk every interleaving of `ops` on the runqueue and the release of its
/// first change, a hold by HOLDER, and check each final word.
fn explore(ops: &[Op]) -> Found {
    assert_eq!(ops[0], Op::Hold(HOLDER));
    let mut explorer = Explorer {
        ops,
        seen: HashSet::new(),
        finals: HashSet::new(),
        release_ran_out: false,
        release_lost: 0,
        runqueue_lost: 0,
    };
    explorer.walk(State {
        word: 0,
        next: 0,
        step: Step::Load { tries: 0 },
        taken: None,
        release: Release::Waiting,
    });
    let serial_made: HashSet<u64> = (0..ops.len())
        .map(|after| serial(ops, after, true))
        .collect();
    let serial_not = serial(ops, 0, false);
    for (word, made) in &explorer.finals {
        if *made {
            assert!(
                serial_made.contains(word),
                "{ops:?}: final {word:#x} is no serial order's"
            );
        } else {
            assert_eq!(
                *word, serial_not,
                "{ops:?}: a release that ran out changed the word"
            );
        }
    }
    Found {
        finals: explorer.finals,
        release_lost: explorer.release_lost,
        runqueue_lost: explorer.runqueue_lost,
        ran_out: explorer.release_ran_out,
    }
}

/// The runqueue's changes after the first hold: a seat taken and cleared
/// by `writes / 2` other tasks.
fn churn(writes: usize) -> Vec<Op> {
    let mut ops = vec![Op::Hold(HOLDER)];
    for index in 0..writes {
        ops.push(if index % 2 == 0 {
            Op::Run
        } else {
            Op::Hold(index as u32)
        });
    }
    ops
}

/// Check the bound on `ops`, and that it is reached where it can be.
fn bounded(ops: &[Op]) -> Found {
    let found = explore(ops);
    assert!(!found.ran_out, "{ops:?}: the release ran out of tries");
    assert!(
        found.release_lost <= 2,
        "{ops:?}: the release lost {}",
        found.release_lost
    );
    assert!(
        found.runqueue_lost <= 1,
        "{ops:?}: a change lost {}",
        found.runqueue_lost
    );
    found
}

#[test]
fn release_after_another_hold_does_nothing() {
    // The holder clears, another task holds: a late release is a no-op.
    let found = bounded(&[Op::Hold(HOLDER), Op::Run, Op::Hold(7), Op::Run]);
    // A clear, then a hold, inside one release: both losses happen.
    assert_eq!(found.release_lost, 2);
    assert_eq!(found.runqueue_lost, 1);
}

/// Does every run end with the seat held by `pid`?
fn ends_held_by(found: &Found, pid: u32) -> bool {
    found
        .finals
        .iter()
        .all(|(word, _)| held(*word) && owner(*word) == pid)
}

#[test]
fn a_second_hold_by_the_same_task_survives_the_first_release() {
    // The release of the first hold, wherever it lands, never undoes the
    // second: the generation tells the two apart.
    let found = bounded(&[Op::Hold(HOLDER), Op::Run, Op::Hold(HOLDER)]);
    assert!(ends_held_by(&found, HOLDER));
}

#[test]
fn a_late_release_never_undoes_another_task_s_hold() {
    let found = bounded(&[Op::Hold(HOLDER), Op::Run, Op::Hold(7)]);
    assert!(ends_held_by(&found, 7));
}

#[test]
fn no_runqueue_exhausts_the_retry_budget() {
    // Far more runqueue writes than CAS_TRIES inside the release.
    for writes in 0..3 * CAS_TRIES as usize {
        bounded(&churn(writes));
    }
}

#[test]
fn a_hold_right_after_the_first_loses_the_release_nothing() {
    // No clear between: the next hold changes the generation at once.
    let found = bounded(&[Op::Hold(HOLDER), Op::Hold(3), Op::Run]);
    assert!(found.release_lost <= 1);
}
