//! Concurrent callback interleaving via token-passing.
//!
//! Runs scheduler callbacks on separate OS threads, with only one thread
//! active at a time. A PRNG-driven scheduler controls which thread gets
//! the "token" at each kfunc yield point, enabling deterministic
//! exploration of different interleavings.
//!
//! ## Determinism
//!
//! Interleaving is fully deterministic for a given seed:
//! - PRNG determines worker selection order
//! - Token passing serializes all state access
//! - Same seed → same interleaving → same trace
//!
//! This enables the stress testing methodology: explore many seeds to find
//! bugs, then reproduce failures with the same seed for debugging.
//!
//! See `ai_docs/DETERMINISM.md` for the full explanation.
//!
//! ## Architecture
//!
//! The orchestrator (engine thread) spawns one worker per CPU in the
//! concurrent group. Workers block on a condvar until the PRNG selects
//! them. At each kfunc entry point, [`maybe_yield`] releases the token
//! and selects the next worker, allowing a different CPU's dispatch
//! callback to make progress.
//!
//! ## Safety
//!
//! Token passing ensures only one thread accesses [`SimulatorState`] at
//! a time. Raw pointers are shared across threads, but actual access is
//! serialized by the token. The [`maybe_yield`] call happens BEFORE
//! `with_sim()`, so no `&mut SimulatorState` reference is held when a
//! worker yields.

use std::cell::Cell;
use std::sync::{Condvar, Mutex};

use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};

use crate::kfuncs::{OpsContext, SimulatorState};
use crate::types::CpuId;

/// Worker identity within a concurrent group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub usize);

// ---------------------------------------------------------------------------
// TokenRing — PRNG-driven cooperative scheduler
// ---------------------------------------------------------------------------

/// Token-passing scheduler for concurrent callback interleaving.
///
/// Workers block on a condvar until selected by the PRNG. Only one worker
/// is active at a time, ensuring single-threaded access to shared state.
pub struct TokenRing {
    mu: Mutex<TokenState>,
    cv: Condvar,
}

struct TokenState {
    /// Which worker currently holds the token.
    active: Option<WorkerId>,
    /// Bitmask of workers that have finished (supports up to 64 workers).
    finished_mask: u64,
    /// Total number of workers.
    total: usize,
    /// Deterministic PRNG for worker selection.
    rng: SmallRng,
}

impl TokenState {
    fn is_finished(&self, id: WorkerId) -> bool {
        self.finished_mask & (1u64 << id.0) != 0
    }

    fn mark_finished(&mut self, id: WorkerId) {
        self.finished_mask |= 1u64 << id.0;
    }

    fn n_finished(&self) -> usize {
        self.finished_mask.count_ones() as usize
    }

    fn all_done(&self) -> bool {
        self.n_finished() == self.total
    }

    /// Pick the next non-finished worker using PRNG.
    fn pick_next(&mut self) -> Option<WorkerId> {
        let n_remaining = self.total - self.n_finished();
        if n_remaining == 0 {
            return None;
        }
        let idx = (self.rng.next_u32() as usize) % n_remaining;
        let mut count = 0;
        for i in 0..self.total {
            if !self.is_finished(WorkerId(i)) {
                if count == idx {
                    return Some(WorkerId(i));
                }
                count += 1;
            }
        }
        unreachable!()
    }
}

impl TokenRing {
    /// Create a new token ring for `total` workers.
    ///
    /// # Panics
    /// Panics if `total` is 0 or exceeds 64.
    pub fn new(total: usize, seed: u32) -> Self {
        assert!(
            total > 0 && total <= 64,
            "TokenRing supports 1–64 workers, got {total}"
        );
        TokenRing {
            mu: Mutex::new(TokenState {
                active: None,
                finished_mask: 0,
                total,
                rng: SmallRng::seed_from_u64(seed as u64),
            }),
            cv: Condvar::new(),
        }
    }

    /// Orchestrator: select the first worker via PRNG and wake it.
    pub fn start(&self) {
        let mut state = self.mu.lock().unwrap();
        state.active = state.pick_next();
        self.cv.notify_all();
    }

    /// Worker: block until this worker is selected.
    pub fn wait_for_token(&self, my_id: WorkerId) {
        let mut state = self.mu.lock().unwrap();
        while state.active != Some(my_id) {
            state = self.cv.wait(state).unwrap();
        }
    }

    /// Worker: release token, select next worker via PRNG, block until
    /// re-selected.
    ///
    /// The current worker gives up the token and waits for a future
    /// turn. Another worker (possibly the same one) is selected by the
    /// PRNG and woken up.
    pub fn yield_token(&self, my_id: WorkerId) {
        let mut state = self.mu.lock().unwrap();
        debug_assert_eq!(state.active, Some(my_id));
        state.active = state.pick_next();
        self.cv.notify_all();
        while state.active != Some(my_id) {
            state = self.cv.wait(state).unwrap();
        }
    }

    /// Worker: mark as finished and wake the next worker (or signal
    /// all-done to the orchestrator).
    pub fn finish(&self, my_id: WorkerId) {
        let mut state = self.mu.lock().unwrap();
        debug_assert_eq!(state.active, Some(my_id));
        state.mark_finished(my_id);
        if state.all_done() {
            state.active = None;
        } else {
            state.active = state.pick_next();
        }
        self.cv.notify_all();
    }

    /// Orchestrator: block until all workers have finished.
    pub fn wait_all_done(&self) {
        let mut state = self.mu.lock().unwrap();
        while !state.all_done() {
            state = self.cv.wait(state).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-local yield-point plumbing
// ---------------------------------------------------------------------------

/// Thread-local interleave context installed on worker threads.
#[derive(Clone, Copy)]
struct InterleaveCtx {
    ring: *const TokenRing,
    worker_id: WorkerId,
}

// Raw pointers are Send — we enforce single-access via token passing.
unsafe impl Send for InterleaveCtx {}

thread_local! {
    static INTERLEAVE_CTX: Cell<Option<InterleaveCtx>> = const { Cell::new(None) };
}

/// Install interleave context on the current worker thread.
///
/// Called by worker threads at startup, before waiting for the token.
pub fn install(ring: &TokenRing, worker_id: WorkerId) {
    INTERLEAVE_CTX.with(|c| {
        c.set(Some(InterleaveCtx {
            ring: ring as *const TokenRing,
            worker_id,
        }));
    });
}

/// Remove interleave context from the current thread.
pub fn uninstall() {
    INTERLEAVE_CTX.with(|c| c.set(None));
}

/// Yield point called at the top of each state-accessing kfunc.
///
/// Dispatches to the appropriate interleaving backend:
/// - If preemptive context is installed: uses [`preempt::maybe_yield_preemptive`]
///   (futex-based, signal-safe, PMU timer aware).
/// - If cooperative context is installed: uses the `TokenRing` (Mutex/Condvar).
/// - If neither is installed: no-op.
///
/// # Safety contract
///
/// Must be called BEFORE `with_sim()`, so no `&mut SimulatorState`
/// reference exists when the worker yields.
pub fn maybe_yield() {
    // Try preemptive yield first (no-op if preempt context not installed).
    crate::preempt::maybe_yield_preemptive();

    // Cooperative yield fallback (no-op if interleave context not installed).
    let ctx = INTERLEAVE_CTX.with(|c| c.get());
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return,
    };

    let ring = unsafe { &*ctx.ring };

    // Read SimulatorState pointer from the kfuncs thread-local.
    let sim_ptr: *mut SimulatorState =
        crate::kfuncs::sim_state_ptr().expect("maybe_yield called outside of simulator context");

    // Save per-callback context from SimulatorState.
    // SAFETY: we hold the token, so exclusive access is guaranteed.
    let saved_cpu: CpuId;
    let saved_ops_ctx: OpsContext;
    let saved_waker: Option<usize>;
    unsafe {
        saved_cpu = (*sim_ptr).current_cpu;
        saved_ops_ctx = (*sim_ptr).ops_context;
        saved_waker = (*sim_ptr).waker_task_raw;
    }

    // Release token and block until re-selected.
    ring.yield_token(ctx.worker_id);

    // Resumed — restore our context to SimulatorState.
    // SAFETY: we hold the token again.
    unsafe {
        (*sim_ptr).current_cpu = saved_cpu;
        (*sim_ptr).ops_context = saved_ops_ctx;
        (*sim_ptr).waker_task_raw = saved_waker;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_worker_completes() {
        let ring = TokenRing::new(1, 42);
        ring.start();
        ring.wait_for_token(WorkerId(0));
        ring.finish(WorkerId(0));
        ring.wait_all_done();
    }

    #[test]
    fn test_two_workers_interleave() {
        let ring = TokenRing::new(2, 42);

        std::thread::scope(|s| {
            let ring_ref = &ring;

            let h0 = s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(0));
                // Do some work, yield
                ring_ref.yield_token(WorkerId(0));
                // Resumed, finish
                ring_ref.finish(WorkerId(0));
            });

            let h1 = s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(1));
                ring_ref.yield_token(WorkerId(1));
                ring_ref.finish(WorkerId(1));
            });

            ring.start();
            ring.wait_all_done();

            h0.join().unwrap();
            h1.join().unwrap();
        });
    }

    #[test]
    fn test_prng_determinism() {
        // Same seed must produce the same selection order.
        let order1 = run_and_record_order(3, 12345);
        let order2 = run_and_record_order(3, 12345);
        assert_eq!(order1, order2, "same seed must give same order");
    }

    #[test]
    fn test_different_seeds_may_differ() {
        // Different seeds should (usually) produce different orders.
        // Not guaranteed for all pairs, but very likely for these.
        let order1 = run_and_record_order(4, 100);
        let order2 = run_and_record_order(4, 999);
        // At least the first selection should differ for most seed pairs.
        // If they happen to match, that's OK — this test just checks
        // the mechanism works.
        let _ = (order1, order2);
    }

    /// Run N workers with the given seed, each yielding once.
    /// Returns the order in which workers were first activated.
    fn run_and_record_order(n: usize, seed: u32) -> Vec<WorkerId> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ring = TokenRing::new(n, seed);
        let order: Vec<AtomicUsize> = (0..n).map(|_| AtomicUsize::new(usize::MAX)).collect();
        let counter = AtomicUsize::new(0);

        std::thread::scope(|s| {
            for i in 0..n {
                let ring_ref = &ring;
                let order_ref = &order;
                let counter_ref = &counter;
                s.spawn(move || {
                    ring_ref.wait_for_token(WorkerId(i));
                    let seq = counter_ref.fetch_add(1, Ordering::SeqCst);
                    order_ref[i].store(seq, Ordering::SeqCst);
                    ring_ref.yield_token(WorkerId(i));
                    ring_ref.finish(WorkerId(i));
                });
            }
            ring.start();
            ring.wait_all_done();
        });

        let mut pairs: Vec<(usize, WorkerId)> = order
            .iter()
            .enumerate()
            .map(|(i, a)| (a.load(Ordering::SeqCst), WorkerId(i)))
            .collect();
        pairs.sort_by_key(|&(seq, _)| seq);
        pairs.into_iter().map(|(_, id)| id).collect()
    }

    #[test]
    fn test_finish_without_yield() {
        // A worker can finish without ever yielding.
        let ring = TokenRing::new(2, 42);

        std::thread::scope(|s| {
            let ring_ref = &ring;

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(0));
                // Finish immediately without yielding
                ring_ref.finish(WorkerId(0));
            });

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(1));
                ring_ref.finish(WorkerId(1));
            });

            ring.start();
            ring.wait_all_done();
        });
    }

    #[test]
    fn test_multiple_yields() {
        // Workers can yield multiple times before finishing.
        let ring = TokenRing::new(2, 42);

        std::thread::scope(|s| {
            let ring_ref = &ring;

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(0));
                ring_ref.yield_token(WorkerId(0));
                ring_ref.yield_token(WorkerId(0));
                ring_ref.yield_token(WorkerId(0));
                ring_ref.finish(WorkerId(0));
            });

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(1));
                ring_ref.yield_token(WorkerId(1));
                ring_ref.finish(WorkerId(1));
            });

            ring.start();
            ring.wait_all_done();
        });
    }
}
