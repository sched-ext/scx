//! Preemptive interleaving via PMU RBC timer signals.
//!
//! Extends the cooperative kfunc-boundary interleaving (see [`interleave`]) with
//! mid-C-code preemption points. A PMU counter fires `SIGSTKFLT` after a random
//! number of retired conditional branches; the signal handler parks the worker
//! via futex and the [`PreemptRing`] passes execution to another worker.
//!
//! ## Signal safety
//!
//! The entire preemption path — signal handler, token passing, park/unpark —
//! uses only async-signal-safe primitives: atomics and raw `futex()` syscalls.
//! No `Mutex`, `Condvar`, or heap allocation in the hot path.
//!
//! ## Relationship to [`interleave`]
//!
//! - [`interleave::TokenRing`] uses `Mutex`/`Condvar` for cooperative yields at
//!   kfunc boundaries.
//! - [`PreemptRing`] uses atomics/futex for both cooperative and preemptive
//!   yields, making it safe to call from signal handlers.
//!
//! When preemptive interleaving is enabled, `PreemptRing` replaces `TokenRing`.
//! The existing [`interleave::maybe_yield`] cooperative yield points continue
//! to work — they call into `PreemptRing` instead of `TokenRing`.
//!
//! [`interleave`]: crate::interleave

use std::cell::Cell;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};

use crate::interleave::WorkerId;
use crate::kfuncs::SimulatorState;

// ---------------------------------------------------------------------------
// Futex wrappers (async-signal-safe — raw syscalls only)
// ---------------------------------------------------------------------------

/// Atomically check `*futex == expected` and sleep until woken.
///
/// Returns immediately (spurious wakeup) if the value has changed.
fn futex_wait(futex: &AtomicU32, expected: u32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            futex as *const AtomicU32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        );
    }
    // Return value intentionally ignored — spurious wakeups handled by caller.
}

/// Wake up to `count` threads blocked on `futex`.
fn futex_wake(futex: &AtomicU32, count: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            futex as *const AtomicU32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        );
    }
}

// ---------------------------------------------------------------------------
// PreemptRing — futex-based token ring (signal-safe)
// ---------------------------------------------------------------------------

/// Per-worker state values.
const PARKED: u32 = 0;
const RUNNING: u32 = 1;

/// Signal-safe token ring using atomics and futex.
///
/// All methods are safe to call from signal handlers. The PRNG is accessed
/// only by the active worker (enforced by the single-active invariant), so
/// no CAS is needed on the PRNG state.
pub struct PreemptRing {
    /// Per-worker state: `PARKED` or `RUNNING`.
    workers: Box<[AtomicU32]>,
    /// PRNG state (xorshift32). Only the active worker mutates this.
    prng: AtomicU32,
    /// Total number of workers.
    total: usize,
    /// Bitmask of finished workers (up to 64).
    finished_mask: AtomicU64,
    /// Orchestrator wake word: 0 = not all done, 1 = all done.
    all_done: AtomicU32,
}

impl PreemptRing {
    /// Create a new preemptive ring for `total` workers.
    ///
    /// # Panics
    /// Panics if `total` is 0 or exceeds 64.
    pub fn new(total: usize, seed: u32) -> Self {
        assert!(
            total > 0 && total <= 64,
            "PreemptRing supports 1–64 workers, got {total}"
        );
        let seed = if seed == 0 { 1 } else { seed };
        let workers: Box<[AtomicU32]> = (0..total).map(|_| AtomicU32::new(PARKED)).collect();
        PreemptRing {
            workers,
            prng: AtomicU32::new(seed),
            total,
            finished_mask: AtomicU64::new(0),
            all_done: AtomicU32::new(0),
        }
    }

    fn next_prng(&self) -> u32 {
        let mut x = self.prng.load(SeqCst);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.prng.store(x, SeqCst);
        x
    }

    fn pick_next(&self) -> Option<WorkerId> {
        let mask = self.finished_mask.load(SeqCst);
        let n_finished = mask.count_ones() as usize;
        let n_remaining = self.total - n_finished;
        if n_remaining == 0 {
            return None;
        }
        let idx = (self.next_prng() as usize) % n_remaining;
        let mut count = 0;
        for i in 0..self.total {
            if mask & (1u64 << i) == 0 {
                if count == idx {
                    return Some(WorkerId(i));
                }
                count += 1;
            }
        }
        unreachable!()
    }

    /// Roll a random timeslice in `[min, max]` using the ring's PRNG.
    pub fn roll_timeslice(&self, min: u64, max: u64) -> u64 {
        debug_assert!(max >= min);
        let range = max - min;
        if range == 0 {
            return min;
        }
        min + (self.next_prng() as u64) % (range + 1)
    }

    /// Orchestrator: select the first worker via PRNG and wake it.
    pub fn start(&self) {
        if let Some(first) = self.pick_next() {
            self.workers[first.0].store(RUNNING, SeqCst);
            futex_wake(&self.workers[first.0], 1);
        }
    }

    /// Worker: block until this worker is selected.
    pub fn wait_for_token(&self, my_id: WorkerId) {
        loop {
            if self.workers[my_id.0].load(SeqCst) == RUNNING {
                break;
            }
            futex_wait(&self.workers[my_id.0], PARKED);
        }
    }

    /// Worker: release token, select next worker via PRNG, block until
    /// re-selected.
    ///
    /// **Async-signal-safe**: safe to call from signal handlers.
    ///
    /// Ordering: parks self BEFORE waking next, preventing the race where
    /// the next worker yields back before we enter futex_wait.
    pub fn yield_token(&self, my_id: WorkerId) {
        // Park ourselves first to prevent wake-before-wait races.
        self.workers[my_id.0].store(PARKED, SeqCst);

        if let Some(next) = self.pick_next() {
            self.workers[next.0].store(RUNNING, SeqCst);
            futex_wake(&self.workers[next.0], 1);
        }

        // Wait until re-selected.
        loop {
            if self.workers[my_id.0].load(SeqCst) != PARKED {
                break;
            }
            futex_wait(&self.workers[my_id.0], PARKED);
        }
    }

    /// Worker: mark as finished and wake the next worker (or signal
    /// all-done to the orchestrator).
    pub fn finish(&self, my_id: WorkerId) {
        self.finished_mask.fetch_or(1u64 << my_id.0, SeqCst);
        if self.finished_mask.load(SeqCst).count_ones() as usize == self.total {
            self.all_done.store(1, SeqCst);
            futex_wake(&self.all_done, 1);
        } else if let Some(next) = self.pick_next() {
            self.workers[next.0].store(RUNNING, SeqCst);
            futex_wake(&self.workers[next.0], 1);
        }
    }

    /// Orchestrator: block until all workers have finished.
    pub fn wait_all_done(&self) {
        loop {
            if self.all_done.load(SeqCst) != 0 {
                break;
            }
            futex_wait(&self.all_done, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-local preemptive interleave context
// ---------------------------------------------------------------------------

/// Thread-local context for a worker participating in preemptive interleaving.
#[derive(Clone, Copy)]
struct PreemptCtx {
    ring: *const PreemptRing,
    worker_id: WorkerId,
    /// Raw fd of the RBC timer (for disable/enable in signal handler).
    timer_fd: RawFd,
    /// Timeslice range for re-arming the timer after preemption.
    timeslice_min: u64,
    timeslice_max: u64,
}

// Raw pointer is Send — access serialized by token passing.
unsafe impl Send for PreemptCtx {}

thread_local! {
    static PREEMPT_CTX: Cell<Option<PreemptCtx>> = const { Cell::new(None) };
}

/// Install preemptive interleave context on the current worker thread.
pub fn install(
    ring: &PreemptRing,
    worker_id: WorkerId,
    timer_fd: RawFd,
    timeslice_min: u64,
    timeslice_max: u64,
) {
    PREEMPT_CTX.with(|c| {
        c.set(Some(PreemptCtx {
            ring: ring as *const PreemptRing,
            worker_id,
            timer_fd,
            timeslice_min,
            timeslice_max,
        }));
    });
}

/// Remove preemptive interleave context from the current thread.
pub fn uninstall() {
    PREEMPT_CTX.with(|c| c.set(None));
}

// ---------------------------------------------------------------------------
// Cooperative yield via PreemptRing (replaces interleave::maybe_yield)
// ---------------------------------------------------------------------------

/// Cooperative yield point for kfunc entry (using the PreemptRing).
///
/// Functionally identical to [`interleave::maybe_yield`] but uses the
/// futex-based `PreemptRing` instead of `Mutex`/`Condvar` `TokenRing`.
///
/// The PMU timer is disabled on entry and stays disabled on return.
/// The caller (via `with_sim()` → `resume_timer()`) is responsible for
/// re-arming the timer before returning to scheduler C code.
///
/// # Safety contract
///
/// Must be called BEFORE `with_sim()`, so no `&mut SimulatorState`
/// reference exists when the worker yields.
pub fn maybe_yield_preemptive() {
    let ctx = PREEMPT_CTX.with(|c| c.get());
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return,
    };

    let ring = unsafe { &*ctx.ring };

    // Disable the PMU timer during the cooperative yield to prevent
    // a preemptive signal from firing while we're in Rust/yield code.
    disable_timer(ctx.timer_fd);

    // Save per-callback context from SimulatorState.
    let sim_ptr: *mut SimulatorState = crate::kfuncs::sim_state_ptr()
        .expect("maybe_yield_preemptive called outside simulator context");

    let (saved_cpu, saved_ops_ctx, saved_waker) = unsafe {
        (
            (*sim_ptr).current_cpu,
            (*sim_ptr).ops_context,
            (*sim_ptr).waker_task_raw,
        )
    };

    // Release token and block until re-selected (futex-based).
    ring.yield_token(ctx.worker_id);

    // Resumed — restore our context to SimulatorState.
    unsafe {
        (*sim_ptr).current_cpu = saved_cpu;
        (*sim_ptr).ops_context = saved_ops_ctx;
        (*sim_ptr).waker_task_raw = saved_waker;
    }

    // Timer stays disabled — with_sim() will re-arm via resume_timer().
}

// ---------------------------------------------------------------------------
// Timer pause/resume for with_sim() bracketing
// ---------------------------------------------------------------------------

/// Pause the preemption timer to prevent signals during kfunc execution.
///
/// Called by `with_sim()` before accessing `SimulatorState`. No-op if
/// preemptive interleaving is not active on this thread.
///
/// **Async-signal-safe**: uses only a thread-local read and an ioctl.
pub fn pause_timer() {
    if let Some(ctx) = PREEMPT_CTX.with(|c| c.get()) {
        disable_timer(ctx.timer_fd);
    }
}

/// Resume the preemption timer after kfunc execution completes.
///
/// Called by `with_sim()` just before returning to scheduler C code.
/// Re-arms the PMU timer with a fresh random timeslice. No-op if
/// preemptive interleaving is not active on this thread.
pub fn resume_timer() {
    if let Some(ctx) = PREEMPT_CTX.with(|c| c.get()) {
        let ring = unsafe { &*ctx.ring };
        rearm_timer(ring, &ctx);
    }
}

// ---------------------------------------------------------------------------
// Signal handler (preemptive yield)
// ---------------------------------------------------------------------------

/// The preemptive signal number. SIGSTKFLT is unused by the kernel.
pub const PREEMPT_SIGNAL: libc::c_int = libc::SIGSTKFLT;

/// Install the process-wide SIGSTKFLT signal handler.
///
/// Must be called before spawning worker threads. The handler is
/// async-signal-safe: it uses only atomics, futex, and raw ioctls.
pub fn install_signal_handler() {
    let sa = libc::sigaction {
        sa_sigaction: preempt_handler as *const () as libc::sighandler_t,
        sa_mask: unsafe { std::mem::zeroed() },
        // SA_SIGINFO so we get siginfo_t; SA_RESTART to not fail slow
        // syscalls (though we don't expect any during C scheduler code).
        sa_flags: libc::SA_SIGINFO | libc::SA_RESTART,
        sa_restorer: None,
    };
    let ret = unsafe { libc::sigaction(PREEMPT_SIGNAL, &sa, std::ptr::null_mut()) };
    assert_eq!(ret, 0, "failed to install SIGSTKFLT handler");
}

/// Remove the SIGSTKFLT signal handler, restoring default behavior.
pub fn uninstall_signal_handler() {
    let sa = libc::sigaction {
        sa_sigaction: libc::SIG_DFL,
        sa_mask: unsafe { std::mem::zeroed() },
        sa_flags: 0,
        sa_restorer: None,
    };
    unsafe {
        libc::sigaction(PREEMPT_SIGNAL, &sa, std::ptr::null_mut());
    }
}

/// Signal handler for preemptive interleaving.
///
/// Called on SIGSTKFLT delivery (PMU counter overflow). All operations
/// here are async-signal-safe.
extern "C" fn preempt_handler(
    _signo: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let pctx = PREEMPT_CTX.with(|c| c.get());
    let pctx = match pctx {
        Some(ctx) => ctx,
        None => return, // Not in a preemptive interleave context.
    };

    let ring = unsafe { &*pctx.ring };

    // 1. Disable PMU timer to prevent recursive signals.
    disable_timer(pctx.timer_fd);

    // 2. Save SimulatorState context to locals (on the signal stack frame).
    let sim_ptr = match crate::kfuncs::sim_state_ptr() {
        Some(p) => p,
        None => return,
    };

    let (saved_cpu, saved_ops_ctx, saved_waker) = unsafe {
        (
            (*sim_ptr).current_cpu,
            (*sim_ptr).ops_context,
            (*sim_ptr).waker_task_raw,
        )
    };

    // 3. Yield token (futex-based, signal-safe). Blocks until re-selected.
    ring.yield_token(pctx.worker_id);

    // 4. Resumed — restore SimulatorState context.
    unsafe {
        (*sim_ptr).current_cpu = saved_cpu;
        (*sim_ptr).ops_context = saved_ops_ctx;
        (*sim_ptr).waker_task_raw = saved_waker;
    }

    // 5. Re-arm PMU timer with a fresh timeslice.
    rearm_timer(ring, &pctx);
}

// ---------------------------------------------------------------------------
// Timer helpers (raw ioctls — async-signal-safe)
// ---------------------------------------------------------------------------

/// Disable the PMU timer. No-op if fd is -1 (no timer).
fn disable_timer(fd: RawFd) {
    if fd < 0 {
        return;
    }
    unsafe {
        libc::ioctl(fd, scx_perf::PERF_IOC_DISABLE, 0 as libc::c_ulong);
    }
}

/// Re-arm the PMU timer with a fresh random timeslice.
fn rearm_timer(ring: &PreemptRing, ctx: &PreemptCtx) {
    let fd = ctx.timer_fd;
    if fd < 0 {
        return;
    }
    let timeslice = ring.roll_timeslice(ctx.timeslice_min, ctx.timeslice_max);
    let mut period = timeslice;
    unsafe {
        // Reset counter to zero.
        libc::ioctl(fd, scx_perf::PERF_IOC_RESET, 0 as libc::c_ulong);
        // Set new period.
        libc::ioctl(fd, scx_perf::PERF_IOC_PERIOD, &mut period as *mut u64);
        // Enable.
        libc::ioctl(fd, scx_perf::PERF_IOC_ENABLE, 0 as libc::c_ulong);
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
        let ring = PreemptRing::new(1, 42);
        ring.start();
        ring.wait_for_token(WorkerId(0));
        ring.finish(WorkerId(0));
        ring.wait_all_done();
    }

    #[test]
    fn test_two_workers_interleave() {
        let ring = PreemptRing::new(2, 42);

        std::thread::scope(|s| {
            let ring_ref = &ring;

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(0));
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

    #[test]
    fn test_prng_determinism() {
        let order1 = run_and_record_order(3, 12345);
        let order2 = run_and_record_order(3, 12345);
        assert_eq!(order1, order2, "same seed must give same order");
    }

    #[test]
    fn test_different_seeds_may_differ() {
        let order1 = run_and_record_order(4, 100);
        let order2 = run_and_record_order(4, 999);
        let _ = (order1, order2); // Just verify no panics.
    }

    #[test]
    fn test_finish_without_yield() {
        let ring = PreemptRing::new(2, 42);

        std::thread::scope(|s| {
            let ring_ref = &ring;

            s.spawn(move || {
                ring_ref.wait_for_token(WorkerId(0));
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
        let ring = PreemptRing::new(2, 42);

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

    #[test]
    fn test_many_workers_stress() {
        // Stress test with many workers and many yields.
        for seed in [1, 42, 12345, 999999] {
            let n = 8;
            let ring = PreemptRing::new(n, seed);

            std::thread::scope(|s| {
                let ring_ref = &ring;
                for i in 0..n {
                    s.spawn(move || {
                        ring_ref.wait_for_token(WorkerId(i));
                        for _ in 0..10 {
                            ring_ref.yield_token(WorkerId(i));
                        }
                        ring_ref.finish(WorkerId(i));
                    });
                }
                ring.start();
                ring.wait_all_done();
            });
        }
    }

    #[test]
    fn test_roll_timeslice() {
        let ring = PreemptRing::new(1, 42);
        // Must be in range.
        for _ in 0..100 {
            let ts = ring.roll_timeslice(50, 500);
            assert!(ts >= 50 && ts <= 500, "timeslice {ts} out of range");
        }
        // Degenerate range.
        assert_eq!(ring.roll_timeslice(100, 100), 100);
    }

    fn run_and_record_order(n: usize, seed: u32) -> Vec<WorkerId> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ring = PreemptRing::new(n, seed);
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
}
