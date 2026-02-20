---
title: Preemptive interleaving via PMU RBC timer signals
status: closed
priority: 0
issue_type: epic
created_at: 2026-02-20T02:31:03.360434728+00:00
updated_at: 2026-02-20T02:49:41.622313403+00:00
---

# Description

## Summary

Currently, the simulator only interleaves scheduler code at **kfunc boundaries**:
each `maybe_yield()` call at the top of a kfunc is a potential context switch to
another worker. This means any scheduler C code *between* kfunc calls runs
atomically — an unrealistic simplification, since the real kernel can preempt or
interleave between arbitrary instructions.

This epic adds **preemptive interleaving** using PMU Retired Conditional Branch
(RCB) counter overflow signals. The idea: roll a random "timeslice" (e.g. 50–500
RCBs) for each scheduler structop invocation, configure the perf counter to fire
a signal after that many branches, then suspend the worker thread and pass the
token to another worker — exactly as we do today at kfunc boundaries, but now
also happening *mid-C-code*.

This dramatically increases the interleaving surface for concurrency bug
detection, catching races that only manifest when scheduler code is preempted
between branches (not just between kfunc calls).

## Background: Reverie's RBC Timer Design

Our `scx_perf` crate was originally extracted from Reverie
(~/work/reverie/reverie-ptrace/src/perf.rs). Reverie has a more complete PMU
timer facility that we can draw from:

**Two-counter design** (reverie-ptrace/src/timer.rs):
- **Clock counter**: pure counting, no signals, monotonic RBC clock
- **Timer counter**: configured with `sample_period` for overflow notification,
  delivers `SIGSTKFLT` to the target thread via `O_ASYNC + F_SETSIG + F_SETOWN_EX`

**Signal delivery** (reverie-ptrace/src/perf.rs:319-328):
```rust
pub fn set_signal_delivery(&self, thread: Tid, signal: Signal) -> Result<(), Errno> {
    fcntl(self.fd, F_SETOWN_EX, &f_owner_ex { type_: F_OWNER_TID, pid: thread.as_raw() });
    fcntl(self.fd, F_SETFL, O_ASYNC);
    fcntl(self.fd, F_SETSIG, signal as i32);
}
```

**Key Reverie parameters** (reverie-ptrace/src/timer.rs:99-133):
- Intel skid margin: 100–125 RCBs
- AMD Zen skid margin: 10,000 RCBs (much higher)
- Minimum viable period: ~5 RCBs (below this, use artificial signaling)

We don't need Reverie's ptrace-based precise delivery (skid compensation via
single-stepping). For interleaving, approximate delivery is fine — we just need
to interrupt somewhere mid-C-code, not at an exact instruction.

## Locking and Atomics Analysis

### What Schedulers Actually Use

None of the supported schedulers (simple, mitosis, LAVD, cosmos) use
`bpf_spin_lock`. All use `__sync_*` GCC builtins (hardware atomics):

| Primitive | Schedulers | Pattern |
|-----------|-----------|---------|
| `__sync_fetch_and_add/sub` | LAVD, Cosmos, Mitosis, Tickless | Atomic counters |
| `__sync_bool_compare_and_swap` | LAVD, Mitosis | CAS allocation/tracking |
| `__sync_val_compare_and_swap` | LAVD | CAS retry loop (logical clock) |
| `__atomic_add_fetch` (RELEASE) | Mitosis | Config sequence number |
| `READ_ONCE/WRITE_ONCE` | LAVD, Mitosis | Volatile access |
| `bpf_kptr_xchg` | Cosmos, Mitosis, Tickless | Pointer ownership transfer |

### Why Atomics and Locks Work Correctly

The `__sync_*` builtins compile to real x86 locked instructions. Under
TokenRing + preemptive interleaving (still one thread at a time):

- **CAS sees the real value**: If thread A did a successful CAS (set flag to 1),
  thread B's CAS on the same flag correctly fails (value is 1, not expected 0).
- **Atomic increments are indivisible**: `lock xadd` is a single instruction,
  either completed or not started at preemption time.
- **Spinlocks and CAS retry loops work naturally**: A spinning thread burns
  RBCs in its tight loop. Its timeslice expires (PMU overflow signal), it gets
  preempted, the PRNG picks the next worker — eventually the lock holder runs
  again and releases. The spinning thread gets another turn and acquires the
  lock. No deadlock: the RBC timeslice IS the bound on spinning.

This is the key correctness argument: preemptive interleaving via RBC timeslices
handles lock contention the same way a real preemptive OS does. A thread that
spins on a contended lock consumes its quantum (here: RBC timeslice) rapidly,
gets descheduled, and the lock holder eventually runs. The PRNG ensures fair
rotation — with N workers, each gets ~1/N probability per selection, so after
O(N log N) selections every worker has run at least once (coupon collector bound).

### Items Requiring Attention

1. **`bpf_kptr_xchg` in sim_wrapper.h**: Currently a non-atomic pointer swap.
   Must become `__sync_lock_test_and_set` or similar under preemptive
   interleaving to match kernel atomic semantics.

2. **Signal handler context save/restore**: When the PMU signal fires mid-C-code,
   the signal handler must save `current_cpu`, `ops_context`, `waker_task_raw`
   from `SimulatorState` (same fields that `maybe_yield()` saves). This is safe
   because the RBC counter is disabled inside kfuncs (`with_sim()` pauses it),
   so preemptive signals only fire during C code execution when no `&mut
   SimulatorState` borrow exists.

## Design

### Signal-Based Preemption Mechanism

1. **Extend `scx_perf::RbcCounter`** with Reverie-style signal delivery:
   - `set_sample_period(n)` — configure overflow after `n` retired branches
   - `set_signal_delivery(tid, signal)` — route overflow to a specific thread
   - `expose_fd()` — expose the raw fd for signal handler to identify source

2. **Choose SIGSTKFLT as the preemption signal** (same as Reverie). The kernel
   never sends it naturally, making it a safe "private" signal.

3. **Signal handler + futex parking**:
   - Install a process-wide SIGSTKFLT handler before concurrent dispatch.
   - On signal receipt: the handler saves SimulatorState context to thread-local,
     then does `futex(FUTEX_WAIT)` on a per-worker futex word to self-suspend.
     (`futex` is a raw syscall, safe to call from a signal handler.)
   - The coordinator (or next token holder) does `futex(FUTEX_WAKE)` to resume
     a worker when it's that worker's turn. On wake, handler restores
     SimulatorState context and returns, resuming C code transparently.

4. **TokenRing integration**:
   - Extend `TokenRing` to support both cooperative yields (existing
     `yield_token()` at kfunc boundaries) and preemptive yields (signal-driven
     `preempt_yield()` that uses the futex mechanism).
   - The PRNG still picks the next active worker — preemption just adds more
     switch points, it doesn't change the selection policy.

### Timeslice Rolling

- Before each scheduler structop invocation (dispatch, select_cpu, enqueue,
  etc.), roll a random timeslice from a configurable range (e.g. 50–500 RCBs)
  using the scenario's deterministic PRNG.
- Configure the PMU timer counter with this period.
- Enable the timer before entering C code, disable after returning.
- The timeslice range should be configurable in `ScenarioBuilder` (e.g.
  `preemptive_timeslice_range(50..500)`).

### Runqueue Lock Implications

In the real kernel, each CPU has a per-runqueue spinlock (`rq->lock`). Scheduler
callbacks execute with the local rq_lock held. Cross-CPU operations acquire the
remote CPU's rq_lock.

With preemptive interleaving, a worker can be suspended *while the C scheduler
is between branches*. However:

- **TokenRing still serializes**: only one worker runs at a time, so there's
  no actual concurrent memory access.
- **Per-CPU isolation**: each worker operates on its own CPU's local state.
  Cross-CPU access only happens through kfuncs (which already yield).
- **Atomics are real**: `__sync_*` builtins provide correct visibility of
  values written by preempted workers.
- **Lock contention resolves naturally**: spinners burn RBCs, get preempted by
  timeslice expiry, lock holders eventually run and release.

**Conclusion**: the existing TokenRing serialization + hardware atomics is
sufficient. We don't need explicit rq_lock modeling for this feature.

### Graceful Degradation

- If PMU counters are unavailable (VM, container, unsupported CPU), fall back
  to kfunc-only interleaving (current behavior).
- The feature should be opt-in via `ScenarioBuilder::preemptive_interleave(true)`
  and default to false initially.

## Tracking

- [x] **Step 1: Extend scx_perf with signal delivery** — Added `RbcTimer` to
  `scx_perf` with `set_sample_period()`, signal delivery via
  `O_ASYNC + F_SETSIG + F_SETOWN_EX`, and `RawFd` accessor. Uses
  `PERF_TYPE_RAW` with Intel 0x01c4 / AMD 0x00d1 event codes.
  Commit: 524ca9c7

- [x] **Step 2: Futex-based worker parking primitive** — Implemented
  `PreemptRing` in `preempt.rs` with per-worker `AtomicI32` futex words.
  Three states: `RUNNING`, `PARKED`, `WOKEN`. Uses raw `SYS_futex` syscall
  (async-signal-safe). Unit tests for park/unpark cycle.
  Commit: 524ca9c7

- [x] **Step 3: Signal handler infrastructure** — Process-wide `SIGSTKFLT`
  handler (`preempt_handler`) saves `current_cpu`, `ops_context`,
  `waker_task_raw` from `SimulatorState` to thread-local, yields token via
  `PreemptRing`, restores context on resume. Timer disabled during kfunc Rust
  code via `with_sim()` bracketing (`pause_timer`/`resume_timer`).
  Commit: 524ca9c7

- [x] **Step 4: Extend TokenRing for preemptive yields** — `PreemptRing`
  replaces `TokenRing` for preemptive mode. Supports both cooperative yields
  (`maybe_yield_preemptive()` at kfunc boundaries) and signal-driven yields
  (from the SIGSTKFLT handler). Same xorshift32 PRNG for deterministic worker
  selection.
  Commit: 524ca9c7

- [x] **Step 5: Timeslice rolling and PMU timer setup** — Engine rolls random
  timeslice from `[timeslice_min, timeslice_max]` range (default 100–1000
  RCBs) using scenario PRNG. `PreemptiveConfig` struct added to
  `ScenarioBuilder` with `.preemptive(config)` method that implies
  `.interleave(true)`.
  Commit: 524ca9c7

- [x] **Step 6: Integration in engine.rs** — `dispatch_concurrent()` branches
  into `dispatch_concurrent_cooperative()` (existing TokenRing) and
  `dispatch_concurrent_preemptive()` (PreemptRing + RbcTimer). Workers create
  per-thread `RbcTimer`, configure signal delivery via `gettid()`, arm timer
  before dispatch, disable after. Falls back to cooperative-only `PreemptRing`
  (timer_fd=-1) when PMU unavailable.
  Commit: 524ca9c7

- [x] **Step 7: Make bpf_kptr_xchg atomic** — `bpf_kptr_xchg_impl` in
  `sim_bpf_stubs.c` now uses `__sync_lock_test_and_set` (XCHG on x86)
  instead of plain pointer swap. Prevents torn read-write under preemption.
  Commit: fa1959da

- [x] **Step 8: Testing** — 5 preemptive interleaving integration tests added
  to `tests/interleave.rs`: smoke, determinism, sleep_wake, multiple_seeds,
  custom_timeslice. Helper `preemptive_scenario()` for concise test setup.
  All 333 tests pass.
  Commit: 20a2c5fa

- [x] **Step 9: Documentation** — Issue updated with implementation details.
  Module-level documentation in `preempt.rs` and `interleave.rs` describes
  the concurrency model, safety invariants, and timer lifecycle.

## Implementation Notes

### Concurrency Model

Two interleaving modes, both using one-thread-at-a-time token passing:

1. **Cooperative** (`interleave=true`): `TokenRing` (Mutex+Condvar) yields at
   kfunc boundaries via `maybe_yield()`. Good for finding bugs in kfunc-level
   ordering.

2. **Preemptive** (`preemptive=PreemptiveConfig`): `PreemptRing` (futex-based,
   async-signal-safe) yields both at kfunc boundaries AND mid-C-code via PMU
   RBC timer overflow signals. Dramatically increases interleaving surface.

### Timer Lifecycle

```
C scheduler code executing
  → PMU overflow (SIGSTKFLT fires)
    → signal handler: disable timer, save context, yield token (futex park)
    → [another worker runs]
    → futex wake: restore context, re-arm timer, return to C code

Kfunc entry (maybe_yield_preemptive)
  → disable timer, cooperative yield via PreemptRing
  → [may or may not switch workers]
  → with_sim() enters: pause_timer() (redundant safety)
  → kfunc Rust code executes (no signals possible)
  → with_sim() exits: resume_timer() re-arms before returning to C
```

### Atomics Correctness

- `__sync_*` builtins → real x86 locked instructions → correct visibility
- `bpf_kptr_xchg` → `__sync_lock_test_and_set` (XCHG) → atomic pointer swap
- Spinners burn RBCs → timeslice expires → lock holder eventually runs
- No deadlock: RBC timeslice IS the bound on spinning
