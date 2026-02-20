---
title: Preemptive interleaving via PMU RBC timer signals
status: open
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

- [ ] **Step 1: Extend scx_perf with signal delivery** — Add `set_sample_period()`,
  `set_signal_delivery()`, `RawFd` accessor to `RbcCounter`. Port the relevant
  bits from Reverie's `perf.rs`. Add unit test that verifies signal delivery on
  counter overflow.

- [ ] **Step 2: Futex-based worker parking primitive** — Implement a
  `WorkerParking` struct (or similar) that provides `park()` (futex wait, safe
  to call from signal handler) and `unpark()` (futex wake). Unit test the
  park/unpark cycle.

- [ ] **Step 3: Signal handler infrastructure** — Install process-wide SIGSTKFLT
  handler. On receipt: identify which worker was preempted (via thread-local),
  save SimulatorState context, park via futex. On resume: restore context.
  Test: verify a thread running a busy loop gets parked on PMU overflow and
  can be unparked.

- [ ] **Step 4: Extend TokenRing for preemptive yields** — Add
  `preemptive_yield()` path that integrates with the futex parking. When a
  worker is preempted, it yields the token; when the token returns to it, it
  is unparked. The PRNG selection logic is reused.

- [ ] **Step 5: Timeslice rolling and PMU timer setup** — In the engine, before
  entering scheduler C code for concurrent dispatch: roll a random timeslice
  from the PRNG, configure the PMU timer, enable it. After C code returns (or
  on preemption): disable/reset the timer. Add `ScenarioBuilder` API for
  configuring the timeslice range and enabling preemptive interleaving.

- [ ] **Step 6: Integration in engine.rs** — Wire preemptive interleaving into
  `dispatch_concurrent()` and potentially other concurrent callback sites.
  Ensure existing kfunc yield points work alongside preemptive yields.

- [ ] **Step 7: Make bpf_kptr_xchg atomic** — Update sim_wrapper.h to use
  `__sync_lock_test_and_set` for bpf_kptr_xchg_impl instead of plain pointer
  swap.

- [ ] **Step 8: Testing** — Integration tests that verify:
  (a) preemptive interleaving produces different orderings than kfunc-only,
  (b) determinism: same seed produces same interleaving,
  (c) graceful degradation when PMU unavailable,
  (d) stress tests with preemptive interleaving enabled,
  (e) no regressions on existing interleave tests.

- [ ] **Step 9: Documentation** — Document the concurrency model (TokenRing +
  futex parking + PMU signals), the atomics correctness argument, and the
  lock contention resolution mechanism.
