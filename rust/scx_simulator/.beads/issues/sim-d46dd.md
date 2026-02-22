---
title: Hardware breakpoint replay for deterministic preemption
status: open
priority: 1
issue_type: feature
created_at: 2026-02-22T01:45:21.927615654+00:00
updated_at: 2026-02-22T01:45:21.927615654+00:00
---

# Description

## Problem

The simulator's preemptive interleaving uses PMU RBC (Retired Branch Conditional)
overflow to trigger preemption, but PMU counters have hardware "skid" — the signal
is delivered several branches after the requested count. This means two runs with
the same seed don't preempt at bitwise-identical points. Bugs found by the stress
test cannot be proven reproducible.

The current state:
- Recording works: `PreemptionRecord` captures `(rbc_count, instruction_pointer,
  cpu_id, sequence)` at each preemption point (preempt.rs:57-82).
- Replay is seed-based only: same PRNG seed produces the same timeslice sequence,
  but PMU skid means actual preemption points vary by ~1-100 branches per event.
- `measure_skid` (scx_perf/examples) empirically confirms skid is non-zero.

## Approach: Hybrid PMU + Hardware Breakpoint Replay

Use PMU to get **close** to the target preemption point, then a hardware debug
breakpoint to stop at the **exact** instruction. This avoids both the PMU skid
problem and the instruction-patching complexity of software breakpoints (INT3).

### Phase 1: Recording (mostly already implemented)

During the initial "exploration" run:
1. PMU timer fires at PRNG-rolled intervals (existing behavior).
2. At each preemption, record `(rbc_count, instruction_pointer, cpu_id)`.
   This is already captured by `PreemptionRecordStore`.
3. **New**: persist the full preemption trace to a file (or in-memory structure)
   so the replay run can consume it.

### Phase 2: Replay with hardware breakpoints

Given a recorded trace of preemption points for each worker thread:

```
For each preemption point (target_ip, target_rbc) in the trace:

  1. ARM PMU:  Set RBC timer to fire at (target_rbc - margin),
               where margin > max_skid (e.g. 200 branches).
               This gets us CLOSE without overshooting.

  2. PMU FIRES (SIGSTKFLT handler):
     - We're within ~200 branches of the target.
     - Disable PMU timer (existing: ioctl PERF_IOC_DISABLE).
     - Set a HARDWARE BREAKPOINT at target_ip using debug
       registers (DR0-DR3 via ptrace or perf_event).
     - Return from signal handler. Execution resumes with
       the breakpoint armed.

  3. BREAKPOINT FIRES (SIGTRAP handler):
     - Read RBC counter via rdpmc (branchless, exact count
       before any handler branches execute).
     - Compare guest_rbc (= rdpmc_value - accumulated_overhead)
       with target_rbc.
     - If match: this is the right dynamic instance.
       Yield the token (existing: ring.yield_token()).
     - If no match (too early — rare, since PMU got us close):
       Track overhead (exit_rdpmc - entry_rdpmc + EPILOGUE_COST),
       clear breakpoint, return, re-arm.
     - Clear the hardware breakpoint in either case.

  4. PREEMPTED: Worker is parked, another worker is selected.
     Next preemption point is set up for whichever worker runs next.
```

### Why hardware breakpoints (DR0-DR3), not software breakpoints (INT3)

- **No instruction patching**: DR registers trigger #DB exception without
  modifying the instruction stream. No save/restore/single-step dance.
- **No code-cache coherency issues**: Patching live code in a multi-threaded
  process requires careful cache flushes. DR registers avoid this entirely.
- **Clean signal**: Delivers SIGTRAP, easily distinguished from other signals.
- **Sufficient capacity**: We only need 1 breakpoint at a time per thread.
  DR0-DR3 give us 4 slots (only 1 needed).

### Branch accounting in signal handlers

The key challenge is that signal handler code executes user-space branches that
pollute the RBC counter. The solution:

1. **rdpmc at handler entry**: The `rdpmc` instruction is branchless. Signal
   delivery happens in kernel space (not counted with `exclude_kernel=1`).
   Function prologues are branchless (push/mov/sub). So `rdpmc` as the first
   meaningful operation reads the TRUE guest branch count.

2. **Overhead tracking**: Maintain a `total_overhead: u64` accumulator.
   At handler entry: `entry_rbc = rdpmc(idx)`.
   At handler exit: `exit_rbc = rdpmc(idx)`.
   `total_overhead += (exit_rbc - entry_rbc) + EPILOGUE_COST`.
   `EPILOGUE_COST = 1` (the `ret` instruction; sigreturn restorer is
   branchless: `mov eax, NR_rt_sigreturn; syscall`).

3. **Guest RBC**: `guest_rbc = entry_rbc - total_overhead` at each handler
   invocation gives the branch count attributable to the guest program.

Because the hybrid approach gets us within ~200 branches, the breakpoint
typically fires 0-2 times before hitting the right instance, so overhead
accumulation is negligible.

## Implementation Plan

### Step 1: rdpmc support in scx_perf

Add `rdpmc` fast-read capability to `scx_perf`:

- Enable userspace `rdpmc` by mmap'ing the perf event fd (the perf mmap page
  contains the counter index for `rdpmc`).
- Add an `rdpmc()` inline function (pure asm, branchless) that reads the
  counter using the mapped index.
- Add a helper to read `rdpmc` safely from signal handlers.

Key files: `crates/scx_perf/src/lib.rs`

### Step 2: Hardware breakpoint abstraction in scx_perf

Add a `HwBreakpoint` type to `scx_perf`:

- Create hardware execution breakpoints via `perf_event_open` with:
  - `type = PERF_TYPE_BREAKPOINT`
  - `bp_type = HW_BREAKPOINT_X` (execution breakpoint)
  - `bp_addr = target_ip`
  - `bp_len = sizeof(long)`
  - `disabled = 1` (arm explicitly)
  - Signal delivery routed to the owning thread.
- Methods: `new(addr)`, `enable()`, `disable()`, `set_addr(new_addr)`, `close()`.
- This uses the kernel's debug register management — no raw DR writes needed.
  The kernel handles DR allocation, task switching, and per-thread isolation.
- Use a separate signal (e.g. SIGTRAP or another RT signal) from the PMU
  timer signal (SIGSTKFLT), so the two handlers are distinct.

Alternative: `ptrace(PTRACE_POKEUSER)` to write DR0-DR7 directly from within
the same process (via a helper thread). The `perf_event_open` approach is
cleaner because the kernel manages the DR registers across context switches.

Key files: `crates/scx_perf/src/lib.rs`

### Step 3: PreemptionTrace serialization

Add serialization for the preemption trace so replay can consume it:

- `PreemptionTrace`: a sequence of `PreemptionRecord` values per worker thread,
  ordered by sequence number.
- Serialize to/from a compact binary format (or just hold in memory for
  same-process record+replay in the determinism check).
- The stress test's `--determinism` mode runs the same seed twice already;
  the first run produces the trace, the second replays it.

Key files: `crates/scx_simulator/src/preempt.rs`

### Step 4: Replay engine

Add a `ReplayScheduler` mode to the preemptive dispatch path:

- New `PreemptiveMode` variant: `Replay(PreemptionTrace)`.
- Each worker thread, instead of arming the PMU with a random timeslice,
  arms it to fire at `(next_target_rbc - MARGIN)`.
- PMU handler (SIGSTKFLT): disable PMU, arm hardware breakpoint at
  `next_target_ip`, return.
- Breakpoint handler (SIGTRAP): read rdpmc, check if guest_rbc matches
  target, yield if so, otherwise track overhead and continue.
- After yielding, advance to the next preemption point in the trace.

Key files:
- `crates/scx_simulator/src/preempt.rs` (new replay state machine)
- `crates/scx_simulator/src/engine.rs` (`dispatch_concurrent_preemptive`)

### Step 5: Determinism verification integration

Wire the replay into the stress test determinism check:

- `--determinism` mode: Run 1 records the trace. Run 2 replays it.
- Compare full execution traces (existing `DeterminismCheckpoint` infra).
- Memory hash comparison should now show bitwise identity.

Key files:
- `crates/scx_simulator/src/engine.rs`
- `bug_finding/stress.py`
- `crates/scx_simulator/tests/interleave.rs` (new replay determinism test)

### Step 6: Measure and validate

- Extend `measure_skid` example to also measure hardware breakpoint latency
  and rdpmc overhead.
- Integration test: record a preemptive trace, replay it, verify identical
  `DeterminismCheckpoint` sequences.
- Stress test: run with `--determinism` and confirm zero divergences.

## Risks and Mitigations

**Risk: rdpmc not available in all environments**
Some kernels disable userspace rdpmc (`/proc/sys/kernel/perf_event_paranoid`).
Mitigation: fall back to reading the perf fd (slower but functional). Only
the replay path needs rdpmc precision; recording can tolerate the overhead.

**Risk: perf_event hardware breakpoints not supported**
Some hypervisors (KVM, cloud VMs) don't expose debug registers.
Mitigation: detect at runtime and fall back to software breakpoints (INT3)
with the instruction-patching approach as a backup. Or fall back to the
DBI/frida approach.

**Risk: Breakpoint fires too many times (hot inner loop)**
If target_ip is in a tight loop, the breakpoint could fire many times in the
~200-branch window. Mitigation: the window is small (200 branches), so even
a 1-branch loop body means at most ~200 hits. At ~1μs per signal handler
invocation, that's ~200μs — acceptable.

**Risk: Signal handler overhead is not perfectly constant**
The `(exit_rdpmc - entry_rdpmc) + 1` calculation assumes the handler takes
a constant number of branches. In practice, conditional branches in the
handler (the match check, error paths) make this slightly variable. But since
we measure the ACTUAL overhead each time and accumulate it, this is handled
automatically. The only imprecision is the +1 EPILOGUE_COST, which is
architecturally fixed.
