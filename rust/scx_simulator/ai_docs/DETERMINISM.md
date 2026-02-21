# Simulator Determinism

This document explains the determinism model of the scx_simulator and how it
enables reliable reproduction of failing test cases.

## Core Principle

**Same seed produces the same trace.**

Given the same:
- Scenario configuration (CPUs, tasks, duration)
- PRNG seed
- Scheduler implementation

The simulator produces an identical event trace. This is fundamental to the
testing methodology: `stress.py` explores many different executions by varying
the seed, and when a failing case is found, the seed can be used to reliably
reproduce it for debugging.

## Why RBC (Retired Branch Conditionals) is Deterministic

The simulator's preemptive interleaving mode uses PMU Retired Branch
Conditional (RBC) counters to inject preemption points mid-C-code. A common
misconception is that RBC is non-deterministic due to speculative execution.

**This is incorrect.** RBC counters count only *retired* (completed) branches,
not speculative ones. When the CPU speculatively executes a branch that is
later squashed, that branch is *not* counted. Only branches that commit to
architectural state are counted.

### Proof by Existing Deterministic Tools

Several production-quality tools rely on RBC being fully deterministic for
record/replay:

1. **rr** (https://rr-project.org/) - A reverse debugger that records
   execution and replays it deterministically. Uses RBC as the primary
   progress metric to know when to inject recorded events during replay.

2. **Hermit** (https://github.com/facebookexperimental/hermit) - A
   deterministic container runtime that uses RBC for progress tracking and
   deterministic scheduling.

These tools would be fundamentally broken if RBC included speculative
branches. Their correctness proves that RBC is deterministic.

### Technical Details

The Intel SDM (Software Developer's Manual) specifies that the "Retired
Conditional Branches" event (0x00C4 with umask 0x01) counts branches that
have retired (committed). AMD's equivalent event (0x00D1) has the same
semantics.

## Interleaving Modes

### Cooperative Interleaving

With `interleave=true` (and no `preemptive` config), workers yield only at
kfunc boundaries via `maybe_yield()`. This is fully deterministic because:

1. Yield points are at fixed code locations (kfunc entry)
2. Worker selection uses a seeded PRNG (`TokenRing`)
3. All PRNG calls are serialized by token ownership

### Preemptive Interleaving (cooperative_only)

With `preemptive(PreemptiveConfig::cooperative_only())`, the `PreemptRing`
infrastructure is used (futex-based, async-signal-safe) but PMU timers are
disabled. Yields still only happen at kfunc boundaries. This is deterministic
for the same reasons as cooperative interleaving.

This mode exists as a baseline for testing the `PreemptRing` infrastructure
without introducing PMU-related variables.

### Preemptive Interleaving (PMU-enabled)

With `preemptive(PreemptiveConfig::default())`, workers are additionally
preempted mid-C-code when their PMU RBC timer fires. The timeslice (number
of RBCs until preemption) is rolled from the seeded PRNG.

**Theoretical determinism**: Given the same seed, the same timeslices are
rolled, so if the C code executes the same instruction sequence, preemption
occurs at the same code point. Combined with deterministic worker selection
via `PreemptRing::pick_next()`, the entire execution should be deterministic.

**Practical considerations**: PMU delivery has inherent "skid" - the signal
may not be delivered at the exact branch count due to pipelining, interrupt
latency, and CPU microarchitecture. This skid is typically bounded (100-125
RBCs on Intel, larger on AMD Zen). While this doesn't affect *counting*
(the count is exact), it can affect *when the signal handler runs*.

For stress testing purposes, even with skid, the simulator explores different
interleavings deterministically within the skid window. The important property
is that a failing seed can be re-run to get a *similar* (often identical)
failure for debugging.

## Determinism Guarantees by Mode

| Mode | PRNG Deterministic | Yield Points Deterministic | Practical Reproducibility |
|------|-------------------|---------------------------|---------------------------|
| Sequential | Yes | N/A (no interleaving) | Exact |
| Cooperative | Yes | Yes (kfunc boundaries) | Exact |
| Preemptive (cooperative_only) | Yes | Yes (kfunc boundaries) | Exact |
| Preemptive (PMU) | Yes | Yes (PRNG-driven RBC count) | High (modulo skid) |

## Test Organization

- `test_preemptive_determinism`: Tests `cooperative_only` mode determinism
  (exact match guaranteed)
- `test_preemptive_pmu_determinism`: Tests true PMU mode determinism. In
  practice, this test passes reliably because the same PRNG-driven timeslices
  combined with identical code execution produce identical RBC counts.

## Usage in Stress Testing

```bash
# Explore many interleavings with the stress test harness
./bug_finding/stress.py --schedulers simple --duration 10

# When a failure is found, the seed is printed:
#   FAIL [simple] seed=12345 exit=ErrorStall{...}
#
# Reproduce the failure with the same seed:
STRESS_SEED=12345 cargo test --test stress stress_random_simple -- --ignored

# For debugging, use cooperative_only mode for exact reproducibility:
# (modify scenario to use PreemptiveConfig::cooperative_only())
```

See `bug_finding/README.md` for detailed documentation on the stress testing
methodology.

## References

- [rr record/replay debugger](https://rr-project.org/)
- [Hermit deterministic container](https://github.com/facebookexperimental/hermit)
- [Intel SDM: Performance Monitoring Events](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- Epic issue: sim-79cb5 (Preemptive interleaving via PMU RBC timer signals)
