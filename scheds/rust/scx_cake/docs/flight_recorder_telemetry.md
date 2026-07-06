# scx_cake Flight Recorder Telemetry

## Goal

Debug telemetry should explain scheduler flow without becoming the workload.
After a one-minute, five-minute, or hour-long run, a dump should answer:

- What changed around a reported lag time?
- Which scheduler paths were hot?
- Which callbacks or decisions were slow?
- Were tasks waiting on CPU placement, queueing, wake handoff, or another task?
- Was load balanced across CPUs, cores, LLCs, and SMT siblings?
- Were CPU load or temperature correlated with the stall?
- Did telemetry itself perturb the capture?

The target is: full debug analytics, zero BPF stack spills, and low enough
capture overhead that gaming benchmark results stay believable.

## Design Rule

BPF records facts. Rust reconstructs meaning.

The BPF side should stay close to scheduler mechanics:

- count exact path frequencies in per-CPU state
- emit compact transition facts when a task crosses scheduler states
- record decision reason codes, target CPUs, and coarse outcome buckets
- avoid large per-task hot-path telemetry objects
- avoid stack-local event structs and helper chains that create `r10` refs

The Rust side should own expensive interpretation:

- task timelines
- enqueue-to-run wait
- run-to-stop runtime
- wake graph and hot wake partners
- per-app summaries
- percentile windows
- anomaly ranking
- "what happened at t+43:12?" reports

## Current First Slice

The TUI already had one-second scheduler deltas, but dumps only printed the
latest 60 seconds. The first flight-recorder slice keeps retained one-second
samples and adds userspace hardware context to each sample:

- average CPU load
- max CPU load and hottest CPU
- average CPU temperature
- max CPU temperature and hottest CPU

Dumps now include:

- `timeline.last60`: exact recent one-second rows
- `flight.second`: compact exact rows for every retained second
- `flight.minute`: full retained minute summaries
- `flight.spikes`: highest-scoring retained anomaly seconds

This is intentionally Rust-only. It does not touch BPF stack pressure.

## Questions The Recorder Should Answer

### Did a task wait too long after wakeup?

Needed facts:

- enqueue timestamp
- selected target CPU
- wake reason
- actual run CPU
- run timestamp
- wait bucket and exact tail event when slow

Rust can match enqueue -> run by PID/TID and attribute the wait to direct,
busy-target, queued, migration, or fallback behavior.

### Did CPU selection make a bad placement decision?

Needed facts:

- previous CPU
- chosen CPU
- select path
- select reason
- allowed mask rejection/fallback reason
- target idle/busy state
- target LLC/core/SMT relationship

The hot path should record compact reason codes. Rust can aggregate by CPU,
core, LLC, TGID, task role, and time window.

### Was load balancing good?

Needed facts:

- per-CPU runtime share
- run count
- local/steal dispatches
- top CPU/core skew
- SMT contended runtime
- queue depth and local pending estimates
- userspace CPU load samples

Minute rows catch long-run imbalance; spike rows catch short bursts.

### Did temperature or CPU load line up with the lag?

Needed facts:

- per-sample CPU load summary
- per-sample temperature summary
- hottest CPU identity
- scheduler wait/callback/queue counters in the same sample

This is a userspace responsibility. Sampling it in BPF would be the wrong
layer and would not be portable.

### Did telemetry perturb the result?

Needed facts:

- exact BPF `r10` count for the final object
- callback timing overhead
- ring/event drop counts
- dump/TUI userspace cost
- whether exact timing is always-on, sampled, or derived

The zero-spill check remains literal:

```text
llvm-objdump -d --no-show-raw-insn <cake.bpf.o> | rg 'r10'
```

The desired debug result is zero matches while preserving the full `--verbose`
capture contract.

## BPF Migration Plan

Debug builds currently expose the full capture surface by default. The
arena-heavy pieces of that recorder should be treated as migration targets, not
as the final architecture: they keep the data visible now, but have too much
per-task hot-path state and have previously created hundreds of `r10` refs in
full telemetry builds.

The migration path should be:

1. Keep exact per-CPU path counters for hot branch frequency.
2. Add zero-stack compact transition events for enqueue, run, stop, and select.
3. Move per-task wait/runtime aggregation into Rust.
4. Keep exact callback timing for major callbacks, but treat nested helper
   timing as sampled or lab-only if it changes the workload.
5. Retire arena-heavy hot telemetry from the implementation once Rust
   reconstruction covers the same questions, without removing the default
   `--verbose` capture surface.

## Dump Contract

A useful long-run dump should contain:

- capture freshness and schema/version markers
- retained history span and sample coverage
- recent one-second rows
- retained minute rows
- top anomaly seconds
- lifetime and 30s/60s windows
- per-CPU/core balance diagnosis
- per-app health
- wake graph and wake tails
- callback histograms
- path-frequency counters
- debug overhead and event/drop accounting

That gives us a stable loop: reproduce a lag, dump once, then ask which fact
changed at that time instead of guessing from FPS alone.
