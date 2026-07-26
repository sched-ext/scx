# scx_cake unified master-algorithm learnings — 2026-07-09

Cold-start research and implementation handoff. This records the direct code
review, current synthetic and World of Warcraft evidence, the proposed
game-plus-throughput master algorithm, and the experiment order. It was written
before switching the reasoning mode from GPT-5.6 Sol xhigh to max.

The review was performed directly against the local source and artifacts. No
Sashiko review was run.

## Status vocabulary

- **MEASURED** — supported by a named local artifact or direct source fact.
- **INFERRED** — a mechanism consistent with the evidence but not isolated by
  an experiment.
- **PROPOSED** — an unimplemented, falsifiable design.
- **REJECTED** — contradicted by existing measurements or violates a governing
  invariant.

## Engineering question

Build one universal Cake policy that minimizes scheduler-created game pipeline
bubbles and extreme frame-time outliers while retaining the current synthetic
throughput, handoff, cache, fairness, and saturation wins. The policy must infer
behavior from scheduling state, never from game/process identity, and must
remain work-conserving and verifier-safe.

"No bubbles" has a strict boundary: a CPU scheduler can prevent a runnable
pipeline task from waiting unnecessarily or being moved to a needlessly cold
CPU. It cannot guarantee the absence of engine locks, shader compilation,
GPU/fence stalls, storage faults, network stalls, or asset-streaming delays.

## Hard confirmation contract — updated 2026-07-10

The master algorithm is not promoted for parity, a geomean win, or a collection
of small point-estimate wins. It must beat both same-window native EEVDF and the
preserved Cake champion on every accepted metric with headroom beyond measured
run noise.

For each metric `m`, define the confirmation margin from the repeated control
arms in that exact scenario:

```text
required_margin(m) = max(practical_floor(m),
                         2 * repeat_noise(m))
```

`repeat_noise(m)` is the robust within-label repeat spread recorded by the
benchmark harness, not a historical best-versus-worst range. The initial
practical floor is 2% for average FPS, lows, frame-time percentiles, throughput,
and wall time, and 5% for maximum, variance, jitter, and other extreme-tail
metrics. These are rejection floors, not tuning targets: a larger measured
noise band raises the required margin.

Game confirmation requires all of the following:

1. At least seven counterbalanced captures per scheduler in the same focused
   scene, with at least five of seven paired wins for every metric.
2. The aggregate effect clears `required_margin(m)` in the favorable direction
   for average/max FPS, 1% and 0.1% lows, average/p95/p99/p99.9/max frame time,
   frame-time variance, and average/p95/max jitter.
3. The one-sided 95% confidence bound remains favorable after the practical
   floor; merely crossing zero is insufficient.
4. Each capture contains enough frames for at least 20 observations in the
   0.1% region. Low-FPS scenes therefore need longer captures.
5. Capped and uncapped presentations are separate gates. A capped scene cannot
   prove an average-FPS margin because the ceiling removes headroom; uncapped
   captures are mandatory for the all-metric promotion claim.
6. The sweep repeats across multiple games with different CPU/GPU balance. No
   game-specific policy or identity is permitted.

Synthetic confirmation requires at least three clean release repeats for every
official benchmark, a favorable confidence bound and `required_margin(m)` for
every scored metric, no severe guardrail regression, complete suite coverage,
and exact binary/BPF/source/activation identity. A candidate that wins games
but loses one accepted synthetic row remains experimental.

Discovery campaigns may use fewer repetitions to reject an implementation
quickly. They may not lower this promotion contract.

## Exact working snapshot

- Branch: `codex/scx-cake-nightly-perf-review-20260709`
- Git HEAD: `52f25c6105f417b38c7f0465cf3984b4ba3d5646`
- Candidate/change ID: `queued_wakeup_state_convergence_v1`
- Release binary SHA-256:
  `d1ce74056915117cf69a6ee15c300389e581ae89cba2cbc2080345ad7ef8eaae`
- Embedded BPF object SHA-256:
  `9c3927e7eaae8cb2e9c5b4dcc00fc171d673a1afa21a2530d34c784e741f65aa`
- Captured `git_diff.patch` SHA-256:
  `9d8b067eaf4f626b2c8290ddad07e9cef23c54737d87b0133c71a109c4be18f0`
- Dirty scheduler files before this note:
  `DESIGN.md`, `cake.bpf.c`, `intf.h`, and `main.rs`
- Live handoff state at writing: native scheduler restored;
  `/sys/kernel/sched_ext/state` was `disabled`.

Do not reconstruct the candidate from HEAD alone: it is a dirty-source build.
Use the binary hash and the source snapshots in the benchmark artifacts.

## Current algorithm — direct source facts

The active design is intentionally stateless per task. Its only durable task
ordering state is `p->scx.dsq_vtime`; adaptiveness comes from the current
frontier, queue emptiness, current-task run age, backlog, and one-shot per-CPU
marks.

The scheduling structure is:

1. One vtime DSQ per CPU, one global `WAKE_DSQ`, and one global `OVF_DSQ`.
2. Idle placement uses `scx_bpf_select_cpu_dfl()` and direct local dispatch.
3. Under saturation, explicit `WAKE_SYNC` and sleeper-depth can converge a wakee
   on an empty callback CPU. `current`, PID, and TGID are deliberately not used
   as original-waker identity under `SCX_OPS_ALLOW_QUEUED_WAKEUP`.
4. Wakeups can be globally discoverable; continuations stay local for cache
   warmth.
5. Home wakeup preemption currently requires a fair-vtime lead and a current
   task younger than `SLICE_NS / 32`.
6. Dispatch compares the local and global-wake heads, then overflow, then uses a
   staggered pull/steal ring. It remains work-conserving.

Primary source anchors:

- `scheds/rust/scx_cake/src/bpf/cake.bpf.c`
- `scheds/rust/scx_cake/src/bpf/intf.h`
- `scheds/rust/scx_cake/DESIGN.md`

## Current synthetic checkpoint

These are one-run checkpoint values for the exact release binary above, not
confidence intervals. Noise labels must remain attached to interpretation.

| Workload | Current Cake result | Noise note |
|---|---:|---|
| stress-ng futex | 4,788,305.93 bogo-ops/s | low, 3.14% external CPU average |
| cpu-cache-mem cache | 4,436,544.96 bogo-ops/s | warn, 7.74% external CPU average |
| cpu-cache-mem memcpy | 4,194.21 bogo-ops/s | same run as cache |
| perf sched pipe | 0.089 s | low |
| schbench saturated | p99 91.520 ms, 2,355.43 average RPS | noisy, 11.20% external CPU average |
| schbench standard | p99 6.840 ms, 3,413.92 average RPS | noisy, 14.28% external CPU average |

Artifact roots:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/single/20260710T024824Z_stress-ng-futex_release-cake/
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/single/20260710T024915Z_stress-ng-cpu-cache-mem_release-cake/
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/single/20260710T025002Z_perf-sched-pipe_release-cake/
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/single/20260710T025019Z_schbench-saturated_release-cake/
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/single/20260710T025143Z_schbench_release-cake/
```

Historical-binary replay on the current kernel produced roughly 4.875M futex
ops/s. That proved the earlier roughly 2.09M result was a Cake regression, not a
kernel-imposed ceiling. The queued-wakeup convergence fix recovered the durable
4.7–4.8M class without using invalid waker identity.

## Clean World of Warcraft 1-vs-1

Stable-scene, focused, one run per scheduler. Positive FPS/low deltas favor
Cake; negative frame-time deltas favor Cake.

| Metric | Cake | native EEVDF | Cake delta |
|---|---:|---:|---:|
| average FPS | 212.831 | 214.454 | -0.757% |
| 1% low | 159.367 | 127.810 | +24.691% |
| 0.1% low | 107.051 | 117.848 | -9.162% |
| average frame time | 4.746 ms | 4.731 ms | +0.335% worse |
| p95 frame time | 5.402 ms | 5.732 ms | -5.760% better |
| p99 frame time | 6.275 ms | 7.824 ms | -19.804% better |
| p99.9 frame time | 9.411 ms | 8.486 ms | +10.904% worse |
| maximum frame time | 10.410 ms | 8.519 ms | +22.194% worse |
| frame-time standard deviation | — | — | -21.584% better |
| average jitter delta | — | — | -4.043% better |
| p95 jitter delta | — | — | -29.857% better |
| maximum jitter delta | — | — | +24.414% worse |

Slow-frame distribution:

| Threshold | Cake, 597 samples | EEVDF, 596 samples |
|---|---:|---:|
| over 6 ms | 7 | 27 |
| over 7 ms | 3 | 18 |
| over 8 ms | 3 | 5 |
| over 9 ms | 1 | 0 |
| over 10 ms | 1 | 0 |

**MEASURED interpretation:** Cake greatly reduced the broad moderate-slow-frame
population and won p95/p99, but one 10.41 ms event flipped 0.1%, p99.9, max,
and maximum jitter.

**Important sample-size limit:** with about 600 frames, the 0.1% low and p99.9
are effectively functions of the worst one or two observations. A 60-second
capture near 213 FPS supplies roughly 12,800 frames, making the 0.1% region
about 13 frames rather than less than one. Extreme-tail promotion decisions
therefore require longer, repeated paired captures.

Authoritative artifact:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game-campaigns/queued_wakeup_state_convergence_v1/wow_clean_1v1_224139/WoW/2026-07-09/
```

## WoW thread and cache profile

The focused profile shows one busy main thread, six substantial workers, and
many supporting Wine/VKD3D/audio/I/O threads. The exact aggregate windows differ
between `perf stat`, `perf sched`, and `perf mem`; do not derive a per-task soft
deadline by dividing fields from different windows.

Direct cache measurements:

- Aggregate L1D hit rate: 96.660%.
- L2 demand-read hit rate: 49.638%.
- Of sampled L2 fills, 98.075% came from the local CCX/cache hierarchy and
  1.925% from DRAM or I/O.
- Main and worker threads migrated frequently. This did not destroy L1D on the
  9800X3D's single shared V-Cache domain, but it remains a portability risk on
  multi-CCD and heterogeneous machines.

**MEASURED conclusion:** a simple "bad cache hit rate caused the WoW outlier"
theory is not supported. Placement and migration remain scheduling concerns,
but the isolated worst frame is not explained by pervasive cache failure.

Profile roots:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game_profiles/wow/2026-07-09/profile_e2d9e038cde6ec9d.json
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game_profiles/wow/2026-07-09/profile_e2d9e038cde6ec9d_perf/
```

## What the current evidence says

### Strengths to preserve

- The fair-vtime foundation and full-slice sleeper credit are load-bearing.
- Callback-CPU convergence recovers exceptional futex handoff throughput.
- Local continuation ordering and longer turns preserve execution warmth and
  cache/throughput performance.
- Global wake discoverability prevents handoff chains from being stranded.
- Cake already wins WoW's broad tail: 1% low, p95, p99, standard deviation, and
  average/p95 jitter.
- Work conservation and structural starvation avoidance are better foundations
  than periodic rescue machinery.

### Remaining gap

The fixed young-current gate is a good throughput guard but a coarse latency
model. Once the current task is older than `SLICE_NS / 32`, a wakee can wait
until the current task blocks or exhausts its slice even when that wakee is
about to gate an active pipeline. Conversely, preempting every short sleeper
hurts saturated schbench by interrupting productive workers.

This is the central conflict:

```text
game/pipeline: avoid a missed service window and a frame bubble
throughput knee: finish the hot worker and avoid cache/refill/preemption cost
```

The scheduler needs a continuous estimate of whether waiting is more expensive
than finishing the current work. Current point-in-time state cannot always see
that distinction.

## Governing laws for the next design

1. One mathematical objective, not gaming and benchmark subsystems.
2. No executable name, PID/TGID, cgroup identity, foreground flag, Steam ID, or
   other workload identity in the policy.
3. `SCX_OPS_ALLOW_QUEUED_WAKEUP` remains unless evidence shows its removal is
   affordable. Consequently, `current` is not assumed to be the original waker.
4. The policy must be work-conserving: runnable compatible work cannot be left
   idle merely to protect locality.
5. Fair vtime remains the starvation and proportional-fairness foundation.
6. Learned urgency is bounded by the existing fairness horizon; it cannot mint
   unbounded priority.
7. Backlog/oversubscription must continuously fade speculative deadline credit
   so saturated throughput does not collapse.
8. Locality affects which compatible task/CPU pairing is preferred, not whether
   the system makes forward progress.
9. No benchmark-specific thresholds. Time constants must derive from observed
   task behavior, the base slice, topology, or dimensionless pressure.
10. Every new hot-path lookup, write, branch, or helper must first pass a
    behavior-neutral cost experiment.

## Proposed master algorithm: Learned-Slack Virtual Deadline (LSVD)

**PROPOSED, not implemented.** LSVD keeps Cake's fair vtime as the base order
and adds a small, bounded estimate of a task's next service window. The same
rank should eventually drive placement, home preemption, enqueue order, and
dispatch preference.

### Minimal learned state

Start with no more than one compact task-storage record:

```c
struct cake_task_state {
        u64 last_wake_ns;
        u64 run_est_ns;
        u64 period_est_ns;
        u32 samples;
        u32 flags;
};
```

Conceptual signals:

- `C_hat`: estimated CPU service burst from `stopping()` runtime.
- `P_hat`: estimated wake/activation interval from `runnable()`.
- `A`: current task's attained service from Cake's existing per-CPU run stamp.
- `Q`: dimensionless local/global backlog pressure from queue state already read
  on the hot paths.
- `M(p,c)`: bounded migration/topology cost for running task `p` on CPU `c`.

Do not add waker PID or waker/wakee propagation in the first design. LAVD's
waker relationship is only reliable when queued wakeups are not enabled; Cake's
current futex result depends on the queued-wakeup design.

### Learned soft-start deadline

For a wake episode, infer the time available before the task's learned service
cycle would slip:

```text
slack(p) = clamp(P_hat(p) - C_hat(p), 0, SLICE_NS)
soft_start_deadline(p) = wake_time(p) + slack(p)
```

The slice cap is not a game-derived magic number. It is Cake's existing
fairness/response horizon and prevents a sparse task's long activation period
from being interpreted as permission to wait indefinitely.

For candidate CPU `c`:

```text
projected_start(p,c) = now + cpu_unavailable_est(c) + M(p,c)
deadline_miss(p,c) = max(projected_start(p,c) - soft_start_deadline(p), 0)
deadline_credit(p,c) = bounded_fade(deadline_miss, backlog_pressure)

master_rank(p,c) = fair_vtime(p)
                 - deadline_credit(p,c)
                 + locality_cost(p,c)
```

Lower rank wins. `deadline_credit` is capped at one fairness horizon and fades
monotonically as oversubscription rises. The implementation should use fixed
point, shifts, `ilog2`, and saturation; the equation is the policy, not any one
encoding.

### Preemption form

The first control experiment need not reorder DSQs. It can replace the binary
young-current decision with a comparison:

```text
predicted_remaining(curr) = max(C_hat(curr) - attained_service(curr), 0)

preempt home iff:
    wakee is fair-vtime eligible, and
    delaying it by predicted_remaining(curr) exceeds its learned slack after
    backlog fading and bounded locality/preemption cost.
```

Cold or untrusted estimates fall back to today's proven gate. This makes the
new path an additive refinement with a safe rollback, not a flag day.

### Expected behavior by scheduling shape

| Shape | Learned signals | Expected LSVD behavior |
|---|---|---|
| continuously runnable compute | no stable sleep period | zero learned deadline credit; current Cake fairness/locality |
| futex/pipe handoff | tiny cycle slack, little runnable backlog, young current | immediate convergence/preemption retained |
| active game pipeline | repeated blocking plus small available slack, usually below system saturation | prompt service before predicted bubble |
| sparse input/audio event | cold/long period but slice-capped response horizon | retains bounded responsiveness, never infinite wait |
| saturated schbench | large runnable backlog and an old productive current | urgency fades; finish bias and fair vtime protect throughput |
| idle CPU exists | zero CPU-unavailable estimate | direct dispatch remains work-conserving; no artificial grace bubble |

These rows are predictions to falsify. They are not workload classes in code.

## Why per-task history is now justified — and dangerous

Cake's current stateless invariant bought simplicity and extremely low hot-path
cost, but it is also the ceiling: no instantaneous queue/vtime test can know a
task's normal burst or activation interval.

Local `scx_lavd` proves that sched_ext can maintain runtime, wait/wake cadence,
and task-local context. It also shows the cost danger: LAVD's task context spans
multiple cachelines and implements a much larger policy. Cake should borrow the
mechanism, not the policy stack.

The key risk is that two task-storage accesses per switch/wake may erase the
4.8M futex win or worsen the structural perf-pipe callback tax. The design is
rejected if the state cost is measurably harmful before it changes one decision.

Local comparison anchors:

- `scheds/rust/scx_lavd/src/bpf/lavd.bpf.h` (`struct task_ctx`)
- `scheds/rust/scx_lavd/src/bpf/lat_cri.bpf.c`
- `scheds/rust/scx_lavd/src/bpf/main.bpf.c` (`runnable`, `running`, `stopping`)

## Magic-number policy

The goal is not literally zero constants; representation, safety, and learning
need bounds. The rule is that no constant may encode a benchmark or game.

Acceptable constant families:

- representation shifts and masks;
- base slice and values algebraically derived from it;
- topology distance obtained from the machine;
- bounded estimator warm-up state;
- watchdog/verifier bounds.

Suspect constant families:

- absolute microsecond classification thresholds;
- queue-depth ladders with separately tuned actions;
- one-off game/benchmark offsets;
- fixed migration grace that can idle a CPU;
- arbitrary permanent EWMA time constants without a sensitivity experiment.

Estimator choice remains open. Begin in shadow mode with last-sample and simple
dyadic estimates, record prediction error, and choose the smallest filter whose
error is stable across futex, schbench, game, and compute workloads. Do not tune
the estimator against WoW alone.

## Research source trail and claim boundaries

1. Linux EEVDF documentation:
   <https://docs.kernel.org/scheduler/sched-eevdf.html>
   - Transfers: lag/eligibility and virtual-deadline ordering are a sound fair
     base; sleepers need bounded credit.
   - Does not transfer: EEVDF does not provide Cake's learned pipeline deadline.
2. Linux sched_ext documentation:
   <https://docs.kernel.org/scheduler/sched-ext.html>
   - Transfers: DSQ lifecycle, priority-queue behavior, and callback/dispatch
     constraints.
3. Linux SCHED_DEADLINE documentation:
   <https://docs.kernel.org/scheduler/sched-deadline.html>
   - Transfers by analogy: recurring work can be modeled with service `C`,
     deadline `D`, period `P`, and schedulability depends on demand/capacity.
   - Does not transfer: LSVD has learned soft estimates, no admission control,
     and makes no real-time guarantee.
4. Shinjuku, NSDI 2019:
   <https://www.usenix.org/conference/nsdi19/presentation/kaffes>
   - Transfers: short urgent work blocked behind long work creates tail latency;
     selective preemption can help.
   - Does not transfer: Shinjuku controls a specialized runtime and can preempt
     at microsecond scale outside general Linux fairness/topology constraints.
5. Caladan, OSDI 2020:
   <https://www.usenix.org/system/files/osdi20-fried.pdf>
   - Transfers: workload demand and interference change rapidly; static
     partitioning wastes capacity and misses bursts.
   - Does not transfer: Caladan uses a dedicated scheduler core and application
     cooperation.
6. Scully and Harchol-Balter, "The Gittins Policy in the M/G/1 Queue":
   <https://arxiv.org/abs/2111.10703>
   - Transfers as inspiration: attained service and learned service-time
     behavior are principled inputs when job size is unknown.
   - Does not transfer: the optimality result is for an M/G/1 queue, not a
     multicore fair scheduler with cache topology and migration cost.

## Experiment ladder

### E0 — preserve the checkpoint

- Copy the exact binary/BPF object and current source snapshot into a named
  candidate directory.
- Preserve Git head, dirty patch hash, binary/BPF hashes, kernel, scheduler
  activation proof, args, and noise metadata.
- Do not modify or overwrite the current benchmark-winning binary.

### E1 — state-cost-only A/B

- Add the smallest task record and lifecycle management.
- Update estimates, but do not use them for routing, ordering, preemption, or
  slice selection.
- Compare verifier/JIT size, callback cost, futex, pipe, cache/memcpy, standard
  and saturated schbench, fork/thread, and runnable-stall behavior.
- If the state-only binary has a repeatable regression beyond normal run noise,
  stop and redesign storage before policy work.
- Rollback: remove task storage and callbacks; scheduling output is unchanged.

### E2 — sampled shadow decisions

- Compute `C_hat`, `P_hat`, slack, predicted current remainder, pressure fade,
  and the would-preempt result without acting on it.
- Expose reason-coded, sampled histograms/counters only; never print or trace
  every wake on the benchmark hot path.
- Check estimator warm-up, prediction error, saturation behavior, and whether
  the score separates proven futex handoffs from old-worker schbench wakes.
- Correlate proposed decisions with longer WoW/Armor Core/Kovaak's captures and
  targeted sched traces.

### E3 — home-preempt substitution

- Leave DSQ topology, select placement, wake routing, steal ring, and slices
  unchanged.
- Use the master comparison only where today's fixed young-current home-preempt
  gate runs.
- Cold-state fallback is the current gate.
- This is the smallest behavioral test of the central theory.
- Rollback: restore the current three-term preempt conditional.

### E4 — one score across routing and dispatch

Only after E3 wins both synthetic and game gates:

- reuse the same score for home versus global wake routing;
- investigate encoding bounded deadline credit into vtime order;
- use locality cost to choose among runnable work, never to suppress work;
- retain structural starvation prevention and bounded credit.

Do not create a second "game lane" or "benchmark lane" during E4.

## Verification gates

### Synthetic

At minimum, compare against the exact checkpoint above:

- stress-ng futex;
- perf sched pipe;
- cpu-cache-mem cache and memcpy;
- schbench standard, light, and saturated including RPS;
- perf sched fork/thread;
- x265 and representative compilation/compute workloads;
- stalls/watchdog, fairness, migrations, context switches, IPC, and BPF cost.

Use repeated same-window A/Bs. A single noisy run may guide investigation but
cannot promote a candidate.

### Games

- Alternate Cake and native order in the same stable, focused scene.
- Use at least 60-second captures at high FPS so the 0.1% region contains
  multiple actual frames; increase duration for low-FPS capped games.
- Repeat enough pairs to report uncertainty rather than cherry-picking one run.
- Keep average FPS, 1% low, 0.1% low, p95/p99/p99.9/max frame time, jitter,
  CPU/GPU utilization, focus, and system-noise evidence together.
- A broad-tail win plus a one-frame max loss is promising, not a universal win.
- Test WoW, Armor Core VI, and Kovaak's because they exercise different frame
  rates and CPU/GPU balance; none receives game-specific policy.

### Portability

The 9800X3D is a single-CCD/shared-V-Cache machine and can hide migration damage.
Before calling locality universal, use topology-constrained tests and, when
available, a multi-CCD or heterogeneous CPU.

## Stop/keep rules

Keep a stage only when:

- the predicted mechanism appears in its reason counters/traces;
- synthetic wins remain within controlled variance;
- game broad-tail wins remain and repeated extreme-tail evidence improves;
- verifier complexity and hot-path cost stay proportionate;
- no starvation or runnable-stall path appears.

Revert or replace a stage when:

- task-history overhead alone loses futex/pipe materially;
- backlog fading fails and saturated RPS drops;
- the score merely learns executable identity indirectly;
- estimator phase changes cause oscillation or unbounded credit;
- locality protection creates an idle CPU while compatible work exists;
- a win exists only in one game or one benchmark.

## GPT-5.6 Sol reasoning-mode handoff

Officially published GeneBench-Pro data is the only direct xhigh/max comparison
found during this session:

| Mode | Pass rate | Average tokens |
|---|---:|---:|
| xhigh | 26.8% | 25.7k |
| max | 28.7% | 33.2k |

Max gained 1.9 percentage points (about 7.1% relative) while using about 29.2%
more tokens. The confidence intervals overlap, and GeneBench-Pro is scientific
analysis rather than kernel engineering. OpenAI describes ultra as maximum
reasoning plus automatic subagents, but no official xhigh/max/ultra
apples-to-apples coding table was published.

Sources:

- <https://openai.com/index/previewing-gpt-5-6-sol/>
- <https://cdn.openai.com/pdf/21938268-21af-442f-af93-3b2249afb241/genebench-pro.pdf>

Recommended continuation: use **max** for the coherent LSVD architecture and
invariant pass, then return to **xhigh** for the repeated implementation and
measurement loop. Ultra is only justified if independent research tracks are
explicitly delegated; it is not automatically better for one hot-path policy.

## Immediate next action after the mode switch

Do not edit the scheduling policy first. Read this note plus current `DESIGN.md`
and `cake.bpf.c`, then design **E1: state-cost-only** as a separately buildable
candidate with an exact rollback. The first question is whether Cake can afford
the minimum per-task learning mechanism without surrendering the benchmark
winner it is meant to preserve.

## E0/E1 continuation receipt

E0 was preserved before the E1 rebuild under:

```text
.scx_cake_bench/candidates/queued_wakeup_state_convergence_v1_e0/
```

It contains the exact measured release binary, embedded BPF object, captured
patch, and full copies of the four dirty scheduler files. The first E1 probe,
`lsvd_e1_task_state_cost_v1`, used one 32-byte
`BPF_MAP_TYPE_TASK_STORAGE` record:

```text
last_wake_ns, run_est_ns, period_est_ns, samples, flags
```

That probe attached successfully, but it added one task-storage lookup to every
`stopping()` call and its run estimate represented one scheduled turn rather
than the full wake-to-sleep activation. Its first paired pipe measurements were
also taken while WoW consumed roughly two CPUs, so they are diagnostic rather
than a clean keep/reject gate.

E1v2, candidate `lsvd_e1_wake_epoch_state_cost_v2`, keeps the record at 32
bytes but changes it to:

```text
last_wake_ns, last_exec_runtime, u32 run_est_ns, u32 period_est_ns,
samples, flags
```

`runnable()` now derives both period and full-activation service from adjacent
wake epochs. Estimates saturate above `u32` nanoseconds, which is still more
than three orders of magnitude above Cake's 3 ms decision horizon. No task
storage is touched in `stopping()`, restoring that hottest callback to the E0
instruction stream. Neither estimate is read by any scheduling decision.
`init_task()` performs allocation; BPF task storage frees the record with task
lifetime, so E1 adds no explicit exit callback. Build, object-cost, activation,
and clean benchmark results belong below this paragraph only after they have
actually run.

## 2026-07-10 folded service-margin experiment

The first implementation avoided task storage and folded fair lead, estimated
wakee service, and switch cost into one home-preemption comparison:

```text
lead = live_curr_vtime - wakee_vtime
margin = min(SLICE/2,
             SLICE/32 + weighted(sum_exec_runtime / voluntary_blocks))

preempt_home iff lead > margin
                 and (curr_age < SLICE/32 or global_wake_queue_empty)
```

The observed WoW thread services motivated the shape: queue/swapchain/audio
stages were generally tens of microseconds per voluntary block, whereas
sustained workers were millisecond-scale and therefore saturated at the old
half-slice protection. This produced a real microarchitectural recovery on
`vkd3d_queue` versus native EEVDF: IPC +11.4%, cache-miss rate −7.7%, L1D miss
rate −54.3%, L2 read hit rate +6.79 percentage points, and DRAM fills/s −24.5%.

The experiment also falsified two assumptions:

1. Ordinary pinned-vtime routing was not sufficient forward-progress
   protection for essential pinned kernel threads. The first 20 s trace
   stranded `ksoftirqd/13` for 6.884 s and triggered the runnable-stall
   watchdog. A generic pinned-kthread wake guard, direct to its sole CPU's
   local DSQ, survived the identical record-plus-parse stress.
2. Improving one rendering queue's cache and execution shape did not imply
   better whole-frame delivery. In the clean unlocked WoW ABBA, guarded v2
   lost 2.97% average FPS, 3.56% 1% low, and 17.83% 0.1% low; p99.9 and maximum
   frame time worsened 24.09% and 39.45%. Both candidate arms lost 0.1% low and
   maximum frame time to both native arms.

Thread traces explain the disconnect: `vkd3d_queue` runnable wait improved,
but broad WoW and audio wake latency/migration behavior regressed. The next
fold must therefore make placement, global-wake arbitration, and home preempt
consume one consistent locality-aware slack rank. Tuning the home margin alone
is rejected; the pinned-kthread guard remains a reusable safety invariant.

Attributable evidence:

- v2 WoW ABBA report:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game-campaigns/service_shaped_fair_lead_pinned_guard_v2/wow_abba_20260710_112007/imported/WoW/2026-07-10/reports/report.json`
- v1 PMU diff:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game-campaigns/service_shaped_fair_lead_v1/wow_abba_20260710_105922/pmu/diff_native_vs_service_unlocked`
- v2 safety trace:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game-campaigns/service_shaped_fair_lead_v1/wow_abba_20260710_105922/thread_trace/service_pinned_guard_v2_unlocked_r1`
