# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C23, PANDEMONIUM assigns every task a latency tier by scheduling role and adapts scheduling decisions in real time. A damped harmonic oscillator drives CoDel-inspired stall detection with the literal RFC 8289 sojourn metric and an R_eff-derived equilibrium reference. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. A migration potential Φ — R_eff priced against the queueing relief a move buys — prices both cross-domain work stealing and enqueue-time placement spill, so a task crosses a cache boundary only when the backlog it relieves outweighs the cache cost. The steal applies Φ as a delay on the backlog age; the spill as a per-peer depth threshold Rust folds from R_eff at topology detect and the kernel reads with one indexed lookup — the computation in the adaptive layer, the application in the kernel. Every knob the adaptive layer ships is a function of a measurement — per-CPU queue depth, traffic shape, critical slowing and persistence — computed on the tick it is applied rather than learned over a convergence window.

Overflow sojourn rescue, longrun detection, sleep-informed batch tuning, tier-gated DSQ routing, a migration-potential-gated R_eff work steal, a Φ-priced placement spill, a Φ-priced warm-stay home anchor, a sojourn selector whose warp is bounded by the live CoDel target, a slice quantum priced in the same unit, an off-tick unified sojourn bound, an RT-policy latency floor and hard starvation rescue.

See the [New User Guide](NEW-USER-GUIDE.md) for an introduction — the ideas behind PANDEMONIUM in plain language.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE, Arch, Ubuntu and NixOS communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs (Ryzen 5 3600), kernel 7.2.2-arch1-1, clang 22. EEVDF baseline vs PANDEMONIUM (BPF and ADAPTIVE); external schedulers are omitted from this comparison. **All figures below are the median of N=3 iterations taken in one interleaved session**, so the ratio between arms is the comparable quantity and the absolutes are not comparable to another day's run.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF   | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|---------|-------------------|------------------------|
| 2     | 2,110us | 406us             | **369us**              |
| 4     | 2,990us | **64us**          | 75us                   |
| 8     | 920us   | 68us              | **66us**               |
| 12    | 533us   | 69us              | **67us**               |

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF   | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|---------|-------------------|------------------------|
| 2     | 2,270us | **647us**         | 907us                  |
| 4     | 1,851us | 943us             | **731us**              |
| 8     | 2,473us | 1,026us           | **906us**              |
| 12    | 2,755us | **355us**         | 477us                  |

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF     | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-----------|-------------------|------------------------|
| 2     | 2,339us   | 2,075us           | **1,426us**            |
| 4     | 3,476us   | 1,427us           | **1,257us**            |
| 8     | 2,230us   | 986us             | **419us**              |
| 12    | 147us     | 184us             | **130us**              |

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF     | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-----------|-------------------|------------------------|
| 2     | 2,576us   | 2,984us           | **2,101us**            |
| 4     | 1,998us   | 1,410us           | **1,259us**            |
| 8     | 1,266us   | **289us**         | 855us                  |
| 12    | **194us** | 673us             | 982us                  |

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------|-------------------|------------------------|
| 2     | 19.5% | **1.0%**          | 1.5%                   |
| 4     | 12.2% | **0.2%**          | 0.3%                   |
| 8     | 10.8% | **0.1%**          | 0.3%                   |
| 12    | 12.9% | **0.0%**          | 0.1%                   |

### App Launch (`fork()`+`exec()` under load, p99 us)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 2,147us     | 1,821us           | **1,669us**            |
| 4     | 2,138us     | **1,421us**       | 2,325us                |
| 8     | 3,434us     | 2,537us           | **1,475us**            |
| 12    | 3,472us     | 2,427us           | **1,623us**            |

### IPC Round-Trip by Primitive (12C, p50 / p99 us)

| Primitive | EEVDF          | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-----------|----------------|-------------------|------------------------|
| pipe      | **9 / 15**     | 11 / 1,372        | 14 / 908               |
| socket    | **16 / 23**    | 22 / 743          | 27 / 1,016             |
| eventfd   | **9 / 13**     | 18 / 28           | 18 / 26                |
| sem       | **9 / 13**     | 23 / 42           | 18 / 34                |
| fanout    | **51** / 2,840 | 74 / 1,638        | 83 / **1,588**         |

### Fork/Thread IPC (`perf bench sched messaging -t -g 24 -l 6000`, 12C)

| Scheduler                | Time        | vs EEVDF | Cache Misses | Cache Refs | IPC       |
|--------------------------|-------------|----------|--------------|------------|-----------|
| EEVDF                    | **17.198s** | baseline | **3.67G**    | **26.08G** | **0.493** |
| PANDEMONIUM (BPF)        | 23.346s     | +35.7%   | 6.36G        | 37.17G     | 0.410     |
| PANDEMONIUM (ADAPTIVE)   | 23.199s     | +34.9%   | 6.42G        | 37.17G     | 0.412     |

Wake-to-run p99 is the other half of that trade: EEVDF 75,541us against PANDEMONIUM's
8,734us (BPF) and 8,767us (ADAPTIVE) — **8.6x better** on the arm that costs 35.7% more
wall time.

| Scheduler                | Mig/s       | same-L2   | same-L3 | same-socket | Decay          |
|--------------------------|-------------|-----------|---------|-------------|----------------|
| EEVDF                    | **5,380**   | 36.3%     | 45.3%   | 18.5%       | 1.25/0.41/0.00 |
| PANDEMONIUM (BPF)        | 38,125      | **62.4%** | 34.6%   | **2.9%**    | **0.56/0.09**  |
| PANDEMONIUM (ADAPTIVE)   | 37,575      | 62.1%     | 35.1%   | 2.8%        | 0.56/0.08      |

Migrations are reported as a RATE, not a count: The arms do not run for the same number of
seconds, so a count rewards the slower arm for the extra time alone. Decay is each tier's
share over the previous one — below 1.00 throughout means migration density FALLS with
distance, and EEVDF's 1.25 means it RISES. montauk classes the two arms differently on this
capture, EEVDF `SCATTERED` against PANDEMONIUM `CACHE-LOCAL`. Every arm captured at 100%
completeness, so the rates are comparable rather than sampled.

### Energy Efficiency (`prism --dev power`, 12C)

3 runs per (scheduler, workload), 30s cooldown between runs. Package energy via `perf stat -a -e power/energy-pkg/`. Zen 2 (Ryzen 5 3600) exposes only `J_pkg` (no per-core or per-DRAM RAPL).

**Idle floor** (30s `sleep`, scheduler restlessness):

| Scheduler                | J_pkg       | Avg W      | vs EEVDF |
|--------------------------|-------------|------------|----------|
| EEVDF                    | 693.82J     | 23.11W     | baseline |
| PANDEMONIUM (BPF)        | **692.72J** | **23.07W** | **-0.2%** |
| PANDEMONIUM (ADAPTIVE)   | 694.21J     | 23.12W     | +0.1%    |

**Messaging** (`perf bench sched messaging`, fork-storm + IPC):

| Scheduler                | Wall_s     | J_pkg       | J/op         | vs EEVDF  |
|--------------------------|------------|-------------|--------------|-----------|
| EEVDF                    | **15.81s** | **992.84J** | **172.37uJ** | baseline  |
| PANDEMONIUM (BPF)        | 20.10s     | 1,230.36J   | 213.60uJ     | +23.9%    |
| PANDEMONIUM (ADAPTIVE)   | 20.09s     | 1,229.00J   | 213.37uJ     | +23.8%    |

Average power is LOWER on both PANDEMONIUM arms (61.2W against 62.8W); the energy cost is
wall time, not draw. This is the same trade the fork-thread table shows, priced in joules.

## Key Features

### Dispatch Waterfall

Layered dispatch with per-CPU DSQ dominance and one age-driven safety mechanism. CPU-tied placement is bounded at the enqueue site and overflow spills to a sibling per-CPU DSQ in R_eff order, each candidate gated by a per-peer depth threshold folded from R_eff at topology detect — near peers accept at higher depth, distant peers only when near-empty, flat on a monolithic L3. Idle-CPU placement inserts directly into the per-domain overflow DSQ and is picked up within one dispatch cycle; an eager R_eff search at that site is a wire-speed regression on fork storms with no measurable placement benefit. The steal is **one Φ-priced walk** with no near/far tier boundary — the penalty alone prices the move, so nearer relief is always preferred without a structural same-domain/different-domain gate (THE FLAG). Bounding a CPU nobody is calling `dispatch()` on at all is `sweep_bound_preempt`'s off-tick job, not a step here. The sojourn gate at STEP 0/1 is load-bearing for workqueue-worker fairness: Without it the watchdog worker strands in the overflow DSQ long enough to trigger a 30s kill.

| Step | Source | Rule |
|---|---|---|
| **0** | Own per-CPU DSQ | Cache-hot, zero contention. **Sojourn-gated**: If either overflow side has aged past the CoDel target, fall through to STEP 2 so this dispatch serves overflow too. |
| **1** | R_eff steal | One loop over the per-CPU R_eff-ascending peer list, cross-domain peers included, on a tau-derived budget. A peer is relieved only when it has more than one task queued *and* its head has aged past the CoDel target plus that peer's distance penalty — so an SMT sibling is freely relievable while a cross-domain pull must show real backlog. A confirmed tight pair adds a hold so a near steal does not split it, and a per-CPU rate limit gates the walk to once per CoDel target. |
| **2** | Older overflow side | The same pick-the-older comparison at the live CoDel target. Feeds the oscillator. |
| **3** | Local interactive overflow | Cache-coherent drain of this cache domain's interactive overflow DSQ (`node_dsq`, sojourn-ordered). |
| **4** | Local batch overflow | This cache domain's batch overflow DSQ. |
| **5** | Cross-domain work conservation | Scan other domains once; drain any non-empty overflow, interactive first per domain, then batch. Runs only when the local domain is empty, so cross-domain migration here is pure idle-time work conservation. |
| **6** | KEEP_RUNNING | `prev` still wants CPU and nothing is queued. |

### Three-Tier Enqueue

- **select_cpu**: idle CPU -> per-CPU DSQ (depth-gated: 1 slot at <4C, 2 at 4C+) -> R_eff sibling spill if full -> last-resort node DSQ, with KICK_IDLE on the placement target. WAKE_SYNC path: Partner-CPU fast path (claim the wakee's `last_cpu` directly if idle and allowed, skipping the R_eff scan on a stable pair) -> R_eff idle search -> waker fallback, WITH a kick — arm A (found-idle) KICK_IDLE, arm B (no-idle) KICK_PREEMPT — so the wakee runs next instead of aging until the target's tick (the dominant IPC round-trip tail)
- **enqueue Tier 1** (idle CPU): Direct `node_dsq` insert + KICK_PREEMPT for non-BATCH / KICK_IDLE for BATCH. Drained by STEP 3 (unconditional `node_dsq`) within one dispatch cycle. The wire-speed path: Eager R_eff search at this site is a fork-storm regression with no placement benefit, so Tier 1 stays a direct insert
- **enqueue Tier 2** (wakeup preemption): Uses `pick_pcpu_dsq_with_spill` for symmetric placement with `select_cpu`. CPU-tied; benefits from eager per-CPU placement
- **enqueue Tier 3** (fallback): Batch overflow DSQ for BATCH only; INTERACTIVE stays in `node_dsq` — the batch DSQ is for BATCH-tier work only, so a burst of fresh INTERACTIVE threads cannot flood it and starve. The sojourn deadline (`now − warp`) is computed at the insert
- **tick**: Longrun detection (batch non-empty >2s), sojourn enforcement, per-CPU preempt of the resident for an aged waiter (`sojourn_stamp_pcpu[this_cpu]` age vs a tau-scaled threshold; BATCH yields at base, INTERACTIVE at 2×)

### Damped Harmonic Oscillator Stall Detection

CoDel-inspired per-CPU DSQ stall detection where the target follows the full damped harmonic oscillator equation:

```
ẍ + 2γẋ + ω₀²(x − c_eq) = F(t)
```

Damping is Butterworth-optimal (ζ ≈ 0.707): The flattest response available, at the cost of one bounded ~4.3% overshoot per adaptation. The overshoot is deliberate — it probes the response boundary on each impulse instead of parking inside it.

**Per-task sojourn** (RFC 8289): `task_ctx.enqueue_at` is stamped at every DSQ insert and consumed in `pandemonium_running` to compute `sojourn = now − enqueue_at` — the literal CoDel metric, wait between enqueue and run start. A per-task timestamp stays accurate through an entire drain, where a per-CPU proxy weakens past the first task.

**Stall decision**: Per-CPU minimum sojourn against `codel_target_ns`. Below is flowing; above for `sojourn_interval_ns` is stalled and forces rescue. The decision is binary CoDel; the target is what oscillates.

**Equilibrium**: `c_eq = ⟨R_eff⟩ × 2m × τ`, built from spectral properties already computed at topology detect — the natural latency tolerance of the machine's own topology rather than a hand-tuned constant. Clamped to `[200µs, 8ms]`.

**Feedback**: The overflow rescue count drives the impulse. Each tick on CPU 0 the oscillator applies impulse, spring and damping, caps velocity and integrates. `x` rests at `c_eq` when quiet, descends on rescue events, returns damped. Every timing constant scales from τ, so a topology change preserves the damping ratio automatically — the live values are derived at runtime, never tabulated.

**Idle quiescence envelope**: The control effort obeys the same damping law as the system it controls, so the oscillator goes quiet when the system does. An energy reservoir built from values the recompute already maintains drives the recompute cadence down as the oscillator contracts: Below a release threshold it recomputes every fourth tick, and below a park threshold it pins the target at its closed-form fixed point, freezes the velocity integrator so it cannot accumulate and slingshot at wake, and stops the arithmetic entirely. The two thresholds sit a factor of two apart, giving multiplicative hysteresis on energy. While parked, three compares per tick arm the detector — a rescue event, the equilibrium moving under the parked value, or a 1024-tick heartbeat — and any of them triggers a full recompute in the same tick, before any dispatch prices against the target, re-priming above release so a bursty wake cannot immediately re-park. Every burst therefore begins from an identical controller state. `nr_osc_park` counts parks; zero parks after an idle-heavy run is the attention-collapse failure this counter exists to detect.

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes downstream anti-starvation unreachable — 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch STEP 0 / STEP 1 fall through to STEP 2 when either overflow DSQ has aged past `codel_target_ns` — the live CoDel target the oscillator drives around its R_eff-derived equilibrium `codel_seed_ns` (`⟨R_eff⟩ × 2m × τ`, clamped into the oscillator's `[floor, max]` window, so ≤~2ms at 12C — not a hand-tuned ~10ms). The spectral scalar opens the gate; sojourn (enqueue-age) fills it and selects the older side. `try_service_older_overflow` then drains that side past the threshold. CAS-based timestamp management prevents races across CPUs.

**Drain both when both aged**: Under sustained mixed load both overflow DSQs can stay continuously non-empty for tens of seconds, freezing both timestamps at their first-non-empty values. A strict "older wins" would then pick the same side every rescue call until external pressure dropped, locking out batch-demoted long-runners (at 2C, a 19-29s starvation tail; 4C+ closes the window through higher dispatch density). So when BOTH sides are aged, both drain — older-first ordering preserved (latency-budget bias for interactive on ties), at the cost of one extra `scx_bpf_dsq_move_to_local`.

### Longrun Detection

When batch DSQ stays non-empty past `longrun_thresh_ns` (tau-scaled, ~2s at 12C reference), `longrun_mode` activates. Two consumers: `task_slice` substitutes `burst_slice_ns` for `slice_ns` on INTERACTIVE/LATCRIT (1ms tighter cap, yields CPU faster under pressure); `tick` scales the preempt threshold via `longrun_preempt_shift` — 4× at 2C (extends BATCH's protected window) so thin topologies don't thrash, no scaling at 4C+ where capacity already absorbs LAT_CRIT contention.

### Wake Sensitivity & Preemption

There is no burst detector, and nothing needs one: A burst is already answered by the oscillator-adapted CoDel target, the placement-side depth gate with its L2/R_eff spill, the starvation rescue, and the tier information present at the enqueue site. Tick preemption is derived per-CPU, with no global signal:

- **Per-CPU preempt**: `pandemonium_tick` reads its own `sojourn_stamp_pcpu[this_cpu]` — the age of the oldest task waiting on this CPU — against a tau-scaled threshold (`preempt_thresh_ns`): A BATCH resident yields once a waiter ages past the base threshold, an INTERACTIVE resident at 2× (batch-throughput protection). Per-CPU by construction — no token to race over. A single global flag instead (armed at enqueue, cleared by the first tick to preempt on *any* CPU) gets token-stolen across cores under a fork storm, so the CPU actually burying a latency waker rarely wins the race — the audio-under-load pathology (intermittent, single-thread, bursty-only). The per-CPU read reuses the bounded-array scan already running for the coarse per-CPU sojourn check, so no new global state.
- **RT never arrives, and that is a property of the kernel rather than of this scheduler**: sched_ext sits BELOW RT and deadline in the scheduling-class hierarchy and is handed only `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE`. A `SCHED_FIFO` or `SCHED_RR` thread is served by the RT class and never reaches these ops at all, so there is no RT tier to declare and no RT floor to hold. Measured rather than assumed: Two `SCHED_FIFO` threads at rtprio 5 held against a live scheduler for 48 seconds produced zero arrivals across all 49 samples.
- **Core-scaled longrun protection**: During sustained `longrun_mode`, the preempt threshold scales up on thin topologies (τ < 4ms) only, extending the protected BATCH window so they don't thrash; wider topologies keep the baseline, where capacity already absorbs LAT_CRIT contention.

### Sojourn Selector: The CoDel-bounded warp

There is no weighted virtual-time engine. `task_deadline()` returns `now − warp` — the enqueue timestamp back-dated by a bounded per-tier warp — so every DSQ is ordered oldest-first (largest sojourn served first). Sojourn IS the selector; no second fairness clock runs parallel to the sojourn + R_eff/CoDel layer.

**The ordering bound and the starvation bound are separate numbers.** The warp is the share of one live CoDel target a task left unconsumed on its last run — `codel_target_ns − last_run_ns`, floored at zero. A task that blocked immediately earns a full target; one that held the CPU for a target or longer earns nothing; everything between is continuous, with no classifier, no maturity gate and no fixed steps (THE FLAG). It is bounded by the target by construction, so a task that has waited past one target out-sorts any fresh claim.

`lag_cap_ns = K_LAG_CAP × τ` clamped `[8ms, 80ms]` is the **starvation** bound and nothing else — the age at which `sweep_bound_preempt` forces a head off its CPU. It was previously also the warp ceiling, which let a single back-date consume the entire starvation budget; the two are no longer one number.

Starvation-freedom is therefore structural rather than clamped: A task older than one target out-sorts any freshly-warped waker, no new-task penalty is needed, and a new task enters at `now` like any other arrival. (A wakeup-frequency-weighted warp and a queue-depth backlog term each reorder by something other than wait — they cluster ping-pong wakers or rubberband interactivity — so the warp stays bounded by the target; deep-queue drainage is left to the overflow sojourn rescue, which forces aged work forward by wait, not depth.)

### Hard Starvation Rescue

Two bounds sit under the dispatch waterfall, the tighter one first. `sweep_bound_preempt` runs off-tick and NO_HZ_FULL-immune: It rotates through CPUs and forces one back into `dispatch()` whenever an overflow head ages past `lag_cap_ns` (see Warp above, ~13ms at 12C). Beneath it, `codel_starve_ns` — `clamp(K_STARVATION_RESCUE × τ, 20ms, 500ms)`, ~167ms at the 12C reference — is the last-resort threshold in dispatch: Past it, the older overflow side is serviced unconditionally. The off-tick bound catches the common case; the starve threshold is the floor under everything, including a CPU the sweep has not yet rotated to. A pinned single-CPU task (per-CPU kworker, IRQ thread, cpuset) is a separate hazard: It can only run on its one CPU, and if that CPU is idle it never ticks, so the in-tick rescue scan never fires and the task strands until the 30s scx watchdog disables the scheduler. A tick-independent guard on the enqueue path seats a pinned task on its own CPU and `SCX_KICK_PREEMPT`s it at enqueue (an event scx guarantees runs), closing the watchdog-disable the tick-driven rescue cannot reach.

### Topology-Aware Placement

**Resistance affinity**: The CPU topology is modeled as a weighted electrical network — SMT and L2 siblings conduct strongly, cross-socket links weakly. The Laplacian pseudoinverse gives all-pairs migration costs accounting for every path through the graph rather than direct connections alone, and `R_eff(i,j)` is a true metric satisfying the triangle inequality. Per-CPU ranked peer lists are folded into a BPF map at detect; the runtime walks them with sentinels marking unused slots so loops early-exit on small machines.

**Online-budget search**: The idle search spends its budget on *online candidates*, not slots. The rank map is built once from the full topology, so after hotplug some top ranks reference offline CPUs; those are skipped without charging budget. Search cost on a fully-online machine is unchanged while remaining correct under arbitrary hotplug asymmetry.

**Tight-pair gate**: Each task's distinct wakers are recorded in a persisted bitmap. A low popcount marks a 1:1-ish handoff pair, where warm co-location pays; a high popcount marks a 1:N server, where it does not and clients must not pile onto the server's CPU. The same discrimination the kernel's `wake_wide()` makes, but persisted and frozen at classification rather than re-derived per wake.

**L2 cache affinity**: An in-enqueue search for an idle CPU in the same L2 domain, gated by a three-position knob holding its base value. Per-dispatch hit/miss counters are kept per tier.

R_eff is proportional to expected round-trip time for work between CPUs [2], so minimizing it between pipe partners minimizes cache-line transfer cost [1][3][4].

### Migration Potential (Φ)

R_eff alone is a placement *ranking* — it orders candidate CPUs by distance but doesn't price a migration against the queueing relief it buys, so a cross-domain steal would be as cheap as an SMT-sibling steal once a head aged. The migration potential prices it: **Φ = R_eff − β·sojourn**, the graph resistance of a move set against the wait it relieves. The dispatch STEP 1 work steal pays Φ, so it crosses a cache boundary only when the backlog justifies the cache cost.

- **The price is precomputed, never multiplied at runtime.** Rust folds `b·R_eff` into a per-peer table at topology detect, so the dispatch steal reads a ns penalty with one indexed lookup. A companion table carries `domain_phi`, the min-conductance cut price between a CPU and each ranked peer, read by the tight-pair steal hold. Both are all-zero on a monolithic part or under `--phi-scale 0`, which collapses every threshold below to a flat `codel_target` — prior behavior, no special case.
- **Distance-scaled steal resist**: A peer is relieved only once its head has waited past `codel_target_ns` plus that peer's penalty. An SMT sibling (R_eff ≈ 0) stays freely relievable at the flat target; a cross-domain pull must show roughly τ of sustained backlog first. The scale is always computed — on a single-domain part it calibrates to the L2 boundary rather than vanishing, so distance is priced on every processor with no binary topology gate.
- **Warm placement and warm-stay**: A wakee is anchored on its own last core and searched R_eff-near before any topology-blind idle pick, which would otherwise seat it on a cross-domain core with a cold L3. A wakee whose stable home is uncongested is held there rather than fanned to a cold idle sibling — the placement dual of the steal threshold, releasing at the same point, so a near home releases quickly and a far one holds hard. The hold lives in `enqueue`, not the idle fast path: Placing on a busy core there is a no-op that strands the wakee until the resident yields. Kthreads are exempt; they flee for immediacy.

Φ prices each migration by its graph resistance [1][2] and pays only when queueing relief justifies the cache cost. Cross-domain work conservation is preserved — an idle cross-domain core is still taken freely; what Φ removes is the *cheap* cross-domain steal that thrashed L3 for marginal queueing gain.

### Tier Classification

`tier` is a **declaration, not a judgement.** It is two values, set from one flag the
kernel already states, and **the dispatch key takes no tier input at all** — see Sojourn
Selector.

| Value | Set by | Effect |
|---|---|---|
| **INTERACTIVE** | `PF_WQ_WORKER` | Slice derived from the task's own measured runtime, capped at the knob base slice. Userspace blocks on workqueue workers, so they are latency-adjacent by construction rather than by observation. |
| **BATCH** | everything else | The adaptive layer's ceiling, itself capped at `SLICE_STANDING_TARGETS × codel_target_ns`, so a resident holds a CPU for a bounded number of CoDel targets and no longer. |

There is no third tier and no behavioural scorer. A score over wakeup and context-switch
rates was built, measured and removed: `last_woke_at` did two jobs that destroyed each
other, so every task read BATCH after its first wake, and repairing it saturated the other
way at 92% latency-critical. Mass on a ceiling cannot be cut by moving a threshold. The
high-priority kthread override went with it — `PF_KTHREAD` at `static_prio <= 110` was
forced to BATCH by a branch that could only ever see BATCH, and BATCH is now the default.

- **Flow Signature**: Each wakeup sets the waker CPU's bit in a per-task bitmap; the popcount is the task's distinct-partner cardinality — a topology-free read of the live communication graph's conductance. Once the partner set is stable the task is classified once and frozen: `≤ SHAPE_TIGHT_MAX` (2) distinct partners is a **TIGHT** pair/loop; a partner set spanning at least half of `nr_cpu_ids` is a **STORM** mesh; everything between defaults to TIGHT (latency-safe — its steal stays freely relievable). Portable — the STORM threshold scales with the machine, no hardcoded core geometry. The shape drives *placement* (TIGHT consolidates on its warm core, STORM spreads), never the steal: Gating the steal on shape strands a STORM-classed latency thread on a busy core, so the steal stays shape-blind.

### Adaptive Control Loop

The Rust control plane is chaos-theory-driven, and **every knob is a function of a measurement rather than the output of a search.** A derived knob is correct on the tick it is computed; a learned one is correct several convergence windows later and only if the regime holds still that long.

Every knob derives from one sensor, and the mapping is the design:

| Sensor | Primitive | Drives | Because |
|---|---|---|---|
| **depth** | mean per-CPU queue depth | the per-CPU slice | A deep queue slices shorter so it drains; a shallow one longer so it stops paying context-switch cost for contention that is not there |
| **critical slowing** | lag-1 autocorrelation | the preempt window | Tightens *ahead* of the burst — the only actuation in the loop acting on a prediction rather than a completed loss |
| **traffic shape** | Kim-Jo burstiness | batch and burst ceilings | Bursty traffic wants a longer batch ceiling, paced traffic a shorter one |
| **persistence** | Veitch-Abry Hurst | the rescue threshold | A queue deep on a persistent CPU will still be deep, so rescue sooner |
| **coupling** | Pecora-Carroll, pairwise | nothing, deliberately | See below — measured, and not actuated |

- **One Thread, Zero Mutexes**: 1-second control loop on the main thread reads the per-CPU BPF stats array — depth, wake latency, dispatch counts, per-tier P99 — and writes knobs BPF picks up on the next scheduling decision. The array survives the read: Relating CPU *i* to CPU *j* is the half of the boundary BPF structurally cannot cross, so the spatial dimension is the reason the loop exists.
- **Chaos primitives** (`chaos.rs`, pure Rust, recomputed each tick over a 16-sample raw window): HVG mean degree λ (Luque–Lacasa horizontal visibility graph — ~2 periodic, →4 IID-random), Bandt–Pompe D=3 permutation entropy (ordinal disorder, normalized to [0,1]) and RQA determinism (fraction of recurrence points on diagonals — →1 steady, →0 IID).
- **One base profile, not three**: An audit of what actually varied across the old LIGHT / MIXED / HEAVY profiles found slice, preempt and batch (now all derived from measured depth, critical slowing and traffic shape) and `affinity_mode`. Everything else was identical in all three — defaults wearing a selector. What remains is a starting point the derivations move from: The value a knob holds on a machine that has not been measured yet.
- **The live load graph**: Nodes are CPUs weighted by mean depth, traffic shape, critical slowing and persistence; edges are CPU pairs weighted by coupling. The chip's electrical graph is a constant and R_eff already prices against it — this is the graph the *workload* forms, which moves every second. Depth sets the per-CPU slice, a deep queue slicing shorter so it drains and a shallow one longer so it stops paying context-switch cost for contention that is not there. Critical slowing tightens the preempt window ahead of the burst, the only actuation here acting on a prediction rather than a completed loss. Traffic shape sets the batch and burst ceilings; persistence sets the rescue threshold, since a queue deep on a persistent CPU will still be deep.
- **Coupling is measured and deliberately not actuated**: Deriving affinity strength from pairwise coupling regressed every IPC primitive on every arm, worst pipe p50 20 → 336us at 1.04x drift. IPC is a two-task ping-pong with tightly coupled queue depths, so the derivation fired hardest exactly where the damage landed. Affinity holds its base value until something measures the direction; the coupling reading stays as telemetry, because the reading was never the problem.
- **One controller on the rescue signal**: The oscillator owns `global_rescue_count` and nothing else adapts on it, so the double-correction hazard the old orchestrator had to be gated against no longer exists. The graph derives from depth, shape and persistence instead.
- **Quiescence freeze**: When the chaos signals sit in their steady band the loop latches frozen and skips the retune and knob write, still ticking at 1 Hz with the sensors as the thaw condition. Short of that, a sub-threshold retune stretches the interval; any disturbance snaps it back. **Known limit, measured:** both terms of the freeze gate read the same `idle_pct` window, and a fully saturated box pins that window flat — `rqa_det` returns 1.0 through its flat-window path and HVG λ sits inside the periodic band — so saturation can read as quiescence. Whether that is correct is deliberately open; that it can happen is not.

### Core-Count Scaling

All timing constants scale from `tau_ns = TAU_SCALE_NS / √(λ₂ · N)` — capacity-aware (the geometric mean of connectivity `1/λ₂` and capacity `1/√N`, so a well-connected but core-starved topology loosens instead of tightening), with safety-rail clamps. 12C reference: τ≈13.3ms (λ₂=12, N=12). Cardinality decisions (per-CPU DSQ depth, wake_wide threshold, tick scan budget) use `nr_cpus` directly — counts are not tau-derived. **The per-column τ values and derived cells below are an approximate reference; the live values are derived at runtime from the capacity-aware τ law.**

Every constant in that law is derived at runtime and none is tabulated here: The sojourn interval, the starvation rescue, the CoDel floor/ceiling/equilibrium, the warp bound, the spill and idle-search budgets, the per-CPU DSQ depth and the longrun preempt shift all fall out of τ with safety-rail clamps. A machine with a different topology gets different numbers by construction, which is the point.

- **Low-core slice discipline**: τ is largest at low core count (λ₂ shrinks as cores drop), so the tau slice cap runs loosest exactly where a wide batch slice hurts most — a 4ms slice on 2–4 cores denies a latency-sensitive probe across many consecutive slices, the low-core tail. The slice is capped to 1ms at `nr_cpus ≤ 4`, where a wide slice buys no throughput; 8C/12C keep the tau-scaled width, where it earns it.
- **CPU Hotplug**: `cpu_online`/`cpu_offline` callbacks clear per-CPU timestamps and oscillator state (velocity, rescue count) to prevent stale oscillation after suspend/resume
- **BPF-Verifier Safe**: No floats in the BPF path; integer-only arithmetic throughout. All shared state uses GCC __sync builtins

## Architecture

```
pandemonium.py           Build/install/benchmark manager (Python)
pandemonium_common.py    Shared infrastructure (logging, build, CPU management,
                           scheduler detection, tracefs, statistics)
export_scx.py            Automated import into sched-ext/scx monorepo
src/
  main.rs              Entry point, CLI, scheduler loop, telemetry
  lib.rs               Library root
  scheduler.rs         BPF skeleton lifecycle, tuning knobs I/O, histogram reads
  adaptive.rs          Adaptive control loop (monitor thread, per-CPU stats array,
                         live load graph, derived knobs, quiescence freeze)
  chaos.rs             Chaos primitives: HVG mean degree/entropy, Bandt-Pompe D=3
                         permutation entropy, RQA determinism (raw-window, no EWMA)
  tuning.rs            Knob types, the base profile the derivations move from,
                         tau-scaled caps, quiescence + adaptive-rarity retune
  topology.rs          CPU topology detection, Laplacian pseudoinverse, effective resistance,
                         resistance affinity ranking, R_eff cost oracle + Φ distance scale (sysfs -> BPF maps)
  event.rs             Pre-allocated ring buffer for stats time series
  watchdog.rs          Control-loop stall detector (10s heartbeat, abort on miss)
  bpf_intf.rs          Mirror of intf.h constants (MAX_CPUS, MAX_AFFINITY_CANDIDATES,
                         MAX_NODES) with static_assert against the C macro
  bpf_skel.rs          libbpf-cargo-generated BPF skeleton bindings
  log.rs               Logging macros
  bpf/
    main.bpf.c         BPF scheduler (GNU C23)
    intf.h             Shared structs: tuning_knobs, pandemonium_stats
  cli/
    mod.rs             Shared CLI helpers
    probe.rs           Interactive wakeup probe (Python test harness hook)
    stress.rs          CPU-pinned stress worker (Python test harness hook)
build.rs               vmlinux.h generation + C23 patching + BPF compilation
tests/
  pandemonium-tests.py Test orchestrator (prism-scale, prism-contention,
                         prism-pcpu, prism-scx, prism-sys, low-cpu-deadline)
  prism-fork-thread.py Fork/thread IPC benchmark (full scx field) + hw counters + non-compensatory regression gate
  prism-power.py       Energy-efficiency benchmark (RAPL J/op + idle floor)
  prism.py     One-command shareable report (montauk digest: specs + ranked offenders + metrics, redacted)
  gate.rs              Integration test gate (load/classify/latency/responsiveness/contention)
include/
  scx/                 Vendored sched_ext headers
```

### Data Flow

```
BPF per-CPU histograms              Monitor Thread (1s loop)
(wake_lat_hist, sleep_hist)  --->   Read + drain histograms
                                    Compute P99 per tier
                                      |
                                      v
                                    per-CPU stats array -> live load graph
                                      -> scaled_regime_knobs() -> base profile
                                      -> derive each knob from its own sensor
                                        (depth -> slice, slowing -> preempt,
                                         shape -> batch/burst, persist -> rescue)
                                      -> quiescence freeze
                                      |
                                      v
                                    BPF reads knobs on next dispatch

Resistance affinity: R_eff ranked map -> BPF select_cpu (is_handoff_partner-gated)
L2 placement:        affinity_mode knob -> BPF enqueue (base value)
Migration potential: R_eff cost oracle + phi_dist_scale_q16 -> BPF dispatch STEP 1 steal resist
Sojourn threshold:   codel_thresh_ns knob -> BPF dispatch (core-count-scaled, codel_eq-floored)
Stall detection:     codel_target_ns (BPF-internal, damped oscillation, no Rust input)
Cross-cache domain scatter:   nr_cross_domain path counters -> telemetry (no actuation)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. Stall detection is fully BPF-internal — the damped oscillation runs in tick() on CPU 0 with no Rust involvement.

### Tuning Knobs (BPF map)

| Knob | Default | Owner | Purpose |
|------|---------|-------|---------|
| `slice_ns` | 1ms | Derived (depth) | Interactive slice ceiling |
| `preempt_thresh_ns` | 1ms | Derived (critical slowing) | Tick preemption threshold |
| `batch_slice_ns` | 20ms | Derived (traffic shape) | Batch slice ceiling, itself capped at `SLICE_STANDING_TARGETS × codel_target_ns` in BPF |
| `burst_slice_ns` | 1ms | Derived (traffic shape) | Slice during longrun mode |
| `affinity_mode` | 0 | Base value | L2 placement (0=OFF, 1=WEAK, 2=STRONG) |
| `codel_thresh_ns` | 5ms | Derived (persistence) | Batch DSQ rescue threshold (tau-scaled) |
| `topology_tau_ns` | 0 | Topology | Fiedler-derived time constant (τ = TAU_SCALE / λ₂) |
| `codel_eq_ns` | 0 | Topology | R_eff-derived CoDel equilibrium (`⟨R_eff⟩ × 2m × τ`) |
| `phi_dist_scale_q16` | 0 | Topology | Φ distance→wait scale (Q16): cross-domain steal resist `R_eff × this >> 16`; 0 = flat CoDel target (monolithic / single domain) |

Topology-owned fields are written by Rust at topology detect and on hotplug; the adaptive loop preserves them on every write, since the 1Hz cycle would otherwise clobber the equilibrium. The knob map is per-CPU, so each CPU reads its own slot — but `topology_tau_ns`, `codel_eq_ns`, `spill_temp_q16` and `affinity_mode` must hold the same value everywhere or tau-scaling diverges by whichever CPU last observed it, and the Rust writer broadcasts those from slot 0 by construction.

## Requirements

- Linux kernel 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`
- Rust toolchain
- clang (BPF compilation)
- system libbpf
- bpftool (first build only — generates vmlinux.h, can be uninstalled after)
- Root privileges (`CAP_SYS_ADMIN`)

```bash
# Arch Linux
pacman -S clang libbpf bpf rust
```

## Build & Install

```bash
# Build manager (recommended)
./pandemonium.py rebuild        # Force clean rebuild
./pandemonium.py install        # Build + install to /usr/local/bin + systemd service file
./pandemonium.py status         # Show build/install status
./pandemonium.py clean          # Wipe build artifacts

# Manual
CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build cargo build --release
```

vmlinux.h is generated from the running kernel's BTF via bpftool on first build and cached at `~/.cache/pandemonium/vmlinux.h`. The cargo target tree lives at `~/.cache/pandemonium-build` (alongside the log and vmlinux caches under `~/.cache/pandemonium`), so all per-user pandemonium state sits in one place. The `CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build` override is also what lets the vendored libbpf Makefile build cleanly when the source tree path contains spaces.

After install:

```bash
sudo systemctl start pandemonium          # Start now
sudo systemctl enable pandemonium         # Start on boot
```

## Usage

```bash
sudo scx_pandemonium                  # Default: adaptive mode
sudo scx_pandemonium --no-adaptive    # BPF-only (no Rust control loop)
sudo scx_pandemonium -v               # Verbose telemetry on stdout
```

There is no compositor allowlist and no learned name database, and there is no
behavioural tier to earn: A task is INTERACTIVE because the kernel flags it a workqueue
worker, and BATCH otherwise. Every session, from cold, with nothing remembered.

### Monitoring

Per-second telemetry:

```
BPF-only (--no-adaptive):
d/s: 4537 idle: 49% shared: 34 preempt: 0 keep: 0 kick: H=34 S=0 enq: W=26 R=8 wake: 8us lat_idle: 8us lat_kick: 9us reenq: 0 sjrn: 0ms l2: B=98% I=28% [BPF]

Adaptive (default) adds the control loop's own readings:
... p99: 10us [B:8 I:9 L:0] ... sleep: io=87% slice: 1000us batch: 20000us sjrn: 3ms/5ms rescue: 0 chaos: lam=2.10 H=0.40 det=0.95 x=0 frozen: 0 (n=12) retune_iv: 2 [MIXED] graph: n=12 e=31 cpl=0.41/0.02/0.88 osc: 1.04/1300us
```

| Counter | Meaning |
|---------|---------|
| d/s | Total dispatches per second |
| idle | select_cpu idle fast path (%) |
| shared | Enqueue -> per-node DSQ |
| preempt | Tick preemptions |
| keep | KEEP_RUNNING re-slices |
| kick H/S | Hard (PREEMPT) / Soft kicks |
| enq W/R | Wakeup / Re-enqueue counts |
| wake / p99 | Average / aggregate P99 wakeup latency |
| [B/I/L] | Per-tier P99. `L` is a retired third lane and reads 0 always — `tier` is two values |
| lat_idle / lat_kick | Wakeup latency split: idle-placement vs kick path |
| sleep: io | I/O-wait sleep pattern (%) |
| slice / batch | Current interactive / batch slice knob (us) |
| reenq | Re-enqueue count |
| sjrn | Batch sojourn: current / threshold |
| rescue | Overflow rescue dispatches this tick |
| l2: B/I/L | L2 cache hit rate per tier |
| chaos: lam/H/det/x | HVG mean degree λ / Bandt-Pompe entropy / RQA determinism / chaos-crossing counter |
| frozen (n) | Quiescence freeze active (1/0) and cumulative frozen ticks |
| retune_iv | Adaptive-rarity retune interval (ticks between retunes) |
| [REGIME] | Base profile label + LONGRUN flag |

## Benchmarking

One entry point. Bare `prism` is the end-user report; `--dev <name>` runs the sustained
validations behind it.

```bash
./pandemonium.py prism                   # One-command shareable report (specs + ranked misbehaving items + metrics)
./pandemonium.py prism --list            # List every workload (default profile + dev tier)
./pandemonium.py prism --schedulers scx_rusty,scx_lavd  # Compare EEVDF against the named scx schedulers (add 'pandemonium' to the list to include the PANDEMONIUM arms)
./pandemonium.py prism --all-scx         # Add the full installed scx field instead (mutually exclusive with --schedulers)
./pandemonium.py prism --workload "ffmpeg -i in.mkv out.mp4"   # Trace YOUR isolated workload instead of the fixed profile
./pandemonium.py prism --attach chrome --duration 30           # Trace an already-running program for 30s
./pandemonium.py prism-sys               # Live system telemetry capture (Ctrl+C to stop)
```

The dev tier — one or more names, or `all` for the full sweep:

```bash
./pandemonium.py prism --dev scale                    # Width sweep: throughput, latency, burst, longrun, mixed, deadline, IPC, launch
./pandemonium.py prism --dev ipc                      # IPC round-trip by primitive (pipe, socket, eventfd, sem, fanout)
./pandemonium.py prism --dev fork-thread              # Fork/thread IPC + hardware counters + regression gate
./pandemonium.py prism --dev power                    # Energy efficiency (RAPL J/op + idle floor)
./pandemonium.py prism --dev locality                 # Cache-locality of migrations (same-L2/L3/socket tiers)
./pandemonium.py prism --dev strand                   # Per-CPU kthread strand detection
./pandemonium.py prism --dev cold-wake                # Cold wakeup latency
./pandemonium.py prism --dev storm                    # Kick/reenqueue storm
./pandemonium.py prism --dev pcpu                     # Per-CPU DSQ correctness
./pandemonium.py prism --dev contention               # Contention stress (6 phases)
./pandemonium.py prism --dev cachyos                  # CachyOS Mini-Benchmarker application suite
./pandemonium.py prism --dev scx                      # sched-ext/scx CI compatibility
./pandemonium.py prism --dev scale ipc power          # Several in one run
./pandemonium.py prism --dev all                      # The full sweep
```

Four flags apply uniformly to every dev workload — each implementer accepts all four,
as a real behavior where it has one and as a documented no-op where it does not:

```bash
--iterations N        # Repeat for a per-run report, to see past per-run noise
--pandemonium-only    # Skip the EEVDF baseline and any external schedulers
--trace               # Force a montauk capture (trace-capable workloads capture anyway)
--ultra               # Sweep the width-specific faults at EVERY core width, not just native
```

`--dev scale` sweeps core counts via CPU hotplug (2, 4, 8, ..., max); the rest run at
native width unless `--ultra` is given. Reports and `.prom` archive to
`~/.cache/pandemonium/`; montauk captures land in `/tmp/pandemonium/`. A run that
captures self-elevates, so invoke it without `sudo`.

`prism` is the one command a user runs to send a report. It runs a short
fixed profile — the cachyos application workloads, a fork/exec storm, an IPC
round-trip and capped (20s) burst-starvation and contention captures — under
your scheduler and EEVDF as a neutral reference, traces each with montauk, and
assembles one small, redacted file: Your system specs, the misbehaving items
ranked by name (hot CPUs, livelocking tasks, unsignaled waiters, idle strands),
a thermal/power block, then the key wake-to-run metrics. Process names are
hashed and the raw traces stay local — you share only the report. montauk is the
only data source; the script orchestrates and assembles, nothing more.

If montauk isn't installed, prism clones it from its repo and drives
montauk's own installer: Two prompts up front decide whether it installs montauk
permanently (capped so `--trace` needs no sudo) or builds it just for the run and
removes it after. It self-elevates for the trace, ejects any scheduler it loaded
if you Ctrl+C, and when a build dependency is missing it prints the exact install
command for your distro (CachyOS, Arch, Gentoo, OpenSUSE, Ubuntu, NixOS). Share
the resulting `prism-report-*.txt`.

If you have already isolated the problem to one program, skip the fixed profile
and capture that program directly: `--workload "<command>"` launches your
command under the loaded scheduler and traces it until it exits (or `--duration`
seconds), while `--attach <comm> --duration <s>` traces an already-running
program by name. Same report, same redaction — captured on your real workload
rather than the synthetic profile.

## Testing

```bash
CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build cargo test --release   # Unit tests (no root)
sudo CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build \
     cargo test --release --test gate -- --ignored \
     --test-threads=1 full_gate                                 # Integration gate (requires root)
```

5 tests in 1 file: The integration gate at `tests/gate.rs` — `full_gate` plus the
load/classify, latency, responsiveness and contention layers (all `#[ignore]`,
root-only). The `src/*.rs` modules carry no inline unit tests; the pure-Rust logic
(chaos, tuning, topology) is validated offline through the bench harnesses.

## sched-ext/scx Integration

PANDEMONIUM is included in the sched-ext/scx monorepo. `export_scx.py` automates the import:

```bash
./export_scx.py /path/to/scx
```

Copies source into `scheds/rust/scx_pandemonium/`, renames the crate, replaces `build.rs` with `scx_cargo::BpfBuilder`, swaps `libbpf-cargo` for `scx_cargo`, registers the workspace member and runs `cargo fmt`.

## Attribution

- `include/scx/*` headers from the [sched_ext](https://github.com/sched-ext/scx) project (GPL-2.0)
- vmlinux.h generated from the running kernel's BTF
- Included in the [sched-ext/scx](https://github.com/sched-ext/scx) project

## References

[1] D.J. Klein, M. Randic. "Resistance Distance." *Journal of Mathematical Chemistry* 12, 81-95, 1993. [doi:10.1007/BF01164627](https://link.springer.com/article/10.1007/BF01164627)

[2] A.K. Chandra, P. Raghavan, W.L. Ruzzo, R. Smolensky, P. Tiwari. "The Electrical Resistance of a Graph Captures its Commute and Cover Times." *STOC 1989*, 574-586. Journal version: *Computational Complexity* 6, 312-340, 1996. [doi:10.1007/BF01270385](https://link.springer.com/article/10.1007/BF01270385)

[3] P. Christiano, J.A. Kelner, A. Madry, D.A. Spielman, S.-H. Teng. "Electrical Flows, Laplacian Systems, and Faster Approximation of Maximum Flow in Undirected Graphs." *STOC 2011*, 273-282. [arXiv:1010.2921](https://arxiv.org/abs/1010.2921)

[4] L. Chen, R. Kyng, Y.P. Liu, R. Peng, M.P. Gutenberg, S. Sachdeva. "Maximum Flow and Minimum-Cost Flow in Almost-Linear Time." *FOCS 2022*. Journal version: *Journal of the ACM* 72(3), 2025. [arXiv:2203.00671](https://arxiv.org/abs/2203.00671)

[5] K. Nichols, V. Jacobson. "Controlling Queue Delay." *ACM Queue* 10(5), 2012. [doi:10.1145/2208917.2209336](https://queue.acm.org/detail.cfm?id=2209336)

[6] K. Nichols, V. Jacobson. "Controlled Delay Active Queue Management." *RFC 8289*, January 2018. [rfc-editor.org/rfc/rfc8289](https://www.rfc-editor.org/rfc/rfc8289.html)

[7] M. Shreedhar, G. Varghese. "Efficient Fair Queuing Using Deficit Round Robin." *ACM SIGCOMM 1995*, 231-242. [doi:10.1145/217382.217453](https://dl.acm.org/doi/10.1145/217382.217453)


[9] J.D. Valois. "Lock-Free Linked Lists Using Compare-and-Swap." *PODC 1995*, 214-222. [doi:10.1145/224964.224988](https://dl.acm.org/doi/10.1145/224964.224988)

[10] M. Fiedler. "Algebraic Connectivity of Graphs." *Czechoslovak Mathematical Journal* 23(2), 298-305, 1973. [doi:10.21136/CMJ.1973.101168](https://dml.cz/dmlcz/101168)

[11] R.D. Blumofe, C.E. Leiserson. "Scheduling Multithreaded Computations by Work Stealing." *Journal of the ACM* 46(5), 720-748, 1999. [doi:10.1145/324133.324234](https://dl.acm.org/doi/10.1145/324133.324234)

[12] C. Bandt, B. Pompe. "Permutation Entropy: A Natural Complexity Measure for Time Series." *Physical Review Letters* 88(17), 174102, 2002. [doi:10.1103/PhysRevLett.88.174102](https://doi.org/10.1103/PhysRevLett.88.174102)

[13] B. Luque, L. Lacasa, F. Ballesteros, J. Luque. "Horizontal Visibility Graphs: Exact Results for Random Time Series." *Physical Review E* 80(4), 046103, 2009. [doi:10.1103/PhysRevE.80.046103](https://doi.org/10.1103/PhysRevE.80.046103)

[14] N. Marwan, M.C. Romano, M. Thiel, J. Kurths. "Recurrence Plots for the Analysis of Complex Systems." *Physics Reports* 438(5-6), 237-329, 2007. [doi:10.1016/j.physrep.2006.11.001](https://doi.org/10.1016/j.physrep.2006.11.001)

[15] S. Butterworth. "On the Theory of Filter Amplifiers." *Experimental Wireless and the Wireless Engineer* 7, 536-541, 1930.

## License

GPL-2.0
