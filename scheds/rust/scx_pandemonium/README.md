# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C23. PANDEMONIUM classifies every task by behavior — wakeup frequency, context switch rate, runtime, sleep patterns — and adapts scheduling decisions in real time. A critically-damped harmonic oscillator drives CoDel-inspired stall detection with the literal RFC 8289 sojourn metric and an R_eff-derived equilibrium reference. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. Multiplicative Weight Updates (MWU) balance six competing expert profiles across four loss pathways.

Three-tier behavioral dispatch, overflow sojourn rescue, longrun detection, tier-aware preempt scaling, sleep-informed batch tuning, classification-gated DSQ routing, workload regime detection, vtime ceiling with new-task lag penalty, hard starvation rescue, and a persistent process database that learns task classifications across lifetimes.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos, scx_cake and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE, Arch and Ubuntu communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs, kernel 6.18+, clang 21. The tables below report v5.8.0 PANDEMONIUM numbers from a single-iteration bench-scale run across 2C/4C/8C/12C; the v5.9.0 deltas at 12C are summarized in the next subsection. EEVDF and scx_bpfland baselines are best-3-of-N historical (28 and 26 complete runs across 75 bench-scale sessions) — those baselines don't drift across PANDEMONIUM versions. v5.8.0 closed the 2C structural starvation class via the rescue-fairness fix and the missing CPU-bound demotion in stopping() that was leaving long-runners stuck at TIER_INTERACTIVE (longrun WORST 19s -> 13ms at 2C, mixed WORST 29s -> 16ms at 2C). Bench-fork-thread lands within 1% of EEVDF and ~40% ahead of scx_bpfland.

### v5.9.0 Deltas (12C, single iteration vs v5.8.0 24-run mean)

| Metric            | v5.8.0 mean | v5.9.0     | Delta              |
|-------------------|-------------|------------|--------------------|
| Burst P99         | 392us       | **83us**   | -4.7x              |
| Longrun P99       | 489us       | **244us**  | -2.0x              |
| Mixed P99         | 724us       | **139us**  | -5.2x              |
| IPC P99           | 107us       | **36us**   | -3.0x              |
| Deadline miss     | 3.56%       | **0.1%**   | -35x               |
| Schbench P99      | 75us        | 77us       | hold               |
| App launch P99    | 2,983us     | 4,692us    | regression (n=1)   |

Architectural changes in v5.9.0 (affinity threading through the R_eff spill chain, `MAX_AFFINITY_CANDIDATES = MAX_CPUS >> 3` topology coverage, slice-relative INTERACTIVE→BATCH demotion, tier-priority tick preempt) address structural classes that did not show on the v5.8.0 12C single-iteration cells. The 32C affinity-stranding class closure was confirmed by a 3.5+ hour real-workload run on Threadripper (game + KVM + libvirt, no watchdog kills, no stalls); multi-iteration sweeps across 2C/4C/8C/12C are pending. The app-launch regression is single-iteration and likely under-sampled — to be retested under multi-run aggregation.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,058us  | 2,004us     | **87us**          | 93us                   |
| 4     | 1,246us  | 2,003us     | **65us**          | 68us                   |
| 8     | 425us    | 2,003us     | **66us**          | 68us                   |
| 12    | 344us    | 2,002us     | **68us**          | 70us                   |

Sub-95us in both modes at every core count.

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,262us  | 2,006us     | 189us             | **69us**               |
| 4     | 3,223us  | 2,003us     | 687us             | **207us**              |
| 8     | 2,331us  | 2,004us     | 611us             | **93us**               |
| 12    | 1,891us  | 2,001us     | **79us**          | 196us                  |

Both modes beat EEVDF and scx_bpfland by a wide margin. Burst-storm cost is workload-sensitive across iterations.

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,293us  | 2,000us     | 2,327us           | **559us**              |
| 4     | 1,421us  | 2,003us     | 870us             | **68us**               |
| 8     | **60us** | 2,003us     | **439us**         | 655us                  |
| 12    | 126us    | 2,002us     | 674us             | **80us**               |

ADAPTIVE 4C/12C sub-100us — the CPU-bound demotion fix in stopping() finally lets INTERACTIVE long-runners reclassify to BATCH so tick() can preempt them on prober wakeups. WORST tails bounded: longrun WORST 13ms at 2C (vs 19s pre-v5.8.0).

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,412us  | 2,000us     | 1,993us           | **876us**              |
| 4     | 1,683us  | 2,003us     | 217us             | **72us**               |
| 8     | 348us    | 2,003us     | 572us             | **326us**              |
| 12    | 494us    | 2,002us     | 644us             | **81us**               |

ADAPTIVE under EEVDF at every core count, sub-100us at 4C and 12C. Mixed WORST 16ms at 2C (vs 29s pre-v5.8.0); deadline miss collapsed to ≤0.1% in every ADAPTIVE cell (table below).

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF   | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|---------|-------------|-------------------|------------------------|
| 2     | 13.1%   | 69.4%       | 0.2%              | **0.1%**               |
| 4     | 8.6%    | 60.4%       | 0.1%              | **0.0%**               |
| 8     | 10.8%   | 53.8%       | 0.1%              | **0.0%**               |
| 12    | 10.4%   | 54.7%       | 0.1%              | **0.0%**               |

Sub-1% at every core count, 0.0% in every ADAPTIVE cell at 4C and above. v5.7.0's 4C bimodal pattern (0.2%–20% across runs) is gone.

### Burst Recovery P99 (latency after storm subsides)

| Cores | PANDEMONIUM (bench-contention burst-recovery phase) |
|-------|------------------------------------------------------|
| 2     | burst 65us / recovery 62us                          |
| 4     | burst 73us / recovery 73us                          |
| 8     | burst 76us / recovery 76us                          |
| 12    | burst 77us / recovery 76us                          |

Sub-80us recovery at every core count.

### App Launch P99

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | **2,899us**| 2,194us   | 12,601us          | 3,595us                |
| 4     | 4,058us  | **2,199us** | 4,516us           | 2,722us                |
| 8     | 4,092us  | **1,723us** | 2,700us           | 4,405us                |
| 12    | 3,552us  | **1,520us** | 6,177us           | 2,994us                |

scx_bpfland keeps the dense-end edge here. ADAPTIVE app-launch dropped substantially across all core counts after the CPU-bound demotion fix removed long-runner head-of-queue contention.

### IPC Round-Trip P99

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | **12us** | 18us        | 751us             | 4,240us                |
| 4     | 118us    | 23us        | 3,952us           | **58us**               |
| 8     | **23us** | 71us        | 109us             | **68us**               |
| 12    | **15us** | 57us        | 32us              | **25us**               |

12C ADAPTIVE within 10us of EEVDF. 2C and BPF 4C still show the pipe-partner placement tail at saturation — the resistance-affinity gap on thin topologies where R_eff peer counts are limited.

### Fork/Thread IPC (`perf bench sched messaging`, 12C, v5.8.0)

| Scheduler | Time | vs EEVDF | Cache Misses | IPC |
|-----------|------|----------|--------------|-----|
| EEVDF                    | 16.38s | baseline  | 29M  | 0.44 |
| PANDEMONIUM (BPF)        | 16.51s | +0.8%     | 35M  | 0.44 |
| PANDEMONIUM (ADAPTIVE)   | 16.53s | +0.9%     | 33M  | 0.45 |
| scx_bpfland              | 23.04s | +40.6%    | 57M  | 0.42 |

BPF and ADAPTIVE land within 0.1% of each other and ~40% ahead of scx_bpfland. ADAPTIVE actually edges out EEVDF on IPC (0.45 vs 0.44) despite the slightly longer wall-time, reflecting the cache-locality benefit from resistance affinity.

### Energy Efficiency (`bench-power`, 12C, v5.9.0)

5 runs per cell, 30s cooldown. Package energy via `perf stat -a -e power/energy-pkg/`. Zen 2 exposes only `J_pkg` (no per-core or per-DRAM RAPL).

**Idle floor** (30s `sleep`, scheduler restlessness):

| Scheduler                | J_pkg   | Avg W    | vs EEVDF |
|--------------------------|---------|----------|----------|
| EEVDF                    | **693.37J** | **23.09W** | baseline |
| scx_lavd                 | 708.18J | 23.58W   | +2.1%    |
| scx_bpfland              | 708.77J | 23.60W   | +2.2%    |
| PANDEMONIUM (BPF)        | 718.19J | 23.92W   | +3.6%    |
| PANDEMONIUM (ADAPTIVE)   | 741.37J | 24.69W   | +6.9%    |

ADAPTIVE's +6.9% is the Rust 1Hz monitoring loop's package-power tax. BPF's +3.6% is the dispatch path firing more on idle than the kernel default.

**Messaging** (`perf bench sched messaging -t -g 24 -l 6000`, fork-storm + IPC):

| Scheduler                | Wall_s     | J_pkg     | J/msg      | vs EEVDF |
|--------------------------|------------|-----------|------------|----------|
| EEVDF                    | **15.67s** | **975.38J** | **169.34uJ** | baseline |
| PANDEMONIUM (BPF)        | 16.13s     | 984.75J   | 170.96uJ   | +1.0%    |
| PANDEMONIUM (ADAPTIVE)   | 16.10s     | 985.21J   | 171.04uJ   | +1.0%    |
| scx_bpfland              | 21.23s     | 1275.33J  | 221.41uJ   | +30.8%   |
| scx_lavd                 | 25.85s     | 1617.79J  | 280.87uJ   | +65.9%   |

Within 1% of EEVDF on J/msg under load.

## Key Features

### Dispatch Waterfall

Layered dispatch with per-CPU DSQ dominance and one age-driven safety mechanism. CPU-tied placement (Tier 2 wakeup preemption, `select_cpu`) is bounded at the enqueue site by `pcpu_depth_base` and overflow spills to a sibling per-CPU DSQ in R_eff order (`find_pcpu_with_room` → `pick_pcpu_dsq_with_spill`), so the dispatch waterfall reaches every CPU-tied enqueue at step 0 (sibling owns) or step 1 (R_eff steal). Idle-CPU placement (Tier 1) inserts directly into `node_dsq` and is picked up by step 3 within one dispatch cycle — eager R_eff search at this site was a wire-speed regression on fork-storm workloads with no measurable placement benefit. v5.8.0 collapsed the v5.7.0 14-decision-point waterfall into 6 steps + 1 safety net by removing redundant rescue paths (deficit-gate-with-exception, DRR deficit counter, batch sojourn rescue) that all reduced to "service the older overflow side past a threshold." `sojourn_gate_pass` was kept at STEP 0 / STEP 1 — bench evidence proved it load-bearing for workqueue-worker fairness under sustained per-CPU load (without it, `scx_watchdog_workfn` strands in node_dsq long enough to trigger 30s watchdog kills).

0. **Own per-CPU DSQ** — cache-hot, zero contention. Sojourn-gated return: if either overflow side has aged past `overflow_sojourn_rescue_ns`, fall through to STEP 2 so this dispatch serves overflow too.
1. **R_eff steal** — single loop over `affinity_rank` (slot 0 = L2 sibling, slots 1+ = R_eff-ranked cross-L2 peers). Budget is tau-derived: `pcpu_spill_search_budget = K_SPILL_BUDGET / tau ≈ λ₂/2`, clamped to `[6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]`. The companion WAKE_SYNC idle-search budget `affinity_search_online = K_AFFINITY_SEARCH / tau ≈ λ₂/4` clamps the same way (smaller divisor because the predicate is more expensive). `MAX_AFFINITY_CANDIDATES = MAX_CPUS >> 3` (= 128 at the current MAX_CPUS=1024) is the verifier-safe compile-time ceiling; the runtime ceiling tracks actual topology via `nr_cpu_ids - 1`. Wider graphs get more coverage: 12C → 6/3, 32C → 16/8, 128C+ → 128/64. Subsumes the v5.7.0 STEP 1 (L2 walk) and STEP 1b (R_eff fallback) since `affinity_rank` is authoritative for placement distance. Same sojourn gate as STEP 0 on success.
1. *Safety net.* **Hard starvation rescue** — `try_service_older_overflow(starvation_rescue_ns)`: drains whichever of `interactive_enqueue_ns` / `batch_enqueue_ns` is older past the tau-scaled hard cap. Fires before STEP 2 so it cannot be gated. Should ~never fire post-placement-fix.
2. **Service older overflow side** — `try_service_older_overflow(overflow_sojourn_rescue_ns)`: same pick-the-older comparison at the ~10ms threshold. Feeds the CoDel oscillator (`global_rescue_count++`). Replaces the v5.7.0 interactive-overflow-amplification + batch-overflow-rescue + deficit-gate-with-exception + DRR cluster.
3. **Node interactive overflow** — unconditional `node_dsq` drain (LAT_CRITICAL + INTERACTIVE, vtime-ordered).
4. **Node batch overflow** — unconditional `batch_dsq` drain.
5. **Cross-node steal** — interactive + batch per remote node.
6. **KEEP_RUNNING** — if prev still wants CPU and nothing queued.

### Three-Tier Enqueue

- **select_cpu**: idle CPU -> per-CPU DSQ (depth-gated: 1 slot at <4C, 2 at 4C+) -> R_eff sibling spill if full -> last-resort node DSQ. KICK_IDLE on the actual placement target. WAKE_SYNC path: wakee_flips gate -> R_eff idle search -> waker fallback (both run through the same depth-gated placement helper)
- **enqueue Tier 1** (idle CPU): direct `node_dsq` insert + KICK_PREEMPT. Drained by STEP 3 (unconditional `node_dsq`) within one dispatch cycle. v5.6.0's wire-speed path — restored after v5.8.0's eager R_eff search proved a fork-storm regression with no placement benefit
- **enqueue Tier 2** (wakeup preemption): uses `pick_pcpu_dsq_with_spill` for symmetric placement with `select_cpu`. CPU-tied; benefits from eager per-CPU placement
- **enqueue Tier 3** (fallback): node_dsq for INTERACTIVE, batch overflow DSQ for BATCH and immature INTERACTIVE. Vtime ceiling applied here
- **tick**: longrun detection (batch non-empty >2s), sojourn enforcement, preempt batch for waiting interactive (tier-aware threshold — tightened 4× when a LAT_CRITICAL waiter is in flight, extended 4× at 2C during longrun to protect BATCH long-runners)

### Damped Harmonic Oscillator Stall Detection

CoDel-inspired per-CPU DSQ stall detection where the target follows the full damped harmonic oscillator equation:

```
ẍ + 2γẋ + ω₀²(x − c_eq) = F(t)
```

with `γ = ω₀` for critical damping (no overshoot, fastest stable return). v5.8.0 added the missing ω₀² spring term last present in v3.0.0 and the literal RFC 8289 sojourn metric replacing the empty-cycle proxy.

**Per-task sojourn** (RFC 8289): `task_ctx.enqueue_at` is set at every `scx_bpf_dsq_insert_vtime` call site (six placement paths) and consumed in `pandemonium_running` to compute `sojourn = now − enqueue_at`. This is the literal CoDel metric — wait between enqueue and run start — feeding `pcpu_min_sojourn_ns`. Replaces the v5.7.0 proxy `now − pcpu_enqueue_ns[cpu]` which weakened past the first task in any drain and became meaningless under vtime ordering.

**Stall decision** (`pcpu_dsq_is_stalled`): compares per-CPU minimum sojourn against `codel_target_ns`. Below = flowing. Above for `sojourn_interval_ns` = stalled, force rescue. Binary CoDel decision; the target itself is what oscillates.

**Spring (restoring term)**: equilibrium `c_eq = ⟨R_eff⟩ × 2m × τ` derived from spectral graph properties already computed at topology detect — `⟨R_eff⟩ = Tr(L⁺)/N` over nonzero eigenvalues, `2m = Tr(L)`, τ the Fiedler-derived mixing time. The product is the natural latency tolerance of the topology. Rust clamps `c_eq` to `[200µs, 8ms]`; BPF additionally constrains it inside the oscillator's `[floor, max]` window.

**Critical damping** (discrete): the existing `v −= v >> damping_shift` corresponds to `2γ ≈ 2^−D` so `γ ≈ 2^−(D+1)`. Setting `γ = ω₀` gives `ω₀² ≈ 2^−(2D+2)`, implemented as `disp >> spring_shift` with `spring_shift = 2*damping_shift + 2`. Co-derived in `apply_tau_scaling` so topology changes keep critical damping automatically.

**Feedback loop**: `global_rescue_count` (atomic, incremented at the overflow rescue site in dispatch) drives the impulse `F(t)`. Each tick on CPU 0: apply impulse → apply spring (`v −= disp >> spring_shift`) → apply damping (`v −= v >> damping_shift`) → cap velocity → integrate `x`. v5.8.0 removed the v5.7.0 `OSCILLATOR_RELAX_NS` quiet-tick drift toward the ceiling, which had been a primitive substitute for the spring and pushed `x` AWAY from `c_eq` every quiet tick.

**Core-scaled parameters** (derived from τ in `apply_tau_scaling`):

| Parameter | 2C (τ≈2ms) | 4C | 8C | 12C (τ≈40ms) |
|-----------|------------|----|-----|---------------|
| Sojourn interval | 2ms | 4ms | 8ms | 12ms |
| Damping shift D | 1 (v/2) | 1-2 | 3 | 5 (v/32) |
| Spring shift (2D+2) | 4 (disp/16) | 4-6 | 8 | 12 (disp/4096) |
| Pull scale | 1 | 1 | 3 | 4 |
| Center floor | 200µs | 200µs | 500µs | 700µs |
| Center ceiling | 1ms | 1ms | 1ms | 2ms |

`x` rests at `c_eq` when the system is quiet, descends below on rescue events, returns critically-damped (one excursion, no ringing).

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes downstream anti-starvation unreachable — 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch STEP 0 / STEP 1 fall through to STEP 2 when either overflow DSQ has aged past `overflow_sojourn_rescue_ns` (tau-scaled, ~10ms at 12C). `try_service_older_overflow` then drains the older side past the threshold. CAS-based timestamp management prevents races across CPUs.

**Drain-both-when-both-aged** (v5.8.0): under sustained mixed load both overflow DSQs can stay continuously non-empty for tens of seconds, freezing both timestamps at their first-non-empty values. The historical "older wins" picked the same side every rescue call until external pressure dropped, locking out batch-demoted long-runners. At 2C this produced 19-29s starvation tails; 4C+ was unaffected because higher dispatch density closed the window. The fix: when BOTH sides are aged, drain BOTH. Older-first ordering preserved (latency-budget bias for interactive on ties); the second drain costs one extra `scx_bpf_dsq_move_to_local`. Result: 2C longrun WORST 19s -> 166ms, mixed WORST 29s -> 170ms.

### Longrun Detection

When batch DSQ stays non-empty past `longrun_thresh_ns` (tau-scaled, ~2s at 12C reference), `longrun_mode` activates. Two consumers: `task_slice` substitutes `burst_slice_ns` for `slice_ns` on INTERACTIVE/LATCRIT (1ms tighter cap, yields CPU faster under pressure); `tick` scales the preempt threshold via `longrun_preempt_shift` — 4× at 2C (extends BATCH's protected window) so thin topologies don't thrash, no scaling at 4C+ where capacity already absorbs LAT_CRIT contention.

### Wake Sensitivity & Preemption

No burst detector. Prior versions layered three (CUSUM on enqueue-interval EWMA, `wake_burst` on absolute wakeup rate, and `burst_mode` gating slice/depth/preempt behaviors). All three have been retired: every failure mode they were covering is now handled by the oscillator-adapted CoDel target, the placement-side depth gate + L2/R_eff spill (v5.8.0 — closes the per-CPU DSQ reachability class STEP -1 was previously papering over), hard starvation rescue, or tier information already present at the enqueue site. The one load-bearing behavior burst_mode provided — aggressive preempt when a latency-critical waker sat behind a BATCH runner — is expressed as a tier signal:

- **`latcrit_waiting`**: set in `pandemonium_enqueue` when a `TIER_LAT_CRITICAL` task arrives at a shared-DSQ path; cleared in `task_should_preempt` after a BATCH preempt fires. `task_should_preempt` tightens its threshold by 4× when this flag is set (1ms baseline → 250µs, 4ms at 2C longrun → 1ms). INTERACTIVE waiters keep the standard threshold so ordinary wakeups don't penalize BATCH throughput. Uses `tctx->tier` which was already being read at both sites — no new detector state, no rate counter.
- **Core-scaled longrun protection**: during sustained `longrun_mode`, preempt threshold scales up on 2C only (4×, i.e. 4ms protected BATCH window from a 1ms base). 4C+ keeps the baseline: the additional CPU capacity already absorbs LAT_CRIT contention without slice extension.

### Vtime Ceiling + Lag Cap + New-Task Lag Penalty

`task_deadline()` caps every task's deadline at `vtime_now + vtime_ceiling_window_ns`, applied universally across every placement path (select_cpu sites, all enqueue tiers). The window is tau-scaled: `K_VTIME_CEILING × τ` clamped `[16ms, 160ms]` — 120ms at the 12C reference (τ=40ms), tightening naturally at lower τ. Hoisted from the v5.5.0 batch-only Tier 3 site in v5.8.0 because retired STEP -1 left daemons in per-CPU DSQs unprotected.

`lag_cap_ns = K_LAG_CAP × τ` clamped `[8ms, 80ms]` is the sleep-boost ceiling, used as `vtime_floor = vtime_now − lag_cap_ns × lag_scale` and as the BATCH per-tier `awake_cap`. Per-tier caps are fractions: `LAT_CRITICAL = lag_cap/2`, `INTERACTIVE = lag_cap × 3/4`, `BATCH = lag_cap`. At the 12C reference (lag_cap=40ms) these are 20/30/40ms, matching the pre-v5.8.0 hardcoded values; at 32C they tighten to 4/6/8ms in proportion to topology timing.

`enable()` lands new tasks at `dsq_vtime = vtime_now + vtime_ceiling_window_ns` rather than `vtime_now`. The ceiling alone bounds tail position but not ordering: a freshly-forked task at `vtime_now` is still at the HEAD ahead of capped daemons. The new-task penalty puts it FIFO with the daemons. EEVDF and other modern fair schedulers apply the equivalent lag for the same reason.

### Hard Starvation Rescue

`min(25ms * nr_cpus, 500ms / max(1, nr_cpus/4))`, clamped 20-500ms. Short at low core counts (2C = 50ms), peaks mid-range (8C = 200ms), short again at high counts (128C = 20ms).

### Topology-Aware Placement

**Resistance affinity**: The CPU topology is modeled as a weighted electrical network (L2 siblings = 10.0, same socket = 1.0, cross-socket = 0.3). The Laplacian pseudoinverse (Jacobi eigendecomposition, O(n^3), pure Rust) gives all-pairs migration costs accounting for every path through the graph, not just direct connections. `R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]` — a true metric satisfying the triangle inequality. Per-CPU ranked lists stored in a BPF map sized at `MAX_AFFINITY_CANDIDATES = MAX_CPUS >> 3` slots per CPU (= 128 at MAX_CPUS=1024); the runtime walk is bounded by `nr_cpu_ids - 1`, with `(u32)-1` sentinels marking unused slots so loops early-exit on small N.

**Online-budget search**: `find_idle_by_affinity()` walks the ranked list with an online-candidates budget, not a total-slots budget. The rank map is built once at init from the full topology; after hotplug, some top ranks may reference offline CPUs. Offline entries are skipped without charging budget, so the search cost on a fully-online system is identical to a raw limit of 3, while remaining robust to arbitrary hotplug asymmetry (12C → 8C, 32C → 4C, etc.).

**Single-loop R_eff steal**: dispatch STEP 1 walks `affinity_rank` once with a tau-derived runtime budget (`pcpu_spill_search_budget`, clamped to `[6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]`) — slot 0 is the L2 sibling, slots 1+ are R_eff-ranked cross-L2 peers. Subsumes the old STEP 1 (l2_siblings walk) and STEP 1b (R_eff fallback) since v5.6.0 made `affinity_rank` authoritative for placement distance. Solo-topology hotplug cases (all L2 partners offline) work without a separate fallback.

**wakee_flips gate**: `select_cpu()` reads waker/wakee `wakee_flips` from `task_struct`. Both below `nr_cpu_ids` = 1:1 pipe pair (affinity beneficial). Either above = 1:N server pattern (skip to normal path). Same discrimination as the kernel's `wake_wide()`.

**L2 cache affinity**: `find_idle_l2_sibling()` in enqueue finds idle CPUs in the same L2 domain (max 8 iterations). Per-regime knob (LIGHT=WEAK, MIXED=STRONG, HEAVY=WEAK). Longrun overrides to WEAK. Per-dispatch L2 hit/miss counters for BATCH, INTERACTIVE, LAT_CRITICAL tiers.

**Commute time interpretation**: R_eff is proportional to expected round-trip time for work between CPUs [2]. Minimizing R_eff between pipe partners minimizes cache line transfer cost [1][3][4].

### Behavioral Classification

- **Latency-Criticality Score**: `lat_cri = (wakeup_freq * csw_rate) / (avg_runtime + runtime_dev/2)`
- **Three Tiers**: LAT_CRITICAL (1.5x avg_runtime slices), INTERACTIVE (2x), BATCH (configurable ceiling)
- **EWMA Classification**: wakeup frequency, context switch rate, runtime variance drive scoring
- **CPU-Bound Demotion**: avg_runtime above `cpu_bound_thresh_ns` demotes INTERACTIVE to BATCH
- **Kworker Floor**: PF_WQ_WORKER floors at INTERACTIVE
- **High-Priority Kthread Override** (v5.8.0): `PF_KTHREAD` at `static_prio <= 110` (`task_nice <= -10`) forced to BATCH regardless of behavioral score. ZFS workers (`z_rd_int_*`, `arc_*`), kopia helpers, and similar storage kthreads no longer compete with userspace LAT_CRITICAL. The kworker floor wins for `PF_WQ_WORKER` (a `PF_KTHREAD` subset), so workqueue workers continue to be treated as latency-adjacent.
- **Compositor Boosting**: BPF hash map, default compositors always LAT_CRITICAL, user-extensible via `--compositor`

### Process Database (procdb)

BPF publishes mature task profiles (tier + avg_runtime) keyed by `comm[16]`. Rust tracks EWMA convergence stability, promotes to "confident", applies learned classifications on spawn. `enable()` warm-starts; `runnable()` EWMA validates and corrects. Persistent to `~/.cache/pandemonium/procdb.bin` (atomic write).

### Adaptive Control Loop

- **One Thread, Zero Mutexes**: 1-second control loop reads BPF histogram maps, computes P99, drives MWU
- **Workload Regime Detection**: LIGHT (idle >50%), MIXED (10-50%), HEAVY (<10%) with Schmitt hysteresis + 2-tick hold
- **MWU Orchestrator**: 6 experts (LATENCY, BALANCED, THROUGHPUT, IO_HEAVY, FORK_STORM, SATURATED) compete via multiplicative weight updates. 8 continuous knobs blended via scale factors, 2 discrete knobs via majority vote. 4 loss pathways: P99 spike (Schmitt-gated, 2-tick confirm), rescue delta (0->nonzero, penalizes LATENCY at 0.4x to prevent compounding with oscillation tightening), IO bucket transition, fork storm (Schmitt-gated + pressure-confirmed: requires concurrent `rescue_count > 0` so a high raw wakeup rate alone cannot trip it; v5.8.0 scales loss magnitudes by wakeup-rate overage and drops the LATENCY-expert penalty so the FORK_STORM expert actually compresses BPF-consumed knobs (`burst_slice_ns`, `preempt_thresh_ns`, `sojourn_thresh_ns`, `batch_slice_ns`) instead of pushing values BPF cannot honor). ETA=8.0, weight floor 1e-6, relaxation at 80% toward equilibrium after 2 healthy ticks below 70% ceiling

### Core-Count Scaling

All timing constants scale from `tau_ns = TAU_SCALE_NS / λ₂` (Fiedler-derived mixing time), with safety-rail clamps. Cardinality decisions (per-CPU DSQ depth, wake_wide threshold, tick scan budget) use `nr_cpus` directly — counts are not tau-derived.

| Parameter | Formula | 2C (τ≈2ms) | 4C | 8C | 12C (τ≈40ms) | 32C (τ≈5ms) |
|-----------|---------|------------|----|----|----|----|
| Sojourn interval | `clamp(K × τ, 2ms, 12ms)` | 2ms | 4ms | 8ms | 12ms | 5ms |
| Overflow rescue | `clamp(K × τ, 4ms, 10ms)` | 4ms | 8ms | 10ms | 10ms | 4ms |
| Starvation rescue | `clamp(K × τ, 20ms, 500ms)` | 20ms | 80ms | 160ms | 166ms | 21ms |
| CoDel target floor | `clamp(K × τ, 200µs, 800µs)` | 200µs | 200µs | 500µs | 700µs | 200µs |
| CoDel target max | `clamp(K × τ, 1ms, 8ms)` | 1ms | 1ms | 1ms | 2ms | 1ms |
| CoDel equilibrium | `clamp(⟨R_eff⟩ × 2m × τ, 200µs, 8ms)` | varies | varies | varies | varies | varies |
| vtime ceiling | `clamp(K × τ, 16ms, 160ms)` | 16ms | 16ms | 54ms | 120ms | 16ms |
| vtime lag cap | `clamp(K × τ, 8ms, 80ms)` | 8ms | 8ms | 18ms | 40ms | 8ms |
| Spill search budget | `clamp(K / τ, 6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES))` (≈ λ₂/2) | 6 | 6 | 6 | 6 | 16 |
| Affinity idle search | `clamp(K / τ, 3, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES))` (≈ λ₂/4) | 3 | 3 | 3 | 3 | 8 |
| Per-CPU DSQ depth | `tau ≥ 6ms ? 2 : 1` | 1 | 2 | 2 | 2 | 1 |
| Longrun preempt shift | `tau < 4ms ? 2 : 0` | 4× | 1× | 1× | 1× | 1× |

- **CPU Hotplug**: `cpu_online`/`cpu_offline` callbacks clear per-CPU timestamps and oscillator state (velocity, rescue count) to prevent stale oscillation after suspend/resume
- **BPF-Verifier Safe**: All EWMA uses bit shifts, no floats. All shared state uses GCC __sync builtins

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
  adaptive.rs          Adaptive control loop (monitor thread, histogram P99,
                         MWU orchestrator, regime detection, longrun override)
  tuning.rs            MWU orchestrator (6 experts, 4 loss pathways, scale factors),
                         regime knobs, stability scoring, sleep adjustment
  procdb.rs            Process classification database (observe -> learn -> predict -> persist)
  topology.rs          CPU topology detection, Laplacian pseudoinverse, effective resistance,
                         resistance affinity ranking (sysfs -> BPF maps)
  event.rs             Pre-allocated ring buffer for stats time series
  watchdog.rs          Control-loop stall detector (10s heartbeat, abort on miss)
  bpf_intf.rs          Mirror of intf.h constants (MAX_CPUS, MAX_AFFINITY_CANDIDATES,
                         MAX_NODES) with static_assert against the C macro
  bpf_skel.rs          libbpf-cargo-generated BPF skeleton bindings
  log.rs               Logging macros
  bpf/
    main.bpf.c         BPF scheduler (GNU C23)
    intf.h             Shared structs: tuning_knobs, pandemonium_stats, task_class_entry
  cli/
    mod.rs             Shared CLI helpers
    probe.rs           Interactive wakeup probe (Python test harness hook)
    stress.rs          CPU-pinned stress worker (Python test harness hook)
build.rs               vmlinux.h generation + C23 patching + BPF compilation
tests/
  pandemonium-tests.py Test orchestrator (bench-scale, bench-trace, bench-contention,
                         bench-pcpu, bench-scx, bench-sys, low-cpu-deadline)
  bench-fork-thread.py Fork/thread IPC benchmark with hardware counter profiling
  bench-power.py       Energy-efficiency benchmark (RAPL J/op + idle floor)
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
                                    scaled_regime_knobs() -> baseline
                                      -> MWU orchestrator (6 experts, 4 loss pathways)
                                        -> blend continuous knobs (scale factors)
                                        -> vote discrete knobs (majority)
                                      -> longrun override -> WEAK affinity, base batch
                                      |
                                      v
                                    BPF reads knobs on next dispatch

Resistance affinity: R_eff ranked map -> BPF select_cpu (wakee_flips-gated)
L2 placement:        affinity_mode knob -> BPF enqueue (WEAK during longrun)
Sojourn threshold:   sojourn_thresh_ns knob -> BPF dispatch (core-count-scaled)
Stall detection:     codel_target_ns (BPF-internal, damped oscillation, no Rust input)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. Stall detection is fully BPF-internal — the damped oscillation runs in tick() on CPU 0 with no Rust involvement.

### Tuning Knobs (BPF map)

| Knob | Default | Owner | Purpose |
|------|---------|-------|---------|
| `slice_ns` | 1ms | MWU | Interactive/lat_cri slice ceiling |
| `preempt_thresh_ns` | 1ms | MWU | Tick preemption threshold |
| `lag_scale` | 4 | MWU | Deadline lag multiplier |
| `batch_slice_ns` | 20ms | MWU | Batch task slice ceiling (sleep-adjusted) |
| `burst_slice_ns` | 1ms | MWU | Slice during longrun mode |
| `lat_cri_thresh_high` | 32 | MWU | LAT_CRITICAL classifier threshold |
| `lat_cri_thresh_low` | 8 | MWU | INTERACTIVE classifier threshold |
| `affinity_mode` | 1 | MWU | L2 placement (0=OFF, 1=WEAK, 2=STRONG) |
| `sojourn_thresh_ns` | 5ms | MWU | Batch DSQ rescue threshold (tau-scaled) |
| `topology_tau_ns` | 0 | Topology | Fiedler-derived time constant (τ = TAU_SCALE / λ₂) |
| `codel_eq_ns` | 0 | Topology | R_eff-derived CoDel equilibrium (`⟨R_eff⟩ × 2m × τ`) |

Topology-owned fields are written by Rust at topology detect and on hotplug. The adaptive loop preserves them on every MWU write (the 1Hz cycle would otherwise clobber the equilibrium).

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
CARGO_TARGET_DIR=/tmp/pandemonium-build cargo build --release
```

vmlinux.h is generated from the running kernel's BTF via bpftool on first build and cached at `~/.cache/pandemonium/vmlinux.h`. The source directory path contains spaces, so `CARGO_TARGET_DIR=/tmp/pandemonium-build` is required for the vendored libbpf Makefile.

After install:

```bash
sudo systemctl start pandemonium          # Start now
sudo systemctl enable pandemonium         # Start on boot
```

## Usage

```bash
sudo scx_pandemonium                            # Default: adaptive mode
sudo scx_pandemonium --no-adaptive              # BPF-only (no Rust control loop)
sudo scx_pandemonium --compositor gamescope     # Boost an additional compositor to LAT_CRITICAL
sudo scx_pandemonium -v                         # Verbose telemetry on stdout
```

### Monitoring

Per-second telemetry:

```
d/s: 251000  idle: 5% shared: 230000  preempt: 12  keep: 0  kick: H=8000 S=22000 enq: W=8000 R=22000 wake: 4us p99: 10us L2: B=67% I=72% LC=85% procdb: 42/5 sleep: io=87% sjrn: 3ms/5ms rescue: 0 [MIXED]
```

| Counter | Meaning |
|---------|---------|
| d/s | Total dispatches per second |
| idle | select_cpu idle fast path (%) |
| shared | Enqueue -> per-node DSQ |
| preempt | Tick preemptions |
| kick H/S | Hard (PREEMPT) / Soft kicks |
| enq W/R | Wakeup / Re-enqueue counts |
| wake / p99 | Average / P99 wakeup latency |
| L2: B/I/LC | L2 cache hit rate per tier |
| procdb | Total profiles / confident predictions |
| sleep: io | I/O-wait sleep pattern (%) |
| sjrn | Batch sojourn: current / threshold |
| rescue | Overflow rescue dispatches this tick |
| [REGIME] | LIGHT/MIXED/HEAVY + LONGRUN flag |

## Benchmarking

```bash
./pandemonium.py bench-scale                     # Full suite (throughput, latency, burst, longrun, mixed, deadline, IPC, launch)
./pandemonium.py bench-scale --iterations 3      # Multi-iteration
./pandemonium.py bench-scale --pandemonium-only  # Skip EEVDF and externals
./pandemonium.py bench-contention                # Contention stress (6 phases)
./pandemonium.py bench-pcpu                      # Per-CPU DSQ correctness
./pandemonium.py bench-fork-thread               # Fork/thread IPC + hardware counters
./pandemonium.py bench-power                     # Energy efficiency (RAPL J/op + idle floor)
./pandemonium.py bench-trace                     # BPF trace capture for external workloads
./pandemonium.py bench-sys                       # Live system telemetry capture
./pandemonium.py bench-scx                       # sched-ext/scx CI compatibility
```

All benchmarks compare across core counts via CPU hotplug (2, 4, 8, ..., max). Results archived to `~/.cache/pandemonium/`.

## Testing

```bash
CARGO_TARGET_DIR=/tmp/pandemonium-build cargo test --release   # Unit tests (no root)
sudo CARGO_TARGET_DIR=/tmp/pandemonium-build \
     cargo test --release --test gate -- --ignored \
     --test-threads=1 full_gate                                 # Integration gate (requires root)
```

11 tests across 2 files: integration gate at `tests/gate.rs` (5 — full_gate plus the
load/classify, latency, responsiveness, and contention layers), topology unit tests
at `src/topology.rs::tests` (6 — sysfs CPU-list parsing and topology detection).

## sched-ext/scx Integration

PANDEMONIUM is included in the sched-ext/scx monorepo. `export_scx.py` automates the import:

```bash
./export_scx.py /path/to/scx
```

Copies source into `scheds/rust/scx_pandemonium/`, renames the crate, replaces `build.rs` with `scx_cargo::BpfBuilder`, swaps `libbpf-cargo` for `scx_cargo`, registers the workspace member, and runs `cargo fmt`.

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

[8] S. Arora, E. Hazan, S. Kale. "The Multiplicative Weights Update Method: a Meta-Algorithm and Applications." *Theory of Computing* 8, 121-164, 2012. [doi:10.4086/toc.2012.v008a006](https://theoryofcomputing.org/articles/v008a006/)

[9] J.D. Valois. "Lock-Free Linked Lists Using Compare-and-Swap." *PODC 1995*, 214-222. [doi:10.1145/224964.224988](https://dl.acm.org/doi/10.1145/224964.224988)

## License

GPL-2.0
