# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C23. PANDEMONIUM classifies every task by behavior — wakeup frequency, context switch rate, runtime, sleep patterns — and adapts scheduling decisions in real time. A damped harmonic oscillator drives CoDel-inspired stall detection with the literal RFC 8289 sojourn metric and an R_eff-derived equilibrium reference. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. A migration potential Φ — R_eff priced against the queueing relief a move buys — gates cross-domain work stealing, so a steal crosses a cache boundary only when the backlog it relieves outweighs the cache cost. Multiplicative Weight Updates (MWU) balance six competing expert profiles across six loss pathways — one of them a cross-CCX scatter signal that holds the adaptive layer's knob choices in line with the Φ placement it sits above.

Three-tier behavioral dispatch, overflow sojourn rescue, longrun detection, tier-aware preempt scaling, sleep-informed batch tuning, classification-gated DSQ routing, workload regime detection, flow-signature shape routing (per-task partner-cardinality classification into TIGHT loops vs STORM meshes), a migration-potential-gated R_eff work steal, a Φ-priced warm-stay home anchor, a sojourn selector with bounded maturity-gated tier warp, a per-CPU tau-derived preempt, an RT-policy latency floor, hard starvation rescue, and a persistent process database that learns task classifications across lifetimes.

See the [New User Guide](NEW-USER-GUIDE.md) for an introduction — the ideas behind PANDEMONIUM in plain language.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE, Arch, Ubuntu and NixOS communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs (Ryzen 5 3600), kernel 7.0.12.arch1, clang 21. v5.13.0 (commit aaa741df0), EEVDF, scx_cosmos 1.1.4, scx_lavd 1.1.1 are from a fresh-boot full-field bench-scale (2026-06-14, 3 iterations). All five schedulers completed every cell (24/24 survived); no crash or hotplug insta-exit contamination.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | scx_cosmos | scx_lavd  | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|------------|-----------|-------------------|------------------------|
| 2     | 3,067us  | 2,257us    | 6,564us   | **62us**          | 162us                  |
| 4     | 2,928us  | 1,443us    | 5,702us   | **65us**          | **65us**               |
| 8     | 71us     | 1,651us    | 2,050us   | **66us**          | 130us                  |
| 12    | 319us    | 1,811us    | 781us     | 65us              | **63us**               |

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | scx_cosmos | scx_lavd  | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|------------|-----------|-------------------|------------------------|
| 2     | 1,627us  | 2,039us    | 6,611us   | **218us**         | 821us                  |
| 4     | 3,963us  | 2,085us    | 5,666us   | **63us**          | 17,467us               |
| 8     | 2,331us  | 1,692us    | 5,985us   | 179us             | **69us**               |
| 12    | 652us    | 1,740us    | 407us     | **68us**          | 70us                   |

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF    | scx_cosmos | scx_lavd  | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|------------|-----------|-------------------|------------------------|
| 2     | 4,041us  | 1,831us    | 5,368us   | **255us**         | 405us                  |
| 4     | 2,081us  | 1,957us    | 5,756us   | **60us**          | 185us                  |
| 8     | 1,325us  | 1,988us    | 4,043us   | **583us**         | 2,069us                |
| 12    | 71us     | 1,784us    | 3,894us   | 86us              | **65us**               |

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF    | scx_cosmos | scx_lavd  | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|------------|-----------|-------------------|------------------------|
| 2     | 5,254us  | 1,062us    | 5,726us   | 669us             | **243us**              |
| 4     | 2,971us  | 1,983us    | 5,727us   | 1,038us           | **187us**              |
| 8     | 1,665us  | 1,977us    | 4,059us   | 68us              | **64us**               |
| 12    | 826us    | 1,770us    | 7,707us   | **64us**          | 68us                   |

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF   | scx_cosmos | scx_lavd | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|---------|------------|----------|-------------------|------------------------|
| 2     | 18.1%   | 71.0%      | 85.4%    | **0.2%**          | 0.4%                   |
| 4     | 11.2%   | 59.8%      | 72.8%    | 0.3%              | **0.1%**               |
| 8     | 12.9%   | 50.4%      | 49.9%    | **0.3%**          | 0.3%                   |
| 12    | 10.8%   | 52.8%      | 49.0%    | **0.0%**          | 0.1%                   |

### Burst Recovery P99 (latency after storm subsides, bench-contention)

| Cores | PANDEMONIUM (bench-contention burst-recovery phase) |
|-------|------------------------------------------------------|
| 2     | base 118us / burst 116us / recovery 123us           |
| 4     | base 124us / burst 131us / recovery 141us           |
| 8     | base 63us / burst 64us / recovery 64us              |
| 12    | base 61us / burst 65us / recovery 77us              |

### App Launch P99

| Cores | EEVDF    | scx_cosmos  | scx_lavd    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------|-------------------|------------------------|
| 2     | 3,449us  | 2,272us     | 17,617us    | **1,453us**       | 3,241us                |
| 4     | 3,048us  | **2,377us** | 6,377us     | 6,435us           | 16,403us               |
| 8     | 3,134us  | **2,087us** | 5,600us     | 9,159us           | 11,340us               |
| 12    | 3,033us  | 1,545us     | **1,179us** | 16,533us          | 2,910us                |

App launch (`fork()`+`exec()` under load) and IPC round-trip below are the two workloads where PANDEMONIUM trails: cosmos is purpose-built for the tightly-coupled pipe pattern and leads both, and the BPF dispatch waterfall's per-decision cost is hardest to amortize on launch. The 1:N fan-out path behind the IPC tail is the top open item for v5.14.0.

### IPC Round-Trip P99

| Cores | EEVDF    | scx_cosmos | scx_lavd  | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|------------|-----------|-------------------|------------------------|
| 2     | 761us    | **21us**   | 1,529us   | 2,738us           | 2,129us                |
| 4     | 1,517us  | **59us**   | 2,676us   | 16,593us          | 2,331us                |
| 8     | 1,926us  | **280us**  | 2,673us   | 2,056us           | 3,003us                |
| 12    | 3,501us  | **137us**  | 2,622us   | 280us             | 3,974us                |

### Fork/Thread IPC (`perf bench sched messaging -t -g 24 -l 6000`, 12C, v5.13.0)

| Scheduler                | Time        | vs EEVDF  | Cache Misses | Cache Refs | IPC   |
|--------------------------|-------------|-----------|--------------|------------|-------|
| EEVDF                    | 16.367s     | baseline  | 33.48M       | 1,082M     | 0.424 |
| PANDEMONIUM (BPF)        | 16.708s     | +2.1%     | 39.96M       | 993M       | 0.424 |
| PANDEMONIUM (ADAPTIVE)   | **16.333s** | **−0.2%** | 38.10M       | 964M       | 0.423 |

ADAPTIVE edges fresh-boot EEVDF on wall time and BPF lands within ~2%; both touch ~8–11% fewer cache lines (references) than EEVDF, trading a slightly higher miss rate for net throughput parity. IPC is identical across all three (0.42).

### Energy Efficiency (`bench-power`, 12C, v5.13.0)

5 runs per (scheduler, workload), 30s cooldown, 2026-06-08. Package energy via `perf stat -a -e power/energy-pkg/`. Zen 2 (Ryzen 5 3600) exposes only `J_pkg` (no per-core or per-DRAM RAPL).

**Idle floor** (30s `sleep`, scheduler restlessness):

| Scheduler                | J_pkg   | Avg W    | vs EEVDF |
|--------------------------|---------|----------|----------|
| scx_bpfland              | **682.32J** | **22.72W** | **-1.4%** |
| EEVDF                    | 691.71J | 23.04W   | baseline |
| scx_flow                 | 698.97J | 23.28W   | +1.1%    |
| PANDEMONIUM (ADAPTIVE)   | 703.32J | 23.42W   | +1.7%    |
| scx_lavd                 | 718.79J | 23.94W   | +3.9%    |
| PANDEMONIUM (BPF)        | 727.59J | 24.23W   | +5.2%    |

**Messaging** (`perf bench sched messaging`, fork-storm + IPC):

| Scheduler                | Wall_s     | J_pkg       | J/op       | vs EEVDF |
|--------------------------|------------|-------------|------------|----------|
| PANDEMONIUM (BPF)        | 15.35s     | **950.70J** | **165.05uJ** | **-0.3%** |
| EEVDF                    | **15.25s** | 953.63J     | 165.56uJ   | baseline |
| PANDEMONIUM (ADAPTIVE)   | 15.67s     | 968.64J     | 168.17uJ   | +1.6%    |
| scx_bpfland              | 21.24s     | 1272.11J    | 220.85uJ   | +33.4%   |
| scx_lavd                 | 27.80s     | 1715.38J    | 297.81uJ   | +79.9%   |
| scx_flow                 | 72.64s     | 4433.50J    | 769.70uJ   | +364.9%  |

## Key Features

### Dispatch Waterfall

Layered dispatch with per-CPU DSQ dominance and one age-driven safety mechanism. CPU-tied placement (Tier 2 wakeup preemption, `select_cpu`) is bounded at the enqueue site by `pcpu_depth_base` and overflow spills to a sibling per-CPU DSQ in R_eff order (`find_pcpu_with_room` → `pick_pcpu_dsq_with_spill`), so the dispatch waterfall reaches every CPU-tied enqueue at STEP 0 (sibling owns) or STEP 1 (near R_eff steal). Idle-CPU placement (Tier 1) inserts directly into the per-CCX overflow DSQ and is picked up by STEP 3 within one dispatch cycle — eager R_eff search at this site is a wire-speed regression on fork-storm workloads with no measurable placement benefit. The steal is **near-before-far tiered**: STEP 1 walks same-CCX peers only, the cross-CCX tier (STEP 4b) is reached only after the home CCX — peers *and* local overflow — is fully exhausted, so a working set never scatters off its home L3 while same-CCX or local work remains. The CCX boundary is structural ordering *between* tiers; Φ still prices the steal *within* each tier. The waterfall is 8 steps (0, 1, 2, 3, 4, 4b, 5, KEEP_RUNNING) + 1 safety net; redundant rescue paths (deficit-gate-with-exception, DRR deficit counter, batch sojourn rescue) are deliberately absent — they all reduce to "service the older overflow side past a threshold," which STEP 2 already does. `sojourn_gate_pass` sits at STEP 0 / STEP 1, load-bearing for workqueue-worker fairness under sustained per-CPU load (without it, `scx_watchdog_workfn` strands in the overflow DSQ long enough to trigger 30s watchdog kills).

0. **Own per-CPU DSQ** — cache-hot, zero contention. Sojourn-gated return: if either overflow side has aged past `overflow_sojourn_rescue_ns`, fall through to STEP 2 so this dispatch serves overflow too.
1. **Near R_eff steal (same-CCX tier)** — single loop over `near_tbl`, the same-CCX prefix of the R_eff rank packed by Rust at topology detect: slot 0 = L2 sibling, each u64 entry packs the peer CPU (low 32 bits) and the pre-folded Φ distance penalty in ns (high 32). Budget is tau-derived: `pcpu_spill_search_budget = K_SPILL_BUDGET / tau ≈ λ₂/2`, clamped to `[6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]`. The companion WAKE_SYNC idle-search budget `affinity_search_online = K_AFFINITY_SEARCH / tau ≈ λ₂/4` clamps the same way (smaller divisor because the predicate is more expensive). A peer is relieved only with `nr_queued > 1` and its head aged past the Φ threshold `codel_target_ns + (penalty >> 32)` — the penalty read straight from the entry's high bits, no second map lookup and no multiply, so an SMT sibling (R_eff≈0) stays freely relievable while a far peer must show ~τ of backlog. A per-CPU scan rate-limit (`last_spill_scan`, one stamp shared with STEP 4b) gates the walk to once per `codel_target_ns`. Same sojourn gate as STEP 0 on success.
1. *Safety net.* **Hard starvation rescue** — `try_service_older_overflow(starvation_rescue_ns)`: drains whichever of `interactive_enqueue_ns` / `batch_enqueue_ns` is older past the tau-scaled hard cap. Fires before STEP 2 so it cannot be gated. Should ~never fire post-placement-fix.
2. **Service older overflow side** — `try_service_older_overflow(overflow_sojourn_rescue_ns)`: same pick-the-older comparison at the R_eff-derived equilibrium threshold (`overflow_sojourn_rescue_ns = codel_target_equilibrium_ns`). Feeds the CoDel oscillator (`global_rescue_count++`).
3. **Per-CCX interactive overflow (local)** — cache-coherent drain of this CCX's interactive overflow DSQ (`node_dsq`; LAT_CRITICAL + INTERACTIVE, sojourn-ordered).
4. **Per-CCX batch overflow (local)** — this CCX's batch overflow DSQ.
4. **STEP 4b — Far R_eff steal (cross-CCX tier)** — reached only with the home CCX fully exhausted (no own work, no qualifying near peer, no local overflow). Walks `far_tbl`, the `FAR_CANDIDATES = 8` nearest cross-CCX peers (dense from slot 0, constant bound, sentinel-terminated), under the same scan window STEP 1 stamped and the same Φ price: a cross-CCX pull still needs ~τ of sustained backlog via the pre-folded penalty. v5.7.0's far-steal-last ordering expressed inside the Φ-priced walk. All-sentinel on a monolithic box — instant break.
5. **Cross-CCX work conservation** — scan other CCXs once; drain any non-empty overflow (interactive first per CCX, then batch). Runs only when the local CCX is empty, so cross-CCX migration here is pure idle-time work conservation.
6. **KEEP_RUNNING** — if prev still wants CPU and nothing queued.

### Three-Tier Enqueue

- **select_cpu**: idle CPU -> per-CPU DSQ (depth-gated: 1 slot at <4C, 2 at 4C+) -> R_eff sibling spill if full -> last-resort node DSQ, with KICK_IDLE on the placement target. WAKE_SYNC path: partner-CPU fast path (claim the wakee's `last_cpu` directly if idle and allowed, skipping the R_eff scan on a stable pair) -> R_eff idle search -> waker fallback, WITH a kick — arm A (found-idle) KICK_IDLE, arm B (no-idle) KICK_PREEMPT — so the wakee runs next instead of aging until the target's tick (the dominant IPC round-trip tail)
- **enqueue Tier 1** (idle CPU): direct `node_dsq` insert + KICK_PREEMPT for non-BATCH / KICK_IDLE for BATCH. Drained by STEP 3 (unconditional `node_dsq`) within one dispatch cycle. The wire-speed path: eager R_eff search at this site is a fork-storm regression with no placement benefit, so Tier 1 stays a direct insert
- **enqueue Tier 2** (wakeup preemption): uses `pick_pcpu_dsq_with_spill` for symmetric placement with `select_cpu`. CPU-tied; benefits from eager per-CPU placement
- **enqueue Tier 3** (fallback): batch overflow DSQ for BATCH only; LAT_CRITICAL, INTERACTIVE, and immature INTERACTIVE (`ewma_age < 2`) all stay in `node_dsq` — immature tasks are deliberately kept out of the batch DSQ to avoid burst-spawn starvation. The sojourn deadline (`now − warp`) is computed at the insert
- **tick**: longrun detection (batch non-empty >2s), sojourn enforcement, per-CPU preempt of the resident for an aged waiter (`pcpu_enqueue_ns[this_cpu]` age vs a tau-scaled threshold; BATCH yields at base, INTERACTIVE at 2×, LAT_CRITICAL never)

### Damped Harmonic Oscillator Stall Detection

CoDel-inspired per-CPU DSQ stall detection where the target follows the full damped harmonic oscillator equation:

```
ẍ + 2γẋ + ω₀²(x − c_eq) = F(t)
```

with `γ` set for Butterworth-optimal damping (ζ ≈ 0.707) — a maximally-flat response that trades a small ~4.3% step-response overshoot per adaptation for shorter settling time; the overshoot is the controller's deliberate exploration term (it probes the convex-response boundary on each impulse instead of parking inside it).

**Per-task sojourn** (RFC 8289): `task_ctx.enqueue_at` is set at every `scx_bpf_dsq_insert_vtime` call site (six placement paths) and consumed in `pandemonium_running` to compute `sojourn = now − enqueue_at`. This is the literal CoDel metric — wait between enqueue and run start — feeding `pcpu_min_sojourn_ns`. A per-task timestamp stays accurate through an entire drain, where a per-CPU `now − pcpu_enqueue_ns[cpu]` proxy weakens past the first task.

**Stall decision** (`pcpu_dsq_is_stalled`): compares per-CPU minimum sojourn against `codel_target_ns`. Below = flowing. Above for `sojourn_interval_ns` = stalled, force rescue. Binary CoDel decision; the target itself is what oscillates.

**Spring (restoring term)**: equilibrium `c_eq = ⟨R_eff⟩ × 2m × τ` derived from spectral graph properties already computed at topology detect — `⟨R_eff⟩ = Tr(L⁺)/N` over nonzero eigenvalues, `2m = Tr(L)`, τ the Fiedler-derived mixing time. The product is the natural latency tolerance of the topology. Rust clamps `c_eq` to `[200µs, 8ms]`; BPF additionally constrains it inside the oscillator's `[floor, max]` window.

**Butterworth damping** (discrete): the existing `v −= v >> damping_shift` corresponds to `2γ ≈ 2^−D`. The spring is `v −= disp >> spring_shift` with `spring_shift = 2*damping_shift + 1`, placing the pole pair at ζ ≈ 2^(−1/2) ≈ 0.707 (Butterworth-optimal). Co-derived in `apply_tau_scaling` so topology changes preserve the damping ratio automatically: `damping_shift=1 → spring_shift=3` (2C, fast restore), `damping_shift=5 → spring_shift=11` (12C, gentle restore).

**Feedback loop**: `global_rescue_count` (atomic, incremented at the overflow rescue site in dispatch) drives the impulse `F(t)`. Each tick on CPU 0: apply impulse → apply spring (`v −= disp >> spring_shift`) → apply damping (`v −= v >> damping_shift`) → cap velocity → integrate `x`.

**Core-scaled parameters** (derived from τ in `apply_tau_scaling`; the per-column values below are an approximate reference — the live values are derived at runtime):

| Parameter | 2C | 4C | 8C | 12C |
|-----------|----|----|-----|------|
| Sojourn interval | 2ms | 4ms | 8ms | 12ms |
| Damping shift D | 1 (v/2) | 1-2 | 3 | 5 (v/32) |
| Spring shift (2D+1) | 3 (disp/8) | 3-5 | 7 (disp/128) | 11 (disp/2048) |
| Pull scale | 1 | 1 | 3 | 4 |
| Center floor | 200µs | 200µs | 500µs | 700µs |
| Center ceiling | 1ms | 1ms | 1ms | 2ms |

`x` rests at `c_eq` when the system is quiet, descends below on rescue events, and returns Butterworth-damped — one bounded ~4.3% overshoot, then settle.

**Oscillator envelope (idle quiescence)**: the control effort obeys the same damping law as the system it controls, so the oscillator goes quiet when the system does. A decayed energy reservoir (`osc_env_energy -= osc_env_energy >> 3`, then `+= disp² + v²`, built only from values the recompute already maintains) drives the recompute cadence down as the oscillator contracts. Below the RELEASE threshold the oscillator recomputes every 4th tick (graded band); below PARK it pins `codel_target_ns` at `codel_target_equilibrium_ns` (the closed-form fixed point, one store), freezes the velocity integrator (anti-windup, so it cannot accumulate across the band and slingshot at wake), and stops the arithmetic. Thresholds derive from the spring/damp dead-band quanta pre-scaled by the reservoir gain, with RELEASE 2× above PARK — multiplicative hysteresis, a Schmitt trigger on energy, not a change-point accumulator. While parked, three compares per tick arm the detector: a rescue event (a discrete count, so no epsilon floor), the equilibrium moving under the parked value (MWU/τ retune), or a 1024-tick max-park heartbeat. On any of these the oscillator does a full recompute in the same tick — before any dispatch prices against the target — and re-primes the reservoir above RELEASE so a bursty wake cannot immediately re-park. Every burst begins from an identical controller state. `nr_osc_park` (in the stats struct, surfaced as TOTAL OSC PARKS) counts parks; zero parks after an idle-heavy run is the minimum-attention-collapse failure mode the counter exists to detect.

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes downstream anti-starvation unreachable — 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch STEP 0 / STEP 1 fall through to STEP 2 when either overflow DSQ has aged past `overflow_sojourn_rescue_ns` — which is set to `codel_target_equilibrium_ns` (the R_eff-derived CoDel equilibrium `⟨R_eff⟩ × 2m × τ`, clamped into the oscillator's `[floor, max]` window, so ≤~2ms at 12C — not a hand-tuned ~10ms). The spectral scalar opens the gate; sojourn (enqueue-age) fills it and selects the older side. `try_service_older_overflow` then drains that side past the threshold. CAS-based timestamp management prevents races across CPUs.

**Drain both when both aged**: under sustained mixed load both overflow DSQs can stay continuously non-empty for tens of seconds, freezing both timestamps at their first-non-empty values. A strict "older wins" would then pick the same side every rescue call until external pressure dropped, locking out batch-demoted long-runners (at 2C, a 19-29s starvation tail; 4C+ closes the window through higher dispatch density). So when BOTH sides are aged, both drain — older-first ordering preserved (latency-budget bias for interactive on ties), at the cost of one extra `scx_bpf_dsq_move_to_local`.

### Longrun Detection

When batch DSQ stays non-empty past `longrun_thresh_ns` (tau-scaled, ~2s at 12C reference), `longrun_mode` activates. Two consumers: `task_slice` substitutes `burst_slice_ns` for `slice_ns` on INTERACTIVE/LATCRIT (1ms tighter cap, yields CPU faster under pressure); `tick` scales the preempt threshold via `longrun_preempt_shift` — 4× at 2C (extends BATCH's protected window) so thin topologies don't thrash, no scaling at 4C+ where capacity already absorbs LAT_CRIT contention.

### Wake Sensitivity & Preemption

No burst detector. The failure modes one would cover — CUSUM on enqueue-interval EWMA, `wake_burst` on absolute wakeup rate, `burst_mode` gating slice/depth/preempt behaviors — are instead handled by the oscillator-adapted CoDel target, the placement-side depth gate + L2/R_eff spill, hard starvation rescue, or tier information already present at the enqueue site. Tick preemption is derived per-CPU, with no global signal:

- **Per-CPU preempt**: `pandemonium_tick` reads its own `pcpu_enqueue_ns[this_cpu]` — the age of the oldest task waiting on this CPU — against a tau-scaled threshold (`preempt_thresh_ns`): a BATCH resident yields once a waiter ages past the base threshold, an INTERACTIVE resident at 2× (batch-throughput protection), a LAT_CRITICAL resident never. Per-CPU by construction — no token to race over. A single global flag instead (armed at enqueue, cleared by the first tick to preempt on *any* CPU) gets token-stolen across cores under a fork storm, so the CPU actually burying a latency waker rarely wins the race — the audio-under-load pathology (intermittent, single-thread, bursty-only). The per-CPU read reuses the bounded-array scan already running for the coarse per-CPU sojourn check, so no new global state.
- **RT-policy floor**: `SCHED_FIFO`/`SCHED_RR` threads are pinned `TIER_LAT_CRITICAL` by declaration, after the behavioral classifier and the high-prio-kthread→BATCH override. A periodic audio RT thread scores erratically on the behavioral `lat_cri` metric and was flipping out of LAT_CRITICAL mid-burst; threaded USB IRQ kthreads were force-demoted to BATCH. The floor keeps both latency-critical under load, immune to the EWMA jitter.
- **Core-scaled longrun protection**: during sustained `longrun_mode`, the preempt threshold scales up on thin topologies (τ < 4ms) only, extending the protected BATCH window so they don't thrash; wider topologies keep the baseline, where capacity already absorbs LAT_CRIT contention.

### Sojourn Selector + Lag Cap

There is no weighted virtual-time engine. `task_deadline()` returns `now − warp` — the enqueue timestamp back-dated by a bounded per-tier warp — so every DSQ is ordered oldest-first (largest sojourn served first). Sojourn IS the selector; no second fairness clock runs parallel to the sojourn + R_eff/CoDel layer.

`lag_cap_ns = K_LAG_CAP × τ` clamped `[8ms, 80ms]` is the warp bound (~13ms at the 12C reference). The warp is flat per tier — `LAT_CRITICAL = lag_cap`, `INTERACTIVE = lag_cap/2`, `BATCH = 0` — and **maturity-gated**: a task earns its warp only once classified (`ewma_age ≥ EWMA_AGE_MATURE`), so a fork storm of unmatured INTERACTIVE children competes on pure arrival order and cannot leapfrog established work.

Because the warp is bounded, a BATCH task older than `lag_cap` always out-sorts a freshly-warped LAT_CRITICAL waker: **starvation-free by construction**, with no ceiling and no new-task penalty needed. A new task simply enters at `now` like any other arrival. (A wakeup-frequency-weighted warp and a queue-depth backlog term each reorder by something other than wait — they cluster ping-pong wakers or rubberband interactivity — so the warp stays flat, bounded, and maturity-gated; deep-queue drainage is left to the overflow sojourn rescue, which forces aged work forward by wait, not depth.)

### Hard Starvation Rescue

`clamp(K_STARVATION_RESCUE × τ, 20ms, 500ms)` — tau-scaled and monotonic in topology timing: 20ms at 2C, ~80ms at 4C, ~160ms at 8C, ~167ms at 12C (the Core-Count Scaling table values). Runs as the dispatch safety net before STEP 2, ungated; should ~never trip after the placement fix.

### Topology-Aware Placement

**Resistance affinity**: The CPU topology is modeled as a weighted electrical network (L2 siblings = 10.0, same socket = 1.0, cross-socket = 0.3). The Laplacian pseudoinverse (Jacobi eigendecomposition, O(n^3), pure Rust) gives all-pairs migration costs accounting for every path through the graph, not just direct connections. `R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]` — a true metric satisfying the triangle inequality. Per-CPU ranked lists stored in a BPF map sized at `MAX_AFFINITY_CANDIDATES = MAX_CPUS >> 3` slots per CPU (= 128 at MAX_CPUS=1024); the runtime walk is bounded by `nr_cpu_ids - 1`, with `(u32)-1` sentinels marking unused slots so loops early-exit on small N.

**Online-budget search**: `find_idle_by_affinity()` walks the ranked list with an online-candidates budget, not a total-slots budget. The rank map is built once at init from the full topology; after hotplug, some top ranks may reference offline CPUs. Offline entries are skipped without charging budget, so the search cost on a fully-online system is identical to a raw limit of 3, while remaining robust to arbitrary hotplug asymmetry (12C → 8C, 32C → 4C, etc.).

**Tiered R_eff steal (near-before-far)**: the R_eff rank is split once, in Rust at topology detect, into two packed tables — `near_tbl` (same-CCX peers, R_eff-ascending) and `far_tbl` (the `FAR_CANDIDATES = 8` nearest cross-CCX peers). Each slot is a u64 packing the peer CPU (low 32) and the pre-folded Φ distance penalty in ns (high 32), so one lookup yields both distance and price — strictly fewer map reads than the prior `affinity_rank` + `reff_value` pair. Dispatch STEP 1 walks `near_tbl` under the tau-derived `pcpu_spill_search_budget` (clamped to `[6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES)]`); STEP 4b walks `far_tbl` under a constant 8-slot bound, reached only with the home CCX exhausted. The split is computed once (topology-static, never a per-dispatch or variable-loop-bound cost) — two earlier inline-loop attempts hit verifier E2BIG path-state explosion, which moving the boundary to Rust-side static tables eliminates. On a monolithic 1-CCX box `near_tbl` is the full rank and `far_tbl` is all-sentinel — bit-identical prior behavior.

**wakee_flips gate**: `select_cpu()` reads waker/wakee `wakee_flips` from `task_struct`. Both below `nr_cpu_ids` = 1:1 pipe pair (affinity beneficial). Either above = 1:N server pattern (skip to normal path). Same discrimination as the kernel's `wake_wide()`.

**L2 cache affinity**: `find_idle_l2_sibling()` in enqueue finds idle CPUs in the same L2 domain (max 8 iterations), gated by the `affinity_mode` knob (0=OFF / 1=WEAK / 2=STRONG). The Rust regime baseline sets it per regime (LIGHT=WEAK, MIXED=STRONG, HEAVY=WEAK); MWU can override by majority vote. Per-dispatch L2 hit/miss counters for BATCH, INTERACTIVE, LAT_CRITICAL tiers.

**Commute time interpretation**: R_eff is proportional to expected round-trip time for work between CPUs [2]. Minimizing R_eff between pipe partners minimizes cache line transfer cost [1][3][4].

### Migration Potential (Φ)

R_eff alone is a placement *ranking* — it orders candidate CPUs by distance but doesn't price a migration against the queueing relief it buys, so a cross-CCX steal would be as cheap as an SMT-sibling steal once a head aged. The migration potential prices it: **Φ = R_eff − β·sojourn**, the graph resistance of a move set against the wait it relieves. The dispatch STEP 1 work steal pays Φ, so it crosses a cache boundary only when the backlog justifies the cache cost.

- **R_eff cost oracle**: the per-tier steal penalty `b·R_eff` is pre-folded by Rust into the high 32 bits of each `near_tbl` / `far_tbl` entry at topology detect (`b = phi_dist_scale_q16`), so the dispatch steal reads peer and price from one u64 — no second lookup, no multiply. A companion `reff_value` map — sized and indexed like the rank, `reff_value[cpu * MAX_AFFINITY_CANDIDATES + slot] = (R_eff(cpu, target) × b) >> 16` in ns, `(u32)-1` past the topology end — remains the price source for the warm-stay home anchor (slot 0) and the MWU oscillator gating, which need a CPU's nearest-peer penalty outside the steal walk.
- **Distance-scaled steal resist**: STEP 1 / STEP 4b relieve a peer only once its head has waited past `codel_target_ns + (penalty >> 32)`, the penalty read straight from the tier-table entry's high bits. An SMT sibling (`R_eff ≈ 0`) stays freely relievable at the flat CoDel target; a cross-CCX pull must show ~τ of sustained backlog before the steal crosses the fabric. The scale is topology-owned (`phi_dist_scale_q16`, folded into the tables at detect); all-zero penalties — pre-first-tick, monolithic topology, or `ccx_active == false` — collapse the threshold to the flat `codel_target_ns`, no Φ resistance, exactly as if Φ were absent.
- **Shape-routed warm placement**: before the topology-blind `scx_bpf_select_cpu_dfl` any-idle pick — which can seat a wakee on a cross-CCX idle core with a cold L3, the storm's residual cache-miss source — the wakee is anchored on its own last core and searched R_eff-near (same L2/CCX first). A TIGHT pair grabs its exact warm core when free (tightest consolidation); both shapes then take the nearest idle; only a fully warm-busy neighborhood falls through to dfl.
- **Warm-stay (Φ-priced home anchor)**: a wakee whose stable home — `home_cpu`, pinned to its first CPU and never chasing the `last_cpu` a migration storm rewrites every stop — is uncongested is held there rather than fanned to a cold idle sibling. It is the placement dual of the steal threshold, releasing at the SAME point. `select_cpu` only DEFERS (returns the anchor without dispatching); `enqueue` TIER 0 seats the wakee on the home's own per-CPU DSQ with `KICK_PREEMPT` — the kick a busy core honors. The idle fast path still never places on a busy core: a `KICK_IDLE` there is a no-op that strands the wakee until the resident yields (the ~90% deadline-miss scar), so the busy placement lives only in enqueue. The hold releases once the home's sojourn passes `codel_target + dist_extra` — the home's own nearest-peer Φ penalty, read from `reff_value` slot 0 — so a near (low-R_eff) home releases quickly while a far cross-fabric home holds hard: one threshold, no binary STORM branch. `reff_value` all-zero (monolithic / `--phi-scale 0`) collapses it to the bare `codel_target`. LAT_CRITICAL and kthreads are exempt — they flee for immediacy.

Φ prices each migration by its graph resistance [1][2] and pays only when queueing relief justifies the cache cost. Cross-domain work conservation is preserved — an idle cross-CCX core is still taken freely; what Φ removes is the *cheap* cross-fabric steal that thrashed L3 for marginal queueing gain.

### Behavioral Classification

- **Latency-Criticality Score**: `lat_cri = (wakeup_freq * csw_rate) / effective_runtime_ms`, where `effective_runtime_ms = (avg_runtime + runtime_dev/2) >> 20` (ns→ms, floored to 1)
- **Three Tiers**: LAT_CRITICAL (1.5x avg_runtime slices), INTERACTIVE (2x), BATCH (configurable ceiling)
- **EWMA Classification**: wakeup frequency, context switch rate, runtime variance drive scoring
- **CPU-Bound Demotion**: an INTERACTIVE task whose `avg_runtime` reaches 75% of `slice_ns` (`avg_runtime*4 >= slice_ns*3`), guarded by `ewma_age <= 4`, is demoted to BATCH — the guard spares tasks that burn a full slice but sleep often
- **Kworker Floor**: PF_WQ_WORKER floors at INTERACTIVE
- **High-Priority Kthread Override**: `PF_KTHREAD` at `static_prio <= 110` (`task_nice <= -10`) forced to BATCH regardless of behavioral score. ZFS workers (`z_rd_int_*`, `arc_*`), kopia helpers, and similar storage kthreads no longer compete with userspace LAT_CRITICAL. The kworker floor wins for `PF_WQ_WORKER` (a `PF_KTHREAD` subset), so workqueue workers continue to be treated as latency-adjacent.
- **Flow Signature**: each wakeup sets the waker CPU's bit in a per-task bitmap; the popcount is the task's distinct-partner cardinality — a topology-free read of the live communication graph's conductance. At maturity (`ewma_age ≥ EWMA_AGE_MATURE`) the task is classified once and frozen: `≤ SHAPE_TIGHT_MAX` (2) distinct partners is a **TIGHT** pair/loop; a partner set spanning at least half of `nr_cpu_ids` is a **STORM** mesh; everything between defaults to TIGHT (latency-safe — its steal stays freely relievable). Portable — the STORM threshold scales with the machine, no hardcoded core geometry. The shape drives *placement* (TIGHT consolidates on its warm core, STORM spreads), never the steal — a shape-gated steal once starved a STORM-classed audio thread on a busy core, so the steal stays shape-blind.

### Process Database (procdb)

BPF publishes mature task profiles (tier + avg_runtime) keyed by `comm[16]`. Rust tracks EWMA convergence stability, promotes to "confident", applies learned classifications on spawn. `enable()` warm-starts; `runnable()` EWMA validates and corrects. Persistent to `~/.cache/pandemonium/procdb.bin` (atomic write).

### Adaptive Control Loop

The Rust control plane is chaos-theory-driven: both regime detection and the MWU weight-update damping run off raw-window nonlinear-dynamics statistics (`chaos.rs`), not EWMAs or Schmitt triggers.

- **One Thread, Zero Mutexes**: 1-second control loop on the main thread reads BPF histogram maps, computes per-tier and aggregate P99, and drives the MWU orchestrator. BPF produces histograms; Rust reads them once per second and writes knobs BPF picks up on the next scheduling decision.
- **Chaos primitives** (`chaos.rs`, pure Rust, recomputed each tick over a 16-sample raw window): HVG mean degree λ (Luque–Lacasa horizontal visibility graph — ~2 periodic, →4 IID-random), Bandt–Pompe D=3 permutation entropy (ordinal disorder, normalized to [0,1]), and RQA determinism (fraction of recurrence points on diagonals — →1 steady, →0 IID).
- **Workload Regime Detection**: LIGHT / MIXED / HEAVY from the raw `idle_pct` window — no Schmitt trigger. LIGHT needs `mean_idle ≥ 50%` AND "chaos-low" (`λ < 3.4` OR `bp_h < 0.85`); HEAVY needs `mean_idle ≤ 10%` AND chaos-low; everything else is MIXED. A 2-tick hold smooths transitions.
- **MWU Orchestrator**: 6 experts (LATENCY, BALANCED, THROUGHPUT, IO_HEAVY, FORK_STORM, SATURATED) compete via multiplicative weight updates, with one weight vector **per regime** (LIGHT/MIXED/HEAVY each learn independently). 7 continuous knobs are blended via per-expert scale factors; 1 discrete knob (`affinity_mode`) by weighted majority vote. Learning rate ETA = 0.33465 (= √(ln 6 / 16), the theory-optimal Hedge rate for the 16-tick window); weight floor 1e-6; relaxation 80% toward a no-op-skewed equilibrium after 2 healthy ticks below 70% of the regime P99 ceiling. The weight update is itself Butterworth-damped by a signal-trust coefficient (RQA determinism + λ), so the controller tracks faithfully only when the workload looks steady.
- **6 loss pathways**, all firing immediately (no streak confirmation): (1) **P99 spike** — worst of aggregate / interactive P99 over the regime ceiling; (2) **rescue delta** — 0→nonzero, penalizes all experts so MWU holds steady while the BPF oscillator does the tightening; (3) **IO-bucket transition**; (4) **fork storm** — raw wake-rate over a tau-derived threshold AND concurrent `rescue_count > 0`, scaled by wake-rate overage, letting the FORK_STORM expert compress `burst_slice_ns` / `preempt_thresh_ns` / `sojourn_thresh_ns` / `batch_slice_ns`; (5) **chaos transition** — a `bp_h` jump > 0.10 or an upward λ crossing penalizes the currently-dominant non-BALANCED expert; (6) **cross-CCX scatter** — the placement-side cross-CCX migration fraction (the select/enqueue `nr_xccx` paths, excluding the Φ-correct steal and work-conservation moves MWU must not punish) climbing past a 20% rising-edge threshold penalizes the THROUGHPUT / SATURATED / FORK_STORM experts, re-weighting the blend toward LATENCY / BALANCED and affinity STRONG. This is the adaptive layer's only direct view of the migration storm its own knobs can induce; rising-edge gating leaves a stable high-scatter throughput regime (8C+) untouched, where wide-slice scatter is a winning trade.
- **Φ-aware oscillator gating**: before scoring, MWU reads the BPF CoDel oscillator's position AND the nearest-peer Φ hold (`reff_value` slot 0). The rescue-delta and fork-storm pathways defer only when the oscillator has tightened (< 0.40) AND the effective release `codel_target + dist_extra` sits below the Φ equilibrium — or gone quiet (> 0.90) above it — so the two controllers never double-correct on `global_rescue_count`, and MWU never reads a hard Φ hold as a loose window and stands down on rescue pressure that is genuinely live.
- **Quiescence freeze + adaptive-rarity retune**: when λ sits in the periodic band, RQA determinism ≥ 0.90, and the active regime's weight vector has converged, the loop latches `frozen` and skips the MWU retune + knob write (it still ticks at 1 Hz; the chaos sensors are the thaw condition). When not frozen, a sub-threshold retune stretches the retune interval ×1.5 (capped at 8 ticks); any disturbance snaps it back to 1.

### Core-Count Scaling

All timing constants scale from `tau_ns = TAU_SCALE_NS / √(λ₂ · N)` — capacity-aware (the geometric mean of connectivity `1/λ₂` and capacity `1/√N`, so a well-connected but core-starved topology loosens instead of tightening), with safety-rail clamps. 12C reference: τ≈13.3ms (λ₂=12, N=12). Cardinality decisions (per-CPU DSQ depth, wake_wide threshold, tick scan budget) use `nr_cpus` directly — counts are not tau-derived. **The per-column τ values and derived cells below are an approximate reference; the live values are derived at runtime from the capacity-aware τ law.**

| Parameter | Formula | 2C | 4C | 8C | 12C | 32C |
|-----------|---------|------------|----|----|----|----|
| Sojourn interval | `clamp(K × τ, 2ms, 12ms)` | 2ms | 4ms | 8ms | 12ms | 5ms |
| Overflow rescue | `= codel_target_equilibrium_ns` (R_eff-derived) | varies | varies | varies | varies | varies |
| Starvation rescue | `clamp(K × τ, 20ms, 500ms)` | 20ms | 80ms | 160ms | 166ms | 21ms |
| CoDel target floor | `clamp(K × τ, 200µs, 800µs)` | 200µs | 200µs | 500µs | 700µs | 200µs |
| CoDel target max | `clamp(K × τ, 1ms, 8ms)` | 1ms | 1ms | 1ms | 2ms | 1ms |
| CoDel equilibrium | `clamp(⟨R_eff⟩ × 2m × τ, 200µs, 8ms)` | varies | varies | varies | varies | varies |
| Lag cap (warp bound) | `clamp(K × τ, 8ms, 80ms)` | — | — | — | — | — |
| Spill search budget | `clamp(K / τ, 6, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES))` (≈ λ₂/2) | 6 | 6 | 6 | 6 | 16 |
| Affinity idle search | `clamp(K / τ, 3, min(nr_cpu_ids - 1, MAX_AFFINITY_CANDIDATES))` (≈ λ₂/4) | 3 | 3 | 3 | 3 | 8 |
| Per-CPU DSQ depth | `tau ≥ 6ms ? 2 : 1` | 1 | 2 | 2 | 2 | 1 |
| Longrun preempt shift | `tau < 4ms ? 2 : 0` | 4× | 1× | 1× | 1× | 1× |

- **Low-core slice discipline**: τ is largest at low core count (λ₂ shrinks as cores drop), so the tau slice cap runs loosest exactly where a wide batch slice hurts most — a 4ms HEAVY-regime slice on 2–4 cores denies a latency-sensitive probe across many consecutive slices, the low-core tail. The regime slice is capped to the MIXED value (1ms) at `nr_cpus ≤ 4`, where a wide slice buys no throughput; 8C/12C keep the tau-scaled width, where it earns it.
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
                         chaos-driven regime detection, MWU, quiescence freeze)
  chaos.rs             Chaos primitives: HVG mean degree/entropy, Bandt-Pompe D=3
                         permutation entropy, RQA determinism (raw-window, no EWMA)
  tuning.rs            MWU orchestrator (6 experts, 6 loss pathways, scale factors),
                         regime thresholds, quiescence + adaptive-rarity retune
  procdb.rs            Process classification database (observe -> learn -> predict -> persist)
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
    intf.h             Shared structs: tuning_knobs, pandemonium_stats, task_class_entry
  cli/
    mod.rs             Shared CLI helpers
    probe.rs           Interactive wakeup probe (Python test harness hook)
    stress.rs          CPU-pinned stress worker (Python test harness hook)
build.rs               vmlinux.h generation + C23 patching + BPF compilation
tests/
  pandemonium-tests.py Test orchestrator (bench-scale, bench-trace, bench-contention,
                         bench-pcpu, bench-scx, bench-sys, low-cpu-deadline)
  bench-fork-thread.py Fork/thread IPC benchmark (full scx field) + hw counters + non-compensatory regression gate
  bench-power.py       Energy-efficiency benchmark (RAPL J/op + idle floor)
  bench-analyze.py     Statistical bench analysis + --trace mode (montauk migration/PMU capture)
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
                                    detect_regime (chaos: HVG λ + Bandt-Pompe)
                                      -> scaled_regime_knobs() -> baseline
                                      -> MWU orchestrator (6 experts, 6 loss pathways)
                                        -> blend continuous knobs (scale factors)
                                        -> vote discrete knobs (majority)
                                      -> oscillator gating + quiescence freeze
                                      |
                                      v
                                    BPF reads knobs on next dispatch

Resistance affinity: R_eff ranked map -> BPF select_cpu (wakee_flips-gated)
L2 placement:        affinity_mode knob -> BPF enqueue (per-regime baseline; MWU vote)
Migration potential: R_eff cost oracle + phi_dist_scale_q16 -> BPF dispatch STEP 1 steal resist
Sojourn threshold:   sojourn_thresh_ns knob -> BPF dispatch (core-count-scaled, codel_eq-floored)
Stall detection:     codel_target_ns (BPF-internal, damped oscillation, no Rust input)
Cross-CCX scatter:   nr_xccx path counters -> Rust MWU PATHWAY 6 (re-weights experts + affinity)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. Stall detection is fully BPF-internal — the damped oscillation runs in tick() on CPU 0 with no Rust involvement.

### Tuning Knobs (BPF map)

| Knob | Default | Owner | Purpose |
|------|---------|-------|---------|
| `slice_ns` | 1ms | MWU | Interactive/lat_cri slice ceiling |
| `preempt_thresh_ns` | 1ms | MWU | Tick preemption threshold |
| `batch_slice_ns` | 20ms | MWU | Batch task slice ceiling (sleep-adjusted) |
| `burst_slice_ns` | 1ms | MWU | Slice during longrun mode |
| `lat_cri_thresh_high` | 32 | MWU | LAT_CRITICAL classifier threshold |
| `lat_cri_thresh_low` | 8 | MWU | INTERACTIVE classifier threshold |
| `affinity_mode` | 0 | MWU | L2 placement (0=OFF, 1=WEAK, 2=STRONG); Rust writes the per-regime value at startup |
| `sojourn_thresh_ns` | 5ms | MWU | Batch DSQ rescue threshold (tau-scaled) |
| `topology_tau_ns` | 0 | Topology | Fiedler-derived time constant (τ = TAU_SCALE / λ₂) |
| `codel_eq_ns` | 0 | Topology | R_eff-derived CoDel equilibrium (`⟨R_eff⟩ × 2m × τ`) |
| `phi_dist_scale_q16` | 0 | Topology | Φ distance→wait scale (Q16): cross-domain steal resist `R_eff × this >> 16`; 0 = flat CoDel target (monolithic / no CCX) |

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

There is no compositor allowlist. Compositors land at `LAT_CRITICAL` naturally
through the behavioral classifier (high wakeup frequency × high context-switch
rate × short avg runtime → `lat_cri` peaks), and procdb warm-starts known
names from prior sessions. The earlier hardcoded comm boost was scaffolding
from when the classifier was less reliable on cold-start; the current
classifier no longer needs the safety net.

### Monitoring

Per-second telemetry:

```
d/s: 251000 idle: 5% shared: 230000 preempt: 12 keep: 0 kick: H=8000 S=22000 enq: W=8000 R=22000 wake: 4us p99: 10us [B:8 I:9 L:7] lat_idle: 3us lat_kick: 6us procdb: 42/5 sleep: io=87% slice: 1000us batch: 20000us reenq: 4 sjrn: 3ms/5ms rescue: 0 l2: B=67% I=72% L=85% chaos: lam=2.10 H=0.40 det=0.95 x=0 frozen: 0 (n=12) retune_iv: 2 [MIXED]
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
| [B/I/L] | Per-tier P99 (BATCH / INTERACTIVE / LAT_CRITICAL) |
| lat_idle / lat_kick | Wakeup latency split: idle-placement vs kick path |
| procdb | Total profiles / confident predictions |
| sleep: io | I/O-wait sleep pattern (%) |
| slice / batch | Current interactive / batch slice knob (us) |
| reenq | Re-enqueue count |
| sjrn | Batch sojourn: current / threshold |
| rescue | Overflow rescue dispatches this tick |
| l2: B/I/L | L2 cache hit rate per tier |
| chaos: lam/H/det/x | HVG mean degree λ / Bandt-Pompe entropy / RQA determinism / chaos-crossing counter |
| frozen (n) | Quiescence freeze active (1/0) and cumulative frozen ticks |
| retune_iv | Adaptive-rarity retune interval (ticks between retunes) |
| [REGIME] | LIGHT/MIXED/HEAVY + LONGRUN flag |

## Benchmarking

```bash
./pandemonium.py bench-scale                     # Full suite (throughput, latency, burst, longrun, mixed, deadline, IPC, launch)
./pandemonium.py bench-scale --iterations 3      # Multi-iteration
./pandemonium.py bench-scale --pandemonium-only  # Skip EEVDF and externals
./pandemonium.py bench-contention                # Contention stress (6 phases)
./pandemonium.py bench-pcpu                      # Per-CPU DSQ correctness
./pandemonium.py bench-fork-thread               # Fork/thread IPC + hw counters + regression gate
./pandemonium.py bench-power                     # Energy efficiency (RAPL J/op + idle floor)
./pandemonium.py bench-trace                     # BPF trace capture for external workloads
./pandemonium.py bench-sys                       # Live system telemetry capture
./pandemonium.py bench-scx                       # sched-ext/scx CI compatibility
./pandemonium.py bench-cachyos                   # CachyOS Mini-Benchmarker application suite
```

All benchmarks compare across core counts via CPU hotplug (2, 4, 8, ..., max). Results archived to `~/.cache/pandemonium/`.

## Testing

```bash
CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build cargo test --release   # Unit tests (no root)
sudo CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build \
     cargo test --release --test gate -- --ignored \
     --test-threads=1 full_gate                                 # Integration gate (requires root)
```

5 tests in 1 file: the integration gate at `tests/gate.rs` — `full_gate` plus the
load/classify, latency, responsiveness, and contention layers (all `#[ignore]`,
root-only). The `src/*.rs` modules carry no inline unit tests; the pure-Rust logic
(chaos, tuning, topology) is validated offline through the bench harnesses.

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

[10] M. Fiedler. "Algebraic Connectivity of Graphs." *Czechoslovak Mathematical Journal* 23(2), 298-305, 1973. [doi:10.21136/CMJ.1973.101168](https://dml.cz/dmlcz/101168)

[11] R.D. Blumofe, C.E. Leiserson. "Scheduling Multithreaded Computations by Work Stealing." *Journal of the ACM* 46(5), 720-748, 1999. [doi:10.1145/324133.324234](https://dl.acm.org/doi/10.1145/324133.324234)

[12] C. Bandt, B. Pompe. "Permutation Entropy: A Natural Complexity Measure for Time Series." *Physical Review Letters* 88(17), 174102, 2002. [doi:10.1103/PhysRevLett.88.174102](https://doi.org/10.1103/PhysRevLett.88.174102)

[13] B. Luque, L. Lacasa, F. Ballesteros, J. Luque. "Horizontal Visibility Graphs: Exact Results for Random Time Series." *Physical Review E* 80(4), 046103, 2009. [doi:10.1103/PhysRevE.80.046103](https://doi.org/10.1103/PhysRevE.80.046103)

[14] N. Marwan, M.C. Romano, M. Thiel, J. Kurths. "Recurrence Plots for the Analysis of Complex Systems." *Physics Reports* 438(5-6), 237-329, 2007. [doi:10.1016/j.physrep.2006.11.001](https://doi.org/10.1016/j.physrep.2006.11.001)

[15] S. Butterworth. "On the Theory of Filter Amplifiers." *Experimental Wireless and the Wireless Engineer* 7, 536-541, 1930.

## License

GPL-2.0
