# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C23, PANDEMONIUM prices every scheduling decision in nanoseconds against a live service bound and adapts that bound in real time. There is no task classifier. Slice, placement, admission and preemption each read a measured quantity — service rendered, queue backlog, accrued wait — so the question at every site is what a task is owed rather than what class it belongs to. A damped harmonic oscillator drives CoDel-inspired stall detection with the literal RFC 8289 sojourn metric, resting at an equilibrium the machine's own Laplacian spectrum chooses. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. A migration potential Φ — R_eff priced against the queueing relief a move buys — prices cross-domain work stealing, the wake-path move and the overflow drain, so a task crosses a cache boundary only when the backlog it relieves outweighs the cache cost. Rust folds the distance terms into per-peer tables at topology detect and the kernel reads them with one indexed lookup — the computation in the adaptive layer, the application in the kernel. Every knob the adaptive layer ships is a function of a measurement — per-CPU queue depth, traffic shape, critical slowing and persistence — computed on the tick it is applied rather than learned over a convergence window.

Overflow sojourn rescue, longrun detection, depth-derived slice tuning, class-free DSQ routing, a wakeup preemption gate keyed on the pair ledger, a per-queue clock judged by CoDel's control law, a migration-potential-gated R_eff work steal, a backlog-admitted placement spill, a Φ-priced warm-stay home anchor, a sojourn selector keyed on the bare arrival stamp, a slice quantum priced in the same unit, an off-tick unified sojourn bound and hard starvation rescue.

See the [New User Guide](https://github.com/wllclngn/PANDEMONIUM/blob/main/NEW-USER-GUIDE.md) for an introduction — the ideas behind PANDEMONIUM in plain language.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE, Arch, Ubuntu and NixOS communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs (Ryzen 5 3600), kernel 7.2.8-arch1-2, clang 23.1.1.

Three iterations per Test arm and scheduler.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 2,707us     | **68us**          | 89us                   |
| 4     | 2,970us     | 68us              | **63us**               |
| 8     | 1,227us     | 68us              | **67us**               |
| 12    | 930us       | **68us**          | 71us                   |

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 2,639us     | **119us**         | 178us                  |
| 4     | 2,864us     | **81us**          | 156us                  |
| 8     | 2,512us     | 72us              | **63us**               |
| 12    | 3,209us     | 69us              | **68us**               |

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 3,172us     | 86us              | **66us**               |
| 4     | 3,661us     | 67us              | **26us**               |
| 8     | 912us       | 75us              | **69us**               |
| 12    | 2,157us     | 68us              | **67us**               |

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 3,843us     | **88us**          | 104us                  |
| 4     | 3,865us     | 66us              | **64us**               |
| 8     | 2,448us     | 87us              | **65us**               |
| 12    | 2,349us     | 73us              | **35us**               |

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 33.2%       | **0.3%**          | **0.3%**               |
| 4     | 16.9%       | **0.1%**          | 0.3%                   |
| 8     | 15.1%       | **0.0%**          | 0.1%                   |
| 12    | 15.2%       | **0.1%**          | **0.1%**               |

### App Launch (`fork()`+`exec()` under load, p99 us)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 3,493us     | **3,443us**       | 3,645us                |
| 4     | 3,060us     | 3,552us           | **2,317us**            |
| 8     | 3,679us     | **2,005us**       | 2,023us                |
| 12    | 3,704us     | **2,003us**       | 2,165us                |

### IPC Round-Trip by Primitive (12C, p50 / p99 us)

| Primitive | EEVDF          | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-----------|----------------|-------------------|------------------------|
| pipe      | **8** / 15     | 10 / **14**       | 10 / **14**            |
| socket    | 17 / 24        | **13** / **17**   | **13** / 19            |
| eventfd   | **9 / 15**     | 23 / 32           | 23 / 32                |
| sem       | **9 / 15**     | 18 / 29           | 24 / 35                |
| fanout    | 98 / 2,923     | **86** / **1,000** | **86** / 1,002        |

### Fork/Thread IPC (`perf bench sched messaging -t -g 24 -l 6000`, 12C)

| Scheduler                | Time                | vs EEVDF  | Cache Misses | Cache Refs | IPC       |
|--------------------------|---------------------|-----------|--------------|------------|-----------|
| EEVDF                    | 17.685±0.079s       | baseline  | 4.14G        | 30.03G     | **0.480** |
| PANDEMONIUM (BPF)        | **16.091±0.149s**   | **-9.0%** | **4.02G**    | **24.41G** | 0.475     |
| PANDEMONIUM (ADAPTIVE)   | 16.449±0.119s       | -7.0%     | 4.08G        | 25.02G     | 0.474     |

| Scheduler                | Mig/s       | same-L2   | same-L3   | same-socket | Decay          |
|--------------------------|-------------|-----------|-----------|-------------|----------------|
| EEVDF                    | **7,281**   | **31.0%** | 44.9%     | 24.1%       | 1.45/0.54/0.00 |
| PANDEMONIUM (BPF)        | 17,100      | 18.9%     | 75.2%     | 6.0%        | 3.98/0.08/0.00 |
| PANDEMONIUM (ADAPTIVE)   | 16,486      | 19.1%     | **76.2%** | **4.7%**    | 3.98/0.06/0.00 |

### Energy Efficiency (`prism --dev power`, 12C)

Five runs per (scheduler, workload), 30s cooldown between runs. Package energy via `perf stat -a -e power/energy-pkg/`. Zen 2 (Ryzen 5 3600) exposes only `J_pkg` (no per-core or per-DRAM RAPL).

**Idle floor** (30s `sleep`, scheduler restlessness):

| Scheduler                | J_pkg       | Avg W      | vs EEVDF   |
|--------------------------|-------------|------------|------------|
| EEVDF                    | **735.51J** | **24.50W** | baseline   |
| PANDEMONIUM (BPF)        | 744.06J     | 24.78W     | +1.2%      |
| PANDEMONIUM (ADAPTIVE)   | 736.21J     | 24.52W     | +0.1%      |

**Messaging** (`perf bench sched messaging`, fork-storm + IPC):

| Scheduler                | Wall_s     | J_pkg       | J/op         | vs EEVDF  |
|--------------------------|------------|-------------|--------------|-----------|
| EEVDF                    | 16.30s     | 1,048.70J   | 182.07uJ     | baseline  |
| PANDEMONIUM (BPF)        | **15.73s** | **984.85J** | **170.98uJ** | **-6.1%** |
| PANDEMONIUM (ADAPTIVE)   | 15.82s     | 990.84J     | 172.02uJ     | -5.5%     |

## Key Features

### Dispatch Waterfall

Per-CPU DSQs carry most of the work, and every step after STEP 0 exists to serve what they cannot. `sweep_bound_preempt` runs first on every dispatch and off the tick: It rotates through the CPUs and forces one off its resident when a per-CPU or overflow head has waited past `lag_cap_ns`, so a CPU nobody calls `dispatch()` on is still bounded and NO_HZ_FULL cannot suppress it.

| Step | Source | Rule |
|---|---|---|
| **0** | Own per-CPU DSQ | Cache-hot. Returns unless the domain's overflow queue has waited past `codel_target_ns`, in which case it falls through so this dispatch serves the overflow too. A CPU that seated a handoff partner within one live target returns anyway (`pair_seat_live`), because a second task would land on its local DSQ and run ahead of the partner; past `codel_starve_ns` it falls through like any other CPU. |
| **1** | R_eff steal | One walk of the R_eff-ranked peer list [8], cross-domain peers included, at most once per CoDel target per CPU. A peer is relieved when its queue wait passes `codel_target_ns` plus that peer's distance penalty. A lone queued task needs one more target, and a recently seated pair adds a hold so a near steal does not split it. |
| **net** | Hard starvation | Blind drain of the domain's overflow queue past `codel_starve_ns`. |
| **2** | Aged overflow | Blind drain once the overflow queue has waited past `codel_target_ns`. Each one is a rescue event for the oscillator. |
| **3** | Local overflow | Selective drain. Peek the head and price it by how far it last ran from here, so a far task is left for a nearer CPU. A CPU whose `prev` cannot continue takes the head regardless (`would_idle`). |
| **5** | Cross-domain | Drain another domain's overflow queue when nothing local was taken. |
| **keep-prev** | KEEP_RUNNING | `prev` still wants the CPU and nothing was dispatched. |

The STEP 0 fall-through is load-bearing. Without it, CPUs busy with their own per-CPU work never visit the overflow queue, and workqueue workers starve there until the scx watchdog fires.

### Placement

**select_cpu**:

- A wakee whose anchor CPU is uncongested is left for enqueue's warm-stay (TIER 0) instead of fanning out to a cold idle sibling.
- A sync wake from the wakee's handoff partner, on a part with more than one cache domain, is seated on the waker's own per-CPU DSQ. The waker is about to block and its own STEP 0 takes the wakee, so the kick is IDLE when the seat is the waker and PREEMPT when the spill moved it.
- Otherwise the wakee is anchored on its last CPU (a fresh fork on its parent's) and searched R_eff-near for an idle CPU before the topology-blind `scx_bpf_select_cpu_dfl`. The anchor → target move is priced: Staying costs the anchor's queue wait, moving costs a base cost plus the distance fraction of one target.

**enqueue**:

- **TIER 0, warm-stay**: The anchor keeps the task while its queue wait is within `codel_target_ns` plus its nearest-peer hold. A wakeup anchors on `home_cpu`, a fixed point set on its first run, so the pull is self-limiting; a requeue anchors on `last_cpu`. Kthreads are excluded.
- **TIER 1, idle CPU**: An R_eff walk from `last_cpu` for an idle CPU, then a node-wide pick. The task goes on that CPU's per-CPU DSQ, and the kicked CPU is the one that dispatches it.
- **TIER 2, warm anchor**: A wakeup that may preempt, or a handoff partner, goes to its last CPU's per-CPU DSQ, or a near R_eff sibling when that seat's backlog is over one live target.
- **TIER 3, overflow**: Everything else goes to the domain's overflow queue, `domain_inter_dsq`, one per cache domain and drained by any CPU in it.

Admission is a backlog in nanoseconds. A seat admits while what it owes is under one live CoDel target, so the wait a task inherits on arrival is bounded by one target plus the single demand that may overshoot it.

### Wakeup Preemption

`wake_cuts()` decides whether a wakeup may preempt the running task. A sync wake is a handoff from a waker about to block. From the wakee's handoff partner it preempts; from any other waker it is one of many a producer fans out, and it waits. Timer, IRQ and fork wakes are never sync and always preempt. A wake that may not preempt skips TIER 0 and TIER 2 and takes an idle CPU through TIER 1 or the overflow queue with `SCX_KICK_IDLE`, so whichever CPU in the domain runs dry first takes it.

A requeue preempts only once its wait has passed one target, paced per CPU by the queue judge below.

**Pair ledger**: `same_waker_runs` counts consecutive wakes from one waker pid, and past `PAIR_OBS_MIN` (8) the task is a handoff partner. It is keyed on the waker's identity rather than a CPU, so the count does not decay when the pair migrates, and nobody qualifies at load time.

### Queue Clock

Each per-CPU DSQ and each domain overflow DSQ carries one cache line, `queue_clock`, holding arrivals, departures, the latest departure's sojourn, the last progress time and the judge's state. A task records which queue it is on, and `running()`, `quiescent()`, `exit_task()` and a re-insert record its departure. A queue is empty when arrivals equal departures, which no drain can erase.

- `queue_wait()` is the latest departure's sojourn plus the time since last progress. Queues are oldest-first, so the head arrived no earlier than the last task to leave and the sum bounds its wait. Every reader of a wait uses it: Warm-stay, the move price, the steal, both drains, the STEP 0 gate, the tick and the sweep.
- `queue_act()` decides every action on a wait, acting once the wait passes a bound. At the paced sites, the requeue preempt and the tick's overflow site, each act schedules the next at pace / √acts while the wait stays above the bound, and the count resets when it falls below. That is CoDel's control law [5][6], with √ from a 65-entry integer table and the count capped at 64.

The sojourn is RFC 8289's metric [6]. `task_ctx.wait_since` is stamped on the first insert after a run, preserved across requeues and cleared in `running()`, which records `now − wait_since` as the queue's departure sojourn.

### Sojourn Selector

There is no weighted virtual time and no warp. `task_deadline()` returns `wait_since` and nothing else, so every DSQ is ordered oldest-first and the longest-waiting task is served first. A task passed over N times keeps its original claim, so a starving task rises on its own as the clock moves under a stationary base.

The latency bound is admission's, not the ordering's. Ten versions of ordering arithmetic (start tags, attained-service credits, back-dated warps) all measured null, because reordering a work-conserving queue does not change how much work completes.

### CoDel Target: A Damped Harmonic Oscillator

`codel_target_ns` is the bound every site above prices against, and it follows the damped harmonic oscillator equation:

```
ẍ + 2γẋ + ω₀²(x − c_eq) = F(t)
```

Damping is Butterworth-optimal (ζ ≈ 0.707) [12]: The flattest response available, at the cost of one bounded ~4.3% overshoot per adaptation, which probes the response boundary on each impulse instead of parking inside it.

**Feedback**: The impulse is the overflow rescue count, every STEP 2 drain of an overflow queue that waited past the target. Each tick on CPU 0 applies impulse, spring and damping, caps velocity and integrates. The target rests at `c_eq` when quiet, descends on rescue events and returns damped. Every timing constant scales from τ, so a topology change preserves the damping ratio.

**Equilibrium**: `c_eq` is a position inside the working band, set by the normalised spectral-gap deficit, how much worse the topology's bottleneck is than its typical connectivity, read from eigenvalues already computed at topology detect. A machine whose cuts are all alike gets the tightest tolerance; one with a genuine bottleneck gets a looser one. Because it is a position, it needs no clamp, and the spring pushes in both directions.

**Idle quiescence envelope**: An energy reservoir built from values the recompute already maintains drives the recompute cadence down as the oscillator contracts. Below a release threshold it recomputes every fourth tick; below a park threshold, a factor of two lower, it pins the target at its closed-form fixed point, freezes the velocity integrator and stops the arithmetic. A rescue event, the equilibrium moving or a 1024-tick heartbeat triggers a full recompute in the same tick, before any dispatch prices against the target, so every burst begins from the same controller state. `nr_osc_park` counts parks.

### Tick

- **Per-CPU band**: The resident yields once its own queue's wait passes `codel_target_ns`, with no class exemption. Each CPU decides from its own queue clock, so there is no global token to race over.
- **Coarse net**: `codel_thresh_ns` is checked on the CPU's own queue and on a rotating scan of four other CPUs per tick, which reaches CPUs whose own tick has stopped.
- **Overflow site**: Once the domain's overflow wait passes its bound, the CPU preempts its own resident to re-enter dispatch, paced by the judge.
- **Longrun mode**: Set on CPU 0 when the overflow wait has stayed above the target for longer than `longrun_thresh_ns` (τ-scaled, ~665ms at the 12C reference). Every task's base slice narrows to `burst_slice_ns`, and on topologies with τ < 4ms the per-CPU band widens 4× so a thin machine does not thrash.

sched_ext sits below the RT and deadline classes and is handed only `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE`, so a `SCHED_FIFO` or `SCHED_RR` thread never reaches these ops. Two `SCHED_FIFO` threads held against a live scheduler for 48 seconds produced zero arrivals across 49 samples.

### Starvation Bounds

Two bounds sit under the waterfall. `sweep_bound_preempt` forces a CPU back into `dispatch()` once a per-CPU or overflow head has waited past `lag_cap_ns`, `clamp(K_LAG_CAP × τ, 8ms, 80ms)`, ~13.3ms at the 12C reference. Beneath it, past `codel_starve_ns`, `clamp(K_STARVATION_RESCUE × τ, 20ms, 500ms)`, ~55.6ms at the 12C reference, the overflow queue is drained unconditionally.

### Topology and Distance

**Resistance affinity**: The CPU topology is modeled as a weighted electrical network, SMT and L2 siblings conducting strongly and cross-socket links weakly. The Laplacian pseudoinverse gives all-pairs migration costs through every path in the graph, and `R_eff(i,j)` is a true metric satisfying the triangle inequality [1]. R_eff is proportional to expected round-trip time for work between CPUs [2], so minimizing it between pipe partners minimizes cache-line transfer cost [1][3][4]. Per-CPU ranked peer lists are folded into a BPF map at detect, with sentinels marking unused slots so loops early-exit on small machines. The idle search spends its budget on online candidates, so hotplug never charges it for offline ranks.

**Cache domains** emerge from the cache graph as a min-conductance cut on the weighted Laplacian, not from a CCX/CCD table, and every crossing is priced, never gated.

**Migration potential (Φ)**: R_eff ranks candidate CPUs; Φ prices a move against the queueing relief it buys. Rust folds the distance terms into per-peer tables at topology detect, and BPF reads them with one indexed lookup:

- `reff_value` is R_eff scaled to τ against the most distant pair and capped at twice the CoDel equilibrium, about 1.1ms at the 12C reference. It is the steal's distance penalty, so a far pull needs sustained backlog and an SMT sibling is relieved at the bare target.
- `reff_frac` is R_eff's excess over the nearest pair as a Q16 fraction of the span: The nearest peer is 0 and the most distant 65536, and every peer is 0 when all pairs are equidistant, as on a 2-core part with one L3. Multiplied by `codel_target_ns`, it is STEP 3's drain price, the select_cpu move price and warm-stay's hold.
- `domain_phi` is the min-conductance cut price between a CPU and each ranked peer, read by the steal's pair hold.

An idle cross-domain core is still taken freely; what Φ removes is the cheap cross-domain steal that thrashes L3 for marginal queueing gain.

### No Task Classifier

There is no task class and the dispatch key takes no class input. Slice, placement, admission and preemption each read a measured quantity in nanoseconds against the live CoDel target (service rendered, queue backlog, accrued wait), so the question at every site is what a task is owed rather than what it is. `PF_WQ_WORKER` is the one flag read, at two sites and neither an ordering or placement decision: It splits the L2 hit/miss counters into two reporting buckets, and it carries a 1.5× multiplier on the nice weight that widens the standing slice ceiling.

### Adaptive Control Loop

The Rust control plane derives every knob from a measurement rather than a search. A derived knob is correct on the tick it is computed; a learned one is correct several convergence windows later and only if the regime holds still that long.

| Sensor | Primitive | Drives | Because |
|---|---|---|---|
| **depth** | mean per-CPU queue depth | the per-CPU slice | A deep queue slices shorter so it drains; a shallow one longer so it stops paying context-switch cost for contention that is not there |
| **critical slowing** | lag-1 autocorrelation | `preempt_thresh_ns` | Computed and written each tick. BPF does not read it; the tick's band is `codel_target_ns` |
| **traffic shape** | Kim-Jo burstiness | batch and burst ceilings | Bursty traffic wants a longer batch ceiling, paced traffic a shorter one |
| **persistence** | Veitch-Abry Hurst | the rescue threshold | A queue deep on a persistent CPU will still be deep, so rescue sooner |
| **coupling** | Pecora-Carroll, pairwise | nothing | Deriving affinity from it regressed every IPC primitive on every arm, worst pipe p50 20 → 336us |

- **One thread, zero mutexes**: A 1-second loop on the main thread reads the per-CPU BPF stats array and writes knobs BPF picks up on the next scheduling decision. Relating CPU *i* to CPU *j* is what BPF structurally cannot do, so the spatial dimension is the reason the loop exists.
- **Chaos primitives** (`chaos.rs`, pure Rust, recomputed each tick over a 16-sample raw window): HVG mean degree λ [10], Bandt–Pompe D=3 permutation entropy [9] and RQA determinism [11].
- **Live load graph**: Nodes are CPUs weighted by depth, traffic shape, critical slowing and persistence; edges are CPU pairs weighted by coupling. This is the graph the workload forms, which moves every second; the chip's electrical graph is a constant and R_eff already prices against it.
- **One controller on the rescue signal**: The oscillator owns `global_rescue_count` and nothing else adapts on it.
- **Quiescence freeze**: When the chaos signals sit in their steady band the loop latches frozen and skips the retune and knob write, still ticking at 1 Hz with the sensors as the thaw condition. Both terms of the freeze gate read the same `idle_pct` window, and a fully saturated box pins that window flat, so saturation can read as quiescence.

### Core-Count Scaling

All timing constants scale from `tau_ns = TAU_SCALE_NS / √(λ₂ · N)` [7], the geometric mean of connectivity `1/λ₂` and capacity `1/√N`, so a well-connected but core-starved topology loosens instead of tightening. The 12C reference is τ ≈ 13.3ms (λ₂ = 12, N = 12). The CoDel floor, ceiling and equilibrium, the starvation bounds, the spill and idle-search budgets and the longrun threshold all fall out of τ with safety-rail clamps, so a machine with a different topology gets different numbers by construction. The tick's four-CPU scan budget is the one count, taken from `nr_cpu_ids` directly.

- **Low-core slice discipline**: τ is largest at low core count, so the τ slice cap runs loosest exactly where a wide slice hurts most. The slice is capped to 1ms at `nr_cpus ≤ 4`; 8C and 12C keep the τ-scaled width.
- **CPU hotplug**: `cpu_online` and `cpu_offline` zero that CPU's backlog ledger, reset the oscillator's feedback and clear the τ snapshot, so the next CPU-0 tick re-derives every τ-scaled constant against the new topology.
- **Verifier-safe**: No floats in the BPF path, integer-only arithmetic throughout, and shared state through GCC `__sync` builtins.

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
  topology.rs          CPU topology detection, Laplacian pseudoinverse, effective
                         resistance, ranked peer lists, distance tables (sysfs -> BPF maps)
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
  pandemonium-tests.py Dev-tier orchestrator (scale, contention, pcpu, scx, sys,
                         low-cpu-deadline)
  prism.py             One-command shareable report (montauk digest, redacted --
                         specs + ranked offenders + metrics)
  prism-fork-thread.py Fork/thread IPC benchmark (full scx field) + hw counters
  prism-ipc.py         IPC round-trip by primitive (pipe, socket, eventfd, sem, fanout)
  prism-power.py       Energy-efficiency benchmark (RAPL J/op + idle floor)
  prism-strand.py      Pinned/stranded-task watchdog probe
  prism-cachyos.py     Comparison against the CachyOS scheduler set
  prism-plot.py        Plot rendering for captured runs
  ipc_workload.py      Shared IPC primitive drivers
  loadgen.c            Load generator (+ loadgen_common.[ch])
  *_gate.py            Non-compensatory regression gates (report, baseline,
                         quiescent tail, fold, install)
  gate.rs              Integration test gate (load/latency/responsiveness/contention)
include/
  scx/                 Vendored sched_ext headers
```

### Data Flow

```
BPF per-CPU histograms              Monitor Thread (1s loop)
(wake_lat_hist, sleep_hist)  --->   Read + drain histograms
                                    Compute aggregate P99
                                      |
                                      v
                                    per-CPU stats array -> live load graph
                                      -> base profile
                                      -> derive each knob from its own sensor
                                        (depth -> slice, shape -> batch/burst,
                                         persist -> rescue)
                                      -> quiescence freeze
                                      |
                                      v
                                    BPF reads knobs on next dispatch

Distance tables:  reff_value, reff_frac, domain_phi -> BPF steal, drain, placement
Sojourn scan:     codel_thresh_ns knob -> BPF tick() own CPU + rotating scan
CoDel target:     codel_target_ns (BPF-internal, damped oscillation, no Rust input)
Queue clocks:     queue_clock per DSQ (BPF-internal, written at insert and departure)
Cross-domain:     nr_cross_domain path counters -> telemetry (no actuation)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. The CoDel target and the queue clocks are fully BPF-internal.

### Tuning Knobs (BPF map)

| Knob | Default | Owner | Purpose |
|------|---------|-------|---------|
| `slice_ns` | 1ms | Derived (depth) | Base slice ceiling, every task |
| `preempt_thresh_ns` | 1ms | Derived (critical slowing) | Written, not read by BPF |
| `batch_slice_ns` | 20ms | Derived (traffic shape) | Standing slice ceiling, the grant for a task that has already held a CPU for a full target, capped at four live targets in BPF |
| `burst_slice_ns` | 1ms | Derived (traffic shape) | Base slice during longrun mode |
| `affinity_mode` | 0 | Base value | Written, not read by BPF |
| `codel_thresh_ns` | 5ms | Derived (persistence) | Age at which `tick()` kicks a CPU holding an aged waiter |
| `topology_tau_ns` | 0 | Topology | Fiedler-derived time constant, capacity-aware in core count; every other bound scales from it |
| `codel_eq_ns` | 0 | Topology | Spectral CoDel equilibrium, a position inside the target band |

The distance scale is not a knob. Rust folds it into the distance tables at topology detect, so BPF reads a price by index instead of multiplying at dispatch. Topology-owned fields are written at detect and on hotplug, and the adaptive loop preserves them on every write. The knob map is per-CPU, so `topology_tau_ns` and `codel_eq_ns` must hold the same value on every CPU, and the Rust writer broadcasts them from slot 0.

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

There is no compositor allowlist, no learned name database and no behavioural tier to
earn — there is no task class at all. Every site that once asked what a task *is* now
asks what it is *owed*, in nanoseconds, against the live CoDel target. Every session,
from cold, with nothing remembered.

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
| shared | Enqueue -> the domain's overflow DSQ |
| preempt | Tick preemptions |
| keep | KEEP_RUNNING re-slices |
| kick H/S | Hard (PREEMPT) / Soft kicks |
| enq W/R | Wakeup / Re-enqueue counts |
| wake / p99 | Average / aggregate P99 wakeup latency |
| [B/I/L] | Wakeup-latency P99 split by the `PF_WQ_WORKER` reporting bucket. `L` is a retired third lane and reads 0 always, since nothing writes it |
| lat_idle / lat_kick | Wakeup latency split: idle-placement vs kick path |
| sleep: io | I/O-wait sleep pattern (%) |
| slice / batch | Current base / standing slice knob (us) |
| reenq | Re-enqueue count |
| sjrn | Overflow wait age: current / threshold |
| rescue | Overflow rescue dispatches this tick |
| l2: B/I | L2 cache hit rate, same two reporting buckets |
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
./pandemonium.py prism --dev strand                   # Per-CPU kthread strand detection
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

Two capture options apply to every montauk capture in a run. `--kick-mode off|resched|full`
arms montauk's kick probes, and `--scx-dsq` records the DSQ every task was inserted into.
`--scx-dsq` fires on every enqueue and drops events under saturation, so it is read for
where tasks went and never to compare arms.

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

[7] M. Fiedler. "Algebraic Connectivity of Graphs." *Czechoslovak Mathematical Journal* 23(2), 298-305, 1973. [doi:10.21136/CMJ.1973.101168](https://dml.cz/dmlcz/101168)

[8] R.D. Blumofe, C.E. Leiserson. "Scheduling Multithreaded Computations by Work Stealing." *Journal of the ACM* 46(5), 720-748, 1999. [doi:10.1145/324133.324234](https://dl.acm.org/doi/10.1145/324133.324234)

[9] C. Bandt, B. Pompe. "Permutation Entropy: A Natural Complexity Measure for Time Series." *Physical Review Letters* 88(17), 174102, 2002. [doi:10.1103/PhysRevLett.88.174102](https://doi.org/10.1103/PhysRevLett.88.174102)

[10] B. Luque, L. Lacasa, F. Ballesteros, J. Luque. "Horizontal Visibility Graphs: Exact Results for Random Time Series." *Physical Review E* 80(4), 046103, 2009. [doi:10.1103/PhysRevE.80.046103](https://doi.org/10.1103/PhysRevE.80.046103)

[11] N. Marwan, M.C. Romano, M. Thiel, J. Kurths. "Recurrence Plots for the Analysis of Complex Systems." *Physics Reports* 438(5-6), 237-329, 2007. [doi:10.1016/j.physrep.2006.11.001](https://doi.org/10.1016/j.physrep.2006.11.001)

[12] S. Butterworth. "On the Theory of Filter Amplifiers." *Experimental Wireless and the Wireless Engineer* 7, 536-541, 1930.

## License

GPL-2.0
