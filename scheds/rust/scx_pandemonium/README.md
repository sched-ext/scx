# PANDEMONIUM

Built in Rust and C23, PANDEMONIUM is a Linux kernel scheduler built for sched_ext. Utilizing BPF patterns, PANDEMONIUM classifies every task by its behavior--wakeup frequency, context switch rate, runtime, sleep patterns--and adapts scheduling decisions in real time. Single-thread adaptive control loop (zero mutexes), three-tier behavioral dispatch, overflow sojourn rescue, longrun detection with deficit tightening, dual burst detection (CUSUM + wakeup rate), L2 cache affinity placement, sleep-informed batch tuning, CoDel-inspired sojourn rescue, classification-gated DSQ routing, workload regime detection, vtime ceiling, hard starvation rescue, and a persistent process database that learns task classifications across lifetimes.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_layered, scx_cosmos, and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE and Arch communities within the Linux ecosystem.

## Performance

Benchmarked on 12 AMD Zen CPUs, kernel 6.18.13-arch1-1, clang 21.1.6, 3 iterations.

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 2,773us  | 1,228us           | **821us**              | 3,181us     |
| 4     | 2,883us  | **1,285us**       | 1,594us                | 2,005us     |
| 8     | 2,886us  | **1,092us**       | 1,239us                | 2,006us     |
| 12    | 2,280us  | 1,231us           | **1,021us**            | 2,007us     |

Both modes beat EEVDF and scx_bpfland at every core count. Overflow sojourn rescue and dual burst detection (CUSUM + wakeup rate) keep burst response sub-2ms.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 1,953us  | 1,922us           | **929us**              | 3,060us     |
| 4     | 1,358us  | **1,012us**       | 1,690us                | 2,011us     |
| 8     | 1,711us  | **1,041us**       | 830us                  | 2,005us     |
| 12    | **718us**| 909us             | 1,284us                | 2,007us     |

ADAPTIVE wins at 2C, BPF beats EEVDF at 4C and 8C. Both modes beat scx_bpfland at every core count.

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 2,295us  | **440us**         | 568us                  | 2,020us     |
| 4     | 1,395us  | **912us**         | 1,338us                | 2,001us     |
| 8     | **557us**| 1,009us           | 1,741us                | 2,005us     |
| 12    | **418us**| 993us             | 1,957us                | 1,999us     |

Longrun detection tightens deficit ratio to 1:1 under sustained batch pressure. BPF mode sub-1ms at 2C and 4C.

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 2,759us  | **520us**         | 1,026us                | 2,167us     |
| 4     | **974us**| 1,075us           | 1,386us                | 1,999us     |
| 8     | 2,183us  | **968us**         | 1,217us                | 2,004us     |
| 12    | 2,100us  | **999us**         | 1,737us                | 2,000us     |

BPF mode sub-1ms at 2C, 8C, and 12C under mixed interactive+batch workloads.

### Throughput (kernel build, vs EEVDF baseline, 3 iterations)

| Cores | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|-------------------|------------------------|-------------|
| 2     | +2.6%             | +18.8%                 | +5.2%       |
| 4     | +3.5%             | +2.7%                  | +0.4%       |
| 8     | +3.9%             | +2.9%                  | +3.8%       |
| 12    | +1.7%             | +0.6%                  | +1.9%       |

### Deadline Jitter (16.6ms frame target, miss ratio)

| Cores | EEVDF   | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|---------|-------------------|------------------------|-------------|
| 8     | 11.3%   | **8.1%**          | **4.3%**               | 56.5%       |
| 12    | 11.9%   | **4.4%**          | **6.8%**               | 56.3%       |

At 8+ cores, PANDEMONIUM ADAPTIVE misses 4.3% of frame deadlines at 8C. BPF mode hits 4.4% at 12C vs EEVDF's 11.9%. scx_bpfland misses 56%.

## Key Features

### Dispatch Order

0. Overflow sojourn rescue (aging overflow DSQ tasks > threshold, deficit-gated)
1. Per-CPU DSQ (direct placement from enqueue, zero contention, counts toward deficit)
2. Deficit counter (DRR: force batch if budget exhausted + starving; longrun tightens budget)
3. Hard starvation rescue (core-count-scaled absolute safety net)
4. Node interactive overflow (LAT_CRITICAL + INTERACTIVE, vtime-ordered)
5. Batch sojourn rescue (CoDel: rescue if oldest batch > threshold)
6. Node batch overflow (normal fallback for batch tasks)
7. Cross-node steal (interactive + batch per remote node)
8. KEEP_RUNNING if prev still wants CPU and nothing queued

### Three-Tier Enqueue

- **Idle CPU Fast Path**: `select_cpu()` places wakeups directly to per-CPU DSQ (depth-gated: 1 slot at <4 CPUs, 2 at 4+), kicks with `SCX_KICK_IDLE`
- **Node-Local Placement with L2 Affinity**: `enqueue()` tries L2 sibling first (INTERACTIVE/BATCH with affinity_mode > 0), then falls back to any idle CPU within the NUMA node, always dispatching to the per-node shared DSQ. LAT_CRITICAL and kernel threads (PF_KTHREAD) skip affinity for fastest-available placement
- **Wakeup Preemption**: All wakeups get node DSQ dispatch with `SCX_KICK_PREEMPT`. A task waking from sleep has external input to deliver regardless of behavioral tier. The classifier operates on historical behavior; the wakeup is the real-time latency signal. LAT_CRITICAL also gets preemption on requeue (compositor guarantee). Batch requeues skip to overflow DSQ
- **NUMA-Scoped Overflow**: Per-node overflow DSQ with classification-gated routing. Immature INTERACTIVE tasks (`ewma_age < 2`) route to batch DSQ until EWMA classifies them. LAT_CRITICAL tasks are never redirected
- **Event-Driven Preemption**: `tick()` checks `interactive_waiting` flag and preempts batch tasks above `preempt_thresh_ns`. During `burst_mode`, preempt threshold drops to 0 (immediate preemption). Zero polling -- no BPF timer

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes all downstream anti-starvation logic unreachable -- 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch Step 0 checks both overflow DSQs for tasks aging past `overflow_sojourn_rescue_ns` (core-count-scaled: 2ms per core, clamped 4-10ms) and serves them before per-CPU DSQ. CAS-based timestamp management prevents races across CPUs.

### Longrun Detection

Tracks sustained batch DSQ pressure. When batch DSQ is non-empty for >2 seconds, `longrun_mode` activates:
- Deficit ratio tightens from `nr_cpu_ids * ratio` to `nr_cpu_ids * 1`, quadrupling batch dispatch share
- `task_slice()` uses `burst_slice_ns` (1ms) instead of regime slice (up to 4ms)
- Rust adaptive layer: sleep-informed batch adjustment skipped, affinity forced to WEAK (spread batch across CPUs)

### Dual Burst Detection

- **CUSUM**: Statistical change-point detection (Page, 1954) monitors total enqueue rate. Samples every 64th enqueue, EWMA baseline with 25% slack. Effective for BPF mode (1ms slices) where enqueue rate spikes during fork storms
- **Wakeup Rate Counter**: Absolute threshold -- `nr_cpu_ids * 2` wakeups per tick = fork storm. No calibration needed, works immediately on first tick. Effective for adaptive mode (4ms slices) where CUSUM is rate-bounded
- Either firing activates `burst_mode`: preempt threshold drops to 0, task_slice uses `burst_slice_ns`
- Split DSQ routing always active. Burst handled via slice reduction and preempt override, not DSQ reorganization

### Vtime Ceiling

High-vtime daemons sort to the tail of the batch DSQ while fresh burst tasks take the head. Sojourn rescue dispatches from the head, so daemons starve. The ceiling caps batch deadline at `vtime_now + 30ms`, keeping every task within 6 sojourn cycles of the head. Gated at >=8 cores -- at 2-4 cores the batch DSQ is shallow enough that sojourn rescue reaches every task naturally.

### Hard Starvation Rescue

Absolute safety net. Computed as the minimum of two linear functions: `min(25ms * nr_cpus, 500ms / max(1, nr_cpus/4))`, clamped to 20-500ms. Short at low core counts (fast starvation: 2C = 50ms) and at high core counts (dispatch contention: 128C = 20ms), peaks in the middle (8C = 200ms). Fires before the interactive DSQ and guarantees batch service regardless of interactive pressure.

### Batch DSQ Separation

Batch tasks enqueue to dedicated per-node batch overflow DSQs instead of sharing vtime-ordered DSQs with interactive tasks. Separate DSQs give dispatch explicit control: interactive overflow first, then sojourn rescue, then batch fallback.

### CoDel Sojourn Rescue

`batch_enqueue_ns` records when the batch DSQ transitions from empty to non-empty. `dispatch()` rescues batch tasks waiting longer than `sojourn_thresh_ns`. The threshold is set by the Rust adaptive layer from observed dispatch rate: target = 4x dispatch interval, EWMA-smoothed (7/8 old + 1/8 new), clamped to core-count-aware floor/ceiling.

### Deficit Counter (DRR)

After `interactive_budget` consecutive interactive dispatches without batch service, forces one batch dispatch. Budget scales with core count: `nr_cpus * ratio` where ratio = `min(4, 2 + nr_cpus/2)` (2C: 6, 4C+: same as nr_cpus * 4). Per-CPU DSQ dispatches count toward the deficit. During longrun mode, budget tightens to `nr_cpu_ids * 1`.

### Behavioral Classification

- **Latency-Criticality Score**: `lat_cri = (wakeup_freq * csw_rate) / effective_runtime` where `effective_runtime = avg_runtime + (runtime_dev >> 1)`
- **Three Tiers**: LAT_CRITICAL (1.5x avg_runtime slices, preemptive kicks), INTERACTIVE (2x avg_runtime), BATCH (configurable ceiling via adaptive layer)
- **EWMA Classification**: All tasks go through full EWMA classification in `runnable()`. Wakeup frequency, context switch rate, and runtime variance drive `lat_cri` scoring
- **CPU-Bound Demotion**: Tasks with avg_runtime above `cpu_bound_thresh_ns` (regime-dependent) are demoted from INTERACTIVE to BATCH. Reversed when the task sleeps
- **Kworker Floor**: Workqueue workers (PF_WQ_WORKER) floor at TIER_INTERACTIVE -- kernel I/O completion handlers are latency-critical infrastructure regardless of EWMA score
- **Compositor Boosting**: BPF hash map populated by Rust at startup. Default compositors (kwin, gnome-shell, mutter, sway, Hyprland, picom, weston, labwc, wayfire, niri) always LAT_CRITICAL. User-extensible via `--compositor` CLI flag

### L2 Cache Affinity

- **Active Placement**: `find_idle_l2_sibling()` in enqueue Tier 1 finds idle CPUs in the same L2 domain. Bounded loop (max 8 iterations), verifier-safe
- **Affinity Mode**: Per-regime knob (LIGHT=WEAK, MIXED=STRONG, HEAVY=WEAK). Longrun overrides to WEAK
- **Kernel Thread Bypass**: kworkers and ksoftirqd (PF_KTHREAD) skip L2 affinity entirely
- **Per-Dispatch Tracking**: Every dispatch compares the selected CPU's L2 domain against the task's last CPU
- **Per-Tier Hit/Miss Counters**: Separate L2 hit rates for BATCH, INTERACTIVE, and LAT_CRITICAL tiers

### Process Classification Database (procdb)

- **Cross-Lifecycle Learning**: BPF publishes mature task profiles (tier + avg_runtime) keyed by `comm[16]` to an observation map
- **Confidence Scoring**: Rust ingests observations, tracks EWMA convergence stability, and promotes profiles to "confident" when avg_runtime stabilizes
- **Warm-Start on Spawn**: `enable()` applies learned classification from prior runs
- **EWMA Validation**: Confident tasks still run through full behavioral classification in `runnable()`. ProcDb provides the initial state; EWMA validates and corrects
- **Persistent Memory**: Saved to `~/.cache/pandemonium/procdb.bin` on shutdown (atomic write). Zero cold-start penalty after the first run
- **Deterministic Eviction**: When the profile cache is full, eviction sorts by (staleness, observations, comm)

### Sleep-Aware Scheduling

- **quiescent() Callback**: Records sleep timestamp
- **Sleep Duration Tracking**: `running()` classifies sleep into BPF per-CPU histogram (IO-WAIT / SHORT IO / MODERATE / IDLE)
- **Sleep-Informed Batch Tuning**: IO-heavy (>60% io_pct) extends batch slices +25%, idle-heavy (<15%) tightens -25%, dead zone unchanged. 25ms ceiling. Skipped during longrun mode
- **Wakeup Latency Histograms**: Per-CPU BPF histograms (3 tiers x 12 buckets), approximately 20ns per wakeup

### Adaptive Control Loop

- **One Thread, Zero Mutexes**: Single monitor thread, 1-second control loop. Reads BPF histogram maps, computes P99, adjusts knobs
- **Workload Regime Detection**: LIGHT (idle >50%), MIXED (10-50%), HEAVY (<10%) with Schmitt trigger hysteresis and 2-tick hold
- **Regime Profiles**:
  - LIGHT: slice 2ms, preempt 1ms, batch 20ms, affinity WEAK
  - MIXED: slice 1ms, preempt 1ms, batch 20ms (scaled: nr_cpus * 5ms cap), affinity STRONG
  - HEAVY: slice 4ms, preempt 2ms, batch 20ms, affinity WEAK
- **Knob Adjustment Layering**:
  1. `regime_knobs()` sets baseline
  2. `sleep_adjust_batch_ns()` adjusts for IO/idle pattern (skipped during longrun)
  3. Dispatch-rate sojourn threshold (EWMA, core-count-aware floor/ceil)
  4. Tighten check: P99 above ceiling tightens slice_ns by 25% (MIXED only)
  5. Graduated relax: step back toward baseline by 500us/tick with 2-second hold
  6. Longrun override: force WEAK affinity, skip sleep adjustment
- **Core-Count-Aware Sojourn**: Floor = `clamp(nr_cpus * 1ms, 2ms, 6ms)`, ceiling = floor * 2. Dispatch rate normalized to actual elapsed time (not assumed 1s)
- **P99 Ceilings**: LIGHT 3ms, MIXED 5ms, HEAVY 10ms

### Core-Count Scaling

All scheduling parameters scale dynamically with `nr_cpus` using clamped linear formulas. No special-casing, no lookup tables -- every value is a calculation.

| Parameter | Formula | 2C | 4C | 8C | 12C |
|-----------|---------|----|----|----|----|
| Sojourn floor | `clamp(nr_cpus * 1ms, 2ms, 6ms)` | 2ms | 4ms | 6ms | 6ms |
| Sojourn ceiling | `floor * 2` | 4ms | 8ms | 12ms | 12ms |
| Overflow rescue | `clamp(nr_cpus * 2ms, 4ms, 10ms)` | 4ms | 8ms | 10ms | 10ms |
| Starvation rescue | `clamp(min(25ms * N, 500ms / max(1,N/4)), 20ms, 500ms)` | 50ms | 100ms | 200ms | 167ms |
| Deficit budget | `nr_cpus * min(4, 2 + nr_cpus/2)` | 6 | 16 | 32 | 48 |
| Per-CPU DSQ depth | `nr_cpus < 4 ? 1 : 2` | 1 | 2 | 2 | 2 |
| Mixed batch cap | `nr_cpus * 5ms` (no-op above base) | 10ms | 20ms | 20ms | 20ms |
| Mixed slice cap | `nr_cpus * 500us` (no-op above base) | 1ms | 1ms | 1ms | 1ms |

- **CPU Hotplug**: `cpu_online`/`cpu_offline` callbacks prevent sched_ext auto-exit during CPU restriction
- **Topology Detection**: Parses sysfs for physical packages, L2/L3 cache domains, NUMA nodes
- **BPF-Verifier Safe**: All EWMA uses bit shifts, no floats. All shared state uses GCC __sync builtins (CAS, atomic add, test-and-set)

## Architecture

```
pandemonium.py           Build/install/benchmark manager (Python)
pandemonium_common.py    Shared infrastructure (logging, build, CPU management,
                           scheduler detection, tracefs, statistics)
export_scx.py            Automated import into sched-ext/scx monorepo
src/
  main.rs              Entry point, CLI, scheduler loop, telemetry
  scheduler.rs         BPF skeleton lifecycle, tuning knobs I/O, histogram reads
  adaptive.rs          Adaptive control loop (single monitor thread, histogram P99,
                         sleep adjustment, sojourn threshold, tighten/relax,
                         longrun override, core-count-aware sojourn)
  tuning.rs            Regime knobs, stability scoring, sleep adjustment
  procdb.rs            Process classification database (observe -> learn -> predict -> persist)
  topology.rs          CPU topology detection (sysfs -> cache_domain + l2_siblings BPF maps)
  event.rs             Pre-allocated ring buffer for stats time series
  log.rs               Logging macros
  lib.rs               Library root
  bpf/
    main.bpf.c         BPF scheduler (GNU C23)
    intf.h             Shared structs: tuning_knobs, pandemonium_stats, task_class_entry
  cli/
    mod.rs             Shared constants, helpers
    check.rs           Dependency + kernel config verification
    run.rs             Build, sudo execution, dmesg, log management
    bench.rs           A/B benchmarking
    probe.rs           Interactive wakeup probe
    report.rs          Statistics, formatting
    test_gate.rs       Test gate orchestration
    child_guard.rs     RAII child process guard
    death_pipe.rs      Orphan detection via pipe POLLHUP
build.rs               vmlinux.h generation + C23 patching + BPF compilation
tests/
  pandemonium-tests.py Test orchestrator (bench-scale, bench-trace, bench-contention,
                         bench-pcpu, bench-scx)
  contention.rs        Contention stress tests (44 tests: sojourn, relax, tighten,
                         longrun, sleep-informed batch, regime hold, P99 histogram)
  adaptive.rs          Adaptive layer tests (29 tests: regime, stability, sleep, telemetry)
  event.rs             Unit tests (ring buffer)
  procdb.rs            Process database tests (26 tests: confidence, eviction, persistence)
  scale.rs             Latency scaling benchmark
include/
  scx/                 Vendored sched_ext headers
```

### BPF Scheduler (main.bpf.c)

```
select_cpu()  ->  Idle CPU found?  ->  Per-CPU DSQ (depth-gated, KICK_IDLE)
                      |                  (depth: 1 at <4C, 2 at 4C+)
                      v (no)
enqueue()     ->  L2 sibling idle?  ->  Node DSQ + kick (L2-affine placement)
                  (skip for LAT_CRITICAL    |
                   and kernel threads)      v (no)
              ->  Wakeup or          ->  Node DSQ + KICK_PREEMPT
                  LAT_CRITICAL?          (all wakeups, any tier)
                      |
                      v (batch requeue)
              ->  BATCH or immature  ->  Per-node batch overflow DSQ (sojourn tracked)
                  INTERACTIVE?           (classification gate: ewma_age < 2)
                  (vtime ceiling at       |
                   >=8 cores)             v (classified INTERACTIVE)
              ->  Per-node interactive overflow DSQ

dispatch()    ->  Overflow sojourn rescue (core-count-scaled threshold, deficit-gated)
              ->  Per-CPU DSQ (direct placement, counts toward deficit)
              ->  Deficit counter (DRR: force batch if budget + starving, longrun tightens)
              ->  Hard starvation rescue (core-count-scaled safety net)
              ->  Node interactive overflow (LAT_CRITICAL + INTERACTIVE)
              ->  Batch sojourn rescue (CoDel: rescue if oldest > threshold)
              ->  Node batch overflow (normal fallback)
              ->  Cross-node steal (interactive + batch per remote node)
              ->  KEEP_RUNNING if nothing queued

tick()        ->  Burst detection (CUSUM + wakeup rate -> burst_mode)
              ->  Longrun detection (batch DSQ non-empty >2s -> longrun_mode)
              ->  Sojourn enforcement (kick batch CPUs when batch DSQ starving)
              ->  interactive_waiting?  ->  Preempt batch (thresh=0 during burst)
```

### Adaptive Layer (adaptive.rs)

```
BPF per-CPU histograms              Monitor Thread (1s loop)
(wake_lat_hist, sleep_hist)  --->   Read + drain histograms
                                    Compute P99 per tier
                                      |
                                      v
                                    regime_knobs() -> baseline
                                      -> sleep_adjust_batch_ns() (skip if longrun)
                                        -> dispatch-rate sojourn threshold (core-count-aware)
                                          -> tighten check -> P99 ceiling
                                            -> graduated relax -> step toward baseline
                                      -> longrun override -> WEAK affinity, base batch
                                      |
                                      v
                                    BPF reads knobs on next dispatch

L2 placement:      affinity_mode knob -> BPF enqueue (WEAK during longrun)
Sojourn threshold: sojourn_thresh_ns knob -> BPF dispatch (core-count-scaled)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the very next scheduling decision.

### Process Database (procdb.rs)

```
BPF stopping()                    Rust monitor                    BPF enable()
  |                                |                                |
  v                                v                                v
task_class_observe  -------->  ingest()  -------->  task_class_init
(comm -> tier, avg_runtime)    confidence scoring   (comm -> tier, avg_runtime)
                               EWMA convergence     warm-start -> EWMA validates
                               detection

~/.cache/pandemonium/procdb.bin
  ^                    |
  |  save() on         |  load() on startup
  |  shutdown          |  -> flush_predictions()
  |  (atomic write)    v
  +--- Rust monitor ---+
```

### Tuning Knobs (BPF map)

| Knob | Default | Purpose |
|------|---------|---------|
| `slice_ns` | 1ms | Interactive/lat_cri slice ceiling |
| `preempt_thresh_ns` | 1ms | Tick preemption threshold (0 during burst) |
| `lag_scale` | 4 | Deadline lag multiplier (higher = more vtime credit) |
| `batch_slice_ns` | 20ms | Batch task slice ceiling (sleep-adjusted) |
| `burst_slice_ns` | 1ms | Slice ceiling during burst/longrun mode |
| `cpu_bound_thresh_ns` | 2.5ms | CPU-bound demotion threshold (regime-dependent) |
| `lat_cri_thresh_high` | 32 | Classifier: LAT_CRITICAL threshold |
| `lat_cri_thresh_low` | 8 | Classifier: INTERACTIVE threshold |
| `affinity_mode` | 1 | L2 placement (0=OFF, 1=WEAK, 2=STRONG) |
| `sojourn_thresh_ns` | 5ms | Batch DSQ rescue threshold (set by Rust, core-count-aware) |

## Requirements

- Linux kernel 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`
- Rust toolchain
- clang (BPF compilation)
- system libbpf
- bpftool (first build only -- generates vmlinux.h, can be uninstalled after)
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

vmlinux.h is generated from the running kernel's BTF via bpftool on first build and cached at `~/.cache/pandemonium/vmlinux.h`. Subsequent builds use the cache -- bpftool is not needed after the first build.

After install, start and enable manually:

```bash
sudo systemctl start pandemonium          # Start now (one-time)
sudo systemctl enable pandemonium         # Start on boot (after confirming it works)
```

Note: the source directory path contains spaces, so `CARGO_TARGET_DIR=/tmp/pandemonium-build` is required for the vendored libbpf Makefile.

## Usage

```bash
# Run the scheduler (default: adaptive mode)
sudo pandemonium

# BPF-only mode (no Rust adaptive control loop)
sudo pandemonium --no-adaptive

# Override CPU count for scaling formulas
sudo pandemonium --nr-cpus 4

# Add custom compositor process names (boosted to LAT_CRITICAL)
sudo pandemonium --compositor gamescope --compositor picom-next

# Subcommands
pandemonium check        # Verify dependencies and kernel config
pandemonium start        # Build + sudo run + dmesg capture + log management
pandemonium bench        # A/B benchmark (EEVDF vs PANDEMONIUM)
pandemonium test         # Full test gate (unit + integration)
pandemonium test-scale   # A/B scaling benchmark with CPU hotplug
pandemonium probe        # Standalone interactive wakeup probe
pandemonium dmesg        # Filtered kernel log for sched_ext/pandemonium
```

### Monitoring

Per-second telemetry (printed to stdout while running):

```
d/s: 251000  idle: 5% shared: 230000  preempt: 12  keep: 0  kick: H=8000 S=22000 enq: W=8000 R=22000 wake: 4us p99: 10us L2: B=67% I=72% LC=85% procdb: 42/5 sleep: io=87% sjrn: 3ms/5ms rescue: 0 [MIXED]
```

During fork/exec storms, burst mode activates:

```
d/s: 380000  idle: 1% shared: 360000  preempt: 45  keep: 0  kick: H=15000 S=35000 enq: W=15000 R=35000 wake: 12us p99: 85us L2: B=45% I=68% LC=82% procdb: 42/5 sleep: io=92% sjrn: 1ms/5ms rescue: 3 [HEAVY BURST]
```

During sustained batch pressure, longrun mode activates:

```
d/s: 180000  idle: 2% shared: 170000  preempt: 8  keep: 0  kick: H=6000 S=18000 enq: W=6000 R=18000 wake: 6us p99: 15us L2: B=55% I=70% LC=80% procdb: 42/5 sleep: io=30% sjrn: 8ms/10ms rescue: 1 [HEAVY LONGRUN]
```

| Counter | Meaning |
|---------|---------|
| d/s | Total dispatches per second |
| idle | Placed via select_cpu idle fast path (%) |
| shared | Enqueue -> per-node DSQ |
| preempt | Tick preemptions (batch task yielded) |
| kick H/S | Hard (PREEMPT) / Soft (nudge) kicks |
| enq W/R | Wakeup / Re-enqueue counts |
| wake | Average wakeup-to-run latency |
| p99 | P99 wakeup latency (from histogram) |
| L2: B/I/LC | L2 cache hit rate per tier (Batch/Interactive/Lat_Critical) |
| procdb | Total profiles / confident predictions |
| sleep: io | I/O-wait sleep pattern percentage |
| sjrn | Batch sojourn: current wait / threshold (ms) |
| rescue | Overflow sojourn rescue dispatches this tick |
| [REGIME] | Current workload regime (LIGHT/MIXED/HEAVY) |
| BURST | Burst detection active (CUSUM or wakeup rate) |
| LONGRUN | Sustained batch pressure detected (>2s) |

## Benchmarking

```bash
# Full benchmark (throughput + latency + burst + longrun + mixed + deadline + IPC + launch)
./pandemonium.py bench-scale
./pandemonium.py bench-scale --iterations 3
./pandemonium.py bench-scale --iterations 3 --core-counts 4,8,12
./pandemonium.py bench-scale --burst       # Burst-only mode
./pandemonium.py bench-scale --longrun     # Longrun-only mode
./pandemonium.py bench-scale --mixed       # Mixed-only mode (burst + longrun combined)
./pandemonium.py bench-scale --deadline    # Deadline jitter only
./pandemonium.py bench-scale --ipc         # IPC round-trip latency only
./pandemonium.py bench-scale --launch      # Fork/exec launch latency only

# Crash-detection stress test with BPF trace capture
./pandemonium.py bench-trace
./pandemonium.py bench-trace --iterations 3 --core-counts 4,8,12

# Contention stress test (6 phases targeting adaptive features)
./pandemonium.py bench-contention
./pandemonium.py bench-contention --iterations 3 --core-counts 4,8,12
./pandemonium.py bench-contention --phase regime-sweep   # Single phase

# Per-CPU DSQ correctness (burst, steal balance, sojourn rescue)
./pandemonium.py bench-pcpu
./pandemonium.py bench-pcpu --core-counts 4,8,12

# sched-ext/scx CI compatibility (functional + stress-ng)
./pandemonium.py bench-scx
./pandemonium.py bench-scx --core-counts 2
./pandemonium.py bench-scx --duration 60 --stress-duration 60
```

All benchmarks compare across core counts via CPU hotplug (2, 4, 8, ..., max). Results are archived to `~/.cache/pandemonium/` in Prometheus exposition format (.prom) for cross-build regression tracking. Human-readable reports are saved as .log files.

## Testing

```bash
# Unit tests (no root required)
CARGO_TARGET_DIR=/tmp/pandemonium-build cargo test --release

# Full test gate (requires root + sched_ext kernel)
pandemonium test

# Scaling benchmark (EEVDF vs PANDEMONIUM, CPU hotplug, requires root)
./pandemonium.py bench-scale
```

110 tests across 6 test files:

| File | Tests | Coverage |
|------|-------|----------|
| tests/contention.rs | 44 | Sojourn EWMA, graduated relax, tighten/spike detection, longrun override, sleep-informed batch, regime hold hysteresis, P99 histogram edge cases, stability score |
| tests/adaptive.rs | 29 | Regime detection, tuning knobs, stability scoring, sleep adjustment, telemetry gating |
| tests/procdb.rs | 26 | Profile confidence, eviction, persistence, determinism |
| src/main.rs | 6 | Topology parsing |
| tests/event.rs | 5 | Ring buffer, snapshot, summary |
| tests/gate.rs | 5 | BPF lifecycle, latency (require root, ignored offline) |

## sched-ext/scx Integration

PANDEMONIUM is included in the sched-ext/scx monorepo. `export_scx.py` automates the import:

```bash
./export_scx.py /path/to/scx
```

The script copies source files into `scheds/rust/scx_pandemonium/`, renames the crate, strips `[profile.release]` (the workspace provides its own), replaces `build.rs` with a `scx_cargo::BpfBuilder` version, swaps `libbpf-cargo` for `scx_cargo` in build dependencies, registers the workspace member, and runs `cargo fmt`.

## Attribution

- `include/scx/*` headers from the [sched_ext](https://github.com/sched-ext/scx) project (GPL-2.0)
- vmlinux.h generated from the running kernel's BTF (cached after first build)
- Included in the [sched-ext/scx](https://github.com/sched-ext/scx) project

## License

GPL-2.0
