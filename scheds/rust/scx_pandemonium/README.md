# PANDEMONIUM

Built in Rust and C23, PANDEMONIUM is a Linux kernel scheduler built for sched_ext. Utilizing BPF patterns, PANDEMONIUM classifies every task by its behavior--wakeup frequency, context switch rate, runtime, sleep patterns--and adapts scheduling decisions in real time. Single-thread adaptive control loop (zero mutexes), three-tier behavioral dispatch, overflow sojourn rescue, longrun detection with deficit tightening, dual burst detection (CUSUM + wakeup rate), L2 cache affinity placement, sleep-informed batch tuning, CoDel-inspired sojourn rescue, classification-gated DSQ routing, workload regime detection, vtime ceiling, hard starvation rescue, and a persistent process database that learns task classifications across lifetimes.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_layered, scx_cosmos, and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext and CachyOS communities within the Linux ecosystem.

## Performance

Benchmarked on 12 AMD Zen CPUs, kernel 6.18.9-arch1-2, clang 21.1.6.

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 2,162us  | **69us**          | 81us                   | --          |
| 4     | 4,000us  | **85us**          | 85us                   | 2,004us     |
| 8     | 2,342us  | **73us**          | 81us                   | 2,004us     |
| 12    | 1,999us  | **77us**          | 112us                  | 2,004us     |

Overflow sojourn rescue and dual burst detection (CUSUM + wakeup rate) keep burst P99 at 69-112us. Interactive tasks are invisible to fork storms -- burst P99 is within 2x of steady-state baseline.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 1,941us  | **69us**          | 81us                   | --          |
| 4     | 1,167us  | 1,100us           | **151us**              | 2,006us     |
| 8     | 56us     | 71us              | **70us**               | 2,005us     |
| 12    | 59us     | 83us              | **73us**               | 2,004us     |

ADAPTIVE P99 beats EEVDF at 4C, matches at 8C and 12C. BPF mode beats EEVDF at 2C. Both modes beat scx_bpfland at every core count.

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF    | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|----------|-------------------|------------------------|-------------|
| 2     | 2,589us  | **161us**         | 77us                   | --          |
| 4     | 1,014us  | **72us**          | 69us                   | 2,004us     |
| 8     | 68us     | 71us              | **98us**               | 2,004us     |
| 12    | 79us     | **74us**          | 75us                   | 2,002us     |

Longrun detection tightens deficit ratio from 4:1 to 1:1 under sustained batch pressure, keeping interactive latency sub-100us even with persistent CPU-bound processes.

### Throughput (kernel build, vs EEVDF baseline, 3 iterations)

| Cores | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|-------------------|------------------------|-------------|
| 2     | +5.3%             | +9.4%                  | +5.2%       |
| 4     | +0.2%             | +0.7%                  | +0.2%       |
| 8     | +2.6%             | +0.9%                  | +2.8%       |
| 12    | +3.2%             | +1.2%                  | +3.3%       |

### Deadline Jitter (16.6ms frame target)

| Cores | EEVDF   | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|---------|-------------------|------------------------|-------------|
| 8     | 12.4%   | **0.2%**          | **0.2%**               | 56.8%       |
| 12    | 10.5%   | **7.1%**          | **6.9%**               | 58.6%       |

At 8+ cores, PANDEMONIUM misses fewer than 1% of frame deadlines vs EEVDF's 10-12%. scx_bpfland misses 57%.

### Contention Stress Test (bench-contention)

6 phases targeting adaptive mechanisms, all core counts (2, 4, 8, 12):

| Phase              |  2C P99 |  4C P99 |  8C P99 | 12C P99 | Status |
|--------------------|---------|---------|---------|---------|--------|
| deficit-storm      |   755us |   126us |   153us |    77us | PASS   |
| sojourn-pressure   |    79us |    66us |    69us |    74us | PASS   |
| longrun-interactive|    64us |    62us |    66us |    64us | PASS   |
| burst-recovery     |    77us |    77us |    77us |    78us | PASS   |
| mixed-storm        |   155us |    65us |    64us |    66us | PASS   |

Zero crashes, zero deadline misses (0/1794 per core count), longrun fairness 0.94-1.00 across all core counts. Burst recovery P99 returns to baseline immediately.

## Key Features

### Dispatch Order

0. Overflow sojourn rescue (aging overflow DSQ tasks > 10ms, deficit-gated)
1. Per-CPU DSQ (direct placement from enqueue, zero contention, counts toward deficit)
2. Deficit counter (DRR: force batch if budget exhausted + starving; longrun tightens budget)
3. Hard starvation rescue (absolute 500ms safety net, core-count-scaled)
4. Node interactive overflow (LAT_CRITICAL + INTERACTIVE, vtime-ordered)
5. Batch sojourn rescue (CoDel: rescue if oldest batch > threshold)
6. Node batch overflow (normal fallback for batch tasks)
7. Cross-node steal (interactive + batch per remote node)
8. KEEP_RUNNING if prev still wants CPU and nothing queued

### Three-Tier Enqueue

- **Idle CPU Fast Path**: `select_cpu()` places wakeups directly to per-CPU DSQ with zero contention, kicks with `SCX_KICK_IDLE`
- **Node-Local Placement with L2 Affinity**: `enqueue()` tries L2 sibling first (INTERACTIVE/BATCH with affinity_mode > 0), then falls back to any idle CPU within the NUMA node. LAT_CRITICAL and kernel threads (PF_KTHREAD) skip affinity for fastest-available placement
- **Wakeup Preemption**: All wakeups get per-CPU DSQ dispatch with `SCX_KICK_PREEMPT`. A task waking from sleep has external input to deliver regardless of behavioral tier. The classifier operates on historical behavior; the wakeup is the real-time latency signal. LAT_CRITICAL also gets preemption on requeue (compositor guarantee). Batch requeues skip to overflow DSQ
- **NUMA-Scoped Overflow**: Per-node overflow DSQ with classification-gated routing. Immature INTERACTIVE tasks (`ewma_age < 2`) route to batch DSQ until EWMA classifies them. LAT_CRITICAL tasks are never redirected
- **Event-Driven Preemption**: `tick()` checks `interactive_waiting` flag and preempts batch tasks above `preempt_thresh_ns`. During `burst_mode`, preempt threshold drops to 0 (immediate preemption). Zero polling -- no BPF timer

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes all downstream anti-starvation logic unreachable -- 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch Step 0 checks both overflow DSQs for tasks aging past 10ms and serves them before per-CPU DSQ. CAS-based timestamp management prevents races across CPUs.

### Longrun Detection

Tracks sustained batch DSQ pressure. When batch DSQ is non-empty for >2 seconds, `longrun_mode` activates:
- Deficit ratio tightens from `nr_cpu_ids * 4` to `nr_cpu_ids * 1`, quadrupling batch dispatch share
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

Absolute safety net: `starvation_rescue_ns = 500ms / (nr_cpu_ids/4)`, floor 50ms. Fires before the interactive DSQ and guarantees batch service regardless of interactive pressure. Catches cases where the deficit counter fails under contention or slow accumulation on high core counts.

### Batch DSQ Separation

Batch tasks enqueue to dedicated per-node batch overflow DSQs instead of sharing vtime-ordered DSQs with interactive tasks. Separate DSQs give dispatch explicit control: interactive overflow first, then sojourn rescue, then batch fallback.

### CoDel Sojourn Rescue

`batch_enqueue_ns` records when the batch DSQ transitions from empty to non-empty. `dispatch()` rescues batch tasks waiting longer than `sojourn_thresh_ns`. The threshold is set by the Rust adaptive layer from observed dispatch rate: target = 4x dispatch interval, EWMA-smoothed (7/8 old + 1/8 new), clamped to core-count-aware floor/ceiling.

### Deficit Counter (DRR)

After `interactive_budget` (nr_cpu_ids * 4, floor 8) consecutive interactive dispatches without batch service, forces one batch dispatch. Per-CPU DSQ dispatches count toward the deficit. During longrun mode, budget tightens to `nr_cpu_ids * 1`.

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
  - MIXED: slice 1ms, preempt 1ms, batch 20ms, affinity STRONG
  - HEAVY: slice 4ms, preempt 2ms, batch 20ms, affinity WEAK
- **Knob Adjustment Layering**:
  1. `regime_knobs()` sets baseline
  2. `sleep_adjust_batch_ns()` adjusts for IO/idle pattern (skipped during longrun)
  3. Dispatch-rate sojourn threshold (EWMA, core-count-aware floor/ceil)
  4. Tighten check: P99 above ceiling tightens slice_ns by 25% (MIXED only)
  5. Graduated relax: step back toward baseline by 500us/tick with 2-second hold
  6. Longrun override: force WEAK affinity, skip sleep adjustment
- **Core-Count-Aware Sojourn**: Floor = max(5ms, 1ms * nr_cpus/2), ceiling = floor * 2. Dispatch rate normalized to actual elapsed time (not assumed 1s)
- **P99 Ceilings**: LIGHT 3ms, MIXED 5ms, HEAVY 10ms

### Core-Count Scaling

- **Sojourn Floor**: max(5ms, 1ms * nr_cpus/2). A 64-core machine gets a 32ms floor; a 2-core machine stays at 5ms
- **Starvation Rescue**: 500ms / (nr_cpu_ids/4), floor 50ms. More cores = more dispatch contention = shorter deadline
- **Deficit Budget**: nr_cpu_ids * 4 (longrun: nr_cpu_ids * 1)
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
  pandemonium-tests.py Test orchestrator (bench-scale, bench-trace, bench-contention)
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
select_cpu()  ->  Idle CPU found?  ->  Per-CPU DSQ (fast path, KICK_IDLE)
                      |
                      v (no)
enqueue()     ->  L2 sibling idle?  ->  Per-CPU DSQ (L2-affine placement)
                  (skip for LAT_CRITICAL    |
                   and kernel threads)      v (no)
              ->  Wakeup or          ->  Per-CPU DSQ + KICK_PREEMPT
                  LAT_CRITICAL?          (all wakeups, any tier)
                      |
                      v (batch requeue)
              ->  BATCH or immature  ->  Per-node batch overflow DSQ (sojourn tracked)
                  INTERACTIVE?           (classification gate: ewma_age < 2)
                  (vtime ceiling at       |
                   >=8 cores)             v (classified INTERACTIVE)
              ->  Per-node interactive overflow DSQ

dispatch()    ->  Overflow sojourn rescue (>10ms aging, deficit-gated)
              ->  Per-CPU DSQ (direct placement, counts toward deficit)
              ->  Deficit counter (DRR: force batch if budget + starving, longrun tightens)
              ->  Hard starvation rescue (500ms absolute safety net)
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
./pandemonium.py bench-scale --iterations 3
./pandemonium.py bench-trace --iterations 3 --core-counts 4,8,12

# Contention stress test (6 phases targeting adaptive features)
./pandemonium.py bench-contention
./pandemonium.py bench-scale --iterations 3
./pandemonium.py bench-contention --iterations 3 --core-counts 4,8,12
./pandemonium.py bench-contention --phase regime-sweep   # Single phase
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

The script copies source files into `scheds/rust/scx_pandemonium/`, renames the crate, strips `[profile.release]` (the workspace provides its own), registers the workspace member, and runs `cargo fmt`. It does not touch `build.rs` -- PANDEMONIUM's C23 keyword patching and BORE anonymous field renaming in vmlinux.h are specific to our build and not handled by `scx_cargo::BpfBuilder`.

## Attribution

- `include/scx/*` headers from the [sched_ext](https://github.com/sched-ext/scx) project (GPL-2.0)
- vmlinux.h generated from the running kernel's BTF (cached after first build)
- Included in the [sched-ext/scx](https://github.com/sched-ext/scx) project

## License

GPL-2.0
