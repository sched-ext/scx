# PANDEMONIUM

Built in Rust and C23, PANDEMONIUM is a Linux kernel scheduler built for sched_ext. Utilizing BPF patterns, PANDEMONIUM classifies every task by its behavior--wakeup frequency, context switch rate, runtime, sleep patterns--and adapts scheduling decisions in real time. Single-thread adaptive control loop (zero mutexes), three-tier behavioral dispatch, L2 cache affinity placement, sleep-informed batch tuning, CoDel-inspired sojourn rescue, CUSUM burst detection with classification-gated DSQ routing, workload regime detection, and a persistent process database that learns task classifications across lifetimes.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_layered, scx_cosmos, and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext and CachyOS communities within the Linux ecosystem.

## Performance

Benchmarked on 12 AMD Zen CPUs, kernel 6.18.9-arch1-2, clang 21.1.6. Numbers from bench-scale (v5.3.0, 3 iterations per core count).

### Throughput (kernel build, vs EEVDF baseline)

| Cores | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) | scx_bpfland |
|-------|-------------------|------------------------|-------------|
| 2     | +5.3%             | +9.4%                  | +5.2%       |
| 4     | +0.2%             | +0.7%                  | +0.2%       |
| 8     | +2.6%             | +0.9%                  | +2.8%       |
| 12    | +3.2%             | +1.2%                  | +3.3%       |

At 4 cores, PANDEMONIUM matches EEVDF and scx_bpfland within 0.2%. Adaptive mode beats scx_bpfland at 4C, 8C, and 12C. Batch DSQ separation (v5.3.0) gives dispatch explicit control over interactive vs batch priority without vtime contention.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | scx_bpfland |
|-------|----------|-------------------|-------------|
| 2     | 1,785us  | **1,715us**       | 2,030us     |
| 4     | 1,831us  | **1,002us**       | 2,003us     |
| 8     | 76us     | 2,003us           | 2,005us     |
| 12    | 303us    | 756us             | 2,003us     |

BPF-only P99 beats EEVDF at 2 and 4 cores, and beats scx_bpfland at every core count. The classification-gated DSQ routing (v5.3.0) keeps unclassified fork storm tasks out of the interactive fast lane while CUSUM burst detection dynamically raises the classification bar during storms.

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | PANDEMONIUM (BPF) | scx_bpfland |
|-------|----------|-------------------|-------------|
| 2     | 2,671us  | 9,999us           | 2,006us     |
| 4     | 2,452us  | 14,996us          | 2,003us     |
| 8     | 2,890us  | 17,000us          | 2,004us     |
| 12    | 65us     | 6,002us           | 2,007us     |

Burst P99 improved 10-20x from pre-v5.3.0 baselines (187ms at 2C, 73ms at 12C) through layered defense: classification gate, CUSUM detection, and dynamic age threshold. Zero crashes across all 12 BPF-mode runs.

## Key Features

### Three-Tier Dispatch
- **Idle CPU Fast Path**: `select_cpu()` places wakeups directly to per-CPU DSQ with zero contention, kicks with `SCX_KICK_IDLE`
- **Node-Local Placement with L2 Affinity**: `enqueue()` tries L2 sibling first (INTERACTIVE/BATCH with affinity_mode > 0), then falls back to any idle CPU within the NUMA node. LAT_CRITICAL and kernel threads (PF_KTHREAD) skip affinity for fastest-available placement
- **Direct Preemptive Placement**: LAT_CRITICAL tasks (any path) and INTERACTIVE wakeups placed directly onto busy CPU's per-CPU DSQ with `SCX_KICK_PREEMPT`. Requeued INTERACTIVE tasks fall to overflow DSQ to avoid unnecessary BPF helper calls
- **NUMA-Scoped Overflow**: Per-node overflow DSQ with cross-node work stealing as final fallback
- **Event-Driven Preemption**: `tick()` checks `interactive_waiting` flag (set by enqueue when non-batch tasks hit overflow DSQ) and preempts batch tasks above `preempt_thresh_ns`. Zero polling -- no BPF timer
- **Batch DSQ Separation**: Batch tasks enqueue to dedicated per-node batch overflow DSQs. Interactive and batch never share vtime order, giving dispatch explicit priority control
- **CoDel Sojourn Rescue**: `batch_enqueue_ns` tracks batch DSQ empty-to-non-empty transitions. dispatch() rescues batch tasks waiting longer than `sojourn_thresh_ns` (set by Rust from observed dispatch rate). tick() enforces sojourn by kicking CPUs running batch when batch DSQ is starving
- **Deficit Counter (DRR)**: After `interactive_budget` (nr_cpu_ids * 4) consecutive interactive dispatches without batch service, forces one batch dispatch. Queue depth gated: only fires when `scx_bpf_dsq_nr_queued(node_dsq) >= nr_cpu_ids` (concurrent lockout). Invisible during steady state
- **CUSUM Burst Detection**: Statistical change-point detection (Page, 1954) monitors enqueue rate. Samples every 64th enqueue, tracks interval EWMA with 25% slack. When `cusum_s` exceeds 2x EWMA, `burst_mode` activates. Integer-only, O(1) per check, BPF-verifier safe
- **Classification-Gated DSQ Routing**: Immature INTERACTIVE tasks (`ewma_age < age_thresh`) route to batch DSQ until EWMA classifies them. Threshold is dynamic: normal=2, burst_mode=4. Prevents fork storms from flooding the interactive fast lane. LAT_CRITICAL tasks are never redirected

### Behavioral Classification
- **Latency-Criticality Score**: `lat_cri = (wakeup_freq * csw_rate) / effective_runtime` where `effective_runtime = avg_runtime + (runtime_dev >> 1)`
- **Three Tiers**: LAT_CRITICAL (1.5x avg_runtime slices, preemptive kicks), INTERACTIVE (2x avg_runtime), BATCH (configurable ceiling via adaptive layer)
- **EWMA Classification**: All tasks -- including procdb-confident tasks -- go through full EWMA classification in `runnable()`. Wakeup frequency, context switch rate, and runtime variance drive `lat_cri` scoring. BPF's natural reclassification validates procdb predictions against actual runtime behavior
- **CPU-Bound Demotion**: Secondary safety net in `stopping()`. Tasks with avg_runtime above `cpu_bound_thresh_ns` (regime-dependent, written by Rust) are demoted from INTERACTIVE to BATCH. Reversed automatically when the task sleeps and `runnable()` reclassifies from fresh behavioral signals
- **Compositor Boosting**: BPF hash map populated by Rust at startup. Default compositors (kwin, sway, Hyprland, gnome-shell, picom, weston) always LAT_CRITICAL. User-extensible via `--compositor` CLI flag
- **Runtime Variance Tracking**: EWMA of |runtime - avg_runtime| penalizes jittery tasks in the lat_cri formula

### L2 Cache Affinity
- **Active Placement**: `find_idle_l2_sibling()` in enqueue Tier 1 finds idle CPUs in the same L2 domain as the task's last CPU. Bounded loop (max 8 iterations), verifier-safe
- **Affinity Mode**: Per-regime knob (LIGHT=WEAK, MIXED=STRONG, HEAVY=WEAK). MIXED is the gaming regime where L2 placement matters most
- **Kernel Thread Bypass**: kworkers and ksoftirqd (PF_KTHREAD) skip L2 affinity entirely -- infrastructure threads need fastest-available, not L2-optimal
- **Per-Dispatch Tracking**: Every dispatch compares the selected CPU's L2 domain against the task's last CPU
- **Per-Tier Hit/Miss Counters**: Separate L2 hit rates for BATCH, INTERACTIVE, and LAT_CRITICAL tiers
- **Cache Domain Map**: Rust populates `cache_domain` and `l2_siblings` BPF maps from sysfs topology at startup

### Process Classification Database (procdb)
- **Cross-Lifecycle Learning**: BPF publishes mature task profiles (tier + avg_runtime) keyed by `comm[16]` to an observation map
- **Confidence Scoring**: Rust ingests observations, tracks EWMA convergence stability, and promotes profiles to "confident" when avg_runtime stabilizes
- **Warm-Start on Spawn**: `enable()` applies learned classification from prior runs -- `make -j12` forks start as BATCH from the first fork instead of 100 fresh INTERACTIVE classifications
- **EWMA Validation**: Confident tasks still run through full behavioral classification in `runnable()`. ProcDb provides the initial state; EWMA validates and corrects it against actual runtime behavior. Observations still publish so the Rust side detects drift
- **Persistent Memory**: Confident profiles are saved to `~/.cache/pandemonium/procdb.bin` on shutdown (atomic write via .tmp + rename). On startup, warm profiles are loaded and pushed to BPF immediately -- zero cold-start penalty after the first run
- **Deterministic Eviction**: When the profile cache is full, eviction sorts by (staleness, observations, comm) -- identical workloads produce identical procdb state
- **Telemetry**: `procdb: total/confident` per tick shows learning progress

### Sleep-Aware Scheduling
- **quiescent() Callback**: Records sleep timestamp when tasks go to sleep
- **Sleep Duration Tracking**: `running()` computes sleep duration, classifies into BPF per-CPU histogram (IO-WAIT / SHORT IO / MODERATE / IDLE)
- **Sleep-Informed Batch Tuning**: IO-heavy workloads (>60% io_pct) extend batch slices +25%, idle-heavy workloads (<15%) tighten -25%, dead zone unchanged. 25ms ceiling
- **Wakeup Latency Histograms**: Per-CPU BPF histograms (3 tiers x 12 buckets) replace the ring buffer. Cost per wakeup: 1 map lookup + 1 atomic increment (approximately 20ns)

### Adaptive Control Loop
- **One Thread, Zero Mutexes**: Single monitor thread runs a 1-second control loop. Reads BPF histogram maps, computes P99, adjusts knobs. No ring buffer, no reflex thread
- **Workload Regime Detection**: LIGHT (idle >50%), MIXED (10-50%), HEAVY (<10%) with Schmitt trigger hysteresis and 2-tick hold to prevent regime bouncing
- **Regime Profiles**:
  - LIGHT: slice 2ms, preempt 1ms, batch 20ms, affinity WEAK
  - MIXED: slice 1ms, preempt 1ms, batch 20ms, affinity STRONG
  - HEAVY: slice 4ms, preempt 2ms, batch 20ms, affinity WEAK
- **Knob Adjustment Layering**:
  1. `regime_knobs()` sets baseline (e.g. 20ms batch, 1ms slice)
  2. `sleep_adjust_batch_ns()` adjusts for IO/idle pattern (+/- 25% batch)
  3. Dispatch-rate sojourn threshold (EWMA: 4x dispatch interval, clamped 5-10ms)
  4. Tighten check: P99 above ceiling tightens slice_ns by 25% (MIXED only)
  5. Graduated relax: step back toward baseline by 500us/tick with 2-second hold
  - L2 placement is a separate axis (affinity_mode knob controls BPF enqueue)
  - Sojourn threshold is a separate axis (sojourn_thresh_ns knob controls BPF dispatch)
- **Dispatch-Rate Adaptive Sojourn**: Measures dispatch rate per tick, computes 4x dispatch interval as sojourn target, EWMA-smoothed (7/8 old + 1/8 new), clamped 5-10ms. Writes sojourn_thresh_ns to BPF tuning knobs
- **Stability Tracking**: Consecutive stable ticks (no regime changes, no tighten events, P99 below half ceiling). After 10 stable ticks, telemetry output halves
- **P99 Ceilings**: LIGHT 3ms, MIXED 5ms, HEAVY 10ms

### Core-Count Scaling
- **Preempt Threshold**: `60 / (nr_cpu_ids + 2)`, clamped 3-20. Scales interactive kick aggressiveness with CPU count
- **CPU Hotplug**: `cpu_online`/`cpu_offline` callbacks prevent sched_ext auto-exit during benchmark CPU restriction
- **Topology Detection**: Parses sysfs for physical packages, L2/L3 cache domains, NUMA nodes. Populates cache_domain and l2_siblings BPF maps at init
- **BPF-Verifier Safe**: All EWMA uses bit shifts, no floats. Loop bounds via `bpf_for` and `MAX_CPUS`/`MAX_NODES` defines

## Architecture

```
pandemonium.py           Build/install manager (Python)
pandemonium_common.py    Shared infrastructure (logging, build, constants)
export_scx.py            Automated import into sched-ext/scx monorepo
src/
  main.rs              Entry point, CLI, scheduler loop, telemetry
  scheduler.rs         BPF skeleton lifecycle, tuning knobs I/O, histogram reads
  adaptive.rs          Adaptive control loop (single monitor thread, histogram P99,
                         sleep adjustment, sojourn threshold, tighten/relax)
  tuning.rs            Regime knobs, stability scoring, sleep adjustment
  procdb.rs            Process classification database (observe -> learn -> predict -> persist)
  topology.rs          CPU topology detection (sysfs -> cache_domain + l2_siblings BPF maps)
  event.rs             Pre-allocated ring buffer for stats time series
  log.rs               Logging macros
  lib.rs               Library root
  bpf/
    main.bpf.c         BPF scheduler (~1150 lines, GNU C23)
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
  pandemonium-tests.py Test orchestrator (bench-scale, CPU hotplug, dmesg capture)
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
              ->  Node-local idle?  ->  Per-CPU DSQ + PREEMPT kick
                      |
                      v (no)
              ->  LAT_CRITICAL or   ->  Direct per-CPU + KICK_PREEMPT
                  INTERACTIVE wakeup?
                      |
                      v (no)
              ->  BATCH or immature  ->  Per-node batch overflow DSQ (sojourn tracked)
                  INTERACTIVE?           (classification gate: ewma_age < age_thresh)
                  (age_thresh: 2          |
                   burst_mode: 4)         v (classified INTERACTIVE)
              ->  Per-node interactive overflow DSQ

dispatch()    ->  Per-CPU DSQ (direct placement)
              ->  Node interactive overflow (LAT_CRITICAL + INTERACTIVE)
              ->  Deficit counter (DRR: force batch if budget + starving + queue gate)
              ->  Batch sojourn rescue (CoDel: rescue if oldest > threshold)
              ->  Node batch overflow (normal fallback)
              ->  Cross-node steal (interactive + batch per remote node)
              ->  KEEP_RUNNING if nothing queued

tick()        ->  Sojourn enforcement (kick batch CPUs when batch DSQ starving)
              ->  interactive_waiting?  ->  Preempt batch if avg_runtime > thresh
```

### Adaptive Layer (adaptive.rs)

```
BPF per-CPU histograms              Monitor Thread (1s loop)
(wake_lat_hist, sleep_hist)  --->   Read + drain histograms
                                    Compute P99 per tier
                                      |
                                      v
                                    regime_knobs() -> baseline
                                      -> sleep_adjust_batch_ns() -> IO/idle
                                        -> dispatch-rate sojourn threshold (EWMA)
                                          -> tighten check -> P99 ceiling
                                            -> graduated relax -> step toward baseline
                                      |
                                      v
                                    BPF reads knobs on next dispatch

L2 placement (separate axis):  affinity_mode knob -> BPF enqueue
Sojourn threshold (separate axis):  sojourn_thresh_ns knob -> BPF dispatch
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
| `preempt_thresh_ns` | 1ms | Tick preemption threshold |
| `lag_scale` | 4 | Deadline lag multiplier (higher = more vtime credit) |
| `batch_slice_ns` | 20ms | Batch task slice ceiling (sleep-adjusted) |
| `cpu_bound_thresh_ns` | 2.5ms | CPU-bound demotion threshold (regime-dependent) |
| `lat_cri_thresh_high` | 32 | Classifier: LAT_CRITICAL threshold |
| `lat_cri_thresh_low` | 8 | Classifier: INTERACTIVE threshold |
| `affinity_mode` | 1 | L2 placement (0=OFF, 1=WEAK, 2=STRONG) |
| `sojourn_thresh_ns` | 5ms | Batch DSQ rescue threshold (set by Rust from dispatch rate) |

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
d/s: 251000  idle: 5% shared: 230000  preempt: 12  keep: 0  kick: H=8000 S=22000 enq: W=8000 R=22000 wake: 4us p99: 10us L2: B=67% I=72% LC=85% procdb: 42/5 sleep: io=87% sjrn: 3ms/5ms [MIXED] stable: 10
```

During fork/exec storms, CUSUM triggers burst mode:

```
d/s: 380000  idle: 1% shared: 360000  preempt: 45  keep: 0  kick: H=15000 S=35000 enq: W=15000 R=35000 wake: 12us p99: 85us L2: B=45% I=68% LC=82% procdb: 42/5 sleep: io=92% sjrn: 1ms/5ms [HEAVY BURST] stable: 0
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
| [REGIME] | Current workload regime (LIGHT/MIXED/HEAVY) |
| BURST | CUSUM burst detection active (appended to regime during fork storms) |
| stable | Consecutive stable ticks (hibernates at 10) |

## Benchmarking

```bash
# Full benchmark (N-way scaling + latency at 2, 4, 8, 12 cores)
./pandemonium.py bench-scale

# Custom options
./pandemonium.py bench-scale --iterations 3 --core-counts 4,8,12
./pandemonium.py bench-scale --skip-latency
./pandemonium.py bench-scale --schedulers scx_bpfland,scx_rusty
```

Benchmarks compare EEVDF (kernel default), PANDEMONIUM (BPF-only and BPF-adaptive), and external sched_ext schedulers across core counts via CPU hotplug. Each core count measures throughput (kernel build), P99 wakeup latency (interactive probe under saturation), and burst resilience (fork/exec storm of n_cpus * 4 processes under full load).

Results are archived to `~/.cache/pandemonium/{version}-{timestamp}.prom` (Prometheus format) for cross-build regression tracking.

## Testing

```bash
# Unit tests (no root required)
CARGO_TARGET_DIR=/tmp/pandemonium-build cargo test --release

# Full test gate (requires root + sched_ext kernel)
pandemonium test

# Scaling benchmark (EEVDF vs PANDEMONIUM, CPU hotplug, requires root)
./pandemonium.py bench-scale
```

66 tests across 5 test files:

| File | Tests | Coverage |
|------|-------|----------|
| tests/adaptive.rs | 29 | Regime detection, tuning knobs, stability scoring, sleep adjustment, telemetry gating |
| tests/procdb.rs | 26 | Profile confidence, eviction, persistence, determinism |
| tests/event.rs | 5 | Ring buffer, snapshot, summary |
| src/main.rs | 6 | Topology parsing |
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
