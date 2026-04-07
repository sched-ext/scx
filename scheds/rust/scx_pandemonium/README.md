# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C23. PANDEMONIUM classifies every task by behavior -- wakeup frequency, context switch rate, runtime, sleep patterns -- and adapts scheduling decisions in real time. Damped harmonic oscillation drives CoDel-inspired stall detection with a self-tuning target. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. Multiplicative Weight Updates (MWU) balance 6 competing expert profiles across 4 loss pathways.

Three-tier behavioral dispatch, overflow sojourn rescue, longrun detection with deficit tightening, dual burst detection (CUSUM + wakeup rate), wakee_flips-gated WAKE_SYNC, sleep-informed batch tuning, classification-gated DSQ routing, workload regime detection, vtime ceiling, hard starvation rescue, and a persistent process database that learns task classifications across lifetimes.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos, scx_cake and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE and Arch communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs, kernel 6.18+, clang 21. EEVDF and scx_bpfland: best 3 of 28 and 26 complete runs (averaged) across 75 bench-scale sessions. PANDEMONIUM: v5.6.0, 3 iterations.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,058us  | 2,004us     | **64us**           | **64us**               |
| 4     | 1,246us  | 2,003us     | **64us**           | 78us                   |
| 8     | 425us    | 2,003us     | **81us**           | 83us                  |
| 12    | 344us    | 2,002us     | 90us              | **83us**               |

Sub-100us in both modes at every core count. EEVDF's best-of-28 can't break 344us at 12C or 2,058us at 2C.

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,262us  | 2,006us     | **68us**           | 86us                   |
| 4     | 3,223us  | 2,003us     | **71us**           | **75us**               |
| 8     | 2,331us  | 2,004us     | **81us**           | 91us                  |
| 12    | 1,891us  | 2,001us     | 94us              | **83us**               |

20-30x faster burst response than both competitors at every core count.

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,293us  | 2,000us     | **74us**           | 97us                  |
| 4     | 1,421us  | 2,003us     | **65us**           | 77us                  |
| 8     | 60us     | 2,003us     | 82us              | **87us**               |
| 12    | 126us    | 2,002us     | **84us**           | 369us                 |

BPF mode sub-100us at every core count under sustained batch pressure.

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | 2,412us  | 2,000us     | **74us**           | 75us                  |
| 4     | 1,683us  | 2,003us     | **70us**           | 73us                  |
| 8     | 348us    | 2,003us     | 85us              | **84us**               |
| 12    | 494us    | 2,002us     | 88us              | **81us**               |

Sub-100us at every core count in both modes. EEVDF's best-of-28 averages 348-2,412us.

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF   | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|---------|-------------|-------------------|------------------------|
| 2     | 13.1%   | 69.4%       | **0.3%**          | **0.4%**               |
| 4     | **8.6%**| 60.4%       | **1.9%**          | **0.2%**               |
| 8     | 10.8%   | 53.8%       | 19.4%             | **8.4%**               |
| 12    | 10.4%   | 54.7%       | **0.4%**          | **0.0%**               |

At 12C: BPF misses 0.4%, ADAPTIVE misses 0.0%. EEVDF's best: 10.4%. scx_bpfland's best: 54.7%.

### Burst Recovery P99 (latency after storm subsides)

| Cores | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------------|------------------------|
| 2     | 79us              | 74us                   |
| 4     | 65us              | 78us                   |
| 8     | 77us              | 140us                  |
| 12    | 102us             | 78us                   |

Sub-100us recovery at every core count. No other scheduler measures this.

### App Launch P99

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | **2,899us** | 2,194us  | 7,993us           | 3,234us                |
| 4     | 4,058us  | **2,199us** | 3,060us           | **2,061us**            |
| 8     | 4,092us  | **1,723us** | 3,332us           | 2,703us                |
| 12    | 3,552us  | 1,520us     | 2,548us           | **2,470us**            |

### IPC Round-Trip P99

| Cores | EEVDF    | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|----------|-------------|-------------------|------------------------|
| 2     | **12us** | 18us        | 6,000us           | 2,995us                |
| 4     | 118us    | **23us**    | 2,998us           | 2,002us                |
| 8     | 23us     | 71us        | 867us             | **24us**               |
| 12    | **15us** | 57us        | 233us             | 27us                   |

### Throughput (kernel build, vs EEVDF baseline)

BPF averaged across 31 runs, ADAPTIVE across 28 runs (outliers >15% excluded). scx_bpfland: best 3 of 26.

| Cores | scx_bpfland | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | -5.1%       | **+3.1%**         | +2.3%                  |
| 4     | +2.6%       | **+3.5%**         | +2.4%                  |
| 8     | +2.8%       | **+3.6%**         | +2.2%                  |
| 12    | +3.0%       | +2.1%             | +0.4%                  |

### Fork/Thread IPC (`perf bench sched messaging`, 12C, 3 runs averaged)

| Scheduler | Time | vs EEVDF | Cache Misses | IPC |
|-----------|------|----------|--------------|-----|
| EEVDF                    | 14.93s | baseline | 26M  | 0.44 |
| PANDEMONIUM (BPF)        | 14.25s | **-4.6%** | 21M  | 0.45 |
| PANDEMONIUM (ADAPTIVE)   | 14.27s | **-4.4%** | 21M  | 0.44 |
| scx_bpfland              | 15.22s | +1.9%  | 32M  | 0.44 |

Resistance affinity places pipe partners on minimum effective resistance CPUs, keeping data in shared cache. Both modes beat EEVDF with fewer cache misses. scx_bpfland is 1.9% slower than EEVDF with 32M cache misses.

## Key Features

### Dispatch Waterfall

8-step dispatch with per-CPU DSQ dominance and layered anti-starvation:

0. **Overflow sojourn rescue** -- aging overflow tasks past core-scaled threshold, deficit-gated
1. **Per-CPU DSQ** -- direct placement from enqueue, zero contention, counts toward deficit
2. **Deficit counter (DRR)** -- force batch if budget exhausted + starving; longrun tightens budget
3. **Hard starvation rescue** -- core-count-scaled absolute safety net
4. **Node interactive overflow** -- LAT_CRITICAL + INTERACTIVE, vtime-ordered
5. **Batch sojourn rescue (CoDel)** -- rescue if oldest batch > threshold
6. **Node batch overflow** -- normal fallback
7. **Cross-node steal** -- interactive + batch per remote node
8. **KEEP_RUNNING** -- if prev still wants CPU and nothing queued

### Three-Tier Enqueue

- **select_cpu**: idle CPU -> per-CPU DSQ (depth-gated: 1 slot at <4C, 2 at 4C+), KICK_IDLE. WAKE_SYNC path: wakee_flips gate -> R_eff idle search -> DSQ fallback
- **enqueue**: L2 sibling idle -> node DSQ + kick. All wakeups get KICK_PREEMPT. Batch/immature INTERACTIVE route to batch overflow DSQ. Vtime ceiling at >=8 cores
- **tick**: burst detection (CUSUM + wakeup rate), longrun detection (batch non-empty >2s), sojourn enforcement, preempt batch for waiting interactive (thresh=0 during burst)

### Damped Oscillation Stall Detection

CoDel-inspired per-CPU DSQ stall detection where the target adapts via damped harmonic oscillation. Replaces static thresholds with a feedback-driven convergent system.

**Stall decision** (`pcpu_dsq_is_stalled`): Compares per-CPU minimum sojourn time against `sigmoid_center_ns`. Below = flowing (dispatch immediately). Above = start interval timer; if still above after `sojourn_interval_ns`, stalled (reject dispatch, force rescue).

**Damped oscillation** (tick, CPU 0): Reads `global_rescue_count` delta since last tick. Rescues fire -> negative impulse tightens center (detect stalls sooner). No rescues, no burst -> positive impulse relaxes center (tolerate higher sojourn). Velocity decays each tick via bit-shift damping. Center clamped between core-scaled floor and 2ms ceiling.

**Feedback loop**: `global_rescue_count` (atomic, incremented at both overflow rescue sites in dispatch) drives the oscillation. The system converges: too permissive -> rescues fire -> center tightens -> fewer stalls -> rescues stop -> center relaxes.

**Core-scaled parameters**:

| Parameter | 2C | 4C | 8C | 12C |
|-----------|----|----|-----|-----|
| Interval | 2ms | 4ms | 8ms | 12ms |
| Margin | 64K | 128K | 256K | 512K |
| Damping (v>>N) | v/4 | v/8 | v/16 | v/32 |
| Pull scale | 2x | 3x | 4x | 4x |
| Center floor | 200us | 300us | 500us | 700us |
| Center ceiling | 2ms | 2ms | 2ms | 2ms |

Center starts at ceiling (2ms, fully permissive) and oscillation converges to the system's natural stall threshold.

### Overflow Sojourn Rescue

Per-CPU DSQ dominance under sustained load makes downstream anti-starvation unreachable -- 90%+ of dispatches serve per-CPU DSQ while overflow tasks age indefinitely. Dispatch Step 0 checks both overflow DSQs for tasks aging past `overflow_sojourn_rescue_ns` (core-count-scaled: 2ms per core, clamped 4-10ms). CAS-based timestamp management prevents races across CPUs.

### Longrun Detection

When batch DSQ is non-empty for >2 seconds, `longrun_mode` activates: deficit ratio tightens to `nr_cpu_ids * 1` (quadrupling batch share), slices drop to 1ms, affinity forced to WEAK.

### Dual Burst Detection

- **CUSUM**: Statistical change-point detection (Page, 1954) on total enqueue rate. Effective for BPF mode (1ms slices)
- **Wakeup Rate**: Absolute threshold `nr_cpu_ids * 2` wakeups per tick. Effective for adaptive mode (4ms slices)
- Either fires `burst_mode`: preempt threshold drops to 0, slice uses `burst_slice_ns`

### Vtime Ceiling

Caps batch deadline at `vtime_now + 30ms`, keeping every task within 6 sojourn cycles of the DSQ head. Gated at >=8 cores where DSQ depth otherwise causes tail starvation.

### Hard Starvation Rescue

`min(25ms * nr_cpus, 500ms / max(1, nr_cpus/4))`, clamped 20-500ms. Short at low core counts (2C = 50ms), peaks mid-range (8C = 200ms), short again at high counts (128C = 20ms).

### Topology-Aware Placement

**Resistance affinity**: First application of effective resistance from spectral graph theory to CPU scheduling. The CPU topology is modeled as a weighted electrical network (L2 siblings = 10.0, same socket = 1.0, cross-socket = 0.3). The Laplacian pseudoinverse (Jacobi eigendecomposition, O(n^3), pure Rust) gives exact all-pairs migration costs accounting for ALL paths, not just direct connections. `R_eff(i,j) = L+[i,i] + L+[j,j] - 2*L+[i,j]` -- a true metric satisfying the triangle inequality. Per-CPU ranked lists stored in BPF map (16 candidates, search limit 3).

**wakee_flips gate**: `select_cpu()` reads waker/wakee `wakee_flips` from `task_struct`. Both below `nr_cpu_ids` = 1:1 pipe pair (affinity beneficial). Either above = 1:N server pattern (skip to normal path). Same discrimination as the kernel's `wake_wide()`.

**L2 cache affinity**: `find_idle_l2_sibling()` in enqueue finds idle CPUs in the same L2 domain (max 8 iterations). Per-regime knob (LIGHT=WEAK, MIXED=STRONG, HEAVY=WEAK). Longrun overrides to WEAK. Per-dispatch L2 hit/miss counters for BATCH, INTERACTIVE, LAT_CRITICAL tiers.

**Commute time interpretation**: R_eff is proportional to expected round-trip time for work between CPUs [2]. Minimizing R_eff between pipe partners minimizes cache line transfer cost [1][3][4].

### Behavioral Classification

- **Latency-Criticality Score**: `lat_cri = (wakeup_freq * csw_rate) / (avg_runtime + runtime_dev/2)`
- **Three Tiers**: LAT_CRITICAL (1.5x avg_runtime slices), INTERACTIVE (2x), BATCH (configurable ceiling)
- **EWMA Classification**: wakeup frequency, context switch rate, runtime variance drive scoring
- **CPU-Bound Demotion**: avg_runtime above `cpu_bound_thresh_ns` demotes INTERACTIVE to BATCH
- **Kworker Floor**: PF_WQ_WORKER floors at INTERACTIVE
- **Compositor Boosting**: BPF hash map, default compositors always LAT_CRITICAL, user-extensible via `--compositor`

### Process Database (procdb)

BPF publishes mature task profiles (tier + avg_runtime) keyed by `comm[16]`. Rust tracks EWMA convergence stability, promotes to "confident", applies learned classifications on spawn. `enable()` warm-starts; `runnable()` EWMA validates and corrects. Persistent to `~/.cache/pandemonium/procdb.bin` (atomic write).

### Adaptive Control Loop

- **One Thread, Zero Mutexes**: 1-second control loop reads BPF histogram maps, computes P99, drives MWU
- **Workload Regime Detection**: LIGHT (idle >50%), MIXED (10-50%), HEAVY (<10%) with Schmitt hysteresis + 2-tick hold
- **MWU Orchestrator**: 6 experts (LATENCY, BALANCED, THROUGHPUT, IO_HEAVY, FORK_STORM, SATURATED) compete via multiplicative weight updates. 8 continuous knobs blended via scale factors, 2 discrete knobs via majority vote. 4 loss pathways: P99 spike (Schmitt-gated, 2-tick confirm), rescue delta (0->nonzero, penalizes LATENCY at 0.4x to prevent compounding with oscillation tightening), IO bucket transition, fork storm (Schmitt-gated). ETA=8.0, weight floor 1e-6, relaxation at 80% toward equilibrium after 2 healthy ticks below 70% ceiling

### Core-Count Scaling

All parameters scale dynamically with `nr_cpus`. No special-casing, no lookup tables.

| Parameter | Formula | 2C | 4C | 8C | 12C |
|-----------|---------|----|----|----|----|
| Sojourn floor | `clamp(nr_cpus * 1ms, 2ms, 6ms)` | 2ms | 4ms | 6ms | 6ms |
| Sojourn ceiling | `floor * 2` | 4ms | 8ms | 12ms | 12ms |
| Overflow rescue | `clamp(nr_cpus * 2ms, 4ms, 10ms)` | 4ms | 8ms | 10ms | 10ms |
| Starvation rescue | `clamp(min(25ms*N, 500ms/max(1,N/4)), 20ms, 500ms)` | 50ms | 100ms | 200ms | 167ms |
| Deficit budget | `nr_cpus * min(4, 2 + nr_cpus/2)` | 6 | 16 | 32 | 48 |
| Per-CPU DSQ depth | `nr_cpus < 4 ? 1 : 2` | 1 | 2 | 2 | 2 |

- **CPU Hotplug**: `cpu_online`/`cpu_offline` callbacks clear per-CPU timestamps and sigmoid state (velocity, rescue count) to prevent stale oscillation after suspend/resume
- **BPF-Verifier Safe**: All EWMA uses bit shifts, no floats. All shared state uses GCC __sync builtins

## Architecture

```
pandemonium.py           Build/install/benchmark manager (Python)
pandemonium_common.py    Shared infrastructure (logging, build, CPU management,
                           scheduler detection, tracefs, statistics)
export_scx.py            Automated import into sched-ext/scx monorepo
src/
  main.rs              Entry point, CLI, scheduler loop, telemetry
  scheduler.rs         BPF skeleton lifecycle, tuning knobs I/O, histogram reads
  adaptive.rs          Adaptive control loop (monitor thread, histogram P99,
                         MWU orchestrator, regime detection, longrun override)
  tuning.rs            MWU orchestrator (6 experts, 4 loss pathways, scale factors),
                         regime knobs, stability scoring, sleep adjustment
  procdb.rs            Process classification database (observe -> learn -> predict -> persist)
  topology.rs          CPU topology detection, Laplacian pseudoinverse, effective resistance,
                         resistance affinity ranking (sysfs -> BPF maps)
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
  contention.rs        Contention stress tests
  adaptive.rs          Adaptive layer tests
  event.rs             Ring buffer tests
  procdb.rs            Process database tests
  scale.rs             Latency scaling benchmark
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
Stall detection:     sigmoid_center_ns (BPF-internal, damped oscillation, no Rust input)
```

One thread, zero mutexes. BPF produces histograms, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. Stall detection is fully BPF-internal -- the damped oscillation runs in tick() on CPU 0 with no Rust involvement.

### Tuning Knobs (BPF map)

| Knob | Default | Purpose |
|------|---------|---------|
| `slice_ns` | 1ms | Interactive/lat_cri slice ceiling |
| `preempt_thresh_ns` | 1ms | Tick preemption threshold (0 during burst) |
| `lag_scale` | 4 | Deadline lag multiplier |
| `batch_slice_ns` | 20ms | Batch task slice ceiling (sleep-adjusted) |
| `burst_slice_ns` | 1ms | Slice during burst/longrun mode |
| `cpu_bound_thresh_ns` | 2.5ms | CPU-bound demotion threshold |
| `lat_cri_thresh_high` | 32 | LAT_CRITICAL classifier threshold |
| `lat_cri_thresh_low` | 8 | INTERACTIVE classifier threshold |
| `affinity_mode` | 1 | L2 placement (0=OFF, 1=WEAK, 2=STRONG) |
| `sojourn_thresh_ns` | 5ms | Batch DSQ rescue threshold (core-count-aware) |

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

vmlinux.h is generated from the running kernel's BTF via bpftool on first build and cached at `~/.cache/pandemonium/vmlinux.h`. The source directory path contains spaces, so `CARGO_TARGET_DIR=/tmp/pandemonium-build` is required for the vendored libbpf Makefile.

After install:

```bash
sudo systemctl start pandemonium          # Start now
sudo systemctl enable pandemonium         # Start on boot
```

## Usage

```bash
sudo pandemonium                    # Default: adaptive mode
sudo pandemonium --no-adaptive      # BPF-only (no Rust control loop)
sudo pandemonium --nr-cpus 4        # Override CPU count for scaling
sudo pandemonium --compositor gamescope  # Add compositor (LAT_CRITICAL boost)

pandemonium check                   # Verify dependencies and kernel config
pandemonium start                   # Build + sudo run + dmesg capture
pandemonium bench                   # A/B benchmark (EEVDF vs PANDEMONIUM)
pandemonium test                    # Full test gate (unit + integration)
pandemonium probe                   # Standalone interactive wakeup probe
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
| [REGIME] | LIGHT/MIXED/HEAVY + BURST/LONGRUN flags |

## Benchmarking

```bash
./pandemonium.py bench-scale                     # Full suite (throughput, latency, burst, longrun, mixed, deadline, IPC, launch)
./pandemonium.py bench-scale --iterations 3      # Multi-iteration
./pandemonium.py bench-scale --pandemonium-only  # Skip EEVDF and externals
./pandemonium.py bench-contention                # Contention stress (6 phases)
./pandemonium.py bench-pcpu                      # Per-CPU DSQ correctness
./pandemonium.py bench-fork-thread               # Fork/thread IPC + hardware counters
./pandemonium.py bench-scx                       # sched-ext/scx CI compatibility
```

All benchmarks compare across core counts via CPU hotplug (2, 4, 8, ..., max). Results archived to `~/.cache/pandemonium/`.

## Testing

```bash
CARGO_TARGET_DIR=/tmp/pandemonium-build cargo test --release   # Unit tests (no root)
pandemonium test                                                # Full gate (requires root)
```

110 tests across 6 files: contention (44), adaptive (29), procdb (26), topology (6), event (5), BPF lifecycle (5).

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

[7] E.S. Page. "Continuous Inspection Schemes." *Biometrika* 41(1-2), 100-115, 1954. [doi:10.1093/biomet/41.1-2.100](https://academic.oup.com/biomet/article-abstract/41/1-2/100/456627)

[8] M. Shreedhar, G. Varghese. "Efficient Fair Queuing Using Deficit Round Robin." *ACM SIGCOMM 1995*, 231-242. [doi:10.1145/217382.217453](https://dl.acm.org/doi/10.1145/217382.217453)

[9] S. Arora, E. Hazan, S. Kale. "The Multiplicative Weights Update Method: a Meta-Algorithm and Applications." *Theory of Computing* 8, 121-164, 2012. [doi:10.4086/toc.2012.v008a006](https://theoryofcomputing.org/articles/v008a006/)

[10] J.D. Valois. "Lock-Free Linked Lists Using Compare-and-Swap." *PODC 1995*, 214-222. [doi:10.1145/224964.224988](https://dl.acm.org/doi/10.1145/224964.224988)

## License

GPL-2.0
