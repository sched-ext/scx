# scx_cake Benchmark Capture Workflow

This workflow is for the benchmark loop we need before making policy changes:
run `scx_cake` in debug mode, run one targeted workload, then review the perf
trace and the scheduler dump from the same window.

## 1. Build and start the debug recorder

```bash
cargo build -p scx_cake
sudo install -d -m 0700 .scx_cake_bench/diag/live
sudo ./target/debug/scx_cake --verbose --diag-dir .scx_cake_bench/diag/live --diag-period 5
```

Keep that terminal running while benchmarks execute in a second terminal. The
short `--diag-period` matters because many scheduler benchmarks finish quickly.
It gives us a nearby `cake_diag_latest.txt` / `cake_diag_latest.json` pair even
when the live TUI is not attached.

Benchmark artifacts default to `.scx_cake_bench/`, which is ignored by git.
Override that root with `SCX_CAKE_BENCH_ROOT=/path/to/fast-disk` when a run
needs to live outside the checkout.

For policy A/B work, use the one-command runner instead of manually starting
the scheduler and suite:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-guard=off
```

Repeat the same command with `shadow`, `shield`, or `full`. The runner starts
`target/debug/scx_cake` headless, uses `stat` capture by default, pauses between
benchmarks, waits before copying diagnostics, stops the scheduler, and writes
one review bundle under `.scx_cake_bench/policy/<timestamp>_*`.

For a full storm-guard A/B sweep in one command:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --all-storm-guards
```

For cleaner storm-guard causality, prefer the balanced ABBA order. This keeps
`shadow` as the record-only control and repeats `shield` so one lucky or cold
run does not dominate the conclusion:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_policy_bench.sh --storm-abba
```

Multi-run policy sweeps write `analysis.md`, `analysis_metrics.tsv`, and
`analysis_diag.tsv` beside the sweep summary.

## 2. Inventory Cake configs and compare sibling schedulers

For the full benchmark workflow, use the wrapper. It builds the selected
schedulers, generates the Cake config plan, runs the scheduler matrix, and
writes one output tree:

```bash
scheds/rust/scx_cake/bench/scx_cake_full_bench.sh --all
```

For the intentionally tiny CLI that runs the full suite and handles scheduler
start/stop for you, use one of these:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_simple_bench.sh --cake-only
sudo scheds/rust/scx_cake/bench/scx_cake_simple_bench.sh --all-schedulers
```

The simple wrapper keeps the human-facing choice to Cake only versus all
schedulers, and writes to `.scx_cake_bench/simple/<timestamp>_<mode>/`.

Use `--core` for a shorter smoke run, `--plan=quick` for fewer Cake flag
variants, or `--dry-run` to print the exact scheduler matrix without loading
BPF schedulers.

Before sweeping Cake flags, generate a config inventory:

```bash
scheds/rust/scx_cake/bench/scx_cake_config_audit.sh --plan=wide
```

That writes `config_options.tsv`, `config_plan.tsv`, and the current
`scx_cake --help` output. The quick/wide plans are meant for first-pass policy
work. The full-factorial plan is an inventory tool, not the first benchmark to
run, because it mixes too many causes at once.

To compare Cake against sibling sched_ext schedulers on the same benchmark
sequence:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh \
  --schedulers cake,pandemonium,lavd,p2dq,flash \
  --all
```

To replace the single Cake entry with every Cake config from an audit plan:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh \
  --cake-config-plan .scx_cake_bench/config-audit/<run>/config_plan.tsv \
  --schedulers cake,pandemonium,lavd,p2dq,flash \
  --all
```

Cake entries run headless `--verbose` and collect Cake diagnostics. Non-Cake
schedulers collect the same benchmark and `perf` artifacts, but they do not
emit Cake diagnostics. This split is intentional: Cake diagnostics explain why
Cake made a decision, while sibling scheduler timings show which workload
shapes Cake should learn from.

Use `--all-schedulers --core` when you want a broad smoke comparison across
every `scheds/rust/scx_*` package that has a built binary:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh --all-schedulers --core
```

## 3. Run a targeted benchmark capture

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh perf-sched-thread
sudo scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh perf-sched-fork
sudo scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh stress-ng-cpu-cache-mem
sudo scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh perf-memcpy
```

To run the whole local suite back to back, use:

```bash
sudo scheds/rust/scx_cake/bench/scx_cake_bench_suite.sh
```

The suite writes one parent directory under
`.scx_cake_bench/suites/<timestamp>_all`, with each benchmark capture under
`runs/`. Asset-dependent cases are skipped unless the matching input is set:

```bash
sudo XZ_INPUT=/path/to/input.tar \
  X265_INPUT=/path/to/input.y4m \
  NAMD_CONFIG=/path/to/namd/benchmark.namd \
  YCRUNCHER_CMD='y-cruncher bench 1b' \
  FFMPEG_BUILD_CMD='make -C /path/to/ffmpeg -j"$(nproc)"' \
  BLENDER_CMD='blender -b /path/to/scene.blend -f 1' \
  scheds/rust/scx_cake/bench/scx_cake_bench_suite.sh
```

Use `--core` for only the built-in benchmarks, or `--dry-run` to print the
planned sequence without collecting perf data.

By default the script writes a run directory under
`.scx_cake_bench/runs/<timestamp>_<benchmark>`. Each run contains:

- `summary.md`: host, kernel, git head, benchmark command, and review order
- `logs/`: workload stdout/stderr and pass status files
- `perf/*.perf_stat.csv`: system-wide perf counters while the workload ran
- `perf/*.perf_sched.data`: raw `perf sched record` trace
- `perf/*.perf_sched_latency.txt`: scheduler latency summary
- `perf/*.perf_sched_timehist_summary.txt`: timehist runtime summary
- `diag/from_*/`: copied `cake_diag_latest.*`, timestamped diagnostics, and
  any fresh `tui_dump_*` files from `.scx_cake_bench/diag/live`

The default capture mode runs the workload twice: once under `perf stat` and
once under `perf sched record`. For long workloads, reduce the pass count:

```bash
sudo SCX_CAKE_BENCH_CAPTURE=stat \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh namd
```

Set `SCX_CAKE_BENCH_BPF=1` when we need an extra pass with
`perf stat --bpf-prog` over the active `cake_select_cpu`, `cake_enqueue`,
`cake_dispatch`, `cake_running`, and `cake_stopping` programs.

Set `SCX_CAKE_BENCH_TIMEHIST_WAKEUPS=1` only when the raw wakeup timehist is
needed; it can be very large during scheduler-messaging runs.

## 4. Recreate the chart's worst areas first

The benchmark chart showed the clearest `scx_cake` pain in scheduler messaging,
NAMD, and the total score/time rollup. Start with these:

```bash
sudo PERF_SCHED_GROUPS=16 PERF_SCHED_LOOPS=500 \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh perf-sched-fork

sudo PERF_SCHED_GROUPS=16 PERF_SCHED_LOOPS=500 \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh perf-sched-thread
```

For NAMD, point the harness at the exact config used by the benchmark suite:

```bash
sudo NAMD_BIN=/path/to/namd2 \
  NAMD_CONFIG=/path/to/namd/benchmark.namd \
  NAMD_THREADS="$(nproc)" \
  SCX_CAKE_BENCH_CAPTURE=stat \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh namd
```

For x265 and xz, use the real input assets from the benchmark run:

```bash
sudo X265_INPUT=/path/to/input.y4m \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh x265

sudo XZ_INPUT=/path/to/input.tar \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh xz-compress
```

For benchmark cases the helper does not know about yet, use `custom`:

```bash
sudo SCX_CAKE_BENCH_CMD='blender -b scene.blend -f 1' \
  scheds/rust/scx_cake/bench/scx_cake_bench_capture.sh custom
```

## 5. What to review before changing policy

Use the run directory as the evidence bundle. The first pass should answer:

- Did `perf sched latency` show large max wake/runtime outliers?
- Did context switches or migrations jump during the bad benchmark?
- Did cache miss, L1/L2, or remote-fill counters move with the regression?
- Did the dump show route/floor confidence disabled or untrained on hot CPUs?
- Did shared queue, dispatch miss, wake-target miss, or pressure-spill counters
  increase during the workload?
- Did the benchmark create many short-lived tasks, long CPU-bound workers, or a
  mixed producer/consumer shape?

Only then should we make a policy change. For example, scheduler messaging
should usually lead us toward wakeup, migration, and short-task placement
evidence. NAMD should lead us toward long CPU-bound worker placement, cache
locality, SMT/LLC behavior, and avoidable migrations. x265/xz should lead us
toward throughput, migration, and cache-fill evidence rather than interactive
latency assumptions.

Before judging a score delta, compare host-noise state. The `cakebench` history
layer records noise severity and top outside processes because noise can change
the benchmark balance, not merely depress all scores. A noisy cache/mem run can
make a mutation appear to improve memcpy while a clean rerun shows the policy is
actually worse. Treat `clean`/`low` versus `clean`/`low` comparisons as
decision-grade, `warn` as rerun-worthy for close calls, and `noisy` as evidence
only. See `CAKEBENCH_HISTORY.md` for the comparability rule and the 2026-05-14
v10 noisy-versus-clean example.
