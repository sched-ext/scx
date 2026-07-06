# scx_cake Benchmark Capture Workflow

This workflow is for the benchmark loop we need before making policy changes:
run `scx_cake` in debug mode, run one targeted workload, then review the perf
trace and the scheduler dump from the same window.

For live game captures using MangoHud socket control, use the bench-assets
workflow instead of the synthetic/local perf harness:

```text
docs/game_capture_mangohud_socket_workflow.md
/home/ritz/Documents/Repo/scx_cake_bench_assets/docs/kovaaks-mangohud-socket-capture.md
```

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

## 6. 2026-06-05 AC6 live-game checkpoint

Armored Core VI was tested live with MangoHud 60s captures on `DP-2`
`3840x2160@240.02Hz`, HDR enabled, VRR automatic.  AC6's direct MangoHud socket
was left in a `LISTEN 1 1` state and had failed to emit CSVs earlier, so these
captures used the AC6-proven `mangohud-autostart` trigger with focus and scene
guards enabled.  The active scene was accepted as `unclassified_game_scene`;
exact in-game location was not inferred.

The tested build family isolated the AC6 queue/wake shape:

| Label | Build knobs | Decision |
|---|---|---|
| `ac6_gaming_idle_v1` | `SCX_CAKE_BUSY_WAKE_KICK=idle`, local queue, 1000us | Reject for AC6 tails; one run hit 15.4ms max / 67 FPS 0.1% low. |
| `ac6_idle_llcvtime_v3` | `idle`, `SCX_CAKE_QUEUE_POLICY=llc-vtime`, 1000us | Park; fixed local-tail risk but jitter avg/p95 stayed high. |
| `ac6_policy_llcvtime_v4` | `policy`, `llc-vtime`, `SCX_CAKE_STORM_GUARD=shield`, 1000us | Current AC6 keeper/champion candidate. |
| `ac6_policy_llcvtime_shadow_v5` | v4 plus `SCX_CAKE_STORM_GUARD=shadow` | Reject; worsened lows, p99.9/max, stddev, and jitter. |
| `ac6_policy_llcvtime_q750_v6` | v4 plus `SCX_CAKE_QUANTUM_US=750` | Park/reject for now; reduced one max-jitter metric but lost avg FPS and worsened jitter avg/p95 versus v4. |
| `ac6_nativefirst_llcvtime_v7` | v4 plus broadening release native-first generic-bulk select to `llc-vtime` | Reject; v7 lost avg FPS/1% low and doubled max jitter versus v4 in the 18:51 three-way follow-up. |
| `ac6_fullcoreprev_llcvtime_v8` | v4 plus requiring full SMT-core idle for release `llc-vtime` default-user `prev` fastscan | Reject/unsafe; it activated, but AC6 exited during the v8 capture window and no MangoHud CSV was produced. |

Aggregate after the 19:01 incomplete v8 attempt.  The native and v4 captures
from that attempt were imported; v8 is excluded because it produced no valid
CSV.

| Label | Runs | Avg FPS | 1% low | 0.1% low | p99.9 ms | Max ms | Jitter avg | Jitter p95 | Jitter max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| native | 7 | 120.526 | 105.217 | 98.023 | 10.250 | 10.845 | 0.444 | 1.288 | 3.049 |
| `ac6_policy_llcvtime_v4` | 6 | 120.598 | 104.791 | 94.420 | 10.779 | 11.030 | 0.529 | 1.410 | 3.387 |

The 18:51 three-way follow-up report is:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game_experiments/ac6_nativefirst_llcvtime_v7_20260605T1851/armoredcore6/2026-06-05/reports/report.md
```

Single-run deltas from that follow-up:

| Label | Avg FPS | 1% low | 0.1% low | p99.9 ms | Max ms | FT stddev | Jitter avg | Jitter p95 | Jitter max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| native | 120.140 | 105.456 | 95.191 | 10.664 | 12.298 | 0.436 | 0.383 | 1.212 | 5.171 |
| `ac6_policy_llcvtime_v4` | 120.545 | 105.168 | 71.158 | 14.054 | 14.133 | 0.623 | 0.536 | 1.305 | 5.684 |
| `ac6_nativefirst_llcvtime_v7` | 120.411 | 104.138 | 78.674 | 14.056 | 19.712 | 0.751 | 0.647 | 1.490 | 11.413 |

The 19:01 v8 attempt report is:

```text
/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/game_experiments/ac6_fullcoreprev_llcvtime_v8_20260605T1901/armoredcore6/2026-06-05/reports/report.md
```

Single-run results before the v8 failure:

| Label | Avg FPS | 1% low | 0.1% low | p99.9 ms | Max ms | FT stddev | Jitter avg | Jitter p95 | Jitter max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| native | 121.165 | 105.790 | 100.671 | 9.948 | 10.426 | 0.484 | 0.425 | 1.245 | 2.600 |
| `ac6_policy_llcvtime_v4` | 120.214 | 103.841 | 91.282 | 10.977 | 11.587 | 0.618 | 0.585 | 1.736 | 3.882 |
| `ac6_fullcoreprev_llcvtime_v8` | no valid capture | no valid capture | no valid capture | no valid capture | no valid capture | no valid capture | no valid capture | no valid capture | no valid capture |

The v8 binary identity was:

```text
binary sha256 d846b5890bdf52b34b1602aa3bb0ad4fc0ed9b34fbec7fd6ee75adca09aed458
BPF sha256    211cf50cc7dbb77c2aaf6e5a32233b0e3e8f334a4a007ee09e20f14883d7b217
build UUID    51ec6a2e-2bc2-53b9-8221-165417d07d30
```

Runner evidence shows v8 started cleanly at local `2026-06-05 19:03:17`
and was unregistered at `19:05:55`, but Steam recorded AC6 leaving the running
list during that target window at local `19:04:24`.  Treat v8 as unsafe until a
fresh focused run disproves it; do not use it as performance evidence.

The durable signal is that the local fallback queue can strand frame-adjacent
work behind one CPU.  `llc-vtime` improves the worst AC6 tails and 0.1% lows,
but the 18:51 and 19:01 v4 repeats show the win is not robust enough to call
complete.  Native is currently smoother on aggregate; v4 remains the best valid
Cake candidate from this AC6 series but is incomplete.
The remaining weakness is small-frame jitter avg/p95 and occasional 0.1% tail
losses.  Do not continue profile roulette after v5/v6/v7; the next useful step
is low-overhead wake/dispatch instrumentation around SMT sibling placement,
fastscan `prev` hits, and native fallback shape so jitter can be attributed to a
specific action path.  Release route prediction was already off for these builds,
so do not chase route-predictor toggles for this AC6 result.

Current AC6 candidate rebuild:

```bash
SCX_CAKE_BUSY_WAKE_KICK=policy \
SCX_CAKE_QUEUE_POLICY=llc-vtime \
SCX_CAKE_STORM_GUARD=shield \
SCX_CAKE_QUANTUM_US=1000 \
cargo build -p scx_cake --release
```

For the next AC6/Kovaak's run, collect frame outcome and Cake action-path shape
as separate artifacts.  MangoHud remains the frame-time source.  Cake diagnostics
should run headless next to the same capture window:

```bash
sudo ./target/release/scx_cake \
  --verbose \
  --diag-dir /tmp/scx_cake_game_diag/<capture-id> \
  --diag-period 5
```

After the 60s MangoHud capture completes, convert the latest Cake diagnostic
snapshot into a stable ML feature packet:

```bash
BPF_OBJECT=$(find target/release/build -path '*/out/cake.bpf.o' -type f -printf '%T@ %p\n' \
  | sort -nr \
  | head -n1 \
  | cut -d' ' -f2-)

python3 scheds/rust/scx_cake/bench/scx_cake_game_diag_extract.py \
  --diag-json /tmp/scx_cake_game_diag/<capture-id>/cake_diag_latest.json \
  --game armoredcore6 \
  --scheduler ac6_policy_llcvtime_v4 \
  --scenario ac6_live_4k240_focused \
  --capture-id <capture-id> \
  --mangohud-csv /home/ritz/Benchmarks/<mangohud-capture>.csv \
  --binary target/release/scx_cake \
  --bpf-object "$BPF_OBJECT" \
  --repo . \
  --out-json /tmp/scx_cake_game_diag/<capture-id>/cake_action_features.json \
  --out-tsv /tmp/scx_cake_game_diag/<capture-id>/cake_action_features.tsv
```

The extractor records scheduler label, game/scenario/capture labels, MangoHud
CSV path, git head/dirty state, dirty scheduler-source diff hash,
`target/release/scx_cake` SHA-256, `cake.bpf.o` SHA-256, a deterministic
source UUID, and a deterministic build UUID.  The build UUID is derived from
binary/BPF/source identity, not from the scheduler label, so relabeling a run
does not invent a new build.  The feature body is kept off the BPF hot path: it
reuses existing debug/service-report counters such as fastscan route
hits/misses, scoreboard probe outcomes, native fallback rate, local-waiter
admission/reject rate, wake tail buckets, monitor states, and AC6-focused
interpretation tags.  Use this to learn *why* a game capture changed, not
merely whether average FPS moved.
