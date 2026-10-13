# Cake diagnostic and historical tools

The maintained benchmark entry point is repository-root `cakebench`, which
delegates to the sibling `scx_cake_bench` project. Run it from the scx root.
See [current status](../STATE.md) and [measurement guidance](../docs/PERFORMANCE.md)
before selecting an experiment. These in-tree files are not an alternative
score-producing pipeline.

This directory also contains ignored local profiling tools that a clone will
not include, such as `PROFILING.md`, `gameprobe.py`, and `wake_maxdecomp.py`.
The [full inventory](../docs/STRUCTURE.md) identifies their tracking status;
audit ownership and compatibility before treating them as maintained tools.

## Offline source checks and models

| Files | Purpose and limit |
|---|---|
| `comment_lint.py` | Source comment-density/style check |
| `fnspills.py` | Per-function BPF stack-spill attribution; not runtime cost |
| `review_regressions.py`, `review_regressions.c` | Extract scheduler functions into deterministic helper models |
| `topology_regressions.py`, `topology_regressions.c` | Offline topology and policy cases using that extractor |
| `pool_mark_ordering.py` | Model queue-mark interleavings; not a kernel concurrency proof |
| `arith_price.c`, `storage_price.c`, `qmark_price.c`, `floor_ladder.c`, `handoff_shape.c`, `decomp.c`, `wakecost.c`, `cakeload.c` | Standalone experiments and load/cost probes; read each source for assumptions and build instructions |

Models may describe an older source shape. Verify extraction against the current
functions before using their results. Compiled models and primitive timings do
not establish verifier acceptance, live scheduler safety or game performance.

## Capture and trace analysis

| Files | Purpose |
|---|---|
| `capture_preflight.py` | Capture environment/validity inspection |
| `scx_cake_thread_profile.py` | Thread-level diagnostics |
| `rt_displace_capture.sh` | Active system tracing; inspect permissions, output path and capture conditions first |
| `rt_displace.py`, `frame_attrib.py` | Trace displacement and frame attribution |
| `wake_occupant.py`, `wake_migsplit.py`, `migrate_cause.py` | Wake placement, occupancy and migration analysis |
| `scx_cake_game_diag_extract.py` | Extract retained game diagnostics |
| `scx_cake_bench_report.sh`, `scx_cake_config_audit.sh` | Historical artifact/report and configuration utilities; generated commands/schema may be stale |

Keep captures and measurement reports under `scx_cake_bench/runs/`, with source,
binary, boot and workload identity. Offline generated scheduler models belong
under the scx repository's `target/`. Do not place outputs alongside these scripts.

## Retired launchers

These intentionally refuse execution and point to `cakebench`; they are kept at
their old paths so callers receive a clear failure:

- `enq_kick_idle_ab.sh`, `enq_kick_idle_schbench_ab.sh`
- `scx_cake_bench_capture.sh`, `scx_cake_bench_suite.sh`
- `scx_cake_full_bench.sh`, `scx_cake_policy_bench.sh`
- `scx_cake_scheduler_matrix.sh`, `scx_cake_simple_bench.sh`

The old blanket claim that scoring is quarantined is obsolete. The maintained
artifact/paired-run route exists. Retired scripts should not be re-enabled or
treated as evidence that the maintained route is unavailable.

For the separate JIT primitive experiment, use its
[self-contained runner](https://github.com/RitzDaCat/experimental-patches/blob/main/kernel/sched-ext/research/jit-bitops-prototype/README.md).
It attaches no scheduler and does not replace Cake/game A/B measurements.
