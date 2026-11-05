# Cake bench tools

The benchmark entry point is the scx root `cakebench`, which runs the sibling
`scx_cake_bench` repo. Read [STATE](../STATE.md) and [PERFORMANCE](../docs/PERFORMANCE.md)
before picking an experiment. Files here are diagnostics and models, not a second scoring
pipeline. Ignored local tools a clone lacks are listed in [STRUCTURE](../docs/STRUCTURE.md).

## 🧮 Offline checks and models

| Files | Purpose and limit |
|---|---|
| `comment_lint.py` | comment density and style (default ceiling 0.30; the rule is 0.20: `--max-ratio 0.20`) |
| `fnspills.py` | per-function BPF stack spills; not runtime cost |
| `review_regressions.py`, `review_regressions.c` | extract scheduler functions into deterministic helper models |
| `topology_regressions.py`, `topology_regressions.c` | offline topology and policy cases using that extractor |
| `pool_mark_ordering.py` | queue-mark interleaving model; not a kernel concurrency proof |
| `arith_price.c`, `storage_price.c`, `qmark_price.c`, `floor_ladder.c`, `handoff_shape.c`, `decomp.c`, `wakecost.c`, `cakeload.c` | standalone cost and load probes; read each source for its assumptions and build line |

Models may describe an older source shape: check the extraction against the current
functions first. Compiled models and primitive timings prove neither verifier
acceptance, live safety nor game performance.

## 🎥 Capture and trace analysis

| Files | Purpose |
|---|---|
| `capture_preflight.py` | capture environment and validity check |
| `scx_cake_thread_profile.py` | thread-level diagnostics |
| `rt_displace_capture.sh` | live system tracing; check permissions, output path and conditions first |
| `rt_displace.py`, `frame_attrib.py` | trace displacement and frame attribution |
| `wake_occupant.py`, `wake_migsplit.py`, `migrate_cause.py` | wake placement, occupancy and migration analysis |
| `scx_cake_game_diag_extract.py` | extract retained game diagnostics |
| `scx_cake_bench_report.sh`, `scx_cake_config_audit.sh` | old report and config utilities; their commands and schema may be stale |

Captures and reports go to `scx_cake_bench/runs/` with source, binary, boot and workload
identity; generated models go to the scx `target/`; nothing next to these scripts.

## 🚫 Retired launchers

These refuse to run and point to `cakebench`; they stay at their old paths so old callers
fail clearly. Do not re-enable them; the maintained artifact and paired-run route exists.

`enq_kick_idle_ab.sh` · `enq_kick_idle_schbench_ab.sh` · `scx_cake_bench_capture.sh` ·
`scx_cake_bench_suite.sh` · `scx_cake_full_bench.sh` · `scx_cake_policy_bench.sh` ·
`scx_cake_scheduler_matrix.sh` · `scx_cake_simple_bench.sh`

The JIT primitive experiment has its own
[runner](https://github.com/RitzDaCat/experimental-patches/blob/main/kernel/sched-ext/research/jit-bitops-prototype/README.md);
it attaches no scheduler and does not replace cake or game A/Bs.
