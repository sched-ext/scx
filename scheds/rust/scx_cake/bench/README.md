# Cake bench tools

The benchmark entry point is the scx root `cakebench`, which runs the sibling
`scx_cake_bench` repo. Read [STATE](../STATE.md) and [PERFORMANCE](../docs/PERFORMANCE.md)
before picking an experiment. Files here are diagnostics and models, not a second scoring
pipeline. Ignored local tools a clone lacks are listed in [STRUCTURE](../docs/STRUCTURE.md).

## 🧮 Offline checks and models

| Files | Purpose and limit |
|---|---|
| `comment_lint.py` | stale names, duplicate comments, comment density (ceiling 0.20) and block format |
| `fnspills.py` | per-function BPF stack spills; not runtime cost |
| `review_regressions.py`, `review_regressions.c` | extract scheduler functions into deterministic helper models; the C no longer compiles against current source |
| `topology_regressions.py`, `topology_regressions.c` | offline topology and policy cases using that extractor; stops on functions that no longer exist |
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

Captures and reports go to `scx_cake_bench/runs/` with source, binary, boot and workload
identity; generated models go to the scx `target/`; nothing next to these scripts.

The JIT primitive experiment has its own
[runner](https://github.com/RitzDaCat/experimental-patches/blob/main/kernel/sched-ext/research/jit-bitops-prototype/README.md);
it attaches no scheduler and does not replace cake or game A/Bs.
