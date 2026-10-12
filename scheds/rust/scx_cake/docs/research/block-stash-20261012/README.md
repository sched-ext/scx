# Block stash: wake classification from one line (2026-10-12)

**Verdict: rejected.** No frame-time effect in KovaaK's; source reverted.
Kernel requirement: none (any sched_ext kernel).

## Why

perf c2c (`scx_cake_bench/runs/c2c_20261012/`, source-line attribution) showed
67 % of cake's cross-core HITM loads at four classifier lines in `select_cpu`:
the wakee's `se.sum_exec_runtime`, `nvcsw`, `sched_info.{run_delay,pcount}`,
three task_struct lines last written by the CPU the task ran on.

## What the patch does

[block-stash.patch](block-stash.patch), against `11744c11b`'s source:
`ops.stopping(!runnable)` writes `{pid, nvcsw+1, runtime + starved bits,
start_time, vtime}` to the second line of its CPU's run slot; wake sites
(`select_cpu`, `claim_warm`, `select_undecided`, admit, task slice, enqueue
wake route) read it when pid, seq, vtime and `!on_cpu` validate, else the task
lines. `nvcsw + 1`: `__schedule` counts the switch after `pick_next_task`,
after `ops.stopping`. Verifier accepts it.

## Evidence (hardware, game)

- Hit rate (probe): KovaaK's ~1 hit per `select_cpu`, 49 % of loads; `perf bench
  sched messaging` (320 tasks) 23 %, as other blockers overwrite the stash.
- A/B, `base` (`fe076988f` source) vs `blk`, KovaaK's menu, 6 × 20 s each:
  quiet avg FPS −0.03 %, p99 −0.3 %, 1 % low +0.9 %; 16 nice-10 hogs avg
  −0.3 %, p99.9 +3.5 %. All within slot-to-slot noise.

The removed HITMs (~2 per cross-CPU wake, ~30 ns) are too small next to frame
time to show; the miss path also pays one extra line. Raw data:
`scx_cake_bench/runs/kovaaks_blkstash_20261012/`.
