---
title: 'Mitosis vtime starvation: tasks permanently starved on 1-CPU scenarios'
status: open
priority: 1
issue_type: task
created_at: 2026-02-19T23:46:39.324129470+00:00
updated_at: 2026-02-19T23:46:39.324129470+00:00
---

# Description

## Summary

Stress testing found a reproducible bug where mitosis starves tasks via vtime
ordering on single-CPU scenarios. A task enqueued with a slightly higher vtime
than its peers is never scheduled again because the other tasks' vtimes never
advance.

## Root Cause (preliminary)

After initial scheduling, tasks converge to the same vtime value (e.g.
343715100) and **never advance beyond it**. One task gets enqueued with a
slightly higher vtime (e.g. 363715100 — 20M higher). Since the vtime-ordered
DSQ always picks the lowest vtime first, and the other tasks' vtimes are frozen,
the higher-vtime task is permanently starved.

The frozen vtimes suggest either:
1. A real mitosis scheduler bug in vtime accounting
2. A simulator fidelity issue where runtime stats (e.g. se.sum_exec_runtime)
   needed for vtime calculation are not being updated

## Reproduction

STRESS_SEED=3525659 cargo test -p scx_simulator --release stress_random_mitosis -- --ignored --nocapture

Scenario: 1 CPU, 5 tasks, random behaviors (scenario_type=0).

Other failing seeds: 3525689, 3525719, 3525727, 3525757, 3525779, 3525787, 3525847.
All produce ErrorStall with the same vtime starvation pattern.

## Evidence

DSQ insertion trace shows vtime stuck at a constant value:

[     49_989_624] DSQ_INS_V pid=4 vtime=343715100
[     55_992_220] DSQ_INS_V pid=3 vtime=363715100   <-- higher, never picked again
[     69_990_574] DSQ_INS_V pid=2 vtime=343715100
[     75_983_511] DSQ_INS_V pid=1 vtime=343715100
[     83_170_666] DSQ_INS_V pid=5 vtime=343715100
[     86_929_882] DSQ_INS_V pid=4 vtime=343715100   <-- same vtime, never advances
[    106_930_884] DSQ_INS_V pid=2 vtime=343715100
... (continues forever at 343715100)

## Stats

Found by stress.sh: 948 tests (316 seeds x 3 schedulers).
- LAVD: 0 failures
- Simple: 0 failures
- Mitosis: 8 failures (all ErrorStall, all 1-CPU scenarios)

## Next Steps

- Investigate whether this is a mitosis bug or a simulator fidelity gap
- Check what runtime stats mitosis reads for vtime calculation
- Verify the simulator updates those stats correctly
