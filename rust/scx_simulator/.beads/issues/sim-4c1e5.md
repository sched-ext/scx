---
title: 'rt-app workload parser: track unsupported features'
status: open
priority: 3
issue_type: task
created_at: 2026-02-13T21:03:22.681008578+00:00
updated_at: 2026-02-13T21:03:22.681008578+00:00
---

# Description

The rtapp module (src/rtapp.rs) parses rt-app JSON workloads into Scenario objects. It currently supports 7 of 17 event types: run/runtime, sleep, suspend, resume, timer (partial). Missing: lock/unlock (mutex), wait/signal/broad/sync (condvars), barrier, mem, iorun, yield, fork. Also missing task-level fields: cpus (affinity, currently ignored), taskgroup (cgroup, ignored), policy (only SCHED_OTHER), dl-runtime/period/deadline, util_min/max, delay, pi_enabled, per-phase overrides. Most sched_ext workloads use the supported subset. Synchronization primitives need a shared resource model in the engine.
