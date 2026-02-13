---
title: Simulator trace lacks balance/dispatch granularity for real-trace comparison
status: open
priority: 3
issue_type: task
labels:
  - realism
created_at: 2026-02-13T21:26:38.505453075+00:00
updated_at: 2026-02-13T21:26:38.505453075+00:00
---

# Description

When comparing bpftrace traces from a real sched_ext run to simulator output, the simulator combines the kernel's 4-step context switch (put_prev_task -> balance -> pick_task -> set_next_task) into 2 events (PREEMPT/YIELD -> SCHED). There are no trace events for the dispatch path (balance, dsq_move_to_local, dsq_nr_queued, pick_task) or the wake path (select_task_rq, dsq_insert). This makes it impossible to compare dispatch-level behavior between real and simulated runs. Consider adding optional TraceKind variants for Dispatch, DsqInsert, SelectCpu, and PickTask.
