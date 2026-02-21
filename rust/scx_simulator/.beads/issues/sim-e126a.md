---
title: Fix scx_bpf_task_cpu semantic inaccuracy
status: closed
priority: 1
issue_type: bug
created_at: 2026-02-13T13:04:34.709807773+00:00
updated_at: 2026-02-13T13:15:57.838035537+00:00
closed_at: 2026-02-13T13:15:57.838035467+00:00
---

# Description

scx_bpf_task_cpu (kfuncs.rs:395) returns sim.current_cpu (the CPU servicing the
current callback) instead of the task's last-scheduled CPU. In the real kernel,
scx_bpf_task_cpu(p) returns task_cpu(p) which is stored per-task.

This matters in cosmos_enqueue where the task's prev_cpu may differ from the CPU
running the enqueue callback (e.g., if a task was migrated or is being woken on
a different CPU).

Fix:
- Track last_cpu per task in SimTask (set when a task starts running on a CPU)
- scx_bpf_task_cpu should look up the task from the raw pointer and return its
  last_cpu, not current_cpu
- This is a correctness fix, not a new feature
