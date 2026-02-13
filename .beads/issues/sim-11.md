---
title: ops.exit_task support
status: open
priority: 1
issue_type: feature
depends_on:
  sim-1: parent-child
  sim-2: blocks
created_at: 2026-02-13T17:58:58.201540892+00:00
updated_at: 2026-02-13T17:59:49.970786743+00:00
---

# Description

Add exit_task callback to Scheduler trait and engine. LAVD implements lavd_exit_task(p, args). Needed for per-task arena cleanup (scx_task_free).
