---
title: ops.exit_task support
status: open
priority: 1
issue_type: feature
depends_on:
  sim-91615: blocks
  sim-6ba30: parent-child
created_at: 2026-02-13T17:58:58.201540892+00:00
updated_at: 2026-02-13T18:10:24.902086744+00:00
---

# Description

Add exit_task callback to Scheduler trait and engine. LAVD implements lavd_exit_task(p, args). Needed for per-task arena cleanup (scx_task_free).
