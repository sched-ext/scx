---
title: ops.exit_task support
status: closed
priority: 1
issue_type: feature
depends_on:
  sim-91615: blocks
  sim-6ba30: parent-child
created_at: 2026-02-13T17:58:58.201540892+00:00
updated_at: 2026-02-19T18:28:26.850021898+00:00
closed_at: 2026-02-19T18:28:26.850021788+00:00
---

# Description

Add exit_task callback to Scheduler trait and engine. LAVD implements lavd_exit_task(p, args). Needed for per-task arena cleanup (scx_task_free).
