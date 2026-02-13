---
title: ops.update_idle support
status: open
priority: 1
issue_type: feature
depends_on:
  sim-1: parent-child
  sim-2: blocks
created_at: 2026-02-13T17:58:58.199671159+00:00
updated_at: 2026-02-13T17:59:49.969354048+00:00
---

# Description

Add update_idle callback to Scheduler trait and engine. LAVD implements lavd_update_idle(cpu, idle). Notifies scheduler when CPU idle state changes.
