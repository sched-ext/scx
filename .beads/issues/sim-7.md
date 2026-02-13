---
title: ops.tick support in engine
status: open
priority: 0
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:58:44.059243643+00:00
updated_at: 2026-02-13T17:59:49.966453865+00:00
---

# Description

Fire periodic tick events while a task is running. LAVD uses ops.tick (lavd_tick) for preemption checks. Kernel default interval is ~4ms. Need to add Tick event type to the engine event loop and schedule it when a task starts running.
