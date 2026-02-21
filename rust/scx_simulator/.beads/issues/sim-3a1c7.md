---
title: ops.tick support in engine
status: closed
priority: 0
issue_type: feature
depends_on:
  sim-6ba30: parent-child
  sim-91615: blocks
created_at: 2026-02-13T17:58:44.059243643+00:00
updated_at: 2026-02-13T21:04:03.860164122+00:00
closed_at: 2026-02-13T21:04:03.860164021+00:00
---

# Description

Fire periodic tick events while a task is running. LAVD uses ops.tick (lavd_tick) for preemption checks. Kernel default interval is ~4ms. Need to add Tick event type to the engine event loop and schedule it when a task starts running.
