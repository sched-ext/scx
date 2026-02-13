---
title: ops.dequeue support
status: open
priority: 1
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:58:58.198196661+00:00
updated_at: 2026-02-13T17:59:49.967888172+00:00
---

# Description

Add dequeue callback to Scheduler trait and DynamicScheduler. LAVD implements lavd_dequeue(p, deq_flags). Called on task removal from runqueue.
