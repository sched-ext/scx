---
title: ops.dequeue support
status: open
priority: 1
issue_type: feature
depends_on:
  sim-6ba30: parent-child
  sim-91615: blocks
created_at: 2026-02-13T17:58:58.198196661+00:00
updated_at: 2026-02-13T18:10:24.901709387+00:00
---

# Description

Add dequeue callback to Scheduler trait and DynamicScheduler. LAVD implements lavd_dequeue(p, deq_flags). Called on task removal from runqueue.
