---
title: Model SCX_OPSS ops_state to gate ops.dequeue calls
status: closed
priority: 2
issue_type: feature
labels:
- realism
depends_on:
  sim-6ba30: parent-child
created_at: 2026-02-14T10:12:28.591999570+00:00
updated_at: 2026-02-14T10:32:56.183777207+00:00
closed_at: 2026-02-14T10:32:56.183777057+00:00
---

# Description

The kernel tracks per-task ops_state (SCX_OPSS_NONE, SCX_OPSS_QUEUED, etc). ops.dequeue is only called when the task is in SCX_OPSS_QUEUED state (accepted by the BPF scheduler but not yet dispatched to a CPU). Currently the simulator calls dequeue unconditionally when a task goes to sleep, which is not kernel-accurate: a running task has already left QUEUED state when it was dispatched. Model ops_state so dequeue is only called when the task is genuinely queued.
