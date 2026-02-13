---
title: Simulate address-space affinity (mm_affinity)
status: closed
priority: 3
issue_type: feature
created_at: 2026-02-13T13:04:28.379110510+00:00
updated_at: 2026-02-13T14:49:15.112778650+00:00
closed_at: 2026-02-13T14:49:15.112778580+00:00
---

# Description

COSMOS supports address-space affinity for wake-affine scheduling
(mm_affinity=false disables this). When enabled:

- is_wake_affine() checks if waker and wakee share an address space
- If wake-affine, the task is dispatched directly to the waker's CPU local DSQ
  instead of going through the shared DSQ
- This improves cache locality for threads in the same process

Work needed:
- Model address spaces / process grouping in simulated tasks
- Implement bpf_get_current_task_btf to return the waker task correctly
- Track which task is performing the wakeup (waker context)
- Add COSMOS test config with mm_affinity=true
- Add tests with multi-threaded workloads (shared address space) verifying
  wake-affine dispatch
