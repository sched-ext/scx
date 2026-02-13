---
title: Add cpu_release callback to Scheduler trait and engine
status: open
priority: 1
issue_type: feature
created_at: 2026-02-13T13:04:16.215801529+00:00
updated_at: 2026-02-13T13:07:58.513850707+00:00
---

# Description

COSMOS defines cosmos_cpu_release(cpu, args) which calls scx_bpf_reenqueue_local().
The Scheduler trait (ffi.rs) has no cpu_release method, and the engine never invokes it.

Work needed:
- Add cpu_release to SchedOps struct in ffi.rs
- Add cpu_release method to Scheduler trait with default no-op
- Implement scx_bpf_reenqueue_local kfunc (currently a no-op stub returning 0)
- Call cpu_release from the engine at appropriate points (when a CPU is preempted
  or yields, the previously-running task should be re-enqueued via this mechanism)
- Add tests exercising the cpu_release path

This is referenced by the TODO comment at ffi.rs:222.
