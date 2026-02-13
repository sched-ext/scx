---
title: Simulate deferred wakeups (BPF timers)
status: closed
priority: 2
issue_type: feature
created_at: 2026-02-13T13:04:26.558951749+00:00
updated_at: 2026-02-13T14:30:10.388504150+00:00
closed_at: 2026-02-13T14:30:10.388504070+00:00
---

# Description

COSMOS uses BPF timers for deferred wakeups (deferred_wakeups=false disables this).
When enabled:

- cosmos_init sets up a BPF timer with wakeup_timerfn callback
- wakeup_cpu() arms the timer instead of immediately kicking the CPU
- wakeup_timerfn fires later, checks if the CPU is still idle, then kicks it
- This reduces unnecessary IPIs by batching wakeups

Work needed:
- Implement BPF timer infrastructure in the simulator (currently stubbed to 0)
  - bpf_timer_init, bpf_timer_set_callback, bpf_timer_start
- Add timer events to the discrete event queue
- Implement wakeup_timerfn callback dispatch
- Remove deferred_wakeups=false from cosmos_setup
- Add tests verifying deferred wakeup behavior
- May also need scx_bpf_dsq_nr_queued to return meaningful values (currently
  implemented but only called from this dead path)
