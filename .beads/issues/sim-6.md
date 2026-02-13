---
title: BPF timer API (bpf_timer_init/set_callback/start)
status: open
priority: 0
issue_type: feature
depends_on:
  sim-1: parent-child
  sim-2: blocks
created_at: 2026-02-13T17:58:44.057817347+00:00
updated_at: 2026-02-13T17:59:49.965057845+00:00
---

# Description

Map LAVD's direct bpf_timer API to simulator's timer mechanism. LAVD fires timer from init_sys_stat() -> update_timer_cb() every LAVD_SYS_STAT_INTERVAL_NS. Simulator already has sim_timer_start for COSMOS but LAVD uses the full BPF timer API directly (bpf_timer_init, bpf_timer_set_callback, bpf_timer_start). Currently stubbed as no-op macros in sim_wrapper.h.
