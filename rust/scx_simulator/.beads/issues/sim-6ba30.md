---
title: LAVD simulator support
status: open
priority: 0
issue_type: epic
depends_on:
  sim-b89a6: parent-child
  sim-d9988: related
  sim-fa170: parent-child
  sim-2db12: parent-child
  sim-64652: parent-child
created_at: 2026-02-13T17:58:00.341650825+00:00
updated_at: 2026-02-13T18:10:24.899924443+00:00
---

# Description

Add scx_lavd scheduler support to scx_simulator. LAVD is ~7500 lines of BPF code across 11 files. Requires arena/SDT stubs, per-CPU map emulation, cpumask extensions, BPF timer API, tick support, and new ops callbacks.

## Remaining gaps

- sim-64652: ops.dequeue callback
- sim-b89a6: ops.update_idle callback
- sim-2db12: ops.exit_task callback
- sim-fa170: __COMPAT_scx_bpf_dsq_peek kfunc
- sim-d9988: Full BPF arena support (current stubs sufficient for basic LAVD)
