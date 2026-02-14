---
title: LAVD simulator support
status: open
priority: 0
issue_type: epic
depends_on:
  sim-e5c8a: parent-child
  sim-d9988: related
  sim-35f7d: parent-child
  sim-56ad9: parent-child
  sim-64652: parent-child
created_at: 2026-02-13T17:58:00.341650825+00:00
updated_at: 2026-02-13T18:10:24.899924443+00:00
---

# Description

Add scx_lavd scheduler support to scx_simulator. LAVD is ~7500 lines of BPF code across 11 files. Requires arena/SDT stubs, per-CPU map emulation, cpumask extensions, BPF timer API, tick support, and new ops callbacks.

## Remaining gaps

- sim-64652: ops.dequeue callback
- sim-e5c8a: ops.update_idle callback
- sim-56ad9: ops.exit_task callback
- sim-35f7d: __COMPAT_scx_bpf_dsq_peek kfunc
- sim-d9988: Full BPF arena support (current stubs sufficient for basic LAVD)
