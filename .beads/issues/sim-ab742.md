---
title: scx_bpf_cpuperf_cur implementation
status: open
priority: 1
issue_type: feature
depends_on:
  sim-91615: blocks
  sim-6ba30: parent-child
created_at: 2026-02-13T17:58:58.204670830+00:00
updated_at: 2026-02-13T18:10:24.902467096+00:00
---

# Description

Read current CPU perf level. scx_bpf_cpuperf_set exists but cpuperf_cur does not. LAVD calls it in main.bpf.c:1624 and power.bpf.h:53.
