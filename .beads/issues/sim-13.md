---
title: scx_bpf_cpuperf_cur implementation
status: open
priority: 1
issue_type: feature
depends_on:
  sim-1: parent-child
  sim-2: blocks
created_at: 2026-02-13T17:58:58.204670830+00:00
updated_at: 2026-02-13T17:59:49.973914358+00:00
---

# Description

Read current CPU perf level. scx_bpf_cpuperf_set exists but cpuperf_cur does not. LAVD calls it in main.bpf.c:1624 and power.bpf.h:53.
