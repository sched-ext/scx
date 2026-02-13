---
title: bpf_per_cpu_ptr / bpf_probe_read_kernel stubs
status: open
priority: 2
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:59:11.215879403+00:00
updated_at: 2026-02-13T17:59:49.980159293+00:00
---

# Description

bpf_per_cpu_ptr used in power.bpf.c:137 for freq reading. bpf_probe_read_kernel used in power.bpf.c:127. Both can return 0/NULL safely.
