---
title: bpf_per_cpu_ptr / bpf_probe_read_kernel stubs
status: open
priority: 2
issue_type: feature
depends_on:
  sim-91615: blocks
  sim-6ba30: parent-child
created_at: 2026-02-13T17:59:11.215879403+00:00
updated_at: 2026-02-13T18:10:24.903215322+00:00
---

# Description

bpf_per_cpu_ptr used in power.bpf.c:137 for freq reading. bpf_probe_read_kernel used in power.bpf.c:127. Both can return 0/NULL safely.
