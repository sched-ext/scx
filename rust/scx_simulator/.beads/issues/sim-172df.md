---
title: bpf_per_cpu_ptr / bpf_probe_read_kernel stubs
status: closed
priority: 2
issue_type: feature
depends_on:
  sim-6ba30: parent-child
  sim-91615: blocks
created_at: 2026-02-13T17:59:11.215879403+00:00
updated_at: 2026-02-13T18:53:44.287895122+00:00
closed_at: 2026-02-13T18:53:44.287895052+00:00
---

# Description

bpf_per_cpu_ptr used in power.bpf.c:137 for freq reading. bpf_probe_read_kernel used in power.bpf.c:127. Both can return 0/NULL safely.
