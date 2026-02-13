---
title: IRQ context stubs (bpf_in_hardirq/nmi/serving_softirq)
status: open
priority: 2
issue_type: feature
depends_on:
  sim-6ba30: parent-child
  sim-91615: blocks
created_at: 2026-02-13T17:59:11.212949415+00:00
updated_at: 2026-02-13T18:10:24.902829432+00:00
---

# Description

Always return false in simulator. LAVD calls bpf_in_hardirq (2x), bpf_in_nmi (4x), bpf_in_serving_softirq (3x) in main.bpf.c for context detection.
