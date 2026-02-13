---
title: IRQ context stubs (bpf_in_hardirq/nmi/serving_softirq)
status: open
priority: 2
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:59:11.212949415+00:00
updated_at: 2026-02-13T17:59:49.977216506+00:00
---

# Description

Always return false in simulator. LAVD calls bpf_in_hardirq (2x), bpf_in_nmi (4x), bpf_in_serving_softirq (3x) in main.bpf.c for context detection.
