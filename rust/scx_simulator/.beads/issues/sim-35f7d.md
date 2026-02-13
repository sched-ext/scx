---
title: __COMPAT_scx_bpf_dsq_peek
status: open
priority: 1
issue_type: feature
depends_on:
  sim-db5df: blocks
created_at: 2026-02-13T18:13:24.014283768+00:00
updated_at: 2026-02-13T18:13:38.508221132+00:00
---

# Description

Peek at head of DSQ without removing. Used in balance.bpf.c for task stealing.
