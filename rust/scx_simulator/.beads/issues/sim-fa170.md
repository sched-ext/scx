---
title: __COMPAT_scx_bpf_dsq_peek implementation
status: closed
priority: 1
issue_type: feature
depends_on:
  sim-91615: blocks
  sim-6ba30: parent-child
created_at: 2026-02-13T17:58:58.203110673+00:00
updated_at: 2026-02-19T15:15:46.975088625+00:00
closed_at: 2026-02-19T15:15:46.975088515+00:00
---

# Description

Peek at head of DSQ without removing. Used by LAVD in balance.bpf.c:438,442 for task stealing between compute domains.
