---
title: bpf_printk stub
status: open
priority: 3
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:59:11.217337276+00:00
updated_at: 2026-02-13T17:59:49.981631628+00:00
---

# Description

Map to eprintln or tracing debug!. Used in lavd.bpf.h:313,320 as debug output wrapper.
