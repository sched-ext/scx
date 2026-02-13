---
title: bpf_get_current_pid_tgid stub
status: open
priority: 2
issue_type: feature
depends_on:
  sim-2: blocks
  sim-1: parent-child
created_at: 2026-02-13T17:59:11.214456683+00:00
updated_at: 2026-02-13T17:59:49.978616703+00:00
---

# Description

Return simulated PID/TGID. Used once in lavd_init (main.bpf.c:2216) to record scheduler process PID.
