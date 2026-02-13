---
title: bpf_get_current_pid_tgid stub
status: closed
priority: 2
issue_type: feature
depends_on:
  sim-6ba30: parent-child
  sim-91615: blocks
created_at: 2026-02-13T17:59:11.214456683+00:00
updated_at: 2026-02-13T18:53:44.287826830+00:00
closed_at: 2026-02-13T18:53:44.287826759+00:00
---

# Description

Return simulated PID/TGID. Used once in lavd_init (main.bpf.c:2216) to record scheduler process PID.
