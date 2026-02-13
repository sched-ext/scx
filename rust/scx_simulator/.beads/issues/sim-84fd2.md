---
title: Implement mitosis scheduler kfuncs
status: closed
priority: 1
issue_type: feature
created_at: 2026-02-13T13:10:59.749117572+00:00
updated_at: 2026-02-13T14:06:58.468558154+00:00
closed_at: 2026-02-13T14:06:58.468558104+00:00
---

# Description

Implement the kfuncs needed for the scx_mitosis scheduler. Mitosis uses heavy cgroup and cpumask operations, LLC-aware scheduling, and task migration. Key areas:
- Cgroup hierarchy (currently stubs returning NULL)
- Per-cgroup/task BPF local storage
- Additional cpumask operations
- scx_bpf_cpuperf_set (already stubbed)
- bpf_for_each(css, ...) cgroup iteration (currently empty stub)

Some kfuncs are already stubbed (returning NULL/no-op). This issue covers making them functional enough for mitosis to run in the simulator.
