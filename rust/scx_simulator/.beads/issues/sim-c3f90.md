---
title: CSS iterator not populated before BPF timer callbacks
status: closed
priority: 1
issue_type: task
created_at: 2026-02-21T21:38:17.566436619+00:00
updated_at: 2026-02-21T22:25:07.573299230+00:00
closed_at: 2026-02-21T22:25:07.573299119+00:00
---

# Description

## Problem

`prepare_css_iter_from_root()` is fully implemented in `cgroup.rs` (lines 541-562) but is dead code — never called from any execution path. The C-side array `sim_css_list[]` is never populated, so `bpf_for_each(css, ...)` in BPF callbacks iterates zero cgroups.

The critical gap is `handle_timer_fired` in `engine.rs` (lines 1175-1207). It calls `self.scheduler.fire_timer()` without first calling `cgroup_registry.prepare_css_iter_from_root()`. The mitosis `update_timer_cb` uses `bpf_for_each(css, ...)` to discover cgroups, read cpusets, and assign cell cpumasks — but the loop body never executes.

Consequences:
- All tasks stay in cell 0 (root) with access to all CPUs
- `applied_configuration_seq` never advances
- Cell isolation only holds coincidentally

Also affects `ops.init` when `cpu_controller_disabled = true`.

## Fix

1. Add `cgroup_registry: &CgroupRegistry` parameter to `handle_timer_fired`
2. Call `cgroup_registry.prepare_css_iter_from_root()` before `self.scheduler.fire_timer()`
3. Also call it before `self.scheduler.init()` in the init path
4. Update tests to verify cell assignment actually happens after timer fires

## Key files

- engine.rs — `handle_timer_fired` (line 1175)
- cgroup.rs — `prepare_css_iter_from_root` (line 557)
- csrc/sim_cgroup.c — `sim_css_list[]`, `sim_css_next()`
- mitosis.bpf.c — `update_timer_cb` (line 972)

Related: sim-b7d70 (mitosis test TODO markers depend on this fix).
