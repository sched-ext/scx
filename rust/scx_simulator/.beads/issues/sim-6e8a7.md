---
title: Implement scx_bpf_select_cpu_and kfunc
status: closed
priority: 2
issue_type: feature
depends_on:
  sim-5a20c: blocks
created_at: 2026-02-13T13:04:33.380874766+00:00
updated_at: 2026-02-13T13:48:08.750415259+00:00
closed_at: 2026-02-13T13:48:08.750415179+00:00
---

# Description

COSMOS uses scx_bpf_select_cpu_and (newer kernel API) for CPU selection with
primary domain filtering and SMT-aware flags (SCX_PICK_IDLE_CORE). Currently
forced to the fallback scx_bpf_select_cpu_dfl via bpf_ksym_exists override.

Work needed:
- Implement scx_bpf_select_cpu_and kfunc with support for:
  - Primary cpumask filtering
  - SCX_PICK_IDLE_CORE flag (requires SMT topology)
  - Other selection flags COSMOS uses
- Remove bpf_ksym_exists(sym) -> 0 override from wrapper.c
- Depends on SMT topology (sim-5a20c) for IDLE_CORE support
- Depends on primary domain modeling for cpumask filtering
