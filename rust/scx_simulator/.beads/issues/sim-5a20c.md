---
title: Simulate SMT topology
status: open
priority: 1
issue_type: feature
created_at: 2026-02-13T13:04:19.322443033+00:00
updated_at: 2026-02-13T13:07:58.514306401+00:00
---

# Description

COSMOS has extensive SMT awareness that is entirely disabled (smt_enabled=false,
avoid_smt=false). Three feature areas are affected:

1. Idle-core scanning: pick_idle_cpu_flat() uses SMT masks to find fully idle
   cores, preferring them over partially-idle ones.
2. SMT contention detection: is_smt_contended() checks if a sibling CPU is
   running a non-idle task, used in need_migrate() and cosmos_dispatch.
3. avoid_smt mode: When enabled, tasks avoid sharing cores with other tasks.

Work needed:
- Model SMT topology in SimCpu (sibling relationships, core grouping)
- Implement scx_bpf_get_idle_smtmask kfunc (currently returns empty mask)
- Implement scx_bpf_cpu_to_smt_group or equivalent topology query
- Add COSMOS test configuration with smt_enabled=true, avoid_smt=true
- Verify is_smt_contended, need_migrate, and idle-core paths are exercised

This is one of the most impactful features for realistic scheduling simulation
since SMT contention is a major real-world performance concern.
