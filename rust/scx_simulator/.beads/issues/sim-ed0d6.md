---
title: Re-enable Mitosis scheduler after kptr/RAII API update
status: open
priority: 2
issue_type: task
created_at: 2026-02-20T02:46:33.837344986+00:00
updated_at: 2026-02-20T02:46:33.837344986+00:00
---

# Description

The Mitosis scheduler was disabled during the simulator.v2 rebase because the upstream code now uses BPF kptr semantics and RAII-style cleanup attributes that require significant simulator support:

New APIs needed:
1. bpf_kptr_xchg() - atomically exchange a kptr and return old value
2. __free(cgroup) attribute - calls bpf_cgroup_release on scope exit
3. __free(bpf_cpumask) attribute - calls bpf_cpumask_release on scope exit
4. no_free_ptr() macro - transfers ownership, prevents __free cleanup
5. split_vtime_updates global was removed

The __free() pattern is used extensively:
- struct cgroup *rootcg __free(cgroup) = bpf_cgroup_from_id(root_cgid);
- struct bpf_cpumask *cpumask __free(bpf_cpumask) = ...;

Options:
A) Implement proper kptr support with reference counting in the simulator
B) Strip __free attributes with preprocessor and manage cleanup manually
C) Create wrapper stubs that bypass the kptr patterns

Files to update:
- schedulers/mitosis/wrapper.c.disabled
- crates/scx_simulator/tests/mitosis.rs.disabled
- crates/scx_simulator/tests/compare.rs.disabled
