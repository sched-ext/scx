# LAVD Simulator Support — Reference

Tracking: `mb list` / `mb ready` (minibeads, prefix `sim-`)

---

## Overview

scx_lavd (Latency-criticality Aware Virtual Deadline) is a sophisticated
scheduler with ~7,500 lines of BPF code across 11 files. It uses
deadline-based scheduling with latency-criticality metrics, per-domain
load balancing, core compaction, frequency scaling, and BPF arena
per-task storage.

**Source**: `scheds/rust/scx_lavd/src/bpf/`

**Ops callbacks (24 total)**:
`init`, `select_cpu`, `enqueue`, `dequeue`, `dispatch`, `runnable`,
`running`, `tick`, `stopping`, `quiescent`, `cpu_online`, `cpu_offline`,
`update_idle`, `set_cpumask`, `cpu_acquire`, `cpu_release`, `enable`,
`init_task`, `exit_task`, `cgroup_init`, `cgroup_exit`, `cgroup_move`,
`cgroup_set_bandwidth`, `exit`

---

## Key Risks

1. **Division by zero**: BPF division by zero returns 0. Native C
   crashes with SIGFPE. LAVD does many divisions (util calculations,
   frequency, load). Need systematic patching or a SIGFPE handler.

2. **Global initialization**: LAVD expects the Rust userspace to
   populate `cpdom_ctxs`, `cpu_capacity`, `cpu_sibling`, etc. before
   `init()`. The wrapper's `lavd_setup()` must simulate this topology
   setup correctly.

3. **Code volume**: 11 source files totaling ~7,500 lines. Many
   subtle interactions between balance, power, preempt, and idle
   subsystems. Incremental testing essential.

---

## LAVD Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.bpf.c` | ~2300 | Core ops: select_cpu, enqueue, dispatch, running, stopping, init |
| `lavd.bpf.h` | ~460 | Data structures, constants, extern declarations |
| `util.bpf.c` | ~340 | Per-CPU context access, EWMA, helpers |
| `balance.bpf.c` | ~470 | Task stealing between compute domains |
| `idle.bpf.c` | ~840 | Idle CPU selection with topology awareness |
| `power.bpf.c` | ~860 | Core compaction, frequency scaling, turbo |
| `preempt.bpf.c` | ~360 | Preemption logic (yield + kick) |
| `sys_stat.bpf.c` | ~580 | Periodic system statistics via BPF timer |
| `lat_cri.bpf.c` | ~290 | Latency criticality calculation |
| `introspec.bpf.c` | ~120 | Ring buffer introspection output |
| `lock.bpf.c` | ~40 | Futex lock boosting |
| `intf.h` | ~200 | Shared interface (Rust <-> BPF) |

## Global Variables (set by Rust userspace before BPF load)

These must be initialized by `lavd_setup(nr_cpus)` in the wrapper:

| Variable | Type | Purpose |
|----------|------|---------|
| `cpdom_ctxs[LAVD_CPDOM_MAX_NR]` | `struct cpdom_ctx` | Compute domain config (id, numa_id, llc_id, is_big, is_valid, cpumask, neighbors) |
| `cpu_capacity[LAVD_CPU_ID_MAX]` | `u16` | Per-CPU capacity (1024 = max) |
| `cpu_big[LAVD_CPU_ID_MAX]` | `u8` | Big core flag per CPU |
| `cpu_turbo[LAVD_CPU_ID_MAX]` | `u8` | Turbo-capable flag per CPU |
| `cpu_sibling[LAVD_CPU_ID_MAX]` | `u32` | SMT sibling CPU ID |
| `nr_llcs` | `u64` | Number of LLC domains |
| `nr_cpu_ids` | `u32` | Number of CPU IDs |
| `nr_cpus_onln` | `u64` | Number of online CPUs |
