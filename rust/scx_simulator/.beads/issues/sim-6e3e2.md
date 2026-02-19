---
title: Cgroup lifecycle modeling for mitosis coverage
status: open
priority: 1
issue_type: task
created_at: 2026-02-19T08:55:50.931864539+00:00
updated_at: 2026-02-19T08:55:50.931864539+00:00
---

## Motivation

Mitosis coverage is stuck at 51.8% line coverage (sim-010a1). The largest
category of uncovered code is the cgroup-driven cell reconfiguration system:
CSS iterator bodies (89 lines), unloaded cgroup ops (61 lines), and functions
only reachable through cgroup paths (130+ lines). Implementing cgroup lifecycle
modeling would unlock approximately **256 additional lines** and raise mitosis
line coverage to an estimated **75.3%**.

## Scope

This issue covers the minimal cgroup modeling needed to exercise mitosis's
cgroup-based cell assignment. It does NOT aim for full cgroup v2 semantics —
just enough to make the relevant scheduler code paths reachable.

## What Mitosis Needs from Cgroups

1. **Multi-cgroup hierarchy**: Tasks belong to non-root cgroups at depth >= 1.
   Currently all tasks belong to a single root cgroup (level 0, cgid 1).

2. **CSS iteration**: `bpf_for_each(css, cur, root, flags)` must iterate
   descendant cgroups. Currently stubbed as an empty loop in `sim_wrapper.h:187`.

3. **Cgroup storage**: `bpf_cgrp_storage_get` must work per-cgroup (not just
   root). The existing `wrapper.c` implementation supports up to 64 cgroups
   via a pointer-keyed array — this is sufficient.

4. **Cgroup ops**: `cgroup_init` and `cgroup_exit` (or their tracepoint
   equivalents `tp_cgroup_mkdir`/`tp_cgroup_rmdir` when `cpu_controller_disabled`)
   must fire during cgroup creation/destruction.

5. **Cpuset modeling**: Cgroups need a `cpuset.cpus` configuration that
   `get_cgroup_cpumask` can read. This drives cell allocation in the timer.

6. **Cgroup ancestor lookup**: `bpf_cgroup_ancestor(cgrp, level)` and
   `bpf_cgroup_from_id(id)` must return the correct cgroup for non-root
   cgroups.

## Implementation Plan

### Phase 1: Cgroup Data Model

Add a cgroup registry to the simulator. Each cgroup needs:
- `cgid: u64` — unique identifier
- `level: u32` — depth in the hierarchy (root = 0)
- `parent_cgid: u64` — parent cgroup's ID
- `cpuset: Option<Vec<CpuId>>` — optional cpuset.cpus assignment
- A `struct cgroup` C allocation (extending `sim_task.c`'s `sim_get_root_cgroup`)

**Files:** New `src/cgroup.rs` module, extend `csrc/sim_task.c`.

The root cgroup (cgid=1, level=0) already exists. New cgroups are created by
tests as part of scenario setup.

### Phase 2: CSS Iterator Implementation

Replace the empty `_bpf_for_each_css` stub with a real iterator:

```c
// sim_wrapper.h — replace empty stub
extern struct cgroup_subsys_state *sim_css_next(
    struct cgroup_subsys_state *root, struct cgroup_subsys_state *prev);

#define _bpf_for_each_css(cur, root, flags) \
    for (cur = sim_css_next(root, NULL); cur != NULL; \
         cur = sim_css_next(root, cur))
```

`sim_css_next` walks the cgroup registry in pre-order (depth-first,
parent-before-children), matching kernel `BPF_CGROUP_ITER_DESCENDANTS_PRE`
semantics. It returns `&cgrp->self` for each cgroup, and NULL when done.

**Files:** `csrc/sim_cgroup.c` (new), `csrc/sim_wrapper.h`.

### Phase 3: Cgroup Ops Loading

Extend `ffi.rs` to load these ops (same pattern as `set_cpumask`/`dump`):

- `cgroup_init(cgrp) -> s32` — called when a cgroup is created
- `cgroup_exit(cgrp) -> s32` — called when a cgroup is destroyed
- `cgroup_move(p, from, to)` — called when a task moves between cgroups

Extend `engine.rs` to call these ops:
- `cgroup_init` during scenario setup for each non-root cgroup
- `cgroup_exit` during teardown (before `exit`)
- `cgroup_move` when a task is reassigned to a different cgroup

When `cpu_controller_disabled=true`, the tracepoint equivalents fire instead.
The wrapper.c already has `cpu_controller_disabled` guards in the cgroup ops,
so we need to model EITHER the ops path (cpu_controller=false) OR the
tracepoint path (cpu_controller=true). Since mitosis defaults to
`cpu_controller_disabled=true`, the tracepoint path is more important.

To model the tracepoint path, we can call the tracepoint entry points directly:
`tp_cgroup_mkdir(cgrp, path)` and `tp_cgroup_rmdir(cgrp, path)`. Load these
as additional function pointers.

### Phase 4: Cgroup Ancestor / Lookup Overrides

Update `wrapper.c` overrides:

- `mitosis_cgroup_ancestor(cgrp, level)`: Look up ancestor in the cgroup
  registry instead of returning root-only.
- `mitosis_cgroup_from_id(id)`: Look up any cgroup by ID instead of
  root-only.

**Files:** `schedulers/mitosis/wrapper.c`.

### Phase 5: Cpuset Modeling

Add `cpuset` configuration to cgroups. Mitosis reads cpusets via
`get_cgroup_cpumask` which accesses `cgrp->subsys[cpuset_cgrp_id]` and reads
`struct cpuset::cpus_allowed`.

Options:
- (a) **Stub `struct cpuset`**: Allocate a cpuset struct per cgroup with a
  `cpus_allowed` field, and wire `cgrp->subsys[cpuset_cgrp_id]` to point to
  its CSS. This is the most faithful approach.
- (b) **Override `get_cgroup_cpumask`**: Replace it entirely in wrapper.c to
  read from the cgroup registry. Simpler but deviates from kernel code path.

Option (a) is preferred for kernel fidelity. The struct layout needs to match
what `bpf_core_type_matches` and `bpf_core_read` expect.

### Phase 6: Scenario API and Tests

Add cgroup operations to the `Scenario` builder:

```rust
Scenario::new(4)
    .cgroup("web", &[0, 1])        // cgid=2, cpuset={0,1}
    .cgroup("batch", &[2, 3])      // cgid=3, cpuset={2,3}
    .task(Pid(1), "web-worker")
        .cgroup("web")             // assign to web cgroup
        .phase(Phase::Run(ms(50)))
    .task(Pid(2), "batch-job")
        .cgroup("batch")
        .phase(Phase::Run(ms(100)))
    .build()
```

Write tests exercising:
- Multi-cell scheduling (tasks in different cells dispatched to correct CPUs)
- Timer-driven cell reconfiguration (bump `configuration_seq`, fire timer)
- Cgroup creation/destruction lifecycle
- Task cgroup migration (when cpu_controller_disabled, via cgid change)
- Nested cgroups (depth > 1, ancestor lookup)
- Debug events for cgroup init/exit

## Coverage Impact Estimate

| Category                              | Lines Unlocked |
|---------------------------------------|----------------|
| CSS iterator body (timer + init)      | ~89            |
| Cgroup ops bodies                     | ~44            |
| `init_cgrp_ctx` + callers            | ~34            |
| `allocate_cell` / `free_cell`        | ~26            |
| `get_cgroup_cpumask`                 | ~20            |
| `record_cgroup_init` / `exit`        | ~28            |
| `lookup_cgrp_ancestor`               | ~5             |
| Dump debug event cases               | ~11            |
| `maybe_refresh_cell` cgid path       | ~1             |
| Misc (ancestors loop, cpumask entry) | ~10            |
| **Total**                            | **~256**       |

**Projected coverage**: 565 + 256 = 821 / 1090 = **75.3% line coverage**
(up from 51.8%).

## Dependencies

- This issue has no blockers.
- Blocked issues: sim-010a1 (coverage tracking) depends on this for further
  progress.

## Risks

- **Cpuset struct layout**: `get_cgroup_cpumask` uses `bpf_core_type_matches`
  and `bpf_core_read` to handle different kernel struct layouts. In the
  simulator these are overridden, so we need the override to match whichever
  branch the compiled code takes.
- **CSS iteration ordering**: The timer callback assumes pre-order traversal
  and uses a `level_cells[]` array to track parent cells. The iterator must
  produce cgroups in this order.
- **Kernel fidelity**: Cgroup ops fire at specific lifecycle points. We must
  match kernel ordering: `cgroup_init` before any task can be scheduled in the
  cgroup, `cgroup_exit` only after all tasks have left.
