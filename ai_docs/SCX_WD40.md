# scx_wd40
Generated: 2026-02-21, git-depth 7778

## Overview

scx_wd40 is an experimental multi-domain BPF/userspace hybrid scheduler for
the Linux `sched_ext` framework. It is a fork of `scx_rusty` that replaces
traditional BPF map-based shared state with **BPF arenas**, enabling direct
memory sharing between the kernel BPF program and the Rust userspace
component.

The scheduler partitions CPUs into **domains** (typically one per LLC/L3
cache) and performs simple vtime-based or FIFO scheduling within each domain.
The BPF component handles the scheduling hot path (CPU selection, enqueue,
dispatch, work stealing), while the Rust userspace component handles two
asynchronous control loops:

- **Tuner** (high-frequency, default 100ms): Monitors per-CPU utilization
  from `/proc/stat` and dynamically adjusts which CPUs participate in greedy
  cross-domain task stealing. Also adjusts the scheduling time slice based
  on system utilization.

- **Load Balancer** (low-frequency, default 2s): Reads per-domain duty-cycle
  averages from BPF, computes load imbalances across NUMA nodes and domains,
  and directs task migrations by setting `target_dom` in each task's BPF
  context.

**Production readiness**: No. scx_wd40 heavily uses BPF arenas and
routinely requires a bleeding-edge kernel toolchain.

## Architecture / Design (Fork of scx_rusty)

scx_wd40 shares the same overall architecture as `scx_rusty` -- a
multi-domain, NUMA-aware, hybrid BPF/userspace scheduler. The key
architectural differences from scx_rusty are:

1. **BPF Arenas instead of BPF Maps**: Task context (`task_ctx`) and domain
   context (`dom_ctx`) are allocated in BPF arena memory rather than in BPF
   hash/array maps. This eliminates map lookups in the hot path and allows
   userspace to directly dereference the same memory via raw pointers.

2. **Modular BPF source layout**: The BPF code is split across multiple
   compilation units (`main.bpf.c`, `common.bpf.c`, `deadline.bpf.c`,
   `lb_domain.bpf.c`, `placement.bpf.c`) rather than a single monolithic
   file, demonstrating how BPF schedulers can be built from reusable modules.

3. **Topology library integration**: Domain-to-CPU mapping uses the
   `lib/topology.h` topo_nodes infrastructure rather than per-CPU BPF maps.

The codebase is organized as follows:

| Component | File(s) | Role |
|---|---|---|
| BPF scheduling hot path | `main.bpf.c` | `select_cpu`, `enqueue`, `dispatch`, lifecycle callbacks |
| Shared types & constants | `intf.h`, `types.h` | Data structures shared between BPF and userspace |
| Domain management | `lb_domain.bpf.c`, `lb_domain.h` | Arena allocation, duty-cycle tracking, domain lookups |
| Deadline computation | `deadline.bpf.c` | Vtime/deadline calculation, interactivity boosting |
| Task placement | `placement.bpf.c` | Domain selection, mempolicy affinity, domain migration |
| Common utilities | `common.bpf.c` | Statistics, NUMA ID lookup, global variables |
| Rust entry point | `main.rs` | BPF skeleton setup, arena init, main scheduling loop |
| Domain abstraction | `domain.rs` | `Domain` and `DomainGroup` structs wrapping topology |
| Load balancer | `load_balance.rs` | Hierarchical NUMA/domain load balancing |
| Tuner | `tuner.rs` | Per-CPU utilization tracking, greedy mask updates |
| Statistics | `stats.rs` | `ClusterStats`, `NodeStats`, `DomainStats`, stats server |

## BPF Arenas

BPF arenas are the defining feature that distinguishes scx_wd40 from
scx_rusty. An arena is a region of memory that is simultaneously mapped into
both BPF program address space and userspace address space, enabling direct
pointer sharing without map lookups.

### Arena Allocation

scx_wd40 uses two arena-based allocators:

1. **`scx_stk` (stack allocator)** for `dom_ctx` objects: Initialized in
   `lb_domain_init()` via `scx_stk_init(&lb_domain_allocator,
   sizeof(struct dom_ctx), LBALLOC_PAGES_PER_ALLOC)`. Domain contexts are
   allocated with `scx_stk_alloc()` and freed with `scx_stk_free()`.

2. **`scx_buddy` (buddy allocator)** for page-level allocations: Initialized
   in `lb_domain_init()` via `scx_buddy_init(&buddy, PAGE_SIZE)`. This
   allocator is declared in a `private(LBDOMAIN_BUDDY)` BSS section to avoid
   linker errors with large BSS sections.

3. **SDT task allocator** (`scx_task_alloc` / `scx_task_free`) from
   `lib/sdt_task.h`: Manages per-task `task_ctx` arena objects. Tasks are
   allocated in `wd40_init_task` and freed in `wd40_exit_task`.

4. **`scx_bitmap_alloc()`** for arena-resident CPU masks: Each domain gets
   three arena bitmaps (`cpumask`, `direct_greedy_cpumask`, `node_cpumask`),
   and each task gets one (`cpumask`).

### Arena Setup Sequence

Arena setup happens in a specific order during initialization:

1. `ArenaLib::init()` is called in userspace (`Scheduler::setup_arenas`) to
   initialize the arena infrastructure and SDT task allocator with the size
   of `task_ctx`.
2. `arenalib.setup()` runs the arena library's BPF setup programs.
3. `Scheduler::setup_wd40()` invokes `SEC("syscall") wd40_setup()` in BPF
   via `test_run()`. This allocates all global arena bitmaps
   (`all_cpumask`, `direct_greedy_cpumask`, `kick_greedy_cpumask`), node
   masks, and domain contexts.
4. After BPF object attachment, userspace reads `topo_nodes[TOPO_LLC][dom_id]`
   pointers, casts them to `*mut dom_ctx`, and writes CPU masks directly into
   the arena memory.

### Task Context Access

The `lookup_task_ctx(p)` macro casts the result of `scx_task_data(p)` to a
`task_ptr` (i.e., `struct task_ctx __arena *`). This avoids BPF map lookups
entirely -- task context is obtained from a single pointer dereference
through the SDT task infrastructure.

### Userspace Access

Userspace accesses domain contexts by reading raw pointers from
`bss_data.topo_nodes[TOPO_LLC][dom_id]` and casting them via
`std::ptr::with_exposed_provenance_mut::<dom_ctx>()`. This gives the Rust
code direct mutable access to the same `dom_ctx` structures that BPF is
using, enabling zero-copy reads of duty-cycle counters and zero-copy writes
of `target_dom` for load balancing.

## Domain Model

### Domain Definition

A **domain** corresponds to a set of CPUs sharing an L3/LLC cache. The
number of domains (`nr_doms`) and their CPU assignments are derived from
system topology at startup. Constants limit the system to `MAX_DOMS = 64`
domains and `MAX_CPUS = 512` CPUs.

### Core Data Structures

**`struct dom_ctx`** (arena-allocated, in `types.h`):

| Field | Type | Purpose |
|---|---|---|
| `id` | `u32` | Domain ID |
| `min_vruntime` | `u64` | Floor vruntime for deadline scheduling |
| `buckets[LB_LOAD_BUCKETS]` | `struct bucket_ctx[100]` | Per-weight-bucket duty-cycle tracking |
| `active_tasks` | `struct dom_active_tasks` | Ring buffer of recently-active task pointers |
| `cpumask` | `scx_bitmap_t` | CPUs belonging to this domain |
| `direct_greedy_cpumask` | `scx_bitmap_t` | CPUs eligible for direct greedy dispatch |
| `node_cpumask` | `scx_bitmap_t` | All CPUs on this domain's NUMA node |
| `vtime_lock` | `arena_lock_t` | Arena spinlock protecting `min_vruntime` |

**`struct task_ctx`** (arena-allocated, in `types.h`):

| Field | Type | Purpose |
|---|---|---|
| `dom_mask` | `u64` | Bitmask of domains where the task can run |
| `preferred_dom_mask` | `u64` | Preferred domains (from mempolicy) |
| `domc` | `dom_ptr` | Arena pointer to the task's current domain |
| `target_dom` | `u32` | Target domain (set by userspace LB) |
| `weight` | `u32` | Task scheduling weight (nice-derived) |
| `runnable` | `bool` | Whether the task is currently runnable |
| `deadline` | `u64` | Computed vtime deadline for dispatch ordering |
| `sum_runtime`, `avg_runtime` | `u64` | Accumulated and averaged runtime |
| `blocked_freq`, `waker_freq` | `u64` | Frequency metrics for interactivity |
| `is_kworker` | `bool` | Whether the task is a workqueue worker |
| `all_cpus` | `bool` | Whether the task can run on all CPUs |
| `dispatch_local` | `bool` | Flag from `select_cpu` to `enqueue` for direct dispatch |
| `dcyc_rd` | `struct ravg_data` | Running average duty-cycle data |
| `cpumask` | `scx_bitmap_t` | Intersection of domain mask and task affinity |

**`struct pcpu_ctx`** (static array, in `lb_domain.h`):

| Field | Type | Purpose |
|---|---|---|
| `dom_rr_cur` | `u32` | Round-robin counter for work stealing across domains |
| `domc` | `dom_ptr` | Cached pointer to this CPU's domain context |

### Domain-to-CPU Mapping

`cpu_to_dom_id(cpu)` traverses the topology tree:
`topo_nodes[TOPO_CPU][cpu]->parent->parent->id`, navigating from CPU node
up through the topology hierarchy to reach the LLC-level domain ID.

Domain contexts are stored in `topo_nodes[TOPO_LLC][dom_id]` and retrieved
via `lookup_dom_ctx(dom_id)` which casts the stored `u64` pointer.

### Domain Selection for Tasks

When a task enters the system (`wd40_init_task`) or changes its cpumask
(`wd40_set_cpumask`), the function `task_pick_and_set_domain()` in
`placement.bpf.c` selects the best domain:

1. `task_pick_domain()` iterates over all domains in round-robin order
   (starting from the CPU's `dom_rr_cur` counter).
2. For each domain whose `cpumask` intersects the task's allowed CPUs, the
   domain is added to the task's `dom_mask`.
3. If `mempolicy_affinity` is enabled, `task_set_preferred_mempolicy_dom_mask()`
   inspects the task's `mempolicy` struct to determine preferred NUMA nodes,
   and maps them to a `preferred_dom_mask`.
4. The preferred domain is chosen if one exists; otherwise the first matching
   domain (round-robin spread) is used.

`task_set_domain()` performs the actual domain assignment: it updates
`target_dom`, sets `domc`, initializes `dsq_vtime` to the new domain's
`min_vruntime`, and computes the intersection cpumask.

## Scheduling Hot Path (BPF Callbacks)

The scheduler registers the following `sched_ext` operations (defined in
`SCX_OPS_DEFINE(wd40, ...)`):

### `wd40_select_cpu`

Called when a task becomes runnable to select a CPU. The logic follows a
priority cascade:

1. **Pinned tasks** (`nr_cpus_allowed == 1`): Dispatch to the only allowed
   CPU. If `kthreads_local` is set and the task is a kernel thread, it counts
   as `DIRECT_DISPATCH`; otherwise `PINNED`.

2. **Sync wakeup** (`SCX_WAKE_SYNC`): `try_sync_wakeup()` checks if the
   waker's LLC contains an idle CPU. It first tries `prev_cpu` if it shares
   the LLC and is idle (`SYNC_PREV_IDLE`). Otherwise, if the current CPU's
   local DSQ is empty and idle cores exist in the LLC, it dispatches to the
   current CPU (`WAKE_SYNC`).

3. **Retain previous CPU**: `select_cpu_retain_prev()` keeps `prev_cpu` if
   its entire physical core is idle (checking the SMT idle mask). If
   `prev_cpu` is in a foreign domain, it can still be retained if it appears
   in the `direct_greedy_cpumask` (`GREEDY_IDLE`).

4. **Pick idle domestic CPU**: `select_cpu_pick_local()` looks for an idle
   core in the task's domain cpumask, then falls back to `prev_cpu` if
   domestic and idle, then any idle domestic CPU (`DIRECT_DISPATCH`).

5. **Cross-domain greedy**: `select_cpu_idle_x_numa()` searches
   `direct_greedy_cpumask` for idle CPUs outside the task's domain. By
   default, this is restricted to the same NUMA node (unless
   `direct_greedy_numa` is set). Prefers idle cores
   (`DIRECT_GREEDY`) over idle hyperthreads (`DIRECT_GREEDY_FAR`).

6. **Fallback**: If no idle CPU is found, returns a domestic CPU (preferring
   `prev_cpu` if domestic, otherwise `scx_bitmap_any_distribute` from the
   domain mask). The task will be enqueued to the domain DSQ.

When a CPU is found via steps 1-5, `taskc->dispatch_local = true` is set,
signaling `wd40_enqueue` to dispatch directly to `SCX_DSQ_LOCAL`.

### `wd40_enqueue`

Called to place a task on a dispatch queue:

1. **Load-balance migration**: If `target_dom != domc->id`, the task has
   been flagged for migration by userspace. `task_set_domain()` moves it to
   the new domain, and it is enqueued to the new domain's DSQ.

2. **Direct local dispatch**: If `dispatch_local` was set by `select_cpu`,
   the task is inserted into `SCX_DSQ_LOCAL` with `slice_ns` duration.

3. **Domain DSQ enqueue**: The task is placed on its domain's DSQ. If in
   FIFO mode (`fifo_sched`), `scx_bpf_dsq_insert()` is used with flat
   priority. Otherwise, `place_task_dl()` computes a deadline and uses
   `scx_bpf_dsq_insert_vtime()`.

4. **Repatriation**: If the task is on a foreign CPU (e.g., from greedy
   execution) and didn't go through `select_cpu`, a domestic CPU is kicked
   to prevent stalls (`REPATRIATE`).

5. **Kick greedy**: If idle CPUs exist in the `kick_greedy_cpumask`, one is
   kicked with `SCX_KICK_IDLE` to accelerate work stealing
   (`KICK_GREEDY`).

### `wd40_dispatch`

Called when a CPU needs work:

1. First tries to consume from its own domain's DSQ via
   `scx_bpf_dsq_move_to_local(curr_dom)` (`DSQ_DISPATCH`).

2. If `greedy_threshold` is nonzero, attempts **local NUMA stealing**:
   `dispatch_steal_local_numa()` iterates domains on the same NUMA node in
   round-robin order (`dom_rr_cur`), skipping the current domain, and tries
   to steal a task from each (`GREEDY_LOCAL`).

3. If `greedy_threshold_x_numa` is nonzero and the system has multiple NUMA
   nodes, attempts **cross-NUMA stealing**: `dispatch_steal_x_numa()`
   iterates domains on other NUMA nodes, but only steals if the foreign
   domain has at least `greedy_threshold_x_numa` queued tasks
   (`GREEDY_XNUMA`).

### `wd40_runnable` / `wd40_running` / `wd40_stopping` / `wd40_quiescent`

These lifecycle callbacks maintain per-task and per-domain accounting:

- **`wd40_runnable`**: Called when a task becomes runnable. Adjusts the
  task's duty-cycle running average (`task_load_adj` with `runnable=true`),
  increments the domain's duty-cycle (`dom_dcycle_adj`), updates the waker's
  `waker_freq`, and resets `sum_runtime`.

- **`wd40_running`**: Called when a task starts executing on a CPU. Records
  the task in the domain's `active_tasks` ring buffer (for userspace LB to
  inspect) via `lb_record_run()`. Updates `min_vruntime` under the domain's
  arena spinlock if the task's `dsq_vtime` exceeds it
  (`running_update_vtime`).

- **`wd40_stopping`**: Called when a task stops running. Computes the
  execution delta, updates `sum_runtime` and `avg_runtime` (EWMA), advances
  `dsq_vtime` by `scale_inverse_fair(delta, weight)`, and recomputes the
  task's deadline (`stopping_update_vtime`).

- **`wd40_quiescent`**: Called when a task goes to sleep. Adjusts
  duty-cycle with `runnable=false`, updates `blocked_freq` for
  interactivity tracking.

## Load Balancing

Load balancing is performed entirely in Rust userspace and communicates
decisions to BPF by directly writing `target_dom` in each task's
arena-allocated `task_ctx`.

### Duty-Cycle Tracking (BPF Side)

Each domain maintains 100 **weight buckets** (`LB_LOAD_BUCKETS = 100`).
Task weights range from `LB_MIN_WEIGHT = 1` to `LB_MAX_WEIGHT = 10000`,
with each bucket covering a range of `LB_WEIGHT_PER_BUCKET = 100` weight
units.

When a task becomes runnable or goes to sleep, `dom_dcycle_adj()` in
`lb_domain.bpf.c`:
1. Maps the task's weight to a bucket index via
   `weight_to_bucket_idx(weight)`.
2. Acquires a per-bucket BPF spinlock (from the `dom_dcycle_locks` map,
   keyed by `dom_id * LB_LOAD_BUCKETS + bucket_idx`).
3. Increments or decrements `bucket->dcycle`.
4. Calls `ravg_accumulate()` to update the bucket's running-average data.

When a task migrates between domains, `dom_dcycle_xfer_task()` atomically
transfers the task's duty-cycle contribution from the source bucket to the
destination bucket using `ravg_transfer()`.

### Active Tasks Ring Buffer

Each domain has a `dom_active_tasks` ring buffer with capacity
`MAX_DOM_ACTIVE_TPTRS = 1024`. When a task starts running, `lb_record_run()`
writes the task's arena pointer to the ring buffer at
`write_idx % MAX_DOM_ACTIVE_TPTRS` (atomic fetch-and-add). A generation
counter (`gen`) prevents the same task from being recorded multiple times
within one load-balancing epoch.

Userspace reads this ring buffer in `populate_tasks_by_load()`, advances
`read_idx` to `write_idx`, and increments `gen` to start a new epoch.

### Load Hierarchy

The `LoadBalancer` in `load_balance.rs` constructs a hierarchical load model:

```
Cluster
  +-- NumaNode (one per NUMA node)
       +-- Domain (one per LLC within the NUMA node)
            +-- TaskInfo (recently active tasks)
```

Each level has a `LoadEntity` with:
- **`load_sum`**: Actual load (sum of `weight * duty_cycle` for all tasks).
- **`load_avg`**: Expected fair share of load.
- **`load_delta`**: Cumulative load transferred in this balancing round.
- **`bal_state`**: One of `Balanced`, `NeedsPush`, or `NeedsPull`.
- **`cost_ratio`**: Threshold for considering an imbalance significant.
- **`push_max_ratio`**: Maximum fraction of imbalance to push in one round.
- **`xfer_ratio`**: Target fraction of imbalance to transfer per migration.

The balance state is computed as:
```
imbal = load_sum - load_avg
if |imbal| > load_avg * cost_ratio:
    NeedsPush if imbal > 0
    NeedsPull if imbal < 0
else:
    Balanced
```

### Imbalance Thresholds

| Level | `cost_ratio` | `push_max_ratio` | `xfer_ratio` |
|---|---|---|---|
| Domain | 0.05 (5%) | 0.50 | 0.50 |
| NumaNode | 0.17 (17%) | 0.50 | 0.50 |

NUMA nodes require a higher imbalance threshold (17% vs 5%) because
cross-node migrations are more expensive due to remote memory access.

### Load Calculation

`calculate_load_avgs()` reads each domain's 100 weight buckets using
`ravg_read()` to extract the duty-cycle running average, then feeds the
data into a `LoadAggregator` from `scx_utils`. The aggregator computes:
- Per-domain load sums (accounting for infeasible weights when
  `lb_apply_weight` is true).
- Global load sum and per-domain averages.

The `lb_apply_weight` flag corresponds to whether the system is fully
utilized (determined by the Tuner). When not fully utilized, all tasks are
treated with `DEFAULT_WEIGHT = 100`.

### Balancing Algorithm

`perform_balancing()` runs two phases:

**Phase 1: Inter-NUMA balancing** (`balance_between_nodes`):
- Sort NUMA nodes by load.
- Iterate from most-loaded (push) to least-loaded (pull).
- For each push/pull pair, attempt to transfer a single task between their
  domains via `transfer_between_nodes()`.
- After each successful migration, re-sort and restart to maintain
  ordering invariants.
- Preferred domain masks are tried first; if no preferred candidate is
  found, any eligible task is considered.

**Phase 2: Intra-NUMA balancing** (`balance_within_node`):
- For each NUMA node, sort domains by load.
- Iterate from most-loaded to least-loaded domains.
- `try_find_move_task()` selects the best migration candidate: it searches
  for the task closest in load to the ideal transfer amount (`xfer`),
  scanning both directions from the target value. A migration only occurs
  if it reduces the combined imbalance.
- The selected task's `target_dom` is written directly into arena memory,
  which BPF reads on the next `wd40_enqueue`.

## Deadline Scheduling

When `fifo_sched` is false (the default), scx_wd40 uses a deadline-based
virtual-time scheduler inspired by `scx_lavd`. The implementation is in
`deadline.bpf.c`.

### Virtual Time

Each task tracks `dsq_vtime` (in `p->scx.dsq_vtime`), which advances
proportionally to wall-clock runtime, inversely scaled by the task's weight:

```
dsq_vtime += delta * 100 / weight
```

This is computed by `scale_inverse_fair(delta, weight)` in
`stopping_update_vtime()`. Higher-weight tasks accumulate vruntime more
slowly, giving them proportionally more CPU time.

Each domain tracks `min_vruntime`, which is the minimum `dsq_vtime` among
currently running tasks. This is updated under the domain's
`vtime_lock` (arena spinlock) in `running_update_vtime()`.

### Deadline Computation

The task's **deadline** is:

```
deadline = dsq_vtime + request_length
```

where `request_length = avg_runtime * 100 / lat_scale`.

The `lat_scale` is a latency-priority weight derived from:

1. **Frequency factor**: `freq_factor = blocked_freq * waker_freq^2`,
   scaled up by `scale_up_fair(freq_factor, weight)`. This prioritizes
   tasks that both produce wakeups and consume them (middle of a work
   chain), per Amdahl's law reasoning.

2. **Latency priority** (`lat_prio`): `log2(freq_factor + 1)`, clamped to
   `DL_MAX_LAT_PRIO = 39`.

3. **Runtime penalty**: `avg_run = log2(avg_runtime / DL_RUNTIME_SCALE + 1)`,
   where `DL_RUNTIME_SCALE = 2` and the raw value is clamped to
   `DL_MAX_LATENCY_NS = 50ms`. This is inversely scaled by weight (lower
   weight -> harsher penalty).

4. Final `lat_prio = max(0, lat_prio - avg_run)`.

5. **`lat_scale`** is looked up from `sched_prio_to_weight[]`, the same
   nice-to-weight table used by CFS in the Linux kernel (40 entries,
   ranging from 15 to 88761). The table is indexed inversely:
   `sched_prio_to_weight[DL_MAX_LAT_PRIO - lat_prio - 1]`.

The effect: tasks with high waker/blocked frequencies and low average
runtimes get shorter request lengths, and therefore earlier deadlines,
causing them to be dispatched sooner. CPU-bound tasks with long runtimes
get later deadlines.

### Vtime Clamping

`clamp_task_vtime()` prevents a task that has been sleeping for a long time
from accumulating an unbounded vruntime budget. A task's `dsq_vtime` is
clamped to `min_vruntime - slice_ns`, limiting the accumulated budget to
at most one scheduling slice. This is counted as `DL_CLAMP`; tasks whose
vtime is already within range count as `DL_PRESET`.

### EWMA for Runtime and Frequencies

Runtime averaging uses a simple exponential weighted moving average:
```
new_avg = old_avg * 0.75 + new_val * 0.25
```
implemented as `calc_avg(old, new) = (old - (old >> 2)) + (new >> 2)`.

Frequency tracking (`update_freq`) computes instantaneous frequency as
`(100 * NSEC_PER_MSEC) / interval` and applies the same EWMA.

## Topology Awareness

### NUMA Awareness

The scheduler is deeply NUMA-aware at multiple levels:

- **Domain-to-NUMA mapping**: `dom_numa_id_map[MAX_DOMS]` maps each domain
  to its NUMA node ID, set during initialization from `DomainGroup`'s
  `dom_numa_map`. `dom_node_id(dom_id)` reads this mapping.

- **Per-domain node masks**: Each `dom_ctx` has a `node_cpumask` bitmap set
  to all CPUs on the domain's NUMA node. This is used to restrict
  cross-domain greedy dispatch to the same NUMA node when
  `direct_greedy_numa` is false.

- **Cross-NUMA work stealing**: `dispatch_steal_x_numa()` only steals from
  foreign NUMA nodes if the source domain has at least
  `greedy_threshold_x_numa` queued tasks, providing a configurable
  threshold to avoid unnecessary remote memory access.

- **Load balancing cost**: Inter-NUMA load balancing uses a 17% imbalance
  threshold vs. 5% for intra-NUMA, reflecting the higher cost of
  cross-node migration.

### LLC/Cache Awareness

Domains are built from LLC (Last Level Cache, typically L3) topology. The
`DomainGroup::new()` constructor in `domain.rs` iterates over the system
topology's NUMA nodes and their LLCs, creating one domain per LLC with a
contiguous domain ID space.

The `cache_level` option (default 3) determines which cache level defines
domain boundaries, though the current implementation uses the
`Topology::new()` defaults from `scx_utils`.

### Mempolicy Affinity

When `mempolicy_affinity` is enabled, `task_set_preferred_mempolicy_dom_mask()`
in `placement.bpf.c` reads the task's `struct mempolicy` via BPF CO-RE:

- For `MPOL_BIND`, `MPOL_PREFERRED`, and `MPOL_PREFERRED_MANY` policies, it
  extracts the `home_node` or the policy's node bitmask.
- It converts NUMA node IDs to a domain mask using `node_dom_mask()`.
- The resulting `preferred_dom_mask` is used during load balancing to
  prefer migrations that respect memory locality.

## Userspace Side

### Scheduler Struct (`main.rs`)

The `Scheduler` struct holds:
- The BPF skeleton (`BpfSkel`) and attached struct_ops link.
- Scheduling intervals (`sched_interval` for LB, `tune_interval` for tuning).
- An `Arc<DomainGroup>` shared between the tuner, load balancer, and stats.
- A `Tuner` and a `StatsServer`.

### Initialization Sequence

1. Parse CLI options (`Opts` via `clap`).
2. Open BPF skeleton, configure `rodata` (const volatiles) and `bss` (mutable state).
3. Load BPF programs (`scx_ops_load!`).
4. Initialize arenas (`setup_arenas` -> `ArenaLib::init` -> `arenalib.setup` -> `setup_wd40`).
5. Read `mask_size` from BPF BSS to determine CPU mask word count.
6. Write domain and NUMA CPU masks into arena-allocated `dom_ctx` structures.
7. Attach struct_ops (`scx_ops_attach!`).
8. Store `dom_ctx` raw pointers into `Domain::ctx` for userspace access.
9. Launch the stats server.

### Main Loop

The `run()` method drives two periodic control loops:

```
while !shutdown && !exited:
    if now >= next_tune_at:
        tuner.step()        // ~100ms
    if now >= next_sched_at:
        lb_step()           // ~2s
    handle stats requests
```

### Tuner (`tuner.rs`)

The `Tuner` maintains:
- `direct_greedy_mask`: CPUs where tasks can be directly dispatched across
  domain boundaries.
- `kick_greedy_mask`: CPUs that can be kicked to accelerate work stealing.
- `fully_utilized`: Boolean indicating whether the system is saturated.
- `slice_ns`: Current scheduling time slice.

`Tuner::step()`:
1. Reads per-CPU stats from `/proc/stat`.
2. Computes per-domain utilization by summing CPU utilization within each
   domain.
3. For each domain with utilization below `direct_greedy_under` (default
   90%): adds the domain's CPUs to `direct_greedy_mask` and updates the
   per-domain `direct_greedy_cpumask` in arena memory.
4. For each domain with utilization below `kick_greedy_under` (default
   100%): adds the domain's CPUs to `kick_greedy_mask`.
5. Updates the global BPF masks via `update_bpf_mask()`.
6. Sets `slice_ns` to `overutil_slice_ns` (1ms) if fully utilized, or
   `underutil_slice_ns` (20ms) if not. This reduces latency under high
   load at the cost of more context switches.

### Load Balancer (`load_balance.rs`)

`LoadBalancer::load_balance()`:
1. Calls `create_domain_hierarchy()` which invokes `calculate_load_avgs()`
   to read duty-cycle data from BPF arena memory and build the
   NumaNode/Domain hierarchy.
2. If `balance_load` is true, calls `perform_balancing()` which runs
   inter-NUMA then intra-NUMA balancing.
3. After balancing, `get_stats()` extracts per-node and per-domain load
   statistics.

Task migration is accomplished by writing `taskc.target_dom = new_dom_id`
directly into the arena-allocated `task_ctx`. On the next `wd40_enqueue`,
BPF detects `domc->id != taskc->target_dom` and calls `task_set_domain()`
to complete the migration.

### Statistics (`stats.rs`)

The stats system exports three levels of metrics:

- **`ClusterStats`** (top-level): CPU busy %, total load, migration count,
  scheduling event breakdown as percentages, slice duration, greedy masks.
- **`NodeStats`**: Per-NUMA-node load, imbalance, and delta.
- **`DomainStats`**: Per-domain load, imbalance, and delta.

Statistics are served via `StatsServer` (from `scx_stats`) and can be
monitored with `scx_wd40 --monitor <interval>`.

The scheduling event percentages track which path each task took through
`select_cpu` / `enqueue` / `dispatch`:

| Stat | Description |
|---|---|
| `wake_sync` | WAKE_SYNC dispatched to waker's CPU |
| `sync_prev_idle` | WAKE_SYNC dispatched to idle prev_cpu in waker's LLC |
| `prev_idle` | Dispatched to idle prev_cpu (domestic) |
| `greedy_idle` | Dispatched to idle prev_cpu (foreign domain, in greedy mask) |
| `pinned` | Task pinned to one CPU |
| `direct` | Direct dispatch to idle domestic CPU or kthread |
| `greedy` | Direct greedy dispatch to foreign domain, same NUMA node |
| `greedy_far` | Direct greedy dispatch to foreign NUMA node |
| `dsq_dispatch` | Consumed from own domain's DSQ |
| `greedy_local` | Stolen from another domain on same NUMA node |
| `greedy_xnuma` | Stolen from a domain on a different NUMA node |
| `kick_greedy` | Foreign CPU kicked on enqueue |
| `repatriate` | Task on foreign CPU kicked domestic CPU |
| `dl_clamp` | Deadline vtime was clamped |
| `dl_preset` | Deadline vtime used as-is |

## Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `-u` / `--slice-us-underutil` | 20000 | Time slice (us) when system is under-utilized |
| `-o` / `--slice-us-overutil` | 1000 | Time slice (us) when system is over-utilized |
| `-i` / `--interval` | 2.0 | Load balance interval (seconds) |
| `-I` / `--tune-interval` | 0.1 | Tuner interval (seconds) |
| `-l` / `--load-half-life` | 1.0 | Half-life for load running averages (seconds) |
| `-c` / `--cache-level` | 3 | Cache level for domain boundaries |
| `-g` / `--greedy-threshold` | 1 | Min queued tasks for intra-NUMA stealing |
| `--greedy-threshold-x-numa` | 0 | Min queued tasks for cross-NUMA stealing (0=disabled) |
| `--no-load-balance` | false | Disable userspace load balancing |
| `-k` / `--kthreads-local` | false | Dispatch per-CPU kthreads to local DSQ |
| `-b` / `--balanced-kworkers` | false | Exclude kworkers from load balancing |
| `-f` / `--fifo-sched` | false | Use FIFO instead of weighted vtime |
| `-D` / `--direct-greedy-under` | 90.0 | Utilization threshold for direct greedy dispatch (%) |
| `-K` / `--kick-greedy-under` | 100.0 | Utilization threshold for kick greedy (%) |
| `-r` / `--direct-greedy-numa` | false | Allow direct greedy dispatch across NUMA nodes |
| `-p` / `--partial` | false | Only schedule SCHED_EXT tasks |
| `--mempolicy-affinity` | false | Respect set_mempolicy for domain placement |
| `--perf` | 0 | CPU performance governor hint [0, 1024] |
| `-v` / `--verbose` | 0 | Verbosity level (repeatable) |

## Key Design Decisions

1. **Arena pointers for zero-copy sharing**: By storing `dom_ctx` and
   `task_ctx` in arena memory, both BPF and userspace can read/write the
   same structures without serialization overhead. Userspace load balancing
   decisions (setting `target_dom`) take effect on the next BPF enqueue
   without any map updates.

2. **Modular BPF compilation**: Splitting BPF code into multiple `.bpf.c`
   files with shared headers demonstrates a composable scheduler
   architecture. Different scheduling policies (deadline, FIFO, placement
   strategies) can be developed and tested independently.

3. **Adaptive time slicing**: The tuner dynamically switches between a long
   slice (20ms, reducing overhead) when the system is under-utilized and a
   short slice (1ms, reducing latency) when fully utilized.

4. **Two-tier greedy work conservation**: Direct greedy dispatch
   (placing a task on a foreign idle CPU) provides the lowest latency but
   can hurt performance under high load. Kick greedy (waking a foreign
   idle CPU to steal work) is more expensive but has no negative
   performance impact. Both are controlled by independent utilization
   thresholds.

5. **Interactivity-aware deadlines**: The deadline computation borrows from
   `scx_lavd`'s latency-criticality analysis, prioritizing tasks in the
   middle of work chains (high waker and blocked frequency) while
   penalizing CPU-bound tasks with long runtimes. This improves interactive
   responsiveness without explicit priority classes.
