# scx_layered
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_layered** is a sched_ext scheduler that organizes tasks into configurable **layers**, each with independent scheduling policies, CPU allocations, and matching rules. It is a hybrid BPF/userspace scheduler developed by Meta Platforms, designed for workload isolation and differentiated service classes on a single machine.

The core idea is that a system administrator defines a JSON configuration describing a set of named layers. Each layer specifies:
1. **Match rules** that determine which tasks belong to the layer (e.g. by cgroup path, process name, nice value, PID, GPU usage, etc.).
2. **A layer kind** -- `Confined`, `Grouped`, or `Open` -- that controls CPU ownership semantics.
3. **Scheduling parameters** -- time slice, preemption behavior, weight, growth algorithm, FIFO vs. vtime ordering, and more.

Tasks are matched to layers at `ops.runnable()` time (and periodically re-checked). The BPF side handles the hot path: `select_cpu`, `enqueue`, `dispatch`, `running`, `stopping`, and `tick`. The userspace Rust daemon periodically recalculates CPU-to-layer assignments, updates cpumasks, collects statistics, and pushes updates to the BPF maps.

Key properties:
- Up to **`MAX_LAYERS` = 16** layers.
- Up to **`MAX_CPUS` = 512** CPUs (9-bit shift).
- Up to **`MAX_LLCS` = 64** last-level caches and **`MAX_NUMA_NODES` = 64** NUMA nodes.
- Per-LLC dispatch queues (DSQs) for each layer, plus high/low fallback DSQs per LLC.
- Topology-aware CPU allocation with multiple growth algorithms.
- Work conservation through cross-layer execution on unoccupied CPUs.

## Architecture / Design

The scheduler is split into two cooperating halves:

### BPF Side (`main.bpf.c`, `timer.bpf.c`, `util.bpf.c`)
Runs in kernel context. Implements the `sched_ext` struct_ops callbacks. Handles the fast path: CPU selection, enqueue, dispatch, preemption, task-to-layer matching, and per-tick accounting. All data structures are in BPF maps (arrays, per-cpu arrays, hash maps).

### Userspace Side (`main.rs`, `lib.rs`, `config.rs`, `layer_core_growth.rs`, `stats.rs`)
A Rust daemon that:
- Parses the JSON layer configuration and initializes BPF skeleton.
- Periodically (default 1 second, configurable via `--interval`) recalculates CPU allocations based on utilization metrics and updates the BPF-side cpumasks.
- Tracks statistics (utilization, memory bandwidth, BPF stats) using exponentially-weighted moving averages (EWMAs).
- Handles GPU task affinitization via NVML.
- Watches for cgroup creation/deletion events (inotify) to maintain cgroup regex match bitmaps.
- Runs a stats server for monitoring (`--monitor` mode).

### DSQ Organization

Each layer gets a per-LLC DSQ. The DSQ ID encodes both layer and LLC:

```c
dsq_id = (layer_id << DSQ_ID_LAYER_SHIFT) | llc_id
```

where `DSQ_ID_LAYER_SHIFT = 16`, so the low 16 bits encode the LLC and bits 16..29 encode the layer. Two special DSQ bases are reserved:

| DSQ Base | Mask | Purpose |
|---|---|---|
| `HI_FB_DSQ_BASE` | `0x40000000` | High-priority fallback (per-cpu kthreads, scheduler tasks) |
| `LO_FB_DSQ_BASE` | `0x80000000` | Low-priority fallback (affinity-constrained tasks, empty-layer tasks) |

Both are per-LLC: `hi_fb_dsq_id(llc) = HI_FB_DSQ_BASE | llc_id`.

### Key BPF Maps

| Map | Type | Purpose |
|---|---|---|
| `cpu_ctxs` | `PERCPU_ARRAY` | Per-CPU context: layer assignment, proximity map, usage accounting, layer consumption orders |
| `llc_data` | `ARRAY` | Per-LLC context: `vtime_now[]`, `queued_runtime[]`, proximity map, fallback sequence |
| `node_data` | `ARRAY` | Per-NUMA-node context with cpumask |
| `layer_cpumasks` | `ARRAY` | Per-layer BPF cpumask (kptr) |
| `gpu_tgid` / `gpu_tid` | `HASH` | GPU usage timestamps per TGID/TID |
| `cgroup_match_bitmap` | `HASH` | Cgroup ID to regex match bitmap |
| `scx_layered_task_hint_map` | `TASK_STORAGE` | Per-task hint values for external control |
| `antistall_cpu_dsq` | `PERCPU_ARRAY` | Anti-stall: most delayed DSQ for each CPU |

## Layer System

### Layer Kinds

There are three fundamental layer kinds, each with different CPU ownership semantics:

**`Open`** -- Tasks can execute on **any** CPU. Open layers do not own CPUs; they run on whatever CPUs are not allocated to confined/grouped layers (the "available" pool). Multiple open layers share the same set of CPUs. Open layers are primarily distinguished by their scheduling parameters (preempt, weight, slice) rather than CPU allocation.

**`Grouped`** -- Layers are dynamically assigned a set of CPUs by the userspace daemon, proportional to utilization. A grouped layer's tasks preferentially run on their assigned CPUs, but can also execute on unassigned CPUs (open execution) for work conservation. Has `util_range` and optional `cpus_range` to control scaling. Can optionally be `protected`, meaning the owned CPUs will not run other layers' tasks.

**`Confined`** -- Like grouped, but **strictly confined** to assigned CPUs. A confined layer's tasks can only be dispatched to CPUs that belong to the layer. The BPF dispatch path enforces this: `try_consume_layer()` checks `layer->kind == LAYER_KIND_CONFINED && cpuc->layer_id != layer_id` and skips. Has `util_range` and `cpus_range`.

### Task-to-Layer Matching

Tasks are matched to layers via the `match_layer()` function in BPF. Each layer has up to `MAX_LAYER_MATCH_ORS = 32` match groups (OR'd). Each group has up to `NR_LAYER_MATCH_KINDS` match conditions (AND'd). A task matches a layer if **any** OR-group has **all** its AND conditions satisfied.

The matching is evaluated in layer order (0..nr_layers). The **first** layer that matches wins. This means the layer ordering in the configuration acts as a priority for task assignment.

Available match predicates (`enum layer_match_kind`):

| Predicate | Description |
|---|---|
| `MATCH_CGROUP_PREFIX` | Cgroup path starts with a prefix |
| `MATCH_CGROUP_SUFFIX` | Cgroup path ends with a suffix |
| `MATCH_CGROUP_CONTAINS` | Cgroup path contains a substring |
| `MATCH_CGROUP_REGEX` | Cgroup path matches a regex (evaluated in userspace, bitmap pushed to BPF) |
| `MATCH_COMM_PREFIX` | Task `comm` starts with a prefix (also has `Exclude` variant) |
| `MATCH_PCOMM_PREFIX` | Parent comm prefix |
| `MATCH_NICE_ABOVE` / `NICE_BELOW` / `NICE_EQUALS` | Nice value comparison |
| `MATCH_USER_ID_EQUALS` / `GROUP_ID_EQUALS` | UID/GID |
| `MATCH_PID_EQUALS` / `PPID_EQUALS` / `TGID_EQUALS` | PID matching |
| `MATCH_NSPID_EQUALS` / `NS_EQUALS` | Namespace PID/ID matching |
| `MATCH_SCXCMD_JOIN` | Dynamic join via scx command protocol |
| `MATCH_IS_GROUP_LEADER` / `IS_KTHREAD` | Process properties |
| `MATCH_USED_GPU_TID` / `USED_GPU_PID` | GPU usage tracking via kprobes |
| `MATCH_AVG_RUNTIME` | Average runtime within a range (microseconds) |
| `MATCH_HINT_EQUALS` | External hint via `scx_layered_task_hint_map` |
| `MATCH_SYSTEM_CPU_UTIL_BELOW` | System-wide CPU utilization threshold |
| `MATCH_DSQ_INSERT_BELOW` | Layer-specific DSQ insertion ratio threshold |
| `MATCH_NUMA_NODE` | Task affinity is subset of a NUMA node |

Each match can be `exclude`d (inverted). The `exclude` flag transforms an allowlist rule into a denylist rule.

Layer matching occurs:
1. At `ops.runnable()` via `maybe_refresh_layer()` when `taskc->refresh_layer` is set.
2. When the userspace increments `layer_refresh_seq_avgruntime`, triggering rematch for tasks whose sequence is stale.
3. When a GPU-tracked task's membership expires (`member_expire_ms`).

### Layer Membership Expiration

For GPU-aware layers, membership can expire after `member_expire_ms` milliseconds. The `recheck_layer_membership` field in `task_ctx` tracks expiration. States:
- `MEMBER_NOEXPIRE` (`(u64)-1`): no expiration.
- `MEMBER_EXPIRED` (`(u64)-2`): membership has expired, trigger rematch.
- `MEMBER_CANTMATCH` (`(u64)-3`): task touched GPU but didn't match the GPU layer's other criteria; skip rematching.

## Scheduling Hot Path (BPF Callbacks)

### `layered_select_cpu()`

Called when a task wakes up. Tries to find an idle CPU in the task's layer:

1. Refreshes the task's layer assignment from hints if stale (`maybe_refresh_task_layer_from_hint`).
2. Calls `pick_idle_cpu()` which uses the CPU proximity map to find the closest idle CPU, preferring:
   - The task's previous CPU (cache warm)
   - Same-core SMT siblings
   - Same-LLC CPUs
   - Same-NUMA-node CPUs
   - System-wide CPUs
3. If `preempt_first` is set and a previous CPU is available, sets `cpuc->try_preempt_first` to attempt preemption of the previous CPU in `enqueue()`.
4. Returns the selected CPU. If the selected CPU is idle and in-layer, it becomes the `SCX_DSQ_LOCAL` target for direct dispatch.

### `layered_enqueue()`

Inserts a task into a DSQ after `select_cpu()`:

1. **Try preempt-first**: If the layer has `preempt_first` and this is a wakeup, try to preempt the task's previous CPU via `try_preempt_cpu()`.
2. **Direct dispatch to idle CPU**: If `select_cpu()` was skipped or preempt-first was attempted, pick an idle CPU and dispatch directly to `SCX_DSQ_LOCAL_ON | cpu`.
3. **Preemption scan**: If the layer has `preempt` set, scan nearby CPUs (via CPU proximity map) to find a preemptable victim. Uses `try_preempt_cpu()` which checks:
   - Victim must not be running a preempting layer (unless `PREEMPT_IGNORE_EXCL`).
   - Victim must not be protected.
   - Uses `__sync_val_compare_and_swap(&cand_cpuc->preempting_task, NULL, p)` to atomically claim preemption.
4. **Per-cpu kthread / scheduler task fast path**: Dispatched to `hi_fb_dsq_id` (or `SCX_DSQ_LOCAL` if single-CPU affinity) with optional preemption.
5. **Fallback for constrained tasks**: Tasks with non-full cpuset affinity or in empty layers go to `lo_fb_dsq_id`.
6. **Normal DSQ insertion**: Enqueued to `layer_dsq_id(layer_id, llc_id)` with either FIFO (`scx_bpf_dsq_insert`) or vtime ordering (`scx_bpf_dsq_insert_vtime`). The vtime is clamped to `[vtime_now - slice_ns, vtime_now + 8192 * slice_ns]`.
7. **LLC drain**: If the layer has zero CPUs in this LLC after enqueue, enables LLC draining and kicks an idle CPU to pull the task.
8. **Queued runtime tracking**: `llcc->queued_runtime[layer_id]` is atomically updated for cross-LLC migration decisions.

### `layered_dispatch()`

Called when a CPU needs work. The consumption order is carefully structured for fairness and priority:

1. **Anti-stall check**: `antistall_consume()` first checks if any DSQ has tasks delayed beyond `antistall_sec` seconds and forcibly consumes from it.
2. **Sibling keep-idle**: If SMT sibling is running an exclusive task, keep this CPU idle.
3. **Keep running**: If the previous task is still runnable and hasn't exceeded `max_exec_ns`, let it continue by not dispatching anything (triggering auto-local-enqueue).
4. **High fallback DSQ**: Always consume `hi_fb_dsq_id` first (kthreads, scheduler tasks).
5. **Empty layer priority on fallback CPU**: The designated `fallback_cpu` tries to consume from empty layers first.
6. **Low fallback DSQ**: Budget-controlled consumption from `lo_fb_dsq_id`. Only consumed after `lo_fb_wait_ns` has elapsed and only up to `lo_fb_share_ppk / 1024` fraction of CPU time.
7. **Layer consumption** (the main dispatch logic):

   For CPUs **in open layers**:
   - If protected: `op` (open preempt) -> `on` (open non-preempt) -> `gp` (grouped preempt) -> `gn` (grouped non-preempt)
   - If not protected: `op` -> `gp` -> `ogn` (open+grouped non-preempt, merged)

   For CPUs **in grouped/confined layers**:
   - Try `ogp` (open+grouped preempt) first, unless the owner layer is protected or preempting.
   - Try the **owner layer** (including LLC draining from orphaned DSQs).
   - If the owner layer is protected, stop here.
   - Otherwise, try remaining `ogp` then `ogn` layers.

8. **Final low fallback**: If nothing was consumed and lo_fb wasn't tried, try `lo_fb_dsq_id`.
9. **Replenish previous task**: If the previous task is still runnable, extend its slice.

The layer consumption orders (`ogp_layer_order`, `ogn_layer_order`, `op_layer_order`, etc.) are **randomized per-CPU** at initialization to prevent thundering herd effects.

### `try_consume_layer()`

Walks the LLC proximity map (`llc_prox_map`) to consume from a specific layer, starting with the local LLC and expanding outward. Cross-LLC migration is gated by `xllc_mig_min_ns`: remote LLCs are skipped unless their `queued_runtime[layer_id]` exceeds the threshold. NUMA-remote LLCs can be skipped entirely via `skip_remote_node`.

### `try_drain_layer_llcs()`

For layers that have tasks stuck in LLC DSQs with zero assigned CPUs in that LLC, this function drains those orphaned DSQs. Uses a bitmap `layer->llcs_to_drain` (u64, one bit per LLC). Draining alternates with normal dispatch (every other call, via `llc_drain_cnt`). The enable/disable of draining is interlocked with enqueue to avoid races.

### `layered_running()` / `layered_stopping()`

**`running()`**: Records the start of execution, sets `protect_owned` and `protect_owned_preempt` flags based on whether the task is running on an owned CPU within `disallow_open_after_ns` / `disallow_preempt_after_ns` of when it was last queued. Handles `min_exec_ns` by extending the slice if needed. Updates `cpuc->running_owned`, `cpuc->running_open`, and per-CPU performance level (`perf`).

**`stopping()`**: Charges the vtime based on `(used * layer->weight / p->scx.weight)` for vtime-ordered layers. Uncharges queued runtime via `task_uncharge_qrt()`. Updates runtime average with exponential decay (`RUNTIME_DECAY_FACTOR = 4`).

### `layered_tick()`

Called every scheduler tick. Invokes `account_used()` which:
- Reads PMU memory bandwidth counters.
- Charges CPU usage to the appropriate layer/usage-type bucket (owned, open, protected, protected_preempt).
- Checks layer membership expiration.

### `layered_yield()`

Sets `cpuc->yielding = true` and steps down the task's vtime by `yield_step_ns` (configurable fraction of the slice). Small yield steps effectively ignore yields.

## Core Allocation and Growth

### CPU Pool (`CpuPool` in `lib.rs`)

The `CpuPool` tracks which CPUs are available (not assigned to any confined/grouped layer). Key operations:

- **`alloc_cpus(allowed_cpus, core_alloc_order, max_to_alloc)`**: Allocates CPUs following the growth order. Allocates whole cores unless `allow_partial` is set. Returns a `Cpumask` of newly allocated CPUs.
- **`free(cpus_to_free)`**: Returns CPUs to the available pool.
- **`next_to_free(cands, core_order)`**: Finds the next core to free, following the reverse growth order.
- **`fallback_cpu`**: Always maintained as the first available CPU, used for scheduling tasks from empty layers.

### Growth Algorithms (`LayerGrowthAlgo` in `layer_core_growth.rs`)

The growth algorithm determines the **core ordering** used when a layer needs to grow or shrink its CPU allocation. Available algorithms:

| Algorithm | Description |
|---|---|
| `Sticky` | Maintains the same cores across reconfigurations. Default. |
| `Linear` | Cores ordered by ascending core ID. |
| `Reverse` | Cores ordered by descending core ID. |
| `Random` | Random permutation of all cores. |
| `Topo` | Topological order: first spread across LLCs, then fill within LLC. |
| `RoundRobin` | Round-robin across LLCs, then across NUMA nodes. |
| `BigLittle` / `LittleBig` | Big cores first / little cores first (for hybrid architectures). |
| `RandomTopo` | Random shuffle within each topological group. |
| `NodeSpread` / `NodeSpreadReverse` / `NodeSpreadRandom` | Spread across NUMA nodes first. |
| `CpusetSpread` / `CpusetSpreadReverse` / `CpusetSpreadRandom` | Spread within configured cpuset. |
| `StickyDynamic` | LLC-granularity sticky allocation: assigns whole LLCs to layers and manages spillover. |

### Utilization-Based Sizing (in `Scheduler::refresh_cpumasks()`)

The userspace daemon recalculates CPU assignments periodically:

1. **`calc_target_nr_cpus()`**: For each confined/grouped layer, compute the ideal CPU count by inverting `util_range`:
   - `low = ceil(util / util_range.1)`
   - `high = floor(util / util_range.0)`
   - Target is `current.clamp(low, high)`, then clamped by `cpus_range`.
   - Memory bandwidth limits (`membw_gb`) further constrain the target.

2. **`weighted_target_nr_cpus()`**: Resolves contention when the sum of targets exceeds available CPUs. Uses weighted fair share allocation:
   - First accepts layers already at or below their minimum.
   - Then accepts layers below their weighted share.
   - Remaining contending layers get proportional shares by weight.

3. **Shrink phase**: Layers above target free CPUs (descending order, with dampening -- only frees half the excess per iteration). At least one layer must free if any layer needs to grow.

4. **Grow phase**: Layers below target allocate CPUs (ascending order, so smaller layers get priority).

5. **Open layer update**: Open layers get all remaining available CPUs.

6. **BPF update**: `update_bpf_layer_cpumask()` writes the new cpumask, per-LLC counts, and per-node counts to the BPF `layers[]` array and sets `refresh_cpus = 1`. The BPF side calls `refresh_cpumasks()` on the next scheduling event, which deserializes the byte-array cpumask into a BPF `bpf_cpumask` kptr.

### StickyDynamic Growth

The `StickyDynamic` algorithm (`recompute_layer_core_order()`) operates at LLC granularity:

1. Computes `(full_LLCs, extra_cores)` from the target CPU count.
2. **Free phase**: Layers that shrunk release excess LLCs back to `cpu_pool.free_llcs`.
3. **Alloc phase**: Growing layers claim freed LLCs.
4. **Spillover**: Extra cores that don't fill a whole LLC are distributed from the free LLC pool, bigger layers first.
5. Core orders are then reconstructed: assigned-LLC cores first, then spillover cores.

## Topology Awareness

### CPU Proximity Map (`cpu_prox_map`)

Each CPU has a proximity map (`cpu_ctx.prox_map`) that orders all other CPUs from closest to farthest. The ordering is: `self -> same-core siblings -> same-LLC CPUs -> same-NUMA-node CPUs -> system-wide CPUs`. Within each tier, CPUs are sorted by distance from the source CPU (radiating outward by core ID). This map is used by `pick_idle_cpu()` and preemption scanning.

### LLC Proximity Map (`llc_prox_map`)

Each LLC context has a proximity map ordering all LLCs from closest to farthest: `self -> same-node LLCs -> other-node LLCs`. Used by `try_consume_layer()` to find work in nearby LLCs before distant ones.

### Initialization (`init_cpu_prox_map()`, `init_llc_prox_map()`)

Both maps are computed in userspace at startup and written to BPF maps. The CPU proximity map is stored in `cpu_ctxs` per-cpu array. The LLC proximity map is stored in `llc_data` array. Each map uses randomized shuffling seeded by CPU/LLC ID to spread load.

### NUMA and LLC Constraints

Layers can be constrained to specific NUMA nodes and/or LLCs via `nodes` and `llcs` fields in `LayerCommon`. The `allowed_cpus` mask is computed at layer creation time and constrains all CPU allocation. The `skip_remote_node` option prevents cross-NUMA-node DSQ consumption. The `allow_node_aligned` option permits tasks with node-aligned affinity to skip the fallback DSQ path.

## Exclusive Layers

When a layer has `exclusive: true`, only one task from that layer can run on a physical core at a time. The SMT sibling is kept idle by:

1. **`sib_keep_idle()`** in `dispatch()`: If the sibling is running an exclusive task, do not dispatch to this CPU.
2. **`try_preempt_cpu()`**: When preempting for an exclusive task, also kicks the sibling to go idle.
3. **`cpuc->current_excl` / `cpuc->next_excl`**: Tracked in `running()` and communicated to sibling CPUs.

`nr_excl_layers` counts how many exclusive layers exist; if zero, all exclusive-related checks are skipped.

## Preemption

Layers with `preempt: true` can preempt tasks from non-preempting layers. The `try_preempt_cpu()` function:

1. Checks that the candidate CPU is not running a preempting task (unless `PREEMPT_IGNORE_EXCL`).
2. Checks that the candidate CPU is not in a protected layer.
3. Uses `__sync_val_compare_and_swap(&cand_cpuc->preempting_task, NULL, p)` to atomically claim the preemption.
4. Dispatches to `SCX_DSQ_LOCAL_ON | cand` with `SCX_ENQ_PREEMPT` flag.
5. Stale preemption claims are cleared after `CLEAR_PREEMPTING_AFTER = 10ms`.

The `preempt_first` option makes a task try to preempt its previous CPU before searching for idle CPUs, optimizing for cache locality at the cost of preemption.

## Protected Layers

Confined and grouped layers can be marked `protected: true`. A protected layer's CPUs will not run tasks from other layers. In `dispatch()`, after consuming from the owner layer, the code jumps to `replenish` instead of trying other layers. This is enforced by tracking an `unprotected_cpumask` BPF cpumask.

The `disallow_open_after_ns` and `disallow_preempt_after_ns` parameters provide time-based protection: a CPU's owned execution is "protected" for a configured duration after a task was last queued, preventing other layers from stealing the CPU during that window.

## Userspace Side

### Main Scheduling Loop (`Scheduler::run()`)

The main loop in `run()` uses `crossbeam::select!` to multiplex between:
1. **Stats requests** from the monitoring server.
2. **Cgroup events** from the inotify watcher thread.
3. **Timeout** at the next scheduling interval.

At each scheduling interval (`step()`):
1. Refresh stats (utilization, BPF stats, EWMA calculations).
2. Push EWMA values (`system_cpu_util_ewma`, `layer_dsq_insert_ewma`) to BPF.
3. Recalculate and apply CPU allocations (`refresh_cpumasks()`).
4. Update idle QoS latency settings.
5. Optionally affinitize GPU tasks to their nearest NUMA node.

### Statistics (`stats.rs`)

The `Stats` struct tracks:
- **Layer utilization**: EWMA-smoothed CPU usage per layer, decomposed into `OWNED`, `OPEN`, `PROTECTED`, and `PROTECTED_PREEMPT` categories. Decay rate `USAGE_HALF_LIFE = 100ms`.
- **Memory bandwidth**: Per-layer memory bandwidth estimated from PMU counters and normalized against `resctrl` readings.
- **BPF stats**: Aggregated per-layer and global statistics from BPF (`lstats`, `gstats`).
- **System CPU utilization EWMA**: 10-second window, pushed to BPF for `MATCH_SYSTEM_CPU_UTIL_BELOW`.
- **DSQ insertion EWMA**: Ratio of DSQ insertions vs. direct/local dispatches per layer, 10-second window.

### GPU Support

When `--enable_gpu_support` is enabled:
- Nvidia kprobes (`nvidia_open`, `nvidia_mmap`, `nvidia_poll`) are attached to track GPU API usage.
- `gpu_tgid` and `gpu_tid` BPF maps store the last GPU usage timestamp per process/thread group.
- The `MATCH_USED_GPU_TID` / `MATCH_USED_GPU_PID` predicates check these timestamps against `member_expire_ms`.
- `GpuTaskAffinitizer` periodically uses NVML to discover GPU processes and `sched_setaffinity()` their threads to the NUMA node closest to their GPU.

### Cgroup Regex Matching

Since BPF cannot execute regular expressions, cgroup regex matching is handled by a userspace watcher thread:
1. An inotify watcher monitors `/sys/fs/cgroup` for directory creation/deletion.
2. For each cgroup, all regex rules are evaluated. A 64-bit bitmap is computed where bit `i` indicates whether regex rule `i` matched.
3. The bitmap is inserted into the `cgroup_match_bitmap` BPF hash map keyed by cgroup inode ID.
4. BPF's `match_one()` for `MATCH_CGROUP_REGEX` simply looks up the bitmap and checks the relevant bit.

## Configuration

### JSON Format

The configuration is a JSON array of `LayerSpec` objects:

```json
[
  {
    "name": "my_layer",
    "comment": "optional description",
    "matches": [
      [{"CgroupPrefix": "/my/workload"}],
      [{"CommPrefix": "myapp"}, {"NiceBelow": 0}]
    ],
    "kind": {
      "Confined": {
        "util_range": [0.5, 0.8],
        "cpus_range": [4, 16],
        "common": {
          "preempt": true,
          "weight": 200,
          "slice_us": 5000,
          "growth_algo": "Topo"
        }
      }
    }
  }
]
```

The `matches` field is a list of OR groups, each containing a list of AND conditions.

### Key `LayerCommon` Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `slice_us` | `u64` | 0 (uses global) | Time slice in microseconds |
| `fifo` | `bool` | `false` | FIFO ordering (vs. vtime/weighted fair queuing) |
| `weight` | `u32` | 100 | Scheduling weight (1..10000). Higher = more CPU share |
| `preempt` | `bool` | `false` | Can preempt non-preempting layers |
| `preempt_first` | `bool` | `false` | Try preempting previous CPU before idle scan |
| `exclusive` | `bool` | `false` | Only one task per physical core |
| `growth_algo` | enum | `Sticky` | CPU growth algorithm |
| `min_exec_us` | `u64` | 0 | Minimum execution guarantee |
| `yield_ignore` | `f64` | 0.0 | Fraction of yield to ignore (0.0 = full yield, 1.0 = ignore yield) |
| `perf` | `u64` | 0 | CPU frequency scaling target |
| `idle_resume_us` | `u32` | None | Idle QoS resume latency |
| `nodes` | `Vec<usize>` | `[]` | Restrict to specific NUMA nodes |
| `llcs` | `Vec<usize>` | `[]` | Restrict to specific LLCs |
| `allow_node_aligned` | `bool` | `false` | Allow node-aligned tasks without fallback |
| `skip_remote_node` | `bool` | `false` | Skip remote NUMA nodes when consuming DSQs |
| `prev_over_idle_core` | `bool` | `false` | Prefer previous CPU over idle core |
| `disallow_open_after_us` | `u64` | global default | Time before open execution is allowed on owned CPUs |
| `disallow_preempt_after_us` | `u64` | global default | Time before preemption is allowed on owned CPUs |
| `xllc_mig_min_us` | `f64` | 0.0 | Minimum queued runtime (us) before cross-LLC migration |
| `placement` | enum | `Standard` | Task placement strategy: `Standard`, `Sticky`, or `Floating` |
| `member_expire_ms` | `u64` | 0 | Layer membership expiration for GPU-tracked tasks |

### Confined/Grouped-Specific Parameters

| Parameter | Type | Description |
|---|---|---|
| `util_range` | `(f64, f64)` | Target utilization range (e.g. `(0.5, 0.8)`) |
| `cpus_range` | `(usize, usize)` | Absolute CPU count limits |
| `cpus_range_frac` | `(f64, f64)` | Fractional CPU count limits (0.0..1.0) |
| `membw_gb` | `f64` | Memory bandwidth limit in GB/s |
| `protected` | `bool` | Prevent other layers from using owned CPUs |
| `util_includes_open_cputime` | `bool` | (Grouped only) Include open execution time in utilization for sizing |

### Global CLI Options

Notable command-line options:

| Option | Description |
|---|---|
| `--interval` | Scheduling interval in seconds (default: 1.0) |
| `--slice-us` | Default time slice in microseconds |
| `--max-exec-us` | Maximum continuous execution time |
| `--lo-fb-wait-us` | Wait before low-fallback execution (default: 5000us) |
| `--lo-fb-share` | Low-fallback CPU share fraction (default: 0.125) |
| `--disable-topology` | Disable topology awareness |
| `--disable-antistall` | Disable anti-stall mechanism |
| `--antistall-sec` | Anti-stall delay in seconds (default: 3) |
| `--enable-gpu-support` | Enable GPU kprobe tracking |
| `--enable-gpu-affinitize` | Enable GPU task NUMA affinitization |
| `--netdev-irq-balance` | Balance network device IRQs across available CPUs |
| `--allow-partial-core` | Allow sub-core (partial SMT) CPU allocation |
| `--monitor` | Connect to running scheduler and display stats |

## Anti-Stall Mechanism

The anti-stall mechanism (`antistall_consume()`) prevents task starvation in DSQs that might not be consumed by their assigned CPUs (e.g., due to affinity constraints). It is implemented as a BPF timer (`layered_antistall_timer_init()` in `timer.bpf.c`) that periodically scans all DSQs. For each CPU, it records the most-delayed DSQ that the CPU can serve. On the next `dispatch()`, the CPU prioritizes consuming from that DSQ.

The delay is measured via `p->scx.runnable_at` against `bpf_jiffies64()`, converted to seconds. The threshold is `antistall_sec` (default 3 seconds).

## Vtime and Weighted Fair Queuing

For non-FIFO layers, tasks are ordered by virtual time (`p->scx.dsq_vtime`) in each per-LLC DSQ. The vtime advances proportionally to `(runtime * layer_weight / task_weight)` when the task stops (`layered_stopping()`).

Each LLC maintains `vtime_now[layer_id]` which tracks the current vtime frontier. On enqueue, the task's vtime is clamped to `[vtime_now - slice_ns, vtime_now + 8192 * slice_ns]` to prevent tasks from accumulating too much credit or falling too far behind.

## Fallback DSQs

Two tiers of fallback ensure no task is starved:

**High fallback (`HI_FB_DSQ_BASE`)**: Per-cpu kthreads with limited affinity and scx_layered's own userspace threads. Consumed first in `dispatch()`, before any layer DSQs. This ensures system-critical threads always run promptly.

**Low fallback (`LO_FB_DSQ_BASE`)**: Tasks with non-standard cpuset affinity or belonging to layers with zero assigned CPUs. Consumption is budget-controlled:
- `lo_fb_wait_ns`: Grace period before low fallback starts consuming (default 5ms).
- `lo_fb_share_ppk`: Parts-per-1024 of CPU time allocated to low fallback (default 128 = 12.5%).
- The budget resets each time the DSQ transitions from empty to non-empty (`llcc->lo_fb_seq`).

## Keep-Running Optimization

When a task exhausts its slice and `dispatch()` is called, the `keep_running()` function decides whether to let it continue rather than context-switching. A task keeps running if:
- It is still runnable (`SCX_TASK_QUEUED`).
- It hasn't exceeded `max_exec_ns` total continuous runtime.
- For preempting layers: its layer DSQ is empty.
- For non-preempting layers: there are idle CPUs (system-wide for open, layer-restricted for confined).
- The high-fallback DSQ is empty.
- The task is not in the low-fallback path.

## Cross-LLC Migration Control

The `xllc_mig_min_ns` parameter controls when tasks are pulled across LLC boundaries. In `try_consume_layer()`, remote LLCs are skipped unless `llcc->queued_runtime[layer_id] >= layer->xllc_mig_min_ns`. This prevents unnecessary cache-cold migrations when the remote LLC has only a small amount of work queued.

The `queued_runtime` is maintained atomically: charged at `enqueue()` with the task's `runtime_avg`, and uncharged at `stopping()` via `task_uncharge_qrt()`.

## Task Placement Strategies

The `placement` field controls CPU selection behavior in `pick_idle_cpu()`:

- **`Standard`**: Default behavior -- try the task's previous CPU first, then search by proximity.
- **`Sticky`**: Strongly prefer the previous CPU. Skip idle core preference.
- **`Floating`**: Do not prefer the previous CPU. Always search for the best idle CPU from scratch.

The `prev_over_idle_core` flag modifies Standard placement to prefer the previous CPU (even if its sibling is busy) over an idle core elsewhere.

## Netdev IRQ Balancing

When `--netdev-irq-balance` is enabled, the scheduler dynamically adjusts network device IRQ CPU affinities. Available CPUs (not allocated to confined/grouped layers) within each device's NUMA node are used for IRQ handling. This prevents scheduling interference from IRQs on allocated CPUs. Affinities are restored on scheduler exit.

## Memory Bandwidth Tracking

When enabled, per-task memory bandwidth is tracked using PMU counters (read via `scx_pmu_read()`) and normalized against `resctrl` `mbm_total_bytes` readings. The normalization corrects for the fact that PMU counters measure proxies (e.g., cache line loads) rather than actual memory traffic. Bandwidth limits (`membw_gb`) can constrain a layer's CPU allocation.

## Timer Infrastructure (`timer.bpf.c`)

The BPF timer system handles periodic maintenance:
- **Anti-stall timer**: Scans all DSQs for delayed tasks and maps them to CPUs.
- **Monitor timer**: Periodically logs layer statistics (when `monitor_disable` is false).
- Timers are initialized in `layered_init()` and fire via BPF timer callbacks.
