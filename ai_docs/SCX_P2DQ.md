# scx_p2dq
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_p2dq` is a general-purpose sched_ext scheduler developed at Meta that uses a **pick-2 random load balancing** algorithm to distribute work across last-level caches (LLCs) and NUMA nodes. The scheduler maintains **multi-layer dispatch queues** (DSQs) organized hierarchically: per-CPU affinity DSQs, per-LLC DSQs (optionally sharded), and per-LLC migration DSQs. All scheduling decisions happen entirely in BPF; the userspace component handles only metric reporting and integration with power management subsystems (EPP, turbo, uncore frequency, idle QoS).

The scheduler classifies tasks as **interactive** or **throughput-oriented** based on their actual runtime relative to their assigned time slice, and routes them to different DSQ tiers with different slice durations. Tasks that exhaust their slice are promoted to longer-duration queues; tasks that yield early are demoted to shorter-duration (interactive) queues. Cross-LLC migration eligibility is gated by a configurable "LLC stickiness" counter (`llc_runs`) that prevents premature migration.

`scx_p2dq` supports BPF arena-based task queues (ATQs), double-helix queues (DHQs), PELT-based load tracking, energy-aware scheduling (EAS) for big.LITTLE architectures, thermal pressure tracking (ARM64), CPU priority scheduling via min-heaps, deadline slice scaling, LLC DSQ sharding, and fork/exec-time load balancing.

## Architecture/Design

### Separation of Concerns

| Layer | Responsibility |
|-------|---------------|
| **BPF (`main.bpf.c`)** | All scheduling hot-path decisions: CPU selection, enqueue, dispatch, load balancing, vtime accounting, PELT tracking, DSQ promotion/demotion |
| **Userspace library (`lib.rs`)** | Configuration parsing (`SchedulerOpts`), topology discovery, BPF skeleton initialization, hardware profile detection, energy model creation |
| **Userspace binary (`main.rs`)** | Lifecycle management, stats server, power management (EPP, turbo, uncore freq, idle QoS), signal handling |
| **Stats (`stats.rs`)** | Per-CPU stat aggregation from BPF maps, delta computation, formatted output for `scxtop` |
| **Energy (`energy.rs`)** | Energy model: per-CPU capacity and power cost from kernel EM or frequency-based heuristics |

### Configuration Architecture

Configuration is organized into four `const volatile` structs in BPF, set from userspace before loading:

| Config Struct | Fields | Purpose |
|---------------|--------|---------|
| `topo_config` | `nr_cpus`, `nr_llcs`, `nr_nodes`, `smt_enabled`, `has_little_cores` | Topology constants |
| `timeline_config` | `min_slice_us`, `max_exec_ns`, `autoslice`, `deadline` | Time slice policy |
| `lb_config` | `slack_factor`, `min_llc_runs_pick2`, `dispatch_pick2_disable`, `dispatch_lb_busy`, `wakeup_llc_migrations`, `single_llc_mode`, ... | Load balancing policy |
| `p2dq_config` | `nr_dsqs_per_llc`, `init_dsq_index`, `dsq_shift`, `interactive_ratio`, `saturated_percent`, `sched_mode`, `llc_shards`, `atq_enabled`, `dhq_enabled`, `cpu_priority`, `pelt_enabled`, `enable_eas`, ... | Core scheduler policy |
| `latency_config` | `latency_priority_enabled`, `wakeup_preemption_enabled` | Latency priority and preemption |

### Hardware Profile Auto-Optimization

The `HardwareProfile::detect()` method (in `lib.rs`) inspects the topology and CPU architecture to apply automatic optimizations via `optimize_scheduler_opts()`:

- **Single-LLC systems**: Disables pick-2 dispatch, wakeup LLC migrations, and multi-LLC run counting.
- **Large single-LLC ARM64 (Neoverse-V2, 64+ cores)**: Adjusts shard count to `core_count / 8` (capped at 16).

## Pick-2 Load Balancing Algorithm

The pick-2 algorithm is the core cross-LLC load balancing mechanism. It operates at two points in the scheduling path:

### Select-CPU Path (Proactive)

In `pick_idle_cpu()`, when a task's current LLC has been identified as imbalanced by the periodic load balance timer, the `lb_llc_id` field on the LLC context points to a less-loaded LLC. The scheduler attempts to find an idle CPU in that target LLC, incrementing `P2DQ_STAT_SELECT_PICK2`.

### Dispatch Path (Reactive)

`dispatch_pick_two()` fires when a CPU has exhausted its local queues. The algorithm:

1. **Guard checks**: Skipped in single-LLC mode, when `dispatch_pick2_disable` is set, when fewer than `min_nr_queued_pick2` tasks are queued, or during a backoff period (`backoff_ns`, default 5ms).

2. **Random selection**: Two LLCs are chosen randomly (or deterministically for 2-LLC systems using `llc_ids[0]` and `llc_ids[1]`). If both random picks hit the same LLC, a deterministic fallback is used: `llc_get_load(cur_llcx) % nr_llcs`.

3. **Load comparison**: The LLC with **higher load** (via `llc_get_load()`, which returns `util_avg` when PELT is enabled, or legacy `load` counter otherwise) is tried first.

4. **Slack factor**: Migration only occurs if the source LLC's load exceeds the current LLC's load plus a slack percentage: `cur_load + (cur_load * slack_factor / 100)`. Default slack is 5%.

5. **Consume**: `consume_llc()` attempts to pop a task from the migration queue (DHQ, ATQ, or DSQ depending on configuration) and insert it into the local LLC DSQ.

6. **Saturation aggressive mode**: When the system is saturated (fewer than `saturated_percent` idle CPUs), the slack check is bypassed and a third random LLC may be tried.

### Periodic Load Balance Timer

A BPF timer (`EAGER_LOAD_BALANCER_TMR`) fires every 250ms (`lb_timer_intvl_ns`). The `load_balance_timer()` function:

1. Iterates over all LLCs comparing each to a rotating partner (`llc_lb_offset` increments each period).
2. Computes load imbalance as a percentage: `100 * (load_A - load_B) / load_A`.
3. If imbalance exceeds `slack_factor`, sets `llcx->lb_llc_id` to suggest migration on the next `select_cpu`.
4. Runs **autoslice** adjustment: scales `dsq_time_slices[0]` up by 10% if interactive load is below the target ratio, or down by ~9% if above. Higher DSQ slices are derived by left-shifting.
5. Resets legacy load counters (PELT metrics decay automatically).

## DSQ Structure

### DSQ Hierarchy

For each LLC, multiple DSQ types are created:

| DSQ Type | ID Formula | Purpose |
|----------|-----------|---------|
| **LLC DSQ** | `llcx->id \| MAX_LLCS` | Main per-LLC queue, or sharded into multiple DSQs |
| **Migration DSQ** | `llcx->id \| P2DQ_MIG_DSQ` (bit 60) | Tasks eligible for cross-LLC migration |
| **Affinity DSQ** | `(MAX_DSQS_PER_LLC * MAX_LLCS) << 2 + cpu` | Per-CPU queue for affinity-restricted tasks |
| **Shard DSQs** | `(MAX_DSQS_PER_LLC * MAX_LLCS) << 3 + llc_id * MAX_DSQS_PER_LLC + shard_id` | Sharded LLC DSQs (when `llc_shards > 1`) |

### DSQ Sharding

When `llc_shards > 1`, the single LLC DSQ is replaced by multiple shard DSQs. Each CPU is assigned to a shard based on `core_id % nr_shards`. During dispatch, the CPU first tries its own shard, then steals from other shards in the LLC. This reduces contention on large-core-count LLCs. Default shard count is `max_cpus_per_llc / 4` (disabled if <= 4 CPUs per LLC).

### Multi-Tier DSQ Time Slices

The scheduler maintains `nr_dsqs_per_llc` (default 3) logical tiers. Each tier has a time slice stored in `dsq_time_slices[]`:

- **DSQ[0]** (interactive): Default 500us. Tasks in this tier are tagged `TASK_CTX_F_INTERACTIVE`.
- **DSQ[1]**: Default 2500us.
- **DSQ[2]** (throughput): Default 5000us.

When `autoslice` is enabled, DSQ[0]'s slice is dynamically adjusted by the load balance timer to maintain the configured `interactive_ratio` (default 10%). Higher tiers are derived: `dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift`.

When `task_slice` is enabled, individual task slices are adjusted based on utilization: tasks using >= 87.5% of their slice get a 25% increase (`5/4`); tasks using < 50% get a 12.5% decrease (`7/8`). All slices are clamped to `[min_dsq_time_slice, max_dsq_time_slice]`.

### DSQ Promotion and Demotion

In `p2dq_stopping()`, when a task becomes non-runnable:

- **Promote** (move to longer-slice DSQ): If `used >= 90% * last_dsq_slice_ns` (95% for affinitized tasks), and the task is not already at the highest DSQ and has weight >= 100.
- **Demote** (move to shorter-slice DSQ): If `used < 50% * last_dsq_slice_ns` (25% for affinitized tasks), and not already at DSQ[0].
- Nice tasks (weight < 100) are capped at DSQ[1].

## Scheduling Hot Path (BPF Callbacks)

### `p2dq_select_cpu` -> `p2dq_select_cpu_impl()`

Called when a task becomes runnable. The function attempts to find an idle CPU and optionally direct-dispatch the task:

1. **Affinitized tasks** (`!TASK_CTX_F_ALL_CPUS`): Routed to `pick_idle_affinitized_cpu()` which tries prev_cpu, then idle SMT core in LLC, then idle CPU in LLC, then idle in NUMA node, then random.

2. **Normal tasks**: Routed to `pick_idle_cpu()` with this priority cascade:
   - **prev_cpu** if idle (fast path, most common)
   - **Interactive sticky**: If enabled and task is interactive, stay on prev_cpu
   - **WAKE_SYNC handling**: For waker/wakee pairs, try idle CPU in waker's LLC
   - **Energy-aware selection** (`enable_eas`): `pick_idle_energy_aware()` scores CPUs by `capacity * 10 - energy_cost / 10`, preferring little cores for low-util tasks and big cores for high-util tasks
   - **Scheduler mode** (`MODE_PERF` / `MODE_EFFICIENCY`): Biases to big or little cores with thermal awareness
   - **Load balance target LLC** (`lb_llc_id`): If the timer flagged an imbalance, try that LLC
   - **CPU priority** (`cpu_priority`): Pop from min-heap for preferred core values (AMD P-state, Intel HWP)
   - **LLC idle core/CPU**: Standard idle search within LLC cpumask
   - **NUMA node / all CPUs**: For saturated migratable tasks, widen search

3. **Wakeup preemption**: If `wakeup_preemption_enabled` and task weight >= 2847 (nice <= -15) and no idle CPU found, target prev_cpu if running task has lower weight.

4. If an idle CPU is found and the task has full CPU affinity, it is **directly dispatched** to `SCX_DSQ_LOCAL` (bypassing enqueue).

### `p2dq_enqueue` -> `async_p2dq_enqueue()` + `complete_p2dq_enqueue()`

The enqueue path uses a **promise/completion** pattern. `async_p2dq_enqueue()` computes where a task should go and returns an `enqueue_promise` tagged union. `complete_p2dq_enqueue()` executes the actual insertion. This two-phase design allows `scx_chaos` (a derivative scheduler) to defer or reorder enqueue decisions.

**Promise kinds:**

| Kind | Description |
|------|-------------|
| `P2DQ_ENQUEUE_PROMISE_COMPLETE` | Already dispatched (e.g., per-CPU kthread to `SCX_DSQ_LOCAL`) |
| `P2DQ_ENQUEUE_PROMISE_FIFO` | Insert to DSQ in FIFO order (idle CPU found, or nice task preemption) |
| `P2DQ_ENQUEUE_PROMISE_VTIME` | Insert to DSQ ordered by virtual time |
| `P2DQ_ENQUEUE_PROMISE_ATQ_VTIME` | Insert to arena-based ATQ with vtime ordering |
| `P2DQ_ENQUEUE_PROMISE_DHQ_VTIME` | Insert to double-helix queue with vtime and strand |
| `P2DQ_ENQUEUE_PROMISE_FAILED` | Error state |

**Enqueue decision flow:**

1. **Per-CPU kthreads**: Direct dispatch to `SCX_DSQ_LOCAL` with minimum slice.
2. **Exec balancing**: If task is transitioning from fork-no-exec to exec, find least-loaded LLC via `find_least_loaded_llc_for_fork()`.
3. **Fork balancing**: New forked tasks (first enqueue, `llc_runs == 0`) are balanced to least-loaded LLC.
4. **Target LLC hint**: If fork/exec balance set a `target_llc_hint`, find idle CPU in that LLC and dispatch with FIFO.
5. **Affinitized tasks**: Always placed on per-CPU `affn_dsq` with vtime ordering. Single-CPU tasks get slice penalized by queue depth.
6. **Migratable tasks** (`can_migrate()` returns true): Placed on migration queue (DHQ, ATQ, or `mig_dsq`).
7. **LLC-local tasks**: Placed on `llc_dsq` (or shard DSQ) with vtime ordering.

### `p2dq_dispatch` -> `p2dq_dispatch_impl()`

Called when a CPU needs work. The dispatch logic implements **cross-DSQ vtime fairness**:

1. **Peek all queues**: Using `scx_bpf_dsq_peek()`, peek the head of: current CPU's `affn_dsq`, LLC DSQ, and migration queue (DHQ/ATQ/mig_dsq). Track the minimum vtime across all.

2. **Affinity DSQ work stealing**: Iterate all other CPUs in the same LLC and peek their `affn_dsq`. If a task there can run on the current CPU and has a lower vtime, prefer it.

3. **Consume lowest vtime**: Pop from whichever queue had the lowest vtime task. For DHQ/ATQ, the task is first inserted into the LLC DSQ, then `scx_bpf_dsq_move_to_local()` is called.

4. **Shard stealing**: If sharding is enabled, try other shard DSQs within the LLC.

5. **Migration DSQ fallback**: Try consuming from `mig_dsq` directly.

6. **Keep running**: If `keep_running_enabled`, and the previous task is in an interactive DSQ, and the LLC is not overloaded, extend its slice and let it continue.

7. **Pick-2 load balance**: As a last resort, call `dispatch_pick_two()`.

### `p2dq_running` -> `p2dq_running_impl()`

Called when a task starts running on a CPU:

- Detects LLC migration (increments `P2DQ_STAT_LLC_MIGRATION`) and refreshes `llc_runs`.
- Decrements `llc_runs` for same-LLC runs.
- Propagates task properties to `cpu_ctx` flags (`CPU_CTX_F_INTERACTIVE`, `CPU_CTX_F_NICE_TASK`).
- Advances LLC `vtime` via `__sync_val_compare_and_swap()` (lock-free).
- If `freq_control` is enabled and task is in the highest DSQ tier, sets CPU frequency to max (`SCX_CPUPERF_ONE`).
- Initializes PELT decay update.

### `p2dq_stopping`

Called when a task stops running:

- Computes `used = now - last_run_at` and `scaled_used = scale_by_task_weight_inverse(p, used)`.
- Advances task vtime: `p->scx.dsq_vtime += scaled_used`.
- Advances LLC vtime atomically: `__sync_fetch_and_add(&llcx->vtime, used)`.
- Updates PELT metrics or legacy load counters.
- Performs DSQ promotion/demotion (described above).
- Adjusts `slice_ns` for task-slice mode.

### `p2dq_update_idle`

Called on CPU idle transitions:

- Computes system-wide idle percentage and sets `saturated` flag if below `saturated_percent`.
- Dynamically adjusts `min_llc_runs_pick2` based on idle percentage and LLC count (using log2 scaling).
- Tracks per-LLC saturation: `LLC_CTX_F_SATURATED` is set when no CPUs in the LLC are idle.
- For `cpu_priority` mode, inserts the CPU into the LLC's min-heap with a score based on `cpu_priority()` and timestamp.

### `p2dq_set_cpumask`

Called when a task's CPU affinity changes:

- Updates `TASK_CTX_F_ALL_CPUS` flag.
- If affinity narrowed from all-CPUs to restricted and task was in a migration DSQ, moves it to the LLC DSQ to prevent cross-LLC livelock.

### `p2dq_init_task` -> `p2dq_init_task_impl()`

Called when a new task is created:

- Allocates task context via `scx_task_alloc()` (BPF arena allocation).
- Creates per-task cpumask via `bpf_cpumask_create()` (stored in `BPF_MAP_TYPE_TASK_STORAGE`).
- Sets initial DSQ index based on nice value: weight < 100 -> DSQ[0], weight == 100 -> `init_dsq_index`, weight > 100 -> last DSQ.
- Initializes vtime to LLC's current vtime.
- Sets `TASK_CTX_F_FORKNOEXEC` if `PF_FORKNOEXEC`.
- For all-CPU tasks, sets `dsq_id = SCX_DSQ_INVALID` to trigger randomized LLC placement on first enqueue.

## BPF Arenas

`scx_p2dq` uses three types of arena-allocated data structures for migration queues:

### Arena Task Queues (ATQ)

Enabled via `--atq-enabled`. Requires kernel 6.12+ with `bpf_spin_unlock` support. Created per-LLC via `scx_atq_create_size()` with capacity equal to `nr_cpus`. ATQs support:

- `scx_atq_insert_vtime()`: Vtime-ordered insertion.
- `scx_atq_pop()`: Pop lowest-vtime task.
- `scx_atq_peek()`: Non-destructive peek at head.
- `scx_atq_cancel()`: Remove a task (called from `p2dq_dequeue`).
- `scx_atq_nr_queued()`: Queue depth.

ATQs are stored as `scx_atq_t *` pointers in `llc_ctx.mig_atq` and copied to `cpu_ctx.mig_atq` for fast access.

### Double-Helix Queues (DHQ)

Enabled via `--dhq-enabled`. DHQs pair two LLCs within the same NUMA node, assigning each LLC to a **strand** (A or B). A single DHQ is shared between the pair. The DHQ provides:

- **Two-strand enqueue**: Each LLC enqueues to its own strand via `scx_dhq_insert_vtime()`.
- **Same-strand dequeue**: Each LLC dequeues from its own strand via `scx_dhq_pop_strand()`.
- **Balance control**: `dhq_max_imbalance` (default 3) limits how far one strand can dequeue ahead of the other. If imbalance is exceeded, `scx_dhq_insert_vtime()` returns `-EAGAIN` and the task falls back to the regular DSQ.
- **Priority mode**: Created with `SCX_DHQ_MODE_PRIORITY` so lowest-vtime tasks are dequeued first.

DHQ creation in `llc_create_dhqs()`:
- Tracks `llcs_per_node[]` to pair LLCs.
- Even-numbered LLCs in a node get strand A (and create the DHQ).
- Odd-numbered LLCs get strand B (and share the existing DHQ).
- Capacity = `nr_cpus * 4`.

### Arena-Based Task Context

All per-task scheduling state is stored in `struct task_p2dq` (aliased as `task_ctx`), which lives in BPF arena memory allocated via `scx_task_alloc()`. The `ArenaLib` is initialized in `main.rs` with `task_size = sizeof(task_p2dq)` and `nr_cpus = NR_CPU_IDS`. The struct begins with `struct scx_task_common` for compatibility with the ATQ/SDT task infrastructure.

## PELT (Per-Entity Load Tracking)

Enabled by default (`--enable-pelt true`). A simplified BPF-friendly implementation of the kernel's PELT algorithm:

### Parameters

| Constant | Value | Meaning |
|----------|-------|---------|
| `PELT_HALFLIFE_MS` | 32 | 32ms half-life for exponential decay |
| `PELT_PERIOD_MS` | 1 | 1ms update period |
| `PELT_MAX_UTIL` | 1024 | Maximum utilization value |
| `PELT_DECAY_SHIFT` | 7 | Decay factor: `127/128` per ms |
| `PELT_SUM_MAX` | 131072 | Maximum `util_sum` (`128 * 1024`) |

### Per-Task Tracking

`update_task_pelt()` is called in `p2dq_running()` (decay-only, delta=0) and `p2dq_stopping()` (with actual runtime delta):

1. Computes elapsed milliseconds since last update.
2. Decays `util_sum` by `(127/128)^periods` via `pelt_decay()` (bounded to 256 iterations for BPF verifier).
3. Scales runtime contribution by CPU capacity and frequency: `scaled_time = wall_time * capacity * freq / (1024 * 1024)`.
4. Adds scaled contribution to `util_sum`, capped at `PELT_SUM_MAX`.
5. Computes `util_avg = util_sum >> 7` (average over ~128ms window), capped at `PELT_MAX_UTIL`.

### Per-LLC Aggregation

`aggregate_pelt_to_llc()` atomically adds task's `util_avg` to LLC-level counters:
- `llcx->util_avg`: Total LLC utilization.
- `llcx->intr_util_avg`: Interactive task utilization.
- `llcx->affn_util_avg`: Affinitized task utilization.

These are used by `llc_get_load()` for load balancing decisions and by the autoslice timer.

## Topology Awareness

### Data Structures

| Structure | Map | Key Fields |
|-----------|-----|------------|
| `cpu_ctx` | `BPF_MAP_TYPE_PERCPU_ARRAY` (1 entry) | `id`, `llc_id`, `node_id`, `affn_dsq`, `llc_dsq`, `mig_dsq`, `mig_atq`, `mig_dhq`, `dhq_strand`, `flags`, `perf`, `running_weight` |
| `llc_ctx` | `BPF_MAP_TYPE_ARRAY` (MAX_LLCS=64) | `id`, `nr_cpus`, `node_id`, `dsq`, `mig_dsq`, `vtime`, `load`, `util_avg`, cpumasks (cpumask, big, little, node, tmp), `idle_cpu_heap`, `shard_dsqs[]`, cache-line padded hot fields |
| `node_ctx` | `BPF_MAP_TYPE_ARRAY` (MAX_NUMA_NODES=64) | `id`, `cpumask`, `big_cpumask` |

### Cache-Line Padding

`llc_ctx` uses explicit cache-line padding (`CACHE_LINE_SIZE`: 64 bytes on x86, 128 bytes on ARM64) to separate hot atomically-updated fields:

1. **Read-mostly fields** (id, nr_cpus, node_id, dsq IDs, shard DSQs)
2. **pad1** -> `vtime` (frequently updated in `p2dq_stopping`)
3. **pad2** -> `load`, `affn_load`, `intr_load`, `state_flags`, PELT averages (updated atomically together)
4. **pad3** -> `idle_lock` (arena spinlock, contended during idle CPU selection)
5. **pad4** -> cpumask pointers, ATQ/DHQ pointers, idle_cpu_heap (read-mostly)

### Big/Little Core Support

Three scheduling modes (`--sched-mode`):

| Mode | Enum | Behavior |
|------|------|----------|
| `Default` | `MODE_DEFAULT` | Interactive tasks on efficient cores, throughput tasks on big cores |
| `Performance` | `MODE_PERF` | Bias all scheduling to big cores first |
| `Efficiency` | `MODE_EFFICIENCY` | Bias all scheduling to little cores first |

In `pick_idle_cpu()`, mode-specific logic tries `big_cpumask` or `little_cpumask` before the full LLC cpumask, with optional thermal-aware fallback on ARM64.

### Energy-Aware Scheduling (EAS)

Enabled via `--enable-eas`. Requires `--enable-pelt` (enabled by default). Uses per-CPU `cpu_capacity[]` and `cpu_energy_cost[]` arrays populated from the kernel energy model (`/sys/kernel/debug/energy_model`) or frequency-based heuristics.

`pick_idle_energy_aware()` in the BPF code:
- Low-utilization tasks (`util_avg < small_task_threshold`, default 256/1024): Prefer little cores.
- High-utilization tasks (`util_avg > large_task_threshold`, default 768/1024): Prefer big cores.
- Medium tasks: Score both core types and pick the best.

Scoring formula in `select_best_idle_cpu()`:
```
score = capacity * 10 - energy_cost / 10
```
Throttled CPUs get score 0. Higher score wins.

The `EnergyModel` (in `energy.rs`) derives `CpuEnergyProfile` per CPU with fields: `capacity` (0-1024), `base_power_mw`, `dynamic_power_mw`, `efficiency`. The `energy_cost()` method returns `total_power / capacity * 1024`. When the kernel EM is unavailable, heuristics estimate power from frequency using `P ~ k * f^2.5`.

## Userspace Side

### Initialization Flow

1. **Topology discovery**: `Topology::new()` (or `Topology::with_args()` for virtual LLCs).
2. **Hardware profile**: `HardwareProfile::detect()` checks single-LLC, core count, ARM64/Neoverse-V2.
3. **BPF open/load/attach**: Standard `scx_ops_open!` / `scx_ops_load!` / `scx_ops_attach!` macros.
4. **Arena setup**: `ArenaLib::init()` with `task_size` and `nr_cpus`, then `arenalib.setup()`.
5. **Config propagation**: The `init_open_skel!` macro writes all `SchedulerOpts` fields into BPF `rodata`.
6. **Topology data**: The `init_skel!` macro populates `big_core_ids[]`, `cpu_core_ids[]`, `cpu_llc_ids[]`, `cpu_node_ids[]`, `cpu_capacity[]`, `cpu_energy_cost[]`, and `llc_ids[]`.
7. **Conditional features**: Thermal tracepoint autoload (ARM64 only), ATQ/DHQ kernel support checks (`bpf_spin_unlock` ksym), CPU priority check (`sched_core_priority` ksym).

### Power Management

The userspace handles several power management features that are restored on exit:

- **EPP (Energy Performance Preference)**: Set to `"power"` in efficiency mode or `"performance"` in performance mode.
- **Turbo boost**: Disabled in efficiency mode, enabled in performance mode. Can be manually overridden with `--turbo`.
- **Uncore frequency**: Set to minimum in efficiency mode, maximum in performance mode, or a specific value with `--uncore-max-freq-mhz`.
- **Idle QoS resume latency**: `--idle-resume-us` sets per-CPU PM QoS constraints via sysfs.

### Stats and Monitoring

The `Metrics` struct (in `stats.rs`) aggregates 27 per-CPU counters from the BPF `stats` percpu array map. Key metrics:

| Metric | Description |
|--------|-------------|
| `direct` / `idle` | Tasks dispatched to local DSQ (select_cpu found idle) |
| `keep` | Tasks that kept running (no preemption needed) |
| `dsq_change` / `same_dsq` | DSQ tier promotion/demotion vs staying |
| `enq_cpu` / `enq_llc` / `enq_intr` / `enq_mig` | Enqueue destination breakdown |
| `select_pick2` / `dispatch_pick2` | Pick-2 load balancing events on select vs dispatch path |
| `llc_migrations` / `node_migrations` | Cross-LLC and cross-NUMA task migrations |
| `wake_prev` / `wake_llc` / `wake_mig` | Wakeup placement: same CPU, same LLC, different LLC |
| `fork_balance` / `exec_balance` | Fork/exec-time cross-LLC balancing events |
| `thermal_kick` / `thermal_avoid` | Thermal pressure events (ARM64) |
| `eas_little_select` / `eas_big_select` / `eas_fallback` | EAS core type selection events |
| `atq_enq` / `atq_reenq` | ATQ/DHQ enqueue and re-enqueue (DHQ fallback) events |

Stats are served via a `StatsServer` and can be monitored with `scx_p2dq --monitor <interval>` or `scxtop`.

## Virtual Time (Vtime) Accounting

Each LLC maintains a monotonically advancing `vtime` (in `llc_ctx`). Each task has `p->scx.dsq_vtime` tracking its virtual time position.

**On task stop** (`p2dq_stopping`):
- `scaled_used = scale_by_task_weight_inverse(p, used)` -- higher-weight tasks advance vtime slower.
- `p->scx.dsq_vtime += scaled_used`
- `llcx->vtime += used` (raw, not weight-scaled)

**On task start** (`update_vtime()`):
- Same LLC: Clamp task vtime so it doesn't lag more than `max_dsq_time_slice` behind LLC vtime.
- Different LLC (migration): Reset task vtime to target LLC's vtime.

**Deadline scheduling** (`--deadline`): `set_deadline_slice()` scales the task's slice inversely with queue pressure: `slice = max_slice * nr_idle / nr_queued`, clamped.

## Migration Eligibility

`can_migrate()` determines if a task can be placed in a migration DSQ:

1. **Single LLC mode**: Never migrate.
2. **Fewer than 2 LLCs**: Never migrate.
3. **Not all-CPUs affinity**: Cannot migrate.
4. **Interactive + `!dispatch_lb_interactive`**: Cannot migrate.
5. **`max_dsq_pick2` mode**: Only the highest DSQ tier can migrate.
6. **`llc_runs > 0`**: Task hasn't exhausted its LLC stickiness counter. This counter is reset to `min_llc_runs_pick2` on each LLC migration and decremented each run on the same LLC. `min_llc_runs_pick2` is dynamically adjusted based on system idle percentage (lower when saturated).
7. **Saturated/overloaded**: Override stickiness -- allow migration.

## Fork and Exec Balancing

### Fork Balancing (`--fork-balance`, enabled by default)

When a newly forked task (`PF_FORKNOEXEC` set, `llc_runs == 0`) is enqueued:
1. `find_least_loaded_llc_for_fork()` compares parent's LLC load with a randomly chosen LLC (or the other LLC in 2-LLC systems).
2. If the candidate LLC has lower load, sets `taskc->target_llc_hint`.
3. On the next enqueue pass, `find_idle_cpu_in_target_llc()` searches for an idle CPU (preferring idle cores over idle threads).

### Exec Balancing (`--exec-balance`, enabled by default)

When a task transitions from fork-no-exec to exec (the `PF_FORKNOEXEC` flag clears):
1. Same pick-2 LLC comparison as fork balancing.
2. If beneficial, sets `taskc->target_llc_hint` for the next enqueue.

## Constants and Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_CPUS` | 512 | Maximum supported CPUs |
| `MAX_NUMA_NODES` | 64 | Maximum NUMA nodes |
| `MAX_LLCS` | 64 | Maximum LLCs |
| `MAX_DSQS_PER_LLC` | 8 | Maximum DSQ tiers per LLC |
| `MAX_LLC_SHARDS` | 32 | Maximum shards per LLC |
| `MAX_TASK_PRIO` | 39 | Maximum task priority levels |
| `MAX_TOPO_NODES` | 1024 | Maximum topology nodes |
| `MIN_SLICE_USEC` | 10 | Absolute minimum time slice |
| `LOAD_BALANCE_SLACK` | 20 | Default load balance slack percentage |
| `P2DQ_MIG_DSQ` | `1 << 60` | Bit flag for migration DSQ IDs |
| `P2DQ_INTR_DSQ` | `1 << 32` | Bit flag for interactive DSQ IDs |
| `timeout_ms` | 25000 | Watchdog timeout for the scheduler |

## Key Design Decisions

1. **All-BPF scheduling**: Zero userspace involvement in the hot path. The userspace component only does stats collection and power management, running on a 1-second timer.

2. **Promise/completion enqueue pattern**: `async_p2dq_enqueue()` returns a tagged union (`enqueue_promise`) that can be completed later. This enables `scx_chaos` to inject entropy or reorder enqueue operations without duplicating the enqueue logic.

3. **Vtime fairness across queue types**: During dispatch, all queue heads (affn_dsq, LLC DSQ, migration queue) are peeked and the task with the lowest vtime is chosen, ensuring global fairness regardless of which queue a task was placed in.

4. **Dynamic LLC stickiness**: `min_llc_runs_pick2` adapts with system load -- lower stickiness when the system is saturated (need more aggressive balancing), higher when there is idle capacity (prefer cache locality).

5. **Per-CPU affinity DSQs**: Affinitized tasks get their own per-CPU DSQ rather than sharing the LLC DSQ, preventing them from blocking non-affinitized work. Cross-CPU affinity work stealing within the LLC prevents starvation.

6. **Cache-line-aware struct layout**: `llc_ctx` uses explicit padding to isolate atomically-contended fields (`vtime`, `load`, `idle_lock`) onto separate cache lines, reducing false sharing on multi-socket systems.
