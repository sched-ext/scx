# scx_flash
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_flash** is a production-ready sched_ext BPF scheduler authored by Andrea Righi. It focuses on **fairness among tasks** and **performance predictability** by using an **Earliest Deadline First (EDF)** scheduling policy. Each task is assigned a dynamically-adjusted "latency weight" based on its voluntary context switch behavior: tasks that release the CPU early (sleep frequently, use short bursts) receive higher latency weight and thus shorter deadlines, giving them priority over CPU-bound tasks that fully consume their time slices.

The scheduler is particularly well-suited for latency-sensitive workloads such as multimedia processing, real-time audio, gaming, and interactive desktop use, while still maintaining fairness under heavy load.

## Architecture / Design

scx_flash is structured as a typical sched_ext scheduler with two cooperating components:

| Component | Language | File | Role |
|-----------|----------|------|------|
| BPF program | C | `src/bpf/main.bpf.c` | All scheduling hot-path logic: CPU selection, enqueue, dispatch, vruntime accounting |
| BPF/userspace interface | C | `src/bpf/intf.h` | Shared type definitions (`cpu_arg`, `domain_arg`, time constants) |
| Userspace daemon | Rust | `src/main.rs` | Topology discovery, domain initialization, cpufreq policy, power profile adaptation, stats server |
| Statistics | Rust | `src/stats.rs` | Metrics collection and monitoring (`Metrics` struct, stats server) |

### DSQ (Dispatch Queue) Hierarchy

The scheduler creates a three-level DSQ hierarchy:

1. **Per-CPU DSQs** -- `cpu_to_dsq(cpu)` returns `(u64)cpu`. Used to keep awakened tasks sticky to their previous CPU when the CPU is not saturated.
2. **Per-node DSQs** -- `node_to_dsq(node)` returns `DSQ_FLAG_NODE | node` (bit 32 set, ORed with node id). Used when a CPU is busy and the task should be available for migration within the NUMA node.
3. **`SCX_DSQ_LOCAL` / `SCX_DSQ_LOCAL_ON`** -- The kernel's built-in per-CPU local DSQs, used for direct dispatch.

### Per-Task State (`task_ctx`)

Stored in `BPF_MAP_TYPE_TASK_STORAGE`, each task carries:

| Field | Type | Purpose |
|-------|------|---------|
| `cpumask` | `bpf_cpumask __kptr` | Task's primary scheduling domain cpumask |
| `l2_cpumask` | `bpf_cpumask __kptr` | L2 cache domain intersection with task's allowed CPUs |
| `l3_cpumask` | `bpf_cpumask __kptr` | L3/LLC cache domain intersection |
| `exec_runtime` | `u64` | Accumulated execution time since last sleep (capped at `run_lag`) |
| `last_run_at` | `u64` | Timestamp when the task last started running |
| `avg_nvcsw` | `u64` | EWMA of voluntary context switch rate |
| `last_sleep_at` | `u64` | Timestamp of last sleep event |
| `recent_used_cpu` | `s32` | Last CPU used; triggers domain refresh on change |
| `waker_pid` | `u32` | PID of the most recent waker (used for sync wakeup decisions) |

### Per-CPU State (`cpu_ctx`)

Stored in `BPF_MAP_TYPE_PERCPU_ARRAY`:

| Field | Type | Purpose |
|-------|------|---------|
| `tot_runtime` | `u64` | Cumulative runtime on this CPU |
| `prev_runtime` | `u64` | Runtime snapshot at last measurement |
| `last_running` | `u64` | Timestamp of last measurement |
| `perf_lvl` | `u64` | Smoothed CPU utilization in `[0, SCX_CPUPERF_ONE]` |
| `smt_cpumask` | `bpf_cpumask __kptr` | SMT sibling mask |
| `l2_cpumask` | `bpf_cpumask __kptr` | L2 cache sibling mask |
| `l3_cpumask` | `bpf_cpumask __kptr` | L3/LLC cache sibling mask |

### Per-Node State (`node_ctx`)

Stored in a `BPF_MAP_TYPE_ARRAY` with `MAX_NUMA_NODES` (1024) entries:

| Field | Type | Purpose |
|-------|------|---------|
| `tot_perf_lvl` | `u64` | Accumulated perf levels across node CPUs (reset each timer tick) |
| `nr_cpus` | `u64` | Number of online CPUs in this node |
| `perf_lvl` | `u64` | Average utilization of the node |
| `need_rebalance` | `bool` | True if node is >= 50% utilized and idle nodes exist |

## EDF Algorithm

### Deadline Computation

The effective deadline of a task is its `dsq_vtime`, which the kernel uses to order tasks in vtime-sorted DSQs (`scx_bpf_dsq_insert_vtime`). The deadline is computed in `update_task_deadline()` as follows:

```
deadline = vruntime + exec_vruntime
```

Where:
- **`vruntime`** is the task's total accumulated runtime, inversely scaled by its normalized weight. This drives **fairness**: tasks that have consumed more CPU time have larger vruntimes and thus later deadlines.
- **`exec_vruntime`** is the runtime accumulated since the task last slept, also inversely scaled by weight. This drives **latency sensitivity**: tasks that sleep frequently reset `exec_runtime` to zero on wakeup (in `flash_runnable`), resulting in smaller `exec_vruntime` contributions and earlier deadlines.

### Vruntime Update Steps

1. **Sleep credit cap** (in `update_task_deadline()`): The task's `dsq_vtime` is clamped so it cannot fall more than `max_sleep` behind `vtime_now`:
   ```c
   max_sleep = scale_by_task_normalized_weight(p, slice_lag * lag_scale);
   vtime_min = vtime_now > max_sleep ? vtime_now - max_sleep : 0;
   if (time_before(p->scx.dsq_vtime, vtime_min))
       p->scx.dsq_vtime = vtime_min;
   ```

2. **Execution vruntime addition** (in `update_task_deadline()`):
   ```c
   p->scx.dsq_vtime += scale_by_task_normalized_weight_inverse(p, tctx->exec_runtime);
   ```

3. **Runtime vruntime addition** (in `flash_stopping()`): Each time a task stops running, the actual slice consumed is added to `dsq_vtime`:
   ```c
   p->scx.dsq_vtime += scale_by_task_normalized_weight_inverse(p, slice);
   ```

4. **Execution runtime accumulation** (in `flash_stopping()`): The task's `exec_runtime` accumulates actual run time, capped at `run_lag` (default 32768 us) to prevent excessive de-prioritization:
   ```c
   tctx->exec_runtime = MIN(tctx->exec_runtime + slice, run_lag);
   ```

5. **Global vruntime advance** (in `flash_running()`): `vtime_now` is advanced to track the maximum observed `dsq_vtime`:
   ```c
   if (time_before(vtime_now, p->scx.dsq_vtime))
       vtime_now = p->scx.dsq_vtime;
   ```

6. **Wakeup reset** (in `flash_runnable()`): When a task wakes up, `exec_runtime` is reset to zero and `waker_pid` is recorded:
   ```c
   tctx->exec_runtime = 0;
   tctx->waker_pid = current->pid;
   ```

### Round-Robin Mode

When `--rr-sched` / `rr_sched` is enabled, the EDF logic is entirely bypassed. Tasks get a fixed time slice and are dispatched in FIFO order via `SCX_DSQ_LOCAL`. The `update_task_deadline()` function returns immediately, and vruntime accounting in `flash_stopping()` and `flash_running()` is skipped.

## Scheduling Hot Path (BPF Callbacks)

The scheduler registers these `sched_ext` operations via `SCX_OPS_DEFINE(flash_ops, ...)`:

### `flash_select_cpu` (ops.select_cpu)

Called when a task is woken up. Finds an idle CPU via `pick_idle_cpu()`. If an idle CPU is found and `can_direct_dispatch()` returns true (no tasks waiting in DSQs, or `direct_dispatch` mode is on), the task is **directly dispatched** to `SCX_DSQ_LOCAL` with `scx_bpf_dsq_insert()`, bypassing `ops.enqueue()` entirely. Returns the chosen CPU regardless.

If the system is throttled (`is_throttled()`), it immediately returns `prev_cpu` without any dispatch.

### `flash_enqueue` (ops.enqueue)

Called for tasks not directly dispatched in `select_cpu`. The logic proceeds as:

1. In round-robin mode, delegates to `rr_enqueue()`.
2. Otherwise, calls `update_task_deadline()` to refresh the task's vruntime (unless re-enqueued due to `SCX_ENQ_REENQ`).
3. Attempts `try_direct_dispatch()` which handles:
   - Per-CPU kthread direct dispatch (if `local_kthreads` is set)
   - Re-checking for idle CPUs not found in `select_cpu` (e.g., remote wakeups that skip `select_cpu`)
   - Per-CPU task (pinned) direct dispatch when their CPU is idle
4. If direct dispatch fails, inserts the task into a **vtime-ordered DSQ**:
   - **Per-CPU DSQ** (`cpu_to_dsq(prev_cpu)`) if the CPU is not busy (checked via `can_enqueue_to_cpu` / `is_cpu_busy`)
   - **Per-node DSQ** (`node_to_dsq(node)`) otherwise, allowing migration
5. After enqueuing to the per-node DSQ, proactively kicks an idle CPU via `kick_idle_cpu()` so it can pull the task.

### `flash_dispatch` (ops.dispatch)

Called when a CPU needs work. The consumption order is:

1. Per-CPU DSQ: `scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu))`
2. Per-node DSQ: `scx_bpf_dsq_move_to_local(node_to_dsq(node))`
3. If neither has tasks and the previous task (`prev`) still wants to run (`keep_running()` returns true), its time slice is replenished in-place via `prev->scx.slice = task_slice(prev, cpu)`.

The `keep_running()` function prevents a task from continuing if:
- It is no longer queued
- Its CPU is outside the primary domain (and it can use the primary domain)
- SMT is enabled and the task is not on a full-idle core (and full-idle cores exist elsewhere)

### `flash_running` (ops.running)

Called when a task starts executing. Increments `nr_running`, records `last_run_at`, calls `update_cpu_load()` for cpufreq scaling, and advances `vtime_now`.

### `flash_stopping` (ops.stopping)

Called when a task stops running. Decrements `nr_running`, computes the actual slice used, accumulates `exec_runtime` (capped at `run_lag`), updates the task's `dsq_vtime`, and updates `cpu_ctx.tot_runtime`.

### `flash_runnable` (ops.runnable)

Called when a task becomes runnable (wakes up). Resets `exec_runtime` to zero and records the waker's PID. This is what gives sleeping tasks their latency advantage: their `exec_runtime` starts from zero, so `update_task_deadline()` will produce an earlier deadline.

### `flash_quiescent` (ops.quiescent)

Called when a task goes to sleep (`SCX_DEQ_SLEEP`). Updates the task's voluntary context switch rate (`avg_nvcsw`) using an EWMA:
```c
nvcsw = slice_max / delta_t;
tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, nvcsw, 0, max_avg_nvcsw);
```
A task that sleeps more frequently (smaller `delta_t` between sleeps) gets a higher `avg_nvcsw`, which translates into a larger `lag_scale` in `update_task_deadline()`, granting it more vruntime credit.

### `flash_cpu_release` (ops.cpu_release)

When a CPU is taken by a higher-priority scheduling class, calls `scx_bpf_reenqueue_local()` to re-enqueue all tasks from the local DSQ so they can migrate to other CPUs.

### `flash_set_cpumask` (ops.set_cpumask)

Called when a task's CPU affinity changes. Refreshes the task's scheduling domain via `task_update_domain()`.

### `flash_enable` (ops.enable)

Called when a task is first managed by the scheduler. Initializes `dsq_vtime` to `vtime_now`.

### `flash_init_task` (ops.init_task)

Allocates and initializes the task's per-task storage (`task_ctx`), creating three cpumasks (primary, L2, L3) and setting the initial scheduling domain.

### `flash_init` (ops.init)

Scheduler initialization:
1. Records `nr_online_cpus` and `nr_cpu_ids`
2. Initializes cpufreq targets and per-node CPU counts via `init_cpuperf_target()`
3. Creates per-CPU DSQs (one per CPU, NUMA-aware)
4. Creates per-node DSQs
5. Initializes the primary cpumask
6. Optionally arms three BPF timers: tickless timer, throttle timer, NUMA timer

### `flash_exit` (ops.exit)

Records exit information via `UEI_RECORD`.

## Latency Weights

The latency weight system is the core mechanism that distinguishes interactive from CPU-bound tasks. It operates through two interacting metrics:

### Voluntary Context Switch Rate (`avg_nvcsw`)

Tracked per-task via EWMA in `flash_quiescent()`. The rate is computed as:
```c
nvcsw = slice_max / delta_t
```
where `delta_t` is the time between consecutive sleep events. This means:
- A task sleeping every 1ms with `slice_max = 4096us`: `nvcsw = 4096/1000 = ~4`
- A task sleeping every 100us: `nvcsw = 4096/100 = ~40`

The rate is clamped to `[0, max_avg_nvcsw]` (default 128). Setting `max_avg_nvcsw = 0` disables this mechanism entirely.

### Lag Scale Factor

In `update_task_deadline()`, the `lag_scale` is computed as:
```c
lag_scale = max_avg_nvcsw ? log2_u64(MAX(tctx->avg_nvcsw, 2)) : 1;
```
This logarithmic scaling means:
- `avg_nvcsw = 2`: `lag_scale = 1`
- `avg_nvcsw = 8`: `lag_scale = 3`
- `avg_nvcsw = 64`: `lag_scale = 6`
- `avg_nvcsw = 128`: `lag_scale = 7`

The `lag_scale` multiplies `slice_lag` to determine the maximum vruntime credit:
```c
max_sleep = scale_by_task_normalized_weight(p, slice_lag * lag_scale);
```
Tasks with higher voluntary context switch rates get larger sleep credit, resulting in earlier deadlines and higher priority.

### Dynamic Fairness (`--slice-lag-scaling`)

When enabled, the `lag_scale` is further modulated by global CPU utilization:
```c
lag_scale = lag_scale * cpu_util / SCX_CPUPERF_ONE;
```
- **Low CPU utilization**: `cpu_util` is small, so `lag_scale` shrinks. This reduces the influence of `vruntime` and lets `exec_vruntime` dominate, favoring bursty message-passing workloads.
- **High CPU utilization**: `lag_scale` grows, restoring full vruntime fairness to keep the system responsive under load.

The `cpu_util` value is computed in userspace by reading `/proc/stat` and normalized to `[0, SCX_CPUPERF_ONE]` (1024).

## Weight Normalization

By default, scx_flash **normalizes** task weights (nice values / priorities) into a compressed range to prevent starvation:

| Property | Original Range | Normalized Range |
|----------|---------------|-----------------|
| Weight | [1, 10000] | [1, 128] |
| Default | 100 | 64 |

The normalization formula is:
```c
normalized_weight = 1 + (127 * log2_u64(weight) / log2_u64(10000))
```

This logarithmic compression ensures that large priority gaps (e.g., nice -20 vs nice 19) do not cause starvation. The `--native-priority` / `-n` flag disables normalization and uses raw Linux weights.

Weight affects scheduling in two places:
- **`scale_by_task_normalized_weight(p, value)`**: Scales `value` proportionally to weight. Used for sleep credit (`max_sleep`): higher-weight tasks get more credit.
- **`scale_by_task_normalized_weight_inverse(p, value)`**: Scales `value` inversely proportional to weight. Used for vruntime accounting: higher-weight tasks accumulate vruntime more slowly, getting earlier deadlines.

## Time Slice Computation

The function `task_slice()` dynamically computes each task's time slice:

```c
u64 nr_wait = nr_tasks_waiting(cpu);
u64 smax = native_priority ? scale_by_task_weight(p, slice_max) : slice_max;

if (!nr_wait)
    return tickless_sched ? SCX_SLICE_INF : smax;

return MAX(smax / nr_wait, slice_min);
```

Key behaviors:
- **No contention**: Task gets `slice_max` (default 4096 us), or `SCX_SLICE_INF` in tickless mode.
- **Under contention**: Slice is divided by the number of waiting tasks, but never below `slice_min` (default 128 us).
- **With `--native-priority`**: `slice_max` is additionally scaled by the task's raw weight.

The `nr_tasks_waiting()` function sums tasks across three DSQs: `SCX_DSQ_LOCAL_ON | cpu`, `cpu_to_dsq(cpu)`, and `node_to_dsq(node)`.

## Topology Awareness

### SMT (Simultaneous Multi-Threading)

When SMT is detected (and not disabled via `--disable-smt`), the scheduler:

1. **Prefers full-idle cores**: The idle CPU selection in `pick_idle_cpu()` first searches for CPUs where the entire physical core is idle (`SCX_PICK_IDLE_CORE` flag), progressing from L2 -> L3 -> primary domain -> all allowed CPUs.
2. **Avoids SMT contention in `keep_running()`**: A running task migrates away from its CPU if its SMT core has a busy sibling and full-idle cores exist elsewhere.
3. **Initializes per-CPU SMT masks** via `init_smt_domains()` using the topology's `sibling_cpus()`.

### L2 Cache Domains

Initialized via `init_l2_cache_domains()`. The scheduler builds per-CPU L2 cpumasks by discovering which CPUs share the same `l2_id` from the topology. Domains containing only a single CPU or only SMT siblings of the same core are skipped (they provide no useful migration targets).

### L3 / LLC Cache Domains

Initialized via `init_l3_cache_domains()`, following the same pattern as L2 but using `llc_id`. The L3 mask is also used by `is_llc_busy()` to determine if the entire LLC is saturated and by `cpus_share_llc()` for sync wakeup decisions.

### NUMA Awareness

For multi-node systems (more than one non-empty NUMA node), the scheduler:

1. Creates **per-node DSQs** for cross-CPU task migration within a node.
2. Runs a **NUMA timer** (`numa_timerfn`) firing every 1 second that:
   - Computes average utilization per node from per-CPU `perf_lvl` values.
   - Identifies "idle nodes" (utilization <= 25% of `SCX_CPUPERF_ONE`).
   - Marks busy nodes (utilization >= 50%) for rebalancing if idle nodes exist.
3. When `node_rebalance()` returns true for a node, the idle CPU search in `pick_idle_cpu()` drops the `SCX_PICK_IDLE_IN_NODE` flag, allowing cross-node migration.

NUMA awareness is automatically disabled on single-node systems or via `--disable-numa`. When disabled, all idle CPU queries use the global (non-node-scoped) `scx_bpf_get_idle_cpumask()` and `scx_bpf_pick_idle_cpu()`.

### Idle CPU Selection Strategy

The `pick_idle_cpu()` function implements a multi-tier search with the following priority order:

1. **Sync wakeup handling**: If the waker is releasing its CPU, try to place the wakee there (considering LLC sharing and pipeline detection via `waker_pid`).
2. **SMT full-idle core search** (if SMT enabled):
   - Previous CPU (if full-idle and allowed)
   - L2 domain (in-node)
   - L3 domain (in-node)
   - Primary domain (in-node, or cross-node if rebalancing)
   - All allowed CPUs
3. **Non-SMT / any-idle fallback**:
   - Previous CPU (if idle and allowed)
   - L2 domain (if not rebalancing)
   - L3 domain (if not rebalancing)
   - Primary domain
   - All allowed CPUs
4. **Default**: Return `prev_cpu` if nothing idle was found.

## Primary Scheduling Domain

The primary domain defines the preferred set of CPUs for task dispatch. Tasks are initially placed on primary domain CPUs; when the system saturates, tasks overflow to non-primary CPUs.

The domain is configured via `--primary-domain` / `-m` with these options:

| Value | Behavior |
|-------|----------|
| `auto` (default) | Selects based on the system's active power profile (`PowerProfile`) |
| `turbo` | Only CPUs with `CoreType::Big { turbo: true }` |
| `performance` | All `CoreType::Big` CPUs |
| `powersave` | Only `CoreType::Little` CPUs |
| `all` | All CPUs (effectively disables domain restriction) |
| `none` | No CPUs in primary domain |
| hex bitmask | Explicit CPU mask (e.g., `0xff`) |

When `primary_all` is true (domain covers all CPUs), the task's `cpus_ptr` is used directly as the scheduling mask, avoiding cpumask intersection operations.

The scheduler monitors the system's power profile at runtime (`refresh_sched_domain()`). If the profile changes (e.g., switching from AC to battery), and `--primary-domain auto` is set, the scheduler **restarts itself** to reconfigure the primary domain.

## CPU Frequency Scaling

The scheduler integrates with the kernel's cpufreq subsystem via `scx_bpf_cpuperf_set()`.

### Dynamic Scaling (--cpufreq)

When enabled (`cpufreq_perf_lvl < 0`), `update_cpu_load()` in `flash_running()` computes per-CPU utilization:

```c
delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
cctx->perf_lvl = calc_avg(perf_lvl, cctx->perf_lvl);  // EWMA smoothing
```

Then applies hysteresis:
- **Above `CPUFREQ_HIGH_THRESH`** (75% of `SCX_CPUPERF_ONE`): Set to max (`SCX_CPUPERF_ONE`)
- **Below `CPUFREQ_LOW_THRESH`** (25% of `SCX_CPUPERF_ONE`): Set to half capacity
- **Between thresholds**: Use the smoothed `perf_lvl`

### Static Scaling

Without `--cpufreq`:
- `powersave` domain: Sets `cpufreq_perf_lvl = 0` (minimum frequency)
- All other domains: Sets `cpufreq_perf_lvl = 1024` (maximum frequency)

## CPU Busy Detection

The `is_cpu_busy()` function determines whether a CPU is saturated. This affects whether tasks enqueue to the per-CPU DSQ (sticky) or the per-node DSQ (migratable).

The busy threshold is either:
- **Fixed** (`--cpu-busy-thresh >= 0`): Normalized to `[0, 1024]` from the user-specified percentage.
- **Dynamic** (`--cpu-busy-thresh = -1`, the default): Computed as `SCX_CPUPERF_ONE - cpu_util`, where `cpu_util` is the global user-mode CPU utilization. Under high system load, the threshold drops, making CPUs appear busy sooner and encouraging task migration for better work conservation. Under low load, the threshold rises, encouraging cache locality.

A CPU is only considered busy if there are tasks waiting in its DSQs **and** its smoothed `perf_lvl` exceeds the threshold.

## CPU Throttling

The `--throttle-us` option enables duty-cycle throttling to reduce power consumption. When enabled:

1. A `throttle_timer` fires periodically, alternating between two states:
   - **Running phase** (duration `slice_max`): Normal operation.
   - **Throttled phase** (duration `throttle_ns`): All CPUs are forced idle. `is_throttled()` returns true, causing `flash_select_cpu` to skip idle search, `flash_dispatch` to return without consuming DSQs, and `try_direct_dispatch` to skip.
2. State transitions use IPIs: `SCX_KICK_PREEMPT` to enter throttled state, `SCX_KICK_IDLE` to resume.
3. Per-CPU kthread direct dispatch is implicitly enabled during throttling (`local_kthreads` is forced on) to prevent critical kernel threads from being delayed.

## Tickless Mode

The `--tickless` / `-T` flag enables tickless scheduling:

1. Tasks receive `SCX_SLICE_INF` (infinite time slice) when no other tasks are waiting.
2. A `tickless_timer` fires every `tick_interval_ns()` (= `NSEC_PER_SEC / CONFIG_HZ`), scanning all CPUs. If a CPU has tasks waiting and the current task has `SCX_SLICE_INF`, the timer sets the slice to `slice_min` to trigger preemption.

This reduces OS scheduling noise and improves performance isolation for workloads that benefit from uninterrupted execution.

## Userspace Side

### Initialization (`Scheduler::init`)

The Rust userspace performs:

1. **Topology discovery** via `scx_utils::Topology` to detect SMT, L2/L3 cache domains, NUMA nodes, and core types (Big/Little/Turbo).
2. **Primary domain resolution** via `resolve_energy_domain()`, mapping string configuration to a `Cpumask`.
3. **BPF skeleton setup**: Opens the BPF skeleton, populates `rodata` with configuration constants (slice parameters, flags, thresholds), and sets scheduler flags (`SCX_OPS_ENQ_EXITING`, `SCX_OPS_ENQ_LAST`, `SCX_OPS_ENQ_MIGRATION_DISABLED`, `SCX_OPS_ALLOW_QUEUED_WAKEUP`, optionally `SCX_OPS_BUILTIN_IDLE_PER_NODE`).
4. **Domain initialization**: Calls BPF syscall programs (`enable_primary_cpu`, `enable_sibling_cpu`) to populate cpumasks in BPF maps.
5. **CPU idle QoS**: If `--idle-resume-us` is non-negative, sets per-CPU idle resume latency via sysfs to control how deep CPUs can sleep.
6. **Attach and launch** the stats server.

### Main Loop (`Scheduler::run`)

The main loop runs at ~1 Hz and:

1. Checks for power profile changes (`refresh_sched_domain()`). If the profile changed and `--primary-domain auto` is set, triggers a scheduler restart.
2. Updates `cpu_util` from `/proc/stat` (user+nice CPU time as a fraction of total, normalized to `[0, 1024]`). This is fed back to BPF for dynamic busy threshold and dynamic fairness calculations.
3. Serves stats requests from the stats server channel.

### Statistics (`Metrics`)

The `Metrics` struct tracks five counters:

| Metric | Description |
|--------|-------------|
| `nr_running` | Current number of running tasks |
| `nr_cpus` | Number of online CPUs |
| `nr_kthread_dispatches` | Cumulative kthread direct dispatches |
| `nr_direct_dispatches` | Cumulative task direct dispatches (idle CPU found) |
| `nr_shared_dispatches` | Cumulative dispatches to per-CPU or per-node DSQs |

Stats can be viewed via `--stats <interval>` (alongside the scheduler) or `--monitor <interval>` (standalone monitoring mode).

## Configuration Reference

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--slice-us` | `-s` | 4096 | Maximum time slice (microseconds) |
| `--slice-us-min` | `-S` | 128 | Minimum time slice (microseconds) |
| `--slice-us-lag` | `-l` | 4096 | Maximum sleep vruntime credit (microseconds) |
| `--slice-lag-scaling` | `-L` | false | Dynamic fairness based on CPU utilization |
| `--run-us-lag` | `-r` | 32768 | Maximum execution runtime penalty (microseconds) |
| `--max-avg-nvcsw` | `-c` | 128 | Cap on voluntary context switch rate (0 = disable) |
| `--cpu-busy-thresh` | `-C` | -1 | CPU busy utilization % (-1 = auto) |
| `--throttle-us` | `-t` | 0 | Idle injection per cycle (0 = disable) |
| `--idle-resume-us` | `-I` | 32 | CPU idle QoS resume latency (-1 = disabled) |
| `--tickless` | `-T` | false | Infinite time slice with timer-based preemption |
| `--rr-sched` | `-R` | false | Round-robin mode (disables EDF) |
| `--no-builtin-idle` | `-b` | false | Disable kernel built-in idle selection |
| `--local-pcpu` | `-p` | false | Prioritize per-CPU (pinned) tasks |
| `--direct-dispatch` | `-D` | false | Always direct-dispatch to idle CPUs |
| `--sticky-cpu` | `-y` | false | Prefer keeping tasks on same CPU |
| `--native-priority` | `-n` | false | Use raw Linux priority range |
| `--local-kthreads` | `-k` | false | Direct-dispatch per-CPU kthreads |
| `--no-wake-sync` | `-w` | false | Disable sync wakeup optimization |
| `--primary-domain` | `-m` | auto | Primary CPU domain (auto/turbo/performance/powersave/all/hex) |
| `--disable-l2` | | false | Disable L2 cache awareness |
| `--disable-l3` | | false | Disable L3/LLC cache awareness |
| `--disable-smt` | | false | Disable SMT awareness |
| `--disable-numa` | | false | Disable NUMA rebalancing |
| `--cpufreq` | `-f` | false | Enable dynamic CPU frequency scaling |

## BPF Timers

The scheduler uses up to three BPF timers, all stored in single-entry `BPF_MAP_TYPE_ARRAY` maps:

| Timer | Fires Every | Purpose |
|-------|------------|---------|
| `tickless_timer` | `NSEC_PER_SEC / CONFIG_HZ` | Preempts tasks with infinite slices when contention exists |
| `throttle_timer` | Alternates `slice_max` / `throttle_ns` | Duty-cycle CPU throttling for power savings |
| `numa_timer` | 1 second | Updates per-node utilization and rebalance flags |

## EWMA Smoothing

The scheduler uses exponential weighted moving averages throughout, implemented as:

```c
static u64 calc_avg(u64 old_val, u64 new_val) {
    return (old_val - (old_val >> 2)) + (new_val >> 2);
}
```

This computes `new_avg = 0.75 * old_val + 0.25 * new_val`, giving 75% weight to the existing average and 25% to the new sample. It is used for:
- Per-CPU `perf_lvl` (utilization smoothing)
- Per-task `avg_nvcsw` (voluntary context switch rate)

The `calc_avg_clamp()` variant additionally clamps the result to a specified range.
