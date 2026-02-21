# scx_beerland
Generated: 2026-02-21, git-depth 7778

## Overview

scx_beerland (**B**PF-**E**nhanced **E**xecution **R**untime **L**ocality-**A**ware **N**on-blocking **D**ispatcher) is a sched_ext scheduler designed to prioritize cache locality and scalability. It targets cache-intensive workloads on systems with large CPU counts and is considered production-ready.

The core design principle is **per-CPU dispatch queues (DSQs)**: each CPU has its own deadline-ordered DSQ. Tasks are given migration opportunities primarily at wakeup time when the system is not saturated. Under saturation, CPUs pull tasks from remote DSQs, always selecting the task with the smallest deadline (earliest virtual deadline first). This approach minimizes cross-CPU lock contention while still enabling work-stealing when needed.

## Architecture / Design

### DSQ Layout

At initialization (`beerland_init`), the scheduler creates one DSQ per CPU using `scx_bpf_create_dsq(cpu, node)`, where the NUMA node is determined by `__COMPAT_scx_bpf_cpu_node(cpu)`. This gives each CPU its own vtime-ordered queue, avoiding a single global lock bottleneck.

### Primary Domain

The scheduler supports a **primary domain** -- a subset of CPUs that are prioritized for task placement. This is configured via the `--primary_domain` (`-m`) CLI option, which accepts:

| Keyword         | Meaning                                                   |
|-----------------|-----------------------------------------------------------|
| `"all"`         | All CPUs belong to the primary domain (default)           |
| `"turbo"`       | CPUs with `CoreType::Big { turbo: true }`                 |
| `"performance"` | All big CPUs (turbo or not)                               |
| `"powersave"`   | All little CPUs                                           |
| `"0-3,12-15"`   | Explicit CPU list/ranges                                  |

When the primary domain includes all CPUs, the BPF global `primary_all` is set to `true` and primary-domain filtering is skipped entirely. Otherwise, the userspace side calls the BPF syscall program `enable_primary_cpu` for each CPU in the domain, populating the `primary_cpumask` BPF kptr cpumask.

### Preferred Idle CPU Scanning

When `--preferred_idle_scan` (`-P`) is enabled, the scheduler uses a custom idle-CPU scan that walks CPUs in descending order of capacity (stored in the `preferred_cpus[]` array, sorted at init time). This prioritizes higher-performance cores. Without this flag, the scheduler delegates to the kernel's `scx_bpf_select_cpu_and()` or the legacy `scx_bpf_select_cpu_dfl()` API.

### SMT Awareness

On SMT-enabled systems, the scheduler tracks SMT sibling relationships. During initialization, userspace calls `enable_sibling_cpu` for each CPU pair, populating a per-CPU `cpu_ctx.smt` cpumask. The BPF side uses this to:

- Detect **SMT contention** via `is_smt_contended()`: returns `true` when the sibling CPU is busy and there are other fully-idle SMT cores available.
- Prefer **full-idle SMT cores** when scanning for idle CPUs (via `scx_bpf_get_idle_smtmask()`).

### CPU Utilization Monitoring

The userspace main loop periodically reads `/proc/stat` to compute user CPU utilization as a fraction of total CPU time. This value is written to the BPF global `cpu_util` (scaled to [0..1024]). The BPF function `is_system_busy()` compares `cpu_util` against `busy_threshold` (derived from the `--cpu_busy_thresh` option, default 75%, also scaled to [0..1024]).

The polling interval is controlled by `--polling_ms` (default 250ms, clamped to [10..1000]).

### Virtual Runtime and Deadline Computation

The scheduler uses a **virtual runtime (vruntime)** model similar to CFS, combined with a **deadline** derived from the vruntime. Key globals:

- **`vtime_now`**: The system-wide vruntime watermark. Updated in `beerland_running()` whenever a task starts executing -- if the task's `dsq_vtime` is ahead of `vtime_now`, the global is advanced.
- **`slice_ns`**: Default time slice (default 1ms, configurable via `--slice_us`).
- **`slice_lag`**: Maximum vruntime credit a sleeping task can accumulate (default 40ms, configurable via `--slice_us_lag`).

**Deadline calculation** (`task_dl()`):

```
lag_scale = max(wakeup_freq, 1)
vtime_min = vtime_now - scale_by_task_weight(slice_lag * lag_scale)
awake_max = scale_by_task_weight_inverse(slice_lag)

// Clamp dsq_vtime so the task can't accumulate unbounded credit
if dsq_vtime < vtime_min:
    dsq_vtime = vtime_min

// Clamp awake_vtime to prevent penalty from growing unboundedly
if awake_vtime > awake_max:
    awake_vtime = awake_max

deadline = dsq_vtime + awake_vtime
```

This means:
- **Frequently waking tasks** get more vruntime credit (higher `lag_scale`), giving them a lower (earlier) deadline, which boosts interactive responsiveness.
- **Continuously running tasks** accumulate `awake_vtime` (added in `beerland_stopping()`), which pushes their deadline later, preventing starvation of other tasks even if `wakeup_freq` never updates.
- All scaling respects task weight (nice/priority) via `scale_by_task_weight()` and its inverse.

### Per-Task Context (`task_ctx`)

Each task has BPF task-local storage with the following fields:

| Field           | Type | Purpose                                                      |
|-----------------|------|--------------------------------------------------------------|
| `last_run_at`   | u64  | Timestamp when the task last started running                 |
| `last_woke_at`  | u64  | Timestamp of the task's last wakeup                          |
| `wakeup_freq`   | u64  | EWMA of wakeup frequency (higher = more interactive)         |
| `awake_vtime`   | u64  | Accumulated virtual runtime since last sleep                 |
| `avg_runtime`   | u64  | EWMA of actual runtime per scheduling cycle                  |

### Sticky Tasks

Tasks with `avg_runtime < 10us` are considered **sticky** (`is_task_sticky()`). In `beerland_enqueue()`, sticky tasks are unconditionally dispatched to `SCX_DSQ_LOCAL` (the current CPU's local queue) without attempting migration. This avoids migration overhead for very short-lived scheduling bursts.

### EWMA (Exponential Weighted Moving Average)

The function `calc_avg(old, new)` computes:

```
new_avg = (old * 0.75) + (new * 0.25)
```

This is used for both `avg_runtime` and `wakeup_freq` tracking.

The wakeup frequency is computed by `update_freq()` as:

```
new_freq = (100 * NSEC_PER_MSEC) / interval_since_last_wakeup
freq = calc_avg(old_freq, new_freq)
freq = min(freq, MAX_WAKEUP_FREQ)  // capped at 64
```

## Scheduling Hot Path (BPF Callbacks)

The scheduler registers the following `sched_ext` operations:

### `beerland_select_cpu` -- Task Wakeup CPU Selection

Called on task wakeup. This is the primary migration opportunity.

1. **Waker-to-wakee affinity**: If the waker's CPU (`this_cpu`) is faster than the wakee's previous CPU (`prev_cpu`) and the task is allowed to run on `this_cpu`, the scheduler attempts to migrate the wakee closer to the waker. However, if `prev_cpu` is in the same LLC, its SMT core is not contended, and it's idle, the task stays on `prev_cpu`.

2. **Idle CPU search**: Calls `pick_idle_cpu()` which delegates to either:
   - `pick_idle_cpu_scan()` (preferred idle scan mode) -- walks `preferred_cpus[]` in descending capacity order, trying in order:
     1. Full-idle SMT core in the primary domain
     2. Any idle CPU in the primary domain
     3. Full-idle SMT core anywhere
     4. Any idle CPU anywhere
   - `scx_bpf_select_cpu_and()` (default mode) -- kernel's built-in idle CPU selection, first restricted to the primary domain mask, then falling back to all CPUs.

3. **Direct dispatch optimization**: When an idle CPU is found, or when the system is not busy, `do_direct_dispatch()` is called, which dispatches the task directly:
   - To `SCX_DSQ_LOCAL` if there is no task waiting on the target CPU's DSQ, or the waiting task has a later deadline.
   - To the CPU's per-CPU DSQ (vtime-ordered) otherwise.

4. **Busy system fallback**: If no idle CPU is found AND the system is busy, the function returns `prev_cpu` without dispatching, deferring to `beerland_enqueue()`.

### `beerland_enqueue` -- Task Queuing

Called when a task's time slice expires or when `select_cpu` did not dispatch the task.

1. **Sticky tasks**: Dispatched directly to `SCX_DSQ_LOCAL` without migration attempts.

2. **Migration attempt** (via `try_migrate()`): Triggered when:
   - `select_cpu()` was skipped and the task is not currently running, OR
   - The previous CPU's DSQ already has queued tasks, OR
   - The previous CPU's SMT core is contended.

   If migration is attempted and an idle CPU is found, the task is dispatched to `SCX_DSQ_LOCAL_ON | cpu` with a kick to wake the idle CPU. If the idle CPU already has a waiting task with an earlier vruntime, the task falls through to local dispatch instead.

3. **Local dispatch fallback**: If no migration occurs, the task is dispatched to `prev_cpu`:
   - To `SCX_DSQ_LOCAL_ON | prev_cpu` if no task is currently running on that CPU.
   - To the per-CPU DSQ with vtime ordering (`scx_bpf_dsq_insert_vtime`) otherwise.

4. If `select_cpu()` was not called, the target CPU is kicked to ensure it processes the new task.

### `beerland_dispatch` -- CPU Dispatch

Called when a CPU needs work. Three-tier dispatch strategy:

1. **System busy -- immediate rebalance**: If `is_system_busy()`, attempt `dispatch_from_any_cpu()` first. This scans all per-CPU DSQs, finds the task with the lowest vruntime that is allowed to run on the current CPU, and moves it locally. Counted as `nr_remote_dispatch`.

2. **Local DSQ consumption**: Try `scx_bpf_dsq_move_to_local(cpu)` to consume from the CPU's own DSQ. Counted as `nr_local_dispatch`.

3. **Remote DSQ consumption**: If the local DSQ is empty, attempt `dispatch_from_any_cpu()` to steal work. Counted as `nr_remote_dispatch`.

4. **Keep running**: If no tasks were found anywhere and the previous task (`prev`) still wants to run (checked by `keep_running()`), refill its time slice and let it continue. Counted as `nr_keep_running`. The `keep_running()` check ensures the task is still queued and, if a primary domain is defined, that the CPU belongs to the primary domain (or the task can't use primary CPUs).

### `beerland_runnable` -- Task Becomes Runnable

Called when a task wakes up. Resets `awake_vtime` to 0 and updates the task's `wakeup_freq` using EWMA based on the interval since the last wakeup.

### `beerland_running` -- Task Starts Running

Records `last_run_at` timestamp. Advances the global `vtime_now` if the task's `dsq_vtime` is ahead.

### `beerland_stopping` -- Task Stops Running

Computes the actual runtime slice, updates `avg_runtime` via EWMA, and charges the task's vruntime:

```
vslice = scale_by_task_weight_inverse(p, actual_runtime)
p->scx.dsq_vtime += vslice
tctx->awake_vtime += vslice
```

Higher-priority tasks (higher weight) accumulate vruntime more slowly, giving them proportionally more CPU time.

### `beerland_enable` -- Task Joins Scheduler

Initializes the task's `dsq_vtime` to `vtime_now` so it starts at the current system-wide vruntime watermark.

### `beerland_init_task` -- Task Storage Allocation

Creates the per-task `task_ctx` in BPF task-local storage.

## Key Mechanisms

### Work Stealing (`dispatch_from_any_cpu`)

When a CPU has no local work, it scans all per-CPU DSQs (up to `nr_cpu_ids`) to find the task with the globally lowest `dsq_vtime` that is allowed to run on the requesting CPU. This ensures fairness across the system while maintaining per-CPU queue isolation during normal operation.

Note: The comment in the source mentions "restricting rebalancing to the LLC" for cache locality and reduced lock contention, but the implementation currently scans all CPUs (not just LLC-local ones).

### Time Slice Scaling

Time slices are scaled by task weight via `task_slice()` -> `scale_by_task_weight(p, slice_ns)`. Higher-priority (higher-weight) tasks receive proportionally longer time slices.

### Direct Dispatch Optimization (`do_direct_dispatch`)

When a suitable CPU is identified in `select_cpu()`, the task is dispatched immediately rather than going through the enqueue/dispatch cycle. This reduces latency:

- If the target CPU's DSQ is empty or the first queued task has a later deadline, the task goes to `SCX_DSQ_LOCAL` (lock-free local dispatch).
- Otherwise, the task is inserted into the per-CPU DSQ with vtime ordering.

### Scheduler Flags

The scheduler sets the following `SCX_OPS_*` flags:

| Flag                              | Effect                                                    |
|-----------------------------------|-----------------------------------------------------------|
| `SCX_OPS_ENQ_EXITING`            | Enqueue tasks that are exiting                            |
| `SCX_OPS_ENQ_LAST`               | Enqueue the last runnable task on a CPU                   |
| `SCX_OPS_ENQ_MIGRATION_DISABLED` | Enqueue tasks with migration disabled                     |
| `SCX_OPS_ALLOW_QUEUED_WAKEUP`    | Allow select_cpu() to be called for already-queued tasks  |

The watchdog timeout is set to 5000ms (`timeout_ms = 5000`).

## Userspace Side

### CLI Options

Defined via `clap::Parser` in the `Opts` struct:

| Flag                     | Short | Default  | Description                                           |
|--------------------------|-------|----------|-------------------------------------------------------|
| `--slice_us`             | `-s`  | 1000     | Maximum scheduling slice in microseconds              |
| `--slice_us_lag`         | `-l`  | 40000    | Maximum time slice lag in microseconds                |
| `--cpu_busy_thresh`      | `-c`  | 75       | CPU utilization percentage for "busy" threshold       |
| `--polling_ms`           | `-p`  | 250      | Polling interval (ms) to refresh CPU utilization      |
| `--primary_domain`       | `-m`  | (all)    | CPUs to prioritize (keyword or list)                  |
| `--preferred_idle_scan`  | `-P`  | false    | Enable capacity-ranked idle CPU scanning              |
| `--stats`                |       | (none)   | Enable stats monitoring at given interval (seconds)   |
| `--monitor`              |       | (none)   | Stats-only mode (scheduler not launched)              |
| `--verbose`              | `-v`  | false    | Verbose output including libbpf details               |
| `--version`              | `-V`  | false    | Print version and exit                                |
| `--help_stats`           |       | false    | Show statistics descriptions                          |
| `--exit_dump_len`        |       | 0        | Exit debug dump buffer length                         |

### Initialization Flow (`Scheduler::init`)

1. **Topology discovery**: Creates a `Topology` object to detect SMT, core types, CPU capacities, and sibling relationships.
2. **BPF skeleton setup**: Opens the BPF skeleton, configures read-only data (`rodata`) with CLI parameters (slice, lag, thresholds, SMT state, preferred CPU order, primary domain flag).
3. **CPU capacity sorting**: All CPUs are sorted by `cpu_capacity` in descending order and stored in `preferred_cpus[]` for use by the preferred idle scan.
4. **BPF load**: Loads and verifies the BPF programs.
5. **SMT domain init**: Calls `enable_sibling_cpu` for each CPU pair via BPF syscall programs.
6. **Primary domain init**: Calls `enable_primary_cpu` for each CPU in the primary domain via BPF syscall programs.
7. **Attach**: Attaches the struct_ops scheduler to the kernel.
8. **Stats server**: Launches the stats server for runtime monitoring.

### Main Loop (`Scheduler::run`)

The main loop runs until shutdown (Ctrl-C) or scheduler exit:

1. **CPU utilization polling**: Reads `/proc/stat`, computes user CPU percentage via `compute_user_cpu_pct()`, and writes the result to `bss_data.cpu_util`.
2. **Stats serving**: Responds to stats requests on the stats channel, providing delta metrics via `Metrics::delta()`.
3. **Restart support**: If the scheduler exits with a restart request (`should_restart()`), the outer loop in `main()` re-initializes and re-attaches the scheduler.

### Statistics (`stats.rs`)

The `Metrics` struct tracks three counters (read from BPF `bss_data`):

| Metric                | Description                                              |
|-----------------------|----------------------------------------------------------|
| `nr_local_dispatch`   | Tasks dispatched from a CPU's own DSQ                    |
| `nr_remote_dispatch`  | Tasks stolen from a remote CPU's DSQ                     |
| `nr_keep_running`     | Tasks that continued running because no contention found |

Statistics are served as deltas between polling intervals. The `monitor()` function uses `scx_utils::monitor_stats` to print formatted output to stdout.

## Data Structures Summary

### BPF Maps

| Map                | Type                    | Purpose                                     |
|--------------------|-------------------------|---------------------------------------------|
| `cpu_ctx_stor`     | `PERCPU_ARRAY` (1 entry)| Per-CPU context holding SMT sibling cpumask  |
| `task_ctx_stor`    | `TASK_STORAGE`          | Per-task scheduling metadata                 |

### BPF Global Variables

| Variable             | Section   | Description                                            |
|----------------------|-----------|--------------------------------------------------------|
| `slice_ns`           | rodata    | Default time slice (nanoseconds)                       |
| `slice_lag`          | rodata    | Max vruntime credit for sleeping tasks                 |
| `smt_enabled`        | rodata    | Whether SMT is active                                  |
| `busy_threshold`     | rodata    | CPU utilization threshold [0..1024]                    |
| `primary_all`        | rodata    | True if primary domain = all CPUs                      |
| `preferred_idle_scan`| rodata    | Enable capacity-ranked idle scanning                   |
| `preferred_cpus[]`   | rodata    | CPU IDs sorted by capacity (descending)                |
| `cpu_capacity[]`     | rodata    | Per-CPU capacity values                                |
| `cpu_util`           | bss       | Current CPU utilization [0..1024], updated from /proc  |
| `vtime_now`          | bss       | System-wide vruntime watermark                         |
| `nr_local_dispatch`  | bss       | Counter for local DSQ dispatches                       |
| `nr_remote_dispatch` | bss       | Counter for remote DSQ dispatches                      |
| `nr_keep_running`    | bss       | Counter for keep-running events                        |
| `nr_cpu_ids`         | bss       | Number of CPU IDs in the system                        |
| `primary_cpumask`    | bss       | BPF kptr cpumask for the primary domain                |

## Design Trade-offs

1. **Per-CPU DSQs vs. global DSQ**: Per-CPU DSQs eliminate global lock contention, making the scheduler highly scalable on large-core systems. The cost is that work-stealing (`dispatch_from_any_cpu`) requires scanning all CPUs, which is O(nr_cpu_ids) -- acceptable because it only runs when the local queue is empty or the system is busy.

2. **Sticky tasks**: Tasks with very short average runtimes (< 10us) skip migration entirely. This avoids the overhead of idle CPU scanning for tasks that barely use their time slice, at the cost of potentially sub-optimal placement for some short-burst workloads.

3. **Busy threshold**: The user-configurable busy threshold (default 75%) controls when the scheduler shifts from locality-first (only migrate on wakeup) to throughput-first (aggressive cross-CPU work stealing). This gives operators a tuning knob for latency-vs-throughput trade-offs.

4. **Wakeup frequency in deadline**: Frequently waking tasks (high `wakeup_freq`) get more vruntime credit, resulting in earlier deadlines. This naturally boosts interactive tasks without explicit "interactive" classification. The `awake_vtime` penalty counterbalances tasks that never sleep, preventing them from gaming the wakeup-frequency heuristic.

5. **Preferred idle scan**: The optional capacity-ranked idle scan ensures that on heterogeneous systems (e.g., big.LITTLE), faster cores are filled first. On homogeneous systems, the default kernel-based idle scan is more efficient.
