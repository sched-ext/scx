# scx_lavd
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_lavd** (Latency-criticality Aware Virtual Deadline) is a sched_ext scheduler designed to deliver low-latency interactive performance while maintaining throughput for CPU-bound workloads. It was created by Changwoo Min at Igalia for Valve Corporation, with initial focus on the Steam Deck and gaming workloads, but designed to be a general-purpose scheduler suitable for desktops, laptops, and heterogeneous (big.LITTLE) systems.

The core insight of LAVD is that latency-critical tasks (UI rendering, audio, input processing) should be identified and prioritized automatically, without requiring manual task classification. Rather than relying on static priorities or cgroup-based policies, LAVD infers latency criticality at runtime from behavioral signals such as wake/wait frequency, runtime duration, waker/wakee relationships, and IRQ context.

**Key design principles:**

- **Virtual Deadline scheduling** with deadlines computed from latency criticality, runtime, and fairness penalties.
- **Automatic latency criticality detection** using multi-signal heuristic analysis.
- **Forward and backward criticality propagation** through task waker/wakee chains.
- **Topology-aware CPU selection** with compute domains, sticky CPU placement, and idle CPU search ordered by turbo/active/overflow tiers.
- **Energy-aware core compaction** with autopilot power mode switching.
- **Lock holder boosting** via futex tracing to accelerate critical sections.
- **Preemption via the "power of two random choices"** technique instead of expensive IPIs.

## Architecture / Design

### Split Between BPF and Userspace

The scheduling logic is entirely in BPF (the `src/bpf/` directory). The Rust userspace component (`src/main.rs`, `src/stats.rs`, `src/cpu_order.rs`) handles:

1. **Topology discovery and CPU ordering** -- building the Performance vs. CPU Order (PCO) table, compute domain neighbor maps, and big/LITTLE core classification.
2. **BPF skeleton initialization** -- loading the PCO table, compute domain structures, and configuration flags into BPF maps.
3. **Runtime monitoring** -- statistics collection via ring buffer introspection, power mode transitions via `--autopower`.
4. **Command-line options** -- power modes, slice bounds, preemption tuning, futex boosting, per-CPU DSQs, etc.

### BPF Source File Organization

| File | Purpose |
|---|---|
| `main.bpf.c` | Core sched_ext callbacks: `ops.select_cpu`, `ops.enqueue`, `ops.dispatch`, `ops.running`, `ops.stopping`, `ops.tick`, `ops.quiescent`, `ops.init_task`, `ops.init`, etc. |
| `lat_cri.bpf.c` | Latency criticality and performance criticality computation, virtual deadline calculation. |
| `balance.bpf.c` | Cross-domain load balancing: stealer/stealee classification, task stealing, DSQ consumption. |
| `idle.bpf.c` | Idle CPU selection: sticky CPU/domain logic, SMT-aware full-idle-core preference, cross-domain migration. |
| `preempt.bpf.c` | Preemption: victim CPU selection via "power of two random choices", slice shrinking at tick, IPI-avoidance. |
| `power.bpf.c` | Power management: core compaction, autopilot mode switching, CPU frequency scaling, effective capacity tracking. |
| `power.bpf.h` | Power-related declarations and the `conv_wall_to_invr` inline for capacity/frequency-invariant time conversion. |
| `sys_stat.bpf.c` | Periodic system statistics collection (timer-driven), CPU utilization, time slice recalculation. |
| `introspec.bpf.c` | Introspection/monitoring: ring buffer submission of per-task scheduling context for live monitoring. |
| `lock.bpf.c` | Futex lock holder detection via fentry/tracepoint hooks on `futex_wait`/`futex_wake` families. |
| `util.bpf.c` | Utility functions: EWMA helpers, CPU context lookup, flag operations, DSQ ID helpers. |
| `util.bpf.h` | Utility declarations. |
| `lavd.bpf.h` | Central header: `task_ctx`, `cpu_ctx`, `cpdom_ctx`, `pick_ctx`, `sys_stat` structures, constants, macros, DSQ helpers. |
| `intf.h` | Interface header shared between BPF and Rust: constants (`LAVD_*`), flag definitions, message structures. |

### Key Data Structures

**`task_ctx`** (per-task, allocated in BPF arena):
- `lat_cri` / `perf_cri` -- computed latency and performance criticality scores.
- `avg_runtime_wall` / `acc_runtime_wall` -- wall-clock runtime averages (accumulated since last sleep).
- `run_freq` / `wait_freq` / `wake_freq` -- how often the task runs, waits, and wakes others (EWMA frequencies).
- `svc_time_wwgt` -- weighted service time for greedy ratio fairness tracking.
- `lat_cri_waker` / `lat_cri_wakee` -- inherited criticality from waker/wakee for propagation.
- `vdeadline` -- the virtual deadline computed at enqueue time.
- `flags` -- bitmask of behavioral flags (`LAVD_FLAG_IS_WAKEUP`, `LAVD_FLAG_WOKEN_BY_HARDIRQ`, `LAVD_FLAG_FUTEX_BOOST`, etc.).

**`cpu_ctx`** (per-CPU, BPF percpu array):
- `cpdom_id`, `cpu_id`, `big_core` -- topology membership.
- `cur_util_wall` / `avg_util_wall` / `cur_util_invr` / `avg_util_invr` -- wall and invariant utilization.
- `effective_capacity` -- current achievable capacity considering policy, thermal, and observed limits.
- `est_stopping_clk` / `lat_cri` -- preemption comparison data for the currently running task.
- `flags` -- mirrors task flags for quick preemption decisions (e.g., `LAVD_FLAG_FUTEX_BOOST`).
- Various temporary cpumasks (`tmp_t_mask`, `tmp_i_mask`, `tmp_a_mask`, `tmp_o_mask`, etc.) for scratch use during idle CPU search.

**`cpdom_ctx`** (per-compute-domain, static array of `LAVD_CPDOM_MAX_NR`):
- `id`, `alt_id` -- domain ID and alternative domain (big<->LITTLE counterpart).
- `nr_active_cpus`, `cap_sum_active_cpus` -- active CPU count and capacity sum.
- `load_invr` -- scaled load metric used for stealer/stealee classification.
- `is_stealer` / `is_stealee` -- load balancing roles.
- `neighbor_ids` / `nr_neighbors` -- ordered neighbor lists for cross-domain migration.
- `__cpumask` -- bitmask of CPUs in this domain.

**`sys_stat`** (global system statistics):
- `avg_util_wall` / `avg_util_invr` -- system-wide utilization (wall and invariant).
- `avg_lat_cri` / `max_lat_cri` / `thr_lat_cri` -- latency criticality statistics and preemption threshold.
- `min_perf_cri` / `avg_perf_cri` / `max_perf_cri` / `thr_perf_cri` -- performance criticality statistics and big/LITTLE threshold.
- `avg_svc_time_wwgt` -- average weighted service time for greedy ratio.
- `nr_active` -- number of currently active CPUs.
- `slice_wall` -- dynamically computed time slice.
- `nr_queued_task` -- running average of queue depth.

### DSQ (Dispatch Queue) Architecture

LAVD supports three DSQ modes, controlled by the `per_cpu_dsq` and `pinned_slice_ns` options:

1. **Per-compute-domain DSQs** (default): Tasks are dispatched to a shared DSQ per compute domain, identified by `cpdom_to_dsq(cpdom_id)`. This is a FIFO-by-vtime queue.

2. **Per-CPU DSQs** (`--per-cpu-dsq`): Each physical core gets its own DSQ via `cpu_to_dsq(cpu)`. This improves L1/L2 cache locality but requires more complex load balancing.

3. **Hybrid mode** (`--pinned-slice-us`): Pinned tasks (those restricted to a single CPU) are placed on per-CPU DSQs while non-pinned tasks use per-domain DSQs. The dispatch path compares vtimes across both DSQ types.

DSQ IDs encode the type in the upper bits using `LAVD_DSQ_TYPE_SHFT`:
- `LAVD_DSQ_TYPE_CPDOM` (0) -- per-domain DSQ
- `LAVD_DSQ_TYPE_CPU` (1) -- per-CPU DSQ

## Latency Criticality Detection

The latency criticality computation happens in `calc_lat_cri()` in `lat_cri.bpf.c`. It combines multiple signals into a single score.

### Input Signals

**Wait frequency** (`wait_freq`): How often the task blocks waiting for I/O or synchronization. Higher wait frequency indicates a consumer in a producer-consumer pipeline. Computed as an EWMA of `1/interval` where interval is the time between consecutive waits.

**Wake frequency** (`wake_freq`): How often the task wakes other tasks. Higher wake frequency indicates a producer. A task with both high wait and high wake frequency is likely in the middle of a task chain (e.g., a compositor).

**Reverse runtime factor**: Shorter-running tasks get higher criticality. Computed as `(LAVD_LC_RUNTIME_MAX - avg_runtime_wall) / LAVD_SLICE_MIN_NS_DFL`. This captures the insight that latency-critical tasks typically have short bursts of computation.

**Weight factor** (`calc_weight_factor`): A multiplicative boost based on task context:

| Condition | Boost Level | Constant |
|---|---|---|
| Recently woken up | Regular | `LAVD_LC_WEIGHT_BOOST_REGULAR` |
| Synchronous wakeup | Regular (additional) | `LAVD_LC_WEIGHT_BOOST_REGULAR` |
| Woken by hardirq | Highest | `LAVD_LC_WEIGHT_BOOST_HIGHEST` |
| Woken by softirq | High | `LAVD_LC_WEIGHT_BOOST_HIGH` |
| Woken by RT/DL task | High | `LAVD_LC_WEIGHT_BOOST_HIGH` |
| Kernel task | Medium | `LAVD_LC_WEIGHT_BOOST_MEDIUM` |
| ksoftirqd | High | `LAVD_LC_WEIGHT_BOOST_HIGH` |
| kworker | Regular | `LAVD_LC_WEIGHT_BOOST_REGULAR` |
| Affinitized task | Regular | `LAVD_LC_WEIGHT_BOOST_REGULAR` |
| Pinned / migration-disabled | Medium | `LAVD_LC_WEIGHT_BOOST_MEDIUM` |
| Lock holder (futex) | Regular | `LAVD_LC_WEIGHT_BOOST_REGULAR` |

The final weight factor is `p->scx.weight * weight_boost + 1`, incorporating the task's nice priority.

### Computation

```
log_wwf = log2(wait_ft * wake_ft)
lat_cri = log_wwf + log2(runtime_ft * weight_ft)
lat_cri = lat_cri * lat_cri   // squared for amplification
```

The log-linearization handles the exponentially skewed distribution of these frequencies, and squaring amplifies the difference between latency-critical and non-latency-critical tasks.

### Forward and Backward Propagation

Latency criticality propagates through waker/wakee relationships:

- **Forward propagation** (waker -> wakee): When task A wakes task B, A's `lat_cri` is propagated to B via `taskc->lat_cri_waker`. This keeps the momentum of a latency-critical chain flowing forward.
- **Backward propagation** (wakee -> waker): When B is highly critical, B's `lat_cri` is propagated back to A via `taskc->lat_cri_wakee`. This handles priority inversion -- if a low-priority task wakes a high-priority task, the waker gets boosted next time.

The inherited amount is bounded: `giver_inh` is capped by `receiver_max = lat_cri >> LAVD_LC_INH_RECEIVER_SHIFT` so the task's own criticality always dominates.

### Performance Criticality

On heterogeneous (big.LITTLE) systems, a separate `perf_cri` score determines which tasks should run on big cores:

```
sum_runtime_ft = max(run_freq, 1) * max(runtime, 1) * p->scx.weight
perf_cri = log_wwf + log2(sum_runtime_ft)
```

Tasks with high wake/wait frequencies AND high runtime consumption AND high nice priority are performance-critical and should prefer big cores. The threshold `thr_perf_cri` divides tasks into big-core vs. LITTLE-core candidates based on the ratio of big to LITTLE core capacity in the currently active set.

## Scheduling Hot Path (Key BPF Callbacks)

### `ops.select_cpu` -- CPU Selection

Implemented in `lavd_select_cpu()` in `main.bpf.c`. Called when a task becomes runnable.

1. Retrieves the task context from the BPF arena.
2. Records waker information for criticality propagation.
3. Sets wakeup flags (`LAVD_FLAG_IS_WAKEUP`, `LAVD_FLAG_IS_SYNC_WAKEUP`).
4. Detects if the task was woken by a hardirq, softirq, or RT/DL task.
5. Calls `pick_idle_cpu()` (in `idle.bpf.c`) which implements the multi-level idle CPU search.
6. If the CPU is idle, sets `is_idle` so the task can be directly dispatched in `ops.enqueue`.

### `ops.enqueue` -- Enqueue to DSQ

Implemented in `lavd_enqueue()` in `main.bpf.c`.

1. Calculates the virtual deadline via `calc_when_to_run()` (from `lat_cri.bpf.c`).
2. Determines the target DSQ: per-CPU for pinned tasks (when `pinned_slice_ns` is active), per-domain otherwise.
3. Computes the time slice:
   - Base slice: `sys_stat.slice_wall` (dynamically adjusted).
   - **Slice boost**: If `no_slice_boost` is not set and the system is underloaded (`can_boost_slice()`), long-running tasks get a boosted slice of `min(LAVD_SLICE_BOOST_MAX_FT * slice, LAVD_SLICE_MAX_NS_DFL)`.
   - Pinned slice: If `pinned_slice_ns` is active and pinned tasks are waiting on this CPU, use `pinned_slice_ns`.
4. Updates service time tracking (`svc_time_wwgt`) for fairness.
5. Dispatches to the DSQ with `scx_bpf_dsq_insert_vtime()` using the computed vtime.
6. Attempts preemption via `try_find_and_kick_victim_cpu()` if the task is sufficiently latency-critical.

### `ops.dispatch` -- Consume from DSQ

Implemented in `lavd_dispatch()` in `main.bpf.c`.

Calls `consume_task()` (in `balance.bpf.c`) which:
1. If the current domain is a stealer, probabilistically attempts cross-domain task stealing.
2. When both per-CPU and per-domain DSQs are active, peeks at both and consumes whichever has the lower vtime.
3. Falls back to force stealing from neighbors if no local tasks are available (disabled when `mig_delta_pct > 0`).

### `ops.running` -- Task Starts Running

Implemented in `lavd_running()` in `main.bpf.c`.

1. Records the `running_clk` timestamp.
2. Sets `cpu_id` on the task context.
3. Computes `est_stopping_clk` for preemption comparison.
4. Copies task flags to `cpuc->flags` (for fast lock-holder checks during preemption).
5. Tracks per-CPU scheduling statistics (`nr_sched`, `nr_lat_cri`, `nr_perf_cri`, etc.).
6. Updates `run_freq` using EWMA.
7. Calls `update_cpuperf_target()` to set CPU frequency.
8. Submits introspection data if monitoring is active.

### `ops.stopping` -- Task Stops Running

Implemented in `lavd_stopping()` in `main.bpf.c`.

1. Computes wall-clock and invariant runtime for this slice.
2. Subtracts stolen time (time lost to IRQs/steal during execution).
3. Updates `avg_runtime_wall` via EWMA.
4. Accumulates `acc_runtime_wall` (reset on sleep, used for slice boost decisions).
5. Updates `tot_task_time_wall`, `tot_task_time_invr`, `tot_task_time_wwgt` on the CPU context for system statistics.
6. Resets lock/futex boost state.
7. Propagates latency criticality backward to the waker.
8. Resets CPU preemption info.

### `ops.tick` -- Periodic Tick

Implemented in `lavd_tick()` in `main.bpf.c`.

1. **For the current task**: If pinned tasks are waiting on this CPU, shrinks the current task's slice (`shrink_slice_at_tick()`).
2. **For remote CPUs**: If a slice-boosted task is running and queued tasks are pending, shrinks its slice remotely (`shrink_boosted_slice_remote()`).

### `ops.quiescent` -- Task Sleeps

Implemented in `lavd_quiescent()` in `main.bpf.c`.

1. Records `last_quiescent_clk`.
2. Updates `wait_freq` (EWMA of how often the task sleeps).
3. Resets `acc_runtime_wall` to zero (the task slept, so accumulated runtime resets).
4. Decrements `cpuc->nr_pinned_tasks` if the task is pinned.

### `ops.init_task` -- Task Initialization

Implemented in `lavd_init_task()` in `main.bpf.c`.

1. Allocates task context from the BPF arena.
2. Initializes all EWMA values (runtime, frequencies, etc.) to sensible defaults.
3. Detects if the task is a ksoftirqd via string comparison.
4. Checks affinity restrictions and sets `LAVD_FLAG_IS_AFFINITIZED`.
5. On big.LITTLE systems, determines which core types the task can run on.

## Key Mechanisms

### Virtual Deadline Computation

The virtual deadline determines the priority within DSQs. Computed in `calc_virtual_deadline_delta()`:

```
adjusted_runtime = LAVD_ACC_RUNTIME_MAX + min(acc_runtime_wall, LAVD_ACC_RUNTIME_MAX)
greedy_penalty = f(lag)   // [100%, 200%] based on how greedy the task has been
deadline = (adjusted_runtime * greedy_penalty) / lat_cri
```

The final vtime is:
```
vtime = (cur_logical_clk - LAVD_DL_COMPETE_WINDOW) + deadline_delta
```

The `LAVD_DL_COMPETE_WINDOW` offset allows newly enqueued tasks to compete against already-enqueued tasks within a time window, preventing starvation of tasks that arrive slightly later.

### Greedy Ratio Fairness

LAVD tracks per-task "lag" -- the difference between the average weighted service time and the task's own weighted service time:

```
lag = sys_stat.avg_svc_time_wwgt - taskc->svc_time_wwgt
```

- **Positive lag** (task underserved): penalty < 100%, task gets prioritized. Bounded by `LAVD_TASK_LAG_MAX` to prevent unbounded boost of long-sleeping tasks.
- **Negative lag** (task overserved/greedy): penalty > 100%, task is penalized. The `LAVD_FLAG_IS_GREEDY` flag is set, which also prevents the task from triggering preemption.

### Slice Boost

When the system is underloaded (`nr_queued_task <= nr_active`), long-running tasks receive a boosted time slice to avoid unnecessary context switching. The boosted slice is:

```
boosted_slice = min(LAVD_SLICE_BOOST_MAX_FT * sys_stat.slice_wall, LAVD_SLICE_MAX_NS_DFL)
```

Slice boosts are cancelled when:
- Pinned tasks are waiting on the CPU.
- A higher-priority task is enqueued and wants to preempt.
- The system becomes overloaded.

### Dynamic Time Slice

The system-wide time slice is recalculated periodically in `calc_sys_time_slice()`:

```
slice = (LAVD_TARGETED_LATENCY_NS * nr_active) / nr_queued_task
slice = clamp(slice, slice_min_ns, slice_max_ns)
```

This ensures that all runnable tasks can be scheduled at least once within the targeted latency window (default: 20ms). The slice is smoothed via EWMA.

### Logical Clock

LAVD maintains a per-DSQ logical clock (`cur_logical_clk`) that advances each time a task is dispatched. Virtual deadlines are expressed relative to this clock. The clock is local to the DSQ, not wall time, which ensures that deadline ordering is consistent even under varying system load.

### Waker/Wakee Criticality Propagation

In `ops.stopping`, when a task finishes running:
```
waker_taskc->lat_cri_wakee = max(waker->lat_cri_wakee, taskc->lat_cri / 2)
```

In `ops.select_cpu`, when a task is woken:
```
taskc->lat_cri_waker = waker_taskc->lat_cri / 2
```

This creates a geometric decay in propagated criticality, preventing unbounded inflation through cyclic waker/wakee chains.

## Power Management

### Power Modes

LAVD supports three power modes:

| Mode | `LAVD_PM_PERFORMANCE` | `LAVD_PM_BALANCED` | `LAVD_PM_POWERSAVE` |
|---|---|---|---|
| Core compaction | Off | On | On |
| CPU preference | All CPUs active | Dynamic (PCO table) | Dynamic, prefer LITTLE |
| Frequency scaling | Max | Utilization-based | Utilization-based |

### Autopilot

When `--autopilot` is enabled (the default), `do_autopilot()` automatically switches between power modes based on system utilization:

```
required_capacity = nr_cpus_onln * avg_util_invr
if required_capacity <= LAVD_AP_LOW_CAP   -> powersave
if required_capacity <= LAVD_AP_HIGH_CAP  -> balanced
otherwise                                  -> performance
```

The thresholds are determined from the energy model (if available) or from heuristics. `LAVD_AP_HIGH_CAP` defaults to ~70% utilization (adjusted for SMT).

### Autopower

When `--autopower` is enabled, the userspace Rust component polls the system's active power profile (e.g., from platform firmware like ACPI or UPower) and maps it to LAVD power modes.

### Core Compaction

In balanced and powersave modes, `do_core_compaction()` reduces the number of active CPUs to concentrate work and allow unused cores to enter deep sleep states:

1. Calculates required capacity with 25% headroom (`LAVD_CC_REQ_CAPACITY_HEADROOM`).
2. Walks the PCO table to find the minimum set of CPUs that satisfies the required capacity.
3. Sets the **active cpumask** (primary CPUs) and **overflow cpumask** (CPUs used when active ones are insufficient).
4. Kicks idle CPUs to wake them up for work or put them to sleep.

### CPU Frequency Scaling

`update_cpuperf_target()` sets the per-CPU frequency target based on utilization:

```
max_util = max(avg_util_wall, cur_util_wall)
if max_util < LAVD_CPU_UTIL_MAX_FOR_CPUPERF (85%):
    target = max_util * SCX_CPUPERF_ONE / LAVD_SCALE
else:
    target = SCX_CPUPERF_ONE (100%)
```

This avoids constant frequency transitions while ensuring high performance under load.

### Performance vs. CPU Order (PCO) Table

The PCO table, built in `cpu_order.rs`, maps each performance level to an ordered list of CPUs. When the energy model is available, the `EnergyModelOptimizer` exhaustively enumerates combinations of performance domains and states to find the most energy-efficient CPU set for each utilization level.

Each PCO entry contains:
- `perf_cap` -- upper bound of performance capacity for this entry.
- `cpus_perf` -- primary CPUs (ordered by preference).
- `cpus_ovflw` -- overflow CPUs (used when primary CPUs are exhausted).
- `pco_nr_primary` -- how many CPUs in the primary set.

### Effective Capacity Tracking

`update_effective_capacity()` computes the actual achievable capacity of each CPU considering:
1. **Policy limits**: `scaling_max_freq` from cpufreq.
2. **Thermal pressure**: `hw_pressure` per-CPU variable.
3. **Observed maximum frequency**: Tracked via `max_freq_observed` CAS-updated during high utilization, smoothed with EWMA.

The effective capacity is `min(capacity_policy, capacity_observed)`.

## Topology Awareness

### Compute Domains

A compute domain groups CPUs by NUMA node, LLC, and core type (big vs. LITTLE). Each domain has:
- An ordered neighbor list, sorted by distance (LLC distance < NUMA distance < core-type distance).
- **Circular sorting** of neighbors to preserve proximity during task stealing traversal.

Distance calculation (`CpuOrderCtx::dist`):
```
d = 0
if core_type differs:  d += 100
if NUMA node differs:  d += 10
else if LLC differs:   d += 1 (per virtual + physical LLC)
```

### Idle CPU Selection Policy

`pick_idle_cpu()` in `idle.bpf.c` implements a sophisticated multi-level search:

1. **Pinned tasks**: Go directly to their only allowed CPU, extending the overflow set if needed.
2. **Affinitized tasks**: Restrict all searches to the task's `cpus_ptr` mask.
3. **Find sticky CPU/domain**: Choose between previous CPU and sync waker CPU, preferring the one on a less loaded domain and matching core type (big task on big core).
4. **No idle CPU**: Stay on sticky CPU/domain for cache locality.
5. **Fully idle core search** (SMT): If the sticky CPU is not fully idle, search the sticky domain for a fully idle core (both siblings idle).
6. **Partially idle sticky CPU**: If the sticky CPU is partially idle, use it.
7. **Sync waker CPU**: If the waker CPU is idle and in the same domain, use it.
8. **Cross-domain migration**: If the sticky domain is a stealee and a neighbor domain is a stealer with a fully idle core, migrate there.
9. **Any idle in sticky domain**: Search turbo > active > overflow CPUs.
10. **Aggressive migration**: For freshly `execve()`-d tasks, try partially idle CPUs in neighbor domains.
11. **Fallback**: Stay on previous CPU for cache locality.

### Cross-Domain Load Balancing

Load balancing is planned periodically in `plan_x_cpdom_migration()` (in `balance.bpf.c`):

1. Compute per-domain load: `load_invr = (util * LAVD_SCALE / nr_active_cpus) + (qlen * LAVD_SCALE^3 / cap_sum)`.
2. Calculate migration delta threshold based on average load.
3. Domains below `avg - delta` become **stealers**; domains above `avg + delta` become **stealees**.
4. Stealers probabilistically steal from stealees by traversing neighbor lists in distance order.
5. **Force stealing**: If no local tasks, traverse neighbors unconditionally (disabled with `mig_delta_pct > 0`).
6. **Task donation**: During idle CPU selection, if the sticky domain is a stealee and a neighbor is a stealer, donate the task preemptively.

Thundering herd mitigation: Only `1 / (nr_active_cpus * LAVD_CPDOM_MIG_PROB_FT)` of CPUs attempt stealing simultaneously. Further cross-distance migration probability decreases exponentially.

## Preemption

### Preemption Decision

Preemption is triggered in `try_find_and_kick_victim_cpu()` (in `preempt.bpf.c`):

1. **Greedy tasks never preempt** -- `LAVD_FLAG_IS_GREEDY` blocks preemption.
2. **Worth checking**: Only tasks with `lat_cri >= sys_stat.thr_lat_cri` trigger preemption attempts.
3. **Slice boost cancellation**: If the preferred CPU runs a slice-boosted task and the new task is more critical, cancel the boost.

### Victim Selection: Power of Two Random Choices

`find_victim_cpu()` uses the "power of two random choices" technique:

1. Initialize the task's preemption info (estimated stopping clock, latency criticality).
2. If a preferred CPU exists, check it first.
3. Randomly sample CPUs from the compute domain mask using `bpf_cpumask_any_distribute()`.
4. Find up to 2 candidate victims -- CPUs running tasks with both lower `lat_cri` AND later `est_stopping_clk`.
5. Never preempt lock holders (`is_lock_holder_running`).
6. Choose the weaker of the two victims (using `can_x_kick_y`).

### IPI Avoidance

Instead of using `scx_bpf_kick_cpu()` (expensive IPI), LAVD sets the victim task's time slice to 1 ns via `ask_cpu_yield_after()`:

```c
WRITE_ONCE(victim_p->scx.slice, new_slice);  // typically 1
```

The victim will yield at the next scheduling point. This avoids expensive cross-CPU interrupts and provides more consistent performance across processor architectures.

An atomic CAS on `est_stopping_clk` prevents the same victim from being targeted by multiple preemptors simultaneously.

### Preemption Threshold

```
thr_lat_cri = max_lat_cri - ((max_lat_cri - avg_lat_cri) >> preempt_shift)
```

The `preempt_shift` parameter (default 6) controls how aggressively preemption occurs. With shift=6, roughly the top 1.56% (0.5^6) of latency-critical tasks can trigger preemption.

## Lock Holder Boosting

### Futex Tracing

LAVD traces userspace lock operations via the futex subsystem to identify lock holders. Two tracing mechanisms are supported (with fentry preferred for lower overhead):

**fentry hooks** (~48ns overhead):
- `fexit___futex_wait` -- lock acquired
- `fexit_futex_wake` -- lock released
- Plus variants for `futex_wait_multiple`, `futex_wait_requeue_pi`, `futex_wake_op`, `futex_lock_pi`, `futex_unlock_pi`

**Tracepoint hooks** (~130ns overhead):
- `sys_enter_futex` -- records `futex_op`
- `sys_exit_futex` -- dispatches based on `futex_op` (WAIT/WAKE/LOCK_PI/UNLOCK_PI)
- Plus `sys_exit_futex_wait`, `sys_exit_futex_waitv`, `sys_exit_futex_wake`

### Boosting Mechanism

When a lock is acquired: `LAVD_FLAG_FUTEX_BOOST` is set on the task and copied to `cpuc->flags`.

When a lock is released: `LAVD_FLAG_FUTEX_BOOST` is cleared.

Effects of the boost:
1. **Weight boost**: `LAVD_LC_WEIGHT_BOOST_REGULAR` added via `LAVD_FLAG_NEED_LOCK_BOOST` during criticality calculation.
2. **Preemption immunity**: `is_lock_holder_running(cpuc)` returns true, preventing the task from being preempted.
3. **Slice preservation**: If a lock holder's slice expires while it holds the lock, the `LAVD_FLAG_NEED_LOCK_BOOST` flag carries the boost to the next scheduling round.

### Approximation Tradeoffs

The futex tracing is deliberately approximate:
- Skipped `futex_wait()` (no contention) -- no boost needed since no waiters.
- Spurious wakeups (multiple `futex_wait()`) -- second call onwards ignored.
- Skipped `futex_wake()` -- boost times out after one time slice.
- No address discrimination -- all futex operations treated as one logical lock.

## Userspace Side

### Rust Entry Point (`main.rs`)

The `Scheduler` struct manages the BPF skeleton lifecycle:

1. **`init()`**: Opens BPF skeleton, initializes CPU topology via `CpuOrder::new()`, sets all BPF global variables, loads and attaches the BPF program.
2. **`run()`**: Main loop that:
   - Polls for stats requests from the stats server.
   - Handles `--autopower` mode transitions.
   - Checks for scheduler exit (UEI).
3. **Power mode switching**: Uses `prog.test_run()` to invoke the `SEC("syscall") set_power_profile` BPF program.

### CPU Order (`cpu_order.rs`)

`CpuOrder::new()` builds the complete CPU topology model:

1. Reads system topology via `scx_utils::Topology`.
2. Builds two CPU orderings: performance-first and powersave-first.
3. Constructs compute domains with neighbor maps.
4. If the energy model is available, `EnergyModelOptimizer` generates optimal PCO tables:
   - Enumerates all combinations of performance domains and states.
   - For each utilization level (5%, 10%, ... 100%), finds the CPU set that achieves the required performance with minimum power.
   - Minimizes the number of active performance domains and maximizes overlap between adjacent performance levels for smooth transitions.

### Statistics (`stats.rs`)

Two statistics channels:
- **SysStats**: System-wide metrics (queue depth, active CPUs, preemption rate, power mode distribution).
- **SchedSample**: Per-task scheduling snapshots (task criticality, CPU placement, slice usage, runtime).

Statistics are served via `scx_stats::StatsServer` and can be viewed with `--monitor` or `--stats` flags, or externally via the stats protocol.

## Configuration Options

| Option | Default | Description |
|---|---|---|
| `--autopilot` | Default mode | Automatically switch power modes based on load |
| `--autopower` | Off | Switch power modes based on platform power profile |
| `--performance` | Off | Force performance mode (all CPUs active) |
| `--balanced` | Off | Force balanced mode (core compaction on) |
| `--powersave` | Off | Force powersave mode (core compaction on, LITTLE preferred) |
| `--slice-max-us` | 5000 | Maximum time slice in microseconds |
| `--slice-min-us` | 500 | Minimum time slice in microseconds |
| `--pinned-slice-us` | 5000 | Slice for pinned tasks; 0 to disable per-CPU DSQs for pinned tasks |
| `--preempt-shift` | 6 | Preemption aggressiveness (0=aggressive, 10=conservative) |
| `--no-futex-boost` | Off | Disable lock holder boosting |
| `--no-preemption` | Off | Disable preemption entirely |
| `--no-wake-sync` | Off | Disable sync wakeup optimization |
| `--no-slice-boost` | Off | Disable slice boost for long-running tasks |
| `--no-core-compaction` | Off | Disable core compaction |
| `--no-freq-scaling` | Off | Disable CPU frequency scaling |
| `--per-cpu-dsq` | Off | Enable per-CPU DSQs (experimental) |
| `--mig-delta-pct` | 0 | Fixed migration threshold percentage (experimental) |
| `--cpu-pref-order` | Auto | Manual CPU preference order |
| `--no-use-em` | Off | Disable energy model for CPU ordering |

## Time Accounting: Wall vs. Invariant

LAVD maintains two parallel time accounting systems:

**Wall time** (`*_wall`): Actual elapsed time. Used for latency-sensitive decisions like time slices, utilization display, and deadline computation.

**Invariant time** (`*_invr`): Time scaled by CPU capacity and frequency via `conv_wall_to_invr()`:
```
duration_invr = (duration_wall * capacity * frequency) / (LAVD_SCALE^2)
```

Invariant time normalizes for CPU heterogeneity -- the same workload on a big core at high frequency produces the same invariant time as on a LITTLE core at low frequency. This is used for:
- System utilization calculation for core compaction decisions.
- Required compute capacity estimation for power mode switching.
- Fair comparison of CPU loads across heterogeneous cores.

## Constants and Tuning Parameters

Key constants from `intf.h` and `lavd.bpf.h`:

| Constant | Value | Purpose |
|---|---|---|
| `LAVD_TARGETED_LATENCY_NS` | 20ms | Target scheduling latency for all runnable tasks |
| `LAVD_SLICE_MIN_NS_DFL` | 500us | Default minimum time slice |
| `LAVD_SLICE_MAX_NS_DFL` | 5ms | Default maximum time slice |
| `LAVD_SLICE_BOOST_MAX_FT` | 3 | Maximum slice boost factor |
| `LAVD_SYS_STAT_INTERVAL_NS` | 20ms | System statistics update interval |
| `LAVD_SCALE` | 1024 | Fixed-point scale factor |
| `LAVD_SHIFT` | 10 | Bit shift for fixed-point arithmetic |
| `LAVD_CPU_ID_MAX` | 512 | Maximum supported CPU count |
| `LAVD_CPDOM_MAX_NR` | 64 | Maximum number of compute domains |
| `LAVD_CPDOM_MAX_DIST` | 9 | Maximum neighbor distance levels |
| `LAVD_CC_REQ_CAPACITY_HEADROOM` | 256 (25%) | Headroom for core compaction capacity |
| `LAVD_CC_PER_CPU_UTIL` | 614 (60%) | Target per-CPU utilization for core compaction |
| `LAVD_CPU_UTIL_MAX_FOR_CPUPERF` | 870 (85%) | Utilization threshold for max frequency |
| `LAVD_LC_RUNTIME_MAX` | 5ms | Runtime above which a task is not considered short |
| `LAVD_ACC_RUNTIME_MAX` | 2ms | Maximum accumulated runtime influence |
| `LAVD_TASK_LAG_MAX` | 300ms | Maximum lag for greedy ratio capping |
| `LAVD_DL_COMPETE_WINDOW` | 3ms | Window for deadline competition |
| `LAVD_PCO_STATE_MAX` | 32 | Maximum PCO table entries |

## Execve Hooks

When multiple compute domains exist, LAVD hooks `sys_enter_execve` and `sys_enter_execveat` tracepoints to set `LAVD_FLAG_MIGRATION_AGGRESSIVE` on newly exec'd tasks. This enables more aggressive cross-domain migration for freshly started programs, which have no cache affinity to their current CPU.

## Suspended Duration Handling

When a system suspends (e.g., laptop lid close), tasks remain in a "running" state on their CPU. `get_suspended_duration_and_reset()` tracks the offline/online clock delta per CPU and subtracts it from runtime calculations upon resume, preventing artificially inflated runtime statistics.
