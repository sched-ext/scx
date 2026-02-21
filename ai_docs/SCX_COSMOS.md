# scx_cosmos
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_cosmos** is a lightweight, general-purpose sched_ext scheduler optimized for preserving task-to-CPU locality. It is authored by Andrea Righi (NVIDIA) and is production-ready.

The scheduler operates in two distinct modes, switching between them dynamically based on system-wide CPU utilization:

- **Round-robin mode (unsaturated):** Tasks are dispatched to per-CPU local DSQs. This preserves cache locality and eliminates locking contention on shared queues. Tasks stay "sticky" to their CPUs.
- **Deadline mode (saturated):** Tasks are dispatched to a shared DSQ (or per-NUMA-node DSQs) using a virtual-deadline policy. This increases task migration across CPUs and favors interactive (frequently-sleeping) tasks over CPU-bound ones.

The transition between modes is governed by a configurable CPU utilization threshold (`busy_threshold`), periodically measured from userspace by reading `/proc/stat`.

Key design highlights:
- Very short default time slice: **10 microseconds** (`slice_ns = 10000`).
- **Deferred CPU wakeups** via a BPF timer to reduce enqueue-path overhead.
- **NUMA-aware** DSQ partitioning (optional).
- **SMT contention avoidance** to avoid co-scheduling on sibling hyperthreads.
- **Address-space affinity** for threads sharing the same `mm_struct`.
- **Hardware performance counter (PMU) integration** for event-driven task placement.
- **CPU frequency scaling** integration via `scx_bpf_cpuperf_set`.

## Architecture / Design

### Dual-Mode Dispatch

The central architectural decision is the dual-mode dispatch strategy, controlled by the function `is_system_busy()`:

```c
static inline bool is_system_busy(void)
{
    return cpu_util >= busy_threshold;
}
```

| Condition | DSQ Used | Policy | Goal |
|---|---|---|---|
| `cpu_util < busy_threshold` | `SCX_DSQ_LOCAL` (per-CPU) | Round-robin | Locality, low contention |
| `cpu_util >= busy_threshold` | `shared_dsq(cpu)` (global or per-node) | Virtual-deadline (vtime) | Fairness, responsiveness |

The `cpu_util` variable (range 0..1024) is updated from userspace by the Rust main loop, which reads `/proc/stat` at a configurable polling interval (`polling_ms`, default 250ms, clamped to 10..1000ms). The threshold `busy_threshold` defaults to 75% (encoded as `75 * 1024 / 100 = 768`).

### DSQ Topology

- **`SHARED_DSQ` (id 0):** A single global shared DSQ used in non-NUMA mode.
- **Per-node DSQs:** When `numa_enabled` is true, each NUMA node gets its own DSQ (keyed by node ID). The function `shared_dsq(cpu)` resolves to the appropriate node DSQ via the `cpu_node_map` BPF hash map.
- **Local DSQs:** `SCX_DSQ_LOCAL` and `SCX_DSQ_LOCAL_ON | cpu` are the kernel-provided per-CPU queues used in round-robin mode.

### Data Structures

**Per-task context (`struct task_ctx`):**

| Field | Type | Purpose |
|---|---|---|
| `last_run_at` | `u64` | Timestamp when the task last started running (for computing used slice) |
| `exec_runtime` | `u64` | Accumulated execution time since last sleep, capped at `slice_lag` |
| `wakeup_freq` | `u64` | EWMA of wakeup frequency, capped at 1024 |
| `last_woke_at` | `u64` | Timestamp of last wakeup |
| `perf_events` | `u64` | PMU event count from last run |

Stored in a `BPF_MAP_TYPE_TASK_STORAGE` map (`task_ctx_stor`).

**Per-CPU context (`struct cpu_ctx`):**

| Field | Type | Purpose |
|---|---|---|
| `last_update` | `u64` | Timestamp of last cpufreq performance level update |
| `perf_lvl` | `u64` | EWMA of CPU utilization, used for cpufreq scaling |
| `perf_events` | `u64` | Accumulated PMU events on this CPU |
| `smt` | `struct bpf_cpumask __kptr *` | Cpumask of SMT sibling(s) |

Stored in a `BPF_MAP_TYPE_PERCPU_ARRAY` map (`cpu_ctx_stor`).

**CPU-to-NUMA-node mapping (`cpu_node_map`):** A `BPF_MAP_TYPE_HASH` map (max 1024 entries) mapping `u32 cpu_id` to `u32 node_id`. Populated at init from the Rust-side `Topology`.

### Constants and Limits

| Constant | Value | Description |
|---|---|---|
| `MAX_CPUS` | 1024 | Max CPUs for flat/preferred idle scan |
| `MAX_NODES` | 1024 | Max NUMA nodes |
| `MAX_GPUS` | 32 | Max GPUs (reserved) |
| `SHARED_DSQ` | 0 | Global shared DSQ ID |
| `slice_ns` | 10,000 (10 us) | Default time slice |
| `slice_lag` | 20,000,000 (20 ms) | Max charged runtime since last sleep |
| `CPUFREQ_LOW_THRESH` | `SCX_CPUPERF_ONE / 4` | Below this, scale to minimum frequency |
| `CPUFREQ_HIGH_THRESH` | `SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4` | Above this, scale to maximum frequency |

## Scheduling Hot Path (BPF Callbacks)

The scheduler registers these `sched_ext` ops callbacks:

### `cosmos_select_cpu`

Called on task wakeup to select a target CPU *before* enqueue. This is the primary fast path.

**Logic flow:**

1. **Validate `prev_cpu`:** If `prev_cpu` is not in the task's allowed cpumask, fall back to `this_cpu` (the waker's CPU) or the first allowed CPU.

2. **Address-space affinity (`mm_affinity`):** If the waker and wakee share the same `mm_struct` (e.g., threads of the same process) and the system is not busy, and `this_cpu == prev_cpu`, dispatch directly to `SCX_DSQ_LOCAL` on that CPU. This exploits warm caches from same-address-space co-location.

3. **PMU event-heavy tasks (`perf_config`):** If the task is classified as "event heavy" (i.e., `tctx->perf_events > perf_threshold`), dispatch it to `SCX_DSQ_LOCAL` and select a CPU with the fewest accumulated PMU events via `pick_least_busy_event_cpu()`. This spreads event-heavy tasks to reduce resource contention (e.g., cache thrashing).

4. **Idle CPU selection:** Call `pick_idle_cpu()` to find an idle CPU. If an idle CPU is found, or the system is not busy, dispatch directly to `SCX_DSQ_LOCAL`. Return the idle CPU if found, otherwise `prev_cpu`.

The key optimization here is that the task is dispatched directly from `select_cpu` (via `scx_bpf_dsq_insert`) whenever possible, bypassing the `enqueue` callback entirely. This avoids the overhead of bouncing through `enqueue`.

### `cosmos_enqueue`

Called when `select_cpu` did not dispatch the task. This handles the saturated/busy case.

**Logic flow:**

1. **PMU event-heavy dispatch:** If `perf_config` is active and the task is event-heavy, dispatch to `SCX_DSQ_LOCAL_ON | new_cpu` where `new_cpu` is the least-busy-event CPU.

2. **Migration attempt:** If the task should migrate (not already CPU-selected, not currently running), try `pick_idle_cpu()`. If an idle CPU is found, dispatch to `SCX_DSQ_LOCAL_ON | cpu` and wake it.

3. **Not busy -- local dispatch:** If `!is_system_busy()`, dispatch to `SCX_DSQ_LOCAL` (keep the task on its current CPU).

4. **Busy -- shared DSQ with deadline:** Dispatch to `shared_dsq(prev_cpu)` using `scx_bpf_dsq_insert_vtime()` with a virtual deadline computed by `task_dl()`.

### `cosmos_dispatch`

Called when a CPU needs work. Tries to consume from the shared DSQ via `scx_bpf_dsq_move_to_local(shared_dsq(cpu))`. If no task is available and the previously-running task is still queued (`SCX_TASK_QUEUED`), it grants the previous task another time slice. This avoids unnecessary context switches when no other work is pending.

### `cosmos_runnable`

Called when a task becomes runnable (wakes up). Resets `exec_runtime` to 0 and updates `wakeup_freq` using the EWMA function `update_freq()`, capped at 1024.

### `cosmos_running`

Called when a task starts running on a CPU. Records `last_run_at`, advances the global `vtime_now` if the task's vtime is ahead, updates cpufreq via `update_cpufreq()`, and starts PMU event capture if configured.

### `cosmos_stopping`

Called when a task stops running. Computes the used time slice as `min(now - last_run_at, slice_ns)`, then:
- Advances `p->scx.dsq_vtime` by the weight-inverse-scaled slice.
- Accumulates `exec_runtime`, capped at `slice_lag`.
- Updates per-CPU load via `update_cpu_load()`.
- Stops and reads PMU counters if configured.

### `cosmos_enable`

Called when a task is first enabled for scheduling. Initializes `p->scx.dsq_vtime = vtime_now` so the task starts with a fair baseline.

### `cosmos_init_task` / `cosmos_exit_task`

Allocate and free per-task context and PMU resources.

### `cosmos_init`

Scheduler initialization:
- Creates shared DSQ(s) -- either one global `SHARED_DSQ` or per-node DSQs.
- Arms the deferred wakeup timer if enabled.
- Initializes per-CPU perf event counters.
- Installs PMU events if `perf_config` is set.

### `cosmos_exit`

Uninstalls PMU events and records the exit info via `UEI_RECORD`.

### Ops Flags

```c
SCX_OPS_ENQ_EXITING | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ALLOW_QUEUED_WAKEUP
```

- `SCX_OPS_ENQ_EXITING`: Enqueue dying tasks (don't silently drop them).
- `SCX_OPS_ENQ_LAST`: Enqueue tasks that are the last runnable task on a CPU.
- `SCX_OPS_ENQ_MIGRATION_DISABLED`: Enqueue tasks with migration disabled.
- `SCX_OPS_ALLOW_QUEUED_WAKEUP`: Allow wakeups while a task is queued.

## Key Mechanisms

### Locality Preservation

When the system is not saturated (`cpu_util < busy_threshold`), tasks are always dispatched to `SCX_DSQ_LOCAL`, keeping them on their current CPU. This is the core locality mechanism:

```c
if (!is_system_busy()) {
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
    ...
    return;
}
```

Additional locality mechanisms:

- **Address-space affinity (`mm_affinity`):** In `cosmos_select_cpu`, if the waker and wakee share `mm_struct` and the waker's CPU equals `prev_cpu`, the task is dispatched directly to that CPU. This keeps threads of the same process co-located.
- **Synchronous wakeup support:** By default, `SCX_WAKE_SYNC` is preserved in wake flags, allowing the idle CPU scanner (`pick_idle_cpu` / `scx_bpf_select_cpu_and`) to prefer the waker's CPU for the wakee. This benefits producer-consumer patterns (e.g., pipes). Can be disabled with `--no-wake-sync`.

### Deadline-Based Scheduling

Under saturation, the scheduler computes a virtual deadline for each task via `task_dl()`:

```c
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx)
{
    u64 lag_scale = MAX(tctx->wakeup_freq, 1);
    u64 vsleep_max = scale_by_task_weight(p, slice_lag * lag_scale);
    u64 vtime_min = vtime_now - vsleep_max;

    if (time_before(p->scx.dsq_vtime, vtime_min))
        p->scx.dsq_vtime = vtime_min;

    return p->scx.dsq_vtime + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}
```

**Deadline = vruntime + weight-inverse-scaled exec_runtime**

- **`p->scx.dsq_vtime`** is the task's accumulated virtual runtime (inversely proportional to weight via `scale_by_task_weight_inverse` in `cosmos_stopping`). This drives fairness -- tasks that have run more get a later deadline.
- **`exec_runtime`** is the accumulated CPU time since the task last slept (reset in `cosmos_runnable`, accumulated in `cosmos_stopping`, capped at `slice_lag`). Tasks that sleep frequently have low `exec_runtime`, giving them earlier deadlines and thus higher priority. This naturally prioritizes interactive/latency-sensitive tasks.
- **`vsleep_max`** limits how much vruntime credit a sleeping task can bank. It is `slice_lag * wakeup_freq`, scaled by weight. Tasks with higher wakeup frequency get a larger credit allowance, further favoring interactive tasks over those that sleep for long, infrequent periods.
- **`wakeup_freq`** is an EWMA of `(100ms / sleep_interval)`, capped at 1024. Updated in `cosmos_runnable`.

The vruntime is advanced in `cosmos_stopping`:

```c
p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
```

This ensures higher-weight (higher-priority) tasks accumulate vruntime more slowly, receiving proportionally more CPU time.

### Saturation Handling

The transition between round-robin and deadline modes is controlled by:

1. **Userspace polling:** The Rust `run()` loop reads `/proc/stat` every `polling_ms` milliseconds (default 250ms) and computes user CPU utilization as `(user + nice) / total * 1024`. This value is written to the BPF global `cpu_util`.

2. **BPF-side check:** `is_system_busy()` compares `cpu_util >= busy_threshold`. Default threshold is 75% (768/1024).

3. **Mode switch effect:**
   - **Not busy:** `cosmos_enqueue` dispatches to `SCX_DSQ_LOCAL`. `cosmos_select_cpu` dispatches directly if an idle CPU is found.
   - **Busy:** `cosmos_enqueue` dispatches to `shared_dsq()` with `scx_bpf_dsq_insert_vtime()`. `cosmos_dispatch` pulls from the shared DSQ.

The stats output indicates the current mode:

```
[scx_cosmos] CPUs  45.2% [round-robin] ev_dispatches=0
[scx_cosmos] CPUs  82.1% [deadline] ev_dispatches=0
```

### Deferred Wakeups

To minimize overhead on the enqueue hot path, CPU wakeups are deferred using a BPF timer (`wakeup_timer`):

```c
static int wakeup_timerfn(void *map, int *key, struct bpf_timer *timer)
{
    bpf_for(cpu, 0, nr_cpu_ids)
        if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) && is_cpu_idle(cpu))
            scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
    bpf_timer_start(timer, slice_ns, 0);
    return 0;
}
```

The timer fires every `slice_ns` (default 10 us). It scans all CPUs: if a CPU has pending tasks in its local DSQ but is running the idle thread, it kicks that CPU. This batching reduces the per-enqueue cost of `scx_bpf_kick_cpu`.

When deferred wakeups are disabled (`--no-deferred-wakeup`), `wakeup_cpu()` calls `scx_bpf_kick_cpu` immediately from the enqueue path.

## Topology Awareness

### NUMA

When `numa_enabled` is true (auto-detected from topology: requires more than one non-empty NUMA node; can be force-disabled with `--disable-numa`):

- **Per-node DSQs** are created in `cosmos_init`, one per node, with DSQ id = node id and NUMA affinity set to that node.
- The **CPU-to-node mapping** is populated in the `cpu_node_map` BPF hash map from userspace during initialization.
- `shared_dsq(cpu)` returns the node ID for the given CPU, ensuring tasks dispatched to the shared DSQ stay within their NUMA domain.

### SMT

SMT awareness is used in multiple ways:

1. **SMT sibling tracking:** Each CPU's `cpu_ctx.smt` cpumask stores its SMT sibling(s). Populated at init via `enable_sibling_cpu` syscall BPF programs, driven by `Topology::sibling_cpus()`.

2. **SMT contention avoidance (`avoid_smt`):** In `pick_idle_cpu`, the `SCX_PICK_IDLE_CORE` flag is passed to `scx_bpf_select_cpu_and` when `avoid_smt` is true, preferring fully-idle cores over half-idle ones.

3. **`is_smt_contended()`:** Checks if the sibling SMT CPU is busy while other full-idle cores exist. Used in `pick_idle_cpu` to avoid migrating to a faster core if the current core is fully idle (no SMT contention).

4. **Flat idle scan SMT preference:** In `pick_idle_cpu_flat`, the scanner first tries full-idle SMT cores (using `scx_bpf_get_idle_smtmask()`), then falls back to any idle CPU.

### Primary Domain

An optional subset of CPUs can be designated as the "primary domain" via `--primary-domain`. This accepts:

| Keyword | Meaning |
|---|---|
| `turbo` | CPUs with `CoreType::Big { turbo: true }` |
| `performance` | All `CoreType::Big` CPUs |
| `powersave` | All `CoreType::Little` CPUs |
| `all` | All CPUs (default) |
| `0-3,12-15` | Explicit CPU list/ranges |

When a primary domain is defined (fewer CPUs than total), the `primary_cpumask` is populated via the `enable_primary_cpu` BPF syscall program, and `primary_all` is set to false. Idle CPU selection then prioritizes CPUs within the primary domain before falling back to the full set.

### Preferred / Flat Idle Scanning

Two alternative idle CPU scanning modes bypass the kernel's default cpumask-based scanning:

- **Flat idle scan (`--flat-idle-scan`):** Iterates CPUs in a rotating fashion (`(start + i) % max_cpus`) to distribute load evenly. Effective for simple topologies.
- **Preferred idle scan (`--preferred-idle-scan`):** Iterates CPUs in descending capacity order (`preferred_cpus[]` array, sorted by `cpu_capacity`). This naturally migrates tasks to faster cores on heterogeneous systems (e.g., big.LITTLE).

Both modes are only used when the system is not busy; under saturation, the standard cpumask-based scan is used instead.

### Hybrid / Heterogeneous CPU Support

On systems with heterogeneous cores (e.g., Intel hybrid with P-cores and E-cores), `cosmos_select_cpu` implements a waker-to-wakee performance migration:

```c
if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
    is_cpu_faster(this_cpu, prev_cpu)) {
    if (cpus_share_cache(this_cpu, prev_cpu) &&
        !is_smt_contended(prev_cpu) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;
    prev_cpu = this_cpu;
}
```

If the waker's CPU is faster than the wakee's previous CPU, the wakee is migrated closer to the waker (by setting `prev_cpu = this_cpu`), which biases the subsequent idle CPU search toward faster cores. An exception is made if both CPUs share the same LLC and the wakee's CPU is a fully-idle core (no SMT contention), in which case locality is preserved.

## CPU Frequency Scaling

When `cpufreq_enabled` is true (default), the scheduler dynamically adjusts CPU performance levels:

1. **Load measurement (`update_cpu_load`):** In `cosmos_stopping`, the CPU's utilization is estimated as `slice * SCX_CPUPERF_ONE / delta_t` (fraction of time the CPU was busy), then smoothed with EWMA into `cctx->perf_lvl`.

2. **Frequency application (`update_cpufreq`):** In `cosmos_running`, the smoothed performance level is applied with hysteresis:
   - If `perf_lvl >= CPUFREQ_HIGH_THRESH` (75% of max): set to `SCX_CPUPERF_ONE` (maximum).
   - If `perf_lvl <= CPUFREQ_LOW_THRESH` (25% of max): set to `SCX_CPUPERF_ONE / 2` (half).
   - Otherwise: use the smoothed value directly.

This is applied via `scx_bpf_cpuperf_set(cpu, perf_lvl)`.

## PMU Event-Based Scheduling

When `--perf-config 0xNNN` is specified (non-zero), the scheduler tracks hardware PMU events per task:

1. **Setup:** Userspace opens raw perf events on every CPU via `perf_event_open` and stores the FDs in the `scx_pmu_map` BPF map.

2. **Tracking:** `scx_pmu_event_start` is called in `cosmos_running`; `scx_pmu_event_stop` and `update_counters` are called in `cosmos_stopping`. The delta of PMU events during the task's run is stored in `tctx->perf_events` and accumulated in `cctx->perf_events`.

3. **Classification:** `is_event_heavy(tctx)` returns true if `tctx->perf_events > perf_threshold`.

4. **Placement:** Event-heavy tasks are handled specially in both `cosmos_select_cpu` and `cosmos_enqueue`:
   - **Sticky mode (`--perf-sticky`):** The task stays on `prev_cpu`.
   - **Distribute mode (default):** The task is moved to the idle CPU with the fewest accumulated PMU events in the same NUMA node, via `pick_least_busy_event_cpu()`.

This mechanism is useful for workloads where specific hardware events (e.g., cache misses, memory bandwidth) should drive placement decisions.

## Userspace Side

### Rust Scheduler Struct

The `Scheduler` struct holds:
- `skel: BpfSkel` -- the loaded and attached BPF skeleton.
- `opts: &Opts` -- parsed CLI options.
- `struct_ops: Option<libbpf_rs::Link>` -- the attached struct_ops link (dropped on exit).
- `stats_server: StatsServer<(), Metrics>` -- statistics server for monitoring.

### Initialization (`Scheduler::init`)

1. **Topology discovery:** Uses `scx_utils::Topology` to detect NUMA nodes, SMT siblings, core types, and CPU capacities.
2. **BPF skeleton setup:** Opens the skeleton, populates `rodata` (read-only data) with configuration from CLI options, and sets ops flags.
3. **Map population:** After loading, populates `cpu_node_map` and optionally sets up `primary_cpumask` and SMT sibling masks via BPF syscall programs.
4. **Perf events:** If `perf_config > 0`, opens raw perf events for each CPU.
5. **Attach:** Attaches the struct_ops and launches the stats server.

### Main Loop (`Scheduler::run`)

The main loop runs until shutdown (Ctrl-C) or BPF-side exit:

1. **CPU utilization polling:** Every `polling_ms`, reads `/proc/stat`, computes user CPU percentage via `compute_user_cpu_pct()`, and writes the result (0..1024) to `bss_data.cpu_util`.
2. **Stats serving:** Handles stats requests from the `StatsServer` channel with a timeout equal to the polling interval.
3. **Restart support:** If `uei_report` indicates `should_restart()`, the scheduler re-initializes.

### Statistics (`stats.rs`)

The `Metrics` struct exposes:

| Metric | Description |
|---|---|
| `cpu_util` | Average CPU utilization (0..1024 scale) |
| `cpu_thresh` | Busy utilization threshold (0..1024 scale) |
| `nr_event_dispatches` | Count of dispatches triggered by PMU event classification |

Stats are served via `scx_stats::StatsServer` and can be monitored with `--stats <interval>` or `--monitor <interval>`.

### CLI Options Summary

| Flag | Default | Description |
|---|---|---|
| `-s` / `--slice-us` | 10 | Time slice in microseconds |
| `-l` / `--slice-lag-us` | 20000 | Max runtime credit since last sleep (us) |
| `-c` / `--cpu-busy-thresh` | 75 | CPU busy threshold (0-100%) |
| `-p` / `--polling-ms` | 250 | CPU utilization polling interval (ms) |
| `-m` / `--primary-domain` | all | Primary CPU domain specification |
| `-e` / `--perf-config` | 0x0 | Raw PMU event code (hex) |
| `-E` / `--perf-threshold` | 0 | PMU events/ms threshold for "event heavy" |
| `-y` / `--perf-sticky` | false | Keep event-heavy tasks on same CPU |
| `-n` / `--disable-numa` | false | Disable NUMA optimizations |
| `-f` / `--disable-cpufreq` | false | Disable CPU frequency control |
| `-i` / `--flat-idle-scan` | false | Flat (rotating) idle CPU scan |
| `-P` / `--preferred-idle-scan` | false | Capacity-ordered idle CPU scan |
| `--disable-smt` | false | Disable SMT awareness |
| `-S` / `--avoid-smt` | false | Avoid placing tasks on SMT siblings |
| `-w` / `--no-wake-sync` | false | Disable synchronous wakeup affinity |
| `-d` / `--no-deferred-wakeup` | false | Disable timer-based deferred wakeups |
| `-a` / `--mm-affinity` | false | Address-space (mm) affinity |
| `--stats` | none | Enable stats monitoring (interval in seconds) |
| `--monitor` | none | Stats-only mode (no scheduling) |
| `-v` / `--verbose` | false | Verbose output |

## EWMA Utilities

The scheduler uses a simple exponential weighted moving average throughout:

```c
static u64 calc_avg(u64 old_val, u64 new_val)
{
    return (old_val - (old_val >> 2)) + (new_val >> 2);
}
```

This computes `new_avg = old_avg * 0.75 + new_val * 0.25`. It is used for:
- Smoothing CPU performance levels (`cctx->perf_lvl`).
- Smoothing wakeup frequency (`tctx->wakeup_freq` via `update_freq`).

The wakeup frequency computation converts a sleep interval to a frequency:

```c
static u64 update_freq(u64 freq, u64 interval)
{
    u64 new_freq = (100 * NSEC_PER_MSEC) / interval;
    return calc_avg(freq, new_freq);
}
```

This yields frequency in units of "wakeups per 100ms", smoothed over time.

## Time Slice Scaling

Time slices are scaled by task weight (nice-derived priority):

```c
static u64 task_slice(const struct task_struct *p)
{
    return scale_by_task_weight(p, slice_ns);
}
```

Higher-weight tasks receive longer slices. The `scale_by_task_weight` and `scale_by_task_weight_inverse` functions (from scx common library) handle the weight-proportional scaling that underpins both slice allocation and vruntime accounting.

## Summary of BPF Maps

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `task_ctx_stor` | `TASK_STORAGE` | int | `struct task_ctx` | Per-task scheduling context |
| `cpu_ctx_stor` | `PERCPU_ARRAY` | u32 (always 0) | `struct cpu_ctx` | Per-CPU context (perf level, SMT mask) |
| `cpu_node_map` | `HASH` | u32 (cpu_id) | u32 (node_id) | CPU-to-NUMA-node mapping |
| `wakeup_timer` | `ARRAY` | u32 (always 0) | `struct wakeup_timer` | Deferred wakeup BPF timer |
| `scx_pmu_map` | (external) | u32 (cpu_id) | fd | PMU perf event file descriptors |
