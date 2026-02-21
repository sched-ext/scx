# scx_bpfland
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_bpfland` is a vruntime-based `sched_ext` scheduler that prioritizes interactive workloads. It is derived from `scx_rustland` but is fully implemented in BPF, with a minimal Rust userspace component that handles command-line option processing, metrics collection, topology initialization, and statistics reporting. All scheduling decisions are made in BPF.

The scheduler uses a **deadline-based** dispatching model. Each task's deadline is computed from its accumulated virtual runtime (`dsq_vtime`) plus a partial vruntime accumulated since the last sleep event (`awake_vtime`). Tasks that sleep frequently and consume the CPU in short bursts receive lower deadlines (higher priority), making the scheduler naturally responsive for interactive and latency-sensitive workloads such as gaming, multimedia, live streaming, and real-time audio encoding/decoding -- especially when these run alongside CPU-intensive background tasks.

**Key design principles:**

- Two-level DSQ hierarchy: per-CPU DSQs and per-NUMA-node DSQs, with deadline-ordered dispatch.
- Interactive prioritization via wakeup frequency-scaled vruntime credit.
- Sticky task optimization for high-frequency reschedulers.
- Topology awareness: SMT, LLC, NUMA, and heterogeneous CPU capacity (big.LITTLE / hybrid).
- CPU frequency scaling integration via `scx_bpf_cpuperf_set`.
- CPU throttling via timer-based idle injection.

## Architecture / Design

### Split Between BPF and Userspace

| Layer | File | Role |
|-------|------|------|
| BPF scheduling logic | `src/bpf/main.bpf.c` | All scheduling callbacks (`select_cpu`, `enqueue`, `dispatch`, `running`, `stopping`, `runnable`, `enable`, `init_task`, `init`, `exit`). Contains the complete scheduling algorithm. |
| BPF/userspace interface | `src/bpf/intf.h` | Shared type definitions (`cpu_arg`, `domain_arg`, time constants). |
| Userspace orchestrator | `src/main.rs` | CLI parsing, topology discovery, primary domain / SMT domain initialization via BPF syscall programs, cpufreq configuration, power profile auto-detection, stats server, and main run loop. |
| Statistics | `src/stats.rs` | `Metrics` struct definition and delta-based stats reporting via `scx_stats`. |

### Dispatch Queue (DSQ) Layout

The scheduler creates two layers of dispatch queues during `bpfland_init`:

1. **Per-CPU DSQs** -- one per CPU, with DSQ ID equal to the CPU index (`cpu_dsq(cpu) = cpu`). Used for tasks dispatched directly to a specific CPU (e.g., via `select_cpu` idle CPU selection, per-CPU kthreads, sticky tasks).

2. **Per-node DSQs** -- one per NUMA node, with DSQ ID `nr_cpu_ids + node` (`node_dsq(cpu) = nr_cpu_ids + node_of(cpu)`). Used as the shared fallback queue when no idle CPU is found.

Both DSQ types use vtime-ordered insertion (`scx_bpf_dsq_insert_vtime`), except for tasks dispatched directly to `SCX_DSQ_LOCAL` (sticky tasks, local kthreads, local per-CPU tasks), which use FIFO insertion.

### Per-Task State (`task_ctx`)

Stored in BPF task-local storage (`BPF_MAP_TYPE_TASK_STORAGE`):

| Field | Type | Description |
|-------|------|-------------|
| `awake_vtime` | `u64` | Accumulated (weight-inverse-scaled) runtime since the task last woke up. Reset to 0 in `ops.runnable()`. |
| `last_run_at` | `u64` | Timestamp (ns) when the task last started running. Set in `ops.running()`. |
| `wakeup_freq` | `u64` | EWMA of wakeup frequency, measured as `(100ms / interval_since_last_wakeup)`. Capped at `MAX_WAKEUP_FREQ` (64). |
| `last_woke_at` | `u64` | Timestamp (ns) of the task's last wakeup. |
| `avg_runtime` | `u64` | EWMA of per-scheduling-cycle runtime, used for sticky task detection. |

### Per-CPU State (`cpu_ctx`)

Stored in a per-CPU array (`BPF_MAP_TYPE_PERCPU_ARRAY`):

| Field | Type | Description |
|-------|------|-------------|
| `tot_runtime` | `u64` | Total accumulated runtime on this CPU. |
| `prev_runtime` | `u64` | Snapshot of `tot_runtime` at last perf level update. |
| `last_running` | `u64` | Timestamp of last perf level update. |
| `perf_lvl` | `u64` | Current dynamic cpufreq performance level for this CPU. |
| `smt` | `bpf_cpumask __kptr *` | Cpumask of SMT siblings for this CPU. |
| `l2_cpumask` | `bpf_cpumask __kptr *` | L2 cache domain cpumask (allocated but not heavily used in current code). |
| `l3_cpumask` | `bpf_cpumask __kptr *` | L3 cache domain cpumask (allocated but not heavily used in current code). |

### Global State

| Variable | Description |
|----------|-------------|
| `vtime_now` | Global virtual runtime clock. Advanced in `ops.running()` to track the maximum `dsq_vtime` seen. |
| `nr_running` | Atomically-tracked count of currently running tasks. |
| `nr_online_cpus` | Number of online CPUs (set at init). |
| `nr_cpu_ids` | Maximum possible CPU ID (from `scx_bpf_nr_cpu_ids()`). |
| `cpus_throttled` | Boolean flag toggled by the throttle timer to inject idle cycles. |
| `primary_cpumask` | kptr to cpumask defining the primary scheduling domain. |

## Scheduling Hot Path

### `bpfland_select_cpu` (ops.select_cpu)

Called on the wakeup path to pick a target CPU. This is the fast path for idle CPU selection.

**Algorithm:**

1. **Validate `prev_cpu`**: If the task's previous CPU is no longer in its cpus_allowed mask, fall back to `this_cpu` (the waker's CPU) if allowed, otherwise the first allowed CPU.

2. **Attempt idle CPU selection** via `pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags, false)`.

3. **If an idle CPU is found**: Dispatch the task directly to the per-CPU DSQ of the target CPU using `scx_bpf_dsq_insert_vtime()` with the task's computed deadline (`task_dl`) and time slice (`task_slice`). This bypasses `ops.enqueue()` entirely. Increment `nr_direct_dispatches`.

4. **If no idle CPU is found**: Return `prev_cpu` without dispatching. The task will proceed to `ops.enqueue()`.

### `pick_idle_cpu`

The idle CPU selection has two modes, selected by the `preferred_idle_scan` flag:

**Standard mode** (default, `preferred_idle_scan = false`):

1. If sync wakeups are enabled and the waker's CPU is faster than the wakee's previous CPU (hybrid topology), attempt to migrate the wakee closer to the waker, unless both share an LLC and the previous CPU is a fully idle SMT core.

2. Use `scx_bpf_select_cpu_and()` (kernel >= 6.17) or `scx_bpf_select_cpu_dfl()` (legacy fallback) to find an idle CPU. When a primary domain is defined, first try to pick within the primary domain, then fall back to any allowed CPU.

**Preferred scan mode** (`preferred_idle_scan = true`, via `pick_idle_cpu_scan`):

Uses a linear scan of CPUs sorted by capacity (descending) via the `preferred_cpus[]` array. The scan follows a 4-tier priority:

1. Full-idle SMT core within the primary domain.
2. Any idle CPU within the primary domain.
3. Full-idle SMT core anywhere.
4. Any idle CPU anywhere.

At each tier, the previous CPU is checked first (if allowed and in the target domain) before scanning the sorted list. This mode always tries `scx_bpf_test_and_clear_cpu_idle()` atomically.

### `bpfland_enqueue` (ops.enqueue)

Handles tasks that were not dispatched in `select_cpu` (i.e., no idle CPU was found, or `select_cpu` was skipped).

**Dispatch decision tree:**

1. **Sticky tasks** (`is_task_sticky`): If the task's `avg_runtime < 10us` and `sticky_tasks` is enabled, dispatch to `SCX_DSQ_LOCAL` (same CPU, FIFO). This reduces contention on shared DSQs for tasks with extremely high reschedule frequency.

2. **Per-CPU kthreads** (`local_kthreads` enabled, task is a kthread with `nr_cpus_allowed == 1`): Dispatch to `SCX_DSQ_LOCAL`.

3. **Per-CPU tasks** (`is_pcpu_task` -- `nr_cpus_allowed == 1` or migration disabled):
   - If `local_pcpu` is enabled: dispatch to `SCX_DSQ_LOCAL` (higher priority, potential starvation).
   - Otherwise: dispatch to the per-CPU DSQ (`cpu_dsq(prev_cpu)`) with vtime ordering.

4. **Migration attempt** (`task_should_migrate`): If `select_cpu` was skipped (e.g., sticky tasks mode, or the task was already running), attempt `pick_idle_cpu` again from enqueue context. If an idle CPU is found, dispatch to its per-CPU DSQ and kick it.

5. **Fallback**: Dispatch to the per-node DSQ (`node_dsq(prev_cpu)`) with vtime ordering. If `select_cpu` was skipped, kick `prev_cpu` to wake it from idle.

### `bpfland_dispatch` (ops.dispatch)

Called when a CPU needs work. Uses a deadline-comparison approach:

1. **Throttle check**: If `cpus_throttled` is true (CPU throttling active), return immediately to let the CPU go idle.

2. **Peek** both the per-CPU DSQ (`cpu_dsq(cpu)`) and the per-node DSQ (`node_dsq(cpu)`) to get the head task from each.

3. **Compare deadlines** using `is_deadline_min(q, p)` (compares `dsq_vtime` values). Consume from the DSQ with the earlier deadline first, falling back to the other if the first fails.

4. **Keep-running optimization**: If no task was consumed from either DSQ and the previously running task (`prev`) is still queued and eligible to continue (checked by `keep_running`), replenish its time slice via `prev->scx.slice = task_slice(prev, cpu)`. This avoids unnecessary context switches. `keep_running` returns false if the task is on a contended SMT core (sibling busy) and there are fully idle cores available elsewhere.

### `bpfland_running` (ops.running)

Called when a task starts executing on a CPU:

1. Atomically increment `nr_running`.
2. Record `last_run_at = bpf_ktime_get_ns()` in the task context.
3. Call `update_cpu_load()` to refresh the CPU's dynamic cpufreq performance level.
4. Advance `vtime_now` if the task's `dsq_vtime` is ahead of the global clock.

### `bpfland_stopping` (ops.stopping)

Called when a task is descheduled:

1. Atomically decrement `nr_running`.
2. Compute `slice = now - tctx->last_run_at` (actual CPU time used).
3. Update `avg_runtime` via EWMA: `avg_runtime = old * 0.75 + slice * 0.25`.
4. Compute `delta_vtime = scale_by_task_weight_inverse(p, slice)` and add to both `p->scx.dsq_vtime` (total vruntime) and `tctx->awake_vtime` (partial vruntime since last sleep).
5. Update `cpu_ctx.tot_runtime` with the elapsed wall time.

### `bpfland_runnable` (ops.runnable)

Called when a task becomes runnable (wakeup):

1. Reset `awake_vtime = 0` (fresh sleep-wake cycle).
2. Update `wakeup_freq` using EWMA of `(100ms / interval_since_last_wakeup)`, capped at `MAX_WAKEUP_FREQ` (64).
3. Record `last_woke_at = now`.

### `bpfland_enable` (ops.enable)

Called when a task is first associated with the scheduler. Initializes `p->scx.dsq_vtime = vtime_now` so new tasks start at the current global vruntime (neither advantaged nor disadvantaged).

### `bpfland_init_task` (ops.init_task)

Allocates task-local storage (`task_ctx`) via `bpf_task_storage_get` with `BPF_LOCAL_STORAGE_GET_F_CREATE`.

## Key Mechanisms

### Deadline Computation (`task_dl`)

The core scheduling priority is determined by the **deadline** formula:

```
deadline = dsq_vtime + awake_vtime
```

Where:
- `dsq_vtime` is the task's total accumulated vruntime, inversely scaled by weight (higher-priority tasks accumulate vruntime more slowly).
- `awake_vtime` is the vruntime accumulated since the last sleep, also weight-inverse-scaled.

**Vruntime credit for sleepers:** Before computing the deadline, `task_dl` clamps `dsq_vtime` from below:

```
vtime_min = vtime_now - scale_by_task_weight(p, slice_lag * lag_scale)
```

If `dsq_vtime < vtime_min`, it is raised to `vtime_min`. This limits the maximum vruntime credit a sleeping task can accumulate to `slice_lag` (default 40ms), preventing long-sleeping tasks from starving others upon wakeup.

**Wakeup frequency scaling (`lag_scale`):** The `lag_scale` factor amplifies the credit for tasks that wake up frequently:
- `lag_scale = max(wakeup_freq, 1)` initially.
- A **queue pressure** factor dampens it: `lag_scale = lag_scale * q_thresh / (q_thresh + nr_queued)`, where `q_thresh = STARVATION_THRESH / slice_max`.
- Emergency clamp: if `nr_queued * slice_max >= STARVATION_THRESH` (500ms worth of queued work), `lag_scale` is forced to 1, effectively disabling interactive boosting under heavy load.

The `awake_vtime` is also capped: `awake_vtime = min(awake_vtime, scale_by_task_weight_inverse(p, slice_lag))`.

### Time Slice Computation (`task_slice`)

```
slice = scale_by_task_weight(p, slice_max) / max(nr_wait, 1)
slice = max(slice, slice_min)
```

Where `nr_wait` is the sum of tasks queued on the CPU's per-CPU DSQ and per-node DSQ. Higher-weight tasks get proportionally larger slices, and slices shrink under contention. The result is never smaller than `slice_min` (default 0, meaning no minimum unless configured).

### Sticky Tasks

Tasks with `avg_runtime < 10us` (very short scheduling bursts, implying high reschedule frequency) are considered "sticky" when `sticky_tasks` is enabled. These are dispatched directly to `SCX_DSQ_LOCAL` (the current CPU's local queue), bypassing the shared per-CPU and per-node DSQs entirely. This reduces lock contention on shared queues for workloads with extremely high context-switch rates.

### EWMA (`calc_avg`)

Used for `avg_runtime` and `wakeup_freq` smoothing:

```
new_avg = old_val * 0.75 + new_val * 0.25
```

Implemented as `(old_val - (old_val >> 2)) + (new_val >> 2)` to avoid floating point.

### CPU Throttling

When `throttle_us > 0`, a BPF timer (`throttle_timerfn`) alternates between two states:

1. **Running phase** (duration = `slice_max`): CPUs run normally.
2. **Throttled phase** (duration = `throttle_ns`): `cpus_throttled` is set, `ops.dispatch()` returns without dispatching, and CPUs go idle.

The timer sends `SCX_KICK_PREEMPT` IPIs to interrupt running tasks before the throttle phase, and `SCX_KICK_IDLE` IPIs to wake CPUs after the throttle phase. This implements a duty-cycle approach for power saving.

### Starvation Prevention

The scheduler sets `timeout_ms = STARVATION_MS = 5000` (5 seconds). If any task waits longer than this in a DSQ without being dispatched, the kernel triggers a watchdog error.

The deadline computation's emergency clamp (disabling interactive boosting when queues are deep) also serves as a starvation mitigation mechanism.

## Topology Awareness

### SMT (Simultaneous Multi-Threading)

When `smt_enabled` is true (detected from `Topology::smt_enabled` and not disabled via `--disable-smt`):

- Userspace initializes each CPU's SMT sibling mask via the `enable_sibling_cpu` BPF syscall program, populating `cpu_ctx.smt`.
- `smt_sibling(cpu)` returns the first CPU in the SMT sibling mask.
- `is_smt_contended(cpu)` checks if the sibling SMT CPU is busy AND there are other idle CPUs available. If so, the task may benefit from migrating to a fully idle core.
- Idle CPU selection prefers full-idle SMT cores (where all siblings are idle) before partially-idle cores, using `get_idle_smtmask()` / `scx_bpf_get_idle_smtmask_node()`.
- The `keep_running` function in `ops.dispatch()` will decline to let a task continue running on an SMT-contended core, giving it a chance to migrate.

### NUMA

When `numa_enabled` is true (detected from topology having > 1 non-empty NUMA node, and not disabled via `--disable-numa`):

- The `SCX_OPS_BUILTIN_IDLE_PER_NODE` flag is set, enabling per-NUMA-node idle CPU tracking in the kernel.
- `get_idle_cpumask(cpu)` and `get_idle_smtmask(cpu)` return NUMA-local idle masks via `scx_bpf_get_idle_cpumask_node()` / `scx_bpf_get_idle_smtmask_node()`.
- Per-node DSQs are created with NUMA affinity: `scx_bpf_create_dsq(dsq_id, node)`.
- `node_dsq(cpu)` maps a CPU to its NUMA node's shared DSQ.

When NUMA is disabled, the global idle masks are used and per-node DSQs still exist but NUMA locality is not enforced for idle CPU selection.

### Heterogeneous CPU Capacity (big.LITTLE / Hybrid)

- Userspace sorts all CPUs by `cpu_capacity` in descending order and writes the sorted list to `rodata.preferred_cpus[]` and per-CPU capacities to `rodata.cpu_capacity[]`.
- `is_cpu_faster(this_cpu, that_cpu)` compares capacities.
- In `pick_idle_cpu`, when the waker's CPU is faster than the wakee's previous CPU, the scheduler attempts to migrate the wakee to the faster CPU (unless both share an LLC and the previous CPU is fully idle at the SMT level).
- The `preferred_idle_scan` mode performs a linear scan through CPUs in capacity-descending order, naturally preferring faster cores.

### Primary Domain

The primary domain is a cpumask defining the preferred subset of CPUs for dispatching. It is configured via `--primary-domain` (alias `-m`) with these modes:

| Value | Behavior |
|-------|----------|
| `auto` (default) | Auto-detect from power profile. Powersave profile selects Little cores; all other profiles select all CPUs. |
| `performance` | Select Big cores only (both Turbo and non-Turbo). |
| `powersave` | Select Little cores only. |
| `turbo` | Select Turbo Big cores only. |
| `all` | All CPUs in the primary domain. |
| `none` | Empty primary domain (no prioritization). |
| hex mask | Explicit cpumask (e.g., `0xff`). |

When `primary_all` is true (all CPUs are in the primary domain), the primary domain filter is skipped for efficiency.

During idle CPU selection, the scheduler first tries to find an idle CPU within the primary domain. Only if no idle CPU is found there does it overflow to the full set of available CPUs.

## Userspace Side

### Scheduler Struct and Lifecycle

The `Scheduler` struct in `main.rs` holds:

| Field | Description |
|-------|-------------|
| `skel` | The loaded BPF skeleton (`BpfSkel`). |
| `struct_ops` | The attached `struct_ops` link (`Option<libbpf_rs::Link>`). |
| `opts` | Reference to parsed CLI options. |
| `topo` | CPU topology (`scx_utils::Topology`). |
| `power_profile` | Current system power profile (`PowerProfile`). |
| `stats_server` | Stats reporting server (`StatsServer<(), Metrics>`). |
| `user_restart` | Flag indicating the scheduler should restart (e.g., power profile changed). |

**Initialization (`Scheduler::init`):**

1. Discover CPU topology via `Topology::new()`.
2. Determine SMT status, NUMA node count, and primary domain.
3. Open, configure, and load the BPF skeleton with all `rodata` parameters.
4. Set scheduler flags: `SCX_OPS_ENQ_EXITING`, `SCX_OPS_ENQ_LAST`, `SCX_OPS_ENQ_MIGRATION_DISABLED`, `SCX_OPS_ALLOW_QUEUED_WAKEUP`, and conditionally `SCX_OPS_BUILTIN_IDLE_PER_NODE`.
5. Initialize primary domain via `enable_primary_cpu` BPF syscall program calls.
6. Initialize cpufreq performance level.
7. Initialize SMT sibling masks via `enable_sibling_cpu` BPF syscall program calls.
8. Attach the struct_ops and launch the stats server.

**Main loop (`Scheduler::run`):**

Runs until shutdown signal or BPF exit. On each iteration (1-second timeout):

1. Check for power profile changes (`refresh_sched_domain`). If the profile changed and `--primary-domain auto` is set, trigger a restart by setting `user_restart = true`.
2. Service stats requests from the stats server.

On drop, CPU idle QoS resume latency is restored to original values.

### Power Profile Auto-Detection

`fetch_power_profile()` detects the system's current power profile (Powersave, Balanced, Performance, Unknown). When `--primary-domain auto` is used, the scheduler maps:

- **Powersave** profile -> Little cores as primary domain.
- **Balanced / Performance / Unknown** -> all CPUs as primary domain.

If the power profile changes at runtime, the scheduler restarts to reconfigure the primary domain.

### CPU Frequency Management

The `cpufreq_perf_lvl` BPF variable controls CPU frequency hints:

| Value | Meaning |
|-------|---------|
| `< 0` | Dynamic mode: `update_cpu_load()` computes per-CPU utilization and calls `scx_bpf_cpuperf_set()` with a utilization-proportional value. If utilization >= 75%, perf is set to maximum (`SCX_CPUPERF_ONE`). |
| `0` | Minimum frequency (used with powersave profile). |
| `1024` (`SCX_CPUPERF_ONE`) | Maximum frequency (default for non-powersave, non-auto profiles). |

Dynamic mode (`--cpufreq` flag) uses the formula:

```
perf_lvl = min(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE)
if perf_lvl >= 75% of SCX_CPUPERF_ONE:
    perf_lvl = SCX_CPUPERF_ONE
```

### Metrics and Statistics

The `Metrics` struct tracks:

| Metric | Description |
|--------|-------------|
| `nr_running` | Current number of running tasks. |
| `nr_cpus` | Number of online CPUs. |
| `nr_kthread_dispatches` | Count of per-CPU kthread direct dispatches. |
| `nr_direct_dispatches` | Count of direct dispatches (idle CPU found, sticky tasks, per-CPU tasks). |
| `nr_shared_dispatches` | Count of dispatches to the per-node shared DSQ. |

Stats are reported as deltas (difference from previous sample) via the `scx_stats` framework and can be viewed with `--stats <interval>` or `--monitor <interval>`.

### CLI Options Summary

| Option | Flag | Default | Description |
|--------|------|---------|-------------|
| `--slice-us` | `-s` | 1000 | Maximum time slice (microseconds). |
| `--slice-min-us` | `-L` | 0 | Minimum time slice (microseconds). |
| `--slice-us-lag` | `-l` | 40000 | Maximum vruntime credit for sleepers (microseconds). |
| `--throttle-us` | `-t` | 0 | CPU idle injection period (0 = disabled). |
| `--idle-resume-us` | `-I` | -1 | CPU idle QoS resume latency (-1 = disabled). |
| `--local-pcpu` | `-p` | false | Prioritize per-CPU tasks via `SCX_DSQ_LOCAL`. |
| `--local-kthreads` | `-k` | false | Prioritize per-CPU kthreads via `SCX_DSQ_LOCAL`. |
| `--no-wake-sync` | `-w` | false | Disable synchronous wakeup optimization. |
| `--sticky-tasks` | `-S` | false | Pin high-frequency tasks to current CPU. |
| `--primary-domain` | `-m` | auto | Primary CPU domain specification. |
| `--preferred-idle-scan` | `-P` | false | Use capacity-ranked linear idle CPU scan. |
| `--disable-smt` | | false | Disable SMT-aware scheduling. |
| `--disable-numa` | | false | Disable NUMA-aware scheduling. |
| `--cpufreq` | `-f` | false | Enable dynamic CPU frequency scaling. |
| `--debug` | `-d` | false | Enable BPF debug output via `bpf_printk`. |

## SCX Ops Flags

The scheduler registers the following `SCX_OPS` flags:

| Flag | Purpose |
|------|---------|
| `SCX_OPS_ENQ_EXITING` | Enqueue tasks that are exiting. |
| `SCX_OPS_ENQ_LAST` | Enqueue the last runnable task (enables the keep-running optimization in `ops.dispatch`). |
| `SCX_OPS_ENQ_MIGRATION_DISABLED` | Enqueue tasks even when migration is disabled. |
| `SCX_OPS_ALLOW_QUEUED_WAKEUP` | Allow wakeups while a task is already queued. |
| `SCX_OPS_BUILTIN_IDLE_PER_NODE` | Enable per-NUMA-node idle CPU tracking (only when NUMA is enabled). |

## BPF Syscall Programs

Two BPF programs are exposed as syscalls for userspace to invoke during initialization:

- **`enable_primary_cpu(cpu_arg)`**: Adds a CPU to the `primary_cpumask`. Passing `cpu_id < 0` clears the entire mask (used for reset before reconfiguration).

- **`enable_sibling_cpu(domain_arg)`**: Adds `sibling_cpu_id` to the SMT sibling cpumask of `cpu_id` in `cpu_ctx.smt`.

These are invoked via `prog.test_run()` from the Rust userspace during `Scheduler::init`.
