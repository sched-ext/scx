# scx_tickless
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_tickless` is a server-oriented sched_ext scheduler designed for cloud computing,
virtualization, and high-performance computing workloads. Its core idea is to **eliminate
the scheduler tick on worker CPUs** by funneling all scheduling decisions through a
small pool of **primary CPUs**. Worker CPUs run tasks with `SCX_SLICE_INF` (infinite
time slices), so the kernel never needs to interrupt them for scheduling purposes.
Preemption only occurs when a primary CPU detects contention and explicitly converts
a worker's infinite slice to a finite one.

The scheduler is authored by Andrea Righi (NVIDIA) and is licensed under GPL-2.0. It
is still considered **experimental** and is not recommended for latency-sensitive
workloads, partly because the required `nohz_full` kernel boot parameter introduces
syscall overhead.

**Key design goals:**

- Minimize OS noise on worker CPUs (important for HPC, virtualization, real-time guests)
- Concentrate scheduling overhead onto a dedicated set of primary CPUs
- Provide EEVDF-inspired deadline-based fairness using vruntime and exec_vruntime
- Allow tunable tick frequency on primary CPUs to balance responsiveness vs. overhead

## Architecture / Design

The scheduler partitions the system's CPUs into two roles:

| Role | Description | Tick Behavior |
|------|-------------|---------------|
| **Primary CPUs** | Handle scheduling decisions, run BPF timers, distribute tasks | Normal ticking (at `--frequency` or `CONFIG_HZ`) |
| **Worker (tickless) CPUs** | Run application workloads | Tickless (`SCX_SLICE_INF`); only interrupted when contended |

All tasks are enqueued into a single **global shared DSQ** (`SHARED_DSQ`, ID 0) ordered
by deadline (vtime). Primary CPUs periodically scan the shared DSQ and distribute tasks
to idle worker CPUs. When a worker CPU has no contention, its running task keeps its
infinite time slice and runs undisturbed.

### Constants and Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_CPUS` | 1024 | Maximum supported CPUs (BPF map size) |
| `SHARED_DSQ` | 0 | The single global dispatch queue ID |
| `SCHEDULER_NAME` | `"scx_tickless"` | Identifier string |
| `timeout_ms` | 5000 | Watchdog timeout for the BPF scheduler |

### Scheduler Flags

The scheduler sets three `SCX_OPS` flags at load time:

- **`SCX_OPS_ENQ_LAST`** -- Requests that the kernel calls `ops.dispatch()` when a CPU
  is about to go idle, enabling the scheduler to keep tasks running via infinite slices.
- **`SCX_OPS_ENQ_MIGRATION_DISABLED`** -- Ensures that tasks with migration disabled
  are still enqueued through `ops.enqueue()` so the scheduler can handle per-CPU tasks
  properly.
- **`SCX_OPS_ALLOW_QUEUED_WAKEUP`** -- Allows wakeup callbacks while a task is already
  queued, enabling sync wakeup optimizations.

## Primary / Worker CPU Model

### Primary CPU Selection

By default, only **CPU 0** is the primary CPU (actually, the CPU with the lowest
capacity is selected when `--primary-domain 0` is specified). The user can override
this with `--primary-domain CPUMASK` to designate multiple primary CPUs.

In the userspace `Scheduler::init()`, CPUs are sorted by capacity in **descending**
order. When `--primary-domain` is `0x0` (autodetect), the **slowest CPU** (last in the
sorted list) is chosen as the primary, on the assumption that sacrificing the
lowest-capacity core for scheduling duties is the best trade-off.

The sorted CPU list is written into the `preferred_cpus[]` BPF array (highest capacity
first). This array is used by `dispatch_all_cpus()` to prefer dispatching to the
fastest idle CPUs first.

### Primary Domain Initialization

The primary domain is configured via a BPF syscall program `enable_primary_cpu()`:

1. Userspace calls `enable_primary_cpu(-1)` to clear the `primary_cpumask`.
2. For each CPU in the domain, userspace calls `enable_primary_cpu(cpu_id)` to set
   the corresponding bit.

The `primary_cpumask` is stored as a `__kptr` BPF cpumask using `bpf_cpumask_create()`
and accessed under RCU protection.

Before attaching the scheduler, userspace pins the main thread to the first primary
CPU using `set_thread_affinity()`. This is required because `tickless_init()` calls
`init_timer(bpf_get_smp_processor_id())`, and the timer must start on a primary CPU.
After attachment, affinity is reset to all CPUs.

### Helper Functions

- **`is_primary_cpu(cpu)`** -- Tests whether `cpu` is in the `primary_cpumask` under
  RCU read lock.
- **`pick_primary_cpu()`** -- Returns a random CPU from the primary domain using
  `bpf_cpumask_any_distribute()`.

## Scheduling Hot Path (BPF Callbacks)

The scheduler registers the following `sched_ext` operations:

### `tickless_select_cpu(p, prev_cpu, wake_flags)`

Called when a task is waking up to select a target CPU.

- **Sync wakeups** (`SCX_WAKE_SYNC` flag, waker not exiting): Returns the waker's
  current CPU (`bpf_get_smp_processor_id()`), treating the wakeup like a function call
  to maximize cache locality.
- **All other wakeups**: Routes the task to a **random primary CPU** via
  `pick_primary_cpu()`. The selected CPU's idle state is cleared with
  `scx_bpf_test_and_clear_cpu_idle()` to prevent it from being picked again during
  distribution. This ensures wake-up processing noise stays on primary CPUs.

### `tickless_enqueue(p, enq_flags)`

Inserts the task into the `SHARED_DSQ` ordered by deadline using
`scx_bpf_dsq_insert_vtime()`. The deadline is computed by `task_deadline()`. The time
slice is set to `SCX_SLICE_INF`, meaning the task will not be preempted by the normal
tick mechanism.

### `tickless_dispatch(cpu, prev)`

Called when a CPU needs work. Behavior differs by CPU role:

**Primary CPU path:**
1. Calls `dispatch_all_cpus(true, true)` -- tries to distribute queued tasks to idle
   worker CPUs, preferring **full-idle SMT cores** first.
2. If tasks remain, calls `dispatch_all_cpus(false, true)` -- distributes to any idle
   worker CPU.
3. Falls through to consume from `SHARED_DSQ` directly (primary CPUs also run tasks
   as a last resort).

**All CPUs (including primary):**
1. Attempts `scx_bpf_dsq_move_to_local(SHARED_DSQ)` to consume a task directly.
   Increments `nr_direct_dispatches`.
2. If no task is available and the previous task (`prev`) is still queued
   (`SCX_TASK_QUEUED` flag), re-grants it `SCX_SLICE_INF` to keep it running
   undisturbed.

### `tickless_runnable(p, enq_flags)`

Called when a task becomes runnable. Resets `tctx->exec_runtime` to 0, beginning a
new accounting period for the task's execution burst.

### `tickless_running(p)`

Called when a task starts executing on a CPU:

1. Records `tctx->last_run_at = scx_bpf_now()` for later slice accounting.
2. Advances the global `vtime_now` to `max(vtime_now, tctx->deadline)`, ensuring the
   global virtual time monotonically increases.

### `tickless_tick(p)`

Simply increments the `nr_ticks` counter. This callback fires on CPUs that still
receive scheduler ticks (primarily the primary CPUs, or worker CPUs before their tick
is suppressed by `nohz_full`).

### `tickless_stopping(p, runnable)`

Called when a task is about to stop running (yield, preempt, or block):

1. Computes the consumed time slice: `slice = scx_bpf_now() - tctx->last_run_at`.
2. Accumulates `exec_runtime += slice`, capped at `NSEC_PER_SEC` (1 second) to prevent
   extreme de-prioritization of CPU-bound tasks.
3. Updates the task's deadline: `tctx->deadline += scale_by_task_weight_inverse(p, slice)`.

### `tickless_enable(p)`

Called when a task enters the BPF scheduler. Initializes the task's deadline to the
current global `vtime_now` so new tasks start at a fair position.

### `tickless_init_task(p, args)`

Called at task creation. Allocates per-task storage (`task_ctx`) via
`bpf_task_storage_get()` with `BPF_LOCAL_STORAGE_GET_F_CREATE`.

### `tickless_init()`

Scheduler initialization (sleepable context):

1. Creates the `SHARED_DSQ` with `scx_bpf_create_dsq(SHARED_DSQ, -1)`.
2. Starts the BPF timer on the current CPU (which was pinned to a primary CPU by
   userspace) via `init_timer()`.

### `tickless_exit(ei)`

Records exit info via `UEI_RECORD(uei, ei)` for userspace to retrieve the exit reason.

## Task Distribution Algorithm

The core distribution logic lives in two functions:

### `dispatch_cpu(cpu, from_dispatch)`

Tries to move a single task from `SHARED_DSQ` to a specific CPU's local DSQ:

1. Iterates over tasks in `SHARED_DSQ` (ordered by deadline/vtime).
2. For each task, checks CPU affinity (`bpf_cpumask_test_cpu(cpu, p->cpus_ptr)`).
3. **Contention check**: Calls `scx_bpf_test_and_clear_cpu_idle(cpu)`.
   - If the CPU is **not idle** and the task is **not a per-CPU task** (`nr_cpus_allowed > 1`
     and migration not disabled), stops immediately -- the goal is to avoid contention
     so the currently running task keeps its infinite slice.
   - If the task **is** a per-CPU task (`is_pcpu_task()`), dispatches regardless of idle
     state to prevent starvation, since the task has no alternative CPU.
4. Moves the task with `__COMPAT_scx_bpf_dsq_move()` to `SCX_DSQ_LOCAL_ON | cpu`.
5. Tracks the dispatch source (`nr_primary_dispatches` or `nr_timer_dispatches`).

### `dispatch_all_cpus(do_idle_smt, from_dispatch)`

Distributes tasks from `SHARED_DSQ` across all CPUs:

1. If `SHARED_DSQ` is empty, returns immediately.
2. If `do_idle_smt` is true and SMT is enabled, obtains the idle SMT mask via
   `scx_bpf_get_idle_smtmask()` to prefer CPUs where the entire SMT core is idle.
3. Iterates through `preferred_cpus[]` (highest capacity first):
   - Skips CPUs not in the SMT idle mask (if applicable).
   - Kicks the CPU with `scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)`.
   - **Skips primary CPUs** -- they are kept as a last resort for running tasks.
   - Calls `dispatch_cpu(cpu, from_dispatch)` to attempt task placement.
   - Stops early if `SHARED_DSQ` becomes empty.

The two-pass strategy (first full-idle SMT cores, then any idle CPU) maximizes
cache efficiency and minimizes sibling interference.

## Deadline / Vruntime Scheduling

### Per-Task Context (`task_ctx`)

```c
struct task_ctx {
    u64 last_run_at;     // Timestamp of last run start (ns)
    u64 exec_runtime;    // Accumulated runtime in current runnable period
    u64 deadline;        // EEVDF-inspired deadline = vruntime + exec_vruntime
};
```

### Deadline Computation (`task_deadline()`)

The deadline is an EEVDF-inspired metric combining two components:

- **`vruntime`** (stored as `tctx->deadline`): Total accumulated runtime scaled
  inversely by task weight. Ensures long-term fairness -- higher-weight (higher-priority)
  tasks accumulate vruntime more slowly.
- **`exec_vruntime`**: The weight-inverse-scaled `exec_runtime` accumulated since the
  task last became runnable. Tasks that frequently block (latency-sensitive) accumulate
  less exec_vruntime and thus get shorter deadlines, resulting in earlier dispatch.

```
effective_deadline = tctx->deadline + scale_by_task_weight_inverse(p, tctx->exec_runtime)
```

**Idle task budget limiting**: To prevent sleeping tasks from accumulating unbounded
vtime credit, the deadline is clamped:

```c
vtime_min = vtime_now - slice_ns;
if (time_before(tctx->deadline, vtime_min))
    tctx->deadline = vtime_min;
```

This limits the maximum "catch-up" budget to one `slice_ns` worth of vtime, with
higher-weight tasks implicitly getting more budget due to the inverse weight scaling.

### Global Vruntime (`vtime_now`)

A single global variable tracking the system-wide virtual time. Updated in
`tickless_running()` to `max(vtime_now, tctx->deadline)`, ensuring monotonic progress.

## Tickless Operation

### How Tickless Execution Works

1. Tasks are dispatched with `SCX_SLICE_INF` (infinite time slice).
2. With `nohz_full` enabled in the kernel, a CPU running a single task with an infinite
   slice will have its scheduler tick suppressed entirely.
3. The task runs undisturbed until one of:
   - The BPF timer on a primary CPU detects contention and converts the slice to finite.
   - The task voluntarily yields/blocks.
   - A per-CPU task must run on that CPU.

### BPF Timer (`sched_timerfn`)

A periodic BPF timer runs on primary CPUs at the configured frequency:

1. **Task distribution**: Calls `dispatch_all_cpus()` (two-pass: SMT-idle first, then
   any idle) to place queued tasks onto worker CPUs.
2. **Preemption scan**: Iterates over all CPUs and for each non-idle CPU:
   - Checks if there are tasks waiting in the CPU's local DSQ or the shared DSQ.
   - If the running task has `SCX_SLICE_INF`, converts it to a finite `slice_ns`,
     making it preemptible. Increments `nr_preemptions`.
3. **Re-arms** itself with `bpf_timer_start(timer, tick_interval_ns(), 0)`.

The timer frequency defaults to `CONFIG_HZ` but can be overridden with `--frequency`.
The tick interval is computed as:

```c
static inline u64 tick_interval_ns(void) {
    u64 freq = tick_freq ? : CONFIG_HZ;
    return NSEC_PER_SEC / freq;
}
```

### Per-CPU Task Handling

Per-CPU tasks (those with `nr_cpus_allowed == 1` or migration disabled) receive special
treatment. Since they cannot migrate, the scheduler dispatches them even if their
target CPU is busy. The currently running task on that CPU will eventually be preempted
when the BPF timer converts its infinite slice to a finite one.

This is checked by `is_pcpu_task()`:
```c
static inline bool is_pcpu_task(const struct task_struct *p) {
    return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}
```

## Userspace Side

### Command-Line Interface

The userspace component is a Rust binary using `clap` for argument parsing.

| Flag | Default | Description |
|------|---------|-------------|
| `--primary-domain CPUMASK` (`-m`) | `0` (autodetect) | Hex bitmask of primary CPUs |
| `--slice-us USEC` (`-s`) | `20000` (20ms) | Max scheduling slice when contended |
| `--frequency FREQ` (`-f`) | `0` (CONFIG_HZ) | Primary CPU timer tick frequency |
| `--nosmt` (`-n`) | false | Disable SMT topology awareness |
| `--stats INTERVAL` | None | Enable periodic stats output |
| `--monitor INTERVAL` | None | Stats-only mode (no scheduler) |
| `--verbose` (`-v`) | false | Enable verbose/libbpf debug output |
| `--version` (`-V`) | false | Print version and exit |
| `--help-stats` | None | Describe available statistics |
| `--exit-dump-len LEN` | 0 | Exit debug dump buffer length |

### Initialization Flow (`Scheduler::init`)

1. **Topology discovery**: Reads system topology via `Topology::new()`, determines SMT
   status.
2. **nohz_full check**: Reads `/sys/devices/system/cpu/nohz_full` and warns if not
   enabled (`is_nohz_enabled()`).
3. **CPU capacity sorting**: Sorts CPUs by capacity descending, writes to BPF
   `preferred_cpus[]`.
4. **Primary domain setup**: Parses `--primary-domain` cpumask. If `0x0`, selects the
   lowest-capacity CPU.
5. **BPF skeleton open/load**: Configures `rodata` (slice_ns, tick_freq, smt_enabled,
   nr_cpu_ids, preferred_cpus), sets scheduler flags.
6. **Thread affinity**: Pins to the first primary CPU so `tickless_init()` starts the
   BPF timer there.
7. **Primary domain configuration**: Calls `enable_primary_cpu()` BPF syscall program
   for each CPU in the domain.
8. **Attach**: Attaches the struct_ops, launches the stats server, resets thread affinity.

### Main Loop (`Scheduler::run`)

The main loop runs until Ctrl-C or scheduler exit:

1. Waits on the stats server request channel with a 1-second timeout.
2. On stats request, reads BPF BSS data counters and sends `Metrics` to the stats
   server.
3. On shutdown or exit, detaches struct_ops and reports exit info via `uei_report!`.

The scheduler supports automatic restart: if `should_restart()` returns true on the
`UserExitInfo`, the outer loop in `main()` re-initializes and re-attaches the scheduler.

## Statistics and Monitoring

### Metrics (`stats.rs`)

The `Metrics` struct tracks five counters, all read from BPF BSS data:

| Metric | BPF Variable | Description |
|--------|-------------|-------------|
| `nr_ticks` | `nr_ticks` | Total scheduler tick callbacks fired |
| `nr_preemptions` | `nr_preemptions` | Times a task's infinite slice was converted to finite |
| `nr_direct_dispatches` | `nr_direct_dispatches` | Tasks consumed directly from SHARED_DSQ by a CPU |
| `nr_primary_dispatches` | `nr_primary_dispatches` | Tasks distributed by primary CPUs in `ops.dispatch()` |
| `nr_timer_dispatches` | `nr_timer_dispatches` | Tasks distributed by the BPF timer callback |

Stats are reported as **deltas** between collection intervals via `Metrics::delta()`.

The output format is:
```
[scx_tickless] ticks -> N     preempts -> N     dispatch -> d: N     p: N     t: N
```

The stats server uses `scx_stats` infrastructure with a request/response channel
pattern. `--monitor` mode runs only the stats client without launching the scheduler.

## BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `cpu_ctx_stor` | `BPF_MAP_TYPE_ARRAY` | `u32` (CPU id) | `struct cpu_ctx` | Stores per-CPU BPF timers |
| `task_ctx_stor` | `BPF_MAP_TYPE_TASK_STORAGE` | `int` | `struct task_ctx` | Per-task scheduling state (deadline, runtime) |

The `cpu_ctx_stor` map is sized to `MAX_CPUS` (1024) entries. The `task_ctx_stor` uses
`BPF_F_NO_PREALLOC` to allocate storage on demand.

## Data Flow Summary

```
Task wakes up
    |
    v
tickless_select_cpu() --> route to primary CPU (or waker's CPU for sync wakeup)
    |
    v
tickless_enqueue() --> insert into SHARED_DSQ ordered by deadline (SCX_SLICE_INF)
    |
    +-----> Primary CPU's tickless_dispatch() distributes to idle worker CPUs
    |           |
    |           v
    |       dispatch_all_cpus() --> iterate preferred_cpus[], move tasks to
    |                               local DSQs of idle worker CPUs
    |
    +-----> BPF timer (sched_timerfn) on primary CPU:
    |           |
    |           +-- distribute queued tasks to idle CPUs
    |           +-- scan for contention: convert SCX_SLICE_INF -> slice_ns
    |
    +-----> Worker CPU's tickless_dispatch() consumes directly from SHARED_DSQ
                |
                v
            Task runs with SCX_SLICE_INF (no tick interrupts)
```

## Design Trade-offs

1. **Single global queue**: All tasks share one DSQ. This simplifies the design but
   creates a serialization point. The scheduler mitigates this by having primary CPUs
   proactively distribute tasks rather than having all CPUs contend on the shared queue.

2. **Primary CPU sacrifice**: Dedicating CPUs to scheduling reduces available compute
   capacity. The default of one CPU is minimal, but large systems may need more to
   avoid becoming a bottleneck.

3. **Latency vs. noise**: The `--frequency` parameter trades off responsiveness (how
   quickly contention is detected) against scheduling overhead on primary CPUs. Lower
   frequencies mean less noise but slower preemption of contended worker CPUs.

4. **nohz_full dependency**: True tickless operation requires `nohz_full` kernel boot
   parameter, which adds syscall overhead system-wide. This makes the scheduler
   unsuitable for syscall-heavy latency-sensitive workloads.

5. **Capacity-ordered dispatch**: By iterating `preferred_cpus[]` (fastest first), the
   scheduler preferentially places tasks on the highest-capacity cores, which is
   beneficial for heterogeneous systems (e.g., big.LITTLE).
