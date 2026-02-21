# scx_rustland
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_rustland` is a `sched_ext` scheduler that delegates **all** scheduling decisions to user space. It is built on top of `scx_rustland_core`, a reusable BPF component that abstracts the low-level `sched_ext` plumbing (ring buffers, DSQ management, idle CPU selection) so that the user-space Rust component only needs to implement the scheduling policy itself.

The scheduler is designed to **prioritize interactive workloads over background CPU-intensive workloads**. Its primary use cases are low-latency interactive applications such as gaming, video conferencing, and live streaming. It also serves as a readable template for developers who want to experiment with custom scheduling policies implemented entirely in Rust.

The key trade-off is performance: offloading every scheduling decision to user space incurs overhead from ring buffer communication, context switches to/from the scheduler process, and memory locking. For performance-critical production use, other sched_ext schedulers are likely superior. However, the user-space model enables seamless integration with sophisticated libraries, tracing tools, and external services (e.g., AI-driven scheduling).

**Author:** Andrea Righi (`andrea.righi@linux.dev`)
**License:** GPL v2

## Architecture / Design

### High-Level Data Flow

```
 Kernel (BPF)                          User Space (Rust)
 ============                          =================

 Task becomes    ops.enqueue()
 runnable  -----> queued_task_ctx ---> [BPF_MAP_TYPE_RINGBUF "queued"]
                                            |
                                            | dequeue_task()
                                            v
                                      Scheduler::drain_queued_tasks()
                                            |
                                            | update_enqueued() computes
                                            | deadline = vruntime + exec_runtime
                                            v
                                      BTreeSet<Task> (ordered by deadline)
                                            |
                                            | dispatch_task()
                                            v
                  dispatched_task_ctx <-- [BPF_MAP_TYPE_USER_RINGBUF "dispatched"]
                        |
                        | ops.dispatch() -> handle_dispatched_task()
                        v
                  dispatch_task() in BPF
                  inserts into per-CPU DSQ or SHARED_DSQ
```

The architecture follows a strict **producer/consumer** pattern with two ring buffers:

| Ring Buffer  | Type                      | Direction              | Content                   |
|-------------|---------------------------|------------------------|---------------------------|
| `queued`    | `BPF_MAP_TYPE_RINGBUF`    | BPF --> User space     | `queued_task_ctx` structs |
| `dispatched`| `BPF_MAP_TYPE_USER_RINGBUF`| User space --> BPF    | `dispatched_task_ctx` structs |

Both ring buffers are sized to hold `MAX_ENQUEUED_TASKS` (4096) entries.

### Dispatch Queues (DSQs)

The scheduler creates three categories of DSQs:

| DSQ             | ID                  | Purpose                                                     |
|-----------------|---------------------|-------------------------------------------------------------|
| Per-CPU DSQs    | `0` .. `MAX_CPUS-1` | One DSQ per CPU for targeted dispatch                       |
| `SHARED_DSQ`    | `MAX_CPUS` (1024)   | Global shared DSQ; tasks run on the first available CPU     |
| `SCHED_DSQ`     | `MAX_CPUS + 1` (1025)| Dedicated DSQ for the user-space scheduler process itself  |

The `SCHED_DSQ` ensures the scheduler process runs in a **bursty** pattern: tasks are queued, the scheduler process runs to dispatch them, and once dispatched tasks exhaust their time slices, the scheduler is invoked again.

### Key Constants

| Constant              | Value         | Description                                           |
|-----------------------|---------------|-------------------------------------------------------|
| `MAX_CPUS`            | 1024          | Maximum supported CPUs                                |
| `MAX_ENQUEUED_TASKS`  | 4096          | Maximum tasks queued between kernel and user space    |
| `MAX_DISPATCH_SLOT`   | 512           | Max dispatch batch size (`MAX_ENQUEUED_TASKS / 8`)    |
| `USERSCHED_TIMER_NS`  | 1,000,000,000 | Heartbeat timer period (1 second)                     |
| `RL_CPU_ANY`          | `1 << 20`     | Flag indicating no specific CPU target                |
| `TASK_COMM_LEN`       | 16            | Maximum length of task command name                   |

### Command-Line Options

| Flag            | Default  | Description                                                      |
|-----------------|----------|------------------------------------------------------------------|
| `-s` / `--slice-us`     | 20000    | Default scheduling slice duration in microseconds       |
| `-S` / `--slice-us-min` | 1000     | Minimum slice duration in microseconds                  |
| `-l` / `--percpu-local`  | false    | Dispatch per-CPU tasks directly to their only eligible CPU |
| `-p` / `--partial`       | false    | Only schedule tasks with `SCHED_EXT` policy             |
| `-v` / `--verbose`       | false    | Enable verbose output and BPF tracing                   |
| `--stats`               | none     | Enable stats monitoring at the given interval (seconds) |
| `--monitor`             | none     | Stats-only mode (scheduler is not launched)             |

## BPF / Userspace Split

### BPF Component (`main.bpf.c`)

The BPF component is **policy-agnostic**. It handles:

1. **Task metadata collection**: Gathers per-task information (PID, CPU, weight, vruntime, exec_runtime, timestamps, cpumask width, enqueue flags, comm name) and sends it to user space via the `queued` ring buffer.
2. **Idle CPU selection**: When `builtin_idle` is enabled (the default), the BPF side performs fast idle CPU selection in `ops.select_cpu()` and `ops.enqueue()`, including direct dispatch to idle CPUs to bypass the user-space round trip entirely.
3. **Kernel-side dispatch shortcuts**: Per-CPU kthreads, `kswapd`, `kcompactd`, and `khugepaged` are dispatched directly without user-space involvement to avoid stalling critical kernel threads.
4. **Consuming dispatched tasks**: In `ops.dispatch()`, the BPF side drains the `dispatched` user ring buffer and inserts tasks into the appropriate DSQ.
5. **Heartbeat timer**: A periodic BPF timer (`usersched_timer_fn`) fires every second to prevent the sched_ext watchdog from killing the scheduler during idle periods.

### Userspace Component (`src/main.rs`, `src/bpf.rs`)

The Rust component handles:

1. **BPF lifecycle management** (`BpfScheduler` in `bpf.rs`): Opens, loads, and attaches the BPF skeleton; manages ring buffers; provides methods for `dequeue_task()`, `dispatch_task()`, and `select_cpu()`.
2. **Scheduling policy** (`Scheduler` in `main.rs`): Implements the actual deadline-based scheduling algorithm using a `BTreeSet<Task>` as the priority queue.
3. **Memory safety**: Locks all memory via `ALLOCATOR.lock_memory()` and disables `mmap` to prevent page faults that could cause deadlocks during scheduling.
4. **Statistics**: Exposes runtime metrics via a `StatsServer` for monitoring.

### Per-Task Storage

The BPF component maintains per-task state in a `BPF_MAP_TYPE_TASK_STORAGE` map (`task_ctx_stor`):

```c
struct task_ctx {
    u64 start_ts;       // Timestamp when the task last started running
    u64 stop_ts;        // Timestamp when the task last stopped running
    u64 exec_runtime;   // Accumulated CPU time since last sleep
    u64 enq_cnt;        // Enqueue generation counter (for stale dispatch detection)
};
```

The `exec_runtime` field is reset to zero in `ops.runnable()` (when a task wakes from sleep) and accumulated in `ops.stopping()` by adding `now - start_ts`. This captures the total CPU time consumed since the last sleep event, which is the key signal used by the user-space scheduler to distinguish interactive from CPU-bound tasks.

The `enq_cnt` field is a generation counter incremented on each enqueue. When the BPF side receives a dispatch decision, it compares the task's current `enq_cnt` with the dispatched task's `enq_cnt`. If the task has been re-enqueued since the dispatch decision was made, the dispatch is cancelled via `scx_bpf_dispatch_cancel()`.

## Scheduling Hot Path (BPF Callbacks)

The BPF component registers the following `sched_ext` operations:

### `ops.select_cpu` (`rustland_select_cpu`)

Called when a task becomes runnable to select a CPU hint. The logic:

1. **Usersched task**: Returns `prev_cpu` immediately (the scheduler process is dispatched separately).
2. **`builtin_idle` disabled**: Returns `prev_cpu`, fully delegating CPU selection to user space.
3. **`builtin_idle` enabled**: Calls `pick_idle_cpu()` to find an idle CPU. If one is found **and** both the per-CPU DSQ and `SHARED_DSQ` are empty (`can_direct_dispatch()`), the task is directly inserted into the per-CPU DSQ via `scx_bpf_dsq_insert_vtime()`, completely bypassing the user-space scheduler. This is counted as `nr_kernel_dispatches`.

### `pick_idle_cpu()`

The idle CPU selection function implements a multi-step heuristic:

1. **Single-CPU tasks**: Simply test if the only allowed CPU is idle.
2. **Wakeup on faster CPU**: On hybrid architectures, if the waker's CPU is faster than the wakee's `prev_cpu`, migrate the wakee closer to the waker -- unless both CPUs share an LLC and the previous CPU is a fully idle SMT core.
3. **`scx_bpf_select_cpu_and`** (kernel >= 6.17): Use the new kernel API to find any idle CPU from the task's cpumask.
4. **Fallback** (kernel <= 6.16): Use `scx_bpf_select_cpu_dfl()` only on wakeup paths.

### `ops.enqueue` (`rustland_enqueue`)

Called when a task becomes ready to run. The decision tree:

1. **Usersched task**: Inserted into `SCHED_DSQ` with the default slice and kicked.
2. **Per-CPU kthreads, kswapd, khugepaged**: Dispatched directly to their CPU's per-CPU DSQ. This avoids stalling critical kernel threads by routing them around the user-space scheduler entirely.
3. **Normal tasks (builtin_idle disabled or not a wakeup)**: Queued to user space via `queue_task_to_userspace()`.
4. **Normal tasks (builtin_idle enabled, wakeup path)**: Attempts to find an idle CPU via `pick_idle_cpu()`. If found and `can_direct_dispatch()` returns true, dispatches directly. Otherwise, queues to user space.

**Ring buffer overflow handling**: If the `queued` ring buffer is full (`bpf_ringbuf_reserve()` fails), the task is dispatched directly to `SHARED_DSQ` as a congestion fallback, and `nr_sched_congested` is incremented.

### `ops.dispatch` (`rustland_dispatch`)

Called when a CPU's local DSQ is empty and needs work. The consumption order is:

1. **Drain the `dispatched` user ring buffer**: Calls `bpf_user_ringbuf_drain()` with `handle_dispatched_task()` as the callback. Each task is dispatched to its target DSQ.
2. **Wake the user-space scheduler**: If `usersched_has_pending_tasks()` returns true, consume from `SCHED_DSQ` to schedule the user-space scheduler itself.
3. **Consume from the per-CPU DSQ**: `scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu))`.
4. **Consume from the shared DSQ**: `scx_bpf_dsq_move_to_local(SHARED_DSQ)`.
5. **Replenish current task**: If the current task has expired its slice but no other task is available, extend its slice by `slice_ns` and let it continue.

### `dispatch_task()` (BPF helper)

Handles the actual dispatch of a single task from the user ring buffer:

1. Looks up the `task_struct` by PID. If the task no longer exists, returns.
2. **`RL_CPU_ANY`**: Dispatches to `SHARED_DSQ` using `scx_bpf_dsq_insert_vtime()` with the task's vtime (deadline) as the ordering key.
3. **Specific CPU**: Validates the CPU against the task's cpumask. If invalid, falls back to `prev_cpu` and increments `nr_bounce_dispatches`.
4. **Stale dispatch detection**: Compares `tctx->enq_cnt` with `task->enq_cnt`. If the task was re-enqueued since this dispatch decision was made, calls `scx_bpf_dispatch_cancel()` and increments `nr_cancel_dispatches`.

### `ops.running` / `ops.stopping`

- **`running`**: Records `start_ts = scx_bpf_now()` and increments `nr_running`.
- **`stopping`**: Records `stop_ts = now`, decrements `nr_running`, and accumulates `exec_runtime += now - start_ts`.

### `ops.runnable`

Called when a task wakes from sleep. Resets `exec_runtime` to 0. This is critical for the deadline calculation: interactive tasks that sleep frequently will have low `exec_runtime` and thus earlier deadlines.

### `ops.enable`

Called when a task first joins the sched_ext scheduler class. Initializes `dsq_vtime = 0` and `slice = slice_ns`.

### Heartbeat Timer

A BPF timer (`usersched_timer_fn`) fires every `USERSCHED_TIMER_NS` (1 second). If the user-space scheduler has been inactive for more than 1 second, it sets the `usersched_needed` flag and kicks the scheduler's CPU to wake it up. This prevents the sched_ext watchdog from killing the scheduler during long idle periods.

### Scheduler Flags

The scheduler registers with the following `sched_ext` flags:

- **`SCX_OPS_ENQ_LAST`**: Receive `ops.enqueue()` calls for tasks that have exhausted their time slice.
- **`SCX_OPS_ALLOW_QUEUED_WAKEUP`**: Allow wakeup-time enqueue optimizations for tasks already in queued state.
- **`SCX_OPS_SWITCH_PARTIAL`** (optional, `--partial`): Only manage tasks explicitly set to `SCHED_EXT` via `sched_setscheduler(2)`.

The watchdog timeout is set to **5000 ms**.

## Userspace Scheduling Policy

### Deadline-Based Scheduling

The core scheduling policy is a **deadline-based virtual runtime scheduler**. The deadline for each task is computed as:

```
deadline = vruntime + exec_runtime
```

Where:

- **`vruntime`**: The task's virtual runtime, which tracks total CPU time consumed scaled inversely by weight (priority). Higher-weight tasks accumulate vruntime more slowly, receiving proportionally more CPU time. The formula for the vruntime increment on each scheduling cycle is: `vslice = (stop_ts - start_ts) * 100 / weight`.
- **`exec_runtime`**: The total CPU time consumed since the task last slept. This is the key signal for interactivity detection. Tasks that sleep frequently reset this to zero, resulting in lower deadlines and earlier scheduling.

The `exec_runtime` contribution is **capped at 100 time slices** (`self.slice_ns * 100`) to prevent indefinite starvation of CPU-intensive tasks.

### Vruntime Management

The `update_enqueued()` method in `Scheduler` handles vruntime updates:

1. **New tasks** (vtime == 0): Aligned to the current global `vruntime_now` so they start at a fair position.
2. **Sleeping tasks**: Their vruntime is clamped to a minimum of `vruntime_now - slice_ns`. This prevents tasks that sleep for a very long time from accumulating unbounded vruntime credit, which would let them monopolize the CPU upon waking. At most, a sleeping task gains one full time slice worth of vruntime advantage.
3. **Vruntime increment**: Both the task's vruntime and the global `vruntime_now` are advanced by `vslice = slice_consumed * 100 / weight`, where `slice_consumed = stop_ts - start_ts`.

### Task Ordering: BTreeSet

All runnable tasks are stored in a `BTreeSet<Task>`, which provides O(log n) insertion and O(log n) extraction of the minimum element. The ordering is:

1. **Primary key**: `deadline` (ascending -- lower deadline runs first)
2. **Secondary key**: `timestamp` (enqueue time, ascending -- FIFO tie-breaking)
3. **Tertiary key**: `pid` (ascending -- deterministic tie-breaking)

This ensures that interactive tasks (low `exec_runtime`, thus low deadline) are always scheduled before CPU-bound tasks (high `exec_runtime`, thus high deadline), while fairness is maintained through vruntime scaling by weight.

### Time Slice Assignment

When dispatching, the assigned time slice is the **minimum slice** (`slice_us_min`, default 1 ms) scaled by the task's weight:

```rust
dispatched_task.slice_ns = scale_by_task_weight(&task.qtask, self.slice_ns_min);
```

Where `scale_by_task_weight(task, value) = value * task.weight / 100`. A default-priority task (weight 100) gets exactly the minimum slice. Higher-priority tasks get proportionally longer slices.

### CPU Selection

During dispatch, the user-space scheduler selects a CPU for each task:

1. **`--percpu-local` enabled**: Tasks are sent to their current CPU (`task.qtask.cpu`).
2. **Default mode**: Calls `BpfScheduler::select_cpu()`, which invokes the BPF program `rs_select_cpu` via `prog.test_run()`. This BPF program uses `pick_idle_cpu()` to find an idle CPU, leveraging kernel topology awareness (LLC, SMT, CPU priority for hybrid architectures).
3. **Fallback**: If no idle CPU is found (`select_cpu` returns < 0), `RL_CPU_ANY` is used, which dispatches to `SHARED_DSQ` for the first available CPU.

### Main Scheduling Loop

The `Scheduler::schedule()` method runs in a tight loop:

```rust
fn schedule(&mut self) {
    self.drain_queued_tasks();   // Drain ring buffer into BTreeSet
    self.dispatch_task();        // Dispatch the highest-priority task
    self.bpf.notify_complete(self.tasks.len() as u64);  // Update nr_scheduled
}
```

The `notify_complete()` method updates `nr_scheduled` in the BPF BSS data and yields the thread (`std::thread::yield_now()`). This is the mechanism that tells the BPF component whether there is still pending work: if `nr_scheduled > 0`, the BPF side will wake the scheduler again.

Notably, only **one task** is dispatched per scheduling cycle (`dispatch_task()` pops a single task from the `BTreeSet`). This is intentional: by dispatching one task at a time and then yielding, the scheduler operates in a fine-grained cooperative manner with the BPF dispatch path.

## Communication Protocol

### Queued Task Context (BPF --> User Space)

```c
struct queued_task_ctx {
    s32 pid;                    // Task PID
    s32 cpu;                    // CPU where the task was last running
    u64 nr_cpus_allowed;        // Number of CPUs in the task's affinity mask
    u64 flags;                  // Enqueue flags (SCX_ENQ_*)
    u64 start_ts;               // Last time the task started running (ns)
    u64 stop_ts;                // Last time the task stopped running (ns)
    u64 exec_runtime;           // CPU time since last sleep (ns)
    u64 weight;                 // Static priority [1..10000], default 100
    u64 vtime;                  // Current dsq_vtime from kernel
    u64 enq_cnt;                // Enqueue generation counter
    char comm[16];              // Executable name
};
```

### Dispatched Task Context (User Space --> BPF)

```c
struct dispatched_task_ctx {
    s32 pid;                    // Task PID
    s32 cpu;                    // Target CPU (or RL_CPU_ANY)
    u64 flags;                  // Enqueue flags (passed through)
    u64 slice_ns;               // Time slice (0 = default)
    u64 vtime;                  // Deadline / vruntime for DSQ ordering
    u64 enq_cnt;                // Enqueue generation (for stale detection)
};
```

### Memory Safety

The user-space scheduler takes special precautions to avoid page faults during scheduling, which could cause deadlocks (the scheduler itself needs to run to handle page faults):

1. **`ALLOCATOR.lock_memory()`**: Locks all current and future memory via `mlockall()`.
2. **`ALLOCATOR.disable_mmap()`**: Disables `mmap`-based allocations in the custom allocator, forcing all allocations through `sbrk`/pre-allocated pools.

## Statistics and Monitoring

The `Metrics` struct (in `stats.rs`) exposes the following counters, accessible via the `scx_stats` framework:

| Metric                  | Description                                                  |
|-------------------------|--------------------------------------------------------------|
| `nr_cpus`               | Number of online CPUs                                        |
| `nr_running`            | Tasks currently running on CPUs                              |
| `nr_queued`             | Tasks queued to the user-space scheduler (in ring buffer)    |
| `nr_scheduled`          | Tasks in the user-space BTreeSet waiting to be dispatched    |
| `nr_page_faults`        | Page faults of the scheduler process (should always be 0)    |
| `nr_user_dispatches`    | Tasks dispatched by the user-space scheduler                 |
| `nr_kernel_dispatches`  | Tasks dispatched directly by BPF (bypassing user space)      |
| `nr_cancel_dispatches`  | Dispatches cancelled due to stale enqueue generation         |
| `nr_bounce_dispatches`  | Dispatches bounced to a different DSQ due to affinity change |
| `nr_failed_dispatches`  | Dispatches that failed (ring buffer full on dispatch side)   |
| `nr_sched_congested`    | Congestion events (queued ring buffer full)                  |

Stats are served via a `StatsServer` and can be consumed with `--stats <interval>` or `--monitor <interval>`. The monitor computes deltas between successive readings, so counters reflect per-interval rates rather than cumulative totals.

## Kernel-Bypass Fast Paths

A critical performance optimization is that **not all tasks go through user space**. The BPF component has several fast paths that dispatch tasks directly without involving the Rust scheduler:

1. **Idle CPU direct dispatch in `ops.select_cpu()`**: When `builtin_idle` is enabled and an idle CPU is found with empty DSQs, the task is dispatched immediately.
2. **Wakeup direct dispatch in `ops.enqueue()`**: On wakeup with `builtin_idle`, if an idle CPU with empty DSQs is found, the task is dispatched directly.
3. **Per-CPU kthread fast path**: Single-CPU kthreads, `kswapd`/`kcompactd`, and `khugepaged` always bypass user space.
4. **Congestion fallback**: When the `queued` ring buffer is full, tasks are dispatched to `SHARED_DSQ` as a fallback.

These fast paths are reflected in the `nr_kernel_dispatches` counter. In a well-functioning system with available idle CPUs, a significant portion of dispatches may bypass user space entirely, reducing the overhead of the user-space scheduling model.

## Topology Awareness

The scheduler is topology-aware through several mechanisms:

- **SMT awareness**: The BPF side detects whether SMT is enabled via `Topology::new().smt_enabled` and uses `scx_bpf_get_idle_smtmask()` to prefer fully idle SMT cores.
- **LLC awareness**: `cpus_share_cache()` uses `cpu_llc_id()` to check whether two CPUs share a last-level cache, preferring same-LLC placement.
- **Hybrid CPU priority**: `is_cpu_faster()` uses `cpu_priority()` to detect asymmetric CPU architectures (e.g., Intel big.LITTLE), migrating woken tasks to faster cores when the waker is on a faster core.
- **User-space CPU selection**: The `rs_select_cpu` BPF syscall program allows the user-space scheduler to invoke `pick_idle_cpu()` from user space via `prog.test_run()`, inheriting all the topology-aware idle selection logic.
