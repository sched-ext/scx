# scx_rlfifo
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_rlfifo` is a minimal Round-Robin / FIFO scheduler for the Linux kernel, implemented as a user-space scheduling policy on top of `sched_ext`. It is built using the `scx_rustland_core` framework, which provides the BPF plumbing that bridges the kernel's scheduling hooks to a user-space Rust process.

The scheduler dequeues tasks in FIFO order from a BPF ring buffer, assigns dynamic time slices (inversely proportional to queue depth), selects an idle CPU for each task (or dispatches to the global shared DSQ), and writes dispatch decisions back to the kernel via a user ring buffer. This creates a basic preemptive round-robin behavior: every runnable task eventually gets a turn, and tasks that exhaust their time slice are re-enqueued.

**Not production-ready.** The README explicitly warns against production use. The scheduler exists as a template and baseline for experimenting with more complex user-space scheduling policies.

## Architecture / Design

### Split-plane Architecture

`scx_rlfifo` follows the `scx_rustland_core` split-plane design:

| Plane | Language | Role |
|-------|----------|------|
| **Kernel / BPF** | C (`main.bpf.c`) | Implements `sched_ext` ops callbacks. Collects per-task metadata, enqueues tasks to a ring buffer, and dispatches tasks from a user ring buffer to per-CPU or shared DSQs. |
| **User-space** | Rust (`main.rs`, `bpf.rs`) | Reads queued tasks from the ring buffer, makes scheduling decisions (CPU selection, time-slice assignment), writes dispatch decisions back through the user ring buffer. |

Communication between the two planes uses two BPF ring buffers:

- **`queued`** (`BPF_MAP_TYPE_RINGBUF`): BPF-to-userspace. The BPF `enqueue` callback writes `queued_task_ctx` records here. The user-space scheduler drains them via `dequeue_task()`.
- **`dispatched`** (`BPF_MAP_TYPE_USER_RINGBUF`): Userspace-to-BPF. The user-space scheduler writes `dispatched_task_ctx` records here. The BPF `dispatch` callback drains them via `bpf_user_ringbuf_drain()`.

### Dispatch Queues (DSQs)

The BPF component creates three categories of DSQs during `dsq_init()`:

| DSQ | ID | Purpose |
|-----|----|---------|
| **Per-CPU DSQs** | `0` .. `nr_cpu_ids - 1` | Targeted dispatch to a specific CPU. |
| **Shared DSQ** | `SHARED_DSQ` = `MAX_CPUS` (1024) | Global queue consumed by any idle CPU. Used when `RL_CPU_ANY` is specified or as a fallback. |
| **Scheduler DSQ** | `SCHED_DSQ` = `MAX_CPUS + 1` (1025) | Dedicated queue for the user-space scheduler process itself. Consumed only when pending scheduling work exists. |

### Key Constants and Limits

| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_CPUS` | 1024 | Maximum supported CPUs; also dimensionss the per-CPU DSQ ID space. |
| `MAX_ENQUEUED_TASKS` | 4096 | Ring buffer capacity in task entries. |
| `MAX_DISPATCH_SLOT` | 512 | `dispatch_max_batch` -- max tasks dispatched per `.dispatch()` call. |
| `SLICE_NS` | 5,000,000 ns (5 ms) | Default time slice passed to `BpfScheduler::init()`. |
| `USERSCHED_TIMER_NS` | 1,000,000,000 ns (1 s) | Heartbeat interval to prevent watchdog stalls. |
| `SCHED_EXT` | 7 | Linux scheduling class constant for sched_ext. |
| `RL_CPU_ANY` | `1 << 20` | Special flag indicating no CPU preference. |

### Data Structures

#### `queued_task_ctx` (BPF -> User-space)

Defined in `intf.h`. Each record represents a task that the BPF `enqueue` callback has queued for user-space scheduling:

```c
struct queued_task_ctx {
    s32 pid;
    s32 cpu;               // CPU where the task was last running
    u64 nr_cpus_allowed;
    u64 flags;             // enqueue flags from the kernel
    u64 start_ts;          // timestamp of last CPU acquisition
    u64 stop_ts;           // timestamp of last CPU release
    u64 exec_runtime;      // CPU time since last sleep
    u64 weight;            // static priority (sched_ext weight)
    u64 vtime;             // current virtual runtime
    u64 enq_cnt;           // generation counter for stale-dispatch detection
    char comm[16];         // executable name
};
```

#### `dispatched_task_ctx` (User-space -> BPF)

Also in `intf.h`. Each record is a scheduling decision:

```c
struct dispatched_task_ctx {
    s32 pid;
    s32 cpu;       // target CPU, or RL_CPU_ANY
    u64 flags;     // propagated enqueue flags
    u64 slice_ns;  // time slice (0 = default)
    u64 vtime;     // vruntime / deadline for ordering in DSQ
    u64 enq_cnt;   // must match task's current enq_cnt, else dispatch is cancelled
};
```

#### `task_ctx` (BPF per-task storage)

Stored in a `BPF_MAP_TYPE_TASK_STORAGE` map. Tracks per-task timing:

```c
struct task_ctx {
    u64 start_ts;       // when the task last started running
    u64 stop_ts;        // when the task last stopped running
    u64 exec_runtime;   // cumulative runtime since last sleep
    u64 enq_cnt;        // monotonically increasing enqueue generation counter
};
```

#### Rust-side Equivalents

In `bpf.rs`, the `QueuedTask` and `DispatchedTask` structs mirror the C structs:

- **`QueuedTask`** -- received via `dequeue_task()`, contains all fields from `queued_task_ctx`. Has a `comm_str()` helper for converting the C char array to a Rust `String`.
- **`DispatchedTask`** -- created via `DispatchedTask::new(&QueuedTask)`, copies `pid`, `flags`, `enq_cnt` from the source task; `slice_ns` and `vtime` default to 0.

## Scheduling Hot Path (BPF Callbacks)

The BPF component registers the following `sched_ext` operations via `SCX_OPS_DEFINE(rustland, ...)`:

### `rustland_select_cpu` (`.select_cpu`)

Called when a task is waking up. Selects a CPU for the task.

1. **Validates `prev_cpu`**: If `prev_cpu` is not in the task's `cpus_ptr`, falls back to the current CPU or the first allowed CPU.
2. **Skips user-space scheduler**: If the task is the user-space scheduler itself (`is_usersched_task`), returns `prev_cpu` immediately.
3. **Delegates to user-space if `builtin_idle` is off**: Returns `prev_cpu` without attempting idle CPU selection.
4. **Calls `pick_idle_cpu()`**: Finds the closest idle CPU. The idle selection logic handles:
   - **Single-CPU tasks** (`nr_cpus_allowed == 1`): Tests and clears `prev_cpu` idle status directly.
   - **Hybrid CPU migration**: On wakeup, if the waker's CPU is faster than the wakee's `prev_cpu`, migrates toward the faster core (unless the wakee's CPU is a fully idle SMT core in the same LLC).
   - **Modern kernels** (>= 6.16): Uses `scx_bpf_select_cpu_and()`.
   - **Older kernels**: Falls back to `scx_bpf_select_cpu_dfl()`.
5. **Direct dispatch optimization**: If an idle CPU is found and both the shared DSQ and the per-CPU DSQ are empty (`can_direct_dispatch()`), the task is dispatched immediately via `scx_bpf_dsq_insert_vtime()` into the per-CPU DSQ, bypassing the user-space scheduler entirely. This is counted as a **kernel dispatch** (`nr_kernel_dispatches`).

### `rustland_enqueue` (`.enqueue`)

Called when a task becomes runnable. Determines whether to handle the task in-kernel or send it to user-space:

1. **User-space scheduler task**: Dispatched to `SCHED_DSQ` with `scx_bpf_dsq_insert()`.
2. **Per-CPU kernel threads, kswapd, khugepaged**: Dispatched directly to their CPU's per-CPU DSQ with `scx_bpf_dsq_insert_vtime()`. These are critical kernel threads that should not be delayed by user-space scheduling latency.
3. **Wakeup with `builtin_idle` enabled**: Attempts `pick_idle_cpu()` for a direct dispatch opportunity. If an idle CPU is found and `can_direct_dispatch()` returns true, dispatches directly. Otherwise, falls back to queuing to user-space.
4. **Default path**: Calls `queue_task_to_userspace()`, which:
   - Looks up `task_ctx` for the task.
   - Reserves a slot in the `queued` ring buffer.
   - Fills in the `queued_task_ctx` via `get_task_info()`, incrementing `enq_cnt`.
   - Submits the entry and increments `nr_queued`.
   - **Congestion fallback**: If the ring buffer is full, dispatches directly to `SHARED_DSQ` and counts it as a kernel dispatch.

### `rustland_dispatch` (`.dispatch`)

Called when a CPU's local DSQ is empty and needs work. Consumes tasks in priority order:

1. **Drains the `dispatched` user ring buffer** via `bpf_user_ringbuf_drain()` with callback `handle_dispatched_task()`. Each entry calls `dispatch_task()` which:
   - Looks up the task by PID (`bpf_task_from_pid`).
   - If `cpu == RL_CPU_ANY`: dispatches to `SHARED_DSQ` with vtime ordering (`scx_bpf_dsq_insert_vtime`) and kicks an idle CPU.
   - If a specific CPU is selected: validates against `cpus_ptr` affinity. If invalid, bounces to `prev_cpu` and increments `nr_bounce_dispatches`.
   - **Stale dispatch detection**: Compares the task's current `enq_cnt` with the dispatched entry's `enq_cnt`. If the task was dequeued and re-enqueued while in user-space (i.e., `tctx->enq_cnt > task->enq_cnt`), cancels the dispatch via `scx_bpf_dispatch_cancel()`.
2. **Scheduler DSQ**: If `usersched_has_pending_tasks()` returns true, moves the user-space scheduler from `SCHED_DSQ` to local DSQ via `scx_bpf_dsq_move_to_local()`.
3. **Per-CPU DSQ**: Attempts to consume from the CPU's own DSQ.
4. **Shared DSQ**: Attempts to consume from `SHARED_DSQ`.
5. **Time-slice replenishment**: If the previous task (`prev`) is still queued and no other task was found, its time slice is replenished to `slice_ns`, letting it continue running.

### `rustland_runnable` (`.runnable`)

Called when a task transitions to runnable state (wakes up from sleep). Resets `exec_runtime` to 0 in the task's `task_ctx`. Skips the user-space scheduler task.

### `rustland_running` (`.running`)

Called when a task begins executing on a CPU:

- Records the timestamp in `tctx->start_ts` via `scx_bpf_now()`.
- Increments the global `nr_running` counter.
- For the user-space scheduler, updates `usersched_last_run_at`.

### `rustland_stopping` (`.stopping`)

Called when a task stops running on a CPU:

- Records stop timestamp in `tctx->stop_ts`.
- Decrements `nr_running`.
- Accumulates execution time: `tctx->exec_runtime += now - tctx->start_ts`.

### `rustland_enable` (`.enable`)

Called when a task joins the sched_ext scheduling class. Initializes `p->scx.dsq_vtime = 0` and `p->scx.slice = slice_ns`.

### `rustland_init_task` (`.init_task`)

Allocates per-task BPF local storage (`task_ctx`) via `bpf_task_storage_get()` with `BPF_LOCAL_STORAGE_GET_F_CREATE`.

### `rustland_init` (`.init`)

Scheduler initialization:

1. Compile-time assertion that `MAX_CPUS` is even.
2. Reads `nr_cpu_ids` from the kernel.
3. Calls `dsq_init()` to create all DSQs.
4. Calls `usersched_timer_init()` to arm the heartbeat timer.

### `rustland_exit` (`.exit`)

Records exit info via `UEI_RECORD(uei, ei)`.

## Heartbeat Timer

The BPF component arms a periodic timer (`usersched_timer`) at `USERSCHED_TIMER_NS` (1 second) intervals using `bpf_timer_start()` with `CLOCK_BOOTTIME`. The callback `usersched_timer_fn()`:

1. Checks if the user-space scheduler has been inactive for more than `USERSCHED_TIMER_NS` by comparing `scx_bpf_now()` against `usersched_last_run_at`.
2. If so, sets the `usersched_needed` flag and kicks the scheduler's CPU.
3. Re-arms the timer.

This prevents the `sched_ext` watchdog (configured at `timeout_ms = 5000`) from killing the scheduler during idle periods when no tasks are being enqueued.

## Userspace Scheduling Logic

The user-space component is deliberately simple. The core scheduling loop lives in `Scheduler::dispatch_tasks()` in `main.rs`:

### Initialization (`Scheduler::init`)

Creates a `BpfScheduler` with the following configuration:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `exit_dump_len` | 0 | Default exit info buffer size |
| `partial` | `false` | All tasks are managed by sched_ext |
| `debug` | `false` | Debug logging disabled |
| `builtin_idle` | `true` | BPF component can bypass user-space for idle CPUs |
| `slice_ns` | `SLICE_NS` (5 ms) | Default time slice |
| `name` | `"rlfifo"` | sched_ext ops name |

During `BpfScheduler::init()` (in `bpf.rs`):

1. Opens and loads the BPF skeleton.
2. Detects SMT topology via `Topology::new()` and sets `smt_enabled`.
3. Sets scheduler flags: `SCX_OPS_ENQ_LAST | SCX_OPS_ALLOW_QUEUED_WAKEUP`.
4. Records `usersched_pid` (this process) and `khugepaged_pid`.
5. Attaches the struct_ops.
6. Creates the `queued` ring buffer reader with a callback that copies one `queued_task_ctx` at a time into a static aligned buffer (`BUF`).
7. Creates the `dispatched` user ring buffer writer.
8. Locks all memory (`ALLOCATOR.lock_memory()`) and disables mmap (`ALLOCATOR.disable_mmap()`) to prevent page faults during scheduling, which could cause deadlocks.

### The Scheduling Loop (`Scheduler::run`)

```
loop {
    dispatch_tasks()   // drain ring buffer, make decisions, write back
    print_stats()      // once per second
}
```

### Task Dispatch (`Scheduler::dispatch_tasks`)

This is the entire scheduling policy:

1. **Read queue depth**: `nr_waiting = *self.bpf.nr_queued_mut()`.
2. **Drain loop**: While `dequeue_task()` returns a task:
   a. Create a `DispatchedTask` from the `QueuedTask`.
   b. **CPU selection**: Call `self.bpf.select_cpu(task.pid, task.cpu, task.flags)`. This invokes the BPF `rs_select_cpu` syscall program, which runs `pick_idle_cpu()` to find a suitable idle CPU. If a valid CPU is returned (`>= 0`), use it; otherwise set `cpu = RL_CPU_ANY` (dispatch to shared DSQ).
   c. **Time slice**: `slice_ns = SLICE_NS / (nr_waiting + 1)`. This divides the base 5 ms slice by the number of waiting tasks plus one, creating shorter slices under load. This is the key mechanism for achieving round-robin behavior -- more contention leads to faster preemption.
   d. **Dispatch**: Write the `DispatchedTask` to the user ring buffer via `self.bpf.dispatch_task()`.
3. **Notify completion**: Call `self.bpf.notify_complete(0)`, which sets `nr_scheduled = 0` (no pending tasks remain in user-space) and yields the thread. This causes the scheduler to sleep until the BPF component wakes it by consuming from `SCHED_DSQ`.

### CPU Selection from User-space (`rs_select_cpu`)

The BPF `rs_select_cpu` program is a `SEC("syscall")` BPF program invoked from Rust via `prog.test_run()`. It receives a `task_cpu_arg` (pid, cpu, flags) and calls `pick_idle_cpu()` to find an idle CPU. On older kernels without `scx_bpf_select_cpu_and()`, it falls back to `scx_bpf_test_and_clear_cpu_idle()` / `scx_bpf_pick_idle_cpu()`.

### Ring Buffer Mechanics (`dequeue_task` / `dispatch_task`)

**Dequeue** (`bpf.rs`):

- Calls `self.queued.consume_raw_n(1)` to read one entry from the kernel ring buffer.
- Uses a static `AlignedBuffer` (`BUF`) with a callback that copies the raw bytes.
- Decrements `nr_queued` on success.

**Dispatch** (`bpf.rs`):

- Reserves a slot in the user ring buffer via `self.dispatched.reserve()`.
- Fills in the `dispatched_task_ctx` fields.
- Submits via `self.dispatched.submit()`.

## Stale Dispatch Detection

A critical correctness mechanism. The `enq_cnt` field in `task_ctx` is incremented every time a task is enqueued to user-space (in `get_task_info()`). When the BPF dispatch callback processes a `dispatched_task_ctx`, it compares the stored `enq_cnt` against the task's current `enq_cnt`. If `tctx->enq_cnt > task->enq_cnt`, the task was dequeued and re-enqueued while in transit through user-space, so the stale dispatch is cancelled via `scx_bpf_dispatch_cancel()`.

## Scheduler Flags

The scheduler enables two `sched_ext` operational flags:

- **`SCX_OPS_ENQ_LAST`**: Tasks are enqueued through the scheduler even if they are the last runnable task, ensuring the scheduler sees all transitions.
- **`SCX_OPS_ALLOW_QUEUED_WAKEUP`**: Permits enqueue of tasks that are waking up while already in a queued state, which enables the remote-wakeup optimization path in `rustland_enqueue`.

## Congestion Handling

When the `queued` ring buffer is full (capacity: `MAX_ENQUEUED_TASKS * sizeof(queued_task_ctx)`), the BPF component cannot send the task to user-space. In this case, `queue_task_to_userspace()` dispatches the task directly to `SHARED_DSQ` with the default time slice, bypassing user-space entirely. The `nr_sched_congested` counter is incremented. This ensures liveness even when user-space scheduling cannot keep up.

## Statistics and Monitoring

The user-space scheduler prints a one-line statistics summary once per second (in `print_stats()`):

```
user=<N> kernel=<N> cancel=<N> bounce=<N> fail=<N> cong=<N>
```

| Counter | Meaning |
|---------|---------|
| `nr_user_dispatches` | Tasks dispatched to a valid user-selected CPU |
| `nr_kernel_dispatches` | Tasks dispatched directly by the BPF component (idle CPU shortcut, per-CPU kthreads, congestion fallback) |
| `nr_cancel_dispatches` | Stale dispatches cancelled due to `enq_cnt` mismatch |
| `nr_bounce_dispatches` | Dispatches where user-selected CPU was invalid due to affinity; task bounced to `prev_cpu` |
| `nr_failed_dispatches` | Failed dispatch attempts |
| `nr_sched_congested` | Ring buffer full events (congestion) |

## Memory Safety

The user-space scheduler takes special precautions to avoid page faults during scheduling, which could deadlock the system (the scheduler itself is managed by sched_ext):

1. **`ALLOCATOR.lock_memory()`**: Calls `mlockall()` to pin all memory pages.
2. **`ALLOCATOR.disable_mmap()`**: Disables mmap-based allocation to prevent new page faults.
3. **`ALLOCATOR.unlock_memory()`**: Called in `Drop for BpfScheduler` on shutdown.

## Restart Behavior

The `main()` function runs the scheduler in a loop. If `sched.run()` returns a `UserExitInfo` where `should_restart()` is true, the scheduler re-initializes and restarts. This supports automatic recovery from transient errors.

## Source File Summary

| File | Purpose |
|------|---------|
| `intf.h` | Shared C header defining data structures (`queued_task_ctx`, `dispatched_task_ctx`, `task_cpu_arg`, `domain_arg`) and constants (`MAX_CPUS`, `RL_CPU_ANY`). |
| `main.bpf.c` | BPF program implementing all `sched_ext` ops callbacks, ring buffer management, DSQ creation, idle CPU selection, heartbeat timer, and direct-dispatch optimizations. |
| `src/main.rs` | User-space entry point. Contains `Scheduler` struct with `init()`, `dispatch_tasks()` (the scheduling policy), `print_stats()`, and `run()` loop. |
| `src/bpf.rs` | User-space BPF interface layer. Contains `BpfScheduler` (BPF skeleton management, ring buffer I/O), `QueuedTask`, `DispatchedTask`, and all counter accessors. |
