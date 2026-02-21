# scx_simple
Generated: 2026-02-21, git-depth 7778

## Overview

`scx_simple` is a minimal sched_ext scheduler that serves as both a working
scheduler and a pedagogical example of the sched_ext BPF framework. It is
implemented entirely in a single BPF C file
(`tools/sched_ext/scx_simple.bpf.c` in the kernel tree; mirrored at
`scheds/c/scx_simple.bpf.c` in the scx repository) with no Rust userspace
component.

The scheduler supports two operating modes selected at load time via the
`fifo_sched` volatile boolean:

- **Weighted virtual-time (vtime) mode** (default) -- a global priority queue
  ordered by each task's accumulated virtual time, weighted inversely by the
  task's scheduling weight. Higher-weight (lower-nice) tasks accumulate vtime
  more slowly and therefore receive proportionally more CPU time.
- **FIFO mode** -- a simple first-in-first-out global queue where tasks are
  served in arrival order regardless of weight.

The scheduler is intentionally simple: it has no preemption logic, no
per-domain partitioning, and no load balancing. Despite this, it performs
reasonably well on systems with a uniform L3 cache topology because its single
shared dispatch queue naturally distributes work across all CPUs.

## Architecture / Design

### Data Structures

| Name | Type | Purpose |
|------|------|---------|
| `fifo_sched` | `const volatile bool` | Mode selector, set from userspace before load. `false` = weighted vtime, `true` = FIFO. |
| `vtime_now` | `static u64` | Global vtime watermark -- the highest `dsq_vtime` of any task that has started running. Used as the reference point for clamping idle-task credit and initializing new tasks. |
| `uei` | `struct user_exit_info` (via `UEI_DEFINE`) | Shared structure for communicating scheduler exit status and diagnostic messages to userspace. |
| `stats` | `BPF_MAP_TYPE_PERCPU_ARRAY` (2 entries) | Per-CPU counters: index 0 counts tasks dispatched to the local DSQ (fast path), index 1 counts tasks dispatched to the shared/global DSQ. |
| `SHARED_DSQ` | `#define 0` | The user-created dispatch queue (DSQ ID 0). Required because built-in DSQs like `SCX_DSQ_GLOBAL` do not support vtime-ordered insertion (`scx_bpf_dsq_insert_vtime`). |

### DSQ Layout

```
                    +-----------------+
                    |   SHARED_DSQ    |  <-- DSQ ID 0, created in simple_init()
                    | (global, all    |      node = -1 (NUMA_NO_NODE)
                    |  CPUs consume)  |
                    +-----------------+
                           |
            scx_bpf_dsq_move_to_local()
                           |
              +------------+------------+
              |            |            |
        +---------+  +---------+  +---------+
        | CPU 0   |  | CPU 1   |  | CPU N   |
        | LOCAL   |  | LOCAL   |  | LOCAL   |
        | DSQ     |  | DSQ     |  | DSQ     |
        +---------+  +---------+  +---------+
```

Every CPU has a per-CPU local DSQ (`SCX_DSQ_LOCAL`) managed by the kernel. The
scheduler creates one additional shared DSQ (`SHARED_DSQ`, ID 0) at
initialization with `scx_bpf_create_dsq(SHARED_DSQ, -1)`. The `-1` (i.e.
`NUMA_NO_NODE`) means the DSQ is not NUMA-affine -- any CPU may consume from
it.

In vtime mode, `SHARED_DSQ` operates as a **priority queue** ordered by
virtual time. In FIFO mode, it operates as a plain FIFO queue.

### Registered Callbacks

The scheduler registers the following `sched_ext_ops` via `SCX_OPS_DEFINE`:

| Callback | Function | Hot Path? |
|----------|----------|-----------|
| `.select_cpu` | `simple_select_cpu` | Yes |
| `.enqueue` | `simple_enqueue` | Yes |
| `.dispatch` | `simple_dispatch` | Yes |
| `.running` | `simple_running` | Yes |
| `.stopping` | `simple_stopping` | Yes |
| `.enable` | `simple_enable` | Cold (task creation) |
| `.init` | `simple_init` | Cold (scheduler load) |
| `.exit` | `simple_exit` | Cold (scheduler unload) |

## Scheduling Hot Path (BPF Callbacks)

The following describes the execution flow when the kernel schedules a task
through scx_simple.

### 1. `simple_select_cpu` -- CPU Selection and Fast-Path Local Dispatch

```c
s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
```

This is the first callback invoked when a task becomes runnable (e.g. waking
from sleep). It performs two functions:

1. **CPU selection**: Calls `scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags,
   &is_idle)` to let the kernel's default idle-CPU selection logic pick the
   best CPU. This helper prefers `prev_cpu` if it is idle, then falls back to
   searching for an idle CPU in the same LLC domain, and finally any idle CPU.

2. **Fast-path local dispatch**: If the selected CPU is idle (`is_idle ==
   true`), the task is dispatched directly to `SCX_DSQ_LOCAL` via
   `scx_bpf_dsq_insert()` with `SCX_SLICE_DFL` as the time slice. This
   bypasses the global `SHARED_DSQ` entirely, avoiding lock contention. The
   local dispatch counter (`stats[0]`) is incremented.

When a task is dispatched in `select_cpu`, the subsequent `enqueue` callback
is **not** invoked -- the task goes straight to the local DSQ of the chosen
CPU.

### 2. `simple_enqueue` -- Global Queue Insertion

```c
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
```

This callback fires only when `select_cpu` did **not** dispatch the task
locally (i.e. no idle CPU was found). The task is placed on the global
`SHARED_DSQ`. The global dispatch counter (`stats[1]`) is incremented.

The behavior diverges by mode:

- **FIFO mode** (`fifo_sched == true`): Calls `scx_bpf_dsq_insert(p,
  SHARED_DSQ, SCX_SLICE_DFL, enq_flags)`. Tasks are appended in arrival
  order.

- **Vtime mode** (`fifo_sched == false`): Reads the task's current virtual
  time from `p->scx.dsq_vtime`, clamps it (see below), and calls
  `scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
  enq_flags)`. The DSQ is ordered by ascending vtime, so tasks with the
  smallest vtime are dequeued first.

**Idle credit clamping**: A task that has been sleeping for a long time will
have a very old (small) `dsq_vtime`, giving it a large burst of priority when
it wakes up. To limit this, the scheduler clamps the vtime:

```c
if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
    vtime = vtime_now - SCX_SLICE_DFL;
```

This means a waking task can be at most one slice ahead of the global vtime
watermark. It receives a small priority boost (it was idle and deserves prompt
service) but cannot monopolize the CPU for an unbounded burst.

### 3. `simple_dispatch` -- Consuming from the Shared DSQ

```c
void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
```

Called when a CPU's local DSQ is empty and it needs more work. The
implementation is a single call:

```c
scx_bpf_dsq_move_to_local(SHARED_DSQ);
```

This atomically moves the highest-priority task (lowest vtime in vtime mode,
or front-of-queue in FIFO mode) from `SHARED_DSQ` to the calling CPU's local
DSQ. If `SHARED_DSQ` is empty, the CPU goes idle.

### 4. `simple_running` -- Advancing the Global Vtime Clock

```c
void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
```

Called when a task starts executing on a CPU. In FIFO mode, this is a no-op.

In vtime mode, it advances `vtime_now` to the task's `dsq_vtime` if the
task's vtime is ahead of the current watermark:

```c
if (time_before(vtime_now, p->scx.dsq_vtime))
    vtime_now = p->scx.dsq_vtime;
```

This ensures `vtime_now` monotonically tracks the most advanced vtime among
all currently running tasks. The update is **intentionally racy** -- multiple
CPUs may read and write `vtime_now` concurrently without synchronization. The
comment in the source acknowledges this: "Any error should be contained and
temporary. Let's just live with it." Since vtime only needs to be
approximately correct for fairness, occasional stale reads are acceptable.

### 5. `simple_stopping` -- Charging Consumed CPU Time

```c
void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
```

Called when a task stops executing (either voluntarily or because its slice
expired). In FIFO mode, this is a no-op.

In vtime mode, the task's `dsq_vtime` is advanced based on how much of its
time slice it consumed:

```c
p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
```

Breaking this down:

- **`SCX_SLICE_DFL - p->scx.slice`**: The amount of CPU time consumed.
  `p->scx.slice` starts at `SCX_SLICE_DFL` and is decremented by the kernel
  as the task runs. When fully consumed, `p->scx.slice == 0` and the consumed
  time equals `SCX_SLICE_DFL`.

- **`* 100 / p->scx.weight`**: Inverse weight scaling. The default weight is
  100 (corresponding to nice 0). A task with weight 200 (nice -5 or similar)
  advances its vtime at half the rate, effectively receiving twice as much CPU
  time before its vtime catches up with a weight-100 task. Conversely, a task
  with weight 50 advances its vtime twice as fast.

**Yield behavior note**: The default `sched_ext` yield implementation sets
`p->scx.slice` to zero. This causes the formula above to charge the full
slice (`SCX_SLICE_DFL * 100 / weight`), penalizing yielding tasks. The source
code notes this as a known trade-off and suggests using explicit timestamps if
the penalty is too harsh.

## FIFO vs Weighted Vtime Mode

| Property | FIFO Mode | Weighted Vtime Mode |
|----------|-----------|---------------------|
| **Queue ordering** | Arrival order (first-in-first-out) | Virtual-time order (lowest vtime first) |
| **Weight awareness** | None -- all tasks treated equally | Yes -- higher-weight tasks accumulate vtime slower |
| **Fairness** | None -- a CPU-bound task can starve interactive tasks | Proportional fairness -- each task gets CPU proportional to its weight |
| **Idle credit** | Unlimited -- a waking task goes to back of queue | Clamped to one `SCX_SLICE_DFL` ahead of `vtime_now` |
| **Overhead** | Slightly lower (no vtime bookkeeping) | Slightly higher (vtime read/write in `running`/`stopping`/`enqueue`) |
| **Best for** | Batch workloads with equal-priority tasks | Mixed interactive/batch workloads, multi-tenant fairness |
| **DSQ insert function** | `scx_bpf_dsq_insert` | `scx_bpf_dsq_insert_vtime` |
| **`running`/`stopping` callbacks** | No-op (early return) | Active (update `vtime_now`, charge consumed time) |

### Vtime Algorithm in Detail

The virtual-time algorithm is a simplified variant of Weighted Fair Queuing
(WFQ). Each task carries a virtual timestamp (`p->scx.dsq_vtime`) representing
how much "virtual CPU time" it has consumed, normalized by weight.

**Invariant**: At any point, the task with the smallest `dsq_vtime` on the
`SHARED_DSQ` is the one that has received the least proportional CPU time and
therefore deserves to run next.

The algorithm operates through three coordinated updates:

1. **Task start (`simple_running`)**: Advance `vtime_now` to match the running
   task's vtime. This tracks the global "present" in virtual time.

2. **Task stop (`simple_stopping`)**: Advance the task's vtime by
   `consumed_time * 100 / weight`. This ensures heavier tasks advance more
   slowly.

3. **Task enqueue (`simple_enqueue`)**: Clamp the task's vtime to at most
   `SCX_SLICE_DFL` behind `vtime_now`, then insert into the vtime-ordered DSQ.

## Topology Awareness

scx_simple has **minimal** topology awareness. Specifically:

- **`scx_bpf_select_cpu_dfl`** provides LLC-aware CPU selection. The kernel's
  default implementation tries (in order): the previous CPU if idle, an idle
  CPU in the same LLC, then any idle CPU. This gives some cache locality
  benefit without any explicit topology logic in the scheduler itself.

- **The shared DSQ is not NUMA-aware**. It is created with `node = -1`
  (`NUMA_NO_NODE`), meaning tasks may be consumed by any CPU regardless of
  NUMA distance. On systems with multiple NUMA nodes, this can result in
  frequent cross-node memory access.

- **No per-LLC or per-NUMA partitioning**. Unlike production schedulers (e.g.
  `scx_rusty`), scx_simple does not create per-domain DSQs or implement
  load balancing between domains.

As the source file's header comment notes: "this scheduler should work
reasonably well on CPUs with a **uniform L3 cache topology**." On multi-socket
or chiplet architectures with non-uniform cache/memory topologies, a more
sophisticated scheduler would be needed.

## Statistics and Observability

The scheduler maintains a single per-CPU array BPF map called `stats` with two
entries:

| Index | Meaning |
|-------|---------|
| 0 | Number of tasks dispatched to `SCX_DSQ_LOCAL` (fast path via `select_cpu`) |
| 1 | Number of tasks dispatched to `SHARED_DSQ` (slow path via `enqueue`) |

The `stat_inc` helper performs a BPF map lookup and increment:

```c
static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}
```

Because the map is `BPF_MAP_TYPE_PERCPU_ARRAY`, each CPU has its own copy of
the counters. There is no contention on updates. Userspace can aggregate the
per-CPU values to get system-wide totals.

A high ratio of `stats[0]` (local) to `stats[1]` (global) indicates that most
tasks are finding idle CPUs on the fast path, which is the ideal scenario for
low-latency scheduling.

## Initialization and Teardown

### `simple_init`

```c
s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    vtime_now = 0;
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}
```

Declared `SLEEPABLE` because `scx_bpf_create_dsq` may sleep (it allocates
memory). Initializes the global vtime to zero and creates the shared DSQ. The
return value propagates any error from DSQ creation -- a non-zero return
aborts scheduler loading.

### `simple_enable`

```c
void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}
```

Called once per task when it first enters sched_ext management. Sets the
task's initial vtime to the current global watermark, ensuring new tasks
start with a fair position in the vtime order -- neither starved nor
excessively privileged.

### `simple_exit`

```c
void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}
```

Records the exit reason, message, and dump information into the `uei` struct
for userspace to read. The `UEI_RECORD` macro copies the kernel's
`scx_exit_info` fields into the BPF-side `user_exit_info` struct using
`bpf_probe_read_kernel_str`, then performs an atomic compare-and-swap on the
`kind` field to signal userspace that exit information is available.

## Key Constants

| Constant | Source | Description |
|----------|--------|-------------|
| `SCX_SLICE_DFL` | Kernel (`scx_public_consts` enum) | Default time slice for a task, typically 20ms. Injected as a volatile constant at BPF load time. |
| `SCX_DSQ_LOCAL` | Kernel (`scx_dsq_id_flags` enum) | Built-in per-CPU local dispatch queue. Used for fast-path direct dispatch. |
| `SCX_DSQ_GLOBAL` | Kernel (`scx_dsq_id_flags` enum) | Built-in global dispatch queue. Not used by scx_simple because it does not support vtime ordering. |
| `SHARED_DSQ` | `scx_simple.bpf.c` (`#define 0`) | User-created DSQ with ID 0, supporting both FIFO and vtime-ordered insertion. |

## Limitations and Trade-offs

1. **No preemption**: Once a task begins running, it holds the CPU for its
   full `SCX_SLICE_DFL` slice unless it voluntarily yields or blocks. A
   newly waking high-priority task must wait for the current slice to expire.

2. **Global contention**: The single `SHARED_DSQ` is a contention point under
   high task counts. Every CPU that runs out of local work calls
   `scx_bpf_dsq_move_to_local(SHARED_DSQ)`, which takes a lock on the DSQ.

3. **Racy vtime updates**: The `vtime_now` global variable is updated without
   synchronization. On systems with many CPUs, stale reads can cause
   temporary fairness deviations. The scheduler accepts this trade-off for
   simplicity and lower overhead.

4. **No topology partitioning**: Without per-LLC or per-NUMA DSQs, cross-node
   scheduling is common on multi-socket systems, leading to increased memory
   latency.

5. **Yield penalty**: Yielding tasks are charged as if they consumed their
   entire slice, which may over-penalize cooperative yielding patterns.

## Summary

scx_simple demonstrates the essential mechanics of a sched_ext scheduler in
approximately 150 lines of BPF C:

- **Fast-path local dispatch** in `select_cpu` for idle CPUs
- **Global shared DSQ** with configurable FIFO or vtime ordering
- **Weight-proportional fairness** via inverse-weight vtime charging
- **Idle credit clamping** to prevent wakeup bursts
- **Per-CPU statistics** for observability
- **UEI (User Exit Info)** for clean shutdown signaling

It serves as an excellent starting point for understanding sched_ext's
callback model and as a baseline scheduler for benchmarking more sophisticated
designs.
