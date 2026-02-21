# scx_mitosis
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_mitosis** is a cgroup-aware sched_ext scheduler developed by Meta that isolates workloads into *cells*. Each cell is a dedicated set of CPUs with its own dispatch queue(s), enabling workload isolation on shared datacenter servers. The scheduler's eventual goal is to support overcommitting workloads by dynamically partitioning CPU resources across cgroups.

The design splits responsibility between a BPF program (hot-path scheduling) and a Rust userspace component (topology discovery, metrics collection, stats serving). The BPF program implements weighted virtual-time (vtime) scheduling within each cell. Userspace populates topology data, monitors per-cell statistics, and serves metrics via a stats server.

Key design properties:
- **Dynamic cells**: Cells are allocated and freed at runtime as cgroups gain or lose `cpuset.cpus` restrictions.
- **Cgroup-driven isolation**: A cgroup whose cpuset is a strict subset of its parent's gets its own cell. Other cgroups inherit the parent's cell.
- **LLC-awareness** (optional): On multi-LLC systems, each cell can be split into per-LLC dispatch queues to keep tasks on cache-sharing CPUs.
- **Work stealing** (optional, requires LLC-awareness): Idle CPUs can steal tasks from sibling LLC DSQs within the same cell.

## Architecture / Design

### Split BPF / Userspace Model

| Component | Role |
|-----------|------|
| `mitosis.bpf.c` | SCX ops callbacks (select_cpu, enqueue, dispatch, running, stopping, etc.), timer-based cell reconfiguration, cgroup lifecycle management |
| `mitosis.bpf.h` | Core data structures (`cell`, `task_ctx`, `cell_map`), constants (`ROOT_CELL_ID`, `ANY_NUMA`), forward declarations |
| `dsq.bpf.h` | 64-bit DSQ ID encoding/decoding (type-tagged union for per-CPU and cell+LLC queues) |
| `llc_aware.bpf.h` | LLC topology maps, weighted LLC selection, per-cell LLC count recalculation, work-stealing logic |
| `cleanup.bpf.h` | RAII guard framework for BPF (scoped cleanup for cgroup refs, cpumasks, RCU, spin locks) |
| `intf.h` | Shared C/Rust interface: constants, `struct cell`, `struct cpu_ctx`, `struct cgrp_ctx`, stat enums |
| `main.rs` | Scheduler initialization, BPF skeleton loading, main event loop, metrics collection and stats serving |
| `mitosis_topology_utils.rs` | Populates `cpu_to_llc[]` and `llc_to_cpus[]` arrays from host topology before BPF load |
| `stats.rs` | `Metrics` and `CellMetrics` structs, stats server setup, monitor mode |

### Lifecycle

1. **Userspace initialization** (`Scheduler::init`): Discovers topology via `scx_utils::Topology`, populates rodata (slice_ns, CPU bitmap, LLC maps, feature flags), creates the BPF skeleton, loads it.
2. **BPF initialization** (`mitosis_init`): Creates `all_cpumask`, initializes per-CPU DSQs and per-cell DSQs (one per LLC or one flat), allocates cell cpumasks, initializes root cgroup context, starts the `update_timer` (100ms interval).
3. **Attach** (`scx_ops_attach`): Registers the SCX ops with the kernel.
4. **Main loop** (`Scheduler::run`): Periodically calls `refresh_bpf_cells` (reads `applied_configuration_seq` to detect cell changes) and `collect_metrics` (reads per-CPU stats, computes deltas, updates `Metrics`). Serves stats requests from the stats server channel.
5. **Shutdown**: Drops `struct_ops` to detach, reports UEI exit info.

### Configuration Sequencing

Cell reconfiguration is driven by two sequence counters:

- **`configuration_seq`**: Bumped by `fentry/cpuset_write_resmask` (cpuset changes), `cgroup_init` (new cgroup with cpuset), and `cgroup_exit` / `tp_cgroup_rmdir` (cell owner destroyed).
- **`applied_configuration_seq`**: Bumped by the timer callback (`update_timer_cb`) after it has fully applied the new CPU/cell assignments.

Tasks check `tctx->configuration_seq != applied_configuration_seq` in `maybe_refresh_cell()` to lazily pick up new cell assignments. The ordering uses `READ_ONCE` and `barrier()` to prevent stale reads.

## Cell Model

### What is a Cell?

A **cell** is a scheduling domain: a set of CPUs with one or more dispatch queues and per-LLC vtime tracking. The `struct cell` is stored in a `BPF_MAP_TYPE_ARRAY` (`cells`) with `MAX_CELLS` (256) entries.

```c
struct cell {
    CELL_LOCK_T lock;       // bpf_spin_lock in BPF, 4-byte pad in userspace
    u32 in_use;             // Whether cell is allocated
    u32 cpu_cnt;            // Total CPUs in this cell
    u32 llc_present_cnt;    // Number of LLCs with >= 1 CPU in this cell
    struct cell_llc llcs[MAX_LLCS];  // Per-LLC data (cacheline-aligned)
};
```

Each `cell_llc` entry is cacheline-aligned (64 bytes) to prevent false sharing:

```c
struct cell_llc {
    u64 vtime_now;  // Current virtual time for this (cell, LLC) domain
    u32 cpu_cnt;    // CPUs from this cell in this LLC
} __attribute__((aligned(CACHELINE_SIZE)));
```

### Cgroup-to-Cell Mapping

The mapping from cgroups to cells is determined by cpuset configuration:

1. **Root cgroup** (identified by `root_cgid`): Always assigned to **cell 0** (`ROOT_CELL_ID`).
2. **Cgroups with a cpuset that is a strict subset of `all_cpumask`**: Get their own cell. The cell is allocated via `allocate_cell()` (atomic CAS on `in_use`) and the cgroup becomes the `cell_owner`.
3. **Cgroups without a restrictive cpuset**: Inherit the parent's cell.

The `cgrp_ctx` structure tracks this:

```c
struct cgrp_ctx {
    u32  cell;        // Which cell this cgroup belongs to
    bool cell_owner;  // Whether this cgroup owns (allocated) the cell
};
```

Stored in `BPF_MAP_TYPE_CGRP_STORAGE`, so each cgroup has its own context. Parent cell inheritance during timer iteration uses a `level_cells[MAX_CG_DEPTH]` array to track the cell assigned at each hierarchy level during pre-order traversal.

### Cell Allocation and Deallocation

- **`allocate_cell()`**: Scans all `MAX_CELLS` entries, uses `__sync_bool_compare_and_swap(&c->in_use, 0, 1)` to atomically claim the first free cell. Zeros all vtime counters via `zero_cell_vtimes()`.
- **`free_cell(cell_idx)`**: Sets `in_use` to 0 via `WRITE_ONCE`. The owning cgroup's exit handler calls this and bumps `configuration_seq` so the timer redistributes CPUs back to the root cell.

### CPU-to-Cell Assignment

CPU-to-cell assignment is performed in `update_timer_cb()` (runs every `TIMER_INTERVAL_NS` = 100ms) when `configuration_seq != applied_configuration_seq`:

1. Start with root cell cpumask = `all_cpumask` (all online CPUs).
2. Iterate all cgroups in pre-order (`BPF_CGROUP_ITER_DESCENDANTS_PRE`).
3. For each cgroup with a cpuset, copy its cpumask to the cell's cpumask and remove those CPUs from the root cell's cpumask. Update `cpu_ctx->cell` for each CPU.
4. Cgroups without a cpuset inherit the parent's cell (tracked via `level_cells[]`).
5. Remaining CPUs are assigned to cell 0 (root).
6. `applied_configuration_seq` is bumped after all assignments complete.

The cpumask swap uses a double-buffering strategy: each cell has both a `cpumask` (active) and `tmp_cpumask` (scratch). The timer builds the new mask in `tmp_cpumask`, then atomically swaps it into `cpumask` via `bpf_kptr_xchg`.

### CPU Controller Disabled Mode

When `--cpu-controller-disabled` is set, SCX cgroup callbacks (`cgroup_init`, `cgroup_exit`, `cgroup_move`) do not fire. Instead:

- **`tp_btf/cgroup_mkdir`** and **`tp_btf/cgroup_rmdir`** tracepoints handle cgroup lifecycle.
- **`init_cgrp_ctx_with_ancestors()`** ensures the entire ancestor chain is initialized (replicating the hierarchical init order SCX would normally provide).
- **`task_cgroup()`** reads `p->cgroups->dfl_cgrp` under RCU instead of using `scx_bpf_task_cgroup()` (which returns root when the CPU controller is disabled).
- **`maybe_refresh_cell()`** additionally checks if the task's cgroup ID changed (detecting cgroup moves that would otherwise be reported via `cgroup_move`).

## Scheduling Hot Path (BPF Callbacks)

### `mitosis_select_cpu`

Called when a task wakes up to select which CPU it should run on.

1. Looks up `cpu_ctx` and `task_ctx`.
2. Calls `maybe_refresh_cell()` to lazily apply any pending cell reconfiguration.
3. **CPU-pinned tasks** (`!tctx->all_cell_cpus_allowed`): The task is pinned to specific CPUs (its affinity doesn't cover the entire cell). Gets the CPU from the task's per-CPU DSQ, tries to claim it idle, and dispatches to `SCX_DSQ_LOCAL` if successful. Increments `CSTAT_AFFN_VIOL`.
4. **Cell-wide tasks**: Calls `pick_idle_cpu()` to find an idle CPU within the task's effective cpumask (cell cpumask AND task affinity). If found, dispatches to `SCX_DSQ_LOCAL` and increments `CSTAT_LOCAL`.
5. **Fallback**: Returns `prev_cpu` if valid within the cell cpumask, otherwise picks any CPU from the cell.

### `pick_idle_cpu_from`

The idle CPU selection strategy prefers:

1. **SMT-aware**: If SMT is enabled and `prev_cpu` is fully idle (both siblings), claim it. Otherwise try `SCX_PICK_IDLE_CORE` to find a fully idle core.
2. **prev_cpu**: If `prev_cpu` is in the candidate set and idle, claim it (cache warmth).
3. **Any idle**: `scx_bpf_pick_idle_cpu(cand_cpumask, 0)` for any idle CPU in the set.

### `mitosis_enqueue`

Called when a task is ready to be queued for execution.

1. Refreshes cell assignment via `maybe_refresh_cell()`.
2. Reads `p->scx.dsq_vtime` **after** cell refresh (refresh may modify vtime).
3. **CPU-pinned tasks**: Dispatched to the per-CPU DSQ. Basis vtime comes from `cpu_ctx->vtime_now`.
4. **Cell-wide tasks**: Dispatched to the cell DSQ (or cell+LLC DSQ if LLC-aware). Basis vtime comes from `cell->llcs[llc].vtime_now`.
5. **Vtime clamping**: If the task's vtime is too far behind the basis (more than `slice_ns` behind), it is clamped to `basis_vtime - slice_ns`. This limits how much "budget" an idle task can accumulate. If vtime is more than `8192 * slice_ns` ahead of basis, this is an error.
6. **Idle CPU kick**: If `select_cpu` was not called (no CPU was pre-selected), finds an idle CPU and kicks it via `scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)`.

### `mitosis_dispatch`

Called when a CPU needs work. Implements competitive dispatch between the cell DSQ and the per-CPU DSQ:

1. Gets the CPU's cell from `cpu_ctx->cell`.
2. Determines the cell DSQ (`get_cell_llc_dsq_id(cell, llc)`) and CPU DSQ (`get_cpu_dsq_id(cpu)`).
3. **Peeks** at the head of both DSQs using `scx_bpf_dsq_peek()`.
4. Picks the DSQ with the **lowest vtime** (fair competition between cell-wide and pinned tasks).
5. Calls `scx_bpf_dsq_move_to_local()` to move the winning task to the local DSQ.
6. **Fallback on race**: If the winner was the cell DSQ but `move_to_local` failed (another CPU consumed it), tries the CPU DSQ.
7. **Work stealing** (if enabled and no task found): Calls `try_stealing_work()` to scan sibling LLC DSQs.

### `mitosis_running`

Called when a task starts running on a CPU.

1. Records `tctx->started_running_at = scx_bpf_now()`.
2. **Work-stealing retag**: If LLC-awareness and work-stealing are enabled, calls `maybe_retag_stolen_task()`. If the task's LLC (`tctx->llc`) differs from the CPU's LLC (`cctx->llc`), the task was stolen. Updates `tctx->llc`, increments `steal_count`, and recalculates the task's cpumask for the new LLC.

### `mitosis_stopping`

Called when a task stops running.

1. Calculates `used = now - tctx->started_running_at`.
2. **Vtime charging**: `p->scx.dsq_vtime += used * 100 / p->scx.weight`. This is the weighted vtime formula -- tasks with higher weight accumulate vtime more slowly, giving them proportionally more CPU time.
3. **Advance DSQ vtimes**: Updates `cpu_ctx->vtime_now` and the appropriate `cell->llcs[].vtime_now` to track the global vtime frontier. This prevents stale vtime values from accumulating.
4. **Cell cycle accounting**: Accumulates `used` into `cpu_ctx->cell_cycles[cell]` for monitoring (only for non-root cells or tasks using all cell CPUs).

### `mitosis_set_cpumask`

Called when a task's CPU affinity changes. Recalculates the task's effective cpumask (task affinity AND cell cpumask) via `update_task_cpumask()`.

### `mitosis_init_task`

Called for each task during scheduler attachment and for new tasks.

1. Creates `task_ctx` via `bpf_task_storage_get` with `BPF_LOCAL_STORAGE_GET_F_CREATE`.
2. Creates a `bpf_cpumask` for the task's effective cpumask.
3. If LLC-aware, initializes LLC fields via `init_task_llc()`.
4. Calls `update_task_cell()` to determine cell assignment and set up DSQ/cpumask.

When the CPU controller is disabled, additionally calls `init_cgrp_ctx_with_ancestors()` to ensure the task's cgroup hierarchy is initialized.

### `fentry/cpuset_write_resmask`

An fentry probe on the kernel's `cpuset_write_resmask` function. Whenever userspace writes to `cpuset.cpus`, this atomically increments `configuration_seq` to signal the timer callback to reconfigure cells.

## DSQ Structure

The scheduler uses a structured 64-bit DSQ ID encoding defined in `dsq.bpf.h`. The `dsq_id_t` is a tagged union:

```
Bits: [63]    [62..32]    [31..28]    [27..0]
       B       unused      QTYPE      DATA

B = 0: User-defined DSQ (mitosis uses this)
B = 1: Built-in DSQ (SCX_DSQ_LOCAL, SCX_DSQ_GLOBAL)
```

### DSQ Types

| QTYPE | Name | Bit Layout (low 32 bits) | Description |
|-------|------|--------------------------|-------------|
| `0x0` | `DSQ_TYPE_NONE` | N/A | Invalid/sentinel (`DSQ_INVALID`) |
| `0x1` | `DSQ_TYPE_CPU` | `[0001][CPU# (28 bits)]` | Per-CPU dispatch queue |
| `0x2` | `DSQ_TYPE_CELL_LLC` | `[0010][CELL# (12 bits)][LLC# (16 bits)]` | Cell+LLC dispatch queue |

### Capacity

- **Per-CPU DSQs**: Up to `MAX_CPUS` (512) queues, one per CPU.
- **Cell+LLC DSQs**: Up to `MAX_CELLS * MAX_LLCS` (256 * 16 = 4096) queues.

### DSQ Creation

During `mitosis_init`:
- One per-CPU DSQ per online CPU: `scx_bpf_create_dsq(get_cpu_dsq_id(i).raw, ANY_NUMA)`.
- For each of `MAX_CELLS` (256) cells: one DSQ per LLC (if LLC-aware) or one flat DSQ using `FAKE_FLAT_CELL_LLC` (index 0).

### Task-to-DSQ Assignment

Each task has a `dsq_id_t dsq` field in its `task_ctx`:

- **CPU-pinned tasks** (affinity doesn't cover entire cell): Assigned to `get_cpu_dsq_id(cpu)` where `cpu` is picked from `p->cpus_ptr`.
- **Cell-wide tasks** (LLC-aware): Assigned to `get_cell_llc_dsq_id(cell, llc)` where `llc` is chosen by `pick_llc_for_task()`.
- **Cell-wide tasks** (flat): Assigned to `get_cell_llc_dsq_id(cell, FAKE_FLAT_CELL_LLC)`.

### Dispatch Competition

In `mitosis_dispatch`, the CPU peeks at both its cell DSQ and its per-CPU DSQ. The task with the lower `dsq_vtime` wins, ensuring fair competition between pinned and cell-wide tasks.

## LLC Awareness

LLC awareness is an optional mode enabled via `--enable-llc-awareness`. It is implemented in `llc_aware.bpf.h`.

### Topology Data

Two global arrays are populated by userspace before BPF load:

- **`cpu_to_llc[MAX_CPUS]`**: Maps each CPU index to its LLC domain ID.
- **`llc_to_cpus[MAX_LLCS]`**: Maps each LLC ID to a `struct llc_cpumask` containing a bitmask of CPUs in that LLC.

These are populated in `mitosis_topology_utils::populate_topology_maps()` from `scx_utils::Topology`.

### Per-Cell LLC Counts

`recalc_cell_llc_counts()` computes, for each cell, how many CPUs belong to each LLC. This is done under the cell's spin lock and updates:
- `cell->llcs[llc].cpu_cnt` for each LLC.
- `cell->llc_present_cnt` (number of non-empty LLCs).
- `cell->cpu_cnt` (total CPUs in cell).

### LLC Selection for Tasks

`pick_llc_for_task(cell_id)` uses **weighted random selection**: generates a random number in `[0, total_cpu_cnt)`, then does a linear scan accumulating CPU counts per LLC until the cumulative count exceeds the random target. LLCs with more CPUs in the cell have proportionally higher probability of being selected. This provides natural load balancing.

### Task Cpumask Narrowing

When LLC-aware, `update_task_llc_assignment()`:
1. Picks an LLC via `pick_llc_for_task()`.
2. Sets `tctx->llc` to the chosen LLC.
3. Narrows `tctx->cpumask` by AND-ing with the LLC's cpumask.
4. Sets `tctx->dsq` to `get_cell_llc_dsq_id(cell, llc)`.
5. Sets vtime baseline from `cell->llcs[llc].vtime_now`.

### Flat (Non-LLC) Mode

When LLC awareness is disabled, all per-LLC operations use `FAKE_FLAT_CELL_LLC` (constant 0). Each cell has exactly one DSQ and one vtime counter, treating all CPUs in the cell as a single scheduling domain.

## Work Stealing

Work stealing is enabled via `--enable-work-stealing` and requires LLC awareness. It allows idle CPUs to steal tasks from sibling LLC DSQs within the same cell.

### Stealing Logic (`try_stealing_work`)

Called from `mitosis_dispatch` when no task is found in either the cell DSQ or CPU DSQ:

1. Iterates over all LLCs in the cell except the local one, starting from `(local_llc + 1) % nr_llc` to spread load.
2. Skips LLCs with `cpu_cnt == 0` in this cell (fast path).
3. Skips empty DSQs (`scx_bpf_dsq_nr_queued == 0`).
4. Attempts `scx_bpf_dsq_move_to_local()` on the candidate DSQ. This is racy -- another CPU may consume the task first.
5. On success, increments `CSTAT_STEAL` and returns.

### Stolen Task Retagging (`maybe_retag_stolen_task`)

Called from `mitosis_running`. When a task runs on a CPU whose LLC differs from `tctx->llc`:

1. Increments `tctx->steal_count`.
2. Records `tctx->last_stolen_at = scx_bpf_now()`.
3. Updates `tctx->llc` to the CPU's LLC.
4. Recalculates the task's effective cpumask for the new LLC via `update_task_cpumask()`.

This lazy approach avoids updating the task context during the steal itself (where the peeked task_ctx may be stale due to races).

## Per-Task Context

```c
struct task_ctx {
    struct bpf_cpumask __kptr *cpumask;  // Effective cpumask (task affinity AND cell mask)
    u64 started_running_at;              // Timestamp for runtime accounting
    u64 basis_vtime;                     // Vtime baseline when enqueued
    u32 cell;                            // Cell this task belongs to
    dsq_id_t dsq;                        // Which DSQ this task is dispatched to
    u32 configuration_seq;               // Last applied config (lazy refresh)
    bool all_cell_cpus_allowed;          // Can run on any CPU in cell?
    u64 cgid;                            // Last known cgroup ID
    s32 llc;                             // Assigned LLC (LLC_INVALID if unset)
    u32 steal_count;                     // Times this task was stolen
    u64 last_stolen_at;                  // Timestamp of last steal
};
```

The `all_cell_cpus_allowed` flag is critical: when `true`, the task uses a cell (or cell+LLC) DSQ; when `false`, it uses a per-CPU DSQ. This is determined by checking whether the cell's cpumask is a subset of the task's affinity mask.

## Per-CPU Context

```c
struct cpu_ctx {
    u64 cstats[MAX_CELLS][NR_CSTATS];  // Per-cell statistics counters
    u64 cell_cycles[MAX_CELLS];         // CPU cycles spent per cell
    u64 vtime_now;                       // Per-CPU vtime for pinned-task DSQ
    u32 cell;                            // Which cell this CPU belongs to
    u32 llc;                             // Which LLC this CPU belongs to
};
```

Stored in a `BPF_MAP_TYPE_PERCPU_ARRAY` with a single key (0), so each CPU gets its own instance without contention.

## Statistics and Metrics

### BPF-Side Stats

Five per-cell statistics are tracked per CPU (to avoid contention):

| Index | Name | Meaning |
|-------|------|---------|
| `CSTAT_LOCAL` | Local dispatch | Task dispatched directly to `SCX_DSQ_LOCAL` in `select_cpu` |
| `CSTAT_CPU_DSQ` | CPU DSQ | Task enqueued to a per-CPU DSQ (pinned task) |
| `CSTAT_CELL_DSQ` | Cell DSQ | Task enqueued to a cell (or cell+LLC) DSQ |
| `CSTAT_AFFN_VIOL` | Affinity violation | Task's affinity doesn't overlap with cell cpumask |
| `CSTAT_STEAL` | Work steal | Task stolen from sibling LLC DSQ |

### Userspace Metrics Collection

`Scheduler::collect_metrics()` runs every `monitor_interval` (default 1s):

1. Reads all per-CPU `cpu_ctx` via `lookup_percpu` on the `cpu_ctxs` map.
2. Accumulates `cstats` across all CPUs for each cell.
3. Computes deltas since last collection.
4. Calculates distribution percentages (local %, CPU DSQ %, cell DSQ %, affinity violation %, steal %).

### Stats Server

The `Metrics` and `CellMetrics` structs (defined in `stats.rs`) are served via `scx_stats::StatsServer`. Running `scx_mitosis --monitor` connects as a client and prints JSON metrics at the specified interval.

**`Metrics`** (global):
- `num_cells`, `local_q_pct`, `cpu_q_pct`, `cell_q_pct`, `affn_violations_pct`, `steal_pct`, `share_of_decisions_pct`, `total_decisions`
- `cells: BTreeMap<u32, CellMetrics>` for per-cell breakdown.

**`CellMetrics`** (per-cell):
- Same fields as global, plus `num_cpus`.

## RAII / Cleanup Framework

`cleanup.bpf.h` implements a subset of the Linux kernel's `cleanup.h` for BPF programs, enabling scoped resource management:

- **`DEFINE_FREE(name, type, free_expr)`**: Defines a cleanup function. Used for `cgroup` (calls `bpf_cgroup_release`), `bpf_cpumask` (calls `bpf_cpumask_release`), `idle_cpumask` (calls `scx_bpf_put_idle_cpumask`), and `cpumask_entry` (resets `used` flag).
- **`__free(name)`**: Attribute to attach cleanup to a variable declaration.
- **`no_free_ptr(p)`**: Transfers ownership out, preventing cleanup (sets variable to NULL).
- **`DEFINE_GUARD(name, type, lock, unlock)`**: Scoped lock guard. Used for `spin_lock` (calls `bpf_spin_lock`/`bpf_spin_unlock`).
- **`guard(name)`**: Creates an anonymous scoped guard instance.
- **`scoped_guard(name, args)`**: Scoped guard with a block scope.

The RCU guard reuses the kernel's `class_rcu_t` type and pairs `bpf_rcu_read_lock()`/`bpf_rcu_read_unlock()`.

## Debug Events

When `--debug-events` is enabled, a circular buffer (`BPF_MAP_TYPE_ARRAY` of `DEBUG_EVENTS_BUF_SIZE` = 4096 entries) records:

- **`DEBUG_EVENT_CGROUP_INIT`**: Cgroup initialized (records `cgid`).
- **`DEBUG_EVENT_INIT_TASK`**: Task initialized (records `cgid`, `pid`).
- **`DEBUG_EVENT_CGROUP_EXIT`**: Cgroup exiting (records `cgid`).

Each event has a `timestamp` from `scx_bpf_now()`. The buffer position (`debug_event_pos`) is advanced atomically with `__sync_fetch_and_add`. Events are dumped in `mitosis_dump()` for debugging scheduler issues.

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--log-level` | `info` | Logging level (supports `tracing` EnvFilter syntax) |
| `--exit-dump-len` | `0` | Exit debug dump buffer length |
| `--reconfiguration-interval-s` | `10` | Cell reconfiguration check interval |
| `--rebalance-cpus-interval-s` | `5` | CPU rebalancing interval |
| `--monitor-interval-s` | `1` | Metrics reporting interval |
| `--monitor <secs>` | - | Run as stats monitor client (no scheduler) |
| `--debug-events` | `false` | Enable debug event circular buffer |
| `--exiting-task-workaround` | `true` | Workaround for exiting tasks with offline cgroups |
| `--cpu-controller-disabled` | `false` | Use tracepoints instead of SCX cgroup callbacks |
| `--reject-multicpu-pinning` | `false` | Error on multi-CPU pinning within non-root cells |
| `--enable-llc-awareness` | `false` | Split cell DSQs per LLC domain |
| `--enable-work-stealing` | `false` | Allow cross-LLC work stealing (requires LLC awareness) |

## Constants and Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CPUS` | 512 | Maximum supported CPUs |
| `MAX_CELLS` | 256 | Maximum concurrent cells |
| `MAX_LLCS` | 16 | Maximum LLC domains |
| `MAX_CG_DEPTH` | 256 | Maximum cgroup hierarchy depth |
| `TIMER_INTERVAL_NS` | 100,000,000 (100ms) | Cell reconfiguration timer period |
| `USAGE_HALF_LIFE` | 100,000,000 (100ms) | Usage decay half-life |
| `CACHELINE_SIZE` | 64 | Cache line size for alignment |
| `DEBUG_EVENTS_BUF_SIZE` | 4096 | Debug event circular buffer capacity |
| `FAKE_FLAT_CELL_LLC` | 0 | Pseudo-LLC index used in non-LLC-aware mode |
| `ROOT_CELL_ID` | 0 | Cell index for the root cell |

## SCX Ops Registration

The scheduler registers the following ops via `SCX_OPS_DEFINE(mitosis, ...)`:

| Op | Function | Purpose |
|----|----------|---------|
| `select_cpu` | `mitosis_select_cpu` | Pick CPU and try direct local dispatch |
| `enqueue` | `mitosis_enqueue` | Queue task to appropriate DSQ with vtime |
| `dispatch` | `mitosis_dispatch` | Move tasks from cell/CPU DSQs to local |
| `running` | `mitosis_running` | Record start time, handle stolen task retag |
| `stopping` | `mitosis_stopping` | Charge vtime, advance DSQ vtimes |
| `set_cpumask` | `mitosis_set_cpumask` | Handle affinity changes |
| `init_task` | `mitosis_init_task` | Initialize per-task context |
| `cgroup_init` | `mitosis_cgroup_init` | Initialize per-cgroup context |
| `cgroup_exit` | `mitosis_cgroup_exit` | Free cell on cgroup destruction |
| `cgroup_move` | `mitosis_cgroup_move` | Update task's cell on cgroup migration |
| `dump` | `mitosis_dump` | Debug dump of cells, CPUs, events |
| `dump_task` | `mitosis_dump_task` | Debug dump of per-task state |
| `init` | `mitosis_init` | Full scheduler initialization |
| `exit` | `mitosis_exit` | Record exit info |
