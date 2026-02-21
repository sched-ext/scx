# scx_rusty
Generated: 2026-02-21, git-depth 7778

## Overview

**scx_rusty** is a multi-domain, BPF/userspace hybrid scheduler for the Linux `sched_ext` framework. It partitions CPUs into scheduling domains (typically aligned with LLC/L3 cache boundaries) and implements a two-tier scheduling architecture:

- **BPF side (kernel):** Performs fast-path scheduling decisions -- CPU selection, task enqueue/dispatch, vtime tracking, duty cycle accounting, and greedy cross-domain work stealing.
- **Userspace side (Rust):** Runs two periodic control loops -- a high-frequency **tuner** (default 100ms) that identifies under-utilized CPUs for greedy task placement, and a lower-frequency **load balancer** (default 2s) that computes domain load averages and migrates tasks between domains and NUMA nodes.

The scheduler supports weighted virtual-time scheduling with deadline-based latency boosting, or optionally FIFO scheduling. It is production-ready and was originally designed for multi-chiplet AMD processors, where each chiplet's LLC forms a natural scheduling domain.

**Key design properties:**
- NUMA-aware: domains are grouped by NUMA node; cross-NUMA migration has a higher cost threshold
- Work-conserving: greedy execution and kick-greedy mechanisms prevent idle CPUs when work is available
- Low userspace overhead: load balancing examines at most 1024 recently-active tasks per domain
- Configurable: extensive CLI options for slice durations, greedy thresholds, cache topology, cpumask overrides, and more

## Architecture / Design

### Split BPF / Userspace Responsibility

| Responsibility | BPF | Userspace |
|---|---|---|
| CPU selection on wakeup | `rusty_select_cpu` | -- |
| Task enqueue / dispatch | `rusty_enqueue`, `rusty_dispatch` | -- |
| Vtime and deadline tracking | `rusty_running`, `rusty_stopping` | -- |
| Duty cycle (dcycle) accumulation | `dom_dcycle_adj`, `task_load_adj` | -- |
| Greedy work stealing | `rusty_dispatch` | -- |
| Tune greedy cpumasks | -- | `Tuner::step` |
| Load balance (task migration) | -- | `LoadBalancer::load_balance` |
| Domain creation / topology | `create_dom`, `create_node` | `DomainGroup::new` |

### Constants and Limits

| Constant | Value | Purpose |
|---|---|---|
| `MAX_CPUS` | 512 | Maximum supported CPUs |
| `MAX_DOMS` | 64 | Maximum scheduling domains |
| `MAX_NUMA_NODES` | 64 | Maximum NUMA nodes |
| `LB_LOAD_BUCKETS` | 100 | Weight buckets for load tracking |
| `LB_MAX_WEIGHT` | 10000 | Maximum task weight |
| `LB_DEFAULT_WEIGHT` | 100 | Default task weight |
| `MAX_DOM_ACTIVE_TPTRS` | 1024 | Max recently-active task pointers per domain |
| `DL_MAX_LAT_PRIO` | 39 | Maximum deadline latency priority levels |
| `DL_FREQ_FT_MAX` | 100000 | Frequency factor clamp |
| `DL_MAX_LATENCY_NS` | 50ms | Maximum latency for deadline computation |

### BPF Arena Memory

Task and domain contexts are allocated in a **BPF arena** -- a memory-mapped region shared between kernel BPF programs and userspace. The arena uses a radix-tree allocator (`sdt_alloc`) with three levels (`SDT_TASK_LEVELS = 3`), where each level has `SDT_TASK_ENTS_PER_CHUNK = 512` entries. This enables:

- Efficient per-task storage allocation/deallocation without BPF map overhead
- Direct userspace pointer access to task contexts for load balancing decisions
- Arena pointers (`dom_ptr`, `task_ptr`) with address-space annotations for Clang 18/19 compatibility

## Domain Model

### Domain Structure

Each scheduling domain is represented by three coordinated structures:

**`struct dom_ctx`** (arena-allocated): Core domain state
- `id`: Domain ID
- `min_vruntime`: Minimum virtual runtime in the domain (for vtime clamping)
- `buckets[LB_LOAD_BUCKETS]`: Array of 100 `bucket_ctx` entries, each tracking aggregate duty cycle (`dcycle`) and a running average (`ravg_data`) for tasks in that weight range
- `active_tasks`: Ring buffer of up to 1024 arena pointers to recently-active `task_ctx` entries, used by userspace load balancer

**`struct lb_domain`** (BPF map): Load balancing metadata
- `vtime_lock`: Spinlock protecting `min_vruntime` updates
- `cpumask`: BPF cpumask of CPUs in this domain
- `direct_greedy_cpumask`: CPUs eligible for cross-domain direct greedy dispatch
- `node_cpumask`: CPUs in the same NUMA node as this domain
- `domc`: Arena pointer to the corresponding `dom_ctx`

**`struct pcpu_ctx`** (per-CPU, cacheline-aligned): Per-CPU scheduling state
- `dom_id`: The domain this CPU belongs to
- `dom_rr_cur`: Round-robin cursor for greedy work-stealing scan order

### Domain Creation

During `rusty_init`, domains are created via `create_dom(dom_id)`:
1. Allocate a `dom_ctx` in the arena via `lb_domain_alloc`
2. Create a kernel DSQ (`scx_bpf_create_dsq`) bound to the domain's NUMA node
3. Initialize the domain's cpumask, direct_greedy_cpumask, and node_cpumask
4. Set CPU performance scaling via `scx_bpf_cpuperf_set`

### Task Context

**`struct task_ctx`** (arena-allocated via `sdt_task_alloc`):
- `dom_mask`: Bitmask of domains the task can run on (based on cpumask affinity)
- `preferred_dom_mask`: Preferred domains based on mempolicy affinity
- `domc`: Arena pointer to the task's current domain
- `target_dom`: The domain the task should run in (set by userspace load balancer to trigger migration)
- `weight`: Task's scheduling weight (from `p->scx.weight`)
- `runnable`: Whether the task is currently runnable
- `deadline`: Computed absolute vtime deadline for EDF-like ordering
- `sum_runtime`, `avg_runtime`, `last_run_at`: Runtime tracking for deadline computation
- `blocked_freq`, `last_blocked_at`: Frequency of task blocking (consumer metric)
- `waker_freq`, `last_woke_at`: Frequency of waking other tasks (producer metric)
- `is_kworker`: Whether this is a workqueue worker thread
- `all_cpus`: True if task is allowed on all CPUs (eligible for greedy optimization)
- `dispatch_local`: Flag from `select_cpu` telling `enqueue` to dispatch directly to local DSQ
- `dcyc_rd`: Running average data for duty cycle tracking

### Domain Assignment

When a task enters the system (`rusty_init_task`), `task_pick_domain` assigns it to a domain by:
1. Scanning all domains in round-robin order (starting from a per-CPU cursor `pcpu_ctx.dom_rr_cur`)
2. For each domain, checking if the task's cpumask intersects the domain's cpumask
3. Building a `dom_mask` of all eligible domains
4. Preferring domains that match the task's mempolicy `preferred_dom_mask` (if mempolicy_affinity is enabled)
5. Falling back to the first eligible domain in round-robin order

## Scheduling Hot Path (BPF Callbacks)

### `rusty_select_cpu` -- CPU Selection on Wakeup

This is the primary scheduling entry point, called when a task becomes runnable. It follows a priority cascade:

1. **Pinned tasks** (`nr_cpus_allowed == 1`): Dispatch to previous CPU directly. If `kthreads_local` is set and the task is a kthread, dispatch locally.

2. **Synchronous wakeup** (`SCX_WAKE_SYNC`): Via `try_sync_wakeup`:
   - If the waker's LLC domain has idle CPUs and `prev_cpu` is in the same LLC and idle, use `prev_cpu`
   - Otherwise, if the current (waker's) CPU is allowed for the wakee and there are idle CPUs in the domain and the local DSQ is empty, dispatch to the waker's CPU

3. **Previous CPU idle** (domestic): If `prev_cpu` belongs to the task's domain and the whole physical core is idle (checked via `idle_smtmask`), use it.

4. **Greedy idle on foreign CPU**: If `prev_cpu` is in a different domain but is on the `direct_greedy_cpumask` and the whole core is idle, stay there.

5. **Domestic idle core**: Pick any idle core in the task's domain via `scx_bpf_pick_idle_cpu(p_cpumask, SCX_PICK_IDLE_CORE)`.

6. **Domestic prev_cpu**: If `prev_cpu` was domestic and is idle (even if sibling is busy), use it for L1/L2 locality.

7. **Any domestic idle CPU**: Pick any idle CPU in the domain.

8. **Direct greedy (cross-domain)**: If the task is allowed on all CPUs and there are CPUs on `direct_greedy_cpumask`:
   - First try within the current domain's `direct_greedy_cpumask` (prefer idle core)
   - Then try the NUMA-filtered `direct_greedy_cpumask` (unless `direct_greedy_numa` is set)
   - Tracks `RUSTY_STAT_DIRECT_GREEDY` vs `RUSTY_STAT_DIRECT_GREEDY_FAR`

9. **Fallback to DSQ**: If no idle CPU was found, return `prev_cpu` (if domestic) or any CPU from the domain mask. The task will be enqueued to the domain's DSQ rather than dispatched directly.

When a CPU is found in steps 1-8, `taskc->dispatch_local = true` is set, signaling `rusty_enqueue` to use `SCX_DSQ_LOCAL`.

### `rusty_enqueue` -- Task Enqueue

Handles task placement after `select_cpu`:

1. **Load balance migration**: If `domc->id != taskc->target_dom` (userspace requested migration), call `task_set_domain` to move the task, then dispatch to the domain DSQ and kick an idle CPU in the new domain.

2. **Direct local dispatch**: If `dispatch_local` was set by `select_cpu`, dispatch to `SCX_DSQ_LOCAL`.

3. **Domain DSQ dispatch**: Otherwise, dispatch to the domain's DSQ:
   - In FIFO mode: `scx_bpf_dsq_insert` with flat ordering
   - In vtime mode: `place_task_dl` which calls `clamp_task_vtime` to prevent excessive vtime credit accumulation (max 1 slice worth of budget), then dispatches via `scx_bpf_dsq_insert_vtime` using the computed `deadline` as the vtime key

4. **Repatriation**: If the task is on a foreign CPU (e.g., from greedy execution), kick a domestic CPU to ensure the domain DSQ is consumed.

5. **Kick greedy**: If the task is allowed on all CPUs and there are idle CPUs on `kick_greedy_cpumask`, kick one to opportunistically steal work.

### `rusty_dispatch` -- Work Stealing

Called when a CPU needs work. Three-phase dispatch:

1. **Local domain**: Try `scx_bpf_dsq_move_to_local(curr_dom)` to consume from the CPU's own domain DSQ.

2. **Same-NUMA greedy**: If `greedy_threshold > 0`, scan other domains on the same NUMA node in round-robin order (`pcpuc->dom_rr_cur`), trying to steal from each.

3. **Cross-NUMA greedy**: If `greedy_threshold_x_numa > 0` and there are multiple NUMA nodes, scan domains on other NUMA nodes. Only steal if the foreign domain has `>= greedy_threshold_x_numa` queued tasks, to avoid unnecessary cross-NUMA traffic.

### `rusty_running` -- Task Starts Executing

- Updates `dom_min_vruntime` if the task's `dsq_vtime` exceeds the current minimum (under spinlock)
- Records the task's arena pointer in `domc->active_tasks` ring buffer (for userspace load balancer to find migration candidates)
- Tracks `last_run_at` timestamp

### `rusty_stopping` -- Task Stops Executing

- Computes elapsed runtime delta since `last_run_at`
- Updates `sum_runtime` and `avg_runtime` (EWMA with 0.75/0.25 blend via `calc_avg`)
- Advances `dsq_vtime` by `scale_inverse_fair(delta, weight)` (inversely proportional to weight)
- Recomputes `deadline = dsq_vtime + task_compute_dl()`

### `rusty_runnable` -- Task Becomes Runnable

- Adjusts task and domain duty cycle tracking (`task_load_adj`, `dom_dcycle_adj`)
- Detects kworker status (`PF_WQ_WORKER`)
- Updates the waker task's `waker_freq` (frequency of waking other tasks)
- Resets `sum_runtime` for the new execution window

### `rusty_quiescent` -- Task Becomes Not Runnable

- Adjusts task and domain duty cycle (marking as not runnable)
- Updates `blocked_freq` (frequency of being blocked/sleeping)

## Deadline / Latency Boosting

When not in FIFO mode, tasks are ordered by a computed **deadline** rather than raw vtime. The deadline mechanism provides latency boosting for interactive tasks, inspired by scx_lavd.

### `task_compute_dl` -- Deadline Computation

The function computes a "CPU request length" that is added to the task's vtime to produce an absolute deadline:

1. **Frequency factors**: Compute `waker_freq` (how often the task wakes others) and `blocked_freq` (how often the task blocks). These are clamped to `DL_FREQ_FT_MAX = 100000`.

2. **Combined frequency factor**: `freq_factor = blocked_freq * waker_freq * waker_freq`. The asymmetric squaring of `waker_freq` gives extra priority to producer tasks. This is then scaled by task weight via `scale_up_fair`.

3. **Latency priority**: `lat_prio = log2(freq_factor + 1)`, clamped to `DL_MAX_LAT_PRIO = 39`. The log2 linearizes the exponential distribution.

4. **Runtime penalty**: `avg_run = log2(avg_runtime / DL_RUNTIME_SCALE)`, inversely scaled by weight. Tasks with longer runtimes get penalized.

5. **Net priority**: `lat_prio = max(0, lat_prio - avg_run)`.

6. **Weight mapping**: `lat_prio` is mapped to a weight via `sched_prio_to_weight[]` (the same table used by CFS nice levels), producing `lat_scale`.

7. **Request length**: `scale_inverse_fair(avg_runtime, lat_scale)` = `avg_runtime * 100 / lat_scale`.

Tasks that are both frequent wakers and frequently blocked (middle of a work chain) get the smallest request lengths, and therefore the earliest deadlines and highest scheduling priority.

### Vtime Clamping

`clamp_task_vtime` prevents a task that has been sleeping for a long time from accumulating unbounded vtime credit. The task's `dsq_vtime` is clamped to `dom_min_vruntime - slice_ns`, allowing at most one slice worth of catch-up budget.

## Load Balancing

### Running Average (RAVG) Mechanism

Load tracking uses a **decaying running average** (`ravg_data`) with configurable half-life (default 1 second):

- `val`: Current value being accumulated
- `val_at`: Timestamp of last value update
- `old`: Accumulated and decayed average from completed periods
- `cur`: Accumulation for the current period

**`ravg_accumulate`**: Called when duty cycle changes. Decays `old` by the number of half-life periods elapsed, folds `cur` into `old`, and accumulates the time-weighted value for the current period. Uses pre-computed `ravg_full_sum[]` table for efficient multi-period decay.

**`ravg_read`**: Returns the current running average by blending `old` and `cur` linearly based on how far into the current half-life period we are: `result = old * (1 - P/2) + cur/2`, where `P` is the progress through the current period.

**`ravg_transfer`**: When a task migrates between domains, its duty cycle contribution must be subtracted from the source domain's bucket and added to the destination. This function synchronizes timestamps and transfers the running average components.

### Duty Cycle Buckets

Each domain has 100 `bucket_ctx` entries (one per weight bucket). When a task becomes runnable/not-runnable, `dom_dcycle_adj` increments/decrements the appropriate bucket's `dcycle` counter and accumulates the running average. Tasks are mapped to buckets via `weight_to_bucket_idx(weight) = weight * LB_LOAD_BUCKETS / LB_MAX_WEIGHT`.

This bucketed approach allows userspace to compute **weighted load** by reading each bucket's duty cycle and multiplying by the bucket's representative weight.

### Userspace Load Balancer

The `LoadBalancer` (in `load_balance.rs`) runs every 2 seconds (configurable via `--interval`):

#### Step 1: Calculate Load Averages

`calculate_load_avgs` reads each domain's 100 bucket contexts from the arena, computes the duty cycle running average via `ravg_read`, and feeds the data into a `LoadAggregator`:

- Each bucket contributes `(weight, duty_cycle)` pairs
- The aggregator computes per-domain load sums, a global load sum, and handles infeasible weights (tasks with weight so high they cannot be fully satisfied)
- Returns a `LoadLedger` with per-domain and global load metrics

#### Step 2: Create Domain Hierarchy

Builds a tree of `NumaNode` -> `Domain` objects:

- **`NumaNode`**: Contains a `LoadEntity` with `load_sum`, `load_avg` (= total_load / num_nodes), and a sorted list of `Domain` objects
- **`Domain`**: Contains a `LoadEntity` with `load_sum`, `load_avg` (= total_load / num_domains), and a sorted list of `TaskInfo` entries (populated lazily)
- **`LoadEntity`**: Encapsulates balance state computation with configurable thresholds

Balance state is determined per entity:
- **NeedsPush**: `imbal > load_avg * cost_ratio` (positive imbalance)
- **NeedsPull**: `imbal < -load_avg * cost_ratio` (negative imbalance)
- **Balanced**: otherwise

| Level | `LOAD_IMBAL_HIGH_RATIO` | `XFER_TARGET_RATIO` | `PUSH_MAX_RATIO` |
|---|---|---|---|
| NumaNode | 0.17 (17%) | 0.50 | 0.50 |
| Domain | 0.05 (5%) | 0.50 | 0.50 |

The higher NUMA cost ratio means cross-NUMA migrations only occur for larger imbalances.

#### Step 3: Inter-Node Balancing

`balance_between_nodes` iterates over nodes sorted by load (most loaded first):

1. Pop the most-loaded node (must be NeedsPush)
2. Pop the least-loaded node (must be NeedsPull)
3. For each push-domain in the push-node and each pull-domain in the pull-node, try to find a task to migrate via `try_find_move_task`
4. On successful migration, update both nodes' load and re-sort
5. First attempts to find tasks with `preferred_dom_mask` matching the pull domain; falls back to any eligible task

#### Step 4: Intra-Node Balancing

`balance_within_node` performs the same algorithm within each NUMA node, iterating over domains sorted by load. The lower cost ratio (5% vs 17%) means intra-node balancing is more aggressive.

#### Task Selection for Migration

`try_find_move_task`:
1. Calls `populate_tasks_by_load` to lazily read up to 1024 recently-active tasks from the domain's `active_tasks` ring buffer
2. For each task, reads its `dcyc_rd` running average and weight to compute load
3. Filters tasks: must be allowed in the pull domain (`dom_mask`), must not be already migrated, optionally skip kworkers
4. Finds the best candidate by scanning left and right from the ideal transfer amount (`xfer`), picking the task whose load minimizes the new combined imbalance
5. If the best candidate reduces the overall imbalance, sets `taskc->target_dom` to the pull domain's ID, which triggers BPF-side migration on next enqueue

## Topology Awareness

### Domain Construction

By default, domains are created per-LLC. `DomainGroup::new` in `domain.rs`:

- Reads system topology via `scx_utils::Topology`
- Iterates over NUMA nodes and their LLCs
- Creates one `Domain` per LLC with contiguous IDs (important: LLC IDs may have gaps due to offline CPUs, but domain IDs must be contiguous)
- Alternatively, accepts explicit `--cpumasks` to define arbitrary domain boundaries

### NUMA Mapping

- `dom_numa_id_map[dom_id]` maps each domain to its NUMA node
- `numa_cpumasks[node_id]` stores the cpumask for each NUMA node
- `dom_cpumasks[dom_id]` stores the cpumask for each domain
- `cpu_dom_id_map[cpu]` maps each CPU to its domain (CPUs with domain > MAX_DOMS are considered offline)

### NUMA-Aware Greedy Execution

When looking for idle CPUs outside the task's domain (`direct_greedy`), the scheduler by default restricts the search to the current NUMA node by intersecting `direct_greedy_cpumask` with `lb_domain->node_cpumask`. This avoids unnecessary cross-NUMA data movement. The `--direct-greedy-numa` flag removes this restriction.

### Mempolicy Affinity

When `--mempolicy-affinity` is enabled, `task_set_preferred_mempolicy_dom_mask` reads the task's `mempolicy` (via `BPF_CORE_READ`) and computes a `preferred_dom_mask`:
- For `MPOL_BIND`, `MPOL_PREFERRED`, `MPOL_PREFERRED_MANY`: uses `home_node` field or the `nodes` bitmask to identify preferred NUMA nodes
- Maps NUMA node IDs to domain bitmasks via `node_dom_mask`
- The load balancer preferentially migrates tasks to domains matching their `preferred_dom_mask`

## Userspace Side

### Tuner (`tuner.rs`)

The `Tuner` runs at high frequency (default 100ms, configurable via `--tune-interval`) and dynamically adjusts:

1. **Direct greedy cpumask**: Identifies domains with utilization below `--direct-greedy-under` (default 90%) and adds their CPUs to `direct_greedy_cpumask`. This mask is written to BPF via `tune_input` and picked up by `refresh_tune_params` in BPF.

2. **Kick greedy cpumask**: Same logic with `--kick-greedy-under` (default 100%). CPUs on this mask get kicked when tasks are enqueued on saturated domains.

3. **Slice duration**: Switches between `--slice-us-underutil` (default 20ms) for under-utilized systems and `--slice-us-overutil` (default 1ms) for fully-utilized systems. Full utilization is detected when average CPU utilization >= 99.999%.

4. **Generation counter**: Bumps `tune_input.genn` so BPF notices the update.

Utilization is computed per-CPU from `/proc/stat` deltas: `busy / (busy + idle + iowait)`.

### Main Loop (`main.rs`)

The `Scheduler::run` loop alternates between tuning and load balancing:

```
while !shutdown:
    if now >= next_tune_at:
        tuner.step()
    if now >= next_sched_at:
        lb_step()  # creates LoadBalancer, calls load_balance()
    handle stats requests
```

The `tune_input` struct in BPF BSS data serves as the communication channel from userspace to BPF. BPF checks `tune_input.genn` against its cached `tune_params_gen` on every `select_cpu` call and refreshes its cpumasks and slice duration if the generation has changed.

### Statistics (`stats.rs`)

Statistics are exported via `scx_stats::StatsServer` and can be monitored with `scx_rusty --monitor`:

**Dispatch statistics** (percentages of total dispatches):

| Stat | Description |
|---|---|
| `sync_prev_idle` | WAKE_SYNC, prev_cpu was idle in waker's LLC |
| `wake_sync` | WAKE_SYNC, dispatched to waker CPU |
| `prev_idle` | prev_cpu was domestic and idle |
| `greedy_idle` | prev_cpu was foreign but on direct_greedy and idle |
| `pinned` | Task pinned to single CPU |
| `direct` | Domestic idle CPU found or kthread local dispatch |
| `greedy` | Direct greedy to foreign domain (same node) |
| `greedy_far` | Direct greedy to foreign node |
| `dsq_dispatch` | Consumed from local domain DSQ |
| `greedy_local` | Stolen from same-NUMA foreign domain |
| `greedy_xnuma` | Stolen from cross-NUMA foreign domain |

**Per-domain stats**: load sum, imbalance from average, and delta from load balancing.

**Per-node stats**: Aggregate of domain stats within each NUMA node.

### CLI Options Summary

| Option | Default | Description |
|---|---|---|
| `-u` / `--slice-us-underutil` | 20000 | Slice duration (us) when under-utilized |
| `-o` / `--slice-us-overutil` | 1000 | Slice duration (us) when over-utilized |
| `-i` / `--interval` | 2.0 | Load balance interval (seconds) |
| `-I` / `--tune-interval` | 0.1 | Tuner interval (seconds) |
| `-l` / `--load-half-life` | 1.0 | RAVG half-life (seconds) |
| `-c` / `--cache-level` | 3 | Cache level for domain partitioning |
| `-C` / `--cpumasks` | -- | Manual domain cpumasks |
| `-g` / `--greedy-threshold` | 1 | Min queued tasks for same-NUMA stealing |
| `--greedy-threshold-x-numa` | 0 | Min queued tasks for cross-NUMA stealing |
| `-D` / `--direct-greedy-under` | 90.0 | Utilization % below which direct greedy is enabled |
| `-K` / `--kick-greedy-under` | 100.0 | Utilization % below which kick greedy is enabled |
| `-r` / `--direct-greedy-numa` | false | Allow direct greedy across NUMA nodes |
| `-k` / `--kthreads-local` | false | Put per-CPU kthreads in local DSQ |
| `-b` / `--balanced-kworkers` | false | Exclude kworkers from load balancing |
| `-f` / `--fifo-sched` | false | Use FIFO instead of weighted vtime |
| `--mempolicy-affinity` | false | Soft NUMA affinity based on mempolicy |
| `--no-load-balance` | false | Disable userspace load balancing |
| `-p` / `--partial` | false | Only schedule SCHED_EXT tasks |
| `--perf` | 0 | CPU frequency governor hint (0-1024) |

## BPF Arena Allocator (SDT)

The scheduler uses a custom arena-based allocator (`sdt_alloc`) for both task contexts and domain contexts. This avoids BPF map overhead for per-task data.

### Radix Tree Structure

- **3 levels** of 512-entry nodes (`SDT_TASK_ENTS_PER_CHUNK = 512`)
- Each node has a **descriptor** (`sdt_desc`) with a 512-bit allocation bitmap and a pointer to a `sdt_chunk`
- Leaf chunks contain `sdt_data` entries (with a `tid` union for index + generation number, and a flexible `payload[]` array)
- Internal chunks contain pointers to child descriptors

### Allocation Flow

1. `sdt_alloc_attempt` pre-allocates arena pages into a stack to avoid allocation under lock
2. `sdt_find_empty` traverses the radix tree to find an unallocated slot, allocating new chunks as needed
3. `sdt_alloc_from_pool` / `sdt_alloc_from_pool_sleepable` carve elements from pre-allocated page slabs

### Generation Numbers

Each `sdt_data` entry has a `genn` field that is incremented on free. Combined with the radix tree index, this forms a unique'ish 64-bit ID (`union sdt_id`) that helps detect stale references.

### Static Allocator

`sdt_static_alloc` provides simple bump-pointer allocation for long-lived objects (like domain contexts). Memory is allocated in configurable page-granularity chunks and never freed.

## Vtime Fairness Model

When FIFO mode is disabled, scx_rusty uses **weighted fair queuing with deadline boosting**:

1. **Vtime advancement**: When a task stops running, its `dsq_vtime` advances by `delta * 100 / weight`. Higher-weight tasks advance slower, accumulating less vtime per unit of CPU time, and thus getting more CPU time over the long run.

2. **Deadline computation**: The task's `deadline = dsq_vtime + request_length`, where `request_length` is inversely scaled by the latency weight derived from the task's interactivity metrics. Interactive tasks (high waker/blocked frequency, low runtime) get shorter request lengths and thus earlier deadlines.

3. **DSQ ordering**: Tasks are inserted into domain DSQs ordered by their `deadline` via `scx_bpf_dsq_insert_vtime`. This creates an EDF-like ordering where interactive tasks are preferentially scheduled.

4. **Min vruntime tracking**: Each domain tracks `min_vruntime` (updated in `rusty_running` under spinlock). This is used to clamp newly-waking tasks' vtime to prevent starvation and ensure bounded catch-up.

5. **Fair scaling helpers**:
   - `scale_up_fair(value, weight) = value * weight / 100` -- scales proportionally to weight
   - `scale_inverse_fair(value, weight) = value * 100 / weight` -- scales inversely to weight
