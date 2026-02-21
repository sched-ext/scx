# Linux EEVDF Scheduler

Generated: 2026-02-21

Source: Linux kernel tree at `~/playground/linux` (kernel 6.x development branch)

## Overview

The **Earliest Eligible Virtual Deadline First** (EEVDF) scheduler is the
current built-in fair scheduling policy in the Linux kernel, replacing the
older Completely Fair Scheduler (CFS) heuristics. It lives in
`kernel/sched/fair.c` and still uses the `SCHED_NORMAL`, `SCHED_BATCH`, and
`SCHED_IDLE` policy classes -- the scheduling class itself is still called
`fair_sched_class`.

### History and Authorship

The EEVDF algorithm was originally described in a 1995 academic paper by
Ion Stoica and Hussein Abdel-Wahab. The Linux implementation was written by
**Peter Zijlstra** (Intel) and merged through Ingo Molnar's scheduler tree.

The transition happened across a series of commits landing for Linux **6.6**
(August-October 2023):

| Commit | Date | Description |
|--------|------|-------------|
| `af4cf40470c2` | 2023-05-31 | Add `cfs_rq::avg_vruntime` -- the weighted average V |
| `86bfbb7ce4f6` | 2023-05-31 | Add lag-based placement across sleep/wake |
| `147f3efaa241` | 2023-05-31 | Implement the EEVDF-like scheduling policy |
| `5e963f2bd465` | 2023-05-31 | **"Commit to EEVDF"** -- remove old CFS heuristics |
| `2227a957e1d5` | 2023-11-15 | Sort RB-tree by virtual deadline (Abel Wu) |
| `ee4373dc902c` | 2023-11-15 | O(1) fastpath for task selection |

The "Commit to EEVDF" patch (`5e963f2bd465`) removed 450 lines of CFS
heuristics (the `GENTLE_FAIR_SLEEPERS`, `START_DEBIT`,
`sched_latency`/`sched_min_granularity` knobs, etc.) and replaced them with
the cleaner EEVDF model.

### Why Replace CFS?

CFS was a Weighted Fair Queueing (WFQ) scheduler with a single parameter
(weight / nice value). It picked the task with the smallest `vruntime`
("leftmost" in the rb-tree). Latency behavior was controlled by heuristics:
`sched_latency`, `sched_min_granularity`, wakeup bonuses, `GENTLE_FAIR_SLEEPERS`,
buddy mechanisms, etc. These heuristics were fragile and often conflicting.

EEVDF provides a principled two-parameter model (weight + request size) where
latency guarantees emerge naturally from the algorithm rather than from
layered heuristics.

## Architecture / Design

### Core Data Structures

The key structures are `struct sched_entity` (per-task scheduling state) and
`struct cfs_rq` (per-CPU fair run queue).

#### `struct sched_entity` (from `include/linux/sched.h`)

```c
struct sched_entity {
    struct load_weight      load;           // weight derived from nice
    struct rb_node          run_node;       // node in the deadline-sorted rb-tree
    u64                     deadline;       // virtual deadline
    u64                     min_vruntime;   // augmented: min vruntime in subtree
    u64                     min_slice;      // augmented: min slice in subtree

    unsigned char           on_rq;
    unsigned char           sched_delayed;  // delayed-dequeue flag
    unsigned char           rel_deadline;   // relative deadline (during migration)
    unsigned char           custom_slice;   // user-specified slice via sched_setattr()

    u64                     exec_start;     // wall-clock start of current run
    u64                     sum_exec_runtime;
    u64                     prev_sum_exec_runtime;
    u64                     vruntime;       // virtual runtime consumed
    union {
        s64                 vlag;           // V - v_i when off-rq (lag storage)
        u64                 vprot;          // protect-slice upper bound when running
    };
    u64                     slice;          // request size r_i (nanoseconds)
    // ... group scheduling, load averages, etc.
};
```

#### `struct cfs_rq` (from `kernel/sched/sched.h`)

```c
struct cfs_rq {
    struct load_weight      load;
    unsigned int            nr_queued;      // entities on this rq
    unsigned int            h_nr_queued;    // hierarchical count
    unsigned int            h_nr_runnable;  // runnable (excludes delayed)
    unsigned int            h_nr_idle;      // SCHED_IDLE tasks

    s64                     avg_vruntime;   // weighted sum of (v_i - v0) * w_i
    u64                     avg_load;       // sum of weights (W)
    u64                     min_vruntime;   // monotonic floor (v0)

    struct rb_root_cached   tasks_timeline; // rb-tree sorted by deadline
    struct sched_entity     *curr;          // currently running entity
    struct sched_entity     *next;          // buddy hint
    // ... load tracking, bandwidth control, group scheduling ...
};
```

### RB-Tree Organization

The rb-tree (`tasks_timeline`) is **sorted by virtual deadline** (the
`entity_before()` comparator):

```c
static inline bool entity_before(const struct sched_entity *a,
                                 const struct sched_entity *b)
{
    return (s64)(a->deadline - b->deadline) < 0;
}
```

This means the **leftmost** node has the earliest deadline. The tree is
**augmented** with two fields propagated from children to parents:

1. **`min_vruntime`**: the minimum `vruntime` in the subtree (used for
   eligibility pruning during the heap search).
2. **`min_slice`**: the minimum `slice` in the subtree (used for
   `RUN_TO_PARITY` protection).

The augmentation callbacks are registered via:

```c
RB_DECLARE_CALLBACKS(static, min_vruntime_cb, struct sched_entity,
                     run_node, min_vruntime, min_vruntime_update);
```

### How It Differs from CFS

| Aspect | CFS | EEVDF |
|--------|-----|-------|
| Tree sort key | `vruntime` (smallest first) | `deadline` (earliest first) |
| Pick-next logic | Leftmost node | Earliest eligible deadline |
| Latency control | Heuristics (`sched_latency`) | Virtual deadline from slice |
| Parameters | weight only | weight + slice (request size) |
| Preemption trigger | vruntime comparison + granularity | Deadline expiry / slice completion |
| Augmented data | None (just leftmost cache) | `min_vruntime` + `min_slice` heap |
| Sleeper fairness | `GENTLE_FAIR_SLEEPERS` heuristic | Lag-based placement |

## Key Concepts

### Virtual Runtime (`vruntime`)

Each task's `vruntime` tracks how much **virtual** CPU time it has consumed.
For a task at nice 0 (weight 1024), virtual time equals wall-clock time. For
other weights, virtual time is scaled:

```
vruntime += delta_exec * NICE_0_LOAD / weight
```

This is computed by `calc_delta_fair()`:

```c
static inline u64 calc_delta_fair(u64 delta, struct sched_entity *se)
{
    if (unlikely(se->load.weight != NICE_0_LOAD))
        delta = __calc_delta(delta, NICE_0_LOAD, &se->load);
    return delta;
}
```

A higher-weight (lower nice) task accumulates vruntime more slowly, meaning
it "uses up" its virtual time allowance slower and gets more real CPU time.

### Virtual Deadline (`deadline`)

The virtual deadline defines when a task's current "request" expires in virtual
time:

```
vd_i = ve_i + r_i / w_i
```

Where:
- `ve_i` = current vruntime of entity i
- `r_i` = request size (the `slice` field, default 0.7ms)
- `w_i` = weight of entity i

In code (`update_deadline()`):

```c
se->deadline = se->vruntime + calc_delta_fair(se->slice, se);
```

A task with a **shorter slice** gets an **earlier deadline** and thus
higher scheduling priority among eligible tasks. This is the key
mechanism for latency-sensitive tasks.

### Eligibility

A task is **eligible** when it has received less service than its fair share
-- i.e., its lag is non-negative. Formally:

```
lag_i = w_i * (V - v_i) >= 0
```

This simplifies to: a task is eligible when `V >= v_i`, where V is the
weighted average virtual time of all runnable tasks.

In code, eligibility is checked without computing V explicitly (to avoid
precision loss from division):

```c
static int vruntime_eligible(struct cfs_rq *cfs_rq, u64 vruntime)
{
    struct sched_entity *curr = cfs_rq->curr;
    s64 avg = cfs_rq->avg_vruntime;
    long load = cfs_rq->avg_load;

    if (curr && curr->on_rq) {
        unsigned long weight = scale_load_down(curr->load.weight);
        avg += entity_key(cfs_rq, curr) * weight;
        load += weight;
    }

    // V >= v_i  <=>  Sum((v_j - v0) * w_j) >= (v_i - v0) * Sum(w_j)
    return avg >= (s64)(vruntime - cfs_rq->min_vruntime) * load;
}
```

### Lag

Lag measures how much service a task is owed (positive) or has over-consumed
(negative):

```
lag_i = S - s_i = w_i * (V - v_i)
```

Where S is the ideal service and s_i is the actual service received. The
kernel tracks **virtual lag** (`vlag = V - v_i`) to avoid carrying the weight
factor everywhere. When a task is dequeued, `update_entity_lag()` snapshots
its lag:

```c
static void update_entity_lag(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    s64 vlag, limit;

    vlag = avg_vruntime(cfs_rq) - se->vruntime;
    limit = calc_delta_fair(max_t(u64, 2*se->slice, TICK_NSEC), se);

    se->vlag = clamp(vlag, -limit, limit);
}
```

The lag is clamped to prevent runaway values. EEVDF theory gives the bound
`-r_max < lag < max(r_max, q)` for a steady-state system.

### Average Virtual Runtime (V)

V is the **weighted average** of all entities' vruntimes:

```
V = Sum(v_i * w_i) / Sum(w_i)
```

This is tracked incrementally using three fields on `cfs_rq`:

- `min_vruntime` (v0): a monotonically increasing floor
- `avg_vruntime`: stores `Sum((v_i - v0) * w_i)` -- relative to v0 to avoid overflow
- `avg_load`: stores `Sum(w_i)`

Then: `V = avg_vruntime / avg_load + min_vruntime`

The `avg_vruntime()` function computes this, including the currently running
task (which is not in the tree):

```c
u64 avg_vruntime(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    s64 avg = cfs_rq->avg_vruntime;
    long load = cfs_rq->avg_load;

    if (curr && curr->on_rq) {
        unsigned long weight = scale_load_down(curr->load.weight);
        avg += entity_key(cfs_rq, curr) * weight;
        load += weight;
    }

    if (load) {
        if (avg < 0)
            avg -= (load - 1);  // floor division for negative values
        avg = div_s64(avg, load);
    }

    return cfs_rq->min_vruntime + avg;
}
```

When `min_vruntime` advances by delta, `avg_vruntime` is updated to
compensate: `avg_vruntime -= avg_load * delta`.

## Scheduling Algorithm

### The Pick-Next Logic: `pick_eevdf()`

EEVDF selects the runnable task with the **earliest virtual deadline** among
**eligible** tasks. This is the core invariant. The implementation achieves
O(log n) complexity by exploiting the augmented rb-tree:

```c
static struct sched_entity *__pick_eevdf(struct cfs_rq *cfs_rq, bool protect)
{
    struct rb_node *node = cfs_rq->tasks_timeline.rb_root.rb_node;
    struct sched_entity *se = __pick_first_entity(cfs_rq);
    struct sched_entity *curr = cfs_rq->curr;
    struct sched_entity *best = NULL;

    // Fast path: single task
    if (cfs_rq->nr_queued == 1)
        return curr && curr->on_rq ? curr : se;

    // Check if current is still eligible
    if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
        curr = NULL;

    // If current is within its protected slice, keep it
    if (curr && protect && protect_slice(curr))
        return curr;

    // O(1) fast path: leftmost entity (earliest deadline) is eligible
    if (se && entity_eligible(cfs_rq, se)) {
        best = se;
        goto found;
    }

    // O(log n) heap search
    while (node) {
        struct rb_node *left = node->rb_left;

        // If left subtree has eligible entities, go left
        // (they have earlier deadlines)
        if (left && vruntime_eligible(cfs_rq,
                    __node_2_se(left)->min_vruntime)) {
            node = left;
            continue;
        }

        se = __node_2_se(node);

        // Check current node
        if (entity_eligible(cfs_rq, se)) {
            best = se;
            break;
        }

        // Otherwise try right subtree
        node = node->rb_right;
    }

found:
    // Prefer current if it has an earlier deadline than best
    if (!best || (curr && entity_before(curr, best)))
        best = curr;

    return best;
}
```

**How the heap search works**: The tree is sorted by deadline (left = earlier).
The `min_vruntime` augmentation lets us check if **any** node in a subtree
could be eligible: if `min_vruntime` of the subtree satisfies the eligibility
check, there exists at least one eligible entity in that subtree. We always
prefer going left (earlier deadlines). If the left subtree has no eligible
entities, we check the current node, then try right.

### How Deadlines Are Computed

Deadlines are set/reset in `update_deadline()`, called from `update_curr()`:

```c
static bool update_deadline(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    // Has the task consumed its entire slice?
    if ((s64)(se->vruntime - se->deadline) < 0)
        return false;  // deadline not yet reached

    // Refresh the slice from sysctl (unless custom)
    if (!se->custom_slice)
        se->slice = sysctl_sched_base_slice;

    // vd_i = ve_i + r_i / w_i
    se->deadline = se->vruntime + calc_delta_fair(se->slice, se);

    return true;  // triggers reschedule
}
```

When `update_deadline()` returns true (deadline crossed), `update_curr()`
triggers a reschedule via `resched_curr_lazy()`.

### Full Update Path

On every timer tick and at various scheduling events, `update_curr()` is called:

```c
static void update_curr(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    s64 delta_exec;

    if (unlikely(!curr))
        return;

    delta_exec = update_se(rq, curr);  // wall-clock delta
    if (unlikely(delta_exec <= 0))
        return;

    curr->vruntime += calc_delta_fair(delta_exec, curr);
    resched = update_deadline(cfs_rq, curr);
    update_min_vruntime(cfs_rq);

    // ... DL server accounting, CFS bandwidth ...

    if (cfs_rq->nr_queued == 1)
        return;

    if (resched || !protect_slice(curr)) {
        resched_curr_lazy(rq);
        clear_buddies(cfs_rq, curr);
    }
}
```

### The `pick_next_entity()` Wrapper

The actual pick function used by the scheduling class also handles buddy
hints and delayed dequeue:

```c
static struct sched_entity *
pick_next_entity(struct rq *rq, struct cfs_rq *cfs_rq)
{
    // Buddy hint: if PICK_BUDDY is enabled and next buddy is eligible
    if (sched_feat(PICK_BUDDY) &&
        cfs_rq->next && entity_eligible(cfs_rq, cfs_rq->next)) {
        return cfs_rq->next;
    }

    se = pick_eevdf(cfs_rq);
    if (se->sched_delayed) {
        // This entity was delay-dequeued; actually dequeue it now
        dequeue_entities(rq, se, DEQUEUE_SLEEP | DEQUEUE_DELAYED);
        return NULL;  // retry
    }
    return se;
}
```

## Key Mechanisms

### Enqueue and Dequeue

**Enqueue** (`enqueue_entity()`): Places an entity on the rb-tree. The key
step is `place_entity()` which sets the initial vruntime and deadline (see
[Placement](#placement-strategies) below).

**Dequeue** (`dequeue_entity()`): Removes an entity. Before removal,
`update_entity_lag()` snapshots the lag for later placement. If
`PLACE_REL_DEADLINE` is enabled and the task is migrating (not sleeping),
the deadline is stored as a relative offset from vruntime.

### Placement Strategies

`place_entity()` is called when a task is enqueued (wakeup, fork, migration).
It sets the task's vruntime and deadline:

```c
static void
place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
    u64 vslice, vruntime = avg_vruntime(cfs_rq);
    s64 lag = 0;

    if (!se->custom_slice)
        se->slice = sysctl_sched_base_slice;
    vslice = calc_delta_fair(se->slice, se);

    // PLACE_LAG: preserve lag across sleep+wake
    if (sched_feat(PLACE_LAG) && cfs_rq->nr_queued && se->vlag) {
        lag = se->vlag;
        // Inflate lag to compensate for V shifting when we add this entity
        // vl_i = (W + w_i) * vl'_i / W
        load = cfs_rq->avg_load;
        if (curr && curr->on_rq)
            load += scale_load_down(curr->load.weight);
        lag *= load + scale_load_down(se->load.weight);
        lag = div_s64(lag, load);
    }

    se->vruntime = vruntime - lag;

    // PLACE_DEADLINE_INITIAL: new tasks get half a slice
    if (sched_feat(PLACE_DEADLINE_INITIAL) && (flags & ENQUEUE_INITIAL))
        vslice /= 2;

    // vd_i = ve_i + r_i/w_i
    se->deadline = se->vruntime + vslice;
}
```

The lag inflation formula ensures that after the entity is added to the
weighted average, its effective lag matches what was recorded at dequeue time.

### Delay Dequeue (`DELAY_DEQUEUE`)

When a task sleeps and has **negative lag** (has over-consumed its share),
the kernel can **delay its dequeue** -- leaving it on the run queue with
`sched_delayed = 1`. This allows the task to "burn off" its negative lag
through virtual time advancement without actually running.

```c
// In dequeue_entity():
if (sched_feat(DELAY_DEQUEUE) && delay &&
    !entity_eligible(cfs_rq, se)) {
    update_load_avg(cfs_rq, se, 0);
    set_delayed(se);
    return false;  // don't actually dequeue
}
```

When a delayed entity is picked by `pick_next_entity()`, it gets fully
dequeued at that point. When it wakes up, `requeue_delayed_entity()` clears
the delayed state.

The `DELAY_ZERO` feature clips lag to zero on delayed dequeue completion,
preventing tasks from accumulating positive lag while sleeping.

### Slice Protection (`RUN_TO_PARITY`)

The `RUN_TO_PARITY` feature inhibits wakeup preemption until the current
task has either:
1. Reached the zero-lag point, or
2. Exhausted a minimal protected slice

The protected slice is the minimum of the current task's slice and the
smallest slice among all queued entities:

```c
static inline void set_protect_slice(struct cfs_rq *cfs_rq,
                                     struct sched_entity *se)
{
    u64 slice = normalized_sysctl_sched_base_slice;
    u64 vprot = se->deadline;

    if (sched_feat(RUN_TO_PARITY))
        slice = cfs_rq_min_slice(cfs_rq);

    slice = min(slice, se->slice);
    if (slice != se->slice)
        vprot = min_vruntime(vprot,
                se->vruntime + calc_delta_fair(slice, se));

    se->vprot = vprot;
}
```

The `PREEMPT_SHORT` feature allows tasks with shorter slices to break
through `RUN_TO_PARITY` protection, ensuring that latency-sensitive tasks
with small slices can still preempt promptly.

### Load Balancing

Load balancing in EEVDF uses the same framework as before (scheduler
domains, `sched_balance_rq()`, etc.) but adds **eligibility-aware migration**.

Tasks that are ineligible on their source CPU are deprioritized for migration
because they will also be ineligible on the destination (the lag is relative
to the local V, which is similar across CPUs under balanced load):

```c
static inline int task_is_ineligible_on_dst_cpu(struct task_struct *p,
                                                 int dest_cpu)
{
    struct cfs_rq *dst_cfs_rq;
    // ...
    if (sched_feat(PLACE_LAG) && dst_cfs_rq->nr_queued &&
        !entity_eligible(task_cfs_rq(p), &p->se))
        return 1;
    return 0;
}
```

Ineligible tasks are only allowed to migrate when `nr_balance_failed` is
non-zero (the balancer has already tried and failed with eligible tasks).

When a task migrates, `PLACE_REL_DEADLINE` preserves its relative deadline
(stored as `deadline - vruntime`) so it can be reconstituted on the
destination CPU.

### Group Scheduling

EEVDF integrates with the cgroup-based hierarchical scheduling
(`CONFIG_FAIR_GROUP_SCHED`). Each task group has a `sched_entity` that
participates in its parent's cfs_rq, and owns a child cfs_rq containing
the group's tasks.

The `for_each_sched_entity()` macro walks up the hierarchy. The
`pick_task_fair()` function walks **down** the hierarchy, picking from the
top-level cfs_rq and then recursively into group cfs_rqs.

### CFS Bandwidth Control

CFS bandwidth throttling (`CONFIG_CFS_BANDWIDTH`) works as before: each
task group can have a quota/period. When a cfs_rq exhausts its runtime
allocation, it is throttled. The default bandwidth slice is 5ms
(`sysctl_sched_cfs_bandwidth_slice`).

### Yield

`yield_task_fair()` forfeits the remaining vruntime by jumping to the
deadline and assigning a new deadline:

```c
if (entity_eligible(cfs_rq, se)) {
    se->vruntime = se->deadline;
    se->deadline += calc_delta_fair(se->slice, se);
    update_min_vruntime(cfs_rq);
}
```

This effectively moves the task to the back of the eligible queue.

## Time Accounting

### How `vruntime` Advances

On every `update_curr()` call (timer tick, context switch, enqueue/dequeue):

1. **Wall-clock delta**: `delta_exec = now - se->exec_start`
2. **Virtual time delta**: `calc_delta_fair(delta_exec, se)` =
   `delta_exec * NICE_0_LOAD / se->load.weight`
3. **Accumulate**: `curr->vruntime += virtual_delta`
4. **Check deadline**: if `vruntime >= deadline`, assign new deadline and
   trigger reschedule

### Weight / Nice Mapping

Weights are defined in `sched_prio_to_weight[]` (in `kernel/sched/core.c`):

| Nice | Weight | Ratio to nice 0 |
|------|--------|-----------------|
| -20 | 88761 | ~86.7x |
| -10 | 9548 | ~9.3x |
| -5 | 3121 | ~3.0x |
| 0 | 1024 | 1.0x |
| 5 | 335 | ~0.33x |
| 10 | 110 | ~0.11x |
| 19 | 15 | ~0.015x |

Each nice level step corresponds to roughly a 1.25x ratio (approximately
10% CPU share difference). The `NICE_0_LOAD` is 1024.

Pre-computed inverse weights (`sched_prio_to_wmult[]`) accelerate the
division in `__calc_delta()` by converting it to multiplication + shift.

### `min_vruntime`

`min_vruntime` on the cfs_rq is a **monotonically increasing** floor that
tracks the minimum of:
- The current task's vruntime (if running)
- The leftmost tree node's `min_vruntime` augmented value

It never goes backwards ("ensure we never gain time by being placed
backwards"). When `min_vruntime` advances, `avg_vruntime` is adjusted
to keep the relative-to-v0 representation consistent:

```c
static u64 __update_min_vruntime(struct cfs_rq *cfs_rq, u64 vruntime)
{
    u64 min_vruntime = cfs_rq->min_vruntime;
    s64 delta = (s64)(vruntime - min_vruntime);
    if (delta > 0) {
        avg_vruntime_update(cfs_rq, delta);
        min_vruntime = vruntime;
    }
    return min_vruntime;
}
```

### Custom Slices via `sched_setattr()`

Users can set a custom request size (slice) via the `sched_runtime` field
of `sched_setattr()`:

```c
void __setparam_fair(struct task_struct *p, const struct sched_attr *attr)
{
    struct sched_entity *se = &p->se;

    p->static_prio = NICE_TO_PRIO(attr->sched_nice);
    if (attr->sched_runtime) {
        se->custom_slice = 1;
        se->slice = clamp_t(u64, attr->sched_runtime,
                            NSEC_PER_MSEC/10,    // min: 0.1ms
                            NSEC_PER_MSEC*100);   // max: 100ms
    } else {
        se->custom_slice = 0;
        se->slice = sysctl_sched_base_slice;
    }
}
```

Smaller slices produce earlier virtual deadlines, giving the task higher
priority among eligible tasks and thus better latency.

## Preemption

### Tick-Driven Preemption

In `update_curr()`, when the current task's vruntime crosses its deadline
(`update_deadline()` returns true), a lazy reschedule is requested. The
`entity_tick()` function calls `update_curr()` on each timer tick.

Additionally, if the current task is not within its protected slice
(`!protect_slice(curr)`), a reschedule is triggered even before deadline
expiry -- this handles the case where a newly woken task has become more
eligible.

```c
// In update_curr():
if (resched || !protect_slice(curr)) {
    resched_curr_lazy(rq);
    clear_buddies(cfs_rq, curr);
}
```

### Wakeup Preemption

`check_preempt_wakeup_fair()` is called when a task wakes up. The
decision flow:

1. **Skip if already rescheduling** (`TIF_NEED_RESCHED` set)
2. **Skip if `WAKEUP_PREEMPTION` disabled**
3. **Find matching scheduling entities** in the group hierarchy
4. **Always preempt idle entities** for non-idle wakers
5. **Skip if BATCH/IDLE policy** (they never preempt)
6. **Check `PREEMPT_SHORT`**: if the waker has a shorter slice than
   current, set `do_preempt_short = true`
7. **EEVDF eligibility check**: call `__pick_eevdf(cfs_rq, !do_preempt_short)`
   -- if the waking task would be picked, preempt

```c
// If @p has become the most eligible task, force preemption.
if (__pick_eevdf(cfs_rq, !do_preempt_short) == pse)
    goto preempt;
```

When `do_preempt_short` is true, slice protection is passed as false to
`__pick_eevdf()`, allowing the short-slice waker to override the current
task's protection window.

### EEVDF vs Old CFS Preemption

In old CFS, preemption was based on comparing vruntimes with a granularity
guard (`sched_min_granularity`). This was a heuristic that tried to balance
fairness against context-switch overhead.

In EEVDF, preemption is driven by two clean mechanisms:
- **Deadline expiry**: the task has consumed its slice
- **Eligibility**: a waking task with an earlier deadline and positive lag

The `RUN_TO_PARITY` feature provides a principled replacement for
granularity-based guards: a task runs at least until it reaches the 0-lag
point or completes the minimum slice among queued entities.

## Configuration

### `sysctl_sched_base_slice` (debugfs: `/sys/kernel/debug/sched/base_slice_ns`)

The default request size for EEVDF. Default: **700,000 ns (0.7ms)**, scaled
by `1 + ilog2(num_online_cpus)`. This replaces the old `sched_min_granularity`.
Smaller values improve latency but increase context switches.

### `sysctl_sched_migration_cost` (debugfs: `migration_cost_ns`)

Time threshold for considering a task "cache hot". Default: **500,000 ns (0.5ms)**.
Cache-hot tasks are not migrated during load balancing.

### `sysctl_sched_tunable_scaling` (debugfs: `tunable_scaling`)

Controls how `base_slice` scales with CPU count:
- `0` (NONE): no scaling
- `1` (LOG): `* (1 + ilog2(ncpus))` -- **default**
- `2` (LINEAR): `* ncpus`

### Scheduler Features (debugfs: `/sys/kernel/debug/sched/features`)

These are toggled via `/sys/kernel/debug/sched/features`:

| Feature | Default | Description |
|---------|---------|-------------|
| `PLACE_LAG` | on | Preserve lag across sleep/wake cycles |
| `PLACE_DEADLINE_INITIAL` | on | New tasks get half a slice to ease in |
| `PLACE_REL_DEADLINE` | on | Preserve relative deadline on migration |
| `RUN_TO_PARITY` | on | Inhibit preemption until 0-lag or min-slice |
| `PREEMPT_SHORT` | on | Short-slice tasks can override RUN_TO_PARITY |
| `DELAY_DEQUEUE` | on | Keep ineligible sleeping tasks on rq to burn lag |
| `DELAY_ZERO` | on | Clip lag to 0 on delayed dequeue completion |
| `NEXT_BUDDY` | off | Prefer last-woken task for cache locality |
| `PICK_BUDDY` | on | Honor the `cfs_rq->next` buddy hint |
| `CACHE_HOT_BUDDY` | on | Consider buddy tasks cache-hot |
| `WAKEUP_PREEMPTION` | on | Allow wakeup-time preemption |
| `HRTICK` | off | Use hrtimer for precise slice expiry |
| `SIS_UTIL` | on | Limit idle CPU scans based on utilization |

### CFS Bandwidth

- `sched_cfs_bandwidth_slice_us`: per-cgroup runtime allocation quantum
  (default: 5000us = 5ms). Available via `/proc/sys/kernel/`.

### Per-Task Tuning via `sched_setattr()`

```c
struct sched_attr attr = {
    .size = sizeof(attr),
    .sched_policy = SCHED_NORMAL,
    .sched_nice = -5,
    .sched_runtime = 300000,  // 0.3ms slice for lower latency
};
sched_setattr(pid, &attr, 0);
```

## Relationship to sched_ext

### Conceptual Parallels

sched_ext (BPF extensible scheduler) borrows several concepts from EEVDF:

1. **Virtual time ordering**: sched_ext's dispatch queues (DSQs) support
   **vtime-ordered** priority queues via `scx_bpf_dsq_insert_vtime()`. Tasks
   are ordered by `p->scx.dsq_vtime` using an rb-tree (`struct scx_dispatch_q::priq`),
   directly analogous to EEVDF's deadline-ordered rb-tree.

2. **Weight-based fairness**: sched_ext tasks carry `p->scx.weight` that
   BPF schedulers use to scale virtual time advancement, mirroring how
   EEVDF uses `se->load.weight` to scale vruntime.

3. **Slice-based time allocation**: sched_ext tasks have `p->scx.slice`
   that determines how long they run before the scheduler regains control,
   directly paralleling `se->slice` in EEVDF.

### Where They Diverge

- **Built-in DSQs** (local per-CPU and global) are always FIFO, not
  vtime-ordered. Vtime ordering is only available on user-created DSQs.
  EEVDF always uses its deadline-ordered tree.

- sched_ext does not enforce eligibility -- any task dispatched to a DSQ
  can run. The BPF scheduler is responsible for fairness. EEVDF enforces
  eligibility as a hard constraint.

- sched_ext does not have EEVDF's lag-tracking machinery. BPF schedulers
  that want fairness must implement their own vtime accounting.

### Fallback Behavior

When no BPF scheduler is loaded (or when one aborts), sched_ext tasks
fall back to the fair scheduling class and are scheduled by EEVDF. The
`SCHED_EXT` policy is treated as equivalent to `SCHED_NORMAL` by the
`normal_policy()` and `fair_policy()` checks in `kernel/sched/sched.h`.

### Lessons for BPF Scheduler Design

BPF schedulers that aim for fairness can implement an EEVDF-like policy:

1. Track per-task vruntime, advancing it by `delta / weight`
2. Compute a virtual deadline: `vtime + slice / weight`
3. Dispatch to a vtime-ordered DSQ using `scx_bpf_dsq_insert_vtime()`
   with the deadline as the vtime key
4. Use `scx_bpf_kick_cpu()` for wakeup preemption when a waking task
   has an earlier deadline than the running task

This is essentially what several production sched_ext schedulers
(scx_rusty, scx_layered) do in their fairness layers, using
weight-scaled vtime to order dispatch.
