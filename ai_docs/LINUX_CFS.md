# Linux CFS (Completely Fair Scheduler)

Generated: 2026-02-21

## Overview

The **Completely Fair Scheduler (CFS)** was the default Linux process scheduler for the `SCHED_NORMAL`, `SCHED_BATCH`, and `SCHED_IDLE` scheduling policies from kernel **2.6.23** (October 2007) through approximately kernel **6.6** (late 2023), when it began being replaced by EEVDF. CFS was designed and implemented by **Ingo Molnar**, building on ideas from **Con Kolivas**'s earlier work on the Rotating Staircase Deadline (RSDL) and SD schedulers, which demonstrated that a simple, deterministic, fairness-driven approach could outperform the complex heuristic-laden O(1) scheduler that preceded CFS.

CFS replaced the O(1) scheduler, which used two priority arrays (active and expired) with 140 priority levels and complex heuristic-based interactivity estimation. The O(1) scheduler suffered from pathological behaviors with certain workload patterns and its heuristics could be gamed by adversarial programs. CFS took a radically different approach: rather than trying to guess which tasks are "interactive" via heuristics, it simply modeled an ideal fair CPU and let fairness itself produce good interactive behavior.

Key contributors beyond Molnar included:
- **Mike Galbraith** -- interactivity improvements
- **Dmitry Adamushko** -- various enhancements
- **Srivatsa Vaddagiri** (IBM) -- group scheduling extensions
- **Thomas Gleixner** -- scaled math optimizations
- **Peter Zijlstra** -- adaptive scheduling granularity, math enhancements, and later the EEVDF replacement

The implementation lived in `kernel/sched/fair.c`, which grew to be one of the largest files in the kernel (over 12,000 lines).

## Architecture / Design

### The "Ideal Fair CPU" Concept

The core design philosophy of CFS can be stated in a single sentence from Molnar's documentation:

> CFS basically models an "ideal, precise multi-tasking CPU" on real hardware.

An "ideal multi-tasking CPU" is a hypothetical processor that can run each task at precisely `1/nr_running` of its full speed, in perfect parallelism. For example, with 2 tasks running, each would receive exactly 50% of CPU power simultaneously.

On real hardware, only one task can run at a time, so CFS introduces **virtual runtime** (`vruntime`) to track how much CPU time each task *should* have received on this ideal processor versus how much it has actually received. The scheduler then always picks the task that is furthest behind -- the one that has received the least service relative to its fair share.

### Red-Black Tree

CFS replaced the O(1) scheduler's priority arrays with a **time-ordered red-black tree** (an `rb_root_cached` in Linux terminology). All runnable tasks are kept in this self-balancing binary search tree, sorted by their `vruntime` key.

```c
struct cfs_rq {
    struct rb_root_cached    tasks_timeline;   /* The RB-tree */
    struct sched_entity      *curr;            /* Currently running entity */
    struct sched_entity      *next;            /* "Next buddy" hint */
    struct sched_entity      *last;            /* "Last buddy" hint */
    struct sched_entity      *skip;            /* Entity to skip */
    u64                      min_vruntime;     /* Monotonically increasing floor */
    struct load_weight       load;             /* Sum of weights on this rq */
    unsigned int             nr_running;       /* Number of runnable entities */
    /* ... */
};
```

The `rb_root_cached` variant caches a pointer to the leftmost (minimum) node, making the "pick the task with smallest vruntime" operation O(1) rather than O(log n). Insertion and deletion remain O(log n).

This design eliminated the "array switch" artifacts that plagued both the O(1) scheduler and RSDL/SD, where periodic bulk reorganization of the run queue caused visible latency spikes.

### Scheduling Entity Hierarchy

CFS operates on **scheduling entities** (`struct sched_entity`), not directly on tasks. This abstraction enables group scheduling: a scheduling entity can represent either a single task or an entire cgroup (task group), with nested CFS run queues forming a hierarchy.

```c
struct sched_entity {
    struct load_weight       load;                /* Weight derived from nice level */
    struct rb_node           run_node;             /* Node in the RB-tree */
    unsigned char            on_rq;                /* Whether entity is on the runqueue */

    u64                      exec_start;           /* Timestamp of last scheduling event */
    u64                      sum_exec_runtime;     /* Total wall-clock runtime */
    u64                      prev_sum_exec_runtime;
    u64                      vruntime;             /* Virtual runtime */

    /* Group scheduling */
    int                      depth;
    struct sched_entity      *parent;
    struct cfs_rq            *cfs_rq;   /* rq on which this entity is queued */
    struct cfs_rq            *my_q;     /* rq "owned" by this group entity */

    struct sched_avg         avg;       /* Per-entity load average (PELT) */
};
```

## Key Concepts

### Virtual Runtime (vruntime)

The **virtual runtime** (`p->se.vruntime`, in nanoseconds) is the central abstraction. It represents the amount of CPU time a task has consumed, normalized by its weight. On the ideal fair CPU, all tasks would always have the same vruntime. On real hardware, vruntimes diverge slightly, and the scheduler corrects this by always running the task with the smallest vruntime.

For a task with nice-0 weight (1024), vruntime advances at the same rate as wall-clock time. For higher-weight tasks (lower nice values), vruntime advances *slower*, giving them more actual CPU time. For lower-weight tasks (higher nice values), vruntime advances *faster*, giving them less actual CPU time.

The conversion is computed by `calc_delta_fair()`:

```c
static inline u64 calc_delta_fair(u64 delta, struct sched_entity *se)
{
    if (unlikely(se->load.weight != NICE_0_LOAD))
        delta = __calc_delta(delta, NICE_0_LOAD, &se->load);
    return delta;
}
```

This computes: `vruntime_delta = wall_delta * (NICE_0_LOAD / task_weight)`.

For a nice-0 task, `weight == NICE_0_LOAD`, so vruntime equals wall time (the common fast path skips the division entirely). For a nice-(-20) task with weight 88761, vruntime advances at roughly `1024/88761 ~= 1.15%` of wall time -- it can run about 87x longer before its vruntime catches up. For a nice-19 task with weight 15, vruntime advances at `1024/15 ~= 68x` wall time.

### Weight Table and Nice Levels

CFS uses a carefully constructed weight table (`sched_prio_to_weight[]`) that maps the 40 nice levels (-20 to +19) to weights. The table follows a **multiplicative** (exponential) progression where each nice level represents approximately a **10% change** in CPU share:

```c
const int sched_prio_to_weight[40] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};
```

The multiplier between adjacent levels is approximately **1.25** (= 1/0.8). If task A goes up 1 nice level (~10% less CPU) and task B goes down 1 nice level (~10% more CPU), the relative difference between them is ~25%, matching the 1.25 ratio.

Key properties:
- **Nice 0** has weight **1024** (`NICE_0_LOAD`)
- **Nice -20** has weight **88761** (~87x nice 0)
- **Nice +19** has weight **15** (~1.5% of nice 0)
- The ratio between nice -20 and +19 is approximately **5917:1**
- Each single nice level step produces the same *relative* effect regardless of absolute nice level

An inverse weight table (`sched_prio_to_wmult[]`) provides pre-computed `2^32 / weight` values to convert divisions into multiplications for performance.

### min_vruntime

The `cfs_rq->min_vruntime` field is a **monotonically increasing** value that tracks the smallest vruntime among all entities on the run queue (including the currently running entity). It serves several critical purposes:

1. **Placing new/waking tasks**: New tasks and tasks waking from sleep have their vruntime set relative to `min_vruntime` to prevent them from monopolizing the CPU (if placed too far left) or being starved (if placed too far right).

2. **Migration normalization**: When a task migrates between CPUs, its vruntime is renormalized relative to the source and destination `min_vruntime` values, since each CPU's vruntime timeline is independent.

3. **Preventing vruntime overflow**: By keeping all vruntimes clustered near `min_vruntime`, the scheduler avoids issues with the unsigned 64-bit arithmetic wrapping.

The update logic (from the pre-EEVDF code):

```c
static void update_min_vruntime(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    struct rb_node *leftmost = rb_first_cached(&cfs_rq->tasks_timeline);
    u64 vruntime = cfs_rq->min_vruntime;

    if (curr) {
        if (curr->on_rq)
            vruntime = curr->vruntime;
        else
            curr = NULL;
    }

    if (leftmost) {
        struct sched_entity *se = rb_entry(leftmost, ...);
        if (!curr)
            vruntime = se->vruntime;
        else
            vruntime = min_vruntime(vruntime, se->vruntime);
    }

    /* ensure we never gain time by being placed backwards */
    cfs_rq->min_vruntime = max_vruntime(cfs_rq->min_vruntime, vruntime);
}
```

The `max_vruntime()` at the end guarantees monotonicity -- `min_vruntime` can only advance forward.

### Sleeper Fairness

In classic CFS (pre-EEVDF), **sleeper fairness** was one of the most debated mechanisms. When a task wakes up from sleep, its old vruntime may be far behind `min_vruntime`, which would give it an enormous amount of CPU time to "catch up." Unconstrained, this creates two problems:

1. Tasks could game the scheduler by sleeping briefly and then running with a large vruntime credit.
2. Long-sleeping tasks would preempt everything upon waking.

CFS addressed this through the `place_entity()` function, which bounded the vruntime credit:

```c
/* Pre-EEVDF place_entity() for waking tasks: */
static void place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int initial)
{
    u64 vruntime = cfs_rq->min_vruntime;

    if (initial && sched_feat(START_DEBIT))
        vruntime += sched_vslice(cfs_rq, se);  /* New tasks start behind */

    if (!initial) {
        unsigned long thresh = sysctl_sched_latency;

        /* GENTLE_FAIR_SLEEPERS: halve the credit */
        if (sched_feat(GENTLE_FAIR_SLEEPERS))
            thresh >>= 1;

        vruntime -= thresh;  /* Allow up to 'thresh' of catch-up */
    }

    se->vruntime = max_vruntime(se->vruntime, vruntime);
}
```

The `GENTLE_FAIR_SLEEPERS` feature (enabled by default) gave sleepers only 50% of their service deficit (half of `sched_latency`, i.e., 3ms by default). This was a pragmatic compromise: it allowed waking tasks to run sooner (good for interactivity) while preventing them from accumulating too much credit (preventing abuse).

The `START_DEBIT` feature penalized new tasks by debiting them one virtual timeslice, preventing fork bombs from getting immediate CPU access.

## Scheduling Algorithm

### The Scheduling Period and Timeslice Calculation

Unlike the O(1) scheduler's fixed timeslices, CFS dynamically computed a **scheduling period** based on the number of runnable tasks:

```c
static u64 __sched_period(unsigned long nr_running)
{
    if (unlikely(nr_running > sched_nr_latency))
        return nr_running * sysctl_sched_min_granularity;
    else
        return sysctl_sched_latency;
}
```

- With **8 or fewer** tasks (`sched_nr_latency = sched_latency / min_granularity = 6ms / 0.75ms = 8`): the period is `sched_latency` (6ms). Each task gets a proportional share of 6ms.
- With **more than 8** tasks: the period stretches to `nr_running * min_granularity`, ensuring each task gets at least 0.75ms. This prevents excessive context switching with many tasks.

Each task's actual timeslice was computed by `sched_slice()`:

```c
static u64 sched_slice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    u64 slice = __sched_period(nr_running + !se->on_rq);

    for_each_sched_entity(se) {
        /* slice = period * (task_weight / rq_total_weight) */
        slice = __calc_delta(slice, se->load.weight, &cfs_rq->load);
    }

    return max_t(u64, slice, sysctl_sched_min_granularity);
}
```

So a nice-0 task in a period of 6ms with one other nice-0 task would get `6ms * 1024/2048 = 3ms`. A nice-(-5) task competing with a nice-0 task would get `6ms * 3121/4145 ~= 4.52ms`.

### Pick-Next-Task Logic

In classic CFS, `pick_next_entity()` selected the next task to run by starting with the leftmost entity in the RB-tree (the one with the smallest vruntime) and then applying buddy heuristics:

```c
static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
    struct sched_entity *left = __pick_first_entity(cfs_rq);
    struct sched_entity *se;

    /* Consider curr if it has smaller vruntime than leftmost */
    if (!left || (curr && entity_before(curr, left)))
        left = curr;

    se = left; /* Ideally run the leftmost entity */

    /* Avoid skip buddy if someone else is close enough */
    if (cfs_rq->skip == se) {
        struct sched_entity *second = __pick_next_entity(se);
        if (second && wakeup_preempt_entity(second, left) < 1)
            se = second;
    }

    /* Honor next buddy (wakeup preemption hint) if not too unfair */
    if (cfs_rq->next && wakeup_preempt_entity(cfs_rq->next, left) < 1)
        se = cfs_rq->next;

    /* Honor last buddy (cache locality hint) if not too unfair */
    else if (cfs_rq->last && wakeup_preempt_entity(cfs_rq->last, left) < 1)
        se = cfs_rq->last;

    return se;
}
```

The buddy system had three slots:
- **`next`**: Set during wakeup preemption -- the task that just woke up and wants to run.
- **`last`**: Set when a task gets preempted -- the task that was just running (cache locality).
- **`skip`**: Set during `sched_yield()` -- the task volunteering to give up the CPU.

The `wakeup_preempt_entity()` check ensured buddies could only override the "ideal" leftmost choice if they were not too far behind in vruntime (within `wakeup_granularity`).

### How Fairness Is Maintained

The fairness loop works as follows:

1. A task runs on the CPU.
2. On each scheduler tick (and at context switches), `update_curr()` is called.
3. `update_curr()` adds the wall-clock time elapsed to the task's vruntime (scaled by weight).
4. The task's vruntime grows, pushing it rightward in the RB-tree.
5. Eventually another entity becomes the leftmost (lowest vruntime), meaning it has received the least service.
6. At the next scheduling decision point, that leftmost entity is selected.
7. The cycle repeats, ensuring all tasks converge toward equal vruntime.

Because higher-weight tasks have their vruntime advance more slowly, they naturally accumulate more wall-clock time before being preempted, receiving their proportionally larger share.

## Key Mechanisms

### Load Balancing

CFS includes a sophisticated multi-level load balancing system operating across **scheduling domains** (SMT, cores, LLC, NUMA nodes). The balancer runs periodically and on idle CPUs.

Key components:
- **`sched_balance_rq()`** (formerly `load_balance()`): The main periodic balancer that runs at each scheduling domain level, finding the busiest group/queue and migrating tasks.
- **`sched_balance_newidle()`**: Runs when a CPU goes idle, pulling tasks from busy CPUs to maximize utilization.
- **`sched_balance_find_src_group()`**: Identifies the busiest scheduling group within a domain based on load statistics.
- **Active balancing**: When passive migration isn't possible (e.g., due to affinity), the kernel can request a busy CPU to push a task via a CPU stop callback.

The balancer uses the **Per-Entity Load Tracking (PELT)** mechanism to make decisions based on actual utilization rather than simple task counts.

The migration cost tunable (`sysctl_sched_migration_cost`, default 500us) helps decide whether migration is worthwhile -- tasks that have been running for less than this threshold are considered "cache hot" and are less likely to be migrated.

### NUMA Balancing

When `CONFIG_NUMA_BALANCING` is enabled, CFS includes NUMA-aware task placement. The kernel:

1. Periodically unmaps pages from task address spaces to generate page faults.
2. Tracks which NUMA nodes each task accesses most frequently.
3. Migrates tasks to the NUMA node where most of their memory resides.
4. Groups tasks that share memory onto the same NUMA node.

This is integrated into the fair scheduler via `task_tick_numa()`, called from `task_tick_fair()` on each tick.

### Group Scheduling (CONFIG_FAIR_GROUP_SCHED)

Group scheduling extends CFS to provide fairness between groups of tasks (e.g., per-user or per-cgroup), not just between individual tasks.

Each task group has a `cpu.shares` (or `cpu.weight` in cgroup v2) value that determines its relative weight. The hierarchy works recursively:

```
Root CFS RQ
├── Group A (shares=2048)
│   ├── Task 1 (nice 0, weight 1024)
│   └── Task 2 (nice 0, weight 1024)
└── Group B (shares=1024)
    └── Task 3 (nice 0, weight 1024)
```

In this example, Group A gets 2/3 of CPU time and Group B gets 1/3, regardless of how many tasks are in each group. Within Group A, Tasks 1 and 2 split their group's allocation evenly.

The group entity weight is computed by `calc_group_shares()`:

```c
/* Simplified: */
ge->load.weight = tg->shares * grq->load.weight / tg_load_avg
```

This hierarchical weight computation was one of CFS's most complex subsystems, requiring careful approximations to avoid prohibitively expensive global summations.

### CPU Bandwidth Control (CONFIG_CFS_BANDWIDTH)

CFS bandwidth control allows capping the maximum CPU time available to a task group within a period:

- **`cpu.cfs_quota_us`**: Maximum CPU time (microseconds) per period (-1 = unlimited)
- **`cpu.cfs_period_us`**: Period length (microseconds, default 100ms)
- **`cpu.cfs_burst_us`**: Allowed burst above quota from accumulated unused time

When a group exhausts its quota, all its tasks are **throttled** (removed from the run queue) until the next period begins and quota is refreshed. The runtime is distributed to per-CPU "silos" in slices (default 5ms, controlled by `sched_cfs_bandwidth_slice_us`) to reduce global lock contention.

### Autogroup

The autogroup feature (`CONFIG_SCHED_AUTOGROUP`, enabled by default) automatically creates a task group for each session (TTY). This means that when one terminal runs `make -j64`, the 64 compiler processes share a single group's weight, and another terminal session gets an equal share -- dramatically improving desktop responsiveness under heavy compilation loads without any manual cgroup configuration.

```c
unsigned int sysctl_sched_autogroup_enabled = 1;
```

Each `setsid()` call creates a new autogroup with its own `task_group`, effectively giving each terminal session fair CPU access.

## Time Accounting

### How vruntime Advances

The `update_curr()` function is the heartbeat of CFS. It is called:
- On every scheduler tick (`entity_tick()` -> `update_curr()`)
- At every context switch (`put_prev_entity()` -> `update_curr()`)
- Before enqueueing/dequeuing entities
- Before any scheduling decision

The pre-EEVDF implementation:

```c
static void update_curr(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    u64 now = rq_clock_task(rq_of(cfs_rq));
    u64 delta_exec;

    if (unlikely(!curr))
        return;

    delta_exec = now - curr->exec_start;
    if (unlikely((s64)delta_exec <= 0))
        return;

    curr->exec_start = now;
    curr->sum_exec_runtime += delta_exec;

    /* Scale wall-clock time by weight to get virtual time */
    curr->vruntime += calc_delta_fair(delta_exec, curr);
    update_min_vruntime(cfs_rq);

    account_cfs_rq_runtime(cfs_rq, delta_exec);  /* bandwidth control */
}
```

### The Weight-Based Scaling

The `__calc_delta()` function performs the weighted division:

```
vruntime_delta = delta_exec * NICE_0_LOAD / se->load.weight
```

For efficiency, this is implemented as a multiply-shift using precomputed inverse weights to avoid expensive 64-bit divisions:

```c
static u64 __calc_delta(u64 delta_exec, unsigned long weight,
                        struct load_weight *lw)
{
    u64 fact = scale_load_down(weight);
    /* fact = weight * inv_weight, then shift to get division result */
    fact = mul_u32_u32(fact, lw->inv_weight);
    return mul_u64_u32_shr(delta_exec, fact, shift);
}
```

The inverse weight table (`sched_prio_to_wmult[]`) provides `2^32 / weight` for each nice level, turning division into multiplication + right-shift.

### Tick-Based Accounting

CFS's time accounting is driven by `entity_tick()`, called from `task_tick_fair()` on every scheduler tick (typically 1ms at HZ=1000):

```c
static void entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr,
                        int queued)
{
    update_curr(cfs_rq);          /* Account elapsed time */
    update_load_avg(cfs_rq, curr, UPDATE_TG);  /* Update PELT averages */
    update_cfs_group(curr);       /* Recompute group weight */

    if (cfs_rq->nr_running > 1)
        check_preempt_tick(cfs_rq, curr);  /* Check if current should yield */
}
```

The `check_preempt_tick()` function determined whether the current task had run long enough:

```c
static void check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
    u64 ideal_runtime = sched_slice(cfs_rq, curr);
    u64 delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;

    if (delta_exec > ideal_runtime) {
        resched_curr(rq_of(cfs_rq));
        return;
    }

    /* Ensure minimum granularity to avoid excessive preemption */
    if (delta_exec < sysctl_sched_min_granularity)
        return;

    /* If leftmost entity has sufficiently smaller vruntime, preempt */
    struct sched_entity *se = __pick_first_entity(cfs_rq);
    s64 delta = curr->vruntime - se->vruntime;
    if (delta > ideal_runtime)
        resched_curr(rq_of(cfs_rq));
}
```

## Preemption

### Wakeup Preemption

When a task wakes up (e.g., receives data on a socket), CFS must decide whether it should preempt the currently running task. This was handled by `check_preempt_wakeup()`:

```c
static void check_preempt_wakeup(struct rq *rq, struct task_struct *p,
                                  int wake_flags)
{
    struct sched_entity *se = &curr->se, *pse = &p->se;

    /* SCHED_IDLE tasks are always preempted by non-idle tasks */
    if (task_has_idle_policy(curr) && !task_has_idle_policy(p))
        goto preempt;

    /* SCHED_BATCH tasks don't preempt */
    if (p->policy != SCHED_NORMAL || !sched_feat(WAKEUP_PREEMPTION))
        return;

    /* Walk up the group hierarchy to find matching level */
    find_matching_se(&se, &pse);

    update_curr(cfs_rq_of(se));

    /* Preempt if waking task's vruntime is sufficiently ahead */
    if (wakeup_preempt_entity(se, pse) == 1) {
        if (!next_buddy_marked)
            set_next_buddy(pse);
        goto preempt;
    }

    return;

preempt:
    resched_curr(rq);
    /* Set last buddy for cache locality on next pick */
    if (sched_feat(LAST_BUDDY) && scale && entity_is_task(se))
        set_last_buddy(se);
}
```

### Wakeup Granularity

The **wakeup granularity** (`sysctl_sched_wakeup_granularity`, default 1ms) prevented excessive preemption from wakeups. A waking task only preempted the current task if the vruntime difference exceeded this granularity:

```c
static int wakeup_preempt_entity(struct sched_entity *curr,
                                  struct sched_entity *se)
{
    s64 gran, vdiff = curr->vruntime - se->vruntime;

    if (vdiff <= 0)
        return -1;       /* curr is ahead or equal -- no preemption */

    gran = wakeup_gran(se);
    if (vdiff > gran)
        return 1;        /* curr is behind enough -- preempt */

    return 0;            /* close enough -- don't preempt */
}
```

The granularity was scaled by the waking entity's weight, meaning lighter tasks needed a larger vruntime gap to trigger preemption. This penalized low-priority tasks from preempting higher-priority ones.

### Buddy Heuristics

CFS used three "buddy" pointers to improve cache locality and responsiveness:

| Buddy | Set When | Purpose |
|-------|----------|---------|
| `next` | Task wakes up and triggers preemption | Prefer the waking task for cache warmth (NEXT_BUDDY, off by default) |
| `last` | Task gets preempted | Return CPU to the preempted task if it's still the best choice (LAST_BUDDY, on by default) |
| `skip` | Task calls `sched_yield()` | Avoid picking the yielding task |

Buddies could only override the "ideal" leftmost-vruntime choice within `wakeup_granularity` to prevent unfairness.

## Configuration

### Classic CFS Tunables (Pre-EEVDF)

CFS exposed its parameters through both `/proc/sys/kernel/` and `/sys/kernel/debug/sched/`:

| Tunable | Default | Description |
|---------|---------|-------------|
| `sched_latency_ns` | 6,000,000 (6ms) | Target scheduling period for <= `sched_nr_latency` tasks |
| `sched_min_granularity_ns` | 750,000 (0.75ms) | Minimum timeslice; period stretches if > `sched_nr_latency` tasks |
| `sched_wakeup_granularity_ns` | 1,000,000 (1ms) | Minimum vruntime advantage needed for wakeup preemption |
| `sched_migration_cost_ns` | 500,000 (0.5ms) | Time threshold below which a task is considered "cache hot" |
| `sched_child_runs_first` | 0 | If 1, child runs before parent after fork |
| `sched_tunable_scaling` | 1 (LOG) | How tunables scale with CPU count: 0=none, 1=log, 2=linear |
| `sched_nr_migrate` | 32 | Max tasks to migrate per load balance pass |
| `sched_cfs_bandwidth_slice_us` | 5,000 (5ms) | Granularity of bandwidth quota distribution |
| `sched_autogroup_enabled` | 1 | Enable per-session automatic task grouping |

The `sched_tunable_scaling` mechanism automatically scaled `sched_latency`, `sched_min_granularity`, and `sched_wakeup_granularity` by `1 + ilog2(ncpus)` (for LOG scaling). On an 8-CPU machine, this multiplied values by 4, recognizing that the effective latency visible to users decreases on multi-CPU systems. This idea came from Con Kolivas's SD scheduler.

Derived value:
- `sched_nr_latency = sched_latency / sched_min_granularity = 8` (the maximum number of tasks that fit within one scheduling period before stretching kicks in)

### Scheduler Features (debugfs toggles)

Classic CFS exposed boolean feature flags via `/sys/kernel/debug/sched/features`:

| Feature | Default | Description |
|---------|---------|-------------|
| `GENTLE_FAIR_SLEEPERS` | true | Give sleepers only 50% of their service deficit |
| `START_DEBIT` | true | New tasks start with a vslice debit |
| `NEXT_BUDDY` | false | Prefer last-woken task for cache locality |
| `LAST_BUDDY` | true | Prefer last-preempted task for cache locality |
| `WAKEUP_PREEMPTION` | true | Allow waking tasks to preempt current |
| `CACHE_HOT_BUDDY` | true | Consider buddies cache-hot (resist migration) |
| `ALT_PERIOD` | true | Use `h_nr_running` (hierarchy-aware count) for period calculation |
| `BASE_SLICE` | true | Enforce minimum granularity per slice |

## Limitations and Why It Was Replaced

CFS served Linux well for over 15 years, but accumulated several fundamental limitations that motivated the transition to **EEVDF (Earliest Eligible Virtual Deadline First)**, proposed by Peter Zijlstra in 2023:

### 1. No Latency Control

CFS had no mechanism for tasks to request specific latency guarantees. The scheduling period was a global property -- all tasks of the same weight received the same timeslice regardless of their latency sensitivity. A video player and a batch compiler at the same nice level got identical treatment, even though the video player needed short, frequent runs while the compiler benefited from long, infrequent runs.

EEVDF introduced **per-task time slices** (`sched_attr::sched_runtime`) allowing tasks to request shorter slices and receive correspondingly earlier virtual deadlines, achieving lower latency without sacrificing fairness.

### 2. Sleeper Fairness Hacks

The `GENTLE_FAIR_SLEEPERS` mechanism was an unprincipled hack. It arbitrarily halved the vruntime credit of sleeping tasks, which was:
- **Unfair by design**: Tasks that legitimately slept received less than their fair share.
- **A tuning knob, not a solution**: The "50% credit" ratio was arbitrary and worked well for some workloads but poorly for others.
- **Gaming-vulnerable**: The interaction between sleep credit and the scheduling period created exploitable patterns.

EEVDF replaces this with a principled **lag** mechanism. A task's lag (the difference between its ideal service and actual service) is tracked precisely. When a task sleeps, its lag is preserved (with decay) so that the fairness accounting is mathematically correct rather than heuristic-driven.

### 3. Buddy Heuristic Complexity

The `next`/`last`/`skip` buddy system added complexity and non-determinism to scheduling decisions. These heuristics worked well in common cases but:
- Created corner cases where "unfair" buddy selection persisted longer than intended.
- Made scheduler behavior difficult to reason about or predict.
- Required careful tuning of `wakeup_granularity` to balance responsiveness vs. throughput.

EEVDF's virtual-deadline mechanism naturally handles cache locality (short-slice tasks get early deadlines and run promptly) without ad-hoc buddy heuristics.

### 4. The Wakeup Granularity Problem

`sched_wakeup_granularity` was a single global tunable that controlled the responsiveness vs. throughput tradeoff for *all* wakeups. Setting it too low caused excessive preemption and cache thrashing. Setting it too high caused latency spikes for interactive tasks. There was no way for the system to handle both cases well simultaneously.

### 5. Period Stretching Artifacts

When the number of tasks exceeded `sched_nr_latency`, the scheduling period stretched linearly. This meant that on systems with hundreds of tasks, individual timeslices could become very small (approaching `min_granularity`), causing high context-switch overhead, or the period could become very long, causing high worst-case latency.

### 6. Lack of Formal Guarantees

CFS provided no formal bounds on scheduling latency. While empirically it worked well, there was no mathematical framework proving bounded latency for any given configuration. EEVDF provides formal guarantees: the maximum delay before a task is scheduled is bounded by `O(r_max)` where `r_max` is the maximum request size of any task in the system.

## Legacy in sched_ext

Many CFS concepts carry directly into `sched_ext` schedulers, which build on the same kernel infrastructure:

### Virtual Time (vtime)

The `scx_bpf_dsq_insert_vtime()` API allows sched_ext schedulers to implement their own virtual-time-based fair queuing on dispatch queues (DSQs). Tasks dispatched with vtime are ordered by their virtual timestamp, directly analogous to CFS's vruntime-ordered RB-tree.

For example, `scx_layered` maintains per-layer `vtime_now` values and constrains task vtimes on migration:

```c
/* From scx_layered: */
u64 vtime = p->scx.dsq_vtime;
u64 vtime_now = llcc->vtime_now[layer_id];
u64 vtime_min = vtime_now - layer->slice_ns;
u64 vtime_max = vtime_now + 8192 * layer->slice_ns;
```

This mirrors CFS's `min_vruntime` clamping logic, preventing tasks from accumulating unbounded vtime credits.

### Weighted Fair Queuing

sched_ext schedulers commonly implement weight-based fair sharing inspired by CFS. The `scx_bpf_dsq_move_set_vtime()` and `scx_bpf_dsq_move_vtime()` APIs provide the building blocks for weight-aware dispatching. Task weights derived from nice levels (using the same `sched_prio_to_weight` table) flow through to BPF schedulers via `p->scx.weight`.

### Slice-Based Execution

The concept of a task running for a "slice" of time before re-evaluation continues in sched_ext, where `scx_bpf_dsq_insert()` takes an explicit `slice` parameter. This is analogous to CFS's `sched_slice()` calculation, though sched_ext schedulers have full freedom to choose their own slice durations.

### Load Balancing Concepts

While sched_ext schedulers implement their own load balancing logic in BPF, many (like `scx_layered`, `scx_rusty`, and `scx_mitosis`) use concepts directly descended from CFS:
- Per-CPU load tracking
- Migration cost thresholds
- NUMA-aware placement
- Weight-proportional load metrics

### The Scheduling Class Framework

The `sched_class` abstraction that CFS introduced -- with its `enqueue_task`, `dequeue_task`, `pick_next_task`, `task_tick`, `wakeup_preempt` hooks -- is precisely the interface that sched_ext builds on. The `ext_sched_class` sits in the class hierarchy alongside `fair_sched_class`, using the same hook-based dispatch mechanism that CFS pioneered for modular scheduling policies.

---

**Sources:**
- `kernel/sched/fair.c` -- CFS implementation (both pre-EEVDF and current EEVDF-based)
- `Documentation/scheduler/sched-design-CFS.rst` -- Ingo Molnar's CFS design document
- `Documentation/scheduler/sched-eevdf.rst` -- EEVDF documentation
- `Documentation/scheduler/sched-nice-design.rst` -- Nice level design rationale
- `Documentation/scheduler/sched-bwc.rst` -- CFS bandwidth control documentation
- `kernel/sched/core.c` -- `sched_prio_to_weight[]` and `sched_prio_to_wmult[]` tables
- `kernel/sched/sched.h` -- `struct cfs_rq`, `struct sched_entity` definitions
- `kernel/sched/features.h` -- Scheduler feature flags
- `kernel/sched/autogroup.c` -- Autogroup implementation
- Git history of `kernel/sched/fair.c` around the EEVDF transition (commits `b41bbb33cf75`, `e4ec3318a17f`)
