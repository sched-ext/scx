# scx_cidland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_cidland` is a port of the kernel's own EEVDF scheduler to `sched_ext`.

The placement and the fairness rules are `fair.c`'s: tasks are ordered by the
virtual deadline `vd_i = ve_i + r_i / w_i`, measured against a per-runqueue
reference `V`, and what a task is owed across a sleep is the lag it carried out
of the queue it left. Each rule below names the `fair.c` function it comes
from, and several can be turned off on the command line so the two can be
compared against each other, which is what this scheduler is for.

It is not a complete `fair.c`. What is faithful is the EEVDF core; the load
balancing goes by queue depth rather than by measured load, and several
subsystems around the edges are simply absent.
[What is missing](#what-is-missing) lists them.

### cid form

`scx_cidland` is a **cid-form** scheduler: instead of raw CPU numbers it
addresses CPUs by their cid (topological CPU ID), an id from a dense space
ordered by topology, so that the CPUs of a core, of an LLC and of a NUMA node
always occupy **contiguous** ranges of that space.

That turns a topology domain into a `(base, len)` slice, so every question the
idle search and the work pulling ask is a range of a bitmap:

 - "is this core fully idle?" -> are all the bits in `[core_base, core_base +
   core_nr)` set?
 - "is there an idle CPU in my LLC?" -> scan `[llc_base, llc_base + llc_nr)`

no cpumask allocation and no per-CPU topology lookup in the hot path. All the
state sized by the machine lives in a BPF arena allocated at start, so no limit
on the number of CPUs, cores, LLCs, nodes or capacity tiers is built in.

This is the substrate the rules below are written against, not a scheduling
policy of its own.

## What it takes from EEVDF

The rules are the ones the kernel's own scheduler uses, translated to cid
space. Each of them names the `fair.c` function it comes from, and several can
be turned off on the command line to compare the two rules against each other.

 - **Virtual deadline.** Tasks that can't be placed on an idle CPU are queued
   by `vd_i = ve_i + r_i / w_i`, EEVDF's `update_deadline()`. The request size
   `r_i` is the scheduler's base slice unless the task supplies a custom one
   through `sched_attr.sched_runtime`; the weight buys an earlier deadline,
   not a longer slice.

 - **Per-runqueue reference.** Each CPU keeps `V = \Sum (w_i * v_i) / \Sum w_i`
   over the tasks queued on it, EEVDF's `avg_vruntime()`, kept incrementally,
   so the queues of different CPUs stay comparable. A running task is only
   charged when it stops, so the reference of its pack stands still while it
   runs; it is brought up to date on the spot before every placement and every
   eligibility test, the way `update_curr()` runs ahead of `place_entity()`.
   `--no-vref-update` reads it as stored instead.

 - **Lag.** How far a task is from the reference is taken when it stops being
   runnable and restored when it comes back or migrates, the way
   `update_entity_lag()` and `place_entity()` do, so a sleeper gets back what
   it was owed and no more, and a migration keeps its fairness. What it carries
   is clamped at the bound `entity_lag()` uses, the largest request on the
   queue plus the timing granularity:

   ```c
   u64 max_slice = cfs_rq_max_slice(cfs_rq) + TICK_NSEC;
   limit = calc_delta_fair(max_slice, se);
   return clamp(vlag, -limit, limit);
   ```

   EEVDF's steady-state `-r_max < lag < max(r_max, q)`. There is no queue to
   walk for `cfs_rq_max_slice()`, so the larger of the task's own request and
   the default stands in for it, and `TICK_NSEC` is read from user space out of
   the resolution of a coarse clock, which the timer interrupt is the only
   thing that updates.

 - **Reweight.** The lag and the deadline are distances in the task's own
   virtual time, which runs at a rate set by its weight. When the weight
   changes, a nice level, a switch to or from `SCHED_IDLE`, a cgroup weight,
   both are rescaled by the old weight over the new and the task is placed
   again from the rescaled lag, as `reweight_eevdf()` and `rescale_entity()`
   do, so the lag stays the service it was and the deadline stays the request
   it was issued for. `ops.set_weight()` is where `set_load_weight()` reaches
   the sched_ext class, as it reaches `reweight_task_fair()` for the fair
   class.

 - **Relative deadline.** A task that is placed again without having slept,
   moved to another CPU or queued again after a preemption by a higher
   class, keeps what is left of the request it was in the middle of: the
   deadline is carried as its distance from the vruntime and re-based where
   the task lands, `PLACE_REL_DEADLINE`. A task that slept gets a new request
   when it wakes, as `place_entity()` issues one. `--no-place-rel-deadline`
   grants a whole new request on every placement instead.

 - **Runtime accounting.** The service consumed is charged as wall-clock time
   inversely scaled by the weight, `update_curr()` with `calc_delta_fair()`;
   the CPU capacity is used to balance the load, never to discount the
   vruntime.

 - **Wakeup preemption.** A task queued on a CPU with a deadline earlier than
   the one the CPU is running is a task that CPU would pick if it were asked
   again, so the CPU is interrupted for it rather than left to finish its
   slice: `wakeup_preempt_fair()`. The woken task has to be owed service to
   qualify and the running one is left alone while it is still owed its own,
   which is what `pick_eevdf()` does when it drops an ineligible `curr` before
   looking at the tree. `--no-run-to-parity` drops the running task's half
   alone, the sense the feature had when EEVDF was merged; `--no-eligibility`
   decides on the deadlines alone; `--no-wakeup-preempt` never interrupts.
   The policies are settled first, as `wakeup_preempt_fair()` settles them: a
   running `SCHED_IDLE` task is interrupted for any task that is not one, and
   a `SCHED_IDLE` or `SCHED_BATCH` task never interrupts anything.

 - **Idle search.** `wake_affine()` first computes the target around which
   `select_idle_sibling()` searches. The target is tried if it is idle, then
   the idle cache-affine CPU a task last ran on, then a fully idle core before
   a thread with a busy sibling, scanning the LLC and then the node. A
   synchronous wakeup from a waker that is the only runnable task on its CPU
   makes that CPU the affine target, `wake_affine_idle()`: idle alternatives
   around it still win, and only when the scan fails is the wakee stacked on
   the waker that is about to sleep. The `record_wakee()`/`wake_wide()` flip
   heuristic disables affinity for wide M:N wakeup patterns. A new task with
   nowhere idle to go is placed on the shortest queue, `find_idlest_cpu()`.

 - **Load balancing.** A CPU that runs out of work pulls from the other queues
   of its node, walking its own LLC first the way the idle balancer walks the
   domains bottom up, and leaves alone a task that ran a moment ago,
   `task_hot()` with `sysctl_sched_migration_cost`. A busy CPU samples a couple
   of remote queues once per slice, the way the balancer runs on the tick, and
   only takes from a queue that is clearly deeper than its own, the equivalent
   of `imbalance_pct`. An idle CPU that keeps finding nothing it is allowed to
   take eventually stops honoring cache hotness, `sd->cache_nice_tries` against
   `sd->nr_balance_failed` in `can_migrate_task()`.

 - **Utilization.** What a task uses is a running average of the time it spends
   on a CPU, read as the larger of that and what it used over its last
   activation, `task_util_est()`. The estimate rises to a new demand at once
   and is only allowed down slowly, the asymmetry `util_est_update()` has, so a
   task that runs a frame at a time is not called small at the moment it is
   about to ask for a whole CPU again. Whether it fits a CPU is asked with the
   same fifth off the top that `fits_capacity()` takes.

 - **cpufreq.** Each CPU's own running average is handed to the governor as a
   utilization in the range capacity is expressed in, with nothing added to it:
   `sugov_effective_cpu_perf()` applies the headroom, the ceiling and the
   bandwidth floor itself, so what is passed is what the fair class passes
   through `cpu_util_cfs_boost()`. `--disable-cpufreq` leaves the governor
   alone.

 - **cgroup weights.** A task's weight is its nice weight scaled by the
   `cpu.weight` of the cgroup it is in and of the cgroups that one sits under,
   so a service in a slice given ten times its siblings' weight is worth ten of
   the same service in a default slice. This is a per-task weight rather than a
   share of the machine handed to a cgroup and divided among its members, which
   is what `fair.c` gives: two tasks in a cgroup of twice the weight get twice
   the CPU each here, where `fair.c` would give them twice between them. Doing
   it `fair.c`'s way needs the weight of the runnable siblings at every level of
   the hierarchy, a count on a cacheline shared by every CPU that wakes a task.
   `--disable-cgroups` ignores the cpu controller entirely.

 - **Asymmetric capacity.** On systems with CPUs of different capacity (e.g.
   P-cores and E-cores), capacities within 5% of the fastest CPU in a tier are
   coalesced by default, so marginal differences do not create a strict
   ordering. An idle previous CPU is retained; otherwise idle CPUs are handed
   out in capacity order. Idle faster CPUs pull non-hot work up from slower
   ones, the way asym packing does, but only onto a fully idle faster core,
   which is what `asym_smt_can_pull_tasks()` refuses to give up.
   `--uniform-capacity` collapses the tiers, which is what the kernel's own
   `cpu_capacity` reports on those machines, for comparing the placement of the
   two.

Time slices are 700 us by default, `fair.c`'s
`normalized_sysctl_sched_base_slice` and under a tick of a HZ=1000 kernel,
which is what a slice is enforced from. A task can select its own slice with
`sched_attr.sched_runtime` (subject to the kernel's limits), and setting it to
zero restores the scheduler default. The slice bounds how long a task holds a
CPU without being asked again rather than a turn it has to give up: at the end
of one it keeps the CPU unless something queued there has an earlier deadline,
which is the comparison `pick_next_entity()` makes between `curr` and the tree,
and without which the weights would mean nothing on a CPU whose queue holds a
single task.

## What is missing

What the kernel does here and `scx_cidland` does not, or does differently
enough to name. None of it is a decision against the feature; it is the work
that has not been done.

### EEVDF itself

 - **No eligibility filter among queued tasks.** `pick_eevdf()` considers
   only the tasks that are owed service, `v_i <= V`, and takes the earliest
   deadline among those. A DSQ is ordered by its key and dispatch takes the
   head, so an over-served task already queued is not skipped. The case that
   matters is handled where the decision is made: a running task that has had
   its share is dropped from the wakeup comparison whatever its deadline, the
   way `pick_eevdf()` drops an ineligible `curr`, and once displaced it has
   its deadline reissued so it cannot sort back ahead of the task that woke.
   Without that, a thread waking against a CPU hog on a saturated machine
   waited for the tick on a third of its wakeups. What is left is a heavier
   over-served queued task, whose `r_i / w_i` is smaller, sorting ahead of a
   lighter under-served one - a bounded latency skew, not a fairness leak,
   since the vruntime is charged either way.

 - **No second chance between a wakeup and the end of a slice.** `fair.c`
   re-decides continuously: on every tick, enqueue and dequeue, with an hrtimer
   armed at the exact moment a task's protection ends, and every wakeup that
   does not preempt still clips the running task's protection. This decides
   once, when the waking task is queued, and a slice that has been granted is
   only noticed at the tick. `sched_ext` has no hrtick, so 1/HZ is the floor.

 - **`sched_yield()` costs more than it does in `fair.c`.** The rule is the
   same, `yield_task_fair()`'s: nothing happens unless someone is queued to
   take the CPU, and then the yielder's vruntime is moved to its deadline and
   the slice given up. The forfeit itself is a BPF op and a dispatch where
   `fair.c` has `update_curr()` and a pick, so a task yielding in a loop
   against a competitor does so at about seven tenths of the kernel's rate:
   `stress-ng --yield` runs at 16M yields/s against 22M. The scheduler ran
   that test faster than the kernel before it had an `ops.yield()`, at 31M,
   because the kernel's fallback ended the slice and the dispatch that
   followed handed the CPU straight back: a yield that never yielded.

 - **`DELAY_DEQUEUE` / `DELAY_ZERO`.** A task that blocks while over-served is
   kept on the runqueue by `fair.c` so it burns the debt off in place and is
   owed service by definition when it is picked again. Here it is dequeued and
   carries the debt in its lag across the sleep.

### Wakeup placement

 - **`wake_affine_weight()`.** The wake affinity here is only
   `wake_affine_idle()`'s "the waker is the only thing running" clause, and it
   is consulted only on a synchronous wakeup. `fair.c` weighs the load of the
   two CPUs whenever nothing is idle, which is the case that matters under
   load. It needs a `cpu_load()` analogue, and the sum of the queued weights is
   not one - it cannot tell a CPU running one task at 5% duty from one running
   a spinner.

 - **The idle scan never gives up.** `select_idle_cpu()` looks for an idle CPU
   under a budget, `SIS_UTIL`, that shrinks as the LLC fills, and past it the
   waking task is left to queue on the target `wake_affine()` chose. Here the
   idle bitmap is scanned whole, so a woken task gets an idle CPU whenever one
   exists.

 - **uclamp, on the placement side.** `asym_fits_cpu()` asks whether a task
   fits a CPU using `uclamp_eff_value()`, so a task with `uclamp_min` set is
   steered to a faster CPU. Here the raw utilization is used and the clamp is
   ignored. The *frequency* side is unaffected: uclamp is aggregated per
   runqueue by the core kernel and reaches the governor whatever the class.

 - **`sched_idle_cpu()`.** `fair.c` prefers a CPU running nothing but
   `SCHED_IDLE` tasks over a busy one. `SCHED_IDLE` is weighted correctly here,
   but the idle search does not know about it.

### Load balancing

 - **No load signal, and the utilization is not used for balancing.** There
   *is* a PELT equivalent here: `ravg` is a geometric running average over a
   32 ms half-life, `LOAD_AVG_PERIOD`, kept per task and per cid. But it
   accumulates running time, so it is `util_avg` and nothing else. `fair.c`
   balances on `cfs_rq->avg.load_avg`, which is runnable time scaled by the
   weight, and distributes it with `task_h_load()`; neither the weight
   scaling nor the hierarchical part exists here. And what is tracked is not
   consulted anyway: `cid_util()` feeds the cpufreq governor, `task_util()`
   decides whether a task fits a CPU, and every balancing decision reads
   queue depth instead. So a cid running one task at 5% duty and a cid
   running a spinner are the same number to the balancer, though not to the
   governor. This is the missing piece underneath most of the rest of this
   section.

 - **No group classification.** `fair.c` sorts groups into overloaded, misfit,
   fully busy and has-spare and computes an imbalance from that
   (`calculate_imbalance()`). Here a busy CPU takes from a queue that is more
   than twice as deep as its own and at least two tasks deeper, which is a
   cruder `imbalance_pct` and nothing else.

 - **Only queue heads move.** `detach_tasks()` walks the busiest runqueue
   looking for something it may take. Here only the head of each queue is
   considered, and a queue whose head cannot move is skipped whole.

 - **No active balancing.** A *running* task is never migrated.
   `active_load_balance_cpu_stop()` exists in `fair.c` for exactly the case
   where the only thing worth moving is the task on the CPU.

 - **No cost budget on the idle pull.** `fair.c` does not balance for a CPU
   that is about to be woken again, `avg_idle < sd->max_newidle_lb_cost`. An
   idle CPU here always scans, with the cache-hotness escalation as the only
   damper.

 - **No misfit detection.** `update_misfit_status()` and the balancing that
   acts on it. The pull up the capacity tiers is a partial stand-in.

### Not implemented at all

 - **`cpu.max`.** `ops.cpuctl_set_bandwidth()` exists and is not implemented,
   so the quota, period and burst of the cgroup bandwidth controller are
   ignored. `cpu.weight` *is* honored, see above.

 - **`cpu.idle`.** `ops.cpuctl_set_idle()` is not implemented.

 - **CPU hotplug.** The cid space is read once at start, so a CPU that comes
   online later is not used for the lifetime of the instance.

 - **NUMA balancing.** No page-fault sampling, no preferred node, no task
   grouping. Placement is topology-aware but blind to where a task's memory
   is.

 - **EAS.** No energy model and no `find_energy_efficient_cpu()`. On a machine
   with an energy model the kernel picks the CPU that costs the least energy
   for the work; this picks by capacity and idleness.

 - **Core scheduling.** `ops.core_sched_before()` is not implemented, so a
   core-scheduled system gets no ordering from here.

 - **Affinity changes.** `ops.set_cmask()` is not implemented; a changed
   affinity is noticed lazily the next time the task is placed, rather than
   fixed up at the moment it changes.

## Requirements

A kernel with cid-form `sched_ext` support (Linux v7.2 or newer).

## Typical Use Case

General-purpose scheduler: it should adapt itself both to server workloads and
to desktop workloads.

## Production Ready?

No. It is experimental and under active development, and it requires a kernel
with cid-form `sched_ext` support (Linux v7.2 or newer).
