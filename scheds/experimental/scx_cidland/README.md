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
   so the queues of different CPUs stay comparable. A running task is charged
   when it stops and at the end of every slice it is kept across, the way
   `update_curr()` runs at every pick, so the reference of its pack is never
   more than a request behind; what it has taken since is added on the spot
   before every placement and every eligibility test, the way `update_curr()`
   runs ahead of `place_entity()`. `--no-vref-update` reads it as stored
   instead. Service is charged in `rq_clock_task()`, the clock
   `update_curr()` charges it in: wall time less the interrupt time and the
   hypervisor steal time the CPU spent on something else, read off the
   runqueue under its lock, so a task is not charged for interrupts landing
   on its CPU or for time the host took from its vCPU. The running averages,
   cache hotness and the balance intervals stay on the monotonic clock.
   `--no-task-clock` charges wall time instead, for comparing the two.

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

 - **Delayed dequeue.** A task that blocks while over-served is not dequeued
   by `fair.c`: it is left in the tree, `sched_delayed`, still counted in the
   weight and still holding its place, so the reference moves past it while it
   sleeps and it is dequeued the moment `pick_eevdf()` would have run it, with
   its lag clipped to zero, `DELAY_DEQUEUE` and `DELAY_ZERO`. A wakeup that
   comes sooner finds the part of the debt that has been paid. There is no
   tree to leave a task in here, so the task leaves its pack and remembers
   where the pack stood and what it weighed without it; when it is placed
   again the pack's progress since, scaled to what it would have been with the
   task's weight still counted, is credited to the debt and not a unit more,
   and a pack that has emptied since forgives it whole. Where the task wakes
   follows too: `ttwu_runnable()` requeues a delayed task on the runqueue it
   slept on, before `select_task_rq()` is asked, so a task woken while it is
   still owed to the pack it left goes back to that CPU, with the debt that
   is left and through the wakeup preemption test, and neither the waker's
   CPU nor an idle one is looked at for it. A task whose debt has been paid
   was dequeued by the pick that would have run it, and wakes through the
   placement like any other. `--no-delay-requeue` places every wakeup, and
   `--no-delay-dequeue` carries the whole debt across the sleep instead,
   which implies it.

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

 - **Eligible selection at dispatch.** Each per-CPU EDQ augments its
   deadline-ordered tree with every subtree's minimum vruntime and finds the
   earliest-deadline eligible task in logarithmic time, matching `fair.c`'s
   selection rule. `--no-eligible-scan` takes the head instead, and
   `--no-eligibility` implies it. Wakeup preemption and keep-running decisions
   remain head-based approximations: applying a queue-only scan there cannot
   reproduce `pick_eevdf()`'s atomic view of the current task, queued
   entities, and virtual-time frontier.

 - **Eligible deadline queues.** Per-cid runnable tasks are stored in
   arena-backed eligible deadline queues; local DSQs remain the final kernel
   handoff. EDQ is an intrusive AVL tree ordered by deadline and
   insertion sequence. Every subtree caches its minimum vruntime, so
   unless `--no-eligible-scan` is used, it atomically finds and removes the
   earliest-deadline task at or before V in O(log n), rather than walking the
   queue. Its cached leftmost node keeps ordinary head selection O(1).
   Active balance remains head-only, because it must also test affinity and
   cache hotness. Each EDQ entry also tracks the core
   scheduler custody workflow (`NONE`, `ENQUEUED`, `DISPATCHING`,
   `DISPATCHED`): a property-change `ops.dequeue()` invalidates the old entry,
   and dispatch checks the state before handing the task to a terminal DSQ.
   A popped or inspected intrusive node remains held through dispatch; a later
   enqueue cannot reuse it and is direct-dispatched instead, preventing an old
   pop from mistaking the new workflow for the one it removed. Remote pulls
   also hold, validate, and remove the same intrusive node, so an enqueue which
   changes the queue head cannot substitute a task with different affinity.
   If a property change races the final affinity check, its state transition
   invalidates the old pop and the core's matching enqueue retains
   responsibility for it.
   EDQ also rechecks affinity after a pop and drops an invalidated workflow so
   the core's matching enqueue can place the task again. Remote inspection and
   removal use trylocks and skip a busy queue, keeping idle scans from joining
   contended lock wait queues. Mandatory queue operations use an abort-safe
   test-and-set lock instead of an MCS queue whose timed-out waiter cannot
   safely unlink itself. Cidland enables `SCX_OPS_TID_TO_TASK` and stores the
   sched_ext tid assigned to each task. `scx_bpf_tid_to_task()` resolves that identity
   under the callbacks' implicit RCU protection even after an exiting task has
   left the PID map, so `SCX_OPS_ENQ_EXITING` remains enabled.
   This is a hard requirement on the kernel: `SCX_OPS_TID_TO_TASK`,
   `scx_bpf_tid_to_task()`, the `scx.tid` field and `SCX_DEQ_SCHED_CHANGE`
   have to be there, and there is no fallback to a DSQ-backed queue on a
   kernel without them; the scheduler fails to load.

 - **Deadlines on time.** A slice is only enforced from `task_tick_scx()`, so
   a task whose request runs out between two ticks holds the CPU until the next
   one, up to a whole tick late, and a task waiting behind it waits that long:
   two hogs sharing a CPU ran 1000 us each at a 700 us slice, and a saturated
   `schbench` had a median wakeup latency of ~900 us. `fair.c` has an hrtimer
   for exactly this, `HRTICK`: `set_next_task_fair()` arms it at every pick
   for the time the running task's vruntime takes to reach its deadline, when
   it has company, `enqueue_task_fair()` arms it the moment a task joins a lone
   runner, and when it fires `update_curr()` reissues the deadline and asks for
   a reschedule. `sched_ext` has no hrtick, so this is a `bpf_timer` per CPU,
   armed from the same three places, that kicks the CPU at the deadline if the
   queue still holds something; the dispatch that follows is the pick. Ops run
   with interrupts off, from where a timer is armed through an `irq_work` and
   a self-IPI, so a timer already pending for no later than the deadline is
   left to fire early and rearm itself from its callback, where that costs
   nothing. The two hogs run 701 us each; the saturated `schbench` wakes in
   6 us at the median, 707 us at the 99th, against 999 and 1698 before, and
   `fair.c`'s 2 and 1618 at its 1.6 ms slice. `--no-hrtick` leaves the end
   of a request to the tick.

- **Wakeup preemption.** A task queued on a CPU with a deadline earlier than
   the one the CPU is running is a task that CPU would pick if it were asked
   again, so the CPU is interrupted for it rather than left to finish its
   slice: `wakeup_preempt_fair()`. The woken task has to be owed service to
   qualify and the running one is left alone while it is still owed its own,
   which is what `pick_eevdf()` does when it drops an ineligible `curr` before
   looking at the tree. And it has to be what the CPU would run next:
   `wakeup_preempt_fair()` preempts only when the woken task is the pick,
   `nse == pse`, and a running task that has lost the pick to some other queued
   task is left to finish its slice. The preemption decision approximates that
   pick with the EDQ head.
   `--no-run-to-parity` drops the running task's half alone, the sense the
   feature had when EEVDF was merged; `--no-eligibility` decides on the
   deadlines alone; `--no-wakeup-preempt` never interrupts. The policies are
   settled first, as
   `wakeup_preempt_fair()` settles them: a running `SCHED_IDLE` task is
   interrupted for any task that is not one, and a `SCHED_IDLE` or
   `SCHED_BATCH` task never interrupts anything.

 - **Short-request preemption.** `PREEMPT_SHORT` lets an eligible wakee whose
   request is shorter than the current task's override RUN_TO_PARITY. The
   local-DSQ insertion acts as `set_short_buddy()` when that DSQ is empty: it
   makes the wakee run before the deadline-ordered EDQ even if another task has
   an earlier virtual deadline. An existing local waiter is not displaced
   because the built-in DSQ is FIFO-only. `--no-preempt-short` keeps the
   current task's ordinary protection for comparison.

 - **Idle search.** `wake_affine()` first computes the target around which
   `select_idle_sibling()` searches. The target is tried if it is idle, then
   the idle cache-affine CPU a task last ran on, then a fully idle core before
   a thread with a busy sibling, scanning the LLC and then the node. A
   synchronous wakeup from a waker that is the only runnable task on its CPU
   makes that CPU the affine target, `wake_affine_idle()`: idle alternatives
   around it still win, and only when the scan fails is the wakee stacked on
   the waker that is about to sleep. When the waking CPU and the previous one
   are both busy the wakee stays on its previous CPU by default; `--wa-weight`
   sends it to whichever the loads say ends up lighter, `wake_affine_weight()`:
   the load of a CPU is the weight of what is runnable on it averaged over
   time, `cpu_load()`, and a task's is its weight scaled by the fraction of
   the time it is runnable, `task_h_load()`, with the previous CPU favoured by
   half the domain's `imbalance_pct`. A waker that runs a little and sleeps a
   lot weighs little, so its wakee lands on its CPU and runs when it sleeps,
   instead of behind a fresh slice on the CPU it came from; on a saturated
   machine that is a third of the wakeups, and the one case where the rule
   has been measured to matter. Everywhere else it is within noise and costs
   a few percent on wakeup-heavy runs, in `fair.c` as much as here, hence
   off by default. The
   `record_wakee()`/`wake_wide()` flip heuristic disables affinity for wide
   M:N wakeup patterns. A new task with nowhere idle to go is placed on the
   shortest queue, `find_idlest_cpu()`.

 - **Load balancing.** A CPU that runs out of work pulls from the other queues
   of its node, walking its own LLC first the way the idle balancer walks the
   domains bottom up, and leaves alone a task that ran a moment ago,
   `task_hot()` with `sysctl_sched_migration_cost`. A busy CPU samples a couple
   of remote queues once per slice, the way the balancer runs on the tick, and
   only takes from a queue that is clearly deeper than its own, the equivalent
   of `imbalance_pct`. An idle CPU that keeps finding nothing it is allowed to
   take eventually stops honoring cache hotness, `sd->cache_nice_tries` against
   `sd->nr_balance_failed` in `can_migrate_task()`. And an idle CPU does not
   scan at all when its idle periods have been shorter than its scans:
   `sched_balance_newidle()` measures how long the CPU stays idle after a
   pull, `rq->avg_idle`, and what a pull at each level has cost at most,
   `sd->max_newidle_lb_cost`, decaying by 1% a second, and gives up before a
   level it cannot pay for, since a CPU its own wakeups keep bringing back is
   about to have work of its own. `--no-newidle-cost` scans every time.

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

 - **Asymmetric capacity and packing.** Capacity and CPU priority are separate
   kernel policies. The default capacity comes from the kernel's exported
   `cpu_capacity`, the value behind `SD_ASYM_CPUCAPACITY`; `--uniform-capacity`
   forces one capacity class and `--asym-capacity` instead uses the best CPPC or
   cpufreq estimate. Independently, when the kernel has an active
   `SD_ASYM_PACKING` domain, cidland reads `arch_asym_cpu_priority()` through
   `sched_core_priority` and uses its exact priority classes for asymmetric
   balancing. They do not rank ordinary cross-core wakeup placement: fair.c
   searches the target LLC in topology order and applies packing priority
   later through load balance. Thus a machine may have uniform capacity and
   still prefer high-performance cores without making every wakeup walk its
   priority classes. Capacity tiers remain independent and continue to rank
   placement when `SD_ASYM_CPUCAPACITY` is in use. An idle previous CPU is
   retained. Within its LLC, cidland tracks `has_idle_core` as fair.c does:
   it looks for a fully idle core while that hint is set; when none is known,
   it tries an idle sibling of the task's previous CPU before the general idle
   CPU scan. A selected CPU is redirected to a higher-priority idle sibling
   when the SMT domain has `SD_ASYM_PACKING`, matching
   `select_idle_smt_cpu()`. Idle preferred CPUs pull non-hot work from
   lower-priority ones, but only onto a fully idle core when SMT is active,
   matching `sched_use_asym_prio()`. Queued pulling alone cannot move the sole
   task running on a lower-priority CPU. Follow fair.c's active-balance order
   for that case: a source tick wakes a suitable idle balancer; the idle CPU
   first tries to detach queued work and only after that fails asks one source
   for its running task. The source revalidates the request at dispatch.
   `SD_ASYM_PACKING` uses the same `sched_asym()` ordering: the destination
   must be able to use asymmetric priority, and must either be preferred to
   the source or the source must be unable to use asymmetric priority because
   an SMT sibling is busy. The latter permits a CPU-heavy task to move to a
   fully idle core of the same or a lower tier instead of sharing a core while
   another is idle. Cidland additionally requires that task to fail
   `fits_capacity()` on the source, so a bursty task can keep its fast shared
   core while the CPU hog beside it moves. `SD_ASYM_CPUCAPACITY` can move a
   task that does not fit its current CPU to a fully idle CPU of its maximum
   allowed capacity. The consumed service is charged normally before the
   destination handoff, and cross-core moves require the whole destination
   core to be idle under SMT.
   `--disable-asym-packing` disables that independent policy, so placement
   follows the capacity classes chosen by the automatic mode,
   `--uniform-capacity`, or `--asym-capacity`.

Time slices default to `fair.c`'s `sysctl_sched_base_slice` as
`update_sysctl()` sets it, so the two schedulers issue requests of the same
size on the same machine. That is not the 700 us `fair.c` is compiled with:
`update_sysctl()` scales `normalized_sysctl_sched_base_slice` by
`1 + ilog2(min(nr_cpus, 8))` at boot, 2.8 ms on eight CPUs or more. A kernel
that runs `fair.c` at some other slice, a distribution that changed the
normalized value or an administrator who tuned the sysctl,
`/sys/kernel/debug/sched/base_slice_ns` says which, is matched with
`--slice-us`. Slices end when they end: the hrtick
asks the running task for the CPU at its deadline rather than at the tick that
follows it, see above. A task can select its own slice with
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

 - **The eligibility filter is head-based away from dispatch.** `pick_eevdf()`
   considers only the tasks that are owed service, `v_i <= V`, and takes the
   earliest deadline among those. Dispatch makes that selection through the
   augmented EDQ, see above; the wakeup preemption and the
   keep-running decision cannot, since neither sees the running task, the
   queue and the reference at once, and both judge the head of the queue
   alone. The case that matters is handled where the decision is made: a
   running task that has had its share is dropped from the wakeup comparison
   whatever its deadline, the way `pick_eevdf()` drops an ineligible `curr`,
   and once displaced it has its deadline reissued so it cannot sort back
   ahead of the task that woke. Without that, a thread waking against a CPU
   hog on a saturated machine waited for the tick on a third of its wakeups.
   What is left is a heavier over-served queued task, whose `r_i / w_i` is
   smaller, standing at the head for those two comparisons in place of the
   lighter under-served one behind it - a bounded latency skew, not a fairness
   leak, since the vruntime is charged either way.

 - **A wakeup that does not preempt leaves the running task's protection
   whole.** `wakeup_preempt_fair()` clips it to one minimum slice ahead of the
   reference on every wakeup that fails to preempt, `update_protect_slice()`.
   The direct `PREEMPT_SHORT` case is handled here, but a shorter ineligible
   wakee does not shorten protection for a later decision. Doing that exactly
   needs the minimum request across an EDQ, which cidland does not track.

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

### Wakeup placement

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

 - **The load signal is not used for balancing.** There *is* a PELT
   equivalent here: `ravg` is a geometric running average over a 32 ms
   half-life, `LOAD_AVG_PERIOD`, kept per task and per cid, and since the
   wake affinity needed it there is a `cfs_rq->avg.load_avg` analogue too,
   the runnable weight of a cid averaged over time, and a `task_h_load()`,
   the weight scaled by the time runnable, without the hierarchical part.
   But only the wakeup path reads them: `cid_util()` feeds the cpufreq
   governor, `task_util()` decides whether a task fits a CPU, and every
   balancing decision reads queue depth instead. So a cid running one task
   at 5% duty and a cid running a spinner are the same number to the
   balancer, though not to the governor or, with `--wa-weight`, to
   `wake_affine_weight()`. This
   is the missing piece underneath most of the rest of this section.

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
