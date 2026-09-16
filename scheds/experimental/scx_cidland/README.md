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

It is not a complete `fair.c`. What is faithful is the EEVDF core; placement
and load balancing follow its topology and averaged-load mechanics where the
`sched_ext` interfaces expose enough state, while several subsystems around
the edges are simply absent.
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
   `--no-eligibility` implies it. Wakeup preemption and the keep-running
   decision compare against that same eligible pick rather than the queue
   head, so a queued task `pick_eevdf()` would skip no longer decides
   either; a queue a remote scan holds is read from its lockless head
   instead. What they cannot reproduce is `pick_eevdf()`'s atomic view of
   the current task, the queued entities and the virtual-time frontier
   together, see below.

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
   the idle cache-affine CPU a task last ran on. On an asymmetric-capacity SMT
   machine those candidates must have a fully idle core, and the asymmetric
   capacity domain is scanned in wrapped CPU order before the ordinary LLC
   scan, as `select_idle_capacity()` does. The fallback takes a fully idle core
   before a thread with a busy sibling and stops at the LLC, as
   `select_idle_sibling()` does, leaving spreading across LLCs to load balance,
   where the cost of the migration is weighed. `--llc-extend` restores
   cidland's wider node and system scan, which can keep work off a busy SMT
   sibling when another LLC has a whole idle core, at the cost of weaker cache
   locality and more wakeup-path work. It is only observable on a machine with
   more than one LLC. A
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
   M:N wakeup patterns. Forks do not use this wakeup-only idle-sibling path:
   they descend the kernel's live `SD_BALANCE_FORK` span through its NUMA,
   LLC and core groups, selecting the child group with the most completely
   idle CPUs at each level, then, when all are busy, the least runnable weight
   per unit of CPU capacity, and keeping the local group on an exact tie.
   Equal-idle, equal-load remote cores prefer the one least recently selected
   for a fork; the stamp expires after the utilization half-life, preserving
   fair.c's recent-use bias without recomputing every CPU's average in the fork
   path.
   The final CPU is selected using averaged, capacity-normalized per-CPU
   utilization, preferring an idle CPU. Affinity-restricted tasks use the flat
   domain scan until cidland can represent fair.c's per-group affinity
   intersections.

 - **SCHED_IDLE-only CPUs as wake targets.** `choose_idle_cpu()` counts a
   runqueue running nothing but `SCHED_IDLE` work as available to a normal
   wakee. The target, previous and recently-used candidates are tested for it
   here too: such a CPU is returned without a direct dispatch, since it is not
   physically idle, and the ordinary enqueue then interrupts the idle-policy
   task. A remote queue holding several `SCHED_IDLE` tasks is not recognized;
   sched_ext does not expose `fair.c`'s per-runqueue idle-policy count.

 - **Load balancing.** A CPU that runs out of work pulls from the other queues
   of its node, walking its own LLC first the way the idle balancer walks the
   domains bottom up, and leaves alone a task that ran a moment ago,
   `task_hot()` with `sysctl_sched_migration_cost`. Busy balancing runs from
   the tick at a separate, backing-off interval for each LLC, NUMA node and
   system domain. It averages capacity-normalized runnable load, classifies
   the local and busiest groups, computes the excess load, and moves only that
   budget, with one elected destination per local group, following
   `sched_balance_domains()`, `update_sd_lb_stats()` and
   `calculate_imbalance()`. An idle CPU that keeps finding nothing it is
   allowed to take eventually stops honoring cache hotness,
   `sd->cache_nice_tries` against `sd->nr_balance_failed` in
   `can_migrate_task()`. And an idle CPU does not scan at all when its idle
   periods have been shorter than its scans:
   `sched_balance_newidle()` measures how long the CPU stays idle after a
   pull, `rq->avg_idle`, and what a pull at each level has cost at most,
   `sd->max_newidle_lb_cost`, decaying by 1% a second, and gives up before a
   level it cannot pay for, since a CPU its own wakeups keep bringing back is
   about to have work of its own. `--no-newidle-cost` scans every time.
   SMT contention is repaired independently of CPU capacity and
   `SD_ASYM_PACKING`, matching `fair.c`'s `group_smt_balance`: a task whose
   sibling has been busy for a slice asks a fully idle core in the same LLC to
   balance, and that core moves one queued task or requests a running one
   after queued pulling fails. This makes one runnable task per physical core
   the steady state whenever affinity allows it.

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

 - **cgroup scheduling.** Off by default: tasks are scheduled on their nice
   levels alone and `cpu.weight` is ignored. `--enable-cgroups` schedules the
   cpu controller's cgroups as groups the way `fair.c` does since it moved to a
   single runqueue: every task stays in its cid's queue at an effective weight,
   its nice weight scaled by `shares / load` at every level of its hierarchy,
   and a group's shares on a cid are the load-proportional part of its
   `cpu.weight` scaled by how many CPUs' worth of tasks it runs (`fair.c`'s
   default `cgroup_mode`, "concur"). Keeping the group loads and effective
   weights current costs every wakeup of a task in a nested cgroup a walk of
   its hierarchy, which on a systemd machine is every task: about 2% of
   throughput and a few microseconds of wakeup latency in schbench from a
   depth-3 session scope. The scheduler warns at startup when some cgroup sets
   `cpu.weight` while this is off, and when it is on but the kernel has no
   sched_ext cgroup support or the cpu controller is not enabled.

 - **`cpu.max`.** A cgroup runs for at most its quota in every period, plus
   what it carried into the period up to its burst, and is held to the limits
   of every group above it as well as its own. It is accounted the way
   `fair.c`'s bandwidth control is: the group keeps a pool for the period it is
   in, and a cid takes a slice of that pool to charge against, so the shared
   count is touched once every few milliseconds of runtime rather than at every
   context switch. Periods turn over on the next charge that finds one expired,
   so an idle group costs nothing, and a cid gives back all but a millisecond
   of what it holds once the sweep finds nothing of the group left on it. One
   timer covers the case every CPU is asleep with a group's tasks all waiting.

   A task of a group that has run out waits for the next period in a backlog of
   its cgroup's own, out of its cid's queue and out of its pack and its group's
   load, and goes back through placement when the group has bandwidth again.
   `ops.dispatch()` puts them back before it picks, so the CPU still goes to
   the earliest deadline among them rather than to whichever was let out first.
   A task that is already running has its slice ended at the tick, and the
   dispatch that follows hands it back rather than renewing it.

   Four hogs in one cgroup over eight seconds, against `fair.c` on the same
   cgroups, in CPUs used:

   | `cpu.max` | cidland | `fair.c` |
   | --- | --- | --- |
   | `20000 100000` | 0.18 | 0.22 |
   | `50000 100000` | 0.50 | 0.54 |
   | `100000 100000` | 0.99 | 1.04 |
   | `250000 100000` (8 hogs) | 2.46 | 2.60 |
   | `20000 20000` | 0.93 | 1.03 |

   cidland stays under the limit where `fair.c` runs a little over it, and is
   up to about a tenth under at a small quota: what a cid holds and does not
   use is stranded until the sweep comes by for it, where `fair.c` gives it
   back as the last task leaves. Rides on `--enable-cgroups`;
   `--disable-cpu-max` turns it off, and a cpu.max nobody reads is warned about
   at startup. A kernel without `ops.cpuctl_set_bandwidth()` gets the warning
   too and the callback is left unbound.

 - **Asymmetric capacity and packing.** Capacity and CPU priority are separate
   kernel policies. The default capacity comes from the kernel's exported
   `cpu_capacity`, and is used for placement when the kernel has a live
   `SD_ASYM_CPUCAPACITY` domain; `--uniform-capacity` forces one capacity class
   and `--asym-capacity` instead uses the best CPPC or cpufreq estimate even
   when the kernel does not enable asymmetric-capacity scheduling.
   Scheduler-domain spans are discovered by `scx_utils::Topology` without
   reading scheduler-internal kernel objects. It prefers the live domain masks
   in schedstat v17 when `/proc/schedstat` is available; schedstat counters may
   remain disabled. If the file is missing or incompatible, it reconstructs
   candidate domains from sysfs topology. In both cases it applies the kernel's
   NUMA-reclaim-distance and complete-capacity-class rules to select the fork,
   wake-affine and asymmetric-capacity domains.

   `/proc/schedstat` does not expose `SD_ASYM_PACKING` or
   `arch_asym_cpu_priority()`, and there is no other portable ABI for them.
   Cidland retains a narrow BPF query for that independent policy until
   sched_ext provides a stable query. This matters for x86 ITMT systems, where
   every CPU may export the same capacity while the kernel assigns cores
   distinct packing priorities. `--disable-asym-packing` disables this policy.
   Capacity tiers remain independent and continue to rank placement when
   `SD_ASYM_CPUCAPACITY` is in use. An idle previous CPU is retained.
   Within its LLC, cidland tracks `has_idle_core` as fair.c does:
   it looks for a fully idle core while that hint is set; when none is known,
   it tries an idle sibling of the task's previous CPU before the general idle
   CPU scan. `SD_ASYM_CPUCAPACITY` can move a
   task that does not fit its current CPU to a fully idle CPU of its maximum
   allowed capacity. The consumed service is charged normally before the
   destination handoff, and cross-core moves require the whole destination
   core to be idle under SMT.
   `--smt-asym-packing` ranks the threads of a core by CPU ID when the kernel
   exposes no priority between them: among the idle siblings of the selected
   physical core the lowest CPU ID is preferred, at wakeup and when a balance
   destination is picked. It never ranks different cores and never migrates a
   running task between the threads of one core. It is a determinism aid for
   comparisons, since equal threads otherwise leave the choice to timing, not
   a performance policy.

   `--smt-whole-core` lets a wakeup leave its LLC to find a whole idle
   core rather than settle for the idle sibling of a busy one. Off by default,
   because `select_idle_sibling()` stops at the LLC and takes that sibling.
   Turning it on trades cache locality for core throughput, and only while a
   whole idle core exists somewhere. It is meant for machines whose LLC spans
   a whole NUMA node: once that node is saturated, every wakeup lands on one
   of its busy cores' siblings and halves the thread already running there,
   while another node's cores sit fully idle. Barrier-synchronized workloads
   pay for that many times over, since every thread waits for the halved one.

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

 - **The current task and reference are read from a published snapshot.**
   `pick_eevdf()` sees the running task, the tree and the reference under one
   runqueue lock. Dispatch, wakeup preemption and the keep-running decision
   ask the EDQ for the earliest-deadline task eligible at the supplied
   cutoff, with the cutoff and the current-task state projected from the
   pack just before the queue is read. The lookup takes the queue with a
   trylock, so a queue a remote scan is holding is answered from its
   lockless head instead, which may be the deadline of a task that is not
   eligible. `fair.c` observes all three together under the runqueue lock.
   `--no-eligible-scan` takes the head everywhere, and `--no-eligibility`
   drops the eligibility test.

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
   `fair.c` has `update_curr()` and a pick, so two yielders pinned to one CPU
   switch at about 1.7 us per yield against the kernel's 0.9 us.

### Wakeup placement

 - **The idle scan gives up only when asked to.** `select_idle_cpu()` looks for
   an idle CPU under a budget, `SIS_UTIL`, that shrinks as the LLC fills, and
   past it the waking task is left to queue on the target `wake_affine()`
   chose. cidland computes the same budget, from the same quadratic in the LLC's
   average utilization, and honours it: the window it allows starts at the
   target and wraps inside the LLC, and a search that runs out of it ends there
   rather than carrying on into the node and the machine. `--no-sis-util`
   scans the whole LLC on every wakeup instead.

   On by default, as it is in `fair.c`, but what it is worth depends on the
   size of the LLC. `select_idle_cpu()` tests one CPU at a time, so a fruitless
   scan of a busy LLC is work proportional to its size; the scan here reads the
   idle bitmap a word at a time and skips busy CPUs for nothing. On a 352-CPU
   Olympus, two LLCs of 176, `hackbench -l 20000 -g 20` runs at 10.17s against
   12.84s, 20.8% better with every sample of six clear of every sample without
   it, while a pinned pipe handoff is unchanged at 2.81 us/op: it pays where
   the scan is long and hopeless and nowhere else. On a 20-CPU laptop whose
   single LLC is one bitmap word there is no scan cost to bound, and the budget
   only loses idle CPUs the fallback passes would have found: five benchmarks
   land between 0 and 8% worse, none of them separated, all five pointing the
   same way. `--no-sis-util` is there for that case. The budget itself tracks
   the kernel's curve, 176 of 176 cids scanned on an idle LLC falling to 10 at
   89% utilization.

 - **uclamp, on the placement side.** `asym_fits_cpu()` asks whether a task
   fits a CPU using `uclamp_eff_value()`, so a task with `uclamp_min` set is
   steered to a faster CPU. Here the raw utilization is used and the clamp is
   ignored. The *frequency* side is unaffected: uclamp is aggregated per
   runqueue by the core kernel and reaches the governor whatever the class.

### Load balancing

 - **Only a bounded prefix of a queue is searched.** `detach_tasks()` walks the
   busiest runqueue looking for something it may take. Here balancing scans the
   first eight deadline-ordered tasks (`BALANCE_TASK_SCAN`), so a blocked head
   no longer hides immediately movable work, but a long prefix of pinned or
   cache-hot tasks can still stop the search.

 - **The group taxonomy is narrower than `fair.c`'s.** Balancing runs per
   domain from the tick, classifies an imbalance and moves capacity-normalized
   averaged load, following `sched_balance_rq()` and `calculate_imbalance()`,
   with `sd->imbalance_pct` between busy groups and one elected balancer per
   local group as `should_we_balance()` has. What is missing is the full
   `group_type` ladder: `group_misfit_task` on the busy side, without an
   `update_misfit_status()` equivalent, capacity pressure from RT and IRQ
   work, and `SD_PREFER_SIBLING`. Capacity misfits are repaired from the idle
   side only, `idle_misfit_cid()`.

 - **A group's cpuset is not known.** `fair.c` scales a task group's shares by
   `min(tg_tasks, tg_cpus)`, where `tg_cpus` is the weight of the effective
   cpuset. sched_ext has no interface to that, and cpuset changes are not
   reported at all, so a group confined to part of the machine counts as the
   whole of it: eight hogs in a two-CPU cpuset against eight pinned to the same
   two CPUs get 576/423 where `fair.c` gives 247/752. This one is blocked on a
   kernel ABI, see `~/scx-kernel-todo.txt`.

### Not implemented at all

 - **NUMA balancing.** No page-fault sampling, no preferred node, no task
   grouping. Placement is topology-aware but blind to where a task's memory
   is.

 - **EAS.** No energy model and no `find_energy_efficient_cpu()`. On a machine
   with an energy model the kernel picks the CPU that costs the least energy
   for the work; this picks by capacity and idleness.

 - **Core scheduling.** `ops.core_sched_before()` is not implemented, so a
   core-scheduled system gets no ordering from here, and the SMT isolation it
   is enabled for is not preserved.

 - **Affinity changes.** `ops.set_cmask()` is not implemented. A changed
   affinity is honored at the next decision that reads it, and an EDQ pop
   rechecks it and hands the task back to the core's enqueue, rather than the
   task being moved at the moment the mask changes.

## Requirements

A kernel with cid-form `sched_ext` support (Linux v7.2 or newer).

## Typical Use Case

General-purpose scheduler: it should adapt itself both to server workloads and
to desktop workloads.

## Production Ready?

No. It is experimental and under active development, and it requires a kernel
with cid-form `sched_ext` support (Linux v7.2 or newer).
