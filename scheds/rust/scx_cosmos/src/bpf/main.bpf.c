/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of CPUs supported by the scheduler.
 */
#define MAX_CPUS	1024

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * CPUs sorted by their capacity in descending order.
 *
 * On a system with CPUs of different capacity (e.g. P-cores and E-cores)
 * this is the order idle CPUs are handed out in, see
 * pick_idle_cpu_ranked(): a task lands on the fastest idle CPU, and the
 * slower ones are used only while all the faster ones are busy. There is
 * no domain and no threshold; the ordering is the whole policy, the way
 * fair.c steers tasks by picking the first idle CPU it finds and leaving
 * them where they are.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * LLC id of each CPU.
 */
const volatile u64 cpu_llc[MAX_CPUS];

/*
 * NUMA node of each CPU.
 */
const volatile u32 cpu_nodes[MAX_CPUS];

/*
 * Core of each CPU and number of CPUs (SMT siblings) in each core. With
 * SMT disabled every CPU is a core of its own.
 */
const volatile u32 cpu_core[MAX_CPUS];
const volatile u32 core_nr_cpus[MAX_CPUS];

/*
 * True when all CPUs have the same capacity (no capacity asymmetry).
 */
const volatile bool all_cpus_same_capacity = false;

/*
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations.
 */
const volatile bool numa_enabled;

/*
 * Disable high-resolution preemption enforcement.
 */
const volatile bool time_preemption;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 1000000ULL;

/*
 * Maximum lag, in virtual time, that a task can carry across a sleep.
 */
const volatile u64 slice_lag = 20000000ULL;

/*
 * Per-CPU contention threshold, in the range [0 .. 1024], to determine
 * when a CPU is busy: a CPU is considered busy when it has had tasks
 * waiting to run for more than this fraction of time.
 *
 * 0 = contention tracking disabled: every CPU is always considered busy
 * (pure deadline mode) and no contention state is ever updated (the
 * branches are resolved at load time, since this is read-only data frozen
 * at that point).
 */
const volatile u64 busy_threshold;

/*
 * Scheduler statistics.
 */
volatile u64 nr_steals;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * Current system vruntime.
 */
static u64 vtime_now;

/*
 * Total weight of the runnable tasks, EEVDF's \Sum w_i (cfs_rq->sum_weight).
 *
 * Maintained across the ops.runnable() / ops.quiescent() pair, which the core
 * scheduler guarantees to be symmetric, so it converges even when a task is
 * dequeued without ever being consumed by the BPF side.
 */
static u64 sum_weight;

/*
 * Per-task context.
 */
struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	u64 last_run_at;
	u64 last_stop_at;
	u64 last_utime;
	u64 vruntime;
	s64 vlag;
	s32 vcpu;
	u64 vjoin_w;
	u64 vjoin_v;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_update;
	u64 perf_lvl;
	u64 busy_avg;
	u64 busy_eval_at;
	u64 acc_utime;
	u64 vtime_rem;
	u64 last_balance_at;
	u64 vsum_w;
	u64 vsum_wv;
	u32 steal_cursor;
	bool busy;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, u64 slice)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_t;
	struct cpu_ctx *cctx;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_update;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);
	cctx->last_update = now;
}

/*
 * Apply target cpufreq performance level to @cpu.
 */
static void update_cpufreq(s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 perf_lvl;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Apply target performance level to the cpufreq governor.
	 */
	if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 2;
	else
		perf_lvl = cctx->perf_lvl;

	scx_bpf_cpuperf_set(cpu, perf_lvl);
}

/*
 * Return the DSQ of @cpu.
 *
 * Every CPU owns a deadline ordered DSQ where the tasks that last ran on
 * it are queued, and every dispatch scans the heads of the DSQs of the
 * node for the earliest deadline (see try_steal_task()). All the keys are
 * built on the same system-wide vruntime reference, so the queues behave
 * as a single node-wide deadline queue, without the single lock that a
 * single queue puts in the path of every wakeup.
 */
static inline u64 cpu_dsq(s32 cpu)
{
	return cpu;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Per-CPU user utilization tracking.
 *
 * This determines, per CPU, when the scheduler needs to switch to
 * deadline-mode (using a shared DSQ) vs round-robin mode (using per-CPU
 * local DSQs).
 *
 * The signal is the fraction of wall time the CPU spends executing user
 * code, deliberately excluding system time: sleep-intensive workloads
 * (frequent short sleeps and wakeups) burn most of their CPU time in the
 * kernel, and for them tasks should stay on their CPU / local DSQ to
 * reduce the scheduling overhead and the balancing pressure in
 * ops.dispatch(). Only CPUs running sustained user work are worth the
 * extra migrations that deadline mode brings.
 *
 * The user time of the running task (p->utime deltas, charged in
 * ops.tick() and ops.stopping()) is accumulated per CPU and periodically
 * folded into an EWMA (@busy_avg) of the user utilization, normalized in
 * the range [0 .. 1024] of wall time. The busy state is derived from the
 * EWMA with hysteresis (enter at @busy_threshold, exit at 3/4 of it) to
 * avoid flapping between the two modes around the threshold. Idle CPUs
 * don't tick, so a CPU with no recent evaluations is considered not
 * busy.
 */
#define BUSY_EVAL_NS	(10ULL * NSEC_PER_MSEC)
#define BUSY_STALE_NS	(50ULL * NSEC_PER_MSEC)

/*
 * Charge the user time accumulated by @p (running on @cpu) since the
 * last update and periodically refresh the CPU's busy state.
 */
static void update_cpu_busy(struct task_struct *p, s32 cpu)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	u64 now, delta_t, util;

	if (!busy_threshold)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	tctx = try_lookup_task_ctx(p);
	if (!cctx || !tctx)
		return;

	cctx->acc_utime += p->utime - tctx->last_utime;
	tctx->last_utime = p->utime;

	now = bpf_ktime_get_ns();
	delta_t = time_delta(now, cctx->busy_eval_at);
	if (delta_t < BUSY_EVAL_NS)
		return;

	util = MIN(cctx->acc_utime * 1024 / delta_t, 1024);
	cctx->busy_avg = calc_avg(cctx->busy_avg, util);
	cctx->acc_utime = 0;
	cctx->busy_eval_at = now;

	if (!cctx->busy && cctx->busy_avg >= busy_threshold)
		cctx->busy = true;
	else if (cctx->busy && cctx->busy_avg < busy_threshold - busy_threshold / 4)
		cctx->busy = false;
}

/*
 * Return true if the given CPU is busy (running sustained user work),
 * false otherwise.
 *
 * @cpu should be the CPU of interest: prev_cpu in select_cpu/enqueue, or
 * scx_bpf_task_cpu(p) in tick.
 */
static inline bool is_cpu_busy(s32 cpu)
{
	struct cpu_ctx *cctx;

	/*
	 * Utilization tracking disabled: always use deadline mode.
	 */
	if (!busy_threshold)
		return true;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return true;

	/*
	 * No recent evaluations: the CPU has been (mostly) idle, hence
	 * not busy.
	 */
	if (time_delta(bpf_ktime_get_ns(), cctx->busy_eval_at) > BUSY_STALE_NS)
		return false;

	return cctx->busy;
}

/*
 * Return the capacity of @cpu, 0 if @cpu is not a valid CPU. The bounds
 * check is kept in the caller's sight for the verifier.
 */
static __always_inline u64 cpu_cap(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return 0;

	/*
	 * The mask is for the verifier, which does not always carry the
	 * bound above over to the register the index ends up in.
	 */
	return cpu_capacity[(u32)cpu & (MAX_CPUS - 1)];
}

/*
 * Return the LLC id of @cpu, -1 if @cpu is not a valid CPU.
 */
static __always_inline u64 cpu_llc_of(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return (u64)-1;

	return cpu_llc[(u32)cpu & (MAX_CPUS - 1)];
}

static __always_inline int cpu_node(s32 cpu)
{
	if (!numa_enabled)
		return 0;
	if (cpu < 0 || cpu >= MAX_CPUS)
		return -ENOENT;

	return cpu_nodes[(u32)cpu & (MAX_CPUS - 1)];
}

static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
}

/*
 * Idle CPU tracking.
 *
 * The idle state of every CPU is kept here rather than in the kernel's
 * idle masks. Implementing ops.update_idle() turns the built-in tracking
 * off, and with it the kernel's own idle CPU selection, whose walk of the
 * topology masks was the single most expensive step of a wakeup and knew
 * nothing of the capacity ordering anyway. What the scan needs is one bit
 * per CPU and, for the SMT preference, whether a whole core is idle, kept
 * as a per-core count of idle CPUs against the size of the core. Both are
 * cheap to keep and cheap to read.
 *
 * ops.update_idle() only fires on real idle transitions. A CPU that was
 * claimed for a task and kicked, and then found nothing to run, goes back
 * to idle without a transition and would keep its bit cleared for good:
 * ops.dispatch() re-arms the bit whenever a CPU is about to idle.
 */
static u64 idle_cpus[MAX_CPUS / 64];
static u32 core_idle_cnt[MAX_CPUS];

/*
 * Number of idle CPUs and of fully idle cores, so that a wakeup on a
 * saturated system finds out without walking the CPUs, and the whole
 * core pass is skipped when it cannot succeed.
 */
static s64 nr_idle_cpus;
static s64 nr_idle_cores;

static __always_inline u32 cpu_core_of(s32 cpu)
{
	return cpu_core[(u32)cpu & (MAX_CPUS - 1)] & (MAX_CPUS - 1);
}

static __always_inline u64 *idle_word(s32 cpu)
{
	return &idle_cpus[((u32)cpu / 64) & (MAX_CPUS / 64 - 1)];
}

static __always_inline u64 idle_bit(s32 cpu)
{
	return 1ULL << ((u32)cpu & 63);
}

/*
 * Return true if @cpu is idle. Nothing is claimed.
 */
static bool cpu_idle_test(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return false;

	return READ_ONCE(*idle_word(cpu)) & idle_bit(cpu);
}

/*
 * Return true if the whole core of @cpu is idle, i.e. @cpu is idle and so
 * are its SMT siblings, if any.
 */
static bool core_is_idle(s32 cpu)
{
	u32 core;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return false;
	core = cpu_core_of(cpu);

	return READ_ONCE(core_idle_cnt[core]) >= core_nr_cpus[core];
}

/*
 * Claim the idle state of @cpu, returning true if this caller is the one
 * that took it out of the idle state. Claiming keeps concurrent wakeups
 * from aiming at the same CPU.
 */
static bool cpu_idle_claim(s32 cpu)
{
	u64 old;
	u32 core;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return false;

	old = __sync_fetch_and_and(idle_word(cpu), ~idle_bit(cpu));
	if (!(old & idle_bit(cpu)))
		return false;
	__sync_fetch_and_sub(&nr_idle_cpus, 1);

	core = cpu_core_of(cpu);
	if (__sync_fetch_and_sub(&core_idle_cnt[core], 1) >= core_nr_cpus[core])
		__sync_fetch_and_sub(&nr_idle_cores, 1);

	return true;
}

/*
 * Mark @cpu idle, unless it already is.
 */
static void cpu_idle_set(s32 cpu)
{
	u64 old;
	u32 core;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return;

	old = __sync_fetch_and_or(idle_word(cpu), idle_bit(cpu));
	if (old & idle_bit(cpu))
		return;
	__sync_fetch_and_add(&nr_idle_cpus, 1);

	core = cpu_core_of(cpu);
	if (__sync_fetch_and_add(&core_idle_cnt[core], 1) + 1 >= core_nr_cpus[core])
		__sync_fetch_and_add(&nr_idle_cores, 1);
}

/*
 * Pick an idle CPU for @p in @preferred_cpus order (capacity descending).
 * Only fully idle cores are
 * considered if @whole_core is set, any idle CPU otherwise: the caller runs
 * the whole core pass first, across every tier, since sharing a core costs
 * more than the step down to the next tier, the way select_idle_core()
 * looks for a whole core before select_idle_cpu() settles for a thread.
 *
 * Within a pass a faster idle CPU always wins. Among idle CPUs of the same
 * capacity a CPU on the node of @prev_cpu beats one on another node, a
 * CPU in the same LLC as @prev_cpu beats one in another LLC, and @prev_cpu
 * itself beats an equivalent CPU, to keep the task where its cache is:
 * the order select_idle_sibling() applies within one domain, with the node
 * on top since this scan covers them all.
 *
 * The idle state is claimed only for the CPU that is returned.
 */
static __always_inline s32
pick_idle_cpu_ranked(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
		     bool whole_core)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS), best_cap = 0;
	u64 prev_llc = cpu_llc_of(prev_cpu);
	bool restricted = p->nr_cpus_allowed < nr_cpu_ids;
	int prev_node = cpu_node(prev_cpu);
	s32 best = -EBUSY;
	int best_score = -1, i;

	bpf_for(i, 0, max_cpus) {
		s32 cpu = preferred_cpus[i];
		u64 cap = cpu_cap(cpu);
		int score;

		/*
		 * A candidate was found in a faster tier: done.
		 */
		if (best >= 0 && cap < best_cap)
			break;

		/*
		 * The idle bit first, it is a load and it rules out most of
		 * the CPUs on a busy system; the cpumask test is a call, and
		 * only needed for a task that cannot run everywhere.
		 */
		if (!cpu_idle_test(cpu))
			continue;
		if (whole_core && !core_is_idle(cpu))
			continue;
		if (restricted && !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		score = 0;
		if (!numa_enabled || cpu_node(cpu) == prev_node)
			score += 4;
		if (cpu_llc_of(cpu) == prev_llc)
			score += 2;
		if (cpu == prev_cpu && is_prev_allowed)
			score += 1;

		if (score > best_score) {
			best_score = score;
			best_cap = cap;
			best = cpu;
			/*
			 * Nothing in this tier can do better.
			 */
			if (score == 7)
				break;
		}
	}

	if (best >= 0 && !cpu_idle_claim(best))
		best = -EBUSY;

	return best;
}

/*
 * Scan for an idle CPU: fully idle cores first, then any idle CPU, in
 * @preferred_cpus order.
 *
 * Return the CPU id or -EBUSY if no idle CPU is found.
 */
static s32 pick_idle_cpu_scan(struct task_struct *p, s32 prev_cpu)
{
	bool is_prev_allowed = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	s32 cpu;

	/*
	 * If the task can't migrate, there's no point looking for other
	 * CPUs.
	 */
	if (is_pcpu_task(p))
		return cpu_idle_claim(prev_cpu) ? prev_cpu : -EBUSY;

	/*
	 * Nothing idle at all is the common case under load: say so without
	 * walking the CPUs. The counters are only hints, the scan and the
	 * claim decide.
	 */
	if (READ_ONCE(nr_idle_cpus) <= 0)
		return -EBUSY;

	if (READ_ONCE(nr_idle_cores) > 0) {
		cpu = pick_idle_cpu_ranked(p, prev_cpu, is_prev_allowed, true);
		if (cpu >= 0)
			return cpu;
	}

	return pick_idle_cpu_ranked(p, prev_cpu, is_prev_allowed, false);
}

/*
 * Pick an idle CPU for task @p. @this_cpu is the waker's CPU on a wakeup,
 * -1 otherwise.
 *
 * On a synchronous wakeup the waker is about to sleep: when nothing else
 * is waiting for its CPU and the wakee shares the LLC with it, the wakee
 * takes that CPU, where the data the two just exchanged is still hot,
 * the same rule the kernel's default selection applies to WF_SYNC.
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags)
{
	if (!no_wake_sync && (wake_flags & SCX_WAKE_SYNC) && this_cpu >= 0 &&
	    !is_pcpu_task(p) && bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr) &&
	    cpu_llc_of(this_cpu) == cpu_llc_of(prev_cpu) &&
	    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) &&
	    !scx_bpf_dsq_nr_queued(cpu_dsq(this_cpu)))
		return this_cpu;

	return pick_idle_cpu_scan(p, prev_cpu);
}

/*
 * Return the CPU of @node with the fewest tasks queued that @p can run on,
 * the fastest one on ties, or -EBUSY.
 *
 * A new task that finds no idle CPU would otherwise be queued behind its
 * parent, and a parent forking a hundred workers on a busy system would
 * stack them all on one queue. find_idlest_cpu() spreads forks by load for
 * the same reason.
 */
static s32 shallowest_queue_cpu(const struct task_struct *p, int node)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	s32 best = -EBUSY, best_nr = 0;
	int i;

	bpf_for(i, 0, max_cpus) {
		s32 cpu = preferred_cpus[i], nr;

		if (cpu < 0 || cpu >= nr_cpu_ids)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (numa_enabled && cpu_node(cpu) != node)
			continue;

		nr = scx_bpf_dsq_nr_queued(cpu_dsq(cpu));
		if (best < 0 || nr < best_nr) {
			best = cpu;
			best_nr = nr;
			if (!nr)
				break;
		}
	}

	return best;
}

/*
 * Return an idle CPU faster than @cpu whose whole core is idle, or
 * -ENOENT. The idle state is not claimed: the caller is expected to kick
 * it.
 */
static s32 idle_faster_cpu(s32 cpu)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS), cap;
	int i;

	if (all_cpus_same_capacity)
		return -ENOENT;

	/*
	 * Only a fully idle faster core counts: pulling a task from a whole
	 * slow core onto a fast thread whose sibling is busy trades the
	 * capacity for a shared core, which is what asym_smt_can_pull_tasks()
	 * refuses to do.
	 */
	cap = cpu_cap(cpu);
	bpf_for(i, 0, max_cpus) {
		s32 other = preferred_cpus[i];

		if (cpu_cap(other) <= cap)
			break;
		if (core_is_idle(other))
			return other;
	}

	return -ENOENT;
}

/*
 * Floor on the weight used to stretch the request and the lag bound.
 *
 * The scx weight of a nice 19 task is 1, so its request would be a hundred
 * times the base slice and the lag it can carry two hundred times: under
 * a deep backlog V takes many seconds to cover that, well past the
 * watchdog. The vruntime is still charged with the real weight, so the
 * share is what nice asks for; only how far ahead the deadline and the lag
 * can stretch is capped, which update_deadline() itself notes is "probably
 * good enough".
 */
#define MIN_DL_WEIGHT	25

static u64 scale_by_dl_weight(const struct task_struct *p, u64 value)
{
	u64 weight = p->scx.weight;

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * 100 / weight;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * This is EEVDF's virtual deadline, see update_deadline():
 *
 *	vd_i = ve_i + r_i / w_i
 *
 * The request size r_i is the same @slice_ns for everybody, exactly like
 * sysctl_sched_base_slice: the weight does not buy a task a longer time
 * slice, it buys it an earlier deadline, so it runs more often instead of
 * running longer.
 *
 * The deadline is the DSQ key and nothing else. The kernel stores what is
 * passed to scx_bpf_dsq_insert_vtime() in p->scx.dsq_vtime, so the
 * vruntime has to live somewhere the key cannot overwrite it, see
 * task_ctx.vruntime.
 *
 * pick_eevdf() considers only the eligible tasks, v_i <= V, and picks the
 * earliest deadline among them. A DSQ cannot skip a task and its key is
 * fixed at insertion, so the filter is not applied here. It is mostly not
 * needed: a task that is over-served carries the excess in its key and
 * sorts after the under-served tasks of the same weight, and stays there
 * until V has moved past it, which is the wait pick_eevdf() would impose
 * anyway. What is lost is the case of a heavier over-served task, whose
 * r_i / w_i is smaller, sorting ahead of a lighter under-served one: it
 * wins by at most the difference between the two requests, a bounded
 * latency skew, not a fairness leak, since the vruntime is charged all
 * the same.
 *
 * Pushing the ineligible tasks further back with an offset, to apply the
 * filter exactly, would starve them instead. V advances by the service
 * delivered divided by the total weight, so under load it barely moves,
 * and a task waiting for V to cover a fixed offset waits for seconds
 * while every newly woken task keeps being queued ahead of it.
 */
static u64 task_dl(const struct task_struct *p, const struct task_ctx *tctx)
{
	return tctx->vruntime + scale_by_dl_weight(p, slice_ns);
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */
static int init_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *mask;

	mask = *p_cpumask;
	if (mask)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	mask = bpf_kptr_xchg(p_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return *p_cpumask ? 0 : -ENOMEM;
}

/*
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * Attempt a migration on wakeup (task was not running) and only if
	 * ops.select_cpu() has not been called already.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Return true if a task that only @cpu can run is waiting in @cpu's DSQ.
 *
 * The kernel skips ops.dispatch() entirely while a CPU's local DSQ is not
 * empty (see dispatch_one()), so tasks stacked on a local DSQ silently
 * outrank the deadline-ordered DSQs. A task pinned to @cpu can therefore
 * wait in @cpu's DSQ forever: remote CPUs skip it in try_steal_task() and
 * @cpu never gets to ops.dispatch().
 *
 * The DSQ is ordered by deadline and the deadline of a task that is
 * not running is fixed at insertion time, so a starving task climbs to the
 * head as the queue drains: peeking at the head is enough to notice it.
 */
static bool dsq_has_pinned_waiter(s32 cpu)
{
	const struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));

	return p && is_pcpu_task(p) && scx_bpf_task_cpu(p) == cpu;
}

/*
 * Per-CPU vruntime reference.
 *
 * With one deadline queue per CPU, each queue is a pack of tasks that
 * advance in lockstep, and the packs drift apart from the system-wide V
 * with their load: a CPU running nine hogs accrues vruntime slower than
 * one running six, and slower than V, which follows the average. A task
 * placed at V minus its lag then lands behind the whole pack of a crowded
 * CPU and waits for the pack to climb past it, or ahead of everything on a
 * lightly loaded one. EEVDF's reference is per runqueue for that reason:
 * the weighted average of the tasks queued there, kept incrementally,
 *
 *	V = \Sum (w_i * v_i) / \Sum w_i
 *
 * and a task is placed against the runqueue it joins with the lag it took
 * from the one it left, which is also how a migration keeps its fairness.
 *
 * Do the same per CPU: a task joins the CPU it is queued on or runs on,
 * leaves it when it stops being runnable, and its contribution follows
 * the vruntime it is charged in ops.stopping(). The vruntimes are scaled
 * down in the sums to keep the weighted products from overflowing. A
 * CPU with no members, or whose sums are found inconsistent, falls back
 * to the system-wide reference.
 */
#define VREF_SHIFT	10

static u64 cpu_vref(s32 cpu)
{
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
	u64 w, wv, v;

	if (!cctx)
		return vtime_now;

	w = READ_ONCE(cctx->vsum_w);
	wv = READ_ONCE(cctx->vsum_wv);
	if (!w)
		return vtime_now;

	v = (wv / w) << VREF_SHIFT;
	if (time_after(v, vtime_now + slice_lag * 100) ||
	    time_before(v, vtime_now - slice_lag * 100))
		return vtime_now;

	return v;
}

static void vref_leave(struct task_ctx *tctx)
{
	struct cpu_ctx *cctx;

	if (tctx->vcpu < 0)
		return;

	cctx = try_lookup_cpu_ctx(tctx->vcpu);
	if (cctx) {
		__sync_fetch_and_sub(&cctx->vsum_w, tctx->vjoin_w);
		__sync_fetch_and_sub(&cctx->vsum_wv, tctx->vjoin_w * tctx->vjoin_v);
	}
	tctx->vcpu = -1;
}

static void vref_join(s32 cpu, const struct task_struct *p, struct task_ctx *tctx)
{
	struct cpu_ctx *cctx;

	if (tctx->vcpu == cpu)
		return;
	vref_leave(tctx);

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	tctx->vjoin_w = p->scx.weight;
	tctx->vjoin_v = tctx->vruntime >> VREF_SHIFT;
	tctx->vcpu = cpu;
	__sync_fetch_and_add(&cctx->vsum_w, tctx->vjoin_w);
	__sync_fetch_and_add(&cctx->vsum_wv, tctx->vjoin_w * tctx->vjoin_v);
}

/*
 * Bring the contribution of @tctx up to date with its vruntime.
 */
static void vref_charge(struct task_ctx *tctx)
{
	struct cpu_ctx *cctx;
	u64 dv;

	if (tctx->vcpu < 0)
		return;

	dv = (tctx->vruntime >> VREF_SHIFT) - tctx->vjoin_v;
	if (!dv)
		return;
	tctx->vjoin_v += dv;
	cctx = try_lookup_cpu_ctx(tctx->vcpu);
	if (cctx)
		__sync_fetch_and_add(&cctx->vsum_wv, tctx->vjoin_w * dv);
}

/*
 * Place @p on @cpu: a task that is not running is put at the CPU's
 * reference minus the lag it carries, the way place_entity() does, and
 * either way it becomes a member of @cpu's reference.
 */
static void place_task(s32 cpu, const struct task_struct *p, struct task_ctx *tctx)
{
	if (!scx_bpf_task_running(p))
		tctx->vruntime = cpu_vref(cpu) - tctx->vlag;
	vref_join(cpu, p, tctx);
}

/*
 * Direct dispatch @p to the local DSQ of @cpu from ops.select_cpu().
 *
 * Insert with SCX_ENQ_IMMED so that the kernel bounces @p back through
 * ops.enqueue() (and from there into a per-CPU DSQ, where the deadline
 * ordering applies) whenever @p can't run on @cpu right away. This keeps
 * the local DSQ a pure "run now" fast path instead of an unbounded queue
 * that outranks the deadline-ordered DSQs.
 *
 * On kernels without SCX_ENQ_IMMED the flag reads as 0, so fall back to
 * skipping the direct dispatch when a task only @cpu can run is already
 * waiting: @p then falls through to ops.enqueue() on its own.
 */
static void direct_dispatch_local(struct task_struct *p, struct task_ctx *tctx, s32 cpu)
{
	if (!SCX_ENQ_IMMED && dsq_has_pinned_waiter(cpu))
		return;

	place_task(cpu, p, tctx);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, SCX_ENQ_IMMED);
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_busy = is_cpu_busy(prev_cpu);
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags);
	if (cpu >= 0 || !is_busy)
		direct_dispatch_local(p, tctx, cpu >= 0 ? cpu : prev_cpu);

	/*
	 * A new task with no idle CPU to go to is queued on the CPU with the
	 * shortest queue rather than behind its parent.
	 */
	if (cpu < 0 && (wake_flags & SCX_WAKE_FORK)) {
		cpu = shallowest_queue_cpu(p, cpu_node(prev_cpu));
		if (cpu >= 0)
			return cpu;
	}

	return cpu >= 0 ? cpu : prev_cpu;
}

void BPF_STRUCT_OPS(cosmos_tick, struct task_struct *p)
{
	struct task_ctx *tctx;

	/*
	 * Refresh the CPU user utilization state (resolved to a no-op at
	 * load time when utilization tracking is disabled).
	 */
	if (busy_threshold)
		update_cpu_busy(p, scx_bpf_task_cpu(p));

	if (!time_preemption)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Force preemption if the task has exceeded its time slice, the
	 * system is busy and there are tasks waiting in the local DSQ or in
	 * this CPU's DSQ.
	 */
	if (time_delta(bpf_ktime_get_ns(), tctx->last_run_at) > slice_ns) {
		s32 cpu = scx_bpf_task_cpu(p);
		bool cpu_busy = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) ||
				scx_bpf_dsq_nr_queued(cpu_dsq(cpu));

		if (is_cpu_busy(cpu) && cpu_busy)
			scx_bpf_task_set_slice(p, 0);
	}
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	struct task_ctx *tctx;

	/*
	 * Dispatch the task to the shared DSQ, using the deadline-based
	 * scheduling.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 *
	 * A busy @prev_cpu is a reason to leave only when it is busy with
	 * someone else. A task that is re-enqueued from its own CPU at the
	 * end of its slice is what @prev_cpu is busy with, and it is giving
	 * the CPU up to whoever was waiting for it, typically a per-CPU
	 * kworker that is done a few microseconds later. Pushing it away at
	 * that point turns every such handover into a migration. Leave it
	 * queued instead, the way a task stays on its runqueue: its own CPU
	 * takes it back as soon as it is free again.
	 *
	 * A task re-enqueued from its own CPU with slice left, on the other
	 * hand, was preempted by a higher scheduling class (the kernel
	 * bounces an IMMED task back through ops.enqueue() in that case)
	 * and @prev_cpu is taken for an unknown amount of time, so an idle
	 * CPU is the better option.
	 *
	 * A busy SMT sibling is not a reason to leave. Sharing a core is
	 * avoided when a task is placed, the idle scan prefers a fully idle
	 * core, and never by moving a running task: EEVDF does the same in
	 * select_idle_core(), and leaves a running task where it is.
	 */
	if (task_should_migrate(p, enq_flags) ||
	    (!is_cpu_idle(prev_cpu) && (!scx_bpf_task_running(p) || p->scx.slice))) {
		cpu = pick_idle_cpu(p, prev_cpu, -1, 0);
		if (cpu >= 0) {
			place_task(cpu, p, tctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   slice_ns, enq_flags | SCX_ENQ_IMMED);
			return;
		}
	}

	/*
	 * Keep using the same CPU if that CPU is not busy.
	 */
	if (!is_cpu_busy(prev_cpu)) {
		place_task(prev_cpu, p, tctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns, enq_flags);
		return;
	}

	place_task(prev_cpu, p, tctx);

	/*
	 * Queue the task on @prev_cpu's DSQ, ordered by deadline.
	 *
	 * Any CPU of the node can take it from there, but only while
	 * dispatching: if @prev_cpu went idle in the meantime and the rest
	 * of the node is idle too, nothing would ever look at it. Kick
	 * @prev_cpu, which is a no-op unless it is idle.
	 */
	scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
				 slice_ns, task_dl(p, tctx), enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);

	/*
	 * A faster CPU sitting idle would never look at this queue on its
	 * own: wake it up so that it pulls the task, see try_steal_task().
	 */
	if (!is_pcpu_task(p)) {
		cpu = idle_faster_cpu(prev_cpu);
		if (cpu >= 0)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	/*
	 * Do not keep running if the task doesn't need to run.
	 */
	if (!is_task_queued(p))
		return false;

	return true;
}

/*
 * A task that ran within this long on its CPU is still cache hot there and
 * is not stolen, like task_hot() with sysctl_sched_migration_cost.
 */
#define MIGRATION_COST_NS	500000ULL

static bool task_hot(struct task_struct *p, u64 now)
{
	const struct task_ctx *tctx = try_lookup_task_ctx(p);

	return tctx && time_before(now, tctx->last_stop_at + MIGRATION_COST_NS);
}

/*
 * Number of other CPUs' queues a busy CPU looks at on each dispatch for a
 * queue deeper than its own.
 */
#define BALANCE_SAMPLE	2

/*
 * Dispatch on @dst_cpu a task from its own DSQ or from the DSQ of another
 * CPU of the node.
 *
 * A CPU with nothing queued pulls the first task it finds: from the slower
 * CPUs first, hot or not, since a task is better off on a faster core than
 * with a warm cache on a slow one (this is what carries the load up the
 * capacity ladder, the way asym packing does), but only when its whole
 * core is idle, as a fast thread sharing its core is no better than a
 * whole slow one and asym_smt_can_pull_tasks() refuses that move too;
 * then from its own LLC,
 * then from the rest of the node, leaving alone a task that ran on its CPU
 * a moment ago, see task_hot(): its home CPU takes it back within a slice,
 * while moving it costs its cache.
 *
 * A CPU with work of its own samples BALANCE_SAMPLE other queues, rotating
 * through them across dispatches, and takes the head of one that is more
 * than twice as deep as its own and at least two tasks deeper. Every queue
 * is fed by the wakeups of its own CPU, so this is the only way a pile-up
 * gets spread out, e.g. a hundred children forked on one CPU while every
 * other CPU was busy with a task of its own, the way the load balancer
 * moves tasks off the busiest runqueue. The margin is what keeps CPUs
 * under an even load from trading tasks back and forth (the balancer has
 * its imbalance_pct), and a CPU samples at most once per slice, the way the load
 * balancer runs on the tick rather than on every pick: sampling on every
 * dispatch under a wakeup storm moved tasks around faster than they could
 * warm a cache. Otherwise the CPU takes its own head: waiting for the
 * owning CPU's slice end is what EEVDF does under RUN_TO_PARITY, and
 * sampling the queues for an earlier deadline instead measured worse on
 * every load.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cpu
 * (or is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cpu)
{
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(dst_cpu);
	struct task_struct *own = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(dst_cpu));
	int node = cpu_node(dst_cpu);
	u64 now = bpf_ktime_get_ns(), dst_llc = cpu_llc_of(dst_cpu);
	u32 limit, start, cpu, i, own_nr = 0;
	s32 src = -1;

	if (own) {
		if (!cctx || time_before(now, cctx->last_balance_at + slice_ns))
			goto own;
		cctx->last_balance_at = now;
		own_nr = scx_bpf_dsq_nr_queued(cpu_dsq(dst_cpu));
	}

	start = cctx ? cctx->steal_cursor : dst_cpu;
	if (start >= nr_cpu_ids)
		start = 0;

	if (!own && !all_cpus_same_capacity && core_is_idle(dst_cpu)) {
		u64 dst_cap = cpu_cap(dst_cpu);

		bpf_for(i, 0, nr_cpu_ids) {
			struct task_struct *p;
			u32 j = nr_cpu_ids - 1 - i;

			if (j >= MAX_CPUS)
				continue;
			cpu = preferred_cpus[j];
			if (cpu_cap(cpu) >= dst_cap)
				break;
			if (numa_enabled && cpu_node(cpu) != node)
				continue;

			p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
			if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr))
				continue;

			src = cpu;
			break;
		}
		if (src >= 0)
			goto pick;
	}

	/*
	 * One extra slot covers @dst_cpu itself falling in the sample. An
	 * idle CPU walks its own LLC before the rest of the node, so it does
	 * two passes.
	 */
	limit = own ? BALANCE_SAMPLE + 1 : nr_cpu_ids;
	bpf_for(i, 0, own ? limit : 2 * limit) {
		struct task_struct *p;
		bool local_pass = !own && i < limit;

		cpu = start + 1 + (i < limit ? i : i - limit);
		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;
		if (cpu >= nr_cpu_ids || cpu == dst_cpu)
			continue;
		if (numa_enabled && cpu_node(cpu) != node)
			continue;
		if (!own && (cpu_llc_of(cpu) == dst_llc) != local_pass)
			continue;
		if (own) {
			u32 nr = scx_bpf_dsq_nr_queued(cpu_dsq(cpu));

			if (nr < own_nr + 2 || nr <= 2 * own_nr)
				continue;
		}

		p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
		if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr) ||
		    task_hot(p, now))
			continue;

		src = cpu;
		break;
	}
	if (cctx) {
		start += limit;
		if (start >= nr_cpu_ids)
			start -= nr_cpu_ids;
		cctx->steal_cursor = start;
	}

own:
	if (src < 0 && own)
		src = dst_cpu;

pick:
	if (src < 0)
		return false;

	if (!scx_bpf_dsq_move_to_local(cpu_dsq(src), 0))
		return false;

	if (src != dst_cpu)
		__sync_fetch_and_add(&nr_steals, 1);

	return true;
}

void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Take a task from this CPU's queue or from a deeper one on the
	 * node, then fall back to this CPU's own DSQ in case the pick raced
	 * with another CPU.
	 */
	if (try_steal_task(cpu) || scx_bpf_dsq_move_to_local(cpu_dsq(cpu), 0))
		return;

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, give it another time slot.
	 */
	if (prev && keep_running(prev, cpu)) {
		scx_bpf_task_set_slice(prev, slice_ns);
		return;
	}

	/*
	 * Nothing to run: the CPU is going idle. ops.update_idle() will not
	 * say so if the CPU was claimed and kicked for a task that never
	 * came, since there is no transition then, so re-arm the bit here.
	 */
	cpu_idle_set(cpu);
}

void BPF_STRUCT_OPS(cosmos_update_idle, s32 cpu, bool idle)
{
	if (idle)
		cpu_idle_set(cpu);
	else
		cpu_idle_claim(cpu);
}

void BPF_STRUCT_OPS(cosmos_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;
	s64 limit, lag;

	__sync_fetch_and_sub(&sum_weight, p->scx.weight);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Remember how far the task is from the reference as it stops being
	 * runnable, clamped both ways, like update_entity_lag():
	 *
	 *	vlag = avg_vruntime(cfs_rq) - se->vruntime;
	 *	se->vlag = clamp(vlag, -limit, limit);
	 *
	 * What is preserved across a sleep is the position relative to the
	 * reference, not the absolute vruntime. Restoring the vruntime
	 * against the reference alone would hand every task that sleeps long
	 * enough the full credit, no matter whether it had earned it.
	 */
	limit = scale_by_dl_weight(p, slice_lag);
	lag = (s64)(cpu_vref(tctx->vcpu >= 0 ? tctx->vcpu : scx_bpf_task_cpu(p)) - tctx->vruntime);
	if (lag > limit)
		lag = limit;
	else if (lag < -limit)
		lag = -limit;
	tctx->vlag = lag;
	vref_leave(tctx);
}

void BPF_STRUCT_OPS(cosmos_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&sum_weight, p->scx.weight);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Place the task back at the lag it had when it went to sleep, the
	 * way place_entity() does:
	 *
	 *	se->vruntime = vruntime - lag;
	 *
	 * A task that had consumed its share before sleeping comes back with
	 * no credit, while one that was still owed service keeps it. This
	 * is against the system-wide reference; the task is placed again
	 * against the CPU it is queued on, see place_task().
	 */
	vref_leave(tctx);
	tctx->vruntime = vtime_now - tctx->vlag;
}

void BPF_STRUCT_OPS(cosmos_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * A task that was moved here from another CPU's queue, by the
	 * balancer or an idle pull, carries a vruntime that means nothing
	 * against this CPU's pack: taken from a pack that was far ahead it
	 * would wait here until the pack climbs past it, seconds under
	 * load. Carry the lag instead, the way a migration does in
	 * place_entity(): how far the task was from the pack it left is how
	 * far it is placed from the pack it joins.
	 */
	cpu = scx_bpf_task_cpu(p);
	if (tctx->vcpu >= 0 && tctx->vcpu != cpu) {
		s64 limit = scale_by_dl_weight(p, slice_lag);
		s64 lag = (s64)(cpu_vref(tctx->vcpu) - tctx->vruntime);

		if (lag > limit)
			lag = limit;
		else if (lag < -limit)
			lag = -limit;
		tctx->vruntime = cpu_vref(cpu) - lag;
	}
	vref_join(cpu, p, tctx);

	/*
	 * Snapshot the task's user time, so that only the user time
	 * accumulated on this CPU is charged to it.
	 */
	if (busy_threshold)
		tctx->last_utime = p->utime;

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(scx_bpf_task_cpu(p));

}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice, weight;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Update task's performance counters */

	/*
	 * Charge the user time accumulated on this CPU before the task
	 * releases it.
	 */
	if (busy_threshold) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);

		if (cctx) {
			cctx->acc_utime += p->utime - tctx->last_utime;
			tctx->last_utime = p->utime;
		}
	}

	/*
	 * Evaluate the used time slice.
	 */
	tctx->last_stop_at = bpf_ktime_get_ns();
	slice = tctx->last_stop_at - tctx->last_run_at;

	/*
	 * The runtime is charged as wall-clock time whatever the CPU it was
	 * spent on. Charging a slow CPU at a discount reads fair, but with
	 * one system-wide reference it isn't: the tasks on the slow CPUs
	 * drift below V without bound while the reference follows the
	 * average, their keys keep getting earlier, and a task waking up on
	 * a slow CPU, placed at V minus a bounded lag, sorts behind all of
	 * them and waits until their vruntime has climbed past it, hundreds
	 * of milliseconds after a second of load. EEVDF charges wall-clock
	 * time and uses the capacity only to balance the load.
	 */
	/*
	 * Charge the service just consumed to the task's vruntime, the way
	 * update_curr() does:
	 *
	 *	se->vruntime += calc_delta_fair(delta_exec, se);
	 */
	tctx->vruntime += scale_by_task_weight_inverse(p, slice);
	vref_charge(tctx);

	/*
	 * Advance the system virtual time by the service just delivered.
	 *
	 * EEVDF's reference is the weighted average of the runnable set,
	 *
	 *	V = \Sum (w_i * v_i) / \Sum w_i
	 *
	 * so serving @p for @slice moves it by
	 *
	 *	dV = w_p * dv_p / \Sum w_i = slice * NICE_0 / \Sum w_i
	 *
	 * since dv_p is the slice scaled by the inverse of @p's weight. That
	 * is an identity, not an approximation: what matters is that V rises
	 * with the service handed out no matter who receives it. Deriving it
	 * from the running task's own vruntime instead (the previous
	 * max-of-running rule) stalls the clock exactly when it is needed,
	 * because the tasks that are behind never run and the tasks that do
	 * run barely advance their own vruntime.
	 *
	 * The division truncates, and once the total weight exceeds a
	 * hundred times the length of a burst every burst contributes
	 * nothing: with a few thousand runnable tasks V would stop entirely
	 * and everything queued behind it would starve. Carry the remainder
	 * per CPU so that the service is accounted in full.
	 */
	weight = sum_weight;
	if (weight) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
		u64 acc = slice * 100 + (cctx ? cctx->vtime_rem : 0);
		u64 delta = acc / weight;

		if (cctx)
			cctx->vtime_rem = acc - delta * weight;
		if (delta)
			__sync_fetch_and_add(&vtime_now, delta);
	}

	/*
	 * Update per-CPU statistics.
	 */
	update_cpu_load(p, slice);
}

void BPF_STRUCT_OPS(cosmos_enable, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (tctx) {
		tctx->vruntime = vtime_now;
		tctx->vcpu = -1;
	}
}

s32 BPF_STRUCT_OPS(cosmos_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	int ret;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	ret = init_cpumask(&tctx->cpumask);
	if (ret)
		return ret;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	int err;
	int cpu;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create the per-CPU DSQs.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		int node = numa_enabled ? cpu_node(cpu) : -1;

		err = scx_bpf_create_dsq(cpu_dsq(cpu), node < 0 ? -1 : node);
		if (err) {
			scx_bpf_error("failed to create DSQ for CPU %d: %d", cpu, err);
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .tick                    = (void *)cosmos_tick,
	       .runnable		= (void *)cosmos_runnable,
	       .quiescent		= (void *)cosmos_quiescent,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .update_idle		= (void *)cosmos_update_idle,
	       .enable			= (void *)cosmos_enable,
	       .init_task		= (void *)cosmos_init_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
