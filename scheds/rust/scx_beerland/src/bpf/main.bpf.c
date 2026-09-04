/* SPDX-License-Identifier: GPL-2.0 */

#include <scx/common.bpf.h>
#include <lib/bpf_cpumask.h>
#include <scx/percpu.bpf.h>
#include "intf.h"

/*
 * Maximum amount of CPUs supported by the scheduler for per-CPU data.
 */
#define MAX_CPUS	4096

/*
 * Return true if @cpu is valid, false otherwise.
 */
#define IS_CPU_VALID(__cpu) ((__cpu) >= 0 && (__cpu) < MAX_CPUS)

/*
 * Return the LLC id associated to a CPU, or -1 if the CPU is invalid.
 */
#define CPU_LLC_ID(__cpu) \
	(IS_CPU_VALID(__cpu) ? cpu_llc_id(__cpu) : -1)

/*
 * Return the capacity of a CPU, or -1 if the CPU is invalid.
 */
#define CPU_CAPACITY(__cpu) \
	(IS_CPU_VALID(__cpu) ? cpu_capacity[__cpu] : -1)

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Default time slice.
 */
const volatile u64 slice_ns = NSEC_PER_MSEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile u64 slice_lag = 40ULL * NSEC_PER_MSEC;

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Enable NUMA optimizations.
 */
const volatile bool numa_enabled = true;

/*
 * Accounted CPU time threshold to decide whether a time slice marks its CPU as
 * a remote dispatch source. 0 disables filtering.
 */
const volatile u64 busy_threshold;

/*
 * Fast event-driven per-CPU busy state. This reacts within a scheduling slice.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u64);
} cpu_busy_until_map SEC(".maps");

/*
 * Subset of CPUs to prioritize.
 */
private(BEERLAND) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile bool primary_all = false;

/*
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * Scheduling statistics.
 */
volatile u64 nr_local_dispatch, nr_remote_dispatch, nr_keep_running;

/*
 * Current system vruntime.
 */
static u64 vtime_now;

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	struct bpf_cpumask __kptr *smt;
	u64 last_run_at;
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
 * Per-task context.
 */
struct task_ctx {
	u64 last_cputime;
	s64 sleep_vlag;
	bool has_sleep_vlag;
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
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @cpu is marked busy enough to steal from.
 */
static inline bool is_cpu_busy(u64 cpu, u64 now)
{
	u64 *until;
	u32 key;

	if (!busy_threshold)
		return true;

	if (cpu >= MAX_CPUS)
		return false;

	key = cpu;
	until = bpf_map_lookup_elem(&cpu_busy_until_map, &key);

	return until && time_before(now, *until);
}

static inline bool task_used_enough_cpu_time(const struct task_struct *p,
					     const struct task_ctx *tctx,
					     u64 runtime)
{
	u64 total_delta;

	if (!runtime)
		return false;

	total_delta = p->utime + p->stime - tctx->last_cputime;

	return total_delta >= runtime * busy_threshold / 1024;
}

static inline void mark_cpu_busy(s32 cpu, u64 now)
{
	u64 *until;
	u32 key;

	if (!IS_CPU_VALID(cpu))
		return;

	key = cpu;
	until = bpf_map_lookup_elem(&cpu_busy_until_map, &key);
	if (until)
		*until = now + slice_ns;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Clamp saved virtual lag so sleepers carry bounded credit or debt.
 */
static s64 task_clamp_sleep_vlag(const struct task_struct *p, s64 vlag)
{
	s64 limit = (s64)scale_by_task_weight_inverse(p, slice_lag);

	return CLAMP(vlag, -limit, limit);
}

/*
 * Save bounded virtual lag for voluntary sleepers.
 *
 * Positive lag means the task slept behind vtime_now (credit), negative lag
 * means it slept ahead of vtime_now (debt).
 */
static void task_save_sleep_vlag(struct task_struct *p, struct task_ctx *tctx)
{
	s64 vlag = (s64)(vtime_now - p->scx.dsq_vtime);

	tctx->sleep_vlag = task_clamp_sleep_vlag(p, vlag);
	tctx->has_sleep_vlag = true;

	scx_bpf_task_set_dsq_vtime(p, vtime_now - tctx->sleep_vlag);
}

/*
 * Re-align a waking task's vruntime to the current vtime_now, applying its
 * saved virtual lag.
 *
 * Positive lag preserves bounded sleep credit, negative lag preserves bounded
 * sleep debt.
 */
static u64 task_apply_sleep_vlag(struct task_struct *p, struct task_ctx *tctx)
{
	s64 vlag;

	if (tctx->has_sleep_vlag) {
		vlag = task_clamp_sleep_vlag(p, tctx->sleep_vlag);
		scx_bpf_task_set_dsq_vtime(p, vtime_now - vlag);
		tctx->has_sleep_vlag = false;
	}

	return p->scx.dsq_vtime;
}

/*
 * Evaluate the deadline of task @p.
 */
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx)
{
	bool was_sleeper = tctx->has_sleep_vlag;
	u64 vtime = task_apply_sleep_vlag(p, tctx);
	u64 vtime_min;

	/*
	 * A task waking from sleep already had its vruntime re-aligned to
	 * vtime_now in task_apply_sleep_vlag(), bounded by the sleep virtual
	 * lag clamp, so there is nothing more to do for it here.
	 */
	if (was_sleeper)
		return vtime;

	/*
	 * Otherwise bound how far a continuously runnable task's vruntime can
	 * fall behind the global vtime.
	 *
	 * A task that keeps running on a heavily contended CPU accumulates
	 * vruntime much more slowly than the rest of the system. Without this
	 * floor its low vruntime keeps undercutting other tasks queued on the
	 * same per-CPU DSQ, which can starve them indefinitely and trip the
	 * runnable task stall watchdog.
	 *
	 * The bound is symmetric with the sleep virtual lag clamp, so that
	 * awake and sleeping tasks can drift from vtime_now by the same amount.
	 */
	vtime_min = vtime_now - scale_by_task_weight_inverse(p, slice_lag);
	if (time_before(vtime, vtime_min)) {
		vtime = vtime_min;
		scx_bpf_task_set_dsq_vtime(p, vtime);
	}

	return vtime;
}

/*
 * Return @p's vruntime including runtime accumulated since it started running.
 *
 * @last_run_at is sourced from the per-CPU context rather than @p's task-local
 * storage, so this can be called on an untrusted remote-CPU current task (only
 * plain field reads, e.g. dsq_vtime and weight, are performed on @p).
 */
static u64 task_current_vtime(const struct task_struct *p, u64 last_run_at)
{
	u64 now;

	if (!last_run_at)
		return p->scx.dsq_vtime;

	now = bpf_ktime_get_ns();
	if (now <= last_run_at)
		return p->scx.dsq_vtime;

	return p->scx.dsq_vtime +
	       scale_by_task_weight_inverse(p, now - last_run_at);
}

/*
 * Return true if @vtime is eligible to run at the current system vruntime.
 */
static bool vtime_eligible(u64 vtime)
{
	return time_before_eq(vtime, vtime_now);
}

/*
 * Return true if an eligible sleeper should preempt @curr on wakeup.
 */
static bool should_preempt_curr(const struct task_struct *curr, s32 curr_cpu,
				u64 dl, bool is_sleep_wakeup)
{
	struct cpu_ctx *cctx;
	u64 curr_vtime, last_run_at = 0;

	if (!is_sleep_wakeup || !vtime_eligible(dl))
		return false;

	/*
	 * Only preempt tasks managed by sched_ext. A task that isn't (or is no
	 * longer) scheduled by sched_ext has a zero dsq_vtime: it is set to a
	 * non-zero system vruntime in ops.enable() and reset in ops.disable().
	 *
	 * Tasks in higher scheduling classes (stop, deadline, RT) can't be
	 * preempted by us anyway. The idle task doesn't need SCX_ENQ_PREEMPT
	 * either: a regular scx_bpf_dsq_insert() followed by the idle kick is
	 * enough to take the CPU out of idle and run the waking task. So for
	 * both cases we fall back to a regular vtime enqueue.
	 *
	 * This also avoids estimating @curr's vruntime from a stale per-CPU
	 * timestamp left behind by a previous sched_ext task.
	 */
	if (!curr->scx.dsq_vtime)
		return false;

	cctx = try_lookup_cpu_ctx(curr_cpu);
	if (cctx)
		last_run_at = cctx->last_run_at;

	curr_vtime = task_current_vtime(curr, last_run_at);

	return !vtime_eligible(curr_vtime) || time_before(dl, curr_vtime);
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return true;

	return CPU_LLC_ID(this_cpu) == CPU_LLC_ID(that_cpu);
}

/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return false;

	return CPU_CAPACITY(this_cpu) > CPU_CAPACITY(that_cpu);
}

/*
 * Return the SMT sibling CPU of a @cpu, or @cpu if SMT is disabled.
 */
static s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx *cctx;

	if (!smt_enabled)
		return cpu;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return cpu;

	smt = cast_mask(cctx->smt);
	if (!smt)
		return cpu;

	return bpf_cpumask_first(smt);
}

/*
 * Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_cpumask();

	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return true if the CPU is part of a fully busy SMT core, false
 * otherwise.
 *
 * If SMT is disabled or SMT contention avoidance is disabled, always
 * return false (since there's no SMT contention or it's ignored).
 */
static bool is_smt_contended(s32 cpu)
{
	const struct cpumask *idle_mask;
	bool is_contended;

	if (!smt_enabled)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask = get_idle_cpumask(cpu);
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if we should attempt a task migration to an idle CPU from
 * ops.enqueue(), false otherwise.
 *
 * We want to attempt a migration on wakeup or if the CPU used by the task
 * is contended, but only if ops.select_cpu() was skipped.
 */
static bool try_migrate(const struct task_struct *p, s32 prev_cpu, u64 enq_flags)
{
	/*
	 * Migrate if ops.select_cpu() was skipped and one of the following
	 * conditions is true:
	 *  - migration was not attempted already via ops.select_cpu(),
	 *  - the CPU is contended by other tasks,
	 *  - SMT is enabled and the SMT core is contended by other tasks.
	 */
	return (!scx_bpf_task_running(p) && !__COMPAT_is_enq_cpu_selected(enq_flags)) ||
	       __COMPAT_scx_bpf_dsq_peek(prev_cpu) ||
	       is_smt_contended(prev_cpu);
}

/*
 * Return true if @cpu is in the primary domain, false otherwise.
 */
static inline bool is_primary_cpu(s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	if (primary_all)
		return true;

	return mask && bpf_cpumask_test_cpu(cpu, mask);
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	/*
	 * Do not keep running if the task doesn't need to run.
	 */
	if (!is_task_queued(p))
		return false;

	/*
	* If the task can only run on this CPU, keep it running.
	*/
	if (is_pcpu_task(p))
		return true;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	/*
	 * If the task is not in the primary domain, give it a chance to
	 * migrate.
	 */
	if (!is_primary_cpu(cpu) &&
	    mask && bpf_cpumask_intersects(p->cpus_ptr, mask))
		return false;

	return true;
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	pmask = &cctx->smt;

	/* Make sure the target CPU mask is initialized */
	err = init_bpfmask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Called from user-space to add CPUs to the the primary domain.
 */
SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_bpfmask(&primary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Return the tartget @cpu if it's usable by @p, or the first CPU usable.
 */
static s32 task_cpu(const struct task_struct *p, s32 cpu)
{
	if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return cpu;

	return bpf_cpumask_first(p->cpus_ptr);
}

/*
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu, u64 wake_flags)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		bool is_idle = false;

		/*
		 * scx_bpf_select_cpu_dfl() can only be used in
		 * ops.select_cpu().
		 */
		if (this_cpu < 0)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * If a primary domain is defined, try to pick an idle CPU from
	 * there first.
	 */
	if (!primary_all && mask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask, 0);
		if (cpu >= 0)
			return cpu;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Return true if @p can run on @cpu, false otherwise.
 */
static bool is_cpu_allowed(const struct task_struct *p, s32 cpu)
{
	return p->nr_cpus_allowed == nr_cpu_ids ||
	       bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/*
 * Called on task wakeup to give the task a chance to migrate to an idle
 * CPU.
 */
s32 BPF_STRUCT_OPS(beerland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = is_cpu_allowed(p, this_cpu);

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 */
	if ((wake_flags & SCX_WAKE_TTWU) &&
	    is_cpu_faster(this_cpu, prev_cpu) && is_this_cpu_allowed) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (is_cpu_allowed(p, prev_cpu) &&
		    cpus_share_cache(this_cpu, prev_cpu) &&
		    (!is_smt_contended(prev_cpu)) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
			return prev_cpu;
		}

		prev_cpu = this_cpu;
	}

	/*
	 * Try to find an optimal idle CPU for the task. If no idle CPU is
	 * found, keep using the same one.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Called when a task expired its time slice and still needs to run or on
 * wakeup when there's no idle CPU available.
 */
void BPF_STRUCT_OPS(beerland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = task_cpu(p, scx_bpf_task_cpu(p));
	struct task_ctx *tctx;
	struct task_struct *curr;
	bool preempt_wakeup = false;
	bool is_wakeup;
	u64 dl;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	is_wakeup = (enq_flags & SCX_ENQ_WAKEUP) && tctx->has_sleep_vlag;
	dl = task_dl(p, tctx);

	/*
	 * Attempt a migration to an idle CPU if possible.
	 */
	if (try_migrate(p, prev_cpu, enq_flags)) {
		s32 cpu;

		if (is_pcpu_task(p))
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -ENOENT, 0);

		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   slice_ns, enq_flags);
			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Keep running on the same CPU.
	 */
	curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);
	if (curr) {
		preempt_wakeup = should_preempt_curr(curr, prev_cpu, dl, is_wakeup);
		if (preempt_wakeup)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
					   slice_ns, enq_flags | SCX_ENQ_PREEMPT);
		else
			scx_bpf_dsq_insert_vtime(p, prev_cpu, slice_ns, dl, enq_flags);
	} else {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns, enq_flags);
	}

	if (!preempt_wakeup && !__COMPAT_is_enq_cpu_selected(enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Try to steal the runnable task with the earliest vruntime and dispatch it on
 * @dst_cpu.
 */
static bool try_steal_task(s32 dst_cpu)
{
	u64 min_vtime = ULLONG_MAX, i, cpu, min_cpu, now;

	now = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_cpu_ids) {
		struct task_struct *p;

		/*
		 * Offset the scan by @dst_cpu so that, on ties, different CPUs
		 * start probing from different positions instead of all
		 * favoring the lowest CPU ID.
		 */
		cpu = dst_cpu + i;
		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;

		if (!is_cpu_busy(cpu, now))
			continue;

		p = __COMPAT_scx_bpf_dsq_peek(cpu);
		if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr))
			continue;

		if (p->scx.dsq_vtime < min_vtime) {
			min_vtime = p->scx.dsq_vtime;
			min_cpu = cpu;
		}
	}

	return min_vtime < ULLONG_MAX && scx_bpf_dsq_move_to_local(min_cpu, 0);
}

/*
 * Called when a CPU becomes available: dispatch the next task on the CPU
 * or let the CPU go idle.
 */
void BPF_STRUCT_OPS(beerland_dispatch, s32 cpu, struct task_struct *prev)
{
	bool need_running = prev && keep_running(prev, cpu);

	if (try_steal_task(cpu)) {
		__sync_fetch_and_add(&nr_remote_dispatch, 1);
		return;
	}

	if (scx_bpf_dsq_move_to_local(cpu, 0)) {
		__sync_fetch_and_add(&nr_local_dispatch, 1);
		return;
	}

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (need_running) {
		scx_bpf_task_set_slice(prev, slice_ns);
		__sync_fetch_and_add(&nr_keep_running, 1);
	}
}

void BPF_STRUCT_OPS(beerland_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run, used to evaluate the
	 * used time slice in ops.stopping() and to estimate this task's
	 * current vruntime from a remote CPU in should_preempt_curr().
	 *
	 * It is stored in the per-CPU context so that should_preempt_curr()
	 * can read it without a task-local storage lookup on an untrusted
	 * remote-CPU current task.
	 */
	cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
	if (cctx)
		cctx->last_run_at = bpf_ktime_get_ns();
	tctx->last_cputime = p->utime + p->stime;

	/*
	 * Re-apply vlag here for tasks that have been directly dispatched,
	 * bypassing the per-CPU DSQ.
	 */
	task_apply_sleep_vlag(p, tctx);

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(beerland_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u64 now, last_run_at, slice, vtime;

	cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
	if (!cctx)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	now = bpf_ktime_get_ns();
	last_run_at = cctx->last_run_at;
	slice = now - last_run_at;

	if (busy_threshold && runnable &&
	    task_used_enough_cpu_time(p, tctx, slice))
		mark_cpu_busy(bpf_get_smp_processor_id(), now);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 */
	vtime = p->scx.dsq_vtime + scale_by_task_weight_inverse(p, slice);
	scx_bpf_task_set_dsq_vtime(p, vtime);
}

void BPF_STRUCT_OPS(beerland_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	task_save_sleep_vlag(p, tctx);
}

void BPF_STRUCT_OPS(beerland_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

void BPF_STRUCT_OPS(beerland_disable, struct task_struct *p)
{
	/*
	 * Reset the task's vruntime when it leaves sched_ext, so that it is no
	 * longer mistaken for a sched_ext task by should_preempt_curr() while
	 * it runs under a different scheduling class.
	 */
	scx_bpf_task_set_dsq_vtime(p, 0);
}

s32 BPF_STRUCT_OPS(beerland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

/*
 * Scheduler exit callback.
 */
void BPF_STRUCT_OPS(beerland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduler init callback.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(beerland_init)
{
	s32 cpu;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	bpf_for(cpu, 0, nr_cpu_ids) {
		int err;

		err = scx_bpf_create_dsq(cpu, __COMPAT_scx_bpf_cpu_node(cpu));
		if (err)
			return err;
	}

	return 0;
}

SCX_OPS_DEFINE(beerland_ops,
	       .select_cpu		= (void *)beerland_select_cpu,
	       .enqueue			= (void *)beerland_enqueue,
	       .dispatch		= (void *)beerland_dispatch,
	       .running			= (void *)beerland_running,
	       .stopping		= (void *)beerland_stopping,
	       .quiescent		= (void *)beerland_quiescent,
	       .enable			= (void *)beerland_enable,
	       .disable			= (void *)beerland_disable,
	       .init_task		= (void *)beerland_init_task,
	       .init			= (void *)beerland_init,
	       .exit			= (void *)beerland_exit,
	       .timeout_ms		= 5000,
	       .name			= "beerland");
