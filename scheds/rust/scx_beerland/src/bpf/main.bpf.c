/* SPDX-License-Identifier: GPL-2.0 */

#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include "intf.h"

/*
 * Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
 * this value).
 */
#define MAX_WAKEUP_FREQ		128ULL

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Default time slice.
 */
const volatile u64 slice_ns = NSEC_PER_MSEC;

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

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
	u64 last_run_at;
	u64 last_woke_at;
	u64 wakeup_freq;
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
 * Update the average frequency of an event.
 *
 * The frequency is computed from the given interval since the last event
 * and combined with the previous frequency using an exponential weighted
 * moving average.
 */
static u64 update_freq(u64 freq, u64 interval)
{
        u64 new_freq;

        new_freq = (100 * NSEC_PER_MSEC) / interval;
        return calc_avg(freq, new_freq);
}

/*
 * Evaluate the task's time slice proportionally to its weight and
 * inversely proportional to the amount of contending tasks.
 */
static u64 task_slice(struct task_struct *p, s32 cpu)
{
	return scale_by_task_weight(p, slice_ns);
}

/*
 * Return task's wakeup frequency.
 */
static u64 task_wakeup_freq(const struct task_struct *p)
{
	const struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return 1;

	return MAX(tctx->wakeup_freq, 1);
}

/*
 * Evaluate the vruntime of task @p.
 *
 * Proportionally scale vruntime in function of the task's priority.
 * Moreover, cap the maximum amount of vruntime credit, accumulated while
 * the task is sleeping, proportionally to the task's priority and the
 * wakeup rate.
 */
static u64 task_vtime(const struct task_struct *p)
{
	u64 vtime, vtime_min;

	vtime = p->scx.dsq_vtime;
	vtime_min = vtime_now - scale_by_task_weight(p, slice_ns * task_wakeup_freq(p));

	return time_before(vtime, vtime_min) ? vtime_min : vtime;
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return true;

	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}

/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return false;

	return cpu_priority(this_cpu) > cpu_priority(that_cpu);
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
	idle_mask = scx_bpf_get_idle_cpumask();
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if all the CPUs in the system are busy, false otherwise.
 */
static bool is_system_busy(void)
{
	const struct cpumask *idle_mask;
	bool is_busy;

	idle_mask = scx_bpf_get_idle_cpumask();
	is_busy = bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_busy;
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
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p))
		return false;

	/*
	 * Migrate if ops.select_cpu() was skipped and one of the following
	 * conditions is true:
	 *  - task was not running (task wakeup),
	 *  - the previously used CPU is contended by other tasks,
	 *  - SMT is enabled, the previously used CPU is not a full-idle
	 *    SMT core and there are other full-idle SMT cores available
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) &&
		       (!scx_bpf_task_running(p) ||
			scx_bpf_dsq_nr_queued(prev_cpu) ||
			(smt_enabled && is_smt_contended(prev_cpu)));
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);

	/* Do not keep running if the task doesn't need to run */
	if (!is_task_queued(p))
		return false;

	/*
	 * Do not keep running if the CPU is not in the primary domain and
	 * the task can use the primary domain).
	 */
	if (primary && bpf_cpumask_intersects(primary, p->cpus_ptr) &&
	    !bpf_cpumask_test_cpu(cpu, primary))
		return false;

	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p))
		return true;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	return true;
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
	err = init_cpumask(pmask);
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

	err = init_cpumask(&primary_cpumask);
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
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
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
 * Called on task wakeup to give the task a chance to migrate to an idle
 * CPU.
 */
s32 BPF_STRUCT_OPS(beerland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

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
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    (!is_smt_contended(prev_cpu)) && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		prev_cpu = this_cpu;
	}

	/*
	 * Rely on the sched_ext built-in idle CPU selection policy (that
	 * automatically applies topology optimizations).
	 */
	cpu = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags);
	if (cpu < 0) {
		/*
		 * If all the CPUs are busy, try to move the wakee to the
		 * waker's CPU, if possible.
		 *
		 * This should help grouping together tasks that are part
		 * of the same pipeline and reduce IPIs at system
		 * saturation.
		 */
		cpu = is_this_cpu_allowed ? this_cpu : prev_cpu;
	}

	/*
	 * Always dispatch directly to the target CPU, since the task will
	 * always use its assigned per-CPU DSQ and we can save some
	 * runqueue locking contention dispatching from here.
	 *
	 * The target CPU is automatically kicked when returning from this
	 * callback.
	 */
	scx_bpf_dsq_insert_vtime(p, cpu, task_slice(p, cpu), task_vtime(p), 0);

	return cpu;
}

/*
 * Called when a task expired its time slice and still needs to run or on
 * wakeup when there's no idle CPU available.
 */
void BPF_STRUCT_OPS(beerland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu, prev_cpu = task_cpu(p, scx_bpf_task_cpu(p));

	/*
	 * Attempt a migration to an idle CPU if possible.
	 */
	if (try_migrate(p, prev_cpu, enq_flags)) {
		cpu = pick_idle_cpu(p, prev_cpu, -ENOENT, 0);
		if (cpu >= 0)
			prev_cpu = cpu;
	}

	/*
	 * Keep running on the same CPU.
	 */
	scx_bpf_dsq_insert_vtime(p, prev_cpu, task_slice(p, prev_cpu),
				 task_vtime(p), enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Try to consume a task from a remote DSQ.
 */
static bool dispatch_from_remote_cpu(s32 from_cpu)
{
	u64 min_vtime = ULLONG_MAX, cpu, min_cpu;

	/*
	 * Pick the task with the lowest vruntime within the same LLC.
	 *
	 * Restricting rebalancing to the LLC improves cache locality and
	 * also reduces lock contention on CPU runqueues.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct task_struct *p;

		if (cpu == from_cpu)
			continue;

		/*
		 * Avoid migrating if the remote CPU is not overloaded and
		 * has only one task waiting: this task will likely get a
		 * chance to run soon.
		 */
		if (scx_bpf_dsq_nr_queued(cpu) <= 1)
			continue;

		bpf_rcu_read_lock();
		p = __COMPAT_scx_bpf_dsq_peek(cpu);
		if (p && bpf_cpumask_test_cpu(from_cpu, p->cpus_ptr) &&
		    p->scx.dsq_vtime < min_vtime) {
			min_vtime = p->scx.dsq_vtime;
			min_cpu = cpu;
		}
		bpf_rcu_read_unlock();
	}

	return min_vtime < ULLONG_MAX && scx_bpf_dsq_move_to_local(min_cpu);
}

/*
 * Called when a CPU becomes available: dispatch the next task on the CPU
 * or let the CPU go idle.
 */
void BPF_STRUCT_OPS(beerland_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Consume from the local DSQ first.
	 */
	if (scx_bpf_dsq_move_to_local(cpu)) {
		__sync_fetch_and_add(&nr_local_dispatch, 1);
		return;
	}

	/*
	 * Try to consume a task from a remote CPU.
	 *
	 * Do no trigger any rebalance unless the system is completely
	 * saturated.
	 */
	if (is_system_busy() && dispatch_from_remote_cpu(cpu)) {
		__sync_fetch_and_add(&nr_remote_dispatch, 1);
		return;
	}

	/*
	 * If no other task is contending the CPU and the previous task
	 * still wants to run, let it run by refilling its time slice.
	 */
	if (prev && keep_running(prev, cpu)) {
		prev->scx.slice = task_slice(prev, cpu);
		__sync_fetch_and_add(&nr_keep_running, 1);
	}
}

void BPF_STRUCT_OPS(beerland_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Update the task's wakeup frequency based on the time since the
	 * last wakeup, then cap the result to avoid large spikes.
	 */
	delta_t = now - tctx->last_woke_at;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(beerland_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(beerland_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	slice = scx_bpf_now() - tctx->last_run_at;

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 */
	p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
}

void BPF_STRUCT_OPS(beerland_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
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
	       .runnable		= (void *)beerland_runnable,
	       .running			= (void *)beerland_running,
	       .stopping		= (void *)beerland_stopping,
	       .enable			= (void *)beerland_enable,
	       .init_task		= (void *)beerland_init_task,
	       .init			= (void *)beerland_init,
	       .exit			= (void *)beerland_exit,
	       .timeout_ms		= 5000,
	       .name			= "beerland");
