/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Global DSQ used to dispatch tasks.
 */
#define SHARED_DSQ		0

/*
 * Maximum multiplier for the dynamic task priority.
 */
#define MAX_LATENCY_WEIGHT	1000

/*
 * Task time slice range.
 */
const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;
const volatile u64 slice_min = 1ULL * NSEC_PER_MSEC;
const volatile u64 slice_lag = 20ULL * NSEC_PER_MSEC;

/*
 * When enabled always dispatch all kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads;

/*
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches,
	     nr_shared_dispatches, nr_migrate_dispatches;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Amount of possible CPUs in the system.
 */
static u64 nr_cpu_ids;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	struct bpf_cpumask __kptr *llc_cpumask;
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
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Temporary cpumask for calculating scheduling domains.
	 */
	struct bpf_cpumask __kptr *llc_cpumask;

	/*
	 * Total execution time of the task.
	 */
	u64 sum_exec_runtime;

	/*
	 * Voluntary context switches metrics.
	 */
	u64 nvcsw;
	u64 nvcsw_ts;

	/*
	 * Task's dynamic priority multiplier.
	 */
	u64 lat_weight;
};

/* Map that contains task-local storage. */
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
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
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
 * Compare two vruntime values, returns true if the first value is less than
 * the second one.
 *
 * Copied from scx_simple.
 */
static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Return true if the target task @p is a kernel thread, false instead.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return the dynamic priority multiplier.
 *
 * The multiplier is evaluated in function of the task's average rate of
 * voluntary context switches per second.
 */
static u64 task_dyn_prio(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return 1;
	return MAX(tctx->lat_weight, 1);
}

/*
 * Return task's dynamic priority.
 */
static u64 task_prio(struct task_struct *p)
{
	return p->scx.weight * task_dyn_prio(p);
}

/*
 * Return the task's allowed lag: used to determine how early its deadline it
 * can be.
 */
static u64 task_lag(struct task_struct *p)
{
	return MIN(slice_lag * task_prio(p) / 100, NSEC_PER_SEC);
}

/*
 * Return a value inversely proportional to the task's weight.
 */
static inline u64 scale_inverse_fair(struct task_struct *p, u64 value)
{
	return value * 100 / task_prio(p);
}

/*
 * Return task's evaluated deadline.
 */
static inline u64 task_vtime(struct task_struct *p)
{
	u64 min_vruntime = vtime_now - task_lag(p);
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return min_vruntime;

	/*
	 * Limit the vruntime to vtime_now minus the maximum task's lag to
	 * avoid excessively penalizing tasks.
	 */
	if (vtime_before(p->scx.dsq_vtime, min_vruntime))
		p->scx.dsq_vtime = min_vruntime;

	return p->scx.dsq_vtime;
}

static inline u64 nr_waiting_tasks(void)
{
	return scx_bpf_dsq_nr_queued(SHARED_DSQ);
}

/*
 * Evaluate task's time slice in function of the total amount of tasks that are
 * waiting to be dispatched and the task's weight.
 */
static inline void task_refill_slice(struct task_struct *p)
{
	u64 slice, nr_waiting = nr_waiting_tasks();

	slice = slice_max / (nr_waiting + 1);
	p->scx.slice = CLAMP(slice, slice_min, slice_max);
}

/*
 * Main logic to select an idle CPU for a task that wants to run.
 *
 * Return the CPU id if an idle CPU is found, -ENOENT otherwise.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct bpf_cpumask *llc_domain, *llc_mask;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	s32 cpu;

	/*
	 * If the task isn't allowed to use its previously used CPU it means
	 * that it's changing affinity. In this case try to pick any random
	 * idle CPU in its new allowed CPU domain.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		return scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is still idle.
	 */
	if (p->nr_cpus_allowed == 1 || p->migration_disabled) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		return -EBUSY;
	}

	/*
	 * Task scheduling domain.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	llc_mask = tctx->llc_cpumask;
	if (!llc_mask) {
		scx_bpf_error("task LLC cpumask not initialized");
		return -EINVAL;
	}

	/*
	 * Read system's idle CPU masks to determine the optimal task's
	 * scheduling domain.
	 */
	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();

	/*
	 * CPU scheduling domain.
	 */
	cctx = try_lookup_cpu_ctx(prev_cpu);
	if (!cctx) {
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	llc_domain = cctx->llc_cpumask;
	if (!llc_domain) {
		scx_bpf_error("CPU LLC cpumask not initialized");
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	/*
	 * Determine the task scheduling domain intersecting its usable CPUs
	 * with the subset of CPUs in the same LLC domain of the previously
	 * used CPU: this allows to keep the task running on the same LLC
	 * domain, as long as there are idle CPUs available.
	 */
	bpf_cpumask_and(llc_mask, p->cpus_ptr, cast_mask(llc_domain));

	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *current = (void *)bpf_get_current_task_btf();
		bool share_llc, has_idle;

		/*
		 * Determine waker CPU scheduling domain.
		 */
		cpu = bpf_get_smp_processor_id();

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx) {
			cpu = -EINVAL;
			goto out_put_cpumask;
		}

		llc_domain = cctx->llc_cpumask;
		if (!llc_domain) {
			scx_bpf_error("CPU LLC cpumask not initialized");
			cpu = -EINVAL;
			goto out_put_cpumask;
		}

		/*
		 * If both the waker and wakee share the same LLC keep using
		 * the same CPU if possible.
		 */
		share_llc = bpf_cpumask_test_cpu(prev_cpu, cast_mask(llc_domain));
		if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * If the waker's domain is not saturated attempt to migrate
		 * the wakee on the same CPU as the waker.
		 */
		has_idle = bpf_cpumask_intersects(cast_mask(llc_domain), idle_cpumask);
		if (has_idle &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    !(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0)
			goto out_put_cpumask;
	}

	if (smt_enabled) {
		/*
		 * Try to re-use the same CPU if it's a full-idle SMT core.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * Otherwise, search for a full-idle SMT core in the same LLC
		 * domain.
		 */
		cpu = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), idle_smtmask);
		if (cpu >= 0 && cpu < nr_cpu_ids &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;

		/*
		 * Otherwise, search for a full-idle SMT core in the system.
		 */
		cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_smtmask);
		if (cpu >= 0 && cpu < nr_cpu_ids &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * Try to re-use the same CPU (independently on the SMT state).
	 */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	/*
	 * Otherwise, try to use a CPU in the same LLC domain (independently on
	 * the SMT state).
	 */
	cpu = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), idle_cpumask);
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * Otherwise, try to use any idle CPU in the system (independently on
	 * the SMT state).
	 */
	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_cpumask);
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * No idle CPU usable by the task has been found.
	 */
	cpu = -EBUSY;

out_put_cpumask:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	scx_bpf_put_idle_cpumask(idle_cpumask);

	return cpu;
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(fair_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Wake up an idle CPU for task @p.
 */
static void kick_task_cpu(struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);

	cpu = pick_idle_cpu(p, cpu, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, 0);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(fair_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu;

	/*
	 * Per-CPU kthreads are critical for system responsiveness so make sure
	 * they are dispatched before any other task.
	 *
	 * If local_kthread is specified dispatch all kthreads directly.
	 */
	if (is_kthread(p) && (local_kthreads || p->nr_cpus_allowed == 1)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				 enq_flags | SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	/*
	 * Enqueue the task to the global DSQ. The task will be dispatched on
	 * the first CPU that becomes available.
	 */
	scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL,
			       task_vtime(p), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * If there is an idle CPU available for the task, wake it up so it can
	 * consume the task immediately.
	 */
	kick_task_cpu(p);
}

void BPF_STRUCT_OPS(fair_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_consume(SHARED_DSQ))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		task_refill_slice(prev);
}

/*
 * Scale target CPU frequency based on the performance level selected
 * from user-space and the CPU utilization.
 */
static void update_cpuperf_target(struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	/*
	 * For non-interactive tasks determine their cpufreq scaling factor as
	 * a function of their CPU utilization.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_running;
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);

	/*
	 * Apply the dynamic cpuperf scaling factor.
	 */
	scx_bpf_cpuperf_set(cpu, perf_lvl);

	cctx->last_running = bpf_ktime_get_ns();
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(fair_running, struct task_struct *p)
{
	/*
	 * Refresh task's time slice immediately before it starts to run on its
	 * assigned CPU.
	 */
	task_refill_slice(p);

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpuperf_target(p);
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(fair_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice, delta_t;
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->tot_runtime += now - cctx->last_running;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * If the time slice is not fully depleted, it means that the task
	 * voluntarily relased the CPU, therefore update the voluntary context
	 * switch counter.
	 *
	 * NOTE: the sched_ext core implements sched_yield() by setting the
	 * time slice to 0, so we won't boost the priority of tasks that are
	 * explicitly calling sched_yield().
	 *
	 * This is actually a good thing, because we want to prioritize tasks
	 * that are releasing the CPU, because they're doing I/O, waiting for
	 * input or sending output to other tasks.
	 *
	 * Tasks that are using sched_yield() don't really need the priority
	 * boost and when they get the chance to run again they will be
	 * naturally prioritized by the vruntime-based scheduling policy.
	 */
	if (p->scx.slice > 0)
		tctx->nvcsw++;

	/*
	 * Evaluate task's used time slice.
	 */
	slice = CLAMP(p->se.sum_exec_runtime - tctx->sum_exec_runtime, slice_min, slice_max);
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;
	slice = scale_inverse_fair(p, slice);

	/*
	 * Update task's vruntime by adding the used time slice, scaled by its
	 * priority.
	 */
	p->scx.dsq_vtime += slice;

	/*
	 * Update global system vruntime.
	 */
	vtime_now += slice;

	/*
	 * Update task's average rate of voluntary context switches per second.
	 */
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (delta_t > NSEC_PER_SEC) {
		/*
		 * Evaluate the task's latency weight as the task's average
		 * rate of voluntary context switches per second.
		 */
		u64 avg_nvcsw = tctx->nvcsw * NSEC_PER_SEC / delta_t;
		u64 lat_weight = MIN(avg_nvcsw, MAX_LATENCY_WEIGHT);

		tctx->nvcsw = 0;
		tctx->nvcsw_ts = now;
		tctx->lat_weight = calc_avg(tctx->lat_weight, lat_weight);
	}
}

void BPF_STRUCT_OPS(fair_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	p->scx.dsq_vtime = vtime_now;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_error("incorrectly initialized task: %d (%s)",
			      p->pid, p->comm);
		return;
	}
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;
	tctx->nvcsw_ts = bpf_ktime_get_ns();
}

s32 BPF_STRUCT_OPS(fair_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	/*
	 * Create task's LLC cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->llc_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 */
	mask = *cpumask;
	if (mask)
		return 0;
	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
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

	/* Make sure the target CPU mask is initialized */
	pmask = &cctx->llc_cpumask;
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

s32 BPF_STRUCT_OPS_SLEEPABLE(fair_init)
{
	int err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create the shared DSQ.
	 *
	 * Allocate the new DSQ id to not clash with any valid CPU id.
	 */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(fair_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(fair_ops,
	       .select_cpu		= (void *)fair_select_cpu,
	       .enqueue			= (void *)fair_enqueue,
	       .dispatch		= (void *)fair_dispatch,
	       .running			= (void *)fair_running,
	       .stopping		= (void *)fair_stopping,
	       .enable			= (void *)fair_enable,
	       .init_task		= (void *)fair_init_task,
	       .init			= (void *)fair_init,
	       .exit			= (void *)fair_exit,
	       .timeout_ms		= 5000,
	       .name			= "fair");
