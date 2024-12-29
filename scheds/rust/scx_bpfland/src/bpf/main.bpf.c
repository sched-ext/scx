/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Maximum task weight.
 */
#define MAX_TASK_WEIGHT		10000

/*
 * Maximum frequency of task wakeup events / sec.
 */
#define MAX_WAKEUP_FREQ		1024

/*
 * DSQ used to dispatch regular tasks.
 */
#define SHARED_DSQ		0

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_min = 1ULL * NSEC_PER_MSEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile s64 slice_lag = 20ULL * NSEC_PER_MSEC;

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
 * Maximum threshold of voluntary context switches.
 */
const volatile u64 nvcsw_max_thresh = 10ULL;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

/*
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running, nr_interactive;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Mask of CPUs that the scheduler can use until the system becomes saturated,
 * at which point tasks may overflow to other available CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *primary_cpumask;

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
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;
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
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;

	/*
	 * Voluntary context switches metrics.
	 */
	u64 nvcsw;
	u64 nvcsw_ts;
	u64 avg_nvcsw;

	/*
	 * Frequency with which a task is blocked (consumer).
	 */
	u64 blocked_freq;
	u64 last_blocked_at;

	/*
	 * Frequency with which a task wakes other tasks (producer).
	 */
	u64 waker_freq;
	u64 last_woke_at;

	/*
	 * Task's average used time slice.
	 */
	u64 sum_runtime;
	u64 last_run_at;

	/*
	 * Task's deadline.
	 */
	u64 deadline;

	/*
	 * Set to true if the task is classified as interactive.
	 */
	bool is_interactive;
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
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if the task can only run on its assigned CPU, false
 * otherwise.
 */
static bool is_migration_disabled(struct task_struct *p)
{
	if (bpf_core_field_exists(p->migration_disabled))
		return p->migration_disabled;
	return false;
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
 * Evaluate the EWMA limited to the range [low ... high]
 */
static u64 calc_avg_clamp(u64 old_val, u64 new_val, u64 low, u64 high)
{
	return CLAMP(calc_avg(old_val, new_val), low, high);
}

/*
 * Evaluate the average frequency of an event over time.
 */
static u64 update_freq(u64 freq, u64 delta)
{
	u64 new_freq;

	new_freq = NSEC_PER_SEC / delta;
	return calc_avg(freq, new_freq);
}

/*
 * Return the total amount of tasks that are currently waiting to be scheduled.
 */
static u64 nr_tasks_waiting(void)
{
	return scx_bpf_dsq_nr_queued(SHARED_DSQ) + 1;
}

/*
 * Return task's dynamic weight.
 */
static u64 task_weight(const struct task_struct *p, const struct task_ctx *tctx)
{
	/*
	 * Scale the static task weight by the average amount of voluntary
	 * context switches to determine the dynamic weight.
	 */
	u64 prio = p->scx.weight * CLAMP(tctx->avg_nvcsw, 1, nvcsw_max_thresh ? : 1);

	return CLAMP(prio, 1, MAX_TASK_WEIGHT);
}

/*
 * Return a value proportionally scaled to the task's priority.
 */
static u64 scale_up_fair(const struct task_struct *p,
			 const struct task_ctx *tctx, u64 value)
{
	return value * task_weight(p, tctx) / 100;
}

/*
 * Return a value inversely proportional to the task's priority.
 */
static u64 scale_inverse_fair(const struct task_struct *p,
			      const struct task_ctx *tctx, u64 value)
{
	return value * 100 / task_weight(p, tctx);
}

/*
 * Return the task's allowed lag: used to determine how early its vruntime can
 * be.
 */
static u64 task_lag(const struct task_struct *p, const struct task_ctx *tctx)
{
	return scale_up_fair(p, tctx, slice_lag);
}

/*
 * ** Taken directly from fair.c in the Linux kernel **
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
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

static u64 max_sched_prio(void)
{
	return ARRAY_SIZE(sched_prio_to_weight);
}

/*
 * Convert task priority to weight (following fair.c logic).
 */
static u64 sched_prio_to_latency_weight(u64 prio)
{
	u64 max_prio = max_sched_prio();

	if (prio >= max_prio) {
		scx_bpf_error("invalid priority");
		return 0;
	}

	return sched_prio_to_weight[max_prio - prio - 1];
}

/*
 * Evaluate task's deadline.
 *
 * Reuse a logic similar to scx_rusty or scx_lavd and evaluate the deadline as
 * a function of the waiting and wake-up events and the average task's runtime.
 */
static u64 task_deadline(struct task_struct *p, struct task_ctx *tctx)
{
	u64 waker_freq, blocked_freq;
	u64 lat_prio, lat_weight;
	u64 sum_run_scaled, sum_run;
	u64 freq_factor;

	/*
	 * Limit the wait and wake-up frequencies to prevent spikes.
	 */
	waker_freq = CLAMP(tctx->waker_freq, 1, MAX_WAKEUP_FREQ);
	blocked_freq = CLAMP(tctx->blocked_freq, 1, MAX_WAKEUP_FREQ);

	/*
	 * We want to prioritize producers (waker tasks) more than consumers
	 * (blocked tasks), using the following formula:
	 *
	 *   freq_factor = blocked_freq * waker_freq^2
	 *
	 * This seems to improve the overall responsiveness of
	 * producer/consumer pipelines.
	 */
	freq_factor = blocked_freq * waker_freq * waker_freq;

	/*
	 * Evaluate the "latency priority" as a function of the wake-up, block
	 * frequencies and average runtime, using the following formula:
	 *
	 *   lat_prio = log(freq_factor / sum_run_scaled)
	 *
	 * Frequencies can grow very quickly, almost exponential, so use
	 * log2_u64() to get a more linear metric that can be used as a
	 * priority.
	 *
	 * The sum_run_scaled component is used to scale the latency priority
	 * proportionally to the task's weight and inversely proportional to
	 * its runtime, so that a task with a higher weight / shorter runtime
	 * gets a higher latency priority than a task with a lower weight /
	 * higher runtime.
	 */
	sum_run_scaled = scale_inverse_fair(p, tctx, tctx->sum_runtime);
	sum_run = log2_u64(sum_run_scaled + 1);

	lat_prio = log2_u64(freq_factor);
	lat_prio = MIN(lat_prio, max_sched_prio());

	if (lat_prio >= sum_run)
		lat_prio -= sum_run;
	else
		lat_prio = 0;

	/*
	 * Lastly, translate the latency priority into a weight and apply it to
	 * the task's average runtime to determine the task's deadline.
	 */
	lat_weight = sched_prio_to_latency_weight(lat_prio);

	return tctx->sum_runtime * 100 / lat_weight;
}

/*
 * Return task's evaluated deadline applied to its vruntime.
 */
static u64 task_vtime(struct task_struct *p, struct task_ctx *tctx)
{
	u64 min_vruntime = vtime_now - task_lag(p, tctx);

	/*
	 * Limit the vruntime to to avoid excessively penalizing tasks.
	 */
	if (vtime_before(p->scx.dsq_vtime, min_vruntime))
		p->scx.dsq_vtime = min_vruntime;
	tctx->deadline = p->scx.dsq_vtime + scale_inverse_fair(p, tctx, tctx->sum_runtime);

	return tctx->deadline;
}

/*
 * Evaluate task's time slice in function of the total amount of tasks that are
 * waiting to be dispatched and the task's weight.
 */
static inline void task_refill_slice(struct task_struct *p)
{
	/*
	 * Scale the time slice of an inversely proportional factor of the
	 * total amount of tasks that are waiting.
	 */
	p->scx.slice = CLAMP(slice_max / nr_tasks_waiting(), slice_min, slice_max);
}

static void task_set_domain(struct task_struct *p, s32 cpu,
			    const struct cpumask *cpumask)
{
	struct bpf_cpumask *primary, *l2_domain, *l3_domain;
	struct bpf_cpumask *p_mask, *l2_mask, *l3_mask;
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	primary = primary_cpumask;
	if (!primary)
		return;

	l2_domain = cctx->l2_cpumask;
	if (!l2_domain)
		l2_domain = primary;

	l3_domain = cctx->l3_cpumask;
	if (!l3_domain)
		l3_domain = primary;

	p_mask = tctx->cpumask;
	if (!p_mask) {
		scx_bpf_error("cpumask not initialized");
		return;
	}

	l2_mask = tctx->l2_cpumask;
	if (!l2_mask) {
		scx_bpf_error("l2 cpumask not initialized");
		return;
	}

	l3_mask = tctx->l3_cpumask;
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		return;
	}

	/*
	 * Determine the task's scheduling domain.
	 * idle CPU, re-try again with the primary scheduling domain.
	 */
	bpf_cpumask_and(p_mask, cpumask, cast_mask(primary));

	/*
	 * Determine the L2 cache domain as the intersection of the task's
	 * primary cpumask and the L2 cache domain mask of the previously used
	 * CPU.
	 */
	bpf_cpumask_and(l2_mask, cast_mask(p_mask), cast_mask(l2_domain));

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));
}

static bool is_wake_sync(const struct task_struct *p,
			 const struct task_struct *current,
			 s32 prev_cpu, s32 cpu, u64 wake_flags)
{
	if (wake_flags & SCX_WAKE_SYNC)
		return true;

	/*
	 * If the current task is a per-CPU kthread running on the wakee's
	 * previous CPU, treat it as a synchronous wakeup.
	 *
	 * The assumption is that the wakee had queued work for the per-CPU
	 * kthread, which has now finished, making the wakeup effectively
	 * synchronous. An example of this behavior is seen in IO completions.
	 */
	if (is_kthread(current) && (p->nr_cpus_allowed == 1) &&
	    (prev_cpu == cpu))
		return true;

	return false;
}

/*
 * Find an idle CPU in the system.
 *
 * NOTE: the idle CPU selection doesn't need to be formally perfect, it is
 * totally fine to accept racy conditions and potentially make mistakes, by
 * picking CPUs that are not idle or even offline, the logic has been designed
 * to handle these mistakes in favor of a more efficient response and a reduced
 * scheduling overhead.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	const struct cpumask *primary, *p_mask, *l2_mask, *l3_mask;
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;
	bool is_prev_llc_affine = false;
	s32 cpu;

	*is_idle = false;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	/*
	 * Acquire the CPU masks to determine the idle CPUs in the system.
	 */
	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();

	/*
	 * Task's scheduling domains.
	 */
	p_mask = cast_mask(tctx->cpumask);
	if (!p_mask) {
		scx_bpf_error("cpumask not initialized");
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	l2_mask = cast_mask(tctx->l2_cpumask);
	if (!l2_mask) {
		scx_bpf_error("l2 cpumask not initialized");
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	l3_mask = cast_mask(tctx->l3_cpumask);
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	cpu = bpf_get_smp_processor_id();
	if (is_wake_sync(p, current, cpu, prev_cpu, wake_flags)) {
		const struct cpumask *curr_l3_domain;
		struct cpu_ctx *cctx;
		bool share_llc, has_idle;

		/*
		 * Determine waker CPU scheduling domain.
		 */
		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx) {
			cpu = -EINVAL;
			goto out_put_cpumask;
		}

		curr_l3_domain = cast_mask(cctx->l3_cpumask);
		if (!curr_l3_domain)
			curr_l3_domain = primary;

		/*
		 * If both the waker and wakee share the same L3 cache keep
		 * using the same CPU if possible.
		 */
		share_llc = bpf_cpumask_test_cpu(prev_cpu, curr_l3_domain);
		if (share_llc &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Migrate the wakee to the same domain as the waker in case of
		 * a sync wakeup.
		 */
		if (!share_llc)
			task_set_domain(p, cpu, p->cpus_ptr);

		/*
		 * If the waker's L3 domain is not saturated attempt to migrate
		 * the wakee on the same CPU as the waker (since it's going to
		 * block and release the current CPU).
		 */
		has_idle = bpf_cpumask_intersects(curr_l3_domain, idle_cpumask);
		if ((!nvcsw_max_thresh || has_idle) &&
		    bpf_cpumask_test_cpu(cpu, p_mask) &&
		    !(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Check if the previously used CPU is still in the L3 task domain. If
	 * not, we may want to move the task back to its original L3 domain.
	 */
	is_prev_llc_affine = bpf_cpumask_test_cpu(prev_cpu, l3_mask);

	/*
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (is_prev_llc_affine &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L2 cache.
		 */
		cpu = scx_bpf_pick_idle_cpu(l2_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L3 cache.
		 */
		cpu = scx_bpf_pick_idle_cpu(l3_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Search for any other full-idle core in the primary domain.
		 */
		cpu = scx_bpf_pick_idle_cpu(p_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * If a full-idle core can't be found (or if this is not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (is_prev_llc_affine &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L2 cache.
	 */
	cpu = scx_bpf_pick_idle_cpu(l2_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L3 cache.
	 */
	cpu = scx_bpf_pick_idle_cpu(l3_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the scheduling domain.
	 */
	cpu = scx_bpf_pick_idle_cpu(p_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * We couldn't find any idle CPU, return the previous CPU if it is in
	 * the task's L3 domain, otherwise pick any other CPU in the L3 domain.
	 */
	if (is_prev_llc_affine)
		cpu = prev_cpu;
	else
		cpu = scx_bpf_pick_any_cpu(l3_mask, 0);

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	/*
	 * If we couldn't find any CPU, or in case of error, return the
	 * previously used CPU.
	 */
	if (cpu < 0)
		cpu = prev_cpu;

	return cpu;
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 cpu;

	/*
	 * Per-CPU kthreads are critical for system responsiveness so make sure
	 * they are dispatched before any other task.
	 *
	 * If local_kthread is specified dispatch all kthreads directly.
	 */
	if (is_kthread(p) && (local_kthreads || p->nr_cpus_allowed == 1)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				   enq_flags | SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	if ((p->nr_cpus_allowed == 1) || is_migration_disabled(p)) {
		/*
		 * If nvcsw_max_thresh is disabled we don't care much about
		 * interactivity, so we can massively boost per-CPU tasks and
		 * always dispatch them directly on their CPU.
		 *
		 * This can help to improve I/O workloads (like large parallel
		 * builds).
		 */
		if (!nvcsw_max_thresh) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return;
		}
	}

	/*
	 * Dispatch regular tasks to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL,
				 task_vtime(p, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);

	/*
	 * Consume regular tasks from the shared DSQ, transferring them to the
	 * local CPU DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU (provided the CPU is in the primary scheduling
	 * domain).
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED) &&
	    primary && bpf_cpumask_test_cpu(cpu, primary))
		task_refill_slice(prev);
}

/*
 * Scale target CPU frequency based on the performance level selected
 * from user-space and the CPU utilization.
 */
static void update_cpuperf_target(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	if (cpufreq_perf_lvl >= 0) {
		/*
		 * Apply fixed cpuperf scaling factor determined by user-space.
		 */
		perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
		return;
	}

	/*
	 * Auto mode: always tset max performance for interactive tasks.
	 */
	if (tctx->is_interactive) {
		scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
		return;
	}

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
	perf_lvl = delta_runtime * SCX_CPUPERF_ONE / delta_t;

	/*
	 * If interactive tasks detection is disabled, always boost the
	 * frequency to make sure it's at least 50%, to prevent being too
	 * conservative.
	 */
	if (!nvcsw_max_thresh)
		perf_lvl += SCX_CPUPERF_ONE / 2;
	perf_lvl = MIN(perf_lvl, SCX_CPUPERF_ONE);

	/*
	 * Apply the dynamic cpuperf scaling factor.
	 */
	scx_bpf_cpuperf_set(cpu, perf_lvl);

	cctx->last_running = bpf_ktime_get_ns();
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	/*
	 * Refresh task's time slice immediately before it starts to run on its
	 * assigned CPU.
	 */
	task_refill_slice(p);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpuperf_target(p, tctx);

	/*
	 * Update CPU interactive state.
	 */
	if (tctx->is_interactive)
		__sync_fetch_and_add(&nr_interactive, 1);

	/*
	 * Update global vruntime.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice;
	s32 cpu = scx_bpf_task_cpu(p);
	s64 delta_t;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->tot_runtime += now - cctx->last_running;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->is_interactive)
		__sync_fetch_and_sub(&nr_interactive, 1);

	/*
	 * Update task's average runtime.
	 */
	slice = now - tctx->last_run_at;
	tctx->sum_runtime += slice;

	/*
	 * Update task vruntime charging the weighted used time slice.
	 */
	p->scx.dsq_vtime += scale_inverse_fair(p, tctx, slice);
	tctx->deadline = p->scx.dsq_vtime + task_deadline(p, tctx);

	if (!nvcsw_max_thresh)
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
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (delta_t > NSEC_PER_SEC) {
		u64 avg_nvcsw = tctx->nvcsw * NSEC_PER_SEC / delta_t;
		u64 max_nvcsw = nvcsw_max_thresh * 100;

		tctx->nvcsw = 0;
		tctx->nvcsw_ts = now;

		/*
		 * Evaluate the latency weight of the task as its average rate
		 * of voluntary context switches (limited to to prevent
		 * excessive spikes).
		 */
		tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, avg_nvcsw, 0, max_nvcsw);

		/*
		 * Classify the task based on the average of voluntary context
		 * switches.
		 *
		 * If the task has an average greater than the global average
		 * it is classified as interactive, otherwise the task is
		 * classified as regular.
		 */
		tctx->is_interactive = tctx->avg_nvcsw >= nvcsw_max_thresh;
	}
}

void BPF_STRUCT_OPS(bpfland_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta;
	struct task_struct *waker;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->sum_runtime = 0;

	waker = bpf_get_current_task_btf();
	tctx = try_lookup_task_ctx(waker);
	if (!tctx)
		return;

	delta = MAX(now - tctx->last_woke_at, 1);
	tctx->waker_freq = update_freq(tctx->waker_freq, delta);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(bpfland_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	delta = MAX(now - tctx->last_blocked_at, 1);
	tctx->blocked_freq = update_freq(tctx->blocked_freq, delta);
	tctx->last_blocked_at = now;
}

void BPF_STRUCT_OPS(bpfland_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();

	task_set_domain(p, cpu, cpumask);
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	/* Initialize task's vruntime */
	p->scx.dsq_vtime = vtime_now;

	/* Initialize voluntary context switch timestamp */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->nvcsw_ts = now;
	tctx->last_woke_at = now;
	tctx->last_blocked_at = now;

	tctx->deadline = p->scx.dsq_vtime + task_deadline(p, tctx);
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	/*
	 * Create task's primary cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	/*
	 * Create task's L2 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l2_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	/*
	 * Create task's L3 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	task_set_domain(p, cpu, p->cpus_ptr);

	return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
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
	switch (input->lvl_id) {
	case 2:
		pmask = &cctx->l2_cpumask;
		break;
	case 3:
		pmask = &cctx->l3_cpumask;
		break;
	default:
		return -EINVAL;
	}
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

SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/* Make sure the primary CPU mask is initialized */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;
	/*
	 * Enable the target CPU in the primary scheduling domain. If the
	 * target CPU is a negative value, clear the whole mask (this can be
	 * used to reset the primary domain).
	 */
	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask) {
		s32 cpu = input->cpu_id;

		if (cpu < 0)
			bpf_cpumask_clear(mask);
		else
			bpf_cpumask_set_cpu(cpu, mask);
	}
	bpf_rcu_read_unlock();

	return err;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	int err;

	/* Initialize amount of online CPUs */
	nr_online_cpus = get_nr_online_cpus();

	/*
	 * Create the global shared DSQ.
	 */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	return 0;
}

void BPF_STRUCT_OPS(bpfland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bpfland_ops,
	       .select_cpu		= (void *)bpfland_select_cpu,
	       .enqueue			= (void *)bpfland_enqueue,
	       .dispatch		= (void *)bpfland_dispatch,
	       .running			= (void *)bpfland_running,
	       .stopping		= (void *)bpfland_stopping,
	       .runnable		= (void *)bpfland_runnable,
	       .quiescent		= (void *)bpfland_quiescent,
	       .set_cpumask		= (void *)bpfland_set_cpumask,
	       .enable			= (void *)bpfland_enable,
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .flags			= SCX_OPS_ENQ_EXITING,
	       .timeout_ms		= 5000,
	       .name			= "bpfland");
