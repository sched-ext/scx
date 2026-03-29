/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

#define MAX_VTIME	(~0ULL)

#define CGROUP_WEIGHT_DFL	100

#define CONFIG_HZ		1000

#define MAX_WAKEUP_FREQ		100

/*
 * Return the time interval between two ticks in ns.
 */
static inline u64 tick_interval_ns(void)
{
	return NSEC_PER_SEC / CONFIG_HZ;
}

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/* Enable round-robin mode */
const volatile bool rr_sched;

/* Primary domain includes all CPU */
const volatile bool primary_all = true;

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 700ULL * NSEC_PER_USEC;

/*
 * Maximum runtime budget that a task can accumulate while sleeping (used
 * to determine the task's minimum vruntime).
 */
const volatile u64 slice_lag = 20ULL * NSEC_PER_MSEC;

/*
 * Adjust the maximum sleep budget in function of the average CPU
 * utilization.
 */
const volatile bool slice_lag_scaling;

/*
 * Enable tickless mode.
 */
const volatile bool tickless_sched;

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
volatile u64 nr_running;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids;

/*
 * Runtime throttling.
 *
 * Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
 */
const volatile u64 throttle_ns;
static volatile bool cpus_throttled;

static inline bool is_throttled(void)
{
	if (!throttle_ns)
		return false;

	return READ_ONCE(cpus_throttled);
}

static inline void set_throttled(bool state)
{
	WRITE_ONCE(cpus_throttled, state);
}

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Mask of CPUs that the scheduler can use until the system becomes saturated,
 * at which point tasks may overflow to other available CPUs.
 */
private(FLASH) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Disable NUMA optimizations.
 */
const volatile bool numa_disabled = false;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Timer used to update NUMA statistics.
 */
struct numa_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct numa_timer);
} numa_timer SEC(".maps");

/*
 * Timer used to inject idle cycles when CPU throttling is enabled.
 */
struct throttle_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct throttle_timer);
} throttle_timer SEC(".maps");

/*
 * Timer used to preempt CPUs in tickless mode.
 */
struct tickless_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tickless_timer);
} tickless_timer SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	u64 perf_lvl;
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
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Timestamp when the task started to run on a CPU (used to
	 * evaluate the consumed time slice).
	 */
	u64 last_run_at;

	/*
	 * Task wakeup frequency.
	 */
	u64 wakeup_freq;
	u64 last_woke_at;

	/*
	 * cgroup weight (cpu.weight).
	 */
	u32 cgweight;
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
 * Per-cgroup context: tracks the cgroup's cpu.weight.
 */
struct cgrp_ctx {
	u32 weight;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

/*
 * Return a local cgroup context from a generic task.
 */
struct cgrp_ctx *try_lookup_cgrp_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return the effective weight of a task, incorporating its cgroup weight.
 *
 * The effective weight is:
 *   task_nice_weight * cgroup_weight / CGROUP_WEIGHT_DFL
 *
 * This ensures tasks in a cgroup with weight 200 get twice the CPU time of
 * tasks in a cgroup with the default weight (100).
 */
static u64 task_weight(const struct task_struct *p)
{
	struct task_ctx *tctx;
	u32 cgw;

	tctx = try_lookup_task_ctx(p);
	cgw = tctx ? tctx->cgweight : CGROUP_WEIGHT_DFL;

	return (u64)p->scx.weight * cgw / CGROUP_WEIGHT_DFL;
}

static inline u64 scale_by_weight(const struct task_struct *p, u64 value)
{
	return value * task_weight(p) / CGROUP_WEIGHT_DFL;
}

static inline u64 scale_by_weight_inverse(const struct task_struct *p, u64 value)
{
	u64 w = task_weight(p);

	return w ? value * CGROUP_WEIGHT_DFL / w : value;
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
 * Return the total amount of tasks that are currently waiting to be scheduled.
 */
static inline u64 nr_tasks_waiting(s32 cpu)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	return scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) +
	       scx_bpf_dsq_nr_queued(node);
}

/*
 * Return the time slice that can be assigned to a task.
 */
static inline u64 task_slice(const struct task_struct *p)
{
	return tickless_sched ? SCX_SLICE_INF :
				scale_by_weight(p, slice_max);
}

/*
 * Return task deadline in function of the accumulated vruntime, limiting
 * the maximum amount of credit a task can accumulate while sleeping to
 * prevent starvation.
 *
 * The amount of time budget accumulated while tasks are sleeping is
 * inversely proportional to the accumulated runtime (in this way tasks
 * that sleep frequently accumulate less runtime and they also have a
 * larger budget).
 */
static u64 task_dl(struct task_struct *p, int node, struct task_ctx *tctx, u64 enq_flags)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 vsleep_max = scale_by_weight(p, slice_lag * lag_scale);
	u64 vtime_min = vtime_now - vsleep_max;
	u64 vtime = p->scx.dsq_vtime;

	if (enq_flags & SCX_ENQ_REENQ)
		return vtime;

	if (time_before(vtime, vtime_min))
		vtime = vtime_min;

	return vtime;
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
	const struct cpumask *primary;
	s32 cpu;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	/*
	 * Compatibility with older kernels (< v6.14).
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		if (wake_flags)
			return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, is_idle);

		return prev_cpu;
	}

	/*
	 * Don't trust user-space about waker releasing the CPU: if it
	 * doesn't, we may have latency issues, so it's safer to just
	 * ignore the hint.
	 */
	wake_flags &= ~SCX_WAKE_SYNC;

	cpu = primary_all ? -ENOENT :
			scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary, 0);
	if (cpu < 0) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
		if (cpu < 0)
			return prev_cpu;
	}
	*is_idle = true;

	return cpu;
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(flash_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	if (is_throttled())
		return prev_cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (rr_sched || is_idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
}

/*
 * Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (numa_disabled)
		return scx_bpf_get_idle_cpumask();

	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return the SMT sibling of @cpu, or @cpu if SMT is disabled.
 */
static inline s32 smt_sibling(s32 cpu)
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
 * Return true if @cpu is in  a partially-idle SMT core, false otherwise.
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
 * Return true if @p is running on a primary CPU (or can't run on a primary
 * CPU due to affinity constraints), false otherwise.
 */
static bool is_primary_cpu(const struct task_struct *p, s32 cpu)
{
	if (!primary_all) {
		const struct cpumask *primary = cast_mask(primary_cpumask);

		if (primary && bpf_cpumask_intersects(primary, p->cpus_ptr) &&
		    !bpf_cpumask_test_cpu(cpu, primary))
			return false;
	}

	return true;
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 enq_flags, bool is_running)
{
	bool is_idle = false;
	s32 cpu = prev_cpu;

	/*
	 * If throttling is enabled always dispatch critical kernel threads
	 * directly to prevent throttling the entire system.
         */
	if (throttle_ns > 0 && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		if (!is_running)
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);

		return true;
	}

	/*
	 * Skip direct dispatch if the CPUs are forced to stay idle.
	 */
	if (is_throttled())
		return false;

	/*
	 * Skip direct dispatch if ops.select_cpu() was already called, as
	 * the task has already had an opportunity for direct dispatch
	 * there.
	 */
	if (!is_running && __COMPAT_is_enq_cpu_selected(enq_flags))
		return false;

	/*
	 * Attempt migration if possible.
	 */
	if (!is_pcpu_task(p)) {
		/*
		 * In task is running in the primary domain, its SMT
		 * sibling is not contended or it has not been re-enqueued,
		 * keep it on the same CPU.
		 */
		if (!(enq_flags & SCX_ENQ_REENQ) &&
		    is_primary_cpu(p, cpu) && !is_smt_contended(cpu))
			return false;

		/*
		 * Try to pick an idle CPU close to the one the task is
		 * using.
		 */
		cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
		if (!is_idle)
			return false;
	} else {
		if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return false;
	}

	/*
	 * Attempt direct dispatch.
	 */
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), 0);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

	if (cpu != prev_cpu || !is_running)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return true;
}

/*
 * Enqueue a task when running in round-robin mode.
 */
static void rr_enqueue(struct task_struct *p, struct task_ctx *tctx,
		       s32 prev_cpu, u64 enq_flags)
{
	bool is_idle;
	s32 cpu;

	/*
	 * Attempt to migrate on another CPU on wakeup or if the task has
	 * been re-enqueued due to a higher priority class stealing the
	 * CPU, otherwise always prefer running on the same CPU.
	 */
	if (!scx_bpf_task_running(p) || (enq_flags & SCX_ENQ_REENQ)) {
		if (is_pcpu_task(p)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
				scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		} else {
			cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
			if (is_idle) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
						   task_slice(p), enq_flags);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				return;
			}
		}
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(flash_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	bool is_running = scx_bpf_task_running(p);

	/*
	 * Dispatch regular tasks to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Keep reusing the same CPU in round-robin mode.
	 */
	if (rr_sched) {
		rr_enqueue(p, tctx, prev_cpu, enq_flags);
		return;
	}

	/*
	 * Try to dispatch the task directly, if possible.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags, is_running))
		return;

	/*
	 * Try to keep running tasks on the same CPU using the per-CPU DSQ
	 * and use the per-node DSQ for tasks that are waking up, so they
	 * can be consumed in the first CPU available.
	 */
	scx_bpf_dsq_insert_vtime(p, node, task_slice(p),
				 task_dl(p, node, tctx, enq_flags), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	if (!is_running && !__COMPAT_is_enq_cpu_selected(enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Return true if the task can keep running on its current CPU, false if
 * the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);

	/* Do not keep running if the task doesn't need to run */
	if (!is_queued(p))
		return false;

	/*
	 * Do not keep running if the CPU is not in the primary domain and
	 * the task can use the primary domain.
	 */
	if (primary && bpf_cpumask_intersects(primary, p->cpus_ptr) &&
	    !bpf_cpumask_test_cpu(cpu, primary))
		return false;

	return true;
}

void BPF_STRUCT_OPS(flash_dispatch, s32 cpu, struct task_struct *prev)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);
	bool need_running = prev && keep_running(prev, cpu);

	/*
	 * Let the CPU go idle if the system is throttled.
	 */
	if (is_throttled())
		return;

	if (need_running) {
		struct task_ctx *tctx = try_lookup_task_ctx(prev);
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node);
		u64 q_vtime = q ? q->scx.dsq_vtime : ULLONG_MAX;

		if (tctx) {
			u64 slice = bpf_ktime_get_ns() - tctx->last_run_at;
			u64 prev_vtime = prev->scx.dsq_vtime +
					 scale_by_weight_inverse(prev, slice);

			if (prev_vtime < q_vtime) {
				prev->scx.slice = task_slice(prev);
				return;
			}
		}
	}

	if (scx_bpf_dsq_move_to_local(node, 0))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (need_running)
		prev->scx.slice = task_slice(prev);
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
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, struct task_ctx *tctx)
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
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);

	/*
	 * Use a moving average to evaluate the target performance level,
	 * giving more priority to the current average, so that we can
	 * react faster at CPU load variations and at the same time smooth
	 * the short spikes.
	 */
	cctx->perf_lvl = calc_avg(perf_lvl, cctx->perf_lvl);

	/*
	 * Refresh the dynamic cpuperf scaling factor if needed.
	 *
	 * Apply hysteresis to the scaling factor:
	 *  - if utilization is above the high threshold, bump to max;
	 *  - if it's below the low threshold, scale down to half capacity;
	 *  - otherwise, maintain the smoothed perf level.
	 */
	if (cpufreq_perf_lvl < 0) {
		if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
			perf_lvl = SCX_CPUPERF_ONE;
		else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
			perf_lvl = SCX_CPUPERF_ONE / 2;
		else
			perf_lvl = cctx->perf_lvl;
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(flash_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	if (cpufreq_perf_lvl < 0)
		update_cpu_load(p, tctx);

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (!rr_sched && time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(flash_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice;
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	if (!rr_sched) {
		tctx = try_lookup_task_ctx(p);
		if (!tctx)
			return;

		/*
		 * Evaluate the time slice used by the task.
		 */
		slice = now - tctx->last_run_at;

		/*
		 * Update task's vruntime and accumulated runtime.
		 */
		p->scx.dsq_vtime += scale_by_weight_inverse(p, slice);
	}

	/*
	 * Update CPU runtime.
	 */
	if (cpufreq_perf_lvl < 0) {
		struct cpu_ctx *cctx;

		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx)
			cctx->tot_runtime += now - cctx->last_running;
	}
}

void BPF_STRUCT_OPS(flash_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	if (rr_sched)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Update the task's wakeup frequency based on the time since
	 * the last wakeup, then cap the result at 1024 to avoid large
	 * spikes.
	 */
	delta_t = now - tctx->last_woke_at;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(flash_enable, struct task_struct *p)
{
	if (rr_sched)
		return;

	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(flash_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;

	cgc->weight = args->weight;

	return 0;
}

void BPF_STRUCT_OPS(flash_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;

	cgc = try_lookup_cgrp_ctx(cgrp);
	if (cgc)
		cgc->weight = weight;
}

void BPF_STRUCT_OPS(flash_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx;
	struct cgrp_ctx *cgc;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	cgc = try_lookup_cgrp_ctx(to);
	tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
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

s32 BPF_STRUCT_OPS(flash_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	if (args->cgroup) {
		struct cgrp_ctx *cgc = try_lookup_cgrp_ctx(args->cgroup);
		tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
	} else {
		tctx->cgweight = CGROUP_WEIGHT_DFL;
	}

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
	case 0:
		pmask = &cctx->smt;
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

/*
 * Initialize cpufreq performance level on all the online CPUs.
 */
static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for (cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		/* Set the initial cpufreq performance level  */
		if (cpufreq_perf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

/*
 * Tickless timer used to preempt CPUs.
 */
static int tickless_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	int err;

	/*
	 * Check if we need to preempt the running tasks.
	 */
	bpf_rcu_read_lock();
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct task_struct *p = __COMPAT_scx_bpf_cpu_curr(cpu);

		/*
		 * Ignore CPU if idle task is running.
		 */
		if (!p || p->flags & PF_IDLE)
			continue;

		/*
		 * Ignore CPUs without any task waiting.
		 */
		if (!nr_tasks_waiting(cpu))
			continue;

		/*
		 * Set a finite time slice to the running task, so that it
		 * can be preempted.
		 */
		if (p->scx.slice == SCX_SLICE_INF)
			p->scx.slice = task_slice(p);
	}
	bpf_rcu_read_unlock();

	err = bpf_timer_start(timer, tick_interval_ns(), 0);
	if (err)
		scx_bpf_error("Failed to re-arm tickless timer");

	return 0;
}

/*
 * Throttle timer used to inject idle time across all the CPUs.
 */
static int throttle_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bool throttled = is_throttled();
	u64 flags, duration;
	s32 cpu;
	int err;

	/*
	 * Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we
	 * need to interrupt the running tasks and inject the idle sleep.
	 *
	 * Otherwise, send a wakeup IPI to resume from the injected idle
	 * sleep.
	 */
	if (throttled) {
		flags = SCX_KICK_IDLE;
		duration = slice_max;
	} else {
		flags = SCX_KICK_PREEMPT;
		duration = throttle_ns;
	}

	/*
	 * Flip the throttled state.
	 */
	set_throttled(!throttled);

	bpf_for(cpu, 0, nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, flags);

	/*
	 * Re-arm the duty-cycle timer setting the runtime or the idle time
	 * duration.
	 */
	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flash_init)
{
	struct bpf_timer *timer;
	int err, node;
	u32 key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs and NUMA properties */
	init_cpuperf_target();

	/* Create per-node DSQs */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	timer = bpf_map_lookup_elem(&tickless_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup tickless timer");
		return -ESRCH;
	}

	/*
	 * Fire the tickless timer if tickless mode is enabled.
	 */
	if (tickless_sched) {
		bpf_timer_init(timer, &tickless_timer, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, tickless_timerfn);
		err = bpf_timer_start(timer, tick_interval_ns(), 0);
		if (err) {
			scx_bpf_error("Failed to arm tickless timer");
			return err;
		}
	}

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup throttle timer");
		return -ESRCH;
	}

	/*
	 * Fire the throttle timer if CPU throttling is enabled.
	 */
	if (throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_max, 0);
		if (err) {
			scx_bpf_error("Failed to arm throttle timer");
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(flash_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(flash_ops,
	       .select_cpu		= (void *)flash_select_cpu,
	       .enqueue			= (void *)flash_enqueue,
	       .dispatch		= (void *)flash_dispatch,
	       .running			= (void *)flash_running,
	       .stopping		= (void *)flash_stopping,
	       .runnable		= (void *)flash_runnable,
	       .enable			= (void *)flash_enable,
	       .cgroup_init		= (void *)flash_cgroup_init,
	       .cgroup_set_weight	= (void *)flash_cgroup_set_weight,
	       .cgroup_move		= (void *)flash_cgroup_move,
	       .init_task		= (void *)flash_init_task,
	       .init			= (void *)flash_init,
	       .exit			= (void *)flash_exit,
	       .timeout_ms		= 5000,
	       .name			= "flash");
