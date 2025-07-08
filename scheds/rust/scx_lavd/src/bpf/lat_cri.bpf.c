/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

static u64 calc_weight_factor(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_boost = 1;

	/*
	 * Prioritize a wake-up task since this is a clear sign of immediate
	 * consumer. If it is a synchronous wakeup, double the prioritization.
	 */
	weight_boost += taskc->wakeup_ft * LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a kernel task since many kernel tasks serve
	 * latency-critical jobs.
	 */
	if (is_kernel_task(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Further prioritize kworkers.
	 */
	if (is_kernel_worker(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize an affinitized task since it has restrictions
	 * in placement so it tends to be delayed.
	 */
	if (taskc->is_affinitized)
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a pinned task since it has restrictions in placement
	 * so it tends to be delayed.
	 */
	if (is_pinned(p) || is_migration_disabled(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST;

	/*
	 * Prioritize a lock holder for faster system-wide forward progress.
	 */
	if (taskc->need_lock_boost) {
		taskc->need_lock_boost = false;
		weight_boost += LAVD_LC_WEIGHT_BOOST;
	}

	/*
	 * Respect nice priority.
	 */
	return p->scx.weight * weight_boost + 1;
}

static u64 calc_wait_factor(struct task_ctx *taskc)
{
	u64 freq = min(taskc->wait_freq, LAVD_LC_FREQ_MAX);
	return freq + 1;
}

static u64 calc_wake_factor(struct task_ctx *taskc)
{
	u64 freq = min(taskc->wake_freq, LAVD_LC_FREQ_MAX);
	return freq + 1;
}

static inline u64 calc_runtime_factor(struct task_ctx *taskc)
{
	u64 ft = 1, delta;

	if (LAVD_LC_RUNTIME_MAX > taskc->avg_runtime) {
		delta = LAVD_LC_RUNTIME_MAX - taskc->avg_runtime;
		return delta / LAVD_SLICE_MIN_NS_DFL;
	}
	return ft;
}

static u64 calc_sum_runtime_factor(struct task_struct *p, struct task_ctx *taskc)
{
	u64 sum = max(taskc->run_freq, 1) * max(taskc->avg_runtime, 1);
	return (sum >> LAVD_SHIFT) * p->scx.weight;
}

static void calc_lat_cri(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_ft, wait_ft, wake_ft, runtime_ft, sum_runtime_ft;
	u64 log_wwf, lat_cri, perf_cri = LAVD_SCALE;

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * (i.e., wait_freq and wake_freq) are higher, and its runtime is
	 * shorter.
	 */
	wait_ft = calc_wait_factor(taskc);
	wake_ft = calc_wake_factor(taskc);
	runtime_ft = calc_runtime_factor(taskc);

	/*
	 * Adjust task's weight based on the scheduling context, such as
	 * if it is a kernel task, lock holder, etc.
	 */
	weight_ft = calc_weight_factor(p, taskc);

	/*
	 * Wake frequency and wait frequency represent how much a task is used
	 * for a producer and a consumer, respectively. If both are high, the
	 * task is in the middle of a task chain. The ratio tends to follow an
	 * exponentially skewed distribution, so we linearize it using sqrt.
	 */
	log_wwf = log2_u64(wait_ft * wake_ft);
	lat_cri = log_wwf + log2_u64(runtime_ft * weight_ft);

	/*
	 * Amplify the task's latency criticality to better differentiate
	 * between latency-critical vs. non-latency-critical tasks.
	 */
	lat_cri = lat_cri * lat_cri;

	/*
	 * Determine latency criticality of a task in a context-aware manner by
	 * considering which task wakes up this task. If its waker is more
	 * latency-critcial, inherit waker's latency criticality partially.
	 */
	if (taskc->lat_cri_waker > lat_cri) {
		lat_cri += (taskc->lat_cri_waker - lat_cri) >>
			   LAVD_LC_INHERIT_SHIFT;
	}
	taskc->lat_cri = lat_cri;

	/*
	 * A task is more CPU-performance sensitive when it meets the following
	 * conditions:
	 *
	 * - It is in the middle of the task graph (high wait and wake
	 *   frequencies).
	 * - Its runtime and frequency are high;
	 * - Its nice priority is high;
	 *
	 * We use the log-ed value since the raw value follows the highly
	 * skewed distribution.
	 *
	 * Note that we use unadjusted weight to reflect the pure task priority.
	 */
	if (have_little_core) {
		sum_runtime_ft = calc_sum_runtime_factor(p, taskc);
		perf_cri = log_wwf + log2_u64(sum_runtime_ft);
	}
	taskc->perf_cri = perf_cri;
}

static u32 calc_greedy_ratio(struct task_ctx *taskc)
{
	u32 ratio;

	/*
	 * The greedy ratio of a task represents how much time the task
	 * overspent CPU time compared to the ideal, fair CPU allocation. It is
	 * the ratio of task's actual service time to average service time in a
	 * system.
	 */
	ratio = (taskc->svc_time << LAVD_SHIFT) / sys_stat.avg_svc_time;
	taskc->is_greedy = ratio > LAVD_SCALE;
	return ratio;
}

static u32 calc_greedy_factor(u32 greedy_ratio)
{
	u32 ft = LAVD_SCALE;

	/*
	 * For all under-utilized tasks, we treat them equally.
	 * For over-utilized tasks, we give some mild penalty.
	 */
	if (greedy_ratio > LAVD_SCALE)
		ft += (greedy_ratio - LAVD_SCALE) >> LAVD_LC_GREEDY_SHIFT;
	return ft;
}

static u64 calc_adjusted_runtime(struct task_ctx *taskc)
{
	u64 runtime;

	/*
	 * Prefer a short-running (avg_runtime) and recently woken-up
	 * (acc_runtime) task. To avoid the starvation of CPU-bound tasks,
	 * which rarely sleep, limit the impact of acc_runtime.
	 */
	runtime = LAVD_ACC_RUNTIME_MAX +
		  min(taskc->acc_runtime, LAVD_ACC_RUNTIME_MAX);

	return runtime;
}

static u64 calc_virtual_deadline_delta(struct task_struct *p,
				       struct task_ctx *taskc)
{
	u64 deadline, adjusted_runtime;
	u32 greedy_ratio, greedy_ft;

	/*
	 * Calculate the deadline based on runtime,
	 * latency criticality, and greedy ratio.
	 */
	calc_lat_cri(p, taskc);
	greedy_ratio = calc_greedy_ratio(taskc);
	greedy_ft = calc_greedy_factor(greedy_ratio);
	adjusted_runtime = calc_adjusted_runtime(taskc);

	deadline = (adjusted_runtime * greedy_ft) / taskc->lat_cri;
	return deadline >> LAVD_SHIFT;
}

static u64 calc_when_to_run(struct task_struct *p, struct task_ctx *taskc)
{
	u64 dl_delta, clc;

	/*
	 * Before enqueueing a task to a run queue, we should decide when a
	 * task should be scheduled. We start from -LAVD_DL_COMPETE_WINDOW
	 * so that the current task can compete against the already enqueued
	 * tasks within [-LAVD_DL_COMPETE_WINDOW, 0].
	 */
	dl_delta = calc_virtual_deadline_delta(p, taskc);
	clc = READ_ONCE(cur_logical_clk) - LAVD_DL_COMPETE_WINDOW;
	return clc + dl_delta;
}
