/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

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
	/*
	 * For all under-utilized tasks, we treat them equally.
	 */
	if (greedy_ratio <= LAVD_SCALE)
		return LAVD_SCALE;

	/*
	 * For over-utilized tasks, we give some mild penalty.
	 */
	return LAVD_SCALE + ((greedy_ratio - LAVD_SCALE) / LAVD_LC_GREEDY_PENALTY);
}

static inline u64 calc_runtime_factor(u64 runtime)
{
	return rsigmoid_u64(runtime, LAVD_LC_RUNTIME_MAX);
}

static inline u64 calc_freq_factor(u64 freq)
{
	return sigmoid_u64(freq, LAVD_LC_FREQ_MAX);
}

static u64 calc_weight_factor(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_boost = 1;
	u64 weight_ft;

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
	weight_ft = p->scx.weight * weight_boost;
	return weight_ft;
}

static void calc_perf_cri(struct task_struct *p, struct task_ctx *taskc)
{
	u64 wait_freq_ft, wake_freq_ft, perf_cri = LAVD_SCALE;

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
		wait_freq_ft = calc_freq_factor(taskc->wait_freq);
		wake_freq_ft = calc_freq_factor(taskc->wake_freq);
		perf_cri = log2_u64(wait_freq_ft * wake_freq_ft);
		perf_cri += log2_u64(max(taskc->run_freq, 1) *
				     max(taskc->avg_runtime, 1) * p->scx.weight);
	}

	taskc->perf_cri = perf_cri;
}

static void calc_lat_cri(struct task_struct *p, struct task_ctx *taskc)
{
	u64 weight_ft, wait_freq_ft, wake_freq_ft, runtime_ft;
	u64 lat_cri;

	/*
	 * Adjust task's weight based on the scheduling context, such as
	 * if it is a kernel task, lock holder, etc.
	 */
	weight_ft = calc_weight_factor(p, taskc);

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * (i.e., wait_freq and wake_freq) are higher.
	 *
	 * Since those frequencies are unbounded and their upper limits are
	 * unknown, we transform them using sigmoid-like functions. For wait
	 * and wake frequencies, we use a sigmoid function (sigmoid_u64), which
	 * is monotonically increasing since higher frequencies mean more
	 * latency-critical.
	 */
	wait_freq_ft = calc_freq_factor(taskc->wait_freq) + 1;
	wake_freq_ft = calc_freq_factor(taskc->wake_freq) + 1;
	runtime_ft = calc_runtime_factor(taskc->avg_runtime) + 1;

	/*
	 * Wake frequency and wait frequency represent how much a task is used
	 * for a producer and a consumer, respectively. If both are high, the
	 * task is in the middle of a task chain. The ratio tends to follow an
	 * exponentially skewed distribution, so we linearize it using log2. We
	 * add +1 to guarantee the latency criticality (log2-ed) is always
	 * positive.
	 */
	lat_cri = log2_u64(wait_freq_ft * wake_freq_ft) +
		  log2_u64(runtime_ft * weight_ft);

	/*
	 * Determine latency criticality of a task in a context-aware manner by
	 * considering which task wakes up this task. If its waker is more
	 * latency-critcial, inherit waker's latency criticality.
	 */
	taskc->lat_cri = max(lat_cri, taskc->lat_cri_waker);
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
	calc_perf_cri(p, taskc);
	calc_lat_cri(p, taskc);
	greedy_ratio = calc_greedy_ratio(taskc);
	greedy_ft = calc_greedy_factor(greedy_ratio);
	adjusted_runtime = calc_adjusted_runtime(taskc);

	deadline = (adjusted_runtime * greedy_ft) / taskc->lat_cri;

	return deadline;
}

static u64 calc_time_slice(struct task_ctx *taskc)
{
	if (!taskc)
		return LAVD_SLICE_MAX_NS_DFL;

	taskc->slice_ns = sys_stat.slice;
	return taskc->slice_ns;
}
