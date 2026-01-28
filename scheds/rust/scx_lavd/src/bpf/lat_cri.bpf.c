/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "power.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <lib/cgroup.h>


static u64 calc_weight_factor(struct task_struct *p, task_ctx *taskc)
{
	u64 weight_boost = 1;

	/*
	 * Prioritize a wake-up task since this is a clear sign of immediate
	 * consumer. If it is a synchronous wakeup, double the prioritization.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_IS_WAKEUP))
		weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;

	if (test_task_flag(taskc, LAVD_FLAG_IS_SYNC_WAKEUP))
		weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;

	/*
	 * Prioritize a task woken by a hardirq or softirq.
	 *   - hardirq: The top half of an interrupt processing (e.g., mouse
	 *     move, keypress, disk I/O completion, or GPU V-Sync) has just
	 *     been completed, and it hands off further processing to a fair
	 *     task. The task that was waiting for this specific hardware
	 *     signal gets the "Express Lane."
	 *
	 *   - softirq: The kernel just finished the bottom half of an
	 *     interrupt processing, like network packets and timers. If a
	 *     packet arrives for your Browser, or a timer expires for a
	 *     frame refresh, the task gets a "High" boost. This keeps the
	 *     data pipeline flowing smoothly.
	 *
	 * Note that the irq-boosted criticality will flow through the forward
	 * & backward propagation mechanism, which will be described below.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_WOKEN_BY_HARDIRQ)) {
		reset_task_flag(taskc, LAVD_FLAG_WOKEN_BY_HARDIRQ);
		weight_boost += LAVD_LC_WEIGHT_BOOST_HIGHEST;
	} else if (test_task_flag(taskc, LAVD_FLAG_WOKEN_BY_SOFTIRQ)) {
		reset_task_flag(taskc, LAVD_FLAG_WOKEN_BY_SOFTIRQ);
		weight_boost += LAVD_LC_WEIGHT_BOOST_HIGH;
	}

	/*
	 * Prioritize a task woken by an RT/DL task.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_WOKEN_BY_RT_DL)) {
		reset_task_flag(taskc, LAVD_FLAG_WOKEN_BY_RT_DL);
		weight_boost += LAVD_LC_WEIGHT_BOOST_HIGH;
	}

	/*
	 * Prioritize a kernel task since many kernel tasks serve
	 * latency-critical jobs.
	 */
	if (is_kernel_task(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST_MEDIUM;

	/*
	 * Further prioritize ksoftirqd.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_KSOFTIRQD))
		weight_boost += LAVD_LC_WEIGHT_BOOST_HIGH;

	/*
	 * Further prioritize kworkers.
	 */
	if (is_kernel_worker(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;

	/*
	 * Prioritize an affinitized task since it has restrictions
	 * in placement so it tends to be delayed.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_IS_AFFINITIZED))
		weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;

	/*
	 * Prioritize a pinned task since it has restrictions in placement
	 * so it tends to be delayed.
	 */
	if (is_pinned(p) || is_migration_disabled(p))
		weight_boost += LAVD_LC_WEIGHT_BOOST_MEDIUM;

	/*
	 * Prioritize a lock holder for faster system-wide forward progress.
	 */
	if (test_task_flag(taskc, LAVD_FLAG_NEED_LOCK_BOOST)) {
		reset_task_flag(taskc, LAVD_FLAG_NEED_LOCK_BOOST);
		weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;
	}

	/*
	 * Respect nice priority.
	 */
	return p->scx.weight * weight_boost + 1;
}

static u64 calc_wait_factor(task_ctx *taskc)
{
	u64 freq = min(taskc->wait_freq, LAVD_LC_FREQ_MAX);
	return freq + 1;
}

static u64 calc_wake_factor(task_ctx *taskc)
{
	u64 freq = min(taskc->wake_freq, LAVD_LC_FREQ_MAX);
	return freq + 1;
}

static inline u64 calc_reverse_runtime_factor(task_ctx *taskc)
{
	if (LAVD_LC_RUNTIME_MAX > taskc->avg_runtime) {
		u64 delta = LAVD_LC_RUNTIME_MAX - taskc->avg_runtime;
		return delta / LAVD_SLICE_MIN_NS_DFL;
	}
	return 1;
}

static u64 calc_sum_runtime_factor(struct task_struct *p, task_ctx *taskc)
{
	u64 runtime = max(taskc->avg_runtime, taskc->acc_runtime);
	u64 sum = max(taskc->run_freq, 1) * max(runtime, 1);
	return (sum >> LAVD_SHIFT) * p->scx.weight;
}

u32 __attribute__ ((noinline)) log2x(u64 v)
{
	return log2_u64(v);
}

static void calc_lat_cri(struct task_struct *p, task_ctx *taskc)
{
	u64 weight_ft, wait_ft, wake_ft, runtime_ft, sum_runtime_ft;
	u64 log_wwf, lat_cri, perf_cri = LAVD_SCALE, lat_cri_giver;

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * (i.e., wait_freq and wake_freq) are higher, and its runtime is
	 * shorter.
	 */
	wait_ft = calc_wait_factor(taskc);
	wake_ft = calc_wake_factor(taskc);
	runtime_ft = calc_reverse_runtime_factor(taskc);

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
	log_wwf = log2x(wait_ft * wake_ft);
	lat_cri = log_wwf + log2x(runtime_ft * weight_ft);

	/*
	 * Amplify the task's latency criticality to better differentiate
	 * between latency-critical vs. non-latency-critical tasks.
	 */
	lat_cri = lat_cri * lat_cri;

	/*
	 * Determine latency criticality of a task in a context-aware manner by
	 * considering its waker and wakee's latency criticality.
	 *
	 * Forward propagation is to keep the waker’s momentum forward to the
	 * wakee, and backward propagation is to boost the low-priority waker
	 * (i.e., priority inversion) for the next time. Propagation decays
	 * geometrically and is capped to a limit to prevent unlimited cyclic
	 * inflation of latency-criticality.
	 *
	 */
	lat_cri_giver = taskc->lat_cri_waker + taskc->lat_cri_wakee;
	if (lat_cri_giver > (2 * lat_cri)) {
		/*
		 * The amount of latency criticality inherited needs to be
		 * limited, so the task's latency criticality portion should
		 * always be a dominant factor.
		 */
		u64 giver_inh = (lat_cri_giver - (2 * lat_cri)) >>
				LAVD_LC_INH_GIVER_SHIFT;
		u64 receiver_max = lat_cri >> LAVD_LC_INH_RECEIVER_SHIFT;
		lat_cri += min(giver_inh, receiver_max);
	}
	taskc->lat_cri = lat_cri;
	taskc->lat_cri_waker = 0;
	taskc->lat_cri_wakee = 0;

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
		perf_cri = log_wwf + log2x(sum_runtime_ft);
	}
	taskc->perf_cri = perf_cri;
}

static u64 calc_greedy_penalty(struct task_struct *p, task_ctx *taskc)
{
	u64 lag_max, penalty;
	s64 lag;

	/*
	 * Calculate the task's lag -- the underserved time. Bound the lag
	 * into [-lag_max, +lag_max] and set the LAVD_FLAG_IS_GREEDY flag
	 * for preemption decision.
	 */
	lag = sys_stat.avg_svc_time - taskc->svc_time;
	lag_max = scale_by_task_weight_inverse(p, LAVD_TASK_LAG_MAX);
	if (lag >= 0) {
		reset_task_flag(taskc, LAVD_FLAG_IS_GREEDY);

		/*
		 * Limit the positive lag to lag_max. This prevents unbounded
		 * boost of long-sleepers.
		 */
		if (lag > lag_max) {
			taskc->svc_time = sys_stat.avg_svc_time - lag_max;
			lag = lag_max;
		}
	} else {
		set_task_flag(taskc, LAVD_FLAG_IS_GREEDY);

		/*
		 * Limit the negative lag to -lag_max to pay the debt
		 * gradually over time.
		 */
		if (lag < -lag_max)
			lag = -lag_max;
	}
	/* lag = [-lag_max, lag_max] */

	/*
	 * penalty = [100%, 125%]
	 */
	penalty = (((-lag + lag_max) << LAVD_SHIFT) / lag_max);
	penalty = LAVD_SCALE + (penalty >> LAVD_LC_GREEDY_SHIFT);
	return penalty;
}

static u64 calc_adjusted_runtime(task_ctx *taskc)
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
				       task_ctx *taskc)
{
	u64 deadline, adjusted_runtime;
	u32 greedy_penalty;

	/*
	 * Calculate the deadline based on runtime,
	 * latency criticality, and greedy ratio.
	 */
	calc_lat_cri(p, taskc);
	greedy_penalty = calc_greedy_penalty(p, taskc);
	adjusted_runtime = calc_adjusted_runtime(taskc);

	deadline = (adjusted_runtime * greedy_penalty) / taskc->lat_cri;
	return deadline >> LAVD_SHIFT;
}

__hidden
u64 calc_when_to_run(struct task_struct *p, task_ctx *taskc)
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
