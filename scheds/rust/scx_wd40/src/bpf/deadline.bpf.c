/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"
#include "deadline.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static u64 scale_up_fair(u64 value, u64 weight)
{
	return value * weight / 100;
}

static u64 scale_inverse_fair(u64 value, u64 weight)
{
	return value * 100 / weight;
}

/*
 * ** Taken directly from fair.c in the Linux kernel **
 *
 * We use this table to inversely scale deadline according to a task's
 * calculated latency factor. We preserve the comment directly from the table
 * in fair.c:
 *
 * "Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)"
 */
const int sched_prio_to_weight[DL_MAX_LAT_PRIO + 1] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

static __noinline u64 sched_prio_to_latency_weight(u64 prio)
{
	if (prio >= DL_MAX_LAT_PRIO) {
		scx_bpf_error("Invalid prio index");
		return 0;
	}

	return sched_prio_to_weight[DL_MAX_LAT_PRIO - prio - 1];
}

static u64 task_compute_dl(struct task_struct *p, task_ptr taskc,
			   u64 enq_flags)
{
	u64 waker_freq, blocked_freq;
	u64 lat_prio, lat_scale, avg_run_raw, avg_run;
	u64 freq_factor;

	/*
	 * Determine the latency criticality of a task, and scale a task's
	 * deadline accordingly. Much of this is inspired by the logic in
	 * scx_lavd that was originally conceived and implemented by Changwoo
	 * Min. Though the implementations for determining latency criticality
	 * are quite different in many ways, individuals familiar with both
	 * schedulers will feel an eerie sense of deja-vu. The details of
	 * interactivity boosting for wd40 are described below.
	 */

	/*
	 * We begin by calculating the following interactivity factors for a
	 * task:
	 *
	 * - waker_freq: The frequency with which a task wakes up other tasks.
	 *		 A high waker frequency generally implies a producer
	 *		 task that is at the beginning and/or middle of a work
	 *		 chain.
	 *
	 * - blocked_freq: The frequency with which a task is blocked. A high
	 *		   blocked frequency indicates a consumer task that is
	 *		   at the middle and/or end of a work chain.
	 *
	 * A task that is high in both frequencies indicates what is often the
	 * most latency-critical interactive task: a task that functions both
	 * as a producer and a consumer by being in the _middle_ of a work
	 * chain.
	 *
	 * We want to prioritize running these tasks, as they are likely to
	 * have a disproporionate impact on the latency (and possibly
	 * throughput) of the workload they are enabling due to Amdahl's law.
	 * For example, say that you have a workload where 50% of the workload
	 * is serialized by a producer and consumer task (25% each), and the
	 * latter 50% is serviced in parallel by n CPU hogging tasks. If either
	 * the producer or consumer is improved by a factor of x, it improves
	 * the latency of the entire workload by:
	 *
	 *	S_lat(x) = 1 / ((1 - .25) + (.25 / x))
	 *
	 * Say that we improve wakeup latency by 2x for either task, the
	 * latency improvement would be:
	 *
	 *	S_lat(2) = 1 / ((1 - .25) + (.25 / 2))
	 *		 = 1 / (.75 + .125)
	 *		 = 1 / .875
	 *		~= 14.2%
	 *
	 * If we instead improve wakeup latency by 2x for all the n parallel
	 * tasks in the latter 50% of the workload window, the improvement
	 * would be:
	 *
	 *	S_lat(2) = 1 / ((1 - .5) + (.5 / 2))
	 *		 = 1 / (.5 + .25)
	 *		 = 1 / .75
	 *		~= 33%
	 *
	 * This is also significant, but the returns are amortized across all
	 * of those tasks. Thus, by giving a latency boost to the producer /
	 * consumer tasks, we optimize for the case of scheduling tasks that
	 * are on the critical path for serial workchains, and have a
	 * disproportionate impact on the latency of a workload.
	 *
	 * We multiply the frequencies of wait_freq and waker_freq somewhat
	 * arbitrarily, based on observed performance for audio and gaming
	 * interactive workloads.
	 */
	waker_freq = min(taskc->waker_freq, DL_FREQ_FT_MAX);
	blocked_freq = min(taskc->blocked_freq, DL_FREQ_FT_MAX);
	freq_factor = blocked_freq * waker_freq * waker_freq;

	/*
	 * Scale the frequency factor according to the task's weight. A task
	 * with higher weight is given a higher frequency factor than a task
	 * with a lower weight.
	 */
	freq_factor = scale_up_fair(freq_factor, p->scx.weight);

	/*
	 * The above frequencies roughly follow an exponential distribution, so
	 * use log2_u64() to linearize it to a boost priority that we can then
	 * scale to a weight factor below.
	 */
	lat_prio = log2_u64(freq_factor + 1);
	lat_prio = min(lat_prio, DL_MAX_LAT_PRIO);

	/*
	 * Next calculate a task's average runtime, and apply it to deadline
	 * accordingly. A task with a large runtime is penalized from an
	 * interactivity standpoint, for obvious reasons.
	 *
	 * As with waker and blocked frequencies above, this follows an
	 * exponential distribution. We inversely scale to account for
	 * empirical observations which seem to bring it roughly to the same
	 * order of magnitude as the blocker and waker frequencies above.
	 *
	 * We inversely scale the task's averge_runtime to cause tasks with
	 * lower weight to receive a harsher penalty for long runtimes, and
	 * vice versa for tasks with lower weight.
	 */
	avg_run_raw = taskc->avg_runtime / DL_RUNTIME_SCALE;
	avg_run_raw = min(avg_run_raw, DL_MAX_LATENCY_NS);
	avg_run_raw = scale_inverse_fair(avg_run_raw, p->scx.weight);
	avg_run = log2_u64(avg_run_raw + 1);

	if (avg_run < lat_prio) {
		/* Equivalent to lat_prio = log(freq_factor / avg_run_raw) */
		lat_prio -= avg_run;
	} else {
		lat_prio = 0;
	}

	/*
	 * Ultimately, what we're trying to arrive at is a single value
	 * 'lat_prio' that we can use to compute the weight that we use to
	 * scale a task's average runtime as below.
	 *
	 * To summarize what we've done above, we compute this lat_prio as the
	 * sum of a task's frequency factor, minus an average runtime factor.
	 * Both factors are scaled according to a task's weight.
	 *
	 * Today, we're just interpreting lat_prio as a niceness value, but
	 * this can and almost certainly will likely change to something more
	 * generic and/or continuous and flexible so that it can also
	 * accommodate cgroups.
	 */
	lat_scale = sched_prio_to_latency_weight(lat_prio);
	lat_scale = min(lat_scale, LB_MAX_WEIGHT);

	/*
	 * Finally, with our 'lat_scale' weight, we compute the length of the
	 * task's request as:
	 *
	 * r_i = avg_runtime * 100 / lat_scale
	 *
	 * In other words, the "CPU request length" which is used to determine
	 * the actual absolute vtime that the task is dispatched with.
	 */
	return scale_inverse_fair(taskc->avg_runtime, lat_scale);
}



/*
 * Exponential weighted moving average
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

__hidden
u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq;

	new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

static void clamp_task_vtime(struct task_struct *p, task_ptr taskc, u64 enq_flags)
{
	u64 dom_vruntime, min_vruntime;
	dom_ptr domc;

	if (!(domc = taskc->domc))
		return;

	dom_vruntime = dom_min_vruntime(domc);
	min_vruntime = dom_vruntime - slice_ns;
	/*
	 * Allow an idling task to accumulate at most one slice worth of
	 * vruntime budget. This prevents e.g. a task for sleeping for 1 day,
	 * and then coming back and having essentially full use of the CPU for
	 * an entire day until it's caught up to the other tasks' vtimes.
	 */
	if (time_before(p->scx.dsq_vtime, min_vruntime)) {
		p->scx.dsq_vtime = min_vruntime;
		taskc->deadline = p->scx.dsq_vtime + task_compute_dl(p, taskc, enq_flags);
		stat_add(RUSTY_STAT_DL_CLAMP, 1);
	} else {
		stat_add(RUSTY_STAT_DL_PRESET, 1);
	}
}

__hidden
void place_task_dl(struct task_struct *p, task_ptr taskc,
			  u64 enq_flags)
{
	clamp_task_vtime(p, taskc, enq_flags);
	scx_bpf_dsq_insert_vtime(p, taskc->target_dom, slice_ns, taskc->deadline,
				 enq_flags);
}

__hidden
void init_vtime(struct task_struct *p, task_ptr taskc)
{
	taskc->deadline = p->scx.dsq_vtime +
			  scale_inverse_fair(taskc->avg_runtime, taskc->weight);
}

__hidden
void running_update_vtime(struct task_struct *p, task_ptr taskc)
{
	arena_lock_t lock;
	dom_ptr domc;
	int ret;

	if (!(domc = taskc->domc)) {
		scx_bpf_error("no domain for task");
		return;
	}

	if (!(lock = domc->vtime_lock))
		return;

	if ((ret = arena_spin_lock(lock))) {
		scx_bpf_error("spinlock error %d", ret);
		return;
	}

	if (time_before(dom_min_vruntime(domc), p->scx.dsq_vtime))
		WRITE_ONCE(domc->min_vruntime, p->scx.dsq_vtime);
	arena_spin_unlock(lock);

	taskc->last_run_at = scx_bpf_now();
}


__hidden
void stopping_update_vtime(struct task_struct *p)
{
	task_ptr taskc;
	u64 now, delta;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	now = scx_bpf_now();
	delta = now - taskc->last_run_at;

	taskc->sum_runtime += delta;
	taskc->avg_runtime = calc_avg(taskc->avg_runtime, taskc->sum_runtime);

	p->scx.dsq_vtime += scale_inverse_fair(delta, p->scx.weight);
	taskc->deadline = p->scx.dsq_vtime + task_compute_dl(p, taskc, 0);
}

