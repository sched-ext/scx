// SPDX-License-Identifier: GPL-2.0
/*
 * Task ordering for the flow scheduler.
 *
 * Every task carries a virtual time that advances with the CPU time it
 * consumes, scaled by the inverse of its weight and by how long it has been
 * computing without a break. The system virtual time follows the tasks
 * that run in short bursts. A task that sleeps a lot falls behind it and
 * gets a bounded credit when it wakes up, while a task that keeps the CPU
 * busy runs ahead of it, by a bounded amount, and therefore behind
 * everybody that waited.
 *
 * The deadline of a task is its virtual time plus an offset: a full slice
 * plus the length of the current burst, divided by the latency criticality.
 * It keeps growing while a task runs without sleeping and stays tiny for
 * tasks that only run briefly before blocking again.
 *
 * Latency criticality rewards tasks that sleep often, wake up other tasks
 * often and run briefly once awake. Each factor goes through a binary
 * logarithm so that no single one dominates. A waker and its wakee share
 * part of their score, which keeps a producer and its consumers close.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H

#include "maps.bpf.h"

static __always_inline bool flow_is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline u64 flow_task_weight(const struct task_struct *p)
{
	u64 weight = p->scx.weight ?: FLOW_WEIGHT_DFLT;

	/* Kernel and I/O workers often sit on the critical path of user tasks. */
	if (p->flags & (PF_KTHREAD | PF_WQ_WORKER | PF_IO_WORKER))
		weight += weight >> 1;
	return flow_min(weight, FLOW_WEIGHT_MAX);
}


static __always_inline u32 flow_log2_u64(u64 v)
{
	u32 r = 0;

	if (v >= 1ULL << 32) {
		v >>= 32;
		r += 32;
	}
	if (v >= 1ULL << 16) {
		v >>= 16;
		r += 16;
	}
	if (v >= 1ULL << 8) {
		v >>= 8;
		r += 8;
	}
	if (v >= 1ULL << 4) {
		v >>= 4;
		r += 4;
	}
	if (v >= 1ULL << 2) {
		v >>= 2;
		r += 2;
	}
	if (v >= 1ULL << 1)
		r += 1;
	return r;
}

/* Moving average with a 1/8 gain. A zero sample leaves the average alone. */
static __always_inline u64 flow_calc_avg(u64 old, u64 sample)
{
	if (!sample)
		return old;
	if (!old)
		return sample;
	return old - (old >> 3) + (sample >> 3);
}

/* Fold the interval between two events into an event rate in Hz. */
static __always_inline u64 flow_calc_avg_freq(u64 old_freq, u64 interval_ns)
{
	u64 freq;

	if (!interval_ns)
		return old_freq;
	freq = FLOW_NSEC_PER_SEC / interval_ns;
	if (!old_freq)
		return freq;
	return old_freq - (old_freq >> 3) + (freq >> 3);
}

/*
 * Virtual time charged to @p for @ran of CPU time, when it has been running
 * for @acc since it last woke up. A burst that fits in a boosted slice is
 * charged at the weight of the task. Beyond that, the charge grows by one
 * multiple of the runtime each time the burst roughly doubles, so a task
 * that keeps a CPU busy without ever sleeping steadily loses ground to
 * tasks that do sleep, while tasks that all behave that way still share
 * the CPUs evenly.
 */
static __always_inline u64 flow_charge(const struct task_struct *p, u64 ran, u64 acc)
{
	u64 scale = 1 + flow_log2_u64(acc / FLOW_SLICE_BOOST_MAX_NS + 1);

	return ran * FLOW_WEIGHT_DFLT / flow_task_weight(p) * scale;
}

/*
 * Expected length of the current burst: the average of completed bursts,
 * or what the task already ran since it woke up if that is longer.
 */
static __always_inline u64 flow_burst(const struct flow_task_ctx *t)
{
	return flow_max(t->avg_runtime_ns, t->acc_runtime_ns);
}

static u32 flow_calc_lat_cri(const struct task_struct *p, const struct flow_task_ctx *t)
{
	u64 burst = flow_burst(t);
	u64 wait = t->wait_freq, wake = t->wake_freq, runtime_ft, inherit;
	u32 lat_cri;

	/* A task that ran for T without sleeping sleeps at most 1/T times a second. */
	if (t->acc_runtime_ns)
		wait = flow_min(wait, FLOW_NSEC_PER_SEC / t->acc_runtime_ns);
	wait = flow_min(wait, FLOW_FREQ_MAX) + 1;
	wake = flow_min(wake, FLOW_FREQ_MAX) + 1;

	runtime_ft = 1;
	if (burst < FLOW_RUNTIME_MAX_NS)
		runtime_ft += (FLOW_RUNTIME_MAX_NS - burst) / FLOW_SLICE_MIN_NS;

	/* The two logarithms add up to less than 64, so the square fits easily. */
	lat_cri = flow_log2_u64(wait * wake) + flow_log2_u64(runtime_ft * flow_task_weight(p));
	lat_cri = lat_cri * lat_cri ?: 1;

	/* Inherit at most a quarter of the own score from the wake chain. */
	inherit = flow_max(t->lat_cri_waker, t->lat_cri_wakee) >> 3;
	lat_cri += flow_min(inherit, lat_cri >> 2);

	if (t->flags & FLOW_FLAG_SYNC_WAKEUP)
		lat_cri += 2;
	if (t->flags & (FLOW_FLAG_HARDIRQ_WAKEUP | FLOW_FLAG_SOFTIRQ_WAKEUP))
		lat_cri += 2;
	if (flow_is_pinned(p))
		lat_cri += 1;
	return lat_cri;
}

/* Deadline of a task at virtual time @vtime that has run for @acc since waking up. */
static __always_inline u64 flow_deadline(const struct flow_task_ctx *t, u64 vtime, u64 acc)
{
	u64 runtime = FLOW_SLICE_MAX_NS + flow_min(acc, FLOW_BURST_MAX_NS);

	return vtime + runtime / t->lat_cri;
}

/*
 * Refresh the latency criticality of @p, which uses up what it inherited
 * from its last wakeup, keep its virtual time within FLOW_VTIME_LAG_NS of
 * the system virtual time and return its deadline. The lower bound caps
 * the credit of a task that slept, the upper bound caps how far a task
 * that kept computing can fall behind the others.
 */
static u64 flow_score_task(const struct task_struct *p, struct flow_task_ctx *t)
{
	u64 vtime_now = READ_ONCE(flow_clock.vtime_now);

	t->lat_cri = flow_calc_lat_cri(p, t);
	t->lat_cri_waker = 0;
	t->lat_cri_wakee = 0;
	if (time_before(t->vtime, vtime_now - FLOW_VTIME_LAG_NS))
		t->vtime = vtime_now - FLOW_VTIME_LAG_NS;
	else if (time_after(t->vtime, vtime_now + FLOW_VTIME_LAG_NS))
		t->vtime = vtime_now + FLOW_VTIME_LAG_NS;
	return flow_deadline(t, t->vtime, t->acc_runtime_ns);
}

/*
 * The base slice spreads the targeted latency over the waiting tasks. A
 * task whose bursts outlast it but still end within the boost limit gets
 * its whole burst instead, while the system has spare CPUs and no pinned
 * task waits for @cpu. A task that never stops is not boosted.
 */
static u64 flow_calc_slice(const struct flow_task_ctx *t, s32 cpu)
{
	u64 base = READ_ONCE(flow_sys_stat.slice_ns);
	u64 burst = flow_burst(t);

	if (!flow_cpu_valid(cpu))
		return base;
	if (burst >= base && burst < FLOW_SLICE_BOOST_MAX_NS &&
	    READ_ONCE(flow_sys_stat.nr_queued) <= flow_nr_cpus &&
	    !READ_ONCE(flow_cpu_states[cpu].nr_pinned))
		return flow_min(burst + FLOW_SLICE_MIN_NS, FLOW_SLICE_BOOST_MAX_NS);
	return base;
}

/*
 * When a task that has run for @acc since waking up and now gets @slice is
 * expected to stop: at the end of a typical burst, or at the end of the
 * slice once it is past that.
 */
static __always_inline u64 flow_est_stop(const struct flow_task_ctx *t, u64 acc, u64 slice,
					 u64 now)
{
	u64 avg = t->avg_runtime_ns;

	return now + (avg > acc ? flow_min(avg - acc, slice) : slice);
}

#endif /* __FLOW_FAIR_BPF_H */
