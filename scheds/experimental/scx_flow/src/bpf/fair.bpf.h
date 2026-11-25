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
 * It keeps growing while a task runs without sleeping and remains tiny for
 * tasks that only run briefly before blocking again.
 *
 * Latency criticality rewards tasks that sleep often, wake up other tasks
 * often and run briefly once awake. Each factor goes through a binary
 * logarithm so that no single one dominates. A waker and its wakee share
 * part of their score, which keeps a producer and its consumers close.
 *
 * With --helicoprion, the CPUs are shared between cgroups by their
 * cpu.weight while they compete, that is while busy tasks of at least two
 * cgroups outnumber the CPUs. Every 100 ms, a task counts as busy in its
 * cgroup if it was charged a maximum slice since it was last counted, so
 * tasks that mostly sleep do not make their cgroup look big. The charge of
 * a task is then scaled by a factor: a cgroup with more busy tasks than
 * its weight earns charges each of them more, one with fewer charges each
 * of them less, so that its busy tasks together get the share its weight
 * asks for. The charge then no longer grows with the length of the burst,
 * and tasks that compute for long move the system virtual time and may
 * run further ahead of it, as the clamp would otherwise even out the
 * factors. While the cgroups do not compete, the weights decide nothing
 * and the penalty for computing without a break applies as it does
 * without --helicoprion.
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

/* Most tasks may run anywhere, which spares a look at their CPU mask. */
static __always_inline bool flow_may_run_on(const struct task_struct *p, s32 cpu)
{
	return p->nr_cpus_allowed >= flow_nr_cpus || bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/*
 * @p, waiting in a shared queue, may be moved to @cpu. The CPU mask of a task
 * can lag behind a migration it has disabled, which is checked as well.
 */
static __always_inline bool flow_task_fits(const struct task_struct *p, s32 cpu)
{
	return flow_may_run_on(p, cpu) && !(is_migration_disabled(p) && scx_bpf_task_cpu(p) != cpu);
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

/* CPU time @t got in its current run, up to @now. */
static __always_inline u64 flow_ran(const struct flow_task_ctx *t, u64 now)
{
	return time_after(now, t->last_running_clk) ? now - t->last_running_clk : 0;
}

/* Charge @used of CPU time to @p, which continues its current burst. */
static __always_inline void flow_charge_run(const struct task_struct *p, struct flow_task_ctx *t,
					    u64 used)
{
	t->acc_runtime_ns += used;
	t->vtime += flow_charge(p, used, t->acc_runtime_ns);
}

/*
 * Once per cgroup period, count @p as a busy task of its cgroup if it was
 * charged at least FLOW_SLICE_MAX_NS since its last count, and work out by
 * how much its charge is scaled. A cgroup with n of the b busy tasks gets
 * n/b of the CPUs when every task is charged alike, but its weight w out
 * of the s that all busy cgroups add up to asks for w/s. Charging each of
 * its tasks n*s/(w*b) closes the gap. All the numbers come from the last
 * finished period, and the factor is one when any of them is missing.
 */
static __noinline void flow_refresh_cgrp(struct task_struct *p, struct flow_task_ctx *t)
{
	u32 period = READ_ONCE(flow_cgrp_stat.period);
	u64 b = READ_ONCE(flow_cgrp_stat.nr_busy_prev);
	u64 s = READ_ONCE(flow_cgrp_stat.weight_sum_prev);
	bool busy = t->busy_ns >= FLOW_SLICE_MAX_NS;
	u64 n = 0, w = 0, factor;
	struct flow_cgrp_ctx *cc;
	struct cgroup *cgrp;
	bool first = false;

	if (t->cgrp_period == period)
		return;
	t->cgrp_period = period;
	t->busy_ns = 0;
	t->cgrp_factor = FLOW_FACTOR_ONE;

	cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp)
		return;
	cc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (cc) {
		bpf_spin_lock(&cc->lock);
		if (cc->period != period) {
			cc->nr_busy_prev = cc->period + 1 == period ? cc->nr_busy : 0;
			cc->nr_busy = 0;
			cc->period = period;
		}
		if (busy)
			first = !cc->nr_busy++;
		n = cc->nr_busy_prev;
		w = cc->weight;
		bpf_spin_unlock(&cc->lock);
	}
	bpf_cgroup_release(cgrp);

	if (busy)
		__sync_fetch_and_add(&flow_cgrp_stat.nr_busy, 1);
	if (first) {
		__sync_fetch_and_add(&flow_cgrp_stat.nr_groups, 1);
		__sync_fetch_and_add(&flow_cgrp_stat.weight_sum, w);
	}

	if (!n || !w || !b || !s)
		return;
	factor = n * s * FLOW_FACTOR_ONE / (w * b);
	t->cgrp_factor = flow_min(flow_max(factor, FLOW_FACTOR_MIN), FLOW_FACTOR_MAX);
}

/*
 * Virtual time that @p is charged for @ran of CPU time while cgroups
 * compete: the weight of the task and the factor of its cgroup. The charge
 * does not grow with the length of the burst as flow_charge() does. That
 * growth outruns the clamp of flow_clamp_vtime(), which would put every
 * task that computes for a while at the upper end of it, whatever its
 * cgroup.
 */
static __always_inline u64 flow_charge_cgrp(const struct task_struct *p,
					    const struct flow_task_ctx *t, u64 ran)
{
	return (ran * FLOW_WEIGHT_DFLT / flow_task_weight(p) * t->cgrp_factor) >>
	       FLOW_FACTOR_SHIFT;
}

/*
 * Charge the CPU time that @p used since it was last charged. The kernel
 * accounts it exactly in sum_exec_runtime, so --helicoprion charges it
 * when the task wakes up or is queued again instead of every time it
 * stops running. While cgroups compete, the charge follows the cgroup of
 * the task, see flow_refresh_cgrp().
 */
static __always_inline void flow_charge_exec(struct task_struct *p, struct flow_task_ctx *t)
{
	u64 sum = p->se.sum_exec_runtime;
	u64 used = sum - t->sum_exec_ns;

	t->sum_exec_ns = sum;
	t->busy_ns += used;
	flow_refresh_cgrp(p, t);

	if (!flow_cgrp_active()) {
		flow_charge_run(p, t, used);
		return;
	}
	t->acc_runtime_ns += used;
	t->vtime += flow_charge_cgrp(p, t, used);
}

/*
 * @t went to sleep, which ends its burst. @now is when it went to sleep,
 * or with --helicoprion when it woke up again. Either comes once per
 * sleep, so the interval between two of them says how often it sleeps.
 */
static __always_inline void flow_end_burst(struct flow_task_ctx *t, u64 now)
{
	t->avg_runtime_ns = flow_calc_avg(t->avg_runtime_ns, t->acc_runtime_ns);
	if (t->last_quiescent_clk && time_after(now, t->last_quiescent_clk))
		t->wait_freq = flow_calc_avg_freq(t->wait_freq, now - t->last_quiescent_clk);
	t->last_quiescent_clk = now;
}

/* The task of @wt woke up the task of @t at @now. */
static __always_inline void flow_note_wakeup(struct flow_task_ctx *t, struct flow_task_ctx *wt,
					     u64 now)
{
	if (wt->last_wake_clk && time_after(now, wt->last_wake_clk))
		wt->wake_freq = flow_calc_avg_freq(wt->wake_freq, now - wt->last_wake_clk);
	wt->last_wake_clk = now;

	t->lat_cri_waker = wt->lat_cri;
	wt->lat_cri_wakee = t->lat_cri;
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
 * Keep the virtual time of @t within FLOW_VTIME_LAG_NS of the system
 * virtual time, or within FLOW_VTIME_LEAD_NS ahead of it while cgroups
 * compete. The lower bound caps the credit of a task that slept, the
 * upper bound caps how far a task that kept computing can fall behind the
 * others.
 */
static __always_inline void flow_clamp_vtime(struct flow_task_ctx *t)
{
	u64 vtime_now = READ_ONCE(flow_clock.vtime_now);
	u64 lead = flow_cgrp_active() ? FLOW_VTIME_LEAD_NS : FLOW_VTIME_LAG_NS;

	if (time_before(t->vtime, vtime_now - FLOW_VTIME_LAG_NS))
		t->vtime = vtime_now - FLOW_VTIME_LAG_NS;
	else if (time_after(t->vtime, vtime_now + lead))
		t->vtime = vtime_now + lead;
}

/*
 * Refresh the latency criticality of @p, which uses up what it inherited
 * from its last wakeup, keep its virtual time in range and return its
 * deadline.
 */
static u64 flow_score_task(const struct task_struct *p, struct flow_task_ctx *t)
{
	t->lat_cri = flow_calc_lat_cri(p, t);
	t->lat_cri_waker = 0;
	t->lat_cri_wakee = 0;
	flow_clamp_vtime(t);
	return flow_deadline(t, t->vtime, t->acc_runtime_ns);
}

/*
 * Deadline of @t when it takes over the CPU of the task it waits for at
 * @now, which can happen hundreds of thousands of times a second. Its
 * latency criticality moves slowly, so it is scored again at most every
 * FLOW_RESCORE_NS. Its virtual time is kept in range every time.
 */
static __always_inline u64 flow_handoff_deadline(const struct task_struct *p,
						 struct flow_task_ctx *t, u64 now)
{
	t->acc_runtime_ns = 0;
	if (now - t->score_clk < FLOW_RESCORE_NS) {
		flow_clamp_vtime(t);
		return flow_deadline(t, t->vtime, 0);
	}
	t->score_clk = now;
	return flow_score_task(p, t);
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
	    READ_ONCE(flow_sys_stat.nr_queued) <= flow_nr_usable &&
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
