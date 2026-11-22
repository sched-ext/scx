// SPDX-License-Identifier: GPL-2.0
/*
 * System-wide statistics of the mlfq scheduler.
 *
 * The hot paths only add samples to the state of their own CPU. A timer
 * folds those samples every period into the values the policy reads: the
 * queue length, the base slice and the latency criticality a task needs to
 * preempt another one. The timer also lowers the performance target of
 * CPUs that stayed idle for a whole period.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __MLFQ_STATS_BPF_H
#define __MLFQ_STATS_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

enum mlfq_timer_clock {
	MLFQ_CLOCK_BOOTTIME	= 7,
};

/*
 * Samples gathered over one period. They live in global memory so that
 * the per-CPU pass is a separate function the verifier checks only once.
 */
struct mlfq_period {
	u64	sum_lat_cri;
	u64	nr_sched;
	u64	max_lat_cri;
	u64	nr_queued;
	u64	llc_nr_queued[MLFQ_MAX_LLCS];
};

static struct mlfq_period mlfq_period;

/*
 * Send a performance target for @cpu. Callers either hold the rq lock of
 * @cpu (ops.running() and ops.tick() on their own CPU) or hold no rq lock
 * at all (the timer), in which case the kernel takes the lock of @cpu.
 */
static __always_inline void mlfq_cpuperf_commit(s32 cpu, struct mlfq_cpu_state *cs,
						u32 perf, u64 now)
{
	scx_bpf_cpuperf_set(cpu, perf);
	WRITE_ONCE(cs->cpuperf_cur, perf);
	WRITE_ONCE(cs->cpuperf_commit_clk, now);
}

/*
 * Move the system virtual time up to @vtime. A compare-and-swap keeps it
 * from going backward when several CPUs update it at once.
 */
static void mlfq_advance_vtime_now(u64 vtime)
{
	u64 now = READ_ONCE(mlfq_clock.vtime_now);
	u32 i;

	bpf_for(i, 0, MLFQ_CLOCK_RETRIES) {
		u64 seen;

		if (!time_after(vtime, now))
			return;
		seen = __sync_val_compare_and_swap(&mlfq_clock.vtime_now, now, vtime);
		if (seen == now)
			return;
		now = seen;
	}
}

static bool mlfq_cpu_runs_idle(s32 cpu)
{
	struct task_struct *curr;
	bool idle;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	idle = curr && !curr->pid;
	bpf_rcu_read_unlock();
	return idle;
}

static u64 mlfq_calc_base_slice(u64 nr_queued)
{
	u64 slice = (u64)MLFQ_TARGETED_LATENCY_NS * mlfq_nr_cpus / mlfq_max(nr_queued, 1);

	if (slice < MLFQ_SLICE_MIN_NS)
		return MLFQ_SLICE_MIN_NS;
	if (slice > MLFQ_SLICE_MAX_NS)
		return MLFQ_SLICE_MAX_NS;
	return slice;
}

/*
 * Only tasks close to the most latency critical ones may preempt. The bar
 * sits 1/2^MLFQ_PREEMPT_SHIFT of the way down from the highest score of
 * recent periods toward the average score.
 */
static void mlfq_update_lat_cri(u64 avg_lat, u64 max_lat)
{
	u64 avg = mlfq_calc_avg(READ_ONCE(mlfq_sys_stat.avg_lat_cri), avg_lat);
	u64 max = mlfq_calc_avg(READ_ONCE(mlfq_sys_stat.max_lat_cri), max_lat);

	WRITE_ONCE(mlfq_sys_stat.avg_lat_cri, avg);
	WRITE_ONCE(mlfq_sys_stat.max_lat_cri, max);
	WRITE_ONCE(mlfq_sys_stat.thr_lat_cri,
		   max > avg ? max - ((max - avg) >> MLFQ_PREEMPT_SHIFT) : max);
}

/*
 * Fold the samples of @cpu into mlfq_period and lower its performance
 * target if it stayed idle for a whole period.
 */
__hidden int mlfq_sample_cpu(u32 cpu, u64 now)
{
	struct mlfq_cpu_state *cs;
	u64 idle_start, lat, q;

	if (cpu >= MLFQ_MAX_CPUS || cpu >= mlfq_nr_cpus)
		return 0;
	cs = &mlfq_cpu_states[cpu];

	mlfq_period.sum_lat_cri += __atomic_exchange_n(&cs->sum_lat_cri, 0, __ATOMIC_RELAXED);
	mlfq_period.nr_sched += __atomic_exchange_n(&cs->nr_sched, 0, __ATOMIC_RELAXED);
	lat = __atomic_exchange_n(&cs->max_lat_cri, 0, __ATOMIC_RELAXED);
	if (lat > mlfq_period.max_lat_cri)
		mlfq_period.max_lat_cri = lat;

	q = scx_bpf_dsq_nr_queued(MLFQ_CPU_DSQ_BASE + cpu);
	mlfq_period.llc_nr_queued[mlfq_llc_of(cpu)] += q;
	mlfq_period.nr_queued += q;

	idle_start = READ_ONCE(cs->idle_start_clk);
	if (idle_start && now - idle_start >= MLFQ_STAT_INTERVAL_NS &&
	    READ_ONCE(cs->cpuperf_cur) != MLFQ_CPUPERF_IDLE && mlfq_cpu_runs_idle(cpu))
		mlfq_cpuperf_commit(cpu, cs, MLFQ_CPUPERF_IDLE, now);
	return 0;
}

static int mlfq_stat_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = scx_bpf_now();
	u32 i;

	__builtin_memset(&mlfq_period, 0, sizeof(mlfq_period));

	bpf_for(i, 0, mlfq_nr_cpus)
		mlfq_sample_cpu(i, now);

	bpf_for(i, 0, mlfq_nr_llcs) {
		u64 q;

		if (i >= MLFQ_MAX_LLCS)
			break;
		q = scx_bpf_dsq_nr_queued(MLFQ_LLC_DSQ_BASE + i);
		WRITE_ONCE(mlfq_llc_nr_queued[i], mlfq_period.llc_nr_queued[i] + q);
		mlfq_period.nr_queued += q;
	}
	mlfq_period.nr_queued += scx_bpf_dsq_nr_queued(MLFQ_FALLBACK_DSQ);

	if (mlfq_period.nr_sched)
		mlfq_update_lat_cri(mlfq_period.sum_lat_cri / mlfq_period.nr_sched,
				    mlfq_period.max_lat_cri);
	WRITE_ONCE(mlfq_sys_stat.nr_queued, mlfq_period.nr_queued);
	WRITE_ONCE(mlfq_sys_stat.slice_ns, mlfq_calc_base_slice(mlfq_period.nr_queued));

	bpf_timer_start(timer, MLFQ_STAT_INTERVAL_NS, 0);
	return 0;
}

#endif /* __MLFQ_STATS_BPF_H */
