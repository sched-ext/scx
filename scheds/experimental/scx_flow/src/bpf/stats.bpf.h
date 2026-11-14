// SPDX-License-Identifier: GPL-2.0
/*
 * System-wide statistics of the flow scheduler.
 *
 * The hot paths only add samples to the state of their own CPU. A timer
 * folds those samples every period into the values the policy reads: the
 * queue length, the base slice and the latency criticality a task needs to
 * preempt another one. The timer also lowers the performance target of
 * CPUs that stayed idle for a whole period.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STATS_BPF_H
#define __FLOW_STATS_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

enum flow_timer_clock {
	FLOW_CLOCK_BOOTTIME	= 7,
};

/*
 * Samples gathered over one period. They live in global memory so that
 * the per-CPU pass is a separate function the verifier checks only once.
 */
struct flow_period {
	u64	sum_lat_cri;
	u64	nr_sched;
	u64	max_lat_cri;
	u64	nr_queued;
	u64	llc_nr_queued[FLOW_MAX_LLCS];
};

static struct flow_period flow_period;

/*
 * Send a performance target for @cpu. Callers either hold the rq lock of
 * @cpu (ops.running() and ops.tick() on their own CPU) or hold no rq lock
 * at all (the timer), in which case the kernel takes the lock of @cpu.
 */
static __always_inline void flow_cpuperf_commit(s32 cpu, struct flow_cpu_state *cs,
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
static void flow_advance_vtime_now(u64 vtime)
{
	u64 now = READ_ONCE(flow_clock.vtime_now);
	u32 i;

	bpf_for(i, 0, FLOW_CLOCK_RETRIES) {
		u64 seen;

		if (!time_after(vtime, now))
			return;
		seen = __sync_val_compare_and_swap(&flow_clock.vtime_now, now, vtime);
		if (seen == now)
			return;
		now = seen;
	}
}

static bool flow_cpu_runs_idle(s32 cpu)
{
	struct task_struct *curr;
	bool idle;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	idle = curr && !curr->pid;
	bpf_rcu_read_unlock();
	return idle;
}

static u64 flow_calc_base_slice(u64 nr_queued)
{
	u64 slice = (u64)FLOW_TARGETED_LATENCY_NS * flow_nr_cpus / flow_max(nr_queued, 1);

	if (slice < FLOW_SLICE_MIN_NS)
		return FLOW_SLICE_MIN_NS;
	if (slice > FLOW_SLICE_MAX_NS)
		return FLOW_SLICE_MAX_NS;
	return slice;
}

/*
 * Only tasks close to the most latency critical ones may preempt. The bar
 * sits 1/2^FLOW_PREEMPT_SHIFT of the way down from the highest score of
 * recent periods toward the average score.
 */
static void flow_update_lat_cri(u64 avg_lat, u64 max_lat)
{
	u64 avg = flow_calc_avg(READ_ONCE(flow_sys_stat.avg_lat_cri), avg_lat);
	u64 max = flow_calc_avg(READ_ONCE(flow_sys_stat.max_lat_cri), max_lat);

	WRITE_ONCE(flow_sys_stat.avg_lat_cri, avg);
	WRITE_ONCE(flow_sys_stat.max_lat_cri, max);
	WRITE_ONCE(flow_sys_stat.thr_lat_cri,
		   max > avg ? max - ((max - avg) >> FLOW_PREEMPT_SHIFT) : max);
}

/*
 * Fold the samples of @cpu into flow_period and lower its performance
 * target if it stayed idle for a whole period.
 */
__hidden int flow_sample_cpu(u32 cpu, u64 now)
{
	struct flow_cpu_state *cs;
	u64 idle_start, lat, q;

	if (cpu >= FLOW_MAX_CPUS || cpu >= flow_nr_cpus)
		return 0;
	cs = &flow_cpu_states[cpu];

	flow_period.sum_lat_cri += __atomic_exchange_n(&cs->sum_lat_cri, 0, __ATOMIC_RELAXED);
	flow_period.nr_sched += __atomic_exchange_n(&cs->nr_sched, 0, __ATOMIC_RELAXED);
	lat = __atomic_exchange_n(&cs->max_lat_cri, 0, __ATOMIC_RELAXED);
	if (lat > flow_period.max_lat_cri)
		flow_period.max_lat_cri = lat;

	q = scx_bpf_dsq_nr_queued(FLOW_CPU_DSQ_BASE + cpu);
	flow_period.llc_nr_queued[flow_llc_of(cpu)] += q;
	flow_period.nr_queued += q;

	idle_start = READ_ONCE(cs->idle_start_clk);
	if (idle_start && now - idle_start >= FLOW_STAT_INTERVAL_NS &&
	    READ_ONCE(cs->cpuperf_cur) != FLOW_CPUPERF_IDLE && flow_cpu_runs_idle(cpu))
		flow_cpuperf_commit(cpu, cs, FLOW_CPUPERF_IDLE, now);
	return 0;
}

static int flow_stat_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = scx_bpf_now();
	u32 i;

	__builtin_memset(&flow_period, 0, sizeof(flow_period));

	bpf_for(i, 0, flow_nr_cpus)
		flow_sample_cpu(i, now);

	bpf_for(i, 0, flow_nr_llcs) {
		u64 q;

		if (i >= FLOW_MAX_LLCS)
			break;
		q = scx_bpf_dsq_nr_queued(FLOW_LLC_DSQ_BASE + i);
		WRITE_ONCE(flow_llc_nr_queued[i], flow_period.llc_nr_queued[i] + q);
		flow_period.nr_queued += q;
	}
	flow_period.nr_queued += scx_bpf_dsq_nr_queued(FLOW_FALLBACK_DSQ);

	if (flow_period.nr_sched)
		flow_update_lat_cri(flow_period.sum_lat_cri / flow_period.nr_sched,
				    flow_period.max_lat_cri);
	WRITE_ONCE(flow_sys_stat.nr_queued, flow_period.nr_queued);
	WRITE_ONCE(flow_sys_stat.slice_ns, flow_calc_base_slice(flow_period.nr_queued));

	bpf_timer_start(timer, FLOW_STAT_INTERVAL_NS, 0);
	return 0;
}

#endif /* __FLOW_STATS_BPF_H */
