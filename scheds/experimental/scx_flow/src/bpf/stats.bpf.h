// SPDX-License-Identifier: GPL-2.0
/*
 * System-wide statistics of the flow scheduler.
 *
 * The hot paths only add samples to the state of their own CPU. A timer
 * folds those samples every period into the values the policy reads: the
 * queue length, the base slice and the latency criticality a task needs to
 * preempt another one. The timer also lowers the performance target of
 * CPUs that were idle for a whole period, and moves the system virtual
 * time on when nothing else does while tasks wait. With --helicoprion,
 * every tenth run also closes the cgroup period that the busy tasks count
 * into, and decides from it whether cgroups compete for the CPUs. With
 * --performance, it also tells which CPUs have been busy lately, and the
 * tasks in the strands of the LLCs count as queued, see helix.bpf.h. The
 * timer only looks at the online CPUs, since the scheduler is loaded again
 * whenever a CPU comes or goes.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STATS_BPF_H
#define __FLOW_STATS_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "helix.bpf.h"

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
	u64	idled;
	u64	llc_nr_queued[FLOW_MAX_LLCS];
};

static struct flow_period flow_period;

/* Runs of the timer since the cgroup period began. */
static u32 flow_stat_runs;

/* The system virtual time at the last run of the timer. */
static u64 flow_stat_vtime;

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
	u64 slice = (u64)FLOW_TARGETED_LATENCY_NS * flow_nr_usable / flow_max(nr_queued, 1);

	if (slice < FLOW_SLICE_MIN_NS)
		return FLOW_SLICE_MIN_NS;
	if (slice > FLOW_SLICE_MAX_NS)
		return FLOW_SLICE_MAX_NS;
	return slice;
}

/*
 * Only tasks close to the most latency critical ones may preempt. The bar
 * sits 1/2^FLOW_PREEMPT_SHIFT of the way down from the highest score of
 * recent periods toward the average score. With --performance, it sits
 * halfway, so that the many threads a game wakes up for each frame can
 * push aside the tasks that compute next to them.
 */
static void flow_update_lat_cri(u64 avg_lat, u64 max_lat)
{
	u64 avg = flow_calc_avg(READ_ONCE(flow_sys_stat.avg_lat_cri), avg_lat);
	u64 max = flow_calc_avg(READ_ONCE(flow_sys_stat.max_lat_cri), max_lat);
	u32 shift = flow_performance ? FLOW_PERF_PREEMPT_SHIFT : FLOW_PREEMPT_SHIFT;

	WRITE_ONCE(flow_sys_stat.avg_lat_cri, avg);
	WRITE_ONCE(flow_sys_stat.max_lat_cri, max);
	WRITE_ONCE(flow_sys_stat.thr_lat_cri,
		   max > avg ? max - ((max - avg) >> shift) : max);
}

/*
 * With --performance, keep a running average of the share of each period
 * in which the CPU of @cs had a task to run, with a gain of 1/8, where
 * FLOW_UTIL_ONE stands for the whole period. The CPU counts as busy once
 * the average reaches FLOW_UTIL_BUSY and until it drops below
 * FLOW_UTIL_IDLE, so that it does not flip between the two with every
 * frame of a game. Userspace keeps the busy CPUs out of the idle states
 * that take time to leave, see pmqos.rs. @idle_start is when the CPU last
 * ran out of work, zero if it has a task now.
 */
static void flow_track_busy(struct flow_cpu_state *cs, u64 idle_start, u64 now)
{
	u64 idle = READ_ONCE(cs->idle_ns), idled, busy;
	u32 util;

	if (idle_start && time_after(now, idle_start))
		idle += now - idle_start;
	/* An ops.running() between the two reads above makes idle smaller than last time. */
	idled = time_after(idle, cs->idle_seen) ? idle - cs->idle_seen : 0;
	cs->idle_seen = idle;
	busy = FLOW_STAT_INTERVAL_NS - flow_min(idled, FLOW_STAT_INTERVAL_NS);

	util = cs->util - (cs->util >> 3) + ((busy * FLOW_UTIL_ONE / FLOW_STAT_INTERVAL_NS) >> 3);
	cs->util = util;
	if (util >= FLOW_UTIL_BUSY)
		WRITE_ONCE(cs->shallow, 1);
	else if (util < FLOW_UTIL_IDLE)
		WRITE_ONCE(cs->shallow, 0);
}

/*
 * Fold the samples of @cpu into flow_period and lower its performance
 * target if it was idle for a whole period.
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

	/* A CPU idle since an earlier period counts as idle, though it did not go idle again. */
	if (flow_helicoprion) {
		u32 idled = __atomic_exchange_n(&cs->idled, 0, __ATOMIC_RELAXED);
		bool idle = READ_ONCE(cs->idle_start_clk);

		flow_period.idled |= idled || idle;
		WRITE_ONCE(cs->busy, !idled && !idle);
	}

	q = scx_bpf_dsq_nr_queued(FLOW_CPU_DSQ_BASE + cpu);
	flow_period.llc_nr_queued[flow_llc_of(cpu)] += q;
	flow_period.nr_queued += q;

	idle_start = READ_ONCE(cs->idle_start_clk);
	if (flow_performance)
		flow_track_busy(cs, idle_start, now);
	if (idle_start && now - idle_start >= FLOW_STAT_INTERVAL_NS &&
	    READ_ONCE(cs->cpuperf_cur) != FLOW_CPUPERF_IDLE && flow_cpu_runs_idle(cpu))
		flow_cpuperf_commit(cpu, cs, FLOW_CPUPERF_IDLE, now);
	return 0;
}

/*
 * Start a new cgroup period. The tasks scale their charges by the counts
 * of the period that just ended, and the cgroups compete during the new
 * period if busy tasks of at least two of them outnumbered the CPUs in it.
 */
static void flow_roll_cgrp_period(void)
{
	u32 nr_busy = __atomic_exchange_n(&flow_cgrp_stat.nr_busy, 0, __ATOMIC_RELAXED);
	u32 nr_groups = __atomic_exchange_n(&flow_cgrp_stat.nr_groups, 0, __ATOMIC_RELAXED);

	WRITE_ONCE(flow_cgrp_stat.nr_busy_prev, nr_busy);
	WRITE_ONCE(flow_cgrp_stat.weight_sum_prev,
		   __atomic_exchange_n(&flow_cgrp_stat.weight_sum, 0, __ATOMIC_RELAXED));
	WRITE_ONCE(flow_cgrp_stat.active, nr_groups >= 2 && nr_busy > flow_nr_usable);
	WRITE_ONCE(flow_cgrp_stat.period, flow_cgrp_stat.period + 1);
}

/*
 * The system virtual time only follows the tasks that run in short bursts.
 * When only tasks that compute without a break are left, it stops, and a
 * task whose deadline lies far ahead of it, such as one at nice 19, never
 * comes first. While tasks wait, a period in which it did not move pushes
 * it forward by the length of the period.
 */
static void flow_unfreeze_vtime(u64 nr_queued)
{
	u64 vtime = READ_ONCE(flow_clock.vtime_now);

	if (vtime == flow_stat_vtime && nr_queued)
		flow_advance_vtime_now(vtime + FLOW_STAT_INTERVAL_NS);
	flow_stat_vtime = READ_ONCE(flow_clock.vtime_now);
}

static int flow_stat_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = flow_now();
	s32 ret;
	u32 i;

	__builtin_memset(&flow_period, 0, sizeof(flow_period));

	bpf_for(i, 0, flow_nr_usable) {
		if (i >= FLOW_MAX_CPUS)
			break;
		flow_sample_cpu(flow_cpu_ids[i], now);
	}

	bpf_for(i, 0, flow_nr_llcs) {
		u64 q;

		if (i >= FLOW_MAX_LLCS)
			break;
		q = scx_bpf_dsq_nr_queued(FLOW_LLC_DSQ_BASE + i) + flow_helix_queued(i);
		WRITE_ONCE(flow_llc_nr_queued[i], flow_period.llc_nr_queued[i] + q);
		flow_period.nr_queued += q;
	}
	flow_period.nr_queued += scx_bpf_dsq_nr_queued(FLOW_FALLBACK_DSQ);

	if (flow_period.nr_sched)
		flow_update_lat_cri(flow_period.sum_lat_cri / flow_period.nr_sched,
				    flow_period.max_lat_cri);
	WRITE_ONCE(flow_sys_stat.nr_queued, flow_period.nr_queued);
	if (flow_helicoprion) {
		WRITE_ONCE(flow_sys_stat.saturated, flow_period.nr_queued && !flow_period.idled);
		if (++flow_stat_runs >= FLOW_CGRP_PERIOD_RUNS) {
			flow_stat_runs = 0;
			flow_roll_cgrp_period();
		}
	}
	WRITE_ONCE(flow_sys_stat.slice_ns, flow_calc_base_slice(flow_period.nr_queued));
	flow_unfreeze_vtime(flow_period.nr_queued);

	ret = bpf_timer_start(timer, FLOW_STAT_INTERVAL_NS, 0);
	if (ret)
		scx_bpf_error("failed to restart the stat timer (%d)", ret);
	return 0;
}

#endif /* __FLOW_STATS_BPF_H */
