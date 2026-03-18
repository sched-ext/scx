/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "power.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern bool CONFIG_NO_HZ_IDLE __kconfig __weak;

struct sys_stat		__weak	sys_stat;
const volatile u8	__weak preempt_shift;
volatile u64		__weak performance_mode_ns;
volatile u64		__weak balanced_mode_ns;
volatile u64		__weak powersave_mode_ns;
extern const volatile u64	slice_min_ns;
extern const volatile u64	slice_max_ns;
extern volatile bool		__weak no_core_compaction;
extern volatile bool		__weak reinit_cpumask_for_performance;
const volatile bool	__weak is_autopilot_on;

int do_autopilot(void);
u32 calc_avg32(u32 old_val, u32 new_val);
u64 calc_avg(u64 old_val, u64 new_val);
int update_power_mode_time(void);

/*
 * Timer for updating system-wide status periorically
 */
struct update_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct update_timer);
} update_timer SEC(".maps") __weak;

struct sys_stat_ctx {
	u64		now;
	u64		duration_wall;
	u64		duration_total_wall;
	u64		idle_total_wall;
	u64		compute_total_wall;
	u64		compute_total_invr;
	u64		tot_task_time_iwgt;
	u64		tsct_spike_invr;
	u64		nr_queued_task;
	s32		max_lat_cri;
	s32		avg_lat_cri;
	u64		sum_lat_cri;
	u32		nr_sched;
	u32		nr_preempt;
	u32		nr_perf_cri;
	u32		nr_lat_cri;
	u32		nr_x_migration;
	u32		nr_big;
	u32		nr_pc_on_big;
	u32		nr_lc_on_big;
	u64		min_perf_cri;
	u64		avg_perf_cri;
	u64		max_perf_cri;
	u64		sum_perf_cri;
	u32		thr_perf_cri;
	u32		cur_util_wall;
	u32		cur_util_invr;
};

static struct sys_stat_ctx ctx;

static void init_sys_stat_ctx(void)
{
	struct sys_stat_ctx *c = &ctx;

	__builtin_memset(c, 0, sizeof(*c));

	c->min_perf_cri = LAVD_SCALE;
	c->now = scx_bpf_now();
	c->duration_wall = time_delta(c->now, sys_stat.last_update_clk)? : 1;
	WRITE_ONCE(sys_stat.last_update_clk, c->now);
}

static void collect_sys_stat(void)
{
	struct sys_stat_ctx *c = &ctx;
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id, compute_wall = 1;
	int cpu;

	/*
	 * Collect statistics for each compute domain.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		int i, j, k;
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		cpdomc->cur_util_wall_sum = 0;
		cpdomc->avg_util_wall_sum = 0;
		cpdomc->cur_util_invr_sum = 0;
		cpdomc->avg_util_invr_sum = 0;
		cpdomc->cur_steal_util_wall_sum = 0;
		cpdomc->avg_steal_util_wall_sum = 0;
		cpdomc->cur_steal_util_invr_sum = 0;
		cpdomc->avg_steal_util_invr_sum = 0;
		cpdomc->cur_dom_pinned_util_wall_sum = 0;
		cpdomc->avg_dom_pinned_util_wall_sum = 0;
		cpdomc->cur_dom_pinned_util_invr_sum = 0;
		cpdomc->avg_dom_pinned_util_invr_sum = 0;
		cpdomc->nr_queued_task = 0;

		if (use_cpdom_dsq())
			cpdomc->nr_queued_task = scx_bpf_dsq_nr_queued(cpdom_to_dsq(cpdom_id));

		bpf_for(i, 0, LAVD_CPU_ID_MAX/64) {
			u64 cpumask = cpdomc->__cpumask[i];
			bpf_for(k, 0, 64) {
				j = cpumask_next_set_bit(&cpumask);
				if (j < 0)
					break;
				cpu = (i * 64) + j;
				if (cpu >= nr_cpu_ids)
					break;

				cpdomc->nr_queued_task += scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
				if (use_per_cpu_dsq())
					cpdomc->nr_queued_task += scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu));
			}
		}

		c->nr_queued_task += cpdomc->nr_queued_task;
	}

	/*
	 * Collect statistics for each CPU (phase 1).
	 *
	 * Note that we divide the loop into multiple phases to lower the
	 * verification burden and to avoid a verification error. Someday,
	 * when the verifier gets smarter, we can merge those phases into
	 * one.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		u64 compute_invr, cpuc_tot_task_time_invr, irq_steal_wall;
		u64 irq_steal_invr, task_wall, rt_dl_time_invr, now_task;
		u64 now_pelt, delta_task, delta_pelt;
		u64 cur_idle_wall = 0, past_idle_wall;
		u64 dom_pinned_task_time_wall, dom_pinned_task_time_invr;
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

		if (!cpuc) {
			c->compute_total_wall = 0;
			break;
		}

		/*
		 * When pinned tasks are waiting to run on this CPU
		 * or a system is overloaded (so the slice cannot be boosted
		 * or there are pending tasks to run), shrink the time slice
		 * of slice-boosted tasks.
		 */
		if (cpuc->nr_pinned_tasks || !can_boost_slice() ||
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpuc->cpu_id)) {
			shrink_boosted_slice_remote(cpuc, c->now);
		}

		/*
		 * Accumulate cpus' loads.
		 */
		c->tot_task_time_iwgt += cpuc->tot_task_time_iwgt;
		cpuc->tot_task_time_iwgt = 0;

		/*
		 * If the CPU is in an idle state (i.e., idle_start_clk is
		 * non-zero), accumulate the current idle period so far.
		 */
		for (int i = 0; i < LAVD_MAX_RETRY; i++) {
			u64 old_clk = cpuc->idle_start_clk;
			if (old_clk == 0 || time_after(old_clk, c->now))
				break;

			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, c->now);
			if (ret) {
				cur_idle_wall = time_delta(c->now, old_clk);
				__sync_fetch_and_add(&cpuc->idle_total_wall,
						     cur_idle_wall);
				break;
			}
		}

		/*
		 * Calculate steal time for this interval using scx_clock_task()
		 * and scx_clock_pelt() snapshots.
		 *
		 * 1) steal_time_wall = compute_wall - tot_task_time_wall:
		 *   wall-clock time the CPU was active but not running SCX
		 *   tasks (IRQ + hypervisor steal + RT/DL), excluding idle.
		 *
		 * 2) steal_time_invr: invariant equivalent, derived as:
		 *   - irq_steal_invr: uses the observed performance factor
		 *     (delta_pelt / task_wall) via conv_wall_to_invr_obs().
		 *     Falls back to avg_perf_factor EWMA when task_wall is
		 *     zero (e.g., CPU was entirely idle with only IRQ traffic).
		 *   - rt_dl_time_invr: derived directly from the delta_pelt
		 *     minus SCX task invariant time -- no approximation needed.
		 *
		 * 3) Deriving task_wall and irq_steal_wall from delta_task:
		 *
		 * 3-1) scx_clock_task() reads rq->clock_task for a remote CPU
		 * without holding the rq lock. With NO_HZ_IDLE, rq->clock_task
		 * is not updated while the CPU is idle (no ticks, no scheduling
		 * events). However, when the CPU wakes from idle,
		 * update_rq_clock() catches rq->clock_task up to the current
		 * time, including the elapsed idle duration.
		 *
		 * Moreover, a CPU may toggle between idle and active multiple
		 * times within a single collection interval. At collection
		 * time, idle_total_wall (after the CAS above) includes all
		 * idle periods: both the completed ones and the current
		 * in-progress one (cur_idle_wall). delta_task, however, only
		 * catches up through the last wakeup event -- it includes
		 * completed idle periods but NOT the current in-progress one.
		 * Therefore:
		 *
		 *   delta_task ≈ (idle_total_wall - cur_idle_wall)
		 *                + compute_wall - IRQ - steal
		 *
		 * 3-2) Subtracting the idle periods already captured by
		 * delta_task:
		 *
		 *   past_idle_wall = idle_total_wall - cur_idle_wall
		 *   task_wall      = delta_task - past_idle_wall
		 *                  = compute_wall - IRQ - steal
		 *   irq_steal_wall = compute_wall - task_wall
		 *                  = IRQ + steal
		 *
		 * This identity holds regardless of the number of idle/active
		 * transitions within the interval and whether the CPU is
		 * currently idle or active at collection time.
		 *
		 * 4) Correcting delta_pelt for the NO_HZ_IDLE stale-read:
		 *
		 * scx_clock_pelt() reads clock_pelt - lost_idle_time. With
		 * NO_HZ_IDLE, clock_pelt advances at wall-clock rate but
		 * lost_idle_time is only updated via update_rq_clock_pelt(),
		 * which requires update_rq_clock() to be called. Since no
		 * ticks fire on an idle CPU, lost_idle_time stays frozen and
		 * delta_pelt drifts at wall-clock rate -- the same stale
		 * behaviour as delta_task before the past_idle_wall correction.
		 *
		 * When the CPU is currently idle (cur_idle_wall > 0), advance
		 * now_pelt by cur_idle_pelt -- the invariant equivalent of
		 * cur_idle_wall -- before computing delta_pelt. This corrects
		 * the current interval and also pre-compensates prev_pelt_clk
		 * for the wakeup bounce: when the CPU wakes up,
		 * update_rq_clock_pelt() advances clock_pelt by
		 * idle_dur * cap/1024 without a matching lost_idle_time update,
		 * which would otherwise inflate delta_pelt in the first active
		 * interval after idle. Storing the pre-compensated value in
		 * prev_pelt_clk cancels this bounce exactly.
		 * A safety clamp then ensures delta_pelt never exceeds
		 * compute_wall, covering residual approximation error and torn
		 * reads of clock_pelt/lost_idle_time at idle exit.
		 *
		 * Without NO_HZ_IDLE, periodic ticks keep lost_idle_time
		 * nearly in sync, so no correction is needed.
		 */
		compute_wall = time_delta(c->duration_wall, cpuc->idle_total_wall);
		cpuc->steal_time_wall = time_delta(compute_wall, cpuc->tot_task_time_wall);
		cpuc->tot_task_time_wall = 0;
		dom_pinned_task_time_wall = cpuc->tot_dom_pinned_task_time_wall;
		cpuc->tot_dom_pinned_task_time_wall = 0;
		now_task = scx_clock_task(cpu);
		now_pelt = scx_clock_pelt(cpu);
		delta_task = time_delta(now_task, cpuc->prev_task_clk);
		if (CONFIG_NO_HZ_IDLE && cur_idle_wall > 0) {
			/*
			 * With NO_HZ_IDLE, lost_idle_time is not updated while
			 * the CPU is idle, so clock_pelt - lost_idle_time drifts
			 * at wall-clock rate during the current idle period.
			 * Advance now_pelt by cur_idle_pelt -- the invariant
			 * equivalent of cur_idle_wall -- before computing
			 * delta_pelt. This corrects the current interval and
			 * pre-compensates prev_pelt_clk for the wakeup bounce
			 * (see block comment above).
			 */
			u64 cap = scx_bpf_cpuperf_cap(cpu);
			u64 cur_idle_pelt = (cur_idle_wall * cap) >> LAVD_SHIFT;
			now_pelt += cur_idle_pelt;
		}
		delta_pelt = time_delta(now_pelt, cpuc->prev_pelt_clk);
		/*
		 * Safety clamp: invariant active time cannot exceed wall active
		 * time. Handles residual approximation error from the
		 * compensation above and torn reads of clock_pelt/lost_idle_time
		 * at idle exit (e.g., when the CPU woke up just before
		 * collection and cur_idle_wall is already zero).
		 */
		if (delta_pelt > compute_wall)
			delta_pelt = compute_wall;

		past_idle_wall = time_delta(cpuc->idle_total_wall, cur_idle_wall);
		task_wall = time_delta(delta_task, past_idle_wall);
		irq_steal_wall = time_delta(compute_wall, task_wall);
		if (task_wall > 0) {
			u64 perf_factor = (delta_pelt << LAVD_SHIFT) / task_wall;
			cpuc->avg_perf_factor = calc_avg(cpuc->avg_perf_factor,
							 perf_factor);
			irq_steal_invr = conv_wall_to_invr_obs(irq_steal_wall,
							       delta_pelt, task_wall);
		} else {
			irq_steal_invr = (irq_steal_wall * cpuc->avg_perf_factor) >> LAVD_SHIFT;
		}

		/*
		 * Snapshot and immediately reset tot_task_time_invr so that
		 * newly accumulated SCX work goes into the next interval.
		 * Use the snapshot for both rt_dl_time_invr and the utilization
		 * calculation below so both see the same consistent value.
		 */
		cpuc_tot_task_time_invr = cpuc->tot_task_time_invr;
		cpuc->tot_task_time_invr = 0;
		dom_pinned_task_time_invr = cpuc->tot_dom_pinned_task_time_invr;
		cpuc->tot_dom_pinned_task_time_invr = 0;
		rt_dl_time_invr = time_delta(delta_pelt, cpuc_tot_task_time_invr);
		cpuc->steal_time_invr = irq_steal_invr + rt_dl_time_invr;
		/*
		 * Same conservative clamp as delta_pelt above: irq_steal_invr
		 * is scaled by perf_factor (delta_pelt / task_wall), which can
		 * exceed 1.0 on a frequency-boosted CPU, pushing steal_time_invr
		 * above compute_wall. Clamp so cur_steal_util_invr stays ≤ 1.0.
		 */
		if (cpuc->steal_time_invr > compute_wall)
			cpuc->steal_time_invr = compute_wall;

		/*
		 * Calculate steal utilization: steal_time as a fraction of
		 * duration_wall. cur_util - cur_steal_util gives the remaining
		 * SCX capacity, usable for load balancing decisions.
		 */
		cpuc->cur_steal_util_wall = (cpuc->steal_time_wall << LAVD_SHIFT) /
					c->duration_wall;
		cpuc->avg_steal_util_wall = calc_asym_avg(cpuc->avg_steal_util_wall,
							   cpuc->cur_steal_util_wall);
		cpuc->cur_steal_util_invr = (cpuc->steal_time_invr << LAVD_SHIFT) /
					c->duration_wall;
		cpuc->avg_steal_util_invr = calc_asym_avg(cpuc->avg_steal_util_invr,
							   cpuc->cur_steal_util_invr);

		ravg_accumulate(&cpuc->avg_irq_steal_ravg, cpuc->cur_steal_util_invr, c->now,
					LAVD_RAVG_HALFLIFE_NS);
		u64 avg_irq_fp = ravg_read(&cpuc->avg_irq_steal_ravg, c->now, LAVD_RAVG_HALFLIFE_NS);
		u32 avg_irq_val = (u32)(avg_irq_fp >> RAVG_FRAC_BITS);
		cpuc->lat_headroom = (avg_irq_val < LAVD_SCALE) ? (LAVD_SCALE - avg_irq_val) : 0;

		/*
		 * Calculate per-CPU wall-clock utilization.
		 * compute_wall = steal_time_wall + tot_task_time_wall (before
		 * zeroing above), i.e., all non-idle CPU time.
		 */
		cpuc->cur_util_wall = (compute_wall << LAVD_SHIFT) / c->duration_wall;
		cpuc->avg_util_wall = calc_asym_avg(cpuc->avg_util_wall, cpuc->cur_util_wall);

		/*
		 * Calculate invariant CPU utilization using steal_time_invr.
		 * tot_task_time_invr + steal_time_invr = SCX_invr + irq_steal_invr
		 * + rt_dl_invr = total invariant active time.
		 *
		 * Clamp compute_invr to compute_wall: invariant active time
		 * cannot exceed wall active time (cap x freq <= 1024^2). Any
		 * excess is a cross-interval measurement artifact where a task
		 * that started in the previous interval contributes its full
		 * runtime to this interval's tot_task_time_invr.
		 */
		compute_invr = cpuc_tot_task_time_invr + cpuc->steal_time_invr;
		if (compute_invr > compute_wall)
			compute_invr = compute_wall;
		cpuc->cur_util_invr = (compute_invr << LAVD_SHIFT) /
					c->duration_wall;
		cpuc->avg_util_invr = calc_asym_avg(cpuc->avg_util_invr, cpuc->cur_util_invr);

		/*
		 * Calculate domain-pinned task utilization. Clamp both
		 * snapshots to compute_wall. For wall time, this guards against
		 * cross-interval contamination (last_measured_*_clk is sampled
		 * at tick, so the first delta after a reset can span the
		 * interval boundary). For invariant time, the additional risk is
		 * a perf_factor > 1.0 on a frequency-boosted CPU scaling the
		 * sum above duration_wall; compute_wall is the same bound used
		 * for compute_invr above.
		 */
		if (dom_pinned_task_time_wall > compute_wall)
			dom_pinned_task_time_wall = compute_wall;
		if (dom_pinned_task_time_invr > compute_wall)
			dom_pinned_task_time_invr = compute_wall;
		cpuc->cur_dom_pinned_util_wall =
			(dom_pinned_task_time_wall << LAVD_SHIFT) /
			c->duration_wall;
		cpuc->avg_dom_pinned_util_wall =
			calc_asym_avg(cpuc->avg_dom_pinned_util_wall,
				      cpuc->cur_dom_pinned_util_wall);
		cpuc->cur_dom_pinned_util_invr =
			(dom_pinned_task_time_invr << LAVD_SHIFT) /
			c->duration_wall;
		cpuc->avg_dom_pinned_util_invr =
			calc_asym_avg(cpuc->avg_dom_pinned_util_invr,
				      cpuc->cur_dom_pinned_util_invr);

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
		if (cpdomc) {
			cpdomc->cur_util_wall_sum += cpuc->cur_util_wall;
			cpdomc->avg_util_wall_sum += cpuc->avg_util_wall;
			cpdomc->cur_util_invr_sum += cpuc->cur_util_invr;
			cpdomc->avg_util_invr_sum += cpuc->avg_util_invr;

			cpdomc->cur_steal_util_wall_sum += cpuc->cur_steal_util_wall;
			cpdomc->avg_steal_util_wall_sum += cpuc->avg_steal_util_wall;
			cpdomc->cur_steal_util_invr_sum += cpuc->cur_steal_util_invr;
			cpdomc->avg_steal_util_invr_sum += cpuc->avg_steal_util_invr;

			cpdomc->cur_dom_pinned_util_wall_sum += cpuc->cur_dom_pinned_util_wall;
			cpdomc->avg_dom_pinned_util_wall_sum += cpuc->avg_dom_pinned_util_wall;
			cpdomc->cur_dom_pinned_util_invr_sum += cpuc->cur_dom_pinned_util_invr;
			cpdomc->avg_dom_pinned_util_invr_sum += cpuc->avg_dom_pinned_util_invr;
		}

		cpuc->prev_task_clk = now_task;
		cpuc->prev_pelt_clk = now_pelt;

		/*
		 * Accumulate cpus' scaled loads,
		 * which is capacity and frequency invariant.
		 */
		c->compute_total_invr += compute_invr;

		/*
		 * Track the scaled time when the utilization spikes happened.
		 */
		if (cpuc->cur_util_wall > LAVD_CC_UTIL_SPIKE)
			c->tsct_spike_invr += compute_invr;

	}

	/*
	 * Collect statistics for each CPU (phase 2).
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total_wall = 0;
			break;
		}

		/*
		 * Update the effective capacity of this CPU -- the capacity
		 * that this CPU can achieve considering all the constraints,
		 * such as policy, thermal, power, etc.
		 *
		 * WARNING: This should be called after updating cpuc->cur_util.
		 */
		update_effective_capacity(cpuc);

		/*
		 * Accumulate statistics.
		 */
		if (cpuc->big_core) {
			c->nr_big += cpuc->nr_sched;
			c->nr_pc_on_big += cpuc->nr_perf_cri;
			c->nr_lc_on_big += cpuc->nr_lat_cri;
		}
		c->nr_perf_cri += cpuc->nr_perf_cri;
		cpuc->nr_perf_cri = 0;

		c->nr_lat_cri += cpuc->nr_lat_cri;
		cpuc->nr_lat_cri = 0;

		c->nr_x_migration += cpuc->nr_x_migration;
		cpuc->nr_x_migration = 0;

		/*
		 * Accumulate task's latency criticlity information.
		 *
		 * While updating cpu->* is racy, the resulting impact on
		 * accuracy should be small and very rare and thus should be
		 * fine.
		 */
		c->sum_lat_cri += cpuc->sum_lat_cri;
		cpuc->sum_lat_cri = 0;

		c->nr_sched += cpuc->nr_sched;
		cpuc->nr_sched = 0;

		c->nr_preempt += cpuc->nr_preempt;
		cpuc->nr_preempt = 0;

		if (cpuc->max_lat_cri > c->max_lat_cri)
			c->max_lat_cri = cpuc->max_lat_cri;
		cpuc->max_lat_cri = 0;
	}

	/*
	 * Collect statistics for each CPU (phase 3).
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total_wall = 0;
			break;
		}

		/*
		 * Accumulate task's performance criticality information.
		 */
		if (have_little_core) {
			if (cpuc->min_perf_cri < c->min_perf_cri)
				c->min_perf_cri = cpuc->min_perf_cri;
			cpuc->min_perf_cri = LAVD_SCALE;

			if (cpuc->max_perf_cri > c->max_perf_cri)
				c->max_perf_cri = cpuc->max_perf_cri;
			cpuc->max_perf_cri = 0;

			c->sum_perf_cri += cpuc->sum_perf_cri;
			cpuc->sum_perf_cri = 0;
		}

		/*
		 * Accumulate system-wide idle time.
		 */
		c->idle_total_wall += cpuc->idle_total_wall;
		cpuc->idle_total_wall = 0;
	}
}

static void calc_sys_stat(void)
{
	struct sys_stat_ctx *c = &ctx;
	static int cnt = 0;
	u64 avg_svc_time_iwgt = 0, cur_util_invr, scu_spike_invr;

	/*
	 * Calculate the CPU utilization that includes everything
	 * — scx tasks, non-scx tasks (e.g., RT/DL), IRQ, etc.
	 */
	c->duration_total_wall = (c->duration_wall * nr_cpus_onln) ? : 1;
	c->compute_total_wall = time_delta(c->duration_total_wall, c->idle_total_wall);
	c->cur_util_wall = (c->compute_total_wall << LAVD_SHIFT) / c->duration_total_wall;

	/*
	 * Calculate the scaled CPU utilization that includes everything
	 * — scx tasks, non-scx tasks (e.g., RT/DL), IRQ, etc.
	 */
	cur_util_invr = (c->compute_total_invr << LAVD_SHIFT) / c->duration_total_wall;
	if (cur_util_invr > c->cur_util_wall)
		cur_util_invr = min(sys_stat.avg_util_invr, c->cur_util_wall);

	/*
	 *
	 * Suppose that a CPU can provide the compute capacity upto 100 and
	 * task A running on the CPU A consumed the compute capacity 100.
	 * Then the measured CPU utilization is of course 100%.
	 *
	 * However, what if task A is a CPU-bound, consuming a lot more CPU
	 * cycles? In that case, if task A is scheduled on a more powerful
	 * CPU B whose capacity is, say 200. Task A may consume 130 out of 200
	 * on CPU B. In that case, the true capacity for task A should be 130,
	 * not 100. This is what we want to measure at a given moment to
	 * eventually calaucate the require capacity.
	 *
	 * In other words, when a CPU is almost fully utilized (say 90%)
	 * during a period, we may underestimate the utilization. For example,
	 * when the measured CPU utilization is 100%, there is a possibility
	 * that the actual utilization is actually higher, such as 130%.
	 *
	 * To handle such utilization spike cases, we give a 50% premium for
	 * the scaled CPU time where the CPU is almost fully utilized. This
	 * overestimates the scaled CPU utilization and required compute
	 * capacity and finally allocates more active CPUs. The over-allocated
	 * CPUs become the breathing room.
	 */
	scu_spike_invr = (c->tsct_spike_invr << (LAVD_SHIFT - 1)) /
				c->duration_total_wall;
	c->cur_util_invr = min(cur_util_invr + scu_spike_invr, LAVD_SCALE);

	/*
	 * Update min/max/avg.
	 */
	if (c->nr_sched == 0 || c->compute_total_wall == 0) {
		/*
		 * When a system is completely idle, it is indeed possible
		 * nothing scheduled for an interval.
		 */
		c->max_lat_cri = sys_stat.max_lat_cri;
		c->avg_lat_cri = sys_stat.avg_lat_cri;

		if (have_little_core) {
			c->min_perf_cri = sys_stat.min_perf_cri;
			c->max_perf_cri = sys_stat.max_perf_cri;
			c->avg_perf_cri = sys_stat.avg_perf_cri;
		}
	}
	else {
		c->avg_lat_cri = c->sum_lat_cri / c->nr_sched;
		if (have_little_core)
			c->avg_perf_cri = c->sum_perf_cri / c->nr_sched;
	}

	/*
	 * Update the CPU utilization to the next version.
	 */
	sys_stat.avg_util_wall = calc_asym_avg(sys_stat.avg_util_wall, c->cur_util_wall);
	sys_stat.avg_util_invr = calc_asym_avg(sys_stat.avg_util_invr, c->cur_util_invr);
	sys_stat.max_lat_cri = calc_avg32(sys_stat.max_lat_cri, c->max_lat_cri);
	sys_stat.avg_lat_cri = calc_avg32(sys_stat.avg_lat_cri, c->avg_lat_cri);
	sys_stat.thr_lat_cri = sys_stat.max_lat_cri - ((sys_stat.max_lat_cri -
				sys_stat.avg_lat_cri) >> preempt_shift);

	if (have_little_core) {
		sys_stat.min_perf_cri =
			calc_avg32(sys_stat.min_perf_cri, c->min_perf_cri);
		sys_stat.avg_perf_cri =
			calc_avg32(sys_stat.avg_perf_cri, c->avg_perf_cri);
		sys_stat.max_perf_cri =
			calc_avg32(sys_stat.max_perf_cri, c->max_perf_cri);
	}

	if (c->nr_sched > 0)
		avg_svc_time_iwgt = c->tot_task_time_iwgt / c->nr_sched;
	sys_stat.avg_svc_time_iwgt = calc_avg(sys_stat.avg_svc_time_iwgt,
					      avg_svc_time_iwgt);
	sys_stat.nr_queued_task = calc_avg(sys_stat.nr_queued_task, c->nr_queued_task);

	/*
	 * Half the statistics every minitue so the statistics hold the
	 * information on a few minutes.
	 */
	if (cnt++ == LAVD_SYS_STAT_DECAY_TIMES) {
		cnt = 0;
		sys_stat.nr_sched >>= 1;
		sys_stat.nr_preempt >>= 1;
		sys_stat.nr_perf_cri >>= 1;
		sys_stat.nr_lat_cri >>= 1;
		sys_stat.nr_x_migration >>= 1;
		sys_stat.nr_big >>= 1;
		sys_stat.nr_pc_on_big >>= 1;
		sys_stat.nr_lc_on_big >>= 1;

		__sync_fetch_and_sub(&performance_mode_ns, performance_mode_ns/2);
		__sync_fetch_and_sub(&balanced_mode_ns, balanced_mode_ns/2);
		__sync_fetch_and_sub(&powersave_mode_ns, powersave_mode_ns/2);
	}

	sys_stat.nr_sched += c->nr_sched;
	sys_stat.nr_preempt += c->nr_preempt;
	sys_stat.nr_perf_cri += c->nr_perf_cri;
	sys_stat.nr_lat_cri += c->nr_lat_cri;
	sys_stat.nr_x_migration += c->nr_x_migration;
	sys_stat.nr_big += c->nr_big;
	sys_stat.nr_pc_on_big += c->nr_pc_on_big;
	sys_stat.nr_lc_on_big += c->nr_lc_on_big;

	update_power_mode_time();
}

static void calc_sys_time_slice(void)
{
	u64 nr_q, slice_wall;

	/*
	 * Given the updated state, recalculate the time slice for the next
	 * round. The time slice should be short enough to schedule all
	 * runnable tasks at least once within a targeted latency using the
	 * active CPUs.
	 */
	nr_q = sys_stat.nr_queued_task;
	if (nr_q > 0) {
		slice_wall = (LAVD_TARGETED_LATENCY_NS * sys_stat.nr_active) / nr_q;
		slice_wall = clamp(slice_wall, slice_min_ns, slice_max_ns);
	} else {
		slice_wall = slice_max_ns;
	}
	sys_stat.slice_wall = calc_avg(sys_stat.slice_wall, slice_wall);
}

static int do_update_sys_stat(void)
{
	init_sys_stat_ctx();
	collect_sys_stat();
	calc_sys_stat();

	return 0;
}

__weak
int update_sys_stat(void)
{
	/*
	 * Update system statistics.
	 */
	do_update_sys_stat();

	/*
	 * Change the power profile based on the statistics.
	 */
	if (is_autopilot_on)
		do_autopilot();

	/*
	 * Perform core compaction for powersave and balance mode.
	 * Or turn on all CPUs for performance mode.
	 */
	if (!no_core_compaction)
		do_core_compaction();

	if (reinit_cpumask_for_performance) {
		reinit_cpumask_for_performance = false;
		reinit_active_cpumask_for_performance();
	}

	/*
	 * Update time slice and performance criticality threshold.
	 */
	calc_sys_time_slice();
	update_thr_perf_cri();

	/*
	 * Plan cross-domain task migration.
	 */
	if (nr_cpdoms > 1)
		plan_x_cpdom_migration();

	return 0;
}

static int update_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	update_sys_stat();

	err = bpf_timer_start(timer, LAVD_SYS_STAT_INTERVAL_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm update timer");

	return 0;
}

__weak
s32 init_sys_stat(u64 now)
{
	struct cpdom_ctx *cpdomc;
	struct bpf_timer *timer;
	u64 cpdom_id;
	u32 key = 0;
	int err;

	sys_stat.last_update_clk = now;
	sys_stat.nr_active = nr_cpus_onln;
	sys_stat.slice_wall = slice_max_ns;
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		if (cpdomc->nr_active_cpus)
			sys_stat.nr_active_cpdoms++;
	}

	timer = bpf_map_lookup_elem(&update_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup update timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &update_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, update_timer_cb);
	err = bpf_timer_start(timer, LAVD_SYS_STAT_INTERVAL_NS, 0);
	if (err) {
		scx_bpf_error("Failed to arm update timer");
		return err;
	}

	return 0;
}
