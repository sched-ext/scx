/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
	u64		duration;
	u64		duration_total;
	u64		idle_total;
	u64		compute_total;
	u64		tot_svc_time;
	u64		tot_sc_time;
	u64		tsct_spike;
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
	u32		cur_util;
	u32		cur_sc_util;
};

static void init_sys_stat_ctx(struct sys_stat_ctx *c)
{
	__builtin_memset(c, 0, sizeof(*c));

	c->min_perf_cri = LAVD_SCALE;
	c->now = scx_bpf_now();
	c->duration = time_delta(c->now, sys_stat.last_update_clk)? : 1;
	WRITE_ONCE(sys_stat.last_update_clk, c->now);
}

static void collect_sys_stat(struct sys_stat_ctx *c)
{
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id, compute, non_scx_time, sc_non_scx_time, cpuc_tot_sc_time;
	int cpu;

	/*
	 * Collect statistics for each compute domain.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		int i, j, k;
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		cpdomc->cur_util_sum = 0;
		cpdomc->avg_util_sum = 0;
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
	 * Note that we divide the loop into phases 1 and 2 to lower the
	 * verification burden and to avoid a verification error. Someday,
	 * when the verifier gets smarter, we can merge phases 1 and 2
	 * into one.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total = 0;
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
		c->tot_svc_time += cpuc->tot_svc_time;
		cpuc->tot_svc_time = 0;

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
				u64 duration = time_delta(c->now, old_clk);

				__sync_fetch_and_add(&cpuc->idle_total, duration);
				break;
			}
		}

		/*
		 * Calculate per-CPU utilization.
		 */
		compute = time_delta(c->duration, cpuc->idle_total);
		cpuc->cur_util = (compute << LAVD_SHIFT) / c->duration;
		cpuc->avg_util = calc_asym_avg(cpuc->avg_util, cpuc->cur_util);

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
		if (cpdomc) {
			cpdomc->cur_util_sum += cpuc->cur_util;
			cpdomc->avg_util_sum += cpuc->avg_util;
		}

		/*
		 * Calculate the scaled non-SCX time of this CPU, including
		 * IRQ, non-SCX (RT/DL) tasks. Since there is no direct way
		 * to track non-SCX time, we derive it from the total SCX task
		 * time (i.e., tot_task_time) and total compute time (i.e.,
		 * duration - idle_total). We assume the CPU frequency was at
		 * its maximum while running non-SCX tasks.
		 */
		non_scx_time = time_delta(compute, cpuc->tot_task_time);
		sc_non_scx_time = scale_cap_max_freq(non_scx_time, cpu);
		cpuc->tot_task_time = 0;

		/*
		 * Update scaled CPU utilization, which is capacity and
		 * frequency invariant. The scaled CPU utilization should
		 * include everything — SCX task time, non-SCX task time
		 * (RT/DL), IRQ times, etc.
		 */
		cpuc_tot_sc_time = cpuc->tot_sc_time + sc_non_scx_time;
		cpuc->cur_sc_util = (cpuc_tot_sc_time << LAVD_SHIFT) / c->duration;
		cpuc->avg_sc_util = calc_avg(cpuc->avg_sc_util, cpuc->cur_sc_util);
		cpuc->tot_sc_time = 0;

		/*
		 * Accumulate cpus' scaled loads,
		 * which is capacity and frequency invariant.
		 */
		c->tot_sc_time += cpuc_tot_sc_time;

		/*
		 * Track the scaled time when the utilization spikes happened.
		 */
		if (cpuc->cur_util > LAVD_CC_UTIL_SPIKE)
			c->tsct_spike += cpuc_tot_sc_time;
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
	 * Collect statistics for each CPU (phase 2).
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total = 0;
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
		 * cpuc->cur_stolen_est is only an estimate of the time stolen by
		 * irq/steal during execution times. We extrapolate that ratio to
		 * the rest of CPU time as an approximation.
		 */
		cpuc->cur_stolen_est = (cpuc->stolen_time_est << LAVD_SHIFT) / compute;
		cpuc->avg_stolen_est = calc_asym_avg(cpuc->avg_stolen_est, cpuc->cur_stolen_est);
		cpuc->stolen_time_est = 0;

		/*
		 * Accmulate system-wide idle time.
		 */
		c->idle_total += cpuc->idle_total;
		cpuc->idle_total = 0;
	}
}

static void calc_sys_stat(struct sys_stat_ctx *c)
{
	static int cnt = 0;
	u64 avg_svc_time = 0, cur_sc_util, scu_spike;

	/*
	 * Calculate the CPU utilization that includes everything
	 * — scx tasks, non-scx tasks (e.g., RT/DL), IRQ, etc.
	 */
	c->duration_total = c->duration * nr_cpus_onln;
	c->compute_total = time_delta(c->duration_total, c->idle_total);
	c->cur_util = (c->compute_total << LAVD_SHIFT) / c->duration_total;

	/*
	 * Calculate the scaled CPU utilization that includes everything
	 * — scx tasks, non-scx tasks (e.g., RT/DL), IRQ, etc.
	 */
	cur_sc_util = (c->tot_sc_time << LAVD_SHIFT) / c->duration_total;
	if (cur_sc_util > c->cur_util)
		cur_sc_util = min(sys_stat.avg_sc_util, c->cur_util);

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
	scu_spike = (c->tsct_spike << (LAVD_SHIFT - 1)) / c->duration_total;
	c->cur_sc_util = min(cur_sc_util + scu_spike, LAVD_SCALE);

	/*
	 * Update min/max/avg.
	 */
	if (c->nr_sched == 0 || c->compute_total == 0) {
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
	sys_stat.avg_util = calc_asym_avg(sys_stat.avg_util, c->cur_util);
	sys_stat.avg_sc_util = calc_asym_avg(sys_stat.avg_sc_util, c->cur_sc_util);
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
		avg_svc_time = c->tot_svc_time / c->nr_sched;
	sys_stat.avg_svc_time = calc_avg(sys_stat.avg_svc_time, avg_svc_time);
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
	u64 nr_q, slice;

	/*
	 * Given the updated state, recalculate the time slice for the next
	 * round. The time slice should be short enough to schedule all
	 * runnable tasks at least once within a targeted latency using the
	 * active CPUs.
	 */
	nr_q = sys_stat.nr_queued_task;
	if (nr_q > 0) {
		slice = (LAVD_TARGETED_LATENCY_NS * sys_stat.nr_active) / nr_q;
		slice = clamp(slice, slice_min_ns, slice_max_ns);
	} else {
		slice = slice_max_ns;
	}
	sys_stat.slice = calc_avg(sys_stat.slice, slice);
}

static int do_update_sys_stat(void)
{
	struct sys_stat_ctx c;

	init_sys_stat_ctx(&c);
	collect_sys_stat(&c);
	calc_sys_stat(&c);

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
	sys_stat.slice = slice_max_ns;
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
