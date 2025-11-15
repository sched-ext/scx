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

/*
 * System-wide properties of CPUs
 */
bool			have_turbo_core;
bool			have_little_core;
const volatile bool	is_smt_active;

/*
 * CPU properties
 */
/* CPU capacity based on 1024 */
const volatile u16	cpu_capacity[LAVD_CPU_ID_MAX];

/* Is a CPU a big core? */
const volatile u8	cpu_big[LAVD_CPU_ID_MAX];

/* Is a CPU a turbo core? */
const volatile u8	cpu_turbo[LAVD_CPU_ID_MAX];


/*
 * Compute domain properties
 */
/* number of compute domains */
int			nr_cpdoms;

/* contexts for compute domains */
struct cpdom_ctx	cpdom_ctxs[LAVD_CPDOM_MAX_NR];

/* online CPU mask for each compute domain */
private(LAVD) struct bpf_cpumask cpdom_cpumask[LAVD_CPDOM_MAX_NR];


/*
 * Performance vs. CPU order (PCO) table
 */
/* Do not use energy model in making CPU preference order decisions. */
const volatile u8	no_use_em;

/* The numbr of PCO states populated */
const volatile u8	nr_pco_states;

/* The upper bounds of performance capacity for each PCO state. */
const volatile u32	pco_bounds[LAVD_PCO_STATE_MAX];

/* The number of CPUs in a primary domain for each PCO state. */
const volatile u16	pco_nr_primary[LAVD_PCO_STATE_MAX];

/* The PCO table */
const volatile u16	pco_table[LAVD_PCO_STATE_MAX][LAVD_CPU_ID_MAX];

/* The index for current PCO state */
volatile static int	pco_idx;

/*
 * Big & LITTLE core's capacities
 */
/* Total compute capacity of online CPUs. */
u64		total_capacity;

/* Capacity of one LITTLEst CPU. */
u64		one_little_capacity;

/* Big core's compute ratio among currently active cores scaled by 1024. */
u32		cur_big_core_scale;

/* Big core's compute ratio when all cores are active scaled by 1024. */
u32		default_big_core_scale;


/*
 * Power mode
 */
static u64		LAVD_AP_LOW_CAP;
static u64		LAVD_AP_HIGH_CAP;
volatile int		power_mode;
volatile u64		last_power_mode_clk;
volatile bool		is_powersave_mode;

__hidden
int reset_suspended_duration(struct cpu_ctx *cpuc)
{
	if (cpuc->online_clk > cpuc->offline_clk)
		cpuc->offline_clk = cpuc->online_clk;

	return 0;
}

__hidden
u64 get_suspended_duration_and_reset(struct cpu_ctx *cpuc)
{
	/*
	 * When a system is suspended, a task is also suspended in a running
	 * stat on the CPU. Hence, we subtract the suspended duration when it
	 * resumes.
	 */
	u64 duration = 0;

	if (cpuc->online_clk > cpuc->offline_clk) {
		duration = time_delta(cpuc->online_clk, cpuc->offline_clk);
		/*
		 * Once calculated, reset the duration to zero.
		 */
		cpuc->offline_clk = cpuc->online_clk;
	}

	return duration;
}

bool is_perf_cri(task_ctx __arg_arena *taskc)
{
	if (unlikely(!taskc))
		return false;

	if (!have_little_core)
		return true;

	if (test_task_flag(taskc, LAVD_FLAG_ON_BIG | LAVD_FLAG_ON_LITTLE))
		return taskc->perf_cri >= sys_stat.thr_perf_cri;

	return test_task_flag(taskc, LAVD_FLAG_ON_BIG);
}

__hidden
const volatile u16 *get_cpu_order(void)
{
	int i = READ_ONCE(pco_idx);

	if (i < 0 || i >= LAVD_PCO_STATE_MAX) {
		scx_bpf_error("Incorrect PCO state: %d", i);
		i = 0;
	}

	return pco_table[i];
}

static u64 calc_required_capacity(void)
{
	/*
	 * Scaled utilization assumes all the CPUs are the fastest ones
	 * running at the highest frequency. So the required compute capacity
	 * given the scaled utilization is defined as follows:
	 *
	 * req_cpacity = total_compute_capaticy * scaled_utilization
	 *             = (nr_cpus_onln * 1024) * (avg_sc_util / 1024)
	 *             = nr_cpus_only * scaled_utilization
	 */
	return nr_cpus_onln * sys_stat.avg_sc_util;
}

static u64 get_human_readable_avg_sc_util(u64 avg_sc_util)
{
	/*
	 * avg_sc_util is the utilization assuming all the CPUs are the
	 * fastest ones (i.e., capacity = 1024) at the highest frequency.
	 * Hence, when all CPUs are 100% utilized, the avg_sc_util is not
	 * 1024, it is the sum of capacities of all online CPUs. Printing
	 * avg_sc_util is confusing. So, let's convert it to 100% scale when
	 * all CPUs are 100% utilized.
	 */
	return (avg_sc_util * nr_cpus_onln * 1000) / total_capacity;
}

static int calc_nr_active_cpus(void)
{
	u64 req_cap;
	int i;

	/*
	 * First, calculate the required compute capacity:
	 */
	req_cap = calc_required_capacity();

	/*
	 * Then, determine the number of active CPUs that meet the required
	 * compute capacity after updating the PCO index.
	 */
	if (no_use_em) {
		/*
		 * When the energy model is not available, update the PCO
		 * index based on the power mode. Then, fill the required
		 * compute capacity in the CPU preference order, utilizing
		 * each CPU in a certain % (LAVD_CC_PER_CORE_UTIL or
		 * LAVD_CC_PER_CORE_SHIFT).
		 */
		const volatile u16 *cpu_order = get_cpu_order();
		u64 cap_cpu, cap_sum = 0;
		u16 cpu_id;

		if (is_powersave_mode)
			WRITE_ONCE(pco_idx, 0);
		else
			WRITE_ONCE(pco_idx, nr_pco_states - 1);

		bpf_for(i, 0, nr_cpu_ids) {
			if (i >= LAVD_CPU_ID_MAX)
				break;

			cpu_id = cpu_order[i];
			if (cpu_id >= LAVD_CPU_ID_MAX)
				break;

			cap_cpu = cpu_capacity[cpu_id];
			cap_sum += cap_cpu >> LAVD_CC_PER_CORE_SHIFT;
			if (cap_sum >= req_cap)
				return i + 1;
		}
	} else {
		/*
		 * When the energy model is available, all primary CPUs should
		 * be active. First, update pco_idx to meet the required
		 * capacity. Then, choose the number of primary CPUs for the
		 * PCO state.
		 */
		bpf_for(i, 0, nr_pco_states) {
			if (i >= LAVD_PCO_STATE_MAX)
				break;

			if (pco_bounds[i] >= req_cap) {
				WRITE_ONCE(pco_idx, i);
				return pco_nr_primary[i];
			}
		}
	}

	/* Should not be here. */
	return nr_cpu_ids;
}

__weak
int do_core_compaction(void)
{
	const volatile u16 *cpu_order;
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	struct cpdom_ctx *cpdomc;
	int nr_active, cpu, i;
	u32 sum_capacity = 0, big_capacity = 0, nr_active_cpdoms = 0;
	u64 cpdom_id;

	bpf_rcu_read_lock();

	/*
	 * Prepare cpumasks.
	 */
	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	if (!active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		goto unlock_out;
	}

	/*
	 * Update the PCO index that meets the required compute capacity
	 * if the energy model is available. Then, it decides the number of
	 * active CPUs. Finally, obtain the CPU order list based on the current
	 * load.
	 */
	nr_active = calc_nr_active_cpus();
	cpu_order = get_cpu_order();

	/*
	 * Assign active and overflow cores.
	 */
	bpf_for(i, 0, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			break;

		/*
		 * Skip offline cpu
		 */
		cpu = cpu_order[i];
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc || !cpuc->is_online) {
			bpf_cpumask_clear_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);
			continue;
		}

		/*
		 * Assign an online cpu to active and overflow cpumasks
		 */
		if (i < nr_active) {
			bpf_cpumask_set_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);

			/*
			 * Accumulate the capacity of active CPUs and
			 * increase the number of active CPUs.
			 */
			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
			if (cpdomc) {
				cpdomc->cap_sum_temp += cpuc->capacity;
				cpdomc->nr_acpus_temp++;
			}

		} else {
			bpf_cpumask_clear_cpu(cpu, active);

			if (cpuc->nr_pinned_tasks || (use_per_cpu_dsq() &&
			    scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)))) {
				/*
				 * If there is something to run on this CPU,
				 * add this CPU to the overflow set.
				 */
				bpf_cpumask_set_cpu(cpu, ovrflw);
			} else if ((bpf_get_prandom_u32() %
				    LAVD_CC_CPU_PIN_INTERVAL_DIV)) {
				/*
				 * This is the case when a CPU belongs to the
				 * overflow set even though that CPU was not an
				 * overflow set initially. This can happen only
				 * when a pinned userspace task ran on this
				 * CPU. In this case, we keep the CPU in an
				 * overflow set since the CPU will be used
				 * anyway for the task. This will promote equal
				 * use of all used CPUs, lowering the energy
				 * consumption by avoiding a few CPUs being
				 * turbo-boosted. Hence, we do not clear the
				 * overflow cpumask here for a while,
				 * approximately for LAVD_CC_CPU_PIN_INTERVAL.
				 */
				bpf_cpumask_clear_cpu(cpu, ovrflw);
				continue;
			} else if (!bpf_cpumask_test_cpu(cpu, cast_mask(ovrflw))) {
				continue;
			}
		}

		/*
		 * When the CPU is in either an active or overflow set, kick it.
		 */
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		/*
		 * Calculate big capacity ratio if a CPU is on.
		 */
		sum_capacity += cpuc->capacity;
		if (cpuc->big_core)
			big_capacity += cpuc->capacity;
	}

	cur_big_core_scale = (big_capacity << LAVD_SHIFT) / sum_capacity;
	sys_stat.nr_active = nr_active;

	/*
	 * Update nr_active_cpus and cap_sum_active_cpus.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		if (!cpdomc)
			continue;
		WRITE_ONCE(cpdomc->nr_active_cpus, cpdomc->nr_acpus_temp);
		WRITE_ONCE(cpdomc->nr_acpus_temp, 0);
		WRITE_ONCE(cpdomc->cap_sum_active_cpus, cpdomc->cap_sum_temp);
		WRITE_ONCE(cpdomc->cap_sum_temp, 0);

		if (cpdomc->nr_active_cpus)
			nr_active_cpdoms++;
	}
	sys_stat.nr_active_cpdoms = nr_active_cpdoms;

unlock_out:
	bpf_rcu_read_unlock();

	return 0;
}

int update_power_mode_time(void)
{
	u64 now = scx_bpf_now();
	u64 delta;

	if (last_power_mode_clk == 0)
		last_power_mode_clk = now;

	delta = time_delta(now, last_power_mode_clk);
	last_power_mode_clk = now;

	switch (power_mode) {
	case LAVD_PM_PERFORMANCE:
		__sync_fetch_and_add(&performance_mode_ns, delta);
		break;
	case LAVD_PM_BALANCED:
		__sync_fetch_and_add(&balanced_mode_ns, delta);
		break;
	case LAVD_PM_POWERSAVE:
		__sync_fetch_and_add(&powersave_mode_ns, delta);
		break;
	}
	
	return 0;
}

static int do_set_power_profile(s32 pm)
{
	u64 hr_sc;

	/*
	 * Skip setting the mode if already in the same mode.
	 */
	if (power_mode == pm)
		return 0;

	/*
	 * Update power mode time
	 */
	update_power_mode_time();
	power_mode = pm;

	/*
	 * Change the power mode.
	 */
	hr_sc = get_human_readable_avg_sc_util(sys_stat.avg_sc_util);
	switch (pm) {
	case LAVD_PM_PERFORMANCE:
		no_core_compaction = true;
		is_powersave_mode = false;

		/*
		 * Since the core compaction becomes off, we need to
		 * reinitialize the active and overflow cpumask for performance
		 * mode.
		 *
		 * Note that a verifier in an old kernel does not allow calling
		 * bpf_cpumask_set_cpu(), so we defer the actual update to our
		 * timer handler, update_sys_stat().
		 */
		reinit_cpumask_for_performance = true;
		debugln("Set the scheduler's power profile to performance mode: %d",
			hr_sc);
		break;
	case LAVD_PM_BALANCED:
		no_core_compaction = false;
		is_powersave_mode = false;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to balanced mode: %d",
			hr_sc);
		break;
	case LAVD_PM_POWERSAVE:
		no_core_compaction = false;
		is_powersave_mode = true;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to power-save mode: %d",
			hr_sc);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

__weak
int do_autopilot(void)
{
	/*
	 * Calculate the required compute capacity from the scaled utilization.
	 */
	u64 req_cap = calc_required_capacity();

	/*
	 * If the required compute capacity is very low (say that CPU
	 * utilization is <= 5%), it means high performance is not required.
	 * So, we run the scheduler in a power-save mode to save energy
	 * consumption.
	 */
	if (req_cap <= LAVD_AP_LOW_CAP)
		return do_set_power_profile(LAVD_PM_POWERSAVE);

	/*
	 * If the required compute capacity is moderate (say that CPU
	 * utilization is between 5% and 70%), we run the scheduler in a
	 * balanced mode.
	 */
	if (req_cap <= LAVD_AP_HIGH_CAP)
		return do_set_power_profile(LAVD_PM_BALANCED);

	/*
	 * If the required compute capacity is high enough (say that the CPU
	 * utilization is > 70%), we run the scheduler in a performance mode.
	 * The system indeed needs performance; also, there is little energy
	 * benefit even under balanced mode anyway.
	 */
	return do_set_power_profile(LAVD_PM_PERFORMANCE);
}

__weak
int update_thr_perf_cri(void)
{
	u32 little_core_scale, delta, diff, thr;

	if (no_core_compaction || !have_little_core)
		cur_big_core_scale = default_big_core_scale;

	/*
	 * If all active cores are big, all tasks should run on the big cores.
	 */
	if (cur_big_core_scale == LAVD_SCALE) {
		sys_stat.thr_perf_cri = 0;
		return 0;
	}

	/*
	 * We approximate the distribution of performance criticality of tasks
	 * using min, avg, and max performance criticality of a given period.
	 *
	 *   min_perf_cri
	 *   |         avg_perf_cri
	 *   |         |                       max_perf_cri
	 *   |         |                       |
	 *   <--------><----------------------->
	 *
	 * The half of compute capacity should be assigned to the below average
	 * tasks (< avg_perf_cri), and the other half should assigned to the
	 * above average tasks (>= avg_perf_cri).
	 *
	 *   <------------><------------------->
	 *   |            |                    |
	 *   |            |                    1024
	 *   |            1024 - big_core_scale (i.e., little_core_scale)
	 *   0
	 */
	little_core_scale = LAVD_SCALE - cur_big_core_scale;
	if (little_core_scale < p2s(50)) {
		/*
		 *   min_perf_cri
		 *   |         avg_perf_cri
		 *   |         |                       max_perf_cri
		 *   |         |                       |
		 *   <--------><----------------------->
		 *
		 *   <-///-><-------------------------->
		 *   |     |                           |
		 *   |     |                           1024
		 *   |     little_core_scale
		 *   0
		 */
		delta = (sys_stat.avg_perf_cri - sys_stat.min_perf_cri) >> 1;
		diff = (delta * little_core_scale) >> LAVD_SHIFT;
		thr = diff + sys_stat.min_perf_cri;
	}
	else {
		/*
		 *   min_perf_cri
		 *   |         avg_perf_cri
		 *   |         |                       max_perf_cri
		 *   |         |                       |
		 *   <--------><----------------------->
		 *
		 *   <---------------------><-////////->
		 *   |                     |           |
		 *   |                     |           1024
		 *   |                     little_core_scale
		 *   0
		 *
		 *  Note that half of the little core capacity is taken by the
		 *  [min_perf_cri, avg_perf_cri] range, so only another half
		 *  can serve for the [avg_perf_cri, max_perf_cri range.
		 */
		delta = (sys_stat.max_perf_cri - sys_stat.avg_perf_cri) >> 1;
		diff = (delta * (little_core_scale >> 1)) >> LAVD_SHIFT;
		thr = diff + sys_stat.avg_perf_cri;
	}

	sys_stat.thr_perf_cri = thr;

	return 0;
}

__weak
int reinit_active_cpumask_for_performance(void)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	const struct cpumask *online_cpumask;
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id;
	u32 nr_active_cpdoms = 0;
	int cpu, err = 0;

	barrier();
	bpf_rcu_read_lock();

	/*
	 * Prepare cpumasks.
	 */
	active  = active_cpumask;
	ovrflw  = ovrflw_cpumask;
	if (!active || !ovrflw) {
		scx_bpf_error("Failed to prepare cpumasks.");
		err = -ENOMEM;
		goto unlock_out;
	}


	/*
	 * Once core compaction becomes off in performance mode, reinitialize
	 * active/overflow cpumasks to reflect the mode change.
	 * In an asymmetric system, big cores belong to the active set but
	 * little cores the overflow set to prefer big cores for performance.
	 * In a symmetric system, all online CPUs belong to the active set.
	 */
	if (have_little_core) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			cpuc = get_cpu_ctx_id(cpu);
			if (!cpuc)
				continue;
			if (!cpuc->is_online) {
				bpf_cpumask_clear_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
				continue;
			}

			if (cpuc->big_core) {
				bpf_cpumask_set_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			} else {
				bpf_cpumask_set_cpu(cpu, ovrflw);
				bpf_cpumask_clear_cpu(cpu, active);
			}
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
			if (cpdomc) {
				cpdomc->nr_acpus_temp++;
				cpdomc->cap_sum_temp += cpuc->capacity;
			}
		}
	} else {
		online_cpumask = scx_bpf_get_online_cpumask();
		nr_cpus_onln = bpf_cpumask_weight(online_cpumask);
		bpf_cpumask_copy(active, online_cpumask);
		scx_bpf_put_cpumask(online_cpumask);

		bpf_cpumask_clear(ovrflw);

		bpf_for(cpu, 0, nr_cpu_ids) {
			cpuc = get_cpu_ctx_id(cpu);
			if (!cpuc || !cpuc->is_online)
				continue;

			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
			if (cpdomc) {
				cpdomc->nr_acpus_temp++;
				cpdomc->cap_sum_temp += cpuc->capacity;
			}
		}

	}

	/*
	 * Update nr_active_cpus, cap_sum_active_cpus, and pco_idx.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		WRITE_ONCE(cpdomc->nr_active_cpus, cpdomc->nr_acpus_temp);
		WRITE_ONCE(cpdomc->nr_acpus_temp, 0);
		WRITE_ONCE(cpdomc->cap_sum_active_cpus, cpdomc->cap_sum_temp);
		WRITE_ONCE(cpdomc->cap_sum_temp, 0);

		if (cpdomc->nr_active_cpus)
			nr_active_cpdoms++;
	}
	sys_stat.nr_active = nr_cpus_onln;
	sys_stat.nr_active_cpdoms = nr_active_cpdoms;
	pco_idx = nr_pco_states - 1;

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

__hidden
int update_cpuperf_target(struct cpu_ctx *cpuc)
{
	u32 util, max_util, cpuperf_target;

	/*
	 * The CPU utilization decides the frequency. The bigger one between
	 * the running average and the recent utilization is used to respond
	 * quickly upon load spikes. When the utilization is greater than
	 * LAVD_CPU_UTIL_MAX_FOR_CPUPERF (85%), ceil to 100%.
	 */
	if (!no_freq_scaling) {
		max_util = max(cpuc->avg_util, cpuc->cur_util);
		util = (max_util < LAVD_CPU_UTIL_MAX_FOR_CPUPERF) ? max_util
								  : LAVD_SCALE;
		cpuperf_target = (util * SCX_CPUPERF_ONE) >> LAVD_SHIFT;
	} else
		cpuperf_target = SCX_CPUPERF_ONE;

	/*
	 * Update the performance target once it changes.
	 */
	if (cpuc->cpuperf_cur != cpuperf_target) {
		scx_bpf_cpuperf_set(cpuc->cpu_id, cpuperf_target);
		cpuc->cpuperf_cur = cpuperf_target;
	}

	return 0;
}

__hidden
int reset_cpuperf_target(struct cpu_ctx *cpuc)
{
	if (!no_freq_scaling) {
		cpuc->cpuperf_cur = 0;
	}

	return 0;
}

u16 get_cpuperf_cap(s32 cpu)
{
	const volatile u16 *cap;

	cap = MEMBER_VPTR(cpu_capacity, [cpu]);
	if (cap)
		return *cap;

	debugln("Infeasible CPU id: %d", cpu);
	return 0;
}

u64 scale_cap_freq(u64 dur, s32 cpu)
{
	u64 cap, freq, scaled_dur;

	/*
	 * Scale the duration by CPU capacity and frequency, so calculate
	 * capacity-invariant and frequency-invariant time duration.
	 */
	cap = get_cpuperf_cap(cpu);
	freq = scx_bpf_cpuperf_cur(cpu);
	scaled_dur = (dur * cap * freq) >> (LAVD_SHIFT * 2);

	return scaled_dur;
}

static void do_update_autopilot_high_cap(void)
{
	u64 c;

	if (is_smt_active)
		c = (total_capacity * LAVD_AP_HIGH_UTIL_DFL_SMT_RT);
	else
		c = (total_capacity * LAVD_AP_HIGH_UTIL_DFL_NO_SMT_RT);

	LAVD_AP_HIGH_CAP = c >> LAVD_SHIFT;
}

int update_autopilot_high_cap(void)
{
	if (no_use_em)
		do_update_autopilot_high_cap();

	return 0;
}

int init_autopilot_caps(void)
{
	if (no_use_em) {
		/*
		 * When the energy model is not available, rely on the heuristics.
		 * We move up to the balanced mode if one core is half utilized.
		 */
		LAVD_AP_LOW_CAP = one_little_capacity / 2;
		do_update_autopilot_high_cap();
	} else {
		/*
		 * When the energy model is available, rely on the PCO table.
		 * Use the upper bounds of the lowest performance state and
		 * the lower bounds of the highest performance state as the
		 * thresholds for the power save and performance modes,
		 * respectively.
		 */
		int i = max((int)nr_pco_states - 2, 0); /* second last entry */

		LAVD_AP_LOW_CAP = pco_bounds[0];
		LAVD_AP_HIGH_CAP = pco_bounds[i];
	}

	return 0;
}

SEC("syscall")
int set_power_profile(struct power_arg *input)
{
	return do_set_power_profile(input->power_mode);
}


