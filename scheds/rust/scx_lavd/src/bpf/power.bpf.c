/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

/*
 * CPU topology
 */
static u64		LAVD_AP_LOW_UTIL;
static bool		have_turbo_core;
static bool		have_little_core;

const volatile u16	cpu_order_performance[LAVD_CPU_ID_MAX]; /* CPU preference order for performance and balanced mode */
const volatile u16	cpu_order_powersave[LAVD_CPU_ID_MAX]; /* CPU preference order for powersave mode */
const volatile u16	cpu_capacity[LAVD_CPU_ID_MAX]; /* CPU capacity based on 1024 */

static int		nr_cpdoms; /* number of compute domains */
struct cpdom_ctx	cpdom_ctxs[LAVD_CPDOM_MAX_NR]; /* contexts for compute domains */
private(LAVD) struct bpf_cpumask cpdom_cpumask[LAVD_CPDOM_MAX_NR]; /* online CPU mask for each compute domain */


/*
 * Big core's compute ratio among currently active cores scaled by 1024.
 */
static u32		cur_big_core_scale;

/*
 * Big core's compute ratio when all cores are active scaled by 1024.
 */
static u32		default_big_core_scale;

/*
 * Statistics
 */
volatile int		power_mode;
volatile u64		last_power_mode_clk;
volatile u64		performance_mode_ns;
volatile u64		balanced_mode_ns;
volatile u64		powersave_mode_ns;

static bool is_perf_cri(struct task_ctx *taskc)
{
	if (!have_little_core)
		return true;

	if (READ_ONCE(taskc->on_big) && READ_ONCE(taskc->on_little))
		return taskc->perf_cri >= sys_stat.thr_perf_cri;
	return READ_ONCE(taskc->on_big);
}

static bool clear_cpu_periodically(u32 cpu, struct bpf_cpumask *cpumask)
{
	u32 clear;

	/*
	 * If the CPU is on, we clear the bit once every four times
	 * (LAVD_CC_CPU_PIN_INTERVAL_DIV). Hence, the bit will be
	 * probabilistically cleared once every 100 msec (4 * 25 msec).
	 */
	clear = !(bpf_get_prandom_u32() % LAVD_CC_CPU_PIN_INTERVAL_DIV);
	if (clear)
		bpf_cpumask_clear_cpu(cpu, cpumask);

	return clear;
}

static const volatile u16 *get_cpu_order(void)
{
	/*
	 * Decide a cpu order to use according to its power mode.
	 */
	if (is_powersave_mode)
		return cpu_order_powersave;
	else
		return cpu_order_performance;
}

static int calc_nr_active_cpus(void)
{
	const volatile u16 *cpu_order;
	u64 req_cap, cap_cpu, cap_sum = 0;
	u16 cpu_id, i;

	/*
	 * Calculate the required compute capacity:
	 *
	 * Scaled utilization assumes all the CPUs are the fastest ones
	 * running at the highest frequency. So the required compute capacity
	 * given the scaled utilization is defined as follows:
	 *
	 * req_cpacity = total_compute_capaticy * scaled_utilization
	 *             = (nr_cpus_onln * 1024) * (avg_sc_util / 1024)
	 *             = nr_cpus_only * scaled_utilization
	 */
	req_cap = nr_cpus_onln * sys_stat.avg_sc_util;

	/*
	 * Fill the required compute capacity in the CPU preference order,
	 * utilizing each CPU in a certain % (LAVD_CC_PER_CORE_UTIL or
	 * LAVD_CC_PER_CORE_SHIFT).
	 */
	cpu_order = get_cpu_order();
	bpf_for(i, 0, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			return nr_cpu_ids;

		cpu_id = cpu_order[i];
		if (cpu_id >= LAVD_CPU_ID_MAX)
			return nr_cpu_ids;

		cap_cpu = cpu_capacity[cpu_id];
		cap_sum += cap_cpu >> LAVD_CC_PER_CORE_SHIFT;
		if (cap_sum >= req_cap)
			return i+1;
	}

	/* Should not be here. */
	return nr_cpu_ids;
}

static void do_core_compaction(void)
{
	const volatile u16 *cpu_order = get_cpu_order();
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw, *cd_cpumask;
	struct cpdom_ctx *cpdomc;
	int nr_active, nr_active_old, cpu, i;
	u32 sum_capacity = 0, big_capacity = 0;
	bool clear;
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
	 * Assign active and overflow cores
	 */
	nr_active_old = sys_stat.nr_active;
	nr_active = calc_nr_active_cpus();
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

			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpu]);
			if (cpdomc)
				WRITE_ONCE(cpdomc->is_active, true);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

			/*
			 * Calculate big capacity ratio among active cores.
			 */
			sum_capacity += cpuc->capacity;
			if (cpuc->big_core)
				big_capacity += cpuc->capacity;
		} else if (i < nr_active_old) {
			bpf_cpumask_clear_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);
		} else {
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
			bpf_cpumask_clear_cpu(cpu, active);
			clear = clear_cpu_periodically(cpu, ovrflw);
			if (!clear)
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		}
	}

	cur_big_core_scale = (big_capacity << LAVD_SHIFT) / sum_capacity;
	sys_stat.nr_active = nr_active;

	/*
	 * Maintain cpdomc->is_active reflecting the active set.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
		if (!cpdomc || !cd_cpumask || !cpdomc->is_active)
			continue;

		if (!bpf_cpumask_intersects(cast_mask(active), cast_mask(cd_cpumask)))
			WRITE_ONCE(cpdomc->is_active, false);
	}

unlock_out:
	bpf_rcu_read_unlock();
}

static void update_power_mode_time(void)
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
}


static int do_set_power_profile(s32 pm, int util)
{
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
	switch (pm) {
	case LAVD_PM_PERFORMANCE:
		no_core_compaction = true;
		no_freq_scaling = false;
		no_prefer_turbo_core = false;
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
		debugln("Set the scheduler's power profile to performance mode: %d", util);
		break;
	case LAVD_PM_BALANCED:
		no_core_compaction = false;
		no_freq_scaling = false;
		no_prefer_turbo_core = false;
		is_powersave_mode = false;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to balanced mode: %d", util);
		break;
	case LAVD_PM_POWERSAVE:
		no_core_compaction = false;
		no_freq_scaling = false;
		no_prefer_turbo_core = true;
		is_powersave_mode = true;
		reinit_cpumask_for_performance = false;
		debugln("Set the scheduler's power profile to power-save mode: %d", util);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int do_autopilot(void)
{
	/*
	 * If the CPU utiulization is very low (say <= 5%), it means high
	 * performance is not required. We run the scheduler in powersave mode
	 * to save energy consumption.
	 */
	if (sys_stat.avg_util <= LAVD_AP_LOW_UTIL)
		return do_set_power_profile(LAVD_PM_POWERSAVE, sys_stat.avg_util);

	/*
	 * If the CPU utiulization is moderate (say > 5%, <= 30%), we run the
	 * scheduler in balanced mode. Actually, balanced mode can save energy
	 * consumption only under moderate CPU load.
	 */
	if (sys_stat.avg_util <= LAVD_AP_HIGH_UTIL)
		return do_set_power_profile(LAVD_PM_BALANCED, sys_stat.avg_util);

	/*
	 * If the CPU utilization is high enough (say > 30%), we run the
	 * scheduler in performance mode. The system indeed needs perrformance
	 * also there is little energy benefit even under balanced mode anyway.
	 */
	return do_set_power_profile(LAVD_PM_PERFORMANCE, sys_stat.avg_util);
}

static void update_thr_perf_cri(void)
{
	u32 little_core_scale, delta, diff, thr;

	if (no_core_compaction || !have_little_core)
		cur_big_core_scale = default_big_core_scale;

	/*
	 * If all active cores are big, all tasks should run on the big cores.
	 */
	if (cur_big_core_scale == LAVD_SCALE) {
		sys_stat.thr_perf_cri = 0;
		return;
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
		delta = sys_stat.avg_perf_cri - sys_stat.min_perf_cri;
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
		 */
		delta = sys_stat.max_perf_cri - sys_stat.avg_perf_cri;
		diff = (delta * cur_big_core_scale) >> LAVD_SHIFT;
		thr = sys_stat.max_perf_cri - diff;
	}

	sys_stat.thr_perf_cri = thr;
}

static int reinit_active_cpumask_for_performance(void)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	const struct cpumask *online_cpumask;
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
			if (!cpuc) {
				err = -ESRCH;
				goto unlock_out;
			}

			if (cpuc->big_core) {
				bpf_cpumask_set_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			}
			else {
				bpf_cpumask_set_cpu(cpu, ovrflw);
				bpf_cpumask_clear_cpu(cpu, active);
			}
		}
	} else {
		online_cpumask = scx_bpf_get_online_cpumask();
		nr_cpus_onln = bpf_cpumask_weight(online_cpumask);
		bpf_cpumask_copy(active, online_cpumask);
		scx_bpf_put_cpumask(online_cpumask);

		bpf_cpumask_clear(ovrflw);
	}
	sys_stat.nr_active = nr_cpus_onln;

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

static void update_cpuperf_target(struct cpu_ctx *cpuc)
{
	u32 util, cpuperf_target;

	/*
	 * The CPU utilization decides the frequency. The bigger one between
	 * the running average and the recent utilization is used to respond
	 * quickly upon load spikes. When the utilization is greater than
	 * LAVD_CPU_UTIL_MAX_FOR_CPUPERF (85%), ceil to 100%.
	 */
	if (!no_freq_scaling) {
		util = max(cpuc->avg_util, cpuc->cur_util) <
			LAVD_CPU_UTIL_MAX_FOR_CPUPERF? : LAVD_SCALE;
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
}

static void reset_cpuperf_target(struct cpu_ctx *cpuc)
{
	if (!no_freq_scaling) {
		cpuc->cpuperf_cur = 0;
	}
}

static u16 get_cpuperf_cap(s32 cpu)
{
	if (cpu >= 0 && cpu < nr_cpu_ids && cpu < LAVD_CPU_ID_MAX)
		return cpu_capacity[cpu];

	debugln("Infeasible CPU id: %d", cpu);
	return 0;
}

static u16 get_cputurbo_cap(void)
{
	u16 turbo_cap = 0;
	int nr_turbo = 0, cpu;

	/*
	 * Find the maximum CPU capacity
	 */
	for (cpu = 0; cpu < nr_cpu_ids && cpu < LAVD_CPU_ID_MAX; cpu++) {
		if (cpu_capacity[cpu] > turbo_cap) {
			turbo_cap = cpu_capacity[cpu];
			nr_turbo++;
		}
	}

	/*
	 * If all CPU's capacities are the same, ignore the turbo.
	 */
	if (nr_turbo <= 1)
		turbo_cap = 0;

	return turbo_cap;
}

static u64 scale_cap_freq(u64 dur, s32 cpu)
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

static void init_autopilot_low_util(void)
{
	if (nr_cpus_big < nr_cpus_onln) {
		/*
		 * When there are little cores, we move up to the balanced mode
		 * if one little core is fully utilized.
		 */
		LAVD_AP_LOW_UTIL = LAVD_SCALE / nr_cpus_onln;
	}
	else {
		/*
		 * When there are only big cores, we move up to the balanced
		 * mode if two big cores are fully utilized.
		 */
		LAVD_AP_LOW_UTIL = (2 * LAVD_SCALE) / nr_cpus_onln;
	}
}

SEC("syscall")
int set_power_profile(struct power_arg *input)
{
	return do_set_power_profile(input->power_mode, 0);
}


