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
const volatile u16	__cpu_capacity_hint[LAVD_CPU_ID_MAX]; /* CPU capacity based on 1000 */
struct cpdom_ctx	cpdom_ctxs[LAVD_CPDOM_MAX_NR]; /* contexts for compute domains */
static int		nr_cpdoms; /* number of compute domains */


/*
 * Big core's compute ratio among currently active cores
 */
static u32		cur_big_core_ratio;

/*
 * Big core's compute ratio when all cores are active
 */
static u32		default_big_core_ratio;

/*
 * Statistics
 */
volatile int		power_mode;
volatile u64		last_power_mode_clk;
volatile u64		performance_mode_ns;
volatile u64		balanced_mode_ns;
volatile u64		powersave_mode_ns;

static bool is_perf_cri(struct task_ctx *taskc, struct sys_stat *stat_cur)
{
	if (!have_little_core)
		return true;

	if (READ_ONCE(taskc->on_big) && READ_ONCE(taskc->on_little))
		return taskc->perf_cri >= stat_cur->thr_perf_cri;
	return READ_ONCE(taskc->on_big);
}

static u64 calc_nr_active_cpus(struct sys_stat *stat_cur)
{
	u64 nr_active;

	/*
	 * nr_active = ceil(nr_cpus_onln * cpu_util * per_core_max_util)
	 */
	nr_active  = (nr_cpus_onln * stat_cur->util * 1000) + 500;
	nr_active /= (LAVD_CC_PER_CORE_MAX_CTUIL * 1000);

	/*
	 * If a few CPUs are particularly busy, boost the active CPUs more.
	 */
	nr_active += min(LAVD_CC_NR_OVRFLW, (stat_cur->nr_violation) / 1000);
	nr_active = max(min(nr_active, nr_cpus_onln),
			LAVD_CC_NR_ACTIVE_MIN);

	return nr_active;
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

static void do_core_compaction(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
	int nr_cpus, nr_active, nr_active_old, cpu, i;
	u32 sum_capacity = 0, big_capacity = 0;
	bool clear;
	const volatile u16 *cpu_order;

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
	 * Decide a cpuorder to use according to its power mode.
	 */
	if (is_powersave_mode)
		cpu_order = cpu_order_powersave;
	else
		cpu_order = cpu_order_performance;

	/*
	 * Assign active and overflow cores
	 */
	nr_active_old = stat_cur->nr_active;
	nr_active = calc_nr_active_cpus(stat_cur);
	nr_cpus = nr_active + LAVD_CC_NR_OVRFLW;
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
		if (i < nr_cpus) {
			if (i < nr_active) {
				bpf_cpumask_set_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			}
			else {
				bpf_cpumask_set_cpu(cpu, ovrflw);
				bpf_cpumask_clear_cpu(cpu, active);
			}
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

			/*
			 * Calculate big capacity ratio among active cores.
			 */
			sum_capacity += cpuc->capacity;
			if (cpuc->big_core)
				big_capacity += cpuc->capacity;
		}
		else {
			if (i < nr_active_old) {
				bpf_cpumask_clear_cpu(cpu, active);
				bpf_cpumask_clear_cpu(cpu, ovrflw);
			}
			else {
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
	}

	cur_big_core_ratio = (1000 * big_capacity) / sum_capacity;
	stat_cur->nr_active = nr_active;

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
	struct sys_stat *stat_cur = get_sys_stat_cur();

	/*
	 * If the CPU utiulization is very low (say <= 5%), it means high
	 * performance is not required. We run the scheduler in powersave mode
	 * to save energy consumption.
	 */
	if (stat_cur->util <= LAVD_AP_LOW_UTIL)
		return do_set_power_profile(LAVD_PM_POWERSAVE, stat_cur->util);

	/*
	 * If the CPU utiulization is moderate (say > 5%, <= 30%), we run the
	 * scheduler in balanced mode. Actually, balanced mode can save energy
	 * consumption only under moderate CPU load.
	 */
	if (stat_cur->util <= LAVD_AP_HIGH_UTIL)
		return do_set_power_profile(LAVD_PM_BALANCED, stat_cur->util);

	/*
	 * If the CPU utilization is high enough (say > 30%), we run the
	 * scheduler in performance mode. The system indeed needs perrformance
	 * also there is little energy benefit even under balanced mode anyway.
	 */
	return do_set_power_profile(LAVD_PM_PERFORMANCE, stat_cur->util);
}

static void update_thr_perf_cri(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	u32 little_core_ratio, delta, diff, thr;

	if (no_core_compaction || !have_little_core)
		cur_big_core_ratio = default_big_core_ratio;

	/*
	 * If all active cores are big, all tasks should run on the big cores.
	 */
	if (cur_big_core_ratio == 1000) {
		stat_cur->thr_perf_cri = 0;
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
	 *   |            |                    1000
	 *   |            1000 - big_core_ratio (i.e., little_core_ratio)
	 *   0
	 */
	little_core_ratio = 1000 - cur_big_core_ratio;
	if (little_core_ratio < 500) {
		/*
		 *   min_perf_cri
		 *   |         avg_perf_cri
		 *   |         |                       max_perf_cri
		 *   |         |                       |
		 *   <--------><----------------------->
		 *
		 *   <-///-><-------------------------->
		 *   |     |                           |
		 *   |     |                           1000
		 *   |     little_core_ratio
		 *   0
		 */
		delta = stat_cur->avg_perf_cri - stat_cur->min_perf_cri;
		diff = (delta * little_core_ratio) / 1000;
		thr = diff + stat_cur->min_perf_cri;
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
		 *   |                     |           1000
		 *   |                     little_core_ratio
		 *   0
		 */
		delta = stat_cur->max_perf_cri - stat_cur->avg_perf_cri;
		diff = (delta * cur_big_core_ratio) / 1000;
		thr = stat_cur->max_perf_cri - diff;
	}

	stat_cur->thr_perf_cri = thr;
}

static int reinit_active_cpumask_for_performance(void)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *active, *ovrflw;
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
	 * Once core compaction becomes off in performance mode,
	 * reinitialize active/overflow cpumasks to reflect the mode change.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
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

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

static int calc_cpuperf_target(struct sys_stat *stat_cur,
			       struct task_ctx *taskc, struct cpu_ctx *cpuc)
{
	u64 max_load, cpu_load;
	u32 cpuperf_target;

	if (!stat_cur || !taskc || !cpuc)
		return -EINVAL;

	if (no_freq_scaling) {
		cpuc->cpuperf_task = SCX_CPUPERF_ONE;
		cpuc->cpuperf_avg = SCX_CPUPERF_ONE;
		return 0;
	}

	/*
	 * We determine the clock frequency of a CPU using two factors: 1) the
	 * current CPU utilization (cpuc->util) and 2) the current task's
	 * performance criticality (taskc->perf_cri) compared to the
	 * system-wide average performance criticality
	 * (stat_cur->thr_perf_cri).
	 *
	 * When a current CPU utilization is 85% and the current task's
	 * performance criticality is the same as the system-wide average
	 * criticality, we set the target CPU frequency to the maximum.
	 *
	 * In other words, even if CPU utilization is not so high, the target
	 * CPU frequency could be high when the task's performance criticality
	 * is high enough (i.e., boosting CPU frequency). On the other hand,
	 * the target CPU frequency could be low even if CPU utilization is
	 * high when a non-performance-critical task is running (i.e.,
	 * deboosting CPU frequency).
	 */
	max_load = stat_cur->thr_perf_cri * LAVD_CPU_UTIL_MAX_FOR_CPUPERF;
	cpu_load = taskc->perf_cri * cpuc->util;
	cpuperf_target = (cpu_load * SCX_CPUPERF_ONE) / max_load;
	cpuperf_target = min(cpuperf_target, SCX_CPUPERF_ONE);

	cpuc->cpuperf_task = cpuperf_target;
	cpuc->cpuperf_avg = calc_avg32(cpuc->cpuperf_avg, cpuperf_target);
	return 0;
}

static bool try_increase_cpuperf_target(struct cpu_ctx *cpuc)
{
	/*
	 * When a task becomes running, update CPU's performance target only
	 * when the current task's target performance is higher. This helps
	 * rapidly adopt workload changes by rapidly increasing CPU's
	 * performance target.
	 */
	u32 target;

	if (!cpuc)
		return false;

	target = max(cpuc->cpuperf_task, cpuc->cpuperf_avg);
	if (cpuc->cpuperf_cur < target) {
		cpuc->cpuperf_cur = target;
		scx_bpf_cpuperf_set(cpuc->cpu_id, target);
		return true;
	}

	return false;
}

static bool try_decrease_cpuperf_target(struct cpu_ctx *cpuc)
{
	/*
	 * Upon every tick interval, we try to decrease the CPU's performance
	 * target if the current one is higher than both the current task's
	 * target and EWMA of past targets. This helps gradually adopt workload
	 * changes upon sudden down falls.
	 */
	u32 target;

	if (!cpuc)
		return false;

	target = max(cpuc->cpuperf_task, cpuc->cpuperf_avg);
	if (cpuc->cpuperf_cur != target) {
		cpuc->cpuperf_cur = target;
		scx_bpf_cpuperf_set(cpuc->cpu_id, target);
		return true;
	}

	return false;
}

static u16 get_cpuperf_cap(s32 cpu)
{
	if (cpu >= 0 && cpu < nr_cpu_ids && cpu < LAVD_CPU_ID_MAX)
		return __cpu_capacity_hint[cpu];

	debugln("Infeasible CPU id: %d", cpu);
	return 0;
}

static u16 get_cputurbo_cap(void)
{
	u16 turbo_cap = 0;
	int nr_turbo = 0, cpu;

	/*
	 * Find the maximum CPU frequency
	 */
	for (cpu = 0; cpu < nr_cpu_ids && cpu < LAVD_CPU_ID_MAX; cpu++) {
		if (__cpu_capacity_hint[cpu] > turbo_cap) {
			turbo_cap = __cpu_capacity_hint[cpu];
			nr_turbo++;
		}
	}

	/*
	 * If all CPU's frequencies are the same, ignore the turbo.
	 */
	if (nr_turbo <= 1)
		turbo_cap = 0;

	return turbo_cap;
}

static void init_autopilot_low_util(void)
{
	if (nr_cpus_big < nr_cpus_onln) {
		/*
		 * When there are little cores, we move up to the balanced mode
		 * if one little core is fully utilized.
		 */
		LAVD_AP_LOW_UTIL = 1000 / nr_cpus_onln;
	}
	else {
		/*
		 * When there are only big cores, we move up to the balanced
		 * mode if two big cores are fully utilized.
		 */
		LAVD_AP_LOW_UTIL = (2 * 1000) / nr_cpus_onln;
	}
}

SEC("syscall")
int set_power_profile(struct power_arg *input)
{
	return do_set_power_profile(input->power_mode, 0);
}


