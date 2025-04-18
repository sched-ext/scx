/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

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
} update_timer SEC(".maps");

struct sys_stat_ctx {
	u64		now;
	u64		duration;
	u64		duration_total;
	u64		idle_total;
	u64		compute_total;
	u64		tot_svc_time;
	u64		tot_sc_time;
	u64		nr_queued_task;
	s32		max_lat_cri;
	s32		avg_lat_cri;
	u64		sum_lat_cri;
	u32		nr_sched;
	u32		nr_perf_cri;
	u32		nr_lat_cri;
	u32		nr_x_migration;
	u32		nr_stealee;
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
	c->duration = c->now - sys_stat.last_update_clk;
	sys_stat.last_update_clk = c->now;
}

static void plan_x_cpdom_migration(struct sys_stat_ctx *c)
{
	struct cpdom_ctx *cpdomc;
	u64 dsq_id;
	u32 avg_nr_q_tasks_per_cpu = 0, nr_q_tasks, x_mig_delta;
	u32 stealer_threshold, stealee_threshold;

	/*
	 * Calcualte average queued tasks per CPU per compute domain.
	 */
	bpf_for(dsq_id, 0, nr_cpdoms) {
		if (dsq_id >= LAVD_CPDOM_MAX_NR)
			break;

		nr_q_tasks = scx_bpf_dsq_nr_queued(dsq_id);
		c->nr_queued_task += nr_q_tasks;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
		cpdomc->nr_q_tasks_per_cpu = (nr_q_tasks << LAVD_SHIFT) / cpdomc->nr_cpus;
		avg_nr_q_tasks_per_cpu += cpdomc->nr_q_tasks_per_cpu;
	}
	avg_nr_q_tasks_per_cpu /= nr_cpdoms;

	/*
	 * Determine stealer and stealee domains.
	 *
	 * A stealer domain, whose per-CPU queue length is shorter than
	 * the average, will steal a task from any of stealee domain,
	 * whose per-CPU queue length is longer than the average.
	 * Compute domain around average will not do anything.
	 */
	x_mig_delta = avg_nr_q_tasks_per_cpu >> LAVD_CPDOM_MIGRATION_SHIFT;
	stealer_threshold = avg_nr_q_tasks_per_cpu - x_mig_delta;
	stealee_threshold = avg_nr_q_tasks_per_cpu + x_mig_delta;

	bpf_for(dsq_id, 0, nr_cpdoms) {
		if (dsq_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);

		if (cpdomc->nr_q_tasks_per_cpu < stealer_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, true);
			WRITE_ONCE(cpdomc->is_stealee, false);
		}
		else if (cpdomc->nr_q_tasks_per_cpu > stealee_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, true);
			c->nr_stealee++;
		}
		else {
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, false);
		}
	}
}

static void collect_sys_stat(struct sys_stat_ctx *c)
{
	int cpu;

	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			c->compute_total = 0;
			break;
		}

		/*
		 * Accumulate cpus' loads.
		 */
		c->tot_svc_time += cpuc->tot_svc_time;
		cpuc->tot_svc_time = 0;

		/*
		 * Update scaled CPU utilization,
		 * which is capacity and frequency invariant.
		 */
		cpuc->cur_sc_util = (cpuc->tot_sc_time << LAVD_SHIFT) / c->duration;
		cpuc->avg_sc_util = calc_avg(cpuc->avg_sc_util, cpuc->cur_sc_util);

		/*
		 * Accumulate cpus' scaled loads,
		 * whcih is capacity and frequency invariant.
		 */
		c->tot_sc_time += cpuc->tot_sc_time;
		cpuc->tot_sc_time = 0;

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

		if (cpuc->max_lat_cri > c->max_lat_cri)
			c->max_lat_cri = cpuc->max_lat_cri;
		cpuc->max_lat_cri = 0;

		/*
		 * Accumulate task's performance criticlity information.
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
		 * If the CPU is in an idle state (i.e., idle_start_clk is
		 * non-zero), accumulate the current idle peirod so far.
		 */
		for (int i = 0; i < LAVD_MAX_RETRY; i++) {
			u64 old_clk = cpuc->idle_start_clk;
			if (old_clk == 0)
				break;

			bool ret = __sync_bool_compare_and_swap(
					&cpuc->idle_start_clk, old_clk, c->now);
			if (ret) {
				cpuc->idle_total += time_delta(c->now, old_clk);
				break;
			}
		}

		/*
		 * Calculcate per-CPU utilization
		 */
		u64 compute = 0;
		if (c->duration > cpuc->idle_total)
			compute = c->duration - cpuc->idle_total;

		cpuc->cur_util = (compute << LAVD_SHIFT) / c->duration;
		cpuc->avg_util = calc_asym_avg(cpuc->avg_util, cpuc->cur_util);

		/*
		 * Accmulate system-wide idle time
		 */
		c->idle_total += cpuc->idle_total;
		cpuc->idle_total = 0;
	}
}

static u64 clamp_time_slice_ns(u64 slice)
{
	if (slice < slice_min_ns)
		slice = slice_min_ns;
	else if (slice > slice_max_ns)
		slice = slice_max_ns;
	return slice;
}

static void calc_sys_stat(struct sys_stat_ctx *c)
{
	static int cnt = 0;
	u64 avg_svc_time = 0;

	c->duration_total = c->duration * nr_cpus_onln;
	if (c->duration_total > c->idle_total)
		c->compute_total = c->duration_total - c->idle_total;
	else
		c->compute_total = 0;
	c->cur_util = (c->compute_total << LAVD_SHIFT) / c->duration_total;
	c->cur_sc_util = (c->tot_sc_time << LAVD_SHIFT) / c->duration_total;

	if (c->nr_sched == 0) {
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
				sys_stat.avg_lat_cri) >> 1);

	if (have_little_core) {
		sys_stat.min_perf_cri =
			calc_avg32(sys_stat.min_perf_cri, c->min_perf_cri);
		sys_stat.avg_perf_cri =
			calc_avg32(sys_stat.avg_perf_cri, c->avg_perf_cri);
		sys_stat.max_perf_cri =
			calc_avg32(sys_stat.max_perf_cri, c->max_perf_cri);
	}

	sys_stat.nr_stealee = c->nr_stealee;

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
	u64 nr_queued, slice;

	/*
	 * Given the updated state, recalculate the time slice for the next
	 * round. The time slice should be short enough to schedule all
	 * runnable tasks at least once within a targeted latency using the
	 * active CPUs.
	 */
	nr_queued = sys_stat.nr_queued_task + 1;
	slice = (LAVD_TARGETED_LATENCY_NS * sys_stat.nr_active) / nr_queued;
	slice = clamp_time_slice_ns(slice);
	sys_stat.slice = calc_avg(sys_stat.slice, slice);
}

static void do_update_sys_stat(void)
{
	struct sys_stat_ctx c;

	init_sys_stat_ctx(&c);
	plan_x_cpdom_migration(&c);
	collect_sys_stat(&c);
	calc_sys_stat(&c);
}

static void update_sys_stat(void)
{
	do_update_sys_stat();

	if (is_autopilot_on)
		do_autopilot();

	if (!no_core_compaction)
		do_core_compaction();

	calc_sys_time_slice();
	update_thr_perf_cri();

	if (reinit_cpumask_for_performance) {
		reinit_cpumask_for_performance = false;
		reinit_active_cpumask_for_performance();
	}
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

static s32 init_sys_stat(u64 now)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	sys_stat.last_update_clk = now;
	sys_stat.nr_active = nr_cpus_onln;

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


