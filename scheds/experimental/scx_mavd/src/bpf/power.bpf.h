/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#pragma once

int do_core_compaction(void);
int update_thr_perf_cri(void);
int reinit_active_cpumask_for_performance(void);
bool is_perf_cri(task_ctx *taskc);

extern bool			have_little_core;
extern bool			have_turbo_core;
extern const volatile bool	is_smt_active;

extern u64			total_max_capacity;
extern u64			one_little_max_capacity;
extern u32			cur_big_core_scale;
extern u32			default_big_core_scale;

int init_autopilot_caps(void);
int update_autopilot_high_cap(void);

int calc_cpuperf_target(struct cpu_ctx *cpuc);
int update_cpuperf_target(struct cpu_ctx *cpuc);

const volatile u16 *get_cpu_order(void);
void update_effective_capacity(struct cpu_ctx *cpuc);

/*
 * Convert a wall-clock duration to invariant time using an observed
 * performance factor derived from a reference pair of measurements taken
 * over the same interval:
 *
 *   duration_invr = duration_wall * (ref_invr / ref_wall)
 *
 * This is more accurate than scaling by the cpuperf value at the current
 * instant because it uses the actual performance factor observed over the
 * measurement window rather than the instantaneous value.
 *
 * Typical use at collection point (collect_sys_stat):
 *   ref_wall = task_wall    (SCX + RT/DL wall time,   excl. IRQ+steal+idle)
 *   ref_invr = delta_pelt   (invariant task time,     excl. IRQ+steal+idle)
 *
 * Returns 0 if ref_wall is zero (CPU was entirely idle or preempted).
 */
static __inline u64 conv_wall_to_invr_obs(u64 duration_wall,
					  u64 ref_invr, u64 ref_wall)
{
	if (!ref_wall)
		return 0;
	return duration_wall * ref_invr / ref_wall;
}
