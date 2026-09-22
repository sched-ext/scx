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

extern bool __arena_global	have_little_core;
extern bool __arena_global	have_turbo_core;
extern const volatile bool	is_smt_active;

extern u64 __arena_global	total_max_capacity;
extern u64 __arena_global	one_little_max_capacity;
extern u32 __arena_global	cur_big_core_scale;
extern u32 __arena_global	default_big_core_scale;

int init_autopilot_caps(void);
int update_autopilot_high_cap(void);

int calc_cpuperf_target(struct cpu_ctx __arena __arg_arena *cpuc);
int update_cpuperf_target(struct cpu_ctx __arena __arg_arena *cpuc);

extern volatile int __arena_global	power_mode;
extern volatile bool __arena_global	is_powersave_mode;
extern u16 __arena_global	pco_table[LAVD_PCO_STATE_MAX][LAVD_CPU_ID_MAX];

const volatile u16 __arena *get_cpu_order(void);
void update_effective_capacity(struct cpu_ctx __arena __arg_arena *cpuc);

/*
 * Convert a wall-clock duration to invariant time using an observed
 * performance factor derived from a reference pair of measurements taken
 * over the same interval:
 *
 *   duration_invr = duration_wall * (ref_invr / ref_wall)
 *
 * This is more accurate than conv_wall_to_invr() (which queries cpuperf
 * at the current instant) because it uses the actual performance factor
 * observed over the measurement window rather than the instantaneous value.
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

static __inline u64 conv_wall_to_invr(u64 duration_wall, struct cpu_ctx __arena *cpuc)
{
	u64 cap, freq, duration_invr;
	s32 cpu;

	if (!cpuc)
		return duration_wall;

	cpu = cpuc->cid;
	if (cpu < 0 || cpu >= nr_cids)
		return duration_wall;

	/*
	 * Scale the duration by CPU capacity and frequency, so calculate
	 * capacity-invariant and frequency-invariant time duration.
	 */
	cap = cpuc->max_capacity;
	freq = scx_bpf_cidperf_cur(cpu);
	duration_invr = (duration_wall * cap * freq) >> (LAVD_SHIFT * 2);

	/*
	 * Keep track of the maximum frequency observed on this CPU.
	 * This will be used to estimate effective CPU capacity.
	 */
	if (freq > READ_ONCE(cpuc->max_freq_observed))
		WRITE_ONCE(cpuc->max_freq_observed, freq);

	return duration_invr;
}
