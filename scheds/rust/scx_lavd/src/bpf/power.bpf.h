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
u64 scale_cap_max_freq(u64 dur, s32 cpu);

int reset_cpuperf_target(struct cpu_ctx *cpuc);
int update_cpuperf_target(struct cpu_ctx *cpuc);
u16 get_cpuperf_cap(s32 cpu);

int reset_suspended_duration(struct cpu_ctx *cpuc);
u64 get_suspended_duration_and_reset(struct cpu_ctx *cpuc);

const volatile u16 *get_cpu_order(void);
void update_effective_capacity(struct cpu_ctx *cpuc);

static __inline u64 scale_cap_freq(u64 dur, struct cpu_ctx *cpuc)
{
	u64 cap, freq, scaled_dur;
	s32 cpu;

	if (!cpuc)
		return dur;

	cpu = cpuc->cpu_id;
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return dur;

	/*
	 * Scale the duration by CPU capacity and frequency, so calculate
	 * capacity-invariant and frequency-invariant time duration.
	 */
	cap = get_cpuperf_cap(cpu);
	freq = scx_bpf_cpuperf_cur(cpu);
	scaled_dur = (dur * cap * freq) >> (LAVD_SHIFT * 2);

	/*
	 * Keep track of the maximum frequency observed on this CPU.
	 * This will be used to estimate effective CPU capacity.
	 */
	if (freq > READ_ONCE(cpuc->max_freq_observed))
		WRITE_ONCE(cpuc->max_freq_observed, freq);

	return scaled_dur;
}
