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
int update_cpufreq_rate_limit(struct cpu_ctx *cpuc);
int update_next_cpufreq_rate_limit(void);
int warn_cpufreq_rate_limit_err(void);
int update_cpuperf_target(struct cpu_ctx *cpuc, u32 demand, u64 now);
int refresh_cpuperf_target(struct cpu_ctx *cpuc, u64 now);
int decay_idle_cpuperf_target(struct cpu_ctx *cpuc, u64 now);

const volatile u16 *get_cpu_order(void);
void update_effective_capacity(struct cpu_ctx *cpuc);
