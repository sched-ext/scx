/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

/*
 * Sched related globals
 */
private(LAVD) struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
private(LAVD) struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
private(LAVD) struct bpf_cpumask __kptr *little_cpumask; /* CPU mask for little CPUs */
private(LAVD) struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
private(LAVD) struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */
private(LAVD) struct bpf_cpumask cpdom_cpumask[LAVD_CPDOM_MAX_NR]; /* CPU mask for each compute domain */
private(LAVD) struct bpf_cpumask padding; /* Padding to work around a verifier bug (?) */

const volatile u64	nr_cpu_ids;	/* maximum CPU IDs */
static volatile u64	nr_cpus_onln;	/* current number of online CPUs */
static volatile u64	nr_cpus_big;

struct sys_stat	__sys_stats[2];
volatile int	__sys_stat_idx;

/*
 * Options
 */
volatile bool		no_core_compaction;
volatile bool		no_freq_scaling;
volatile bool		no_prefer_turbo_core;
volatile bool		is_powersave_mode;
volatile bool		reinit_cpumask_for_performance;
const volatile bool	is_autopilot_on;
const volatile u32 	is_smt_active;
const volatile u8	verbose;

/*
 * Exit information
 */
UEI_DEFINE(uei);

/*
 * per-CPU globals
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Per-task scheduling context
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");


#define debugln(fmt, ...)						\
({									\
	if (verbose > 0)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__,		\
					##__VA_ARGS__);			\
})

#define traceln(fmt, ...)						\
({									\
	if (verbose > 1)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__,		\
					##__VA_ARGS__);			\
})

#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

static struct sys_stat *get_sys_stat_cur(void)
{
	if (READ_ONCE(__sys_stat_idx) == 0)
		return &__sys_stats[0];
	return &__sys_stats[1];
}

static struct sys_stat *get_sys_stat_next(void)
{
	if (READ_ONCE(__sys_stat_idx) == 0)
		return &__sys_stats[1];
	return &__sys_stats[0];
}

static void flip_sys_stat(void)
{
	WRITE_ONCE(__sys_stat_idx, __sys_stat_idx ^ 0x1);
}


static u64 sigmoid_u64(u64 v, u64 max)
{
	/*
	 * An integer approximation of the sigmoid function. It is convenient
	 * to use the sigmoid function since it has a known upper and lower
	 * bound, [0, max].
	 *
	 *      |
	 *	|      +------ <= max
	 *	|    /
	 *	|  /
	 *	|/
	 *	+------------->
	 */
	return (v > max) ? max : v;
}

static u64 rsigmoid_u64(u64 v, u64 max)
{
	/*
	 * A horizontally flipped version of sigmoid function. Again, it is
	 * convenient since the upper and lower bound of the function is known,
	 * [0, max].
	 *
	 *
	 *      |
	 *	|\ <= max
	 *	| \
	 *	|  \
	 *	|   \
	 *	+----+-------->
	 */
	return (v >= max) ? 0 : max - v;
}

static struct task_ctx *try_get_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

static struct task_ctx *get_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = try_get_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for %s[%d]",
			      p->comm, p->pid);
	return taskc;
}

struct task_ctx *try_get_current_task_ctx(void)
{
	struct task_struct *p = bpf_get_current_task_btf();
	struct task_ctx *taskc = try_get_task_ctx(p);

	return taskc;
}

static struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;
	struct cpu_ctx *cpuc;

	cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
	if (!cpuc)
		scx_bpf_error("cpu_ctx lookup failed for current cpu");

	return cpuc;
}

static struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id)
{
	const u32 idx = 0;
	struct cpu_ctx *cpuc;

	cpuc = bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu_id);
	if (!cpuc)
		scx_bpf_error("cpu_ctx lookup failed for %d", cpu_id);

	return cpuc;
}

static u32 calc_avg32(u32 old_val, u32 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.75 * old) + (0.25 * new)
	 */
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 calc_avg(u64 old_val, u64 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.75 * old) + (0.25 * new)
	 */
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 calc_avg_freq(u64 old_freq, u64 interval)
{
	u64 new_freq, ewma_freq;

	/*
	 * Calculate the exponential weighted moving average (EWMA) of a
	 * frequency with a new interval measured.
	 */
	new_freq = LAVD_TIME_ONE_SEC / interval;
	ewma_freq = calc_avg(old_freq, new_freq);
	return ewma_freq;
}

static bool is_kernel_task(struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

static bool is_lat_cri(struct task_ctx *taskc, struct sys_stat *stat_cur)
{
	return taskc->lat_cri >= stat_cur->avg_lat_cri;
}

static bool is_perf_cri(struct task_ctx *taskc, struct sys_stat *stat_cur)
{
	if (READ_ONCE(taskc->on_big) && READ_ONCE(taskc->on_little))
		return taskc->perf_cri >= stat_cur->thr_perf_cri;
	return READ_ONCE(taskc->on_big);
}

static bool is_greedy(struct task_ctx *taskc)
{
	return taskc->greedy_ratio > 1000;
}

static bool is_eligible(struct task_ctx *taskc)
{
	return !is_greedy(taskc);
}

static bool is_lock_holder(struct task_ctx *taskc)
{
	return (taskc->lock_boost > 0) || (taskc->futex_boost > 0);
}

static bool have_scheduled(struct task_ctx *taskc)
{
	/*
	 * If task's time slice hasn't been updated, that means the task has
	 * been scheduled by this scheduler.
	 */
	return taskc->slice_ns != 0;
}

static u16 get_nice_prio(struct task_struct *p)
{
	u16 prio = p->static_prio - MAX_RT_PRIO; /* [0, 40) */
	return prio;
}

static bool use_full_cpus(void)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	return (stat_cur->nr_active + LAVD_CC_NR_OVRFLW) >= nr_cpus_onln;
}

static u64 pick_any_bit(u64 bitmap, u64 nuance)
{
	u64 i, pos;

	bpf_for(i, 0, 64) {
		pos = (i + nuance) % 64;
		if (bitmap & (1LLU << pos))
			return pos;
	}

	return -ENOENT;
}

static void set_on_core_type(struct task_ctx *taskc,
			     const struct cpumask *cpumask)
{
	bool on_big = false, on_little = false;
	struct cpu_ctx *cpuc;
	int cpu;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, cpumask))
			continue;

		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to look up cpu_ctx: %d", cpu);
			return;
		}

		if (cpuc->big_core)
			on_big = true;
		else
			on_little = true;

		if (on_big && on_little)
			break;
	}

	WRITE_ONCE(taskc->on_big, on_big);
	WRITE_ONCE(taskc->on_little, on_little);
}
