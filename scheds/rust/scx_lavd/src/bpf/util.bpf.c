/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "power.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * To be included to the main.bpf.c
 */

/*
 * Sched related globals
 */
private(LAVD) struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
private(LAVD) struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
private(LAVD) struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
private(LAVD) struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */
private(LAVD) struct bpf_cpumask __kptr *steady_cpumask; /* CPU mask for non-turbulent (steady) CPUs */

const volatile u64	nr_llcs;	/* number of LLC domains */
volatile u64		nr_cpus_onln;	/* current number of online CPUs */

const volatile u32	cpu_sibling[LAVD_CPU_ID_MAX]; /* siblings for CPUs when SMT is active */

/*
 * Options
 */
volatile bool		reinit_cpumask_for_performance;
volatile bool		no_preemption;
volatile bool		no_core_compaction;
volatile bool		no_freq_scaling;

const volatile bool	no_wake_sync;
const volatile bool	no_slice_boost;
const volatile bool	per_cpu_dsq;
const volatile bool	enable_cpu_bw;
const volatile bool	is_autopilot_on;
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

__hidden
u64 __get_task_ctx_slowpath(struct task_struct __arg_trusted *p,
			    struct cpu_ctx *cpuc)
{
	u64 raw = (u64)scx_task_data(p);

	if (cpuc && raw) {
		cpuc->cached_task = (u64)p;
		cpuc->cached_pid = p->pid;
		cpuc->cached_taskc_raw = raw;
	}
	return raw;
}

__hidden
struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
}

__hidden
struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu_id);
}

__hidden
struct cpu_ctx *get_cpu_ctx_task(const struct task_struct *p)
{
	return get_cpu_ctx_id(scx_bpf_task_cpu(p));
}

__hidden
u32 __attribute__ ((noinline)) calc_avg32(u32 old_val, u32 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.875 * old) + (0.125 * new)
	 */
	return __calc_avg(old_val, new_val, 3);
}

__hidden
u64 __attribute__ ((noinline)) calc_avg(u64 old_val, u64 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.875 * old) + (0.125 * new)
	 */
	return __calc_avg(old_val, new_val, 3);
}

__hidden
u64 __attribute__ ((noinline)) calc_asym_avg(u64 old_val, u64 new_val)
{
	/*
	 * Increase fast but decrease slowly.
	 */
	if (old_val < new_val)
		return __calc_avg(new_val, old_val, 2);
	else
		return __calc_avg(old_val, new_val, 3);
}

__hidden
u64 __attribute__ ((noinline)) calc_avg_freq(u64 old_freq, u64 interval)
{
	u64 new_freq, ewma_freq;

	/*
	 * Calculate the exponential weighted moving average (EWMA) of a
	 * frequency with a new interval measured.
	 */
	new_freq = LAVD_TIME_ONE_SEC / interval;
	ewma_freq = __calc_avg(old_freq, new_freq, 3);
	return ewma_freq;
}

__hidden
bool is_kernel_task(struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

__hidden
bool is_kernel_worker(struct task_struct *p)
{
	return !!(p->flags & (PF_WQ_WORKER | PF_IO_WORKER));
}

__hidden
bool is_ksoftirqd(struct task_struct *p)
{
	return is_kernel_task(p) && !__builtin_memcmp(p->comm, "ksoftirqd/", 10);
}

__hidden
bool is_permanently_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
}

__hidden
bool is_effectively_pinned(task_ctx __arg_arena *taskc)
{
	return test_task_flag(taskc, LAVD_FLAG_IS_EFFECTIVELY_PINNED);
}

__hidden
bool test_task_flag(task_ctx __arg_arena *taskc, u64 flag)
{
	return (taskc->flags & flag) == flag;
}

__hidden
bool test_task_flag_mask(task_ctx __arg_arena *taskc, u64 flag)
{
	return (taskc->flags & flag);
}

__hidden
void set_task_flag(task_ctx __arg_arena *taskc, u64 flag)
{
	taskc->flags |= flag;
}

__hidden
void reset_task_flag(task_ctx __arg_arena *taskc, u64 flag)
{
	taskc->flags &= ~flag;
}

__hidden
inline bool test_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	return (cpuc->flags & flag) == flag;
}

__hidden
inline void set_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	cpuc->flags |= flag;
}

__hidden
inline void reset_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	cpuc->flags &= ~flag;
}

__hidden
bool is_lat_cri(task_ctx __arg_arena *taskc)
{
	return taskc->lat_cri >= sys_stat.avg_lat_cri;
}

__hidden
bool is_lock_holder(task_ctx __arg_arena *taskc)
{
	return test_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST);
}

__hidden
bool is_lock_holder_running(struct cpu_ctx *cpuc)
{
	return test_cpu_flag(cpuc, LAVD_FLAG_FUTEX_BOOST);
}

bool have_scheduled(task_ctx __arg_arena *taskc)
{
	/*
	 * If task's time slice hasn't been updated, that means the task has
	 * been scheduled by this scheduler.
	 */
	return taskc->slice_wall != 0;
}

__hidden
bool can_boost_slice(void)
{
	/*
	 * When CPU utilization is too high (>= 95%), do not boost the
	 * time slice. Checking the number of queued tasks alone is not
	 * sufficient, especially when many tasks are slice-boosted and
	 * unlikely relinquish CPUs soon.
	 */
	return (sys_stat.avg_util_wall <= LAVD_SLICE_BOOST_UTIL_WALL) &&
	       (sys_stat.nr_queued_task <= sys_stat.nr_active);
}

__hidden
u16 get_nice_prio(struct task_struct __arg_trusted *p)
{
	u16 prio = p->static_prio - MAX_RT_PRIO; /* [0, 40) */
	return prio;
}

__hidden
bool use_full_cpus(void)
{
	return sys_stat.nr_active >= nr_cpus_onln;
}

__hidden
void set_affinity_flags(task_ctx __arg_arena *taskc,
			const struct cpumask *cpumask)
{
	bool is_affinitized, dom_pinned, dom_pinned_settled;
	bool on_big = false, on_little = false;
	s32 first_cpdom_id = -ENOENT;
	struct cpu_ctx *cpuc;
	u32 weight;
	int cpu;

	if (!cpumask)
		return;

	weight = bpf_cpumask_weight(cpumask);
	is_affinitized = weight != nr_cpu_ids;
	if (weight == 1)
		set_task_flag(taskc, LAVD_FLAG_IS_EFFECTIVELY_PINNED);
	else
		reset_task_flag(taskc, LAVD_FLAG_IS_EFFECTIVELY_PINNED);
	if (nr_cpdoms == 1) {
		dom_pinned = false;
		dom_pinned_settled = true;
	} else {
		dom_pinned = is_affinitized;
		dom_pinned_settled = !is_affinitized;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= LAVD_CPU_ID_MAX)
			break;

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

		/*
		 * Track whether the task is domain-pinned: confined to a
		 * single compute domain. On the first CPU seen, record its
		 * domain. On any subsequent CPU in a different domain, the
		 * task spans multiple domains and is not domain-pinned.
		 */
		if (!dom_pinned_settled) {
			if (first_cpdom_id < 0)
				first_cpdom_id = cpuc->cpdom_id;
			else if (cpuc->cpdom_id != first_cpdom_id) {
				dom_pinned = false;
				dom_pinned_settled = true;
			}
		}

		if (on_big && on_little && dom_pinned_settled)
			break;
	}

	if (is_affinitized)
		set_task_flag(taskc, LAVD_FLAG_IS_AFFINITIZED);
	else
		reset_task_flag(taskc, LAVD_FLAG_IS_AFFINITIZED);

	if (on_big)
		set_task_flag(taskc, LAVD_FLAG_ON_BIG);
	else
		reset_task_flag(taskc, LAVD_FLAG_ON_BIG);

	if (on_little)
		set_task_flag(taskc, LAVD_FLAG_ON_LITTLE);
	else
		reset_task_flag(taskc, LAVD_FLAG_ON_LITTLE);

	if (dom_pinned)
		set_task_flag(taskc, LAVD_FLAG_DOMAIN_PINNED);
	else
		reset_task_flag(taskc, LAVD_FLAG_DOMAIN_PINNED);
}

__hidden
bool __attribute__ ((noinline)) prob_x_out_of_y(u32 x, u32 y)
{
	u32 r;

	if (x >= y)
		return true;

	/*
	 * [0, r, y)
	 *  ---- x?
	 */
	r = bpf_get_prandom_u32() % y;
	return r < x;
}
/*
 * We define the primary cpu in the physical core as the lowest logical cpu id.
 */
__hidden
u32 __attribute__ ((noinline)) get_primary_cpu(u32 cpu) {
	const volatile u32 *sibling;

	if (!is_smt_active)
		return cpu;

	sibling = MEMBER_VPTR(cpu_sibling, [cpu]);
	if (!sibling) {
		debugln("Infeasible CPU id: %d", cpu);
		return cpu;
	}

	return ((cpu < *sibling) ? cpu : *sibling);
}

__hidden
u32 cpu_to_dsq(u32 cpu)
{
	return (get_primary_cpu(cpu)) | LAVD_DSQ_TYPE_CPU << LAVD_DSQ_TYPE_SHFT;
}

__hidden
bool queued_on_cpu(struct cpu_ctx *cpuc)
{
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpuc->cpu_id))
		return true;

	if (use_per_cpu_dsq() && scx_bpf_dsq_nr_queued(cpu_to_dsq(cpuc->cpu_id)))
		return true;

	if (use_cpdom_dsq() && scx_bpf_dsq_nr_queued(cpdom_to_dsq(cpuc->cpdom_id)))
		return true;

	if (use_cpdom_dsq() && scx_bpf_dsq_nr_queued(cpdom_to_turb_dsq(cpuc->cpdom_id)))
		return true;

	return false;
}

__hidden
u64 peek_dsq_vtime(u64 dsq_id)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	return p ? p->scx.dsq_vtime : U64_MAX;
}

__hidden
void sort_dsqs(struct dsq_entry *a, struct dsq_entry *b,
	       struct dsq_entry *c)
{
	struct dsq_entry t;

	if (b->vtime < a->vtime) { t = *a; *a = *b; *b = t; }
	if (c->vtime < b->vtime) { t = *b; *b = *c; *c = t; }
	if (b->vtime < a->vtime) { t = *a; *a = *b; *b = t; }
}

__hidden
u64 get_target_dsq_id(struct task_struct *p, struct cpu_ctx *cpuc, task_ctx *taskc)
{
	struct cpdom_ctx *cpdomc;

	/*
	 * Route effectively pinned tasks (permanent pinning or
	 * migrate_disable) to the per-CPU DSQ when pinned_slice_ns is
	 * enabled, so the slice-shrinking heuristic in preempt.bpf.c can
	 * act on them consistently.
	 */
	if (per_cpu_dsq || (pinned_slice_ns && is_effectively_pinned(taskc)))
		return cpu_to_dsq(cpuc->cpu_id);

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
	if (cpdomc &&
	    preemption_vulnerability(taskc->normalized_lat_cri,
				    taskc->util_est) >= cpdomc->vuln_thresh)
		return cpdom_to_dsq(cpuc->cpdom_id);

	return cpdom_to_turb_dsq(cpuc->cpdom_id);
}

/**
 * normalize_lat_cri - Normalize latency criticality to 1024 scale
 * @lat_cri: The latency criticality value from task_ctx
 *
 * Normalizes the lat_cri value from the range [0, max_lat_cri] to [0, 1024].
 * Uses the system-wide max_lat_cri as the upper bound for normalization.
 *
 * Returns: Normalized value in range [0, 1024]
 */
__hidden
u16 normalize_lat_cri(u16 lat_cri)
{
	u32 max = sys_stat.max_lat_cri;

	/*
	 * Handle edge cases:
	 * - If max_lat_cri is 0, return 0 (no tasks have run yet)
	 * - If lat_cri >= max_lat_cri, return 1024 (maximum)
	 */
	if (max == 0)
		return 0;

	if (lat_cri >= max)
		return 1024;

	return (u16)(((u64)lat_cri << LAVD_SHIFT) / max);
}
