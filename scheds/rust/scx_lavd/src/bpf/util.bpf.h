/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UTIL_H
#define __UTIL_H

extern const volatile u64	nr_llcs;	/* number of LLC domains */
extern volatile u64		nr_cpus_onln;	/* current number of online CPUs */

extern const volatile u32	cpu_sibling[LAVD_CPU_ID_MAX]; /* siblings for CPUs when SMT is active */

/*
 * Scheduler parameters
 */
extern volatile bool		reinit_cpumask_for_performance;
extern volatile bool		no_preemption;
extern volatile bool		no_core_compaction;
extern volatile bool		no_freq_scaling;

extern const volatile bool	no_wake_sync;
extern const volatile bool	no_slice_boost;
extern const volatile bool	per_cpu_dsq;
extern const volatile bool	enable_cpu_bw;
extern const volatile bool	is_autopilot_on;
extern const volatile u8	verbose;

/*
 * Exit information (from UEI_DEFINE)
 */
extern struct user_exit_info uei;
extern char uei_dump[];
extern const volatile u32 uei_dump_len;

u64 calc_avg_freq(u64 old_freq, u64 interval);
u32 calc_avg32(u32 old_val, u32 new_val);
bool is_kernel_task(struct task_struct *p);
bool is_kernel_worker(struct task_struct *p);
bool is_ksoftirqd(struct task_struct *p);
bool is_pinned(const struct task_struct *p);
bool use_full_cpus(void);
void set_affinity_flags(task_ctx __arg_arena *taskc,
			const struct cpumask *cpumask);
bool prob_x_out_of_y(u32 x, u32 y);
u32 get_primary_cpu(u32 cpu);

static inline bool rt_or_dl_task(struct task_struct *p)
{
	return unlikely(p->prio < MAX_RT_PRIO);
}

/*
 * task_ctx lookup with per-CPU cache.
 *
 * get_task_ctx_curcpu(p, cpuc) -- @cpuc MUST be the current CPU's cpu_ctx
 * (i.e. obtained via get_cpu_ctx(), not get_cpu_ctx_id(...) or
 * get_cpu_ctx_task(...) for an arbitrary CPU). Misuse silently corrupts
 * the cache of a remote CPU and racing reads can return torn results.
 *
 * get_task_ctx(p) is a foot-gun-free wrapper that always uses
 * get_cpu_ctx() internally.
 */
struct cpu_ctx;
u64 __get_task_ctx_slowpath(struct task_struct *p, struct cpu_ctx *cpuc);

static __always_inline u64
__get_task_ctx_curcpu(struct task_struct *p, struct cpu_ctx *cpuc)
{
	if (cpuc) {
#ifdef LAVD_DEBUG
		if (cpuc->cpu_id != bpf_get_smp_processor_id())
			scx_bpf_error("get_task_ctx_curcpu: non-local cpuc "
				      "(cpu_id=%u, cur=%d)",
				      cpuc->cpu_id,
				      bpf_get_smp_processor_id());
#endif
		if (cpuc->cached_task == (u64)p &&
		    cpuc->cached_pid == p->pid)
			return cpuc->cached_taskc_raw;
	}
	return __get_task_ctx_slowpath(p, cpuc);
}

#define get_task_ctx_curcpu(p, cpuc) \
	((task_ctx *)__get_task_ctx_curcpu((p), (cpuc)))
#define get_task_ctx(p)	get_task_ctx_curcpu((p), get_cpu_ctx())


#endif /* __UTIL_H */
