/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UTIL_H
#define __UTIL_H

extern const volatile u64	nr_llcs;	/* number of LLC domains */
extern volatile u64 __arena_global	nr_cpus_onln;	/* current number of online CPUs */


/*
 * Scheduler parameters
 */
extern volatile bool __arena_global	reinit_cpumask_for_performance;
extern volatile bool __arena_global	no_preemption;
extern volatile bool __arena_global	no_core_compaction;
extern volatile bool __arena_global	no_freq_scaling;

extern const volatile bool	no_wake_sync;
extern const volatile bool	no_slice_boost;
extern const volatile bool	per_cpu_dsq;
extern const volatile u64	warm_cpu_ns;	/* enables per-CPU DSQ consume */
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
bool is_permanently_pinned(const struct task_struct *p);
bool is_effectively_pinned(task_ctx __arg_arena *taskc);
bool use_full_cpus(void);
void set_affinity_flags(task_ctx __arg_arena *taskc,
			const struct scx_cmask __arena __arg_arena *cpumask);
bool prob_x_out_of_y(u32 x, u32 y);
u32 get_primary_cpu(u32 cpu);

static __always_inline bool task_allows_cid(const struct task_struct *p, s32 cid)
{
	return cid >= 0 && cid < nr_cids &&
		bpf_cpumask_test_cpu(scx_bpf_cid_to_cpu(cid), p->cpus_ptr);
}

static __always_inline s32 first_allowed_cid(const struct task_struct *p)
{
	u32 cpu = bpf_cpumask_first(p->cpus_ptr);

	return cpu < nr_cpu_ids ? scx_bpf_cpu_to_cid(cpu) : -ENOENT;
}

static inline bool rt_or_dl_task(struct task_struct *p)
{
	return unlikely(p->prio < MAX_RT_PRIO);
}

static __always_inline bool is_rt_or_dl_task_running(s32 cpu)
{
	struct task_struct *curr = scx_bpf_cid_curr(cpu);
	return curr && rt_or_dl_task(curr);
}

/*
 * Two lookups, chosen by which task a program is asking about.
 *
 * get_task_ctx() is for the task a scheduler callback was invoked for. The
 * kernel keeps that task alive across the callback, its context must exist, and
 * the callback runs with preemption disabled, so the lookup may cache the
 * result in this CPU's cpu_ctx and treats a miss as an error.
 * get_task_ctx_curcpu() is the same with the current CPU's cpu_ctx the caller
 * already holds.
 *
 * find_task_ctx() is for every other task: wakers, DSQ candidates, the parent
 * in init_task() and the current task in tracing hooks. Those may have no
 * context or may exit concurrently, so it returns NULL instead of reporting the
 * miss on the error stream, and it never touches the cache, because a
 * preemptible or sleepable caller can tear a cache entry or write another
 * CPU's. Keep the returned pointer inside one RCU read-side critical section.
 */
u64 __find_task_ctx(struct task_struct *p, struct cpu_ctx __arena __arg_arena *cpuc,
		      bool quiet);

static __always_inline u64
__get_task_ctx_curcpu(struct task_struct *p, struct cpu_ctx __arena *cpuc)
{
	if (cpuc) {
#ifdef LAVD_DEBUG
		if (cpuc->raw_cpu != bpf_get_smp_processor_id())
			scx_bpf_error("get_task_ctx_curcpu: non-local cpuc "
				      "(cpu_id=%u, cur=%d)", cpuc->raw_cpu,
				      bpf_get_smp_processor_id());
#endif
		if (cpuc->cached_task == (u64)p &&
		    cpuc->cached_pid == p->pid)
			return cpuc->cached_taskc_raw;
	}
	return __find_task_ctx(p, cpuc, false);
}

#define get_task_ctx_curcpu(p, cpuc) \
	((task_ctx *)__get_task_ctx_curcpu((p), (cpuc)))
#define get_task_ctx(p)	get_task_ctx_curcpu((p), get_cpu_ctx())

static __always_inline task_ctx *find_task_ctx(struct task_struct *p)
{
	return (task_ctx *)__find_task_ctx(p, NULL, true);
}

/*
 * ravg_accumulate() takes a native pointer, so an arena-resident average is
 * staged through the stack. Returns the updated average at @now.
 */
static __always_inline u64 update_ravg_arena(struct ravg_data __arena *ard, u64 new_val,
					     u64 now)
{
	struct ravg_data rd;

	ravg_from_arena(&rd, ard);
	ravg_accumulate(&rd, new_val, now, LAVD_RAVG_HALFLIFE_NS);
	ravg_to_arena(ard, &rd);
	return ravg_read(&rd, now, LAVD_RAVG_HALFLIFE_NS);
}

#endif /* __UTIL_H */
