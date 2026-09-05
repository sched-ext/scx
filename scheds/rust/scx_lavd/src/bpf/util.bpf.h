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
			const struct cpumask *cpumask);
bool prob_x_out_of_y(u32 x, u32 y);
u32 get_primary_cpu(u32 cpu);

static inline bool rt_or_dl_task(struct task_struct *p)
{
	return unlikely(p->prio < MAX_RT_PRIO);
}

static __always_inline bool is_rt_or_dl_task_running(s32 cpu)
{
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	return curr && rt_or_dl_task(curr);
}

/*
 * Invariant clock for @cpu, mirroring the kernel's rq_clock_pelt(): it advances
 * more slowly when @cpu runs below its maximum capacity or frequency, so a ravg
 * accumulated against it is capacity- and frequency-invariant.
 *
 * Returns 0 when the read would be remote. clock_pelt is per-rq, is not
 * comparable across CPUs, and the kernel does not refresh a remote rq's clock
 * while it is NO_HZ-idle. A 0 return means "do not accumulate" -- the same
 * convention as taskc->last_measured_pelt_clk.
 */
static __always_inline u64 local_clock_pelt(s32 cpu)
{
	if (unlikely(bpf_get_smp_processor_id() != cpu))
		return 0;
	return scx_clock_pelt(cpu);
}

static __always_inline
void __arena * __arena_memset(void __arena *ptr, int value, size_t num)
{
	for (int i = 0; i < num && can_loop; i++)
		((char __arena *)ptr)[i] = value;

	return ptr;
}

/*
 * Bring @rd up to @pelt_now, or rebase it onto the current clock domain when
 * @anchored says its timestamps belong to a different one.
 *
 * The rebase mirrors attach_entity_load_avg(): only the timestamp moves, by
 * direct assignment with no decay across the gap. @rd->old and @rd->cur are
 * both preserved -- they are normalized sums, not timestamps, and @rd->cur
 * carries up to half of what ravg_read() returns, so clearing it would erase
 * the recent history on every migration.
 *
 * Operates on a stack copy; the callers below own the arena bounce.
 */
static __always_inline void
ravg_accumulate_anchored(struct ravg_data *rd, u64 val, u64 pelt_now,
			 bool anchored)
{
	if (unlikely(!anchored || !rd->val_at)) {
		rd->val_at = pelt_now;
		rd->val = val;
		return;
	}

	ravg_accumulate(rd, val, pelt_now, LAVD_RAVG_HALFLIFE_NS);
}

/*
 * Accumulate @val against @cpu's invariant clock, re-anchoring @ri to that
 * clock domain first if it arrived from another one.
 */
static __always_inline void
ravg_accumulate_invr(struct ravg_data_invr __arena *ri, u64 val, s32 cpu)
{
	u64 pelt_now = local_clock_pelt(cpu);
	struct ravg_data rd;

	if (unlikely(!pelt_now)) {
		/*
		 * The transition is a fact even when the clock is not readable.
		 * Drop the anchor so the next local update rebases onto a fresh
		 * timestamp instead of folding a stale @rd.val across the gap
		 * that went unmeasured.
		 */
		ri->anchor_cpu = LAVD_CPU_ID_NONE;
		return;
	}

	ravg_from_arena(&rd, &ri->rd);
	ravg_accumulate_anchored(&rd, val, pelt_now, ri->anchor_cpu == cpu);
	ravg_to_arena(&ri->rd, &rd);
	ri->anchor_cpu = cpu;
}

/*
 * ravg_accumulate_invr() plus the resulting average, for callers that need both
 * without a second arena round trip.
 *
 * Stores the average in @avg in RAVG_FRAC_BITS fixed point and returns true. On
 * a remote clock read nothing is accumulated and false is returned, so a caller
 * can leave its derived value at the last good reading -- 0 is a legitimate
 * average and cannot double as "no reading".
 */
static __always_inline bool
ravg_accumulate_read_invr(struct ravg_data_invr __arena *ri, u64 val, s32 cpu,
			  u64 *avg)
{
	u64 pelt_now = local_clock_pelt(cpu);
	struct ravg_data rd;

	if (unlikely(!pelt_now)) {
		ri->anchor_cpu = LAVD_CPU_ID_NONE;
		return false;
	}

	ravg_from_arena(&rd, &ri->rd);
	ravg_accumulate_anchored(&rd, val, pelt_now, ri->anchor_cpu == cpu);
	ravg_to_arena(&ri->rd, &rd);
	ri->anchor_cpu = cpu;

	*avg = ravg_read(&rd, pelt_now, LAVD_RAVG_HALFLIFE_NS);
	return true;
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
