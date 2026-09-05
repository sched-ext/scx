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
u32 get_sibling_cpu(u32 cpu);

static inline bool rt_or_dl_task(struct task_struct *p)
{
	return unlikely(p->prio < MAX_RT_PRIO);
}

static __always_inline bool is_rt_or_dl_task_running(s32 cpu)
{
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	return curr && rt_or_dl_task(curr);
}

static __always_inline
void __arena * __arena_memset(void __arena *ptr, int value, size_t num)
{
	for (int i = 0; i < num && can_loop; i++)
		((char __arena *)ptr)[i] = value;

	return ptr;
}

/*
 * Extrapolate @anchor_cpu's clock_pelt from its last reading @val_at, taken at
 * wall time @val_at_wall, to wall time @now, for an update that runs off-rq
 * and cannot read it. The kernel advances clock_pelt scaled by capacity and
 * frequency while the CPU is busy and at wall rate while it is idle, where it
 * is synced to clock_task. Per unit wall time, in LAVD_SCALE fixed point:
 *
 *   rate = avg_perf_factor * avg_util_wall / LAVD_SCALE    (busy fraction)
 *        + (LAVD_SCALE - avg_util_wall)                     (idle fraction)
 *
 * Returns 0 with nothing to extrapolate from: no anchor, an unpaired stamp,
 * or no context for the anchor.
 */
static __always_inline u64
ravg_invr_extrapolate(u16 anchor_cpu, u64 val_at, u64 val_at_wall, u64 now)
{
	struct cpu_ctx *ac;
	u64 avg_util_wall, avg_perf_factor;
	u64 busy_ft, idle_ft, rate;

	if (unlikely(anchor_cpu == LAVD_CPU_ID_NONE || !val_at_wall)) {
		return 0;
	}

	ac = get_cpu_ctx_id(anchor_cpu);
	if (unlikely(!ac)) {
		return 0;
	}

	/* The rate at which the anchor's clock_pelt advances per wall time. */
	avg_util_wall = min(READ_ONCE(ac->avg_util_wall), LAVD_SCALE);
	avg_perf_factor = min(READ_ONCE(ac->avg_perf_factor), LAVD_SCALE);
	busy_ft = (avg_util_wall * avg_perf_factor) >> LAVD_SHIFT;
	idle_ft = LAVD_SCALE - avg_util_wall;
	rate = busy_ft + idle_ft;

	return val_at + ((time_delta(now, val_at_wall) * rate) >> LAVD_SHIFT);
}

/*
 * @cpu's invariant clock, the kernel's rq_clock_pelt(): it advances slower
 * when @cpu runs below its maximum capacity or frequency. Returns 0 when the
 * read would be remote, since clock_pelt is per-rq and a NO_HZ-idle rq's is
 * stale.
 */
static __always_inline u64 local_clock_pelt(s32 cpu)
{
	if (unlikely(bpf_get_smp_processor_id() != cpu))
		return 0;
	return scx_clock_pelt(cpu);
}

/*
 * Accumulate @val into @ri against @cpu's invariant clock at wall time @now
 * and anchor it to @cpu. Returns the clock @ri was brought up to, or 0 when
 * nothing could be accumulated; @ri is then left unanchored so the next update
 * rebases instead of folding a stale value across the unmeasured gap.
 *
 * Off-rq @cpu's clock cannot be read: settle up on the current anchor's
 * extrapolated clock and stay there. When @ri is anchored to another CPU,
 * first settle up the gap on that CPU's extrapolated clock, as the kernel
 * syncs a blocked entity against its old rq before attaching it elsewhere;
 * without this a task that migrates on wakeup would neither accumulate nor
 * decay its sleep. Then move only the timestamp, as attach_entity_load_avg()
 * does; old and cur are normalized sums and stay.
 *
 * @ri is in plain memory; the task path bounces its arena copy through the
 * stack.
 */
static __always_inline u64
ravg_invr_accumulate(struct ravg_data_invr *ri, u64 val, s32 cpu, u64 now)
{
	struct ravg_data *rd = &ri->rd;
	u64 pelt_now = local_clock_pelt(cpu);
	u16 anchor_cpu = cpu;
	u64 pelt_prev;

	if (unlikely(!pelt_now)) {
		/*
		 * Cannot read @cpu's pelt clock since the current CPU != @cpu.
		 * Hence, extrapolate pelt clock using the wall clock time.
		 */
		anchor_cpu = ri->anchor_cpu;
		pelt_now = ravg_invr_extrapolate(anchor_cpu, rd->val_at,
						 ri->val_at_wall, now);
		if (unlikely(!pelt_now)) {
			ri->anchor_cpu = LAVD_CPU_ID_NONE;
			return 0;
		}
	}

	if (unlikely(anchor_cpu != ri->anchor_cpu || !rd->val_at)) {
		/*
		 * @cpu is not the ravg's anchor CPU, or @ri has never been
		 * accumulated. clock_pelt readings of different CPUs are not
		 * comparable, so settle up the gap on the anchor's extrapolated
		 * clock, then start a new period with the new value on @cpu's.
		 */
		pelt_prev = ravg_invr_extrapolate(ri->anchor_cpu, rd->val_at,
						  ri->val_at_wall, now);
		if (pelt_prev) {
			ravg_accumulate(rd, rd->val, pelt_prev,
					LAVD_RAVG_HALFLIFE_NS);
		}
		rd->val_at = pelt_now;
		rd->val = val;
	} else {
		/* Everything is aligned; just accumulate @cpu's pelt clock. */
		ravg_accumulate(rd, val, pelt_now, LAVD_RAVG_HALFLIFE_NS);
	}

	ri->val_at_wall = now;
	ri->anchor_cpu = anchor_cpu;

	return pelt_now;
}

/*
 * ravg_invr_accumulate() plus the resulting average in @avg (RAVG_FRAC_BITS
 * fixed point). Returns false when nothing could be accumulated, so the caller
 * can keep its last reading; 0 is a valid average.
 */
static __always_inline bool
ravg_invr_accumulate_read(struct ravg_data_invr *ri, u64 val, s32 cpu, u64 now,
			  u64 *avg)
{
	u64 pelt_now = ravg_invr_accumulate(ri, val, cpu, now);

	if (unlikely(!pelt_now)) {
		return false;
	}

	*avg = ravg_read(&ri->rd, pelt_now, LAVD_RAVG_HALFLIFE_NS);
	return true;
}

/*
 * The two above on an arena-resident @ri, bounced through a stack copy. The
 * average is written back only when something was accumulated; the anchor and
 * wall stamp always are, so a dropped anchor sticks. @avg may be NULL.
 */
static __always_inline bool
__ravg_invr_accumulate_arena(struct ravg_data_invr __arena *ri, u64 val,
			     s32 cpu, u64 now, u64 *avg)
{
	struct ravg_data_invr li;
	bool ok;

	ravg_from_arena(&li.rd, &ri->rd);
	li.val_at_wall = ri->val_at_wall;
	li.anchor_cpu = ri->anchor_cpu;

	if (avg) {
		ok = ravg_invr_accumulate_read(&li, val, cpu, now, avg);
	} else {
		ok = ravg_invr_accumulate(&li, val, cpu, now) != 0;
	}

	if (likely(ok)) {
		ravg_to_arena(&ri->rd, &li.rd);
	}
	ri->val_at_wall = li.val_at_wall;
	ri->anchor_cpu = li.anchor_cpu;

	return ok;
}

static __always_inline void
ravg_invr_accumulate_arena(struct ravg_data_invr __arena *ri, u64 val, s32 cpu,
			   u64 now)
{
	__ravg_invr_accumulate_arena(ri, val, cpu, now, NULL);
}

static __always_inline bool
ravg_invr_accumulate_read_arena(struct ravg_data_invr __arena *ri, u64 val,
				s32 cpu, u64 now, u64 *avg)
{
	return __ravg_invr_accumulate_arena(ri, val, cpu, now, avg);
}

/*
 * Update @cpuc's duty-cycle ravg and util_est. @val is LAVD_SCALE when the CPU
 * picks up a task and 0 when it drops one.
 */
static __always_inline void
cpu_util_ravg_update(struct cpu_ctx *cpuc, u64 val, u64 now)
{
	u64 avg_util_fp;

	if (ravg_invr_accumulate_read(&cpuc->avg_util_ravg, val, cpuc->cpu_id,
				      now, &avg_util_fp)) {
		cpuc->util_est = (u32)(avg_util_fp >> RAVG_FRAC_BITS);
	}
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
struct cpu_ctx;
u64 __find_task_ctx(struct task_struct *p, struct cpu_ctx *cpuc, bool quiet);

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
	return __find_task_ctx(p, cpuc, false);
}

#define get_task_ctx_curcpu(p, cpuc) \
	((task_ctx *)__get_task_ctx_curcpu((p), (cpuc)))
#define get_task_ctx(p)	get_task_ctx_curcpu((p), get_cpu_ctx())

static __always_inline task_ctx *find_task_ctx(struct task_struct *p)
{
	return (task_ctx *)__find_task_ctx(p, NULL, true);
}

#endif /* __UTIL_H */
