/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Realtime/DL core avoidance, included by main.bpf.c via #include.
 *
 * The kernel schedules RT, DL and stop tasks outside sched_ext. When
 * one of them becomes runnable on a CPU running an SCX task, the kernel
 * switches the CPU to the higher-priority class and only hands it back
 * when the higher-priority queue empties. This module tracks which CPUs
 * a realtime task is running on through a sched_switch hook, drains the
 * DSQs of a CPU that is taken over so its tasks are not stranded, and
 * (in the placement modules) redirects wakeups away from occupied
 * cores. The occupancy flag is the scheduler's view of a CPU the SCX
 * classes cannot run on. It is updated on every real context switch,
 * so it always reflects the class of the last task that ran.
 */

/*
 * The kernel's RT priority cutoff (kernel/sched/sched.h) is this.
 * Tasks with prio < MAX_RT_PRIO are the realtime classes, DL at prio -1,
 * RT at 0..99 and the stop task at 0, while fair, ext and idle tasks
 * sit at prio >= 100. The vmlinux.h type header does not expose the
 * macro, so it is stated here as the constant it is.
 */
#define MAX_RT_PRIO 100

/*
 * Look up the per-CPU realtime-occupancy state.
 *
 * Return: The state, or NULL for an invalid CPU or a failed lookup.
 */
static __always_inline struct mlfq_rtdl_state *mlfq_lookup_rtdl_state(s32 cpu)
{
	u32 key;

	if (cpu < 0)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&rtdl_state_stor, &key);
}

/*
 * Whether the last task that ran on @cpu belonged to a realtime class.
 * An invalid CPU or a failed lookup never reports occupied.
 */
static __always_inline bool mlfq_cpu_occupied(s32 cpu)
{
	struct mlfq_rtdl_state *rt;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return false;
	return rt->flags & MLFQ_RTDL_OCCUPIED;
}

/*
 * Pick a non-occupied CPU out of a membership bitmap for @p. The same
 * word-major, bit-minor bounded walk the idle scan in select_cpu.bpf.c
 * uses, skipping occupied CPUs instead of busy ones. No idle marks are
 * touched. The caller has already decided the wakeup must not land on
 * an occupied core, and the kernel's idle accounting is unaffected.
 *
 * Return: The first non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_in_bitmap(const struct mlfq_bitmap *bm,
			       const struct task_struct *p)
{
	u32 word, bit;

	bpf_for(word, 0, MLFQ_BITMAP_WORDS) {
		bpf_for(bit, 0, 64) {
			u32 cand = word * 64 + bit;

			if (cand >= MLFQ_MAX_CPUS)
				break;
			if (!mlfq_bitmap_test_cpu(bm, cand))
				continue;
			if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
				continue;
			if (mlfq_cpu_occupied((s32)cand))
				continue;
			return (s32)cand;
		}
	}

	return -ENOENT;
}

/*
 * Pick a non-occupied CPU for @p, preferring the cache domain of @origin
 * (the waker's CPU). The LLC pass walks the origin's membership bitmap.
 * When it finds nothing, a flat bounded scan takes any non-occupied CPU
 * @p may run on. An unpopulated LLC bitmap or an unknown LLC proceeds
 * to the flat scan.
 *
 * Return: A non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_cpu(const struct task_struct *p, s32 origin)
{
	const struct mlfq_bitmap *bm;
	s32 pick;
	u32 cand;

	if (origin >= 0 && (u32)origin < MLFQ_MAX_CPUS && mlfq_nr_llcs > 0) {
		u32 origin_llc = mlfq_cpu_llc[(u32)origin];

		if (origin_llc < MLFQ_MAX_LLCS && origin_llc < mlfq_nr_llcs) {
			bm = bpf_map_lookup_elem(&mlfq_llc_bitmaps, &origin_llc);
			if (bm) {
				pick = mlfq_pick_unoccupied_in_bitmap(bm, p);
				if (pick >= 0)
					return pick;
			}
		}
	}

	/*
	 * The global fallback is any non-occupied CPU in a flat bounded
	 * scan. The LLC bitmaps partition the machine, but walking all of
	 * them would nest three loops. A single scan over the CPU id
	 * space reaches the same set in one bounded pass.
	 */
	bpf_for(cand, 0, MLFQ_MAX_CPUS) {
		if (cand >= nr_cpu_ids)
			break;
		if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
			continue;
		if (mlfq_cpu_occupied((s32)cand))
			continue;
		return (s32)cand;
	}

	return -ENOENT;
}

/*
 * mlfq_rtdl_drain - Evacuation pass for a taken-over CPU.
 * @cpu: The CPU a realtime task took over.
 * @now: Current time (scx_bpf_now()).
 *
 * Rate-limited evacuation pass. The rate-limit gate is load-bearing.
 * The kernel reenqueues the local DSQ on a takeover without a repeat
 * guard of its own, so the interval bounds the churn a takeover can
 * stir up, in particular the pinned-task reenqueue loop, which the
 * kernel lets run unthrottled. The pass is skipped entirely when every
 * DSQ this CPU owns is empty, which also keeps the gate from being
 * consumed by the takeover blips themselves. The stop-class blips that
 * interrupt a takeover are safe for the same reason, because the drain
 * they trigger is rate-limited and a no-op when there is nothing to
 * drain.
 */
static __always_inline void mlfq_rtdl_drain(s32 cpu, u64 now)
{
	struct mlfq_rtdl_state *rt;
	bool evacuated = false;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return;

	/*
	 * The rate-limited drain gate allows at most one pass per CPU per
	 * mlfq_rtdl_drain_interval_ns, so a takeover storm cannot burn
	 * the CPU in the hook. The first pass is ungated (last_drain_at
	 * == 0). On kernels without the reenqueue kfuncs, the gate never
	 * closes. The pass is a no-op and last_drain_at does not advance,
	 * so every realtime-class switch pays the nonempty gate below.
	 * That is the documented 6.18 degradation.
	 */
	if (rt->last_drain_at &&
	    !mlfq_time_before(rt->last_drain_at + mlfq_rtdl_drain_interval_ns, now))
		return;

	/*
	 * Nonempty gate: when every DSQ this CPU owns is empty there is
	 * nothing to evacuate, so the pass is skipped without consuming
	 * the rate-limit window.
	 */
	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu)))
		return;

	/*
	 * The evacuation is version-gated. The local DSQ is reenqueued
	 * from anywhere only where the call-from-anywhere kfunc exists
	 * (v6.19+), and the queue DSQs only through the generic
	 * reenqueue (v7.1+), with three explicit constant-id calls.
	 * The reenqueue itself re-anchors the tasks in the queue DSQs.
	 * The enqueue redirect then relocates them off the occupied CPU,
	 * so the drain plus the redirect is what actually evacuates. On
	 * 6.18 the drain is a no-op by kernel limitation. The local DSQ
	 * is reenqueued by ops.cpu_release, whose reenqueue the redirect
	 * likewise relocates, and the queue DSQs are served by the steal
	 * scans on every kernel. On 6.19 the local reenqueue runs and
	 * can consume the gate while the queue DSQs wait for the steal
	 * scans. This is the intermediate kernel degradation. The probe
	 * is the compat layer's stable surface, and the call goes
	 * straight to the v2 kfunc, which is what the from-anywhere
	 * wrapper does internally. Spelling it out keeps the drain
	 * buildable against compat headers that predate the wrapper.
	 */
	if (__COMPAT_scx_bpf_reenqueue_local_from_anywhere()) {
		scx_bpf_reenqueue_local___v2___compat();
		evacuated = true;
	}
	if (__COMPAT_has_generic_reenq()) {
		if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)))
			scx_bpf_dsq_reenq(mlfq_dsq_id(1, cpu), 0);
		if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)))
			scx_bpf_dsq_reenq(mlfq_dsq_id(2, cpu), 0);
		if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu)))
			scx_bpf_dsq_reenq(mlfq_dsq_id(3, cpu), 0);
		evacuated = true;
	}

	/*
	 * The gate and the counter are consumed only when the pass
	 * actually ran. On kernels without the reenqueue kfuncs nothing
	 * was evacuated, so the rate-limit window stays open and no
	 * evacuation is counted.
	 */
	if (evacuated) {
		rt->last_drain_at = now;
		__sync_fetch_and_add(&mlfq_stats.rt_evacuations, 1);
	}
}

/*
 * The sched_switch hook. The kernel fires this tracepoint on every real
 * context switch. The program reads next->prio to learn the class of
 * the task the CPU is about to run. A realtime next marks the CPU
 * occupied and attempts the takeover drain. Any other next clears the
 * mark. Because the hook fires on every real switch, the flag always
 * reflects the class of the last task that ran on the CPU, which is
 * exactly the invariant the placement redirect needs. The program is
 * loaded on every kernel. The flag logic alone drives placement even
 * where the evacuation cannot run, and the evacuation branches inside
 * are ksym-gated so they self-prune on kernels without the reenqueue
 * kfuncs. The body is straight-line with at most a few bounded map
 * operations per switch. There are no loops.
 */
SEC("?tp_btf/sched_switch")
int BPF_PROG(mlfq_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next,
	     unsigned int prev_state)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct mlfq_rtdl_state *rt;
	u64 now;

	if (unlikely(next->prio < MAX_RT_PRIO)) {
		rt = mlfq_lookup_rtdl_state(cpu);
		if (!rt)
			return 0;
		if (!(rt->flags & MLFQ_RTDL_OCCUPIED)) {
			rt->flags |= MLFQ_RTDL_OCCUPIED;
			__sync_fetch_and_add(&mlfq_stats.rt_takeovers, 1);
		}
		now = scx_bpf_now();
		mlfq_rtdl_drain(cpu, now);
	} else {
		rt = mlfq_lookup_rtdl_state(cpu);
		if (!rt)
			return 0;
		if (rt->flags & MLFQ_RTDL_OCCUPIED)
			rt->flags &= ~MLFQ_RTDL_OCCUPIED;
	}
	return 0;
}
