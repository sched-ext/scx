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
 * local DSQ of a CPU that is taken over so its tasks are not stranded,
 * and (in the placement modules) redirects wakeups away from occupied
 * cores. The queue DSQs of a taken-over CPU are requeued when the
 * kernel offers the generic call, and are served by the steal scans
 * as the second channel where the call is absent. The occupancy flag
 * is the scheduler's view of a CPU the SCX classes cannot run on. It
 * is updated on every real context switch, so it always reflects the
 * class of the last task that ran.
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
 * mlfq_local_insert_safe - Veto a FIFO local insert to a bad CPU.
 * @cpu: The CPU whose local DSQ would receive the task.
 *
 * A FIFO local insert bypasses the virtual-time order and shadows the
 * queue DSQs while it sits, so it is allowed only when the CPU can run
 * the task immediately: not occupied by a higher-priority class and with
 * an empty local DSQ. An occupied CPU would strand the task behind the
 * takeover until the drain, and a non-empty local would queue it behind
 * unrelated work. Both cases fall back to the owning queue DSQ, which
 * the steal scans serve. The idle claim itself is not tested here; the
 * caller holds it via test_and_clear.
 *
 * Return: true when the local insert may proceed.
 */
static __always_inline bool mlfq_local_insert_safe(s32 cpu)
{
	if (nr_cpu_ids == 0)
		return false;
	if (cpu < 0 || cpu >= (s32)nr_cpu_ids)
		return false;
	if (mlfq_cpu_occupied(cpu))
		return false;
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu))
		return false;
	return true;
}

/*
 * Whether a queue DSQ insert needs an idle kick.
 * @p is the task just queued.
 * @enq_flags carries the select mark.
 * @target_cpu owns the queue DSQ.
 * @redirected is true for a fallback pick.
 * A local insert never kicks.
 * A kick needs an allowed and remote and unoccupied target.
 * A redirected insert kicks when the target can run it.
 * The claim for the first target does not cover the new one.
 * A plain insert kicks only when no claim was made or when
 * the task can run on a few CPUs only. Inserts to the global
 * DSQ never reach here, so the global fallback stays allowed.
 */
static __always_inline bool mlfq_needs_shared_kick(const struct task_struct *p,
						   u64 enq_flags, s32 target_cpu,
						   bool redirected)
{
	if (!mlfq_init_done)
		return false;
	if (target_cpu == bpf_get_smp_processor_id())
		return false;
	if (target_cpu < 0 || target_cpu >= (s32)nr_cpu_ids)
		return false;
	if (nr_cpu_ids == 0)
		return false;
	if (!bpf_cpumask_test_cpu((u32)target_cpu, p->cpus_ptr))
		return false;
	if (mlfq_cpu_occupied(target_cpu))
		return false;
	if (redirected)
		return true;
	if (__COMPAT_is_enq_cpu_selected(enq_flags) &&
	    p->nr_cpus_allowed == (u32)nr_cpu_ids)
		return false;
	return true;
}

/*
 * Pick a non-occupied CPU out of a membership bitmap for @p. The same
 * word-major, bit-minor bounded walk the idle scan in select_cpu.bpf.c
 * uses, skipping occupied CPUs instead of busy ones. No idle marks are
 * touched. The caller has already decided the wakeup must not land on
 * an occupied core, and the kernel's idle accounting is unaffected.
 * When @strict_smt is true the same SMT-sibling Q1 predicate the
 * selection uses (is_smt_sibling_q1_busy) is also a veto; when false
 * only the realtime hard gate applies. No new heuristic: the predicate
 * is exactly the selection's.
 *
 * Return: The first non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_in_bitmap(const struct mlfq_bitmap *bm,
			       const struct task_struct *p, bool strict_smt)
{
	u32 word, bit;

	bpf_for(word, 0, MLFQ_BITMAP_WORDS) {
		bpf_for(bit, 0, 64) {
			u32 cand = word * 64 + bit;

			if (cand >= MLFQ_MAX_CPUS)
				break;
			if (cand >= nr_cpu_ids)
				continue;
			if (!mlfq_bitmap_test_cpu(bm, cand))
				continue;
			if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
				continue;
			if (mlfq_cpu_occupied((s32)cand))
				continue;
			if (strict_smt && is_smt_sibling_q1_busy((s32)cand))
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
 * to the flat scan. @strict_smt adds the selection's SMT-sibling Q1 veto
 * to both passes (same predicate, no new heuristic); false keeps the
 * realtime-only hard gate.
 *
 * Return: A non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_cpu(const struct task_struct *p, s32 origin,
			 bool strict_smt)
{
	const struct mlfq_bitmap *bm;
	s32 pick;
	u32 cand;

	if (origin >= 0 && (u32)origin < MLFQ_MAX_CPUS && mlfq_nr_llcs > 0) {
		u32 origin_llc = mlfq_cpu_llc[(u32)origin];

		if (origin_llc < MLFQ_MAX_LLCS && origin_llc < mlfq_nr_llcs) {
			bm = bpf_map_lookup_elem(&mlfq_llc_bitmaps, &origin_llc);
			if (bm) {
				pick = mlfq_pick_unoccupied_in_bitmap(bm, p,
								      strict_smt);
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
		if (strict_smt && is_smt_sibling_q1_busy((s32)cand))
			continue;
		return (s32)cand;
	}

	return -ENOENT;
}

/*
 * Takeover evacuation for one CPU, startup safe.
 * One pass per CPU per interval at most. The local
 * part moves the local DSQ back to the queue DSQs.
 * The queue part moves the three queue DSQs through
 * the generic requeue call when it exists. Both parts
 * share one rate window. When the generic call is
 * absent the redirect kick plus the steal scans carry
 * the queued work. No extra kick runs here.
 */
static __always_inline void mlfq_rtdl_drain(s32 cpu, u64 now)
{
	struct mlfq_rtdl_state *rt;
	bool evacuated = false;

	/*
	 * Startup gate. The hook fires during attach
	 * before the queue DSQs exist, so no pass runs
	 * before the init gate is published. A create
	 * failure never publishes it, so every early
	 * path stays inert.
	 */
	if (!mlfq_init_done)
		return;
	/*
	 * Range gate, mirroring the select and local
	 * insert guards. An offline or unknown CPU
	 * returns before any queue id is formed.
	 */
	if (nr_cpu_ids == 0)
		return;
	if (cpu < 0 || cpu >= (s32)nr_cpu_ids)
		return;
	if ((u32)cpu >= mlfq_created_cpus)
		return;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return;

	/*
	 * Rate gate. One pass per interval at most. The
	 * BSS zero state leaves the first pass after the
	 * gate free, and the window stays open when
	 * nothing moved.
	 */
	if (rt->last_drain_at &&
	    !mlfq_time_before(rt->last_drain_at +
			      mlfq_rtdl_drain_interval_ns, now))
		return;

	/*
	 * Local part. Runs only when the local DSQ holds
	 * work. One straight call with no loop.
	 */
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu)) {
		if (mlfq_reenqueue_local_step())
			evacuated = true;
	}

	/*
	 * Queue part. Three straight checks with no loop.
	 * Each queued DSQ is requeued once per pass at
	 * most. Version gated. Absent on old kernels. The
	 * ids sit below the reserved range by the init
	 * check and the created range above, so the
	 * queued depth is only the second gate, never the
	 * only one.
	 */
	{
		u64 q1 = mlfq_dsq_id(1, cpu);
		u64 q2 = mlfq_dsq_id(2, cpu);
		u64 q3 = mlfq_dsq_id(3, cpu);

		if (q1 < SCX_DSQ_LOCAL_ON &&
		    scx_bpf_dsq_nr_queued(q1)) {
			if (mlfq_reenqueue_one(q1))
				evacuated = true;
		}
		if (q2 < SCX_DSQ_LOCAL_ON &&
		    scx_bpf_dsq_nr_queued(q2)) {
			if (mlfq_reenqueue_one(q2))
				evacuated = true;
		}
		if (q3 < SCX_DSQ_LOCAL_ON &&
		    scx_bpf_dsq_nr_queued(q3)) {
			if (mlfq_reenqueue_one(q3))
				evacuated = true;
		}
	}

	/*
	 * The window moves only when some part moved and
	 * only after the gate above, so old kernels keep
	 * the window open.
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
 * occupied and attempts the takeover drain. Any other next
 * clears the mark. Because the hook fires on every real switch, the
 * flag always reflects the class of the last task that ran on the CPU,
 * which is exactly the invariant the placement redirect needs. The
 * program is loaded on every kernel. The flag logic alone drives
 * placement even where the evacuation cannot run, and the evacuation
 * branch inside is version gated so it folds away on older releases
 * without the reenqueue calls. The drain stays inert before the init gate,
 * so early switches during attach cannot name a queue that does not
 * exist yet. The body is straight-line with at most a few bounded
 * map operations per switch. There are no loops.
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
