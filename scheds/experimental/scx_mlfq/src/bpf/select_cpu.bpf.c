/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * CPU selection, included by main.bpf.c via #include.
 *
 * Placement preference, in order, is the prev CPU when idle, the prev
 * CPU's SMT sibling (non-interactive wakeups only), the largest-LLC
 * domain (interactive wakeups only), the waker's LLC, the least-loaded
 * LLC with an idle CPU (when idle tracking is live), then the global
 * fallbacks (an idle primary core for Q1, any idle CPU otherwise). Each
 * step after the prev fast path is gated on the state that populates
 * it, so an unpopulated machine reproduces the plain order exactly.
 * The per-step detail is at the corresponding points in
 * mlfq_select_cpu() below. When no CPU is selected, prev_cpu is
 * returned. The kernel validates the return as a CPU number (any
 * negative value aborts the scheduler), and the task then goes through
 * the normal enqueue path into the owning CPU's queue vtime DSQ.
 *
 * With SCX_OPS_ENQ_MIGRATION_DISABLED the kernel never invokes this
 * callback for migration-disabled tasks.
 *
 * The primary-core and LLC sets live in ARRAY map values as plain u64
 * bitmaps (see main.bpf.c), written by the Rust front-end after load and
 * read directly as map values. An unpopulated map entry means "no data".
 * The primary bitmap is treated as all-primary and an empty LLC bitmap
 * yields no idle candidate.
 */

/*
 * The primary-core bitmap, or NULL when every CPU is primary. Looked up
 * once per select_cpu() call and passed down. The map value is immutable
 * after load, so the single lookup is valid for the whole scan.
 */
static __always_inline const struct mlfq_bitmap *mlfq_get_primary_bitmap(void)
{
	u32 key = 0;

	if (mlfq_primary_all)
		return NULL;
	return bpf_map_lookup_elem(&mlfq_primary_bitmap, &key);
}

/*
 * Return true if @cpu belongs to the primary (big-core) set.
 *
 * @bm is NULL when every CPU is primary (uniform-capacity behavior). An
 * empty bitmap (with mlfq_primary_all false) reports no primaries, so the
 * selector falls back to any idle CPU.
 */
static __always_inline bool mlfq_is_primary(const struct mlfq_bitmap *bm,
					    s32 cpu)
{
	return !bm || mlfq_bitmap_test_cpu(bm, (u32)cpu);
}

/*
 * Pick an idle CPU out of the bitmap in @map at @key for @p, optionally
 * restricted to primary cores (@primary_bm is the hoisted primary bitmap,
 * NULL when every CPU is primary).
 *
 * One map lookup, then a compile-time-bounded scan: word-major over
 * MLFQ_BITMAP_WORDS words, bit-minor over 64 bits per word. For each set
 * candidate the scan tests task affinity, idleness (clearing the idle
 * mark) and, when requested, primary membership, returning the first
 * match in ascending CPU order, with no capacity ordering. An unpopulated
 * entry or an empty scan returns -ENOENT.
 */
static __always_inline s32 mlfq_pick_idle_in_bitmap(void *map, u32 key,
						    const struct task_struct *p,
						    bool require_primary,
						    const struct mlfq_bitmap *primary_bm)
{
	const struct mlfq_bitmap *bm;
	u32 word, bit;

	bm = bpf_map_lookup_elem(map, &key);
	if (!bm)
		return -ENOENT;

	bpf_for(word, 0, MLFQ_BITMAP_WORDS) {
		bpf_for(bit, 0, 64) {
			u32 cand = word * 64 + bit;

			if (cand >= MLFQ_MAX_CPUS)
				break;
			if (!mlfq_bitmap_test_cpu(bm, cand))
				continue;
			if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
				continue;
			if (require_primary &&
			    !mlfq_is_primary(primary_bm, (s32)cand))
				continue;
			if (!scx_bpf_test_and_clear_cpu_idle((s32)cand))
				continue;
			return (s32)cand;
		}
	}

	return -ENOENT;
}

/*
 * Global primary-core scan: pick an idle primary CPU, or -ENOENT. The
 * primary bitmap holds only primary cores, so the require_primary
 * restriction is unnecessary here.
 */
static __always_inline s32
mlfq_pick_idle_primary(const struct task_struct *p,
		       const struct mlfq_bitmap *primary_bm)
{
	return mlfq_pick_idle_in_bitmap(&mlfq_primary_bitmap, 0, p, false,
					primary_bm);
}

/*
 * mlfq_interactive_on_wakeup - Whether a wakeup will be treated as interactive.
 * @p: The task being woken.
 * @tctx: The task context.
 * @now: Current time (scx_bpf_now()).
 *
 * The queue recorded in the task context reflects the previous run,
 * while the short-sleep boost runs in ops.enqueue(), after the CPU
 * selection. The CPU selection must treat a wakeup that is about to be
 * promoted as interactive already, so the primary-core preference
 * applies to it from the start. SCHED_IDLE tasks are excluded, the
 * classification pins them to Q3. The MLFQ tree is not walked here.
 * Its classification also runs in ops.enqueue(), after the CPU
 * selection, so the boost mirror above is the only pre-classification
 * interactivity signal.
 *
 * Return: true if the wakeup is or will become interactive.
 */
static __always_inline bool
mlfq_interactive_on_wakeup(const struct task_struct *p,
			   const struct task_ctx *tctx, u64 now)
{
	u64 sleep_ns = 0;

	if (tctx->last_sleep_at && mlfq_time_before(tctx->last_sleep_at, now))
		sleep_ns = now - tctx->last_sleep_at;

	return tctx->queue == 1 ||
	       (p->policy != MLFQ_SCHED_IDLE &&
		mlfq_ss_boost_pending(tctx, sleep_ns, mlfq_task_io_wait(p),
				      now, mlfq_short_sleep_ns,
				      mlfq_short_sleep_rate_limit_ns));
}

/*
 * is_cpu_available_for_q3 - Strategy veto for Q3 placement.
 * @cpu: Candidate CPU.
 * @p: Task.
 * @strict_smt: When true, SMT sibling Q1 busy is a soft veto; when false, relaxed.
 *
 * Evaluation order: affinity → RT hard gate (MLFQ_RTDL_OCCUPIED, never
 * relaxed) → SMT soft veto (logical sibling, is_smt_sibling_q1_busy).
 * Returns true if CPU passes all enabled gates.
 */
static __always_inline bool is_cpu_available_for_q3(s32 cpu,
						    const struct task_struct *p,
						    bool strict_smt)
{
	struct mlfq_rtdl_state *rt;
	u32 key;

	if (cpu < 0 || cpu >= (s32)nr_cpu_ids)
		return false;
	if (!bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr))
		return false;
	key = (u32)cpu;
	rt = bpf_map_lookup_elem(&rtdl_state_stor, &key);
	if (rt && (rt->flags & MLFQ_RTDL_OCCUPIED))
		return false;
	if (strict_smt && is_smt_sibling_q1_busy(cpu))
		return false;
	return true;
}

s32 BPF_STRUCT_OPS(mlfq_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx;
	const struct mlfq_bitmap *primary_bm;
	u32 first_cpu, waker_cpu, waker_llc;
	u64 now;
	s32 cpu_id = -1;
	bool interactive;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/* SCX_WAKE_SYNC fast-path: synchronous waker handoff for Q1/Q2.
	 * Strategy: when wake_flags carries SCX_WAKE_SYNC or the task
	 * carries MLFQ_TF_DRM_WAKE and the wakee is Q1/Q2, keep cache hot
	 * by staying on waker's CPU. Affinity is checked, RT hard gate
	 * (mlfq_cpu_occupied) is never relaxed and strands Q1/Q2 behind
	 * an RT-occupied LOCAL until rtdl drain; RT-occupied waker CPU
	 * falls through to regular placement. SMT sibling veto is
	 * intentionally bypassed for this handoff (cache-hot policy,
	 * zero-knob). Null cur (bpf_get_current_task_btf failed) also
	 * falls through. The insert uses SCX_DSQ_LOCAL + SCX_ENQ_IMMED
	 * (never SCX_ENQ_HEAD) as the zero-knob policy and the queue's
	 * own slice (Q1 1ms, Q2 2ms) to match enqueue's per-queue slice,
	 * not SCX_SLICE_DFL (20ms), so the dispatch slice accounting stays
	 * consistent. MLFQ_TF_DRM_WAKE is cleared after the insert, no
	 * new branch depth, no new loop.
	 */
	if (((wake_flags & SCX_WAKE_SYNC) || (tctx->flags & MLFQ_TF_DRM_WAKE)) && tctx->queue <= 2) {
		struct task_struct *cur = bpf_get_current_task_btf();

		if (cur) {
			s32 cur_cpu = scx_bpf_task_cpu(cur);

			if (cur_cpu >= 0 && cur_cpu < (s32)MLFQ_MAX_CPUS &&
			    !mlfq_cpu_occupied(cur_cpu) &&
			    bpf_cpumask_test_cpu((u32)cur_cpu, p->cpus_ptr)) {
				u64 slice = tctx->queue == 1 ?
					    MLFQ_Q1_SLICE_NS : MLFQ_Q2_SLICE_NS;

				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice,
						   SCX_ENQ_IMMED);
				tctx->flags &= ~MLFQ_TF_DRM_WAKE;
				return cur_cpu;
			}
		}
		tctx->flags &= ~MLFQ_TF_DRM_WAKE;
	}

	/* Clear any fast-path state from a previous select_cpu(). */
	tctx->wake_cpu_state = 0;

	/*
	 * The task allowed on prev_cpu (cpuset) may have changed since
	 * the last run; fix that up.
	 */
	if (!bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
		first_cpu = bpf_cpumask_first(p->cpus_ptr);
		if (first_cpu >= nr_cpu_ids)
			/*
		 * An empty allowed mask leaves the out-of-affinity
		 * return in place. The kernel's own return
		 * validation (SCX_EV_SELECT_CPU_FALLBACK) falls back
		 * to a CPU the task may run on, so the return is
		 * safe.
			 */
			return prev_cpu;
		prev_cpu = (s32)first_cpu;
	}

	/*
	 * Hoist the primary-core bitmap lookup: it is immutable after load,
	 * so one lookup serves the whole scan (see mlfq_pick_idle_in_bitmap).
	 */
	primary_bm = mlfq_get_primary_bitmap();

	/*
	 * Whether this wakeup will be treated as interactive. The queue
	 * recorded in the task context reflects the previous run, while
	 * the short-sleep boost runs in ops.enqueue(), after the CPU
	 * selection. A task about to be promoted must already be treated
	 * as interactive here, otherwise it could claim an idle
	 * efficiency core and then be promoted onto it.
	 */
	now = scx_bpf_now();
	interactive = mlfq_interactive_on_wakeup(p, tctx, now);

	/*
	 * Q3 isolation path: bounded bpf_for scans with SMT soft veto.
	 * Phase 1 (strict) respects SMT sibling Q1 busy as veto (64 cap);
	 * Phase 2 (relaxed) drops SMT veto but never the RT hard gate
	 * (32 cap). Both scans are MLFQ_MAX_CPUS-bounded and verifier
	 * flat (bpf_for). Fallback returns prev_cpu when no idle Q3 CPU
	 * is found.
	 */
	if (tctx->queue == 3) {
		s32 cand;
		int cnt = 0;

		bpf_for(cand, 0, MLFQ_MAX_CPUS) {
			if (cand >= (s32)nr_cpu_ids)
				break;
			if (cnt++ >= 64)
				break;
			if (!is_cpu_available_for_q3(cand, p, true))
				continue;
			if (!scx_bpf_test_and_clear_cpu_idle(cand))
				continue;
			cpu_id = cand;
			goto direct;
		}
		cnt = 0;
		bpf_for(cand, 0, MLFQ_MAX_CPUS) {
			if (cand >= (s32)nr_cpu_ids)
				break;
			if (cnt++ >= 32)
				break;
			if (!is_cpu_available_for_q3(cand, p, false))
				continue;
			if (!scx_bpf_test_and_clear_cpu_idle(cand))
				continue;
			cpu_id = cand;
			goto direct;
		}
		return prev_cpu;
	}

	/*
	 * Step 1, the prev CPU fast path. The prev CPU is preferred when idle
	 * for cache locality. An interactive task on a hybrid system only
	 * sticks to prev when it is a primary core. Settling an interactive
	 * wakeup on an efficiency core would trade cache warmth for
	 * sustained capacity. The idle mark is cleared only after the
	 * primary check passes, so an idle efficiency core is never lost
	 * from the idle pool for an interactive wakeup.
	 */
	if ((!interactive || mlfq_is_primary(primary_bm, prev_cpu)) &&
	    !is_smt_sibling_q1_busy(prev_cpu) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu_id = prev_cpu;
		goto direct;
	}

	/*
	 * Step 1.5, the SMT sibling preference for non-interactive wakeups.
	 * When prev is busy, its core sibling shares the L1/L2 caches, so
	 * a Q2/Q3 wakeup lands there before any scan. This is the
	 * shared-cache warmth that the LLC and global scans cannot offer.
	 * Interactive wakeups are excluded. SCX_PICK_IDLE_CORE is
	 * authoritative for them (the whole-core preference in steps 2 and
	 * 3), and settling an interactive wakeup on a sibling would split
	 * the core. The affinity fix-up above guarantees prev_cpu is in
	 * p->cpus_ptr, so only the sibling's own affinity is tested here.
	 * mlfq_smt_on gates the whole step, so an unwritten (all-zero)
	 * rodata table can never fire it. The idle mark is claimed only
	 * through scx_bpf_test_and_clear_cpu_idle, and occupied CPUs are
	 * never idle-marked, so a realtime-occupied sibling cannot be
	 * claimed.
	 */
	if (!interactive && mlfq_smt_on && prev_cpu >= 0 &&
	    prev_cpu < MLFQ_MAX_CPUS) {
		u32 sib = mlfq_cpu_sibling[prev_cpu];

		if (sib != (u32)prev_cpu && sib < MLFQ_MAX_CPUS &&
		    bpf_cpumask_test_cpu(sib, p->cpus_ptr) &&
		    !is_smt_sibling_q1_busy((s32)sib) &&
		    scx_bpf_test_and_clear_cpu_idle((s32)sib)) {
			cpu_id = (s32)sib;
			goto direct;
		}
	}

	/*
	 * Saturation fast path. When the scheduler's idle-CPU count is
	 * zero, no CPU is idle, so the LLC and global idle scans below can
	 * only fail. They would still cost an idle-scan kfunc each (and a
	 * per-candidate test-and-clear on the bitmap walk) on the waker's
	 * own CPU, which multiplies into the wake-all latency on a
	 * saturated machine. Return prev_cpu directly, the same fallback
	 * the scans end in. The wakeup then goes through the normal enqueue
	 * path into prev_cpu's queue DSQ. The count is maintained by
	 * ops.update_idle() and this path is gated on mlfq_idle_tracking,
	 * which is set only when the kernel keeps its built-in idle
	 * tracking alongside the callback. Without it, the behavior is
	 * unchanged. An occupied prev_cpu proceeds to the scans
	 * regardless of the count. The idle count only tracks the kernel's
	 * idle-thread transitions and can be stale about a realtime
	 * takeover, so a CPU a realtime task is running on must not be
	 * returned through this path.
	 */
	if (mlfq_idle_tracking && !mlfq_idle_count &&
	    !mlfq_cpu_occupied(prev_cpu))
		return prev_cpu;

	/*
	 * The waker's LLC domain, resolved once and shared by the
	 * largest-LLC step (1.9), the waker-LLC step (2) and the
	 * least-loaded steering step (2.5). MLFQ_MAX_LLCS marks an
	 * unavailable domain. LLC awareness disabled (mlfq_nr_llcs == 0)
	 * or the waker CPU unmapped leaves the marker set. Steps 2 and 2.5
	 * are dead then, and step 1.9 cannot fire on an unpopulated
	 * machine (its own gates require a populated domain).
	 */
	waker_cpu = (u32)bpf_get_smp_processor_id();
	if (mlfq_nr_llcs > 0 && waker_cpu < MLFQ_MAX_CPUS &&
	    mlfq_cpu_llc[waker_cpu] < MLFQ_MAX_LLCS &&
	    mlfq_cpu_llc[waker_cpu] < mlfq_nr_llcs)
		waker_llc = mlfq_cpu_llc[waker_cpu];
	else
		waker_llc = MLFQ_MAX_LLCS;

	/*
	 * Step 1.9, the largest-LLC bias for interactive wakeups. When the
	 * machine has a strictly-largest LLC domain and it is not the
	 * waker's own (which step 2 is about to scan), an interactive
	 * wakeup is placed there first. Cache capacity serves Q1 latency
	 * best, the clock tradeoff of a larger (often lower-clocked) L3
	 * is worth it for interactive work, and the idle claim is
	 * authoritative, so the bias is non-exclusive. The
	 * mlfq_llc_has_primary gate keeps the "interactive never parks on
	 * an efficiency core" invariant on hybrid systems and
	 * require_primary is an extra defense. The step is dead on
	 * single-LLC machines, on ties or failed discovery (the
	 * MLFQ_MAX_LLCS sentinel), and when the largest domain is the
	 * waker's. The MLFQ_MAX_LLCS bound in the gate keeps the
	 * has_primary index verifier-bounded.
	 */
	if (interactive && mlfq_llc_largest < MLFQ_MAX_LLCS &&
	    mlfq_llc_largest < mlfq_nr_llcs &&
	    mlfq_llc_largest != waker_llc &&
	    mlfq_llc_has_primary[mlfq_llc_largest]) {
		cpu_id = mlfq_pick_idle_in_bitmap(&mlfq_llc_bitmaps,
						  mlfq_llc_largest, p,
						  true, primary_bm);
		if (cpu_id >= 0)
			goto direct;
	}

	/*
	 * Step 2, the LLC-aware placement, keeps the wakeup in the
	 * waker's cache domain. For Q1 an all-efficiency LLC is skipped
	 * entirely so the wakeup can land on an idle primary of a faster
	 * LLC via the global fallbacks below.
	 *
	 * On a machine with a single LLC, the cache domain is the whole
	 * machine, so the kernel's idle scan serves the placement directly
	 * instead of walking the LLC bitmap with a test-and-clear per
	 * candidate. The kernel's scan is affinity- and SMT-aware and
	 * claims the CPU in one call, while the bitmap walk issues one
	 * kfunc call per candidate until it finds an idle one. The
	 * whole-core preference for Q1 matches the step-3 fallback.
	 */
	if (waker_llc < MLFQ_MAX_LLCS &&
	    (!interactive || mlfq_llc_has_primary[waker_llc])) {
		if (mlfq_nr_llcs == 1) {
			cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr,
						       interactive ?
						       SCX_PICK_IDLE_CORE : 0);
			if (cpu_id < 0)
				cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		} else {
			cpu_id = mlfq_pick_idle_in_bitmap(&mlfq_llc_bitmaps,
							  waker_llc, p,
							  interactive,
							  primary_bm);
		}
		if (cpu_id >= 0)
			goto direct;
	}

	/*
	 * Step 2.5, the least-loaded-LLC steering. When the waker-LLC walk
	 * found nothing and other LLCs have an idle CPU, the wakeup is
	 * placed on the least-loaded of them. The per-LLC runnable gauge
	 * is the load metric, the per-LLC idle gate the candidate filter,
	 * and the idle claim inside the bitmap walk stays the
	 * authoritative placement. The selection repeats up to
	 * MLFQ_STEER_LLC_MAX times over the eligible domains in ascending
	 * runnable order (ties by ascending id, so the order is
	 * deterministic), stopping early when a walk claims an idle CPU
	 * or no eligible domain remains. Each failed walk (affinity-stale
	 * bitmap) marks its domain visited so the next pass picks the
	 * next-least-loaded. The gauges are advisory. A stale count costs
	 * one suboptimal but still-idle placement in a race window, never
	 * a correctness issue. This is the same trust model as the
	 * saturation fast path. The step is gated on idle tracking (the
	 * gauges live only then), on more than one LLC (a single-LLC
	 * machine was fully covered by step 2) and on some idle CPU
	 * existing. The per-LLC idle gate excludes every unpopulated
	 * domain, so the all-zero state proceeds to the global fallbacks
	 * unchanged.
	 */
	if (mlfq_idle_tracking && mlfq_nr_llcs > 1 &&
	    mlfq_idle_count > 0) {
		u64 visited = 0;
		u32 attempt;

		bpf_for(attempt, 0, MLFQ_STEER_LLC_MAX) {
			u32 steer_llc = mlfq_steer_pick_llc(mlfq_llc_runnable,
							    mlfq_llc_idle,
							    mlfq_nr_llcs,
							    waker_llc, visited);

			if (steer_llc >= MLFQ_MAX_LLCS)
				break;
			visited |= 1ULL << steer_llc;
			cpu_id = mlfq_pick_idle_in_bitmap(&mlfq_llc_bitmaps,
							  steer_llc, p,
							  interactive,
							  primary_bm);
			if (cpu_id >= 0)
				goto direct;
		}
	}

	/*
	 * Step 3, the global fallbacks. Interactive wakeups prefer an idle
	 * primary core, with the SMT-aware whole-core preference on
	 * uniform-capacity systems. The other queues take any idle CPU.
	 */
	if (interactive) {
		if (mlfq_primary_all) {
			/*
			 * pick_idle_cpu() returns an error when no idle CPU
			 * exists, so the idle-cpumask acquire and the empty
			 * pre-check would only add an acquire/release pair
			 * without changing the result.
			 */
			cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr,
						       SCX_PICK_IDLE_CORE);
			if (cpu_id < 0)
				cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		} else {
			cpu_id = mlfq_pick_idle_primary(p, primary_bm);
			if (cpu_id < 0)
				cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		}
	} else {
		/* Q2/Q3: any idle CPU. */
		cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	}

	if (cpu_id >= 0)
		goto direct;

	/* No idle CPU selected. Decline via prev_cpu (see file header). */
	return prev_cpu;

direct:
	tctx->wake_cpu_state = MLFQ_WAKE_CPU_VALID | MLFQ_WAKE_CPU_IDLE;
	return cpu_id;
}
