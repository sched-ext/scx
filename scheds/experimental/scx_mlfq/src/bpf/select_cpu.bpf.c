/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * CPU selection, included by main.bpf.c via #include.
 *
 * Placement preference, in order: the prev CPU when idle, an idle CPU in
 * the waker's LLC, then the global fallbacks (an idle primary core for
 * Q1, any idle CPU otherwise). The per-step detail is at the
 * corresponding points in mlfq_select_cpu() below. When no CPU is
 * selected, prev_cpu is returned: the kernel validates the return as a
 * CPU number (any negative value aborts the scheduler), and the task
 * then goes through the normal enqueue path into the owning CPU's queue
 * vtime DSQ.
 *
 * With SCX_OPS_ENQ_MIGRATION_DISABLED the kernel never invokes this
 * callback for migration-disabled tasks.
 *
 * The primary-core and LLC sets live in ARRAY map values as plain u64
 * bitmaps (see main.bpf.c), written by the Rust front-end after load and
 * read directly as map values. An unpopulated map entry means "no data":
 * the primary bitmap is treated as all-primary and an empty LLC bitmap
 * yields no idle candidate.
 */

/*
 * The primary-core bitmap, or NULL when every CPU is primary. Looked up
 * once per select_cpu() call and passed down: the map value is immutable
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
 * Global primary-core scan: pick an idle primary CPU, or -ENOENT. Every
 * member of the primary bitmap is primary by construction, so the
 * require_primary restriction is unnecessary here.
 */
static __always_inline s32
mlfq_pick_idle_primary(const struct task_struct *p,
		       const struct mlfq_bitmap *primary_bm)
{
	return mlfq_pick_idle_in_bitmap(&mlfq_primary_bitmap, 0, p, false,
					primary_bm);
}

s32 BPF_STRUCT_OPS(mlfq_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx;
	const struct mlfq_bitmap *primary_bm;
	u32 first_cpu, waker_cpu, waker_llc;
	s32 cpu_id = -1;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/* Clear any fast-path state from a previous select_cpu(). */
	tctx->wake_cpu_state = 0;

	/* The task may not be allowed on prev_cpu (cpuset); fix that up. */
	if (!bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
		first_cpu = bpf_cpumask_first(p->cpus_ptr);
		if (first_cpu >= nr_cpu_ids)
			/*
			 * An empty allowed mask leaves the out-of-affinity
			 * return in place; the kernel's own return
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
	 * Step 1: prev CPU fast path. The prev CPU is preferred when idle
	 * for cache locality. An interactive task on a hybrid system only
	 * sticks to prev when it is a primary core: settling an interactive
	 * wakeup on an efficiency core would trade cache warmth for
	 * sustained capacity. The idle mark is cleared only after the
	 * primary check passes, so an idle efficiency core is never lost
	 * from the idle pool for a Q1 wakeup.
	 */
	if ((tctx->queue != 1 || mlfq_is_primary(primary_bm, prev_cpu)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu_id = prev_cpu;
		goto direct;
	}

	/*
	 * Step 2: LLC-aware placement, which keeps the wakeup in the waker's
	 * cache domain. The waker is the current CPU. For Q1 an
	 * all-efficiency LLC is skipped entirely so the wakeup can land on
	 * an idle primary of a faster LLC via the global fallbacks below.
	 *
	 * On a machine with a single LLC the cache domain is the whole
	 * machine, so the kernel's idle scan serves the placement directly
	 * instead of walking the LLC bitmap with a test-and-clear per
	 * candidate: the kernel's scan is affinity- and SMT-aware and
	 * claims the CPU in one call, while the bitmap walk issues one
	 * kfunc call per candidate until it finds an idle one. The
	 * whole-core preference for Q1 matches the step-3 fallback.
	 */
	waker_cpu = (u32)bpf_get_smp_processor_id();
	if (mlfq_nr_llcs > 0 && waker_cpu < MLFQ_MAX_CPUS) {
		waker_llc = mlfq_cpu_llc[waker_cpu];
		if (waker_llc < MLFQ_MAX_LLCS && waker_llc < mlfq_nr_llcs &&
		    (tctx->queue != 1 || mlfq_llc_has_primary[waker_llc])) {
			if (mlfq_nr_llcs == 1) {
				cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr,
							       tctx->queue == 1 ?
							       SCX_PICK_IDLE_CORE : 0);
				if (cpu_id < 0)
					cpu_id = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			} else {
				cpu_id = mlfq_pick_idle_in_bitmap(&mlfq_llc_bitmaps,
								  waker_llc, p,
								  tctx->queue == 1,
								  primary_bm);
			}
			if (cpu_id >= 0)
				goto direct;
		}
	}

	/*
	 * Step 3: global fallbacks. Q1 prefers an idle primary core, with
	 * the SMT-aware whole-core preference on uniform-capacity systems;
	 * Q2/Q3 take any idle CPU.
	 */
	if (tctx->queue == 1) {
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

	/* No idle CPU selected: decline via prev_cpu (see file header). */
	return prev_cpu;

direct:
	tctx->wake_cpu_state = MLFQ_WAKE_CPU_VALID | MLFQ_WAKE_CPU_IDLE;
	return cpu_id;
}
