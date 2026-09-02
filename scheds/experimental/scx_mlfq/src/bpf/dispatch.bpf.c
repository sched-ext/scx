/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Dispatch, the queue service with quotas and cross-CPU stealing, is included by
 * main.bpf.c via #include.
 *
 * The kernel serves SCX_DSQ_LOCAL before ops.dispatch() (the dispatch
 * loop in ext.c), so this callback only fills the local DSQ from the
 * per-CPU queue DSQs. Each CPU serves its own three queue DSQs in Q1..Q3
 * priority order, each queue bounded by dispatch_max_batch. A queue's own
 * DSQ is consumed first, directly from its head: the kernel keeps each
 * vtime DSQ's list in deadline order (scx_dsq_priq_less), so every
 * scx_bpf_dsq_move_to_local() pops the min-deadline head without a peek
 * or a scan, and the kernel re-validates affinity on the move. When the
 * own queue does not fill its quota, the remaining slots steal from
 * remote CPUs' same-queue DSQs in two tiers. Tier A scans the consuming
 * CPU's own LLC domain first. A flat, compile-time-bounded window over
 * the per-LLC CPU list (mlfq_llc_cpus, looked up once per dispatch call
 * and immutable after load), gated by a cheap nr_queued check before
 * each peek, keeps stolen work inside the consuming CPU's cache domain.
 * Only when Tier A finds nothing does Tier B scan the cross-LLC rotating
 * window of remote CPUs, now skipping the same-LLC candidates Tier A
 * already probed. On a single-LLC machine the own-LLC list is the whole
 * machine, so Tier A covers it and Tier B never runs. The candidate set,
 * the rotation and the deadline-major choice reproduce the pre-LLC
 * behavior. With LLC awareness unpopulated (map lookup failed or
 * mlfq_nr_llcs == 0) Tier A is skipped and Tier B degrades to today's
 * plain window, including its same-LLC probing. In both tiers the
 * earliest eligible remote deadline wins. The kernel enforces affinity
 * on the move itself: consume_dispatch_q() in ext.c skips heads that
 * cannot run on the consuming CPU, so the BPF pre-check only prefers the
 * earliest eligible head and avoids wasted moves.
 *
 * The three quotas are served by bounded loops: every queue consumes its
 * own DSQ with a quota-bounded move loop, then scans at most the
 * init-clamped mlfq_steal_scan cross-LLC candidates (Tier B), after a
 * flat MLFQ_LLC_SCAN_MAX window over the own-LLC list (Tier A), both
 * starting at a per-CPU offset that drifts per dispatch call, so the
 * window is fair across the system and no remote CPU is permanently
 * excluded. The loop bodies stay flat (one move per slot, one peek per
 * gated candidate) and the verifier state small.
 *
 * The keep path runs first, before the slot loops. balance() runs before
 * put_prev_task() in the scheduling pass, and with SCX_OPS_ENQ_LAST set
 * the kernel does not keep prev automatically, so when prev is still
 * queued and all three of the CPU's queue DSQs are empty, the keep path
 * grants prev a fresh slice and returns, without inserting prev into the
 * local DSQ. balance_one()'s post-dispatch keep (prev_on_rq && slice)
 * then runs the task without a context switch. The grant alone is the
 * whole keep. A resident local-DSQ entry would shadow the queue DSQs on
 * every later dispatch cycle (ext.c takes the local DSQ before
 * ops.dispatch()) because a kept prev is never popped
 * (put_prev_set_next_task() early-returns on next == prev), refilling the
 * task at the 20 ms SCX_SLICE_DFL granularity and freezing
 * running()/stopping() accounting until the next real context switch.
 * Before keeping, the three queue heads of one remote CPU (the rotating
 * scan candidate) are probed. A CPU whose own queues are empty should
 * still pull the most-owed remote task instead of running the previous
 * task for a full slice. Resolving the keep up front reads the queue
 * state once, before the slot loops churn it, and keeps the loop bodies
 * to a single job each.
 *
 * Realtime-takeover interaction. Stealing from an occupied CPU's queue
 * DSQs stays legal. The steal scan is the second evacuation channel
 * for tasks stranded by a takeover, and no path dispatches to an
 * occupied CPU's local DSQ. Dispatch runs only on CPUs the kernel hands
 * to sched_ext, and the class-pick loop reaches sched_ext only when no
 * higher-priority class has a runnable task.
 */

/*
 * mlfq_remote_work_probe - Peek one remote CPU's queue DSQ heads.
 * @cand: Remote CPU to probe.
 * @cpu: Local CPU, the affinity target of the peeked tasks.
 *
 * Three lockless peeks, one per queue DSQ, each gated on nr_queued so an
 * empty DSQ is skipped without a peek. A head that can run on @cpu means
 * the slot loops below have work to steal.
 *
 * Return: true if any queue DSQ head can run on @cpu.
 */
static __always_inline bool mlfq_remote_work_probe(s32 cand, s32 cpu)
{
	struct task_struct *t;

	if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cand))) {
		t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(1, cand));
		if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
			return true;
	}
	if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cand))) {
		t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(2, cand));
		if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
			return true;
	}
	if (scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cand))) {
		t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(3, cand));
		if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
			return true;
	}
	return false;
}

/*
 * mlfq_dispatch_queue - Serve one queue for up to @quota slots.
 * @cpu: CPU running dispatch.
 * @qid: Queue being served (1..3), a constant at each call site.
 * @quota: Number of slots granted to this queue. Zero yields no slots.
 * @cpu_state: Per-CPU state of @cpu, may be NULL.
 * @nr_cpus: Snapshot of nr_cpu_ids.
 * @own_llc_list: The consuming CPU's own-LLC CPU list, hoisted once per
 *	dispatch call and immutable after load. NULL when LLC awareness is
 *	unpopulated for this CPU, which skips Tier A. The Tier-A window
 *	base is derived from it inside the null-checked branch (see the
 *	prologue).
 * @own_llc: The consuming CPU's LLC domain id, valid (below
 *	MLFQ_MAX_LLCS) exactly when @own_llc_list is non-NULL. The
 *	validated same-domain filter for Tier B.
 *
 * Each slot serves the queue's own head first: scx_bpf_dsq_move_to_local()
 * pops the min-deadline head of the own DSQ (the kernel keeps a vtime
 * DSQ's list in deadline order, scx_dsq_priq_less) and re-validates
 * affinity on the move, so no peek or scan is needed for the local work.
 * Only when the own head is gone does the slot steal, in two tiers.
 * Tier A scans a flat MLFQ_LLC_SCAN_MAX window over @own_llc_list, the
 * consuming CPU's cache domain, so same-LLC work is pulled before any
 * cross-LLC probe. Tier B, reached only when Tier A found nothing and
 * only when a cross-LLC candidate set exists (the whole-machine
 * single-LLC case was covered by Tier A), scans the rotating window of
 * remote CPUs' same-queue DSQs and skips the same-LLC candidates Tier A
 * already probed. Each candidate of both tiers is gated on nr_queued
 * before its peek, and the earliest eligible deadline among the peeked
 * heads is moved once per slot. On machines smaller than the scan cap
 * the window covers every remote CPU.
 *
 * With the own head drained, there is no local deadline to protect, so
 * the steal takes the earliest eligible remote head freely. The own-first
 * order still guarantees that every local head is served before any
 * remote one within the quota, and the tier order guarantees that a
 * same-LLC head always beats a cross-LLC head regardless of deadline.
 * This is the intended cache-warmth policy.
 *
 * The single slot loop also keeps the verifier's exploration bounded. A
 * second loop whose bound depends on how many moves the first one made
 * cannot converge within the kernel's jump-sequence limit.
 *
 * Return: The number of tasks moved.
 */
static __always_inline u32
mlfq_dispatch_queue(s32 cpu, u8 qid, u32 quota,
		    struct mlfq_cpu_state *cpu_state, u64 nr_cpus,
		    const struct mlfq_llc_cpu_list *own_llc_list,
		    u32 own_llc)
{
	u64 own_dsq = mlfq_dsq_id(qid, cpu);
	u32 slot, moved = 0;
	u32 tier_a_nr = 0;
	u32 key0 = 0;
	const struct mlfq_llc_cpu_list *base_list;
	const u32 *llc_cpus;

	/*
	 * The constant-key lookup of entry 0 always succeeds (an ARRAY
	 * map lookup with a known in-range key is non-NULL by verifier
	 * contract), so base_list is a valid map value and llc_cpus is a
	 * non-null cpus[] base in every path. The populated-domain branch
	 * below replaces it with the consuming CPU's own-LLC base, taken
	 * from the null-checked own_llc_list. Keeping the base non-null
	 * everywhere is what lets the slot loop index it directly.
	 * clang's loop-invariant code motion would otherwise hoist the
	 * &list->cpus[] address computation above the null check, and the
	 * BPF verifier rejects pointer arithmetic on a possibly-null map
	 * value ("map_value_or_null").
	 *
	 * The gate is the populated-state test. A NULL list (LLC
	 * awareness disabled or the CPU unmapped), a zero nr (an
	 * oversized domain the front-end left empty), or an out-of-range
	 * domain id keeps tier_a_nr at zero, the tier stays dead, and the
	 * dispatch degrades to the plain rotating window.
	 */
	base_list = bpf_map_lookup_elem(&mlfq_llc_cpus, &key0);
	if (!base_list)
		return 0;
	llc_cpus = base_list->cpus;

	if (own_llc_list && own_llc_list->nr > 0 && own_llc < mlfq_nr_llcs) {
		llc_cpus = own_llc_list->cpus;
		tier_a_nr = own_llc_list->nr;
		if (tier_a_nr > MLFQ_LLC_SCAN_MAX)
			tier_a_nr = MLFQ_LLC_SCAN_MAX;
	}

	/* Hoist off and mlfq_dsq_id reuse: off computed once per queue, dsq ids reused via locals. 3072 tail cut documented: MLFQ_ALPHA 3072 is the EMA tail cut. No new bpf_for. */
	u32 off = cpu_state ? cpu_state->steal_scan_off % (u32)nr_cpus : 0;

	bpf_for(slot, 0, quota) {
		struct task_struct *best = NULL;
		u64 best_dsq = 0;
		s32 best_cpu = cpu;
		u32 cand, i;
		bool tier_a_ran = false;

		/*
		 * Own head first: move_to_local pops the min-deadline head
		 * of the own DSQ and returns false when the DSQ is empty
		 * or nothing can run on this CPU, which then proceeds
		 * to the steal scan. The move is same-LLC by construction.
		 * The source DSQ is owned by this consuming CPU, so the
		 * task's LLC ownership record is unchanged and no
		 * runnable-accounting adjustment is needed (the ownership
		 * adjust only fires at the steal below, where the source
		 * DSQ is remote and the domain may differ).
		 */
		if (scx_bpf_dsq_move_to_local(own_dsq, 0)) {
			moved++;
			continue;
		}

		/*
		 * Tier A, the same-LLC steal. The flat window over the
		 * consuming CPU's own-LLC list keeps stolen work inside
		 * the cache domain; the window starts at the same rotating
		 * offset as Tier B so the drift is shared and the rotation
		 * stays fair. The candidate index wraps with a
		 * compile-time-constant modulo (MLFQ_LLC_SCAN_MAX). The
		 * verifier only bounds a division/modulo result when the
		 * divisor is a constant, and list->nr is runtime, so a
		 * modulo by nr would leave the index unbounded and the
		 * cpus[] access unverifiable. The window covers the whole
		 * populated list because the front-end never publishes a
		 * longer one. MLFQ_MAX_LLC_CPUS equals the window width,
		 * so a populated domain has at most MLFQ_LLC_SCAN_MAX CPUs
		 * and the constant-modulo window is exactly the design's
		 * rotating (off + i) % nr window over the domain. The wrap
		 * order rotates the start, and the idx >= nr guard skips
		 * the list padding beyond the populated count (the zeroed
		 * tail of the map value). The window base and the entry
		 * count were hoisted out of the slot loop above; a zero
		 * count (the unpopulated map state, or a domain too large
		 * for the window that the front-end left empty) keeps
		 * tier_a_ran false, so Tier B's rotating window covers
		 * such a domain below, its same-LLC skip dead. Each
		 * candidate is gated on nr_queued before its peek, exactly
		 * like the Tier B window.
		 */
		if (tier_a_nr > 0) {
			u32 nr = tier_a_nr;

			tier_a_ran = true;
			bpf_for(i, 0, MLFQ_LLC_SCAN_MAX) {
				struct task_struct *t;
				u64 cand_dsq;
				u32 idx = (off + i) % MLFQ_LLC_SCAN_MAX;

				if (idx >= nr)
					continue;
				cand = llc_cpus[idx];
				if (cand == (u32)cpu)
					continue;
				cand_dsq = mlfq_dsq_id(qid, cand);
				/* Tighten nr_queued gate before peek, hoist dsq id. */
				if (!scx_bpf_dsq_nr_queued(cand_dsq))
					continue;
				t = __COMPAT_scx_bpf_dsq_peek(cand_dsq);
				if (!t || !bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
					continue;
				if (!best ||
				    mlfq_time_before(t->scx.dsq_vtime,
						     best->scx.dsq_vtime)) {
					best = t;
					best_dsq = cand_dsq;
					best_cpu = (s32)cand;
				}
			}
		}

		/*
		 * Tier B, the cross-LLC steal, runs only when Tier A found nothing
		 * and only when a cross-LLC candidate set exists. On a
		 * single-LLC machine Tier A scanned the whole machine, so
		 * this tier must not run. When Tier A could not run at all, because
		 * LLC awareness is unpopulated, the own list is empty (an oversized
		 * domain whose list the front-end left at nr == 0), or the consuming
		 * CPU is unmapped. tier_a_ran stays false, the same-LLC skip below
		 * is dead, and this tier is today's plain rotating window. The full
		 * window
		 * covers the domain, oversized or not, and the unpopulated
		 * state reproduces the pre-LLC behavior exactly. The skip
		 * compares raw mlfq_cpu_llc values, so an unmapped
		 * candidate (the MLFQ_MAX_LLCS sentinel) can never equal a
		 * valid own_llc and is always probed.
		 */
		if (!best && (!tier_a_ran || mlfq_nr_llcs != 1)) {
			bpf_for(i, 0, mlfq_steal_scan) {
				struct task_struct *t;

				cand = (off + i) % (u32)nr_cpus;
				if (cand == (u32)cpu)
					continue;
				/*
				 * The index is masked to the array bound for
				 * the verifier. The modulo only proves
				 * cand < nr_cpus, and nr_cpus is a runtime
				 * value whose upper bound the verifier
				 * cannot derive (the ALU32 modulo also
				 * leaves the register's high bits
				 * unbounded), so the mlfq_cpu_llc[] access
				 * needs the explicit mask. Identity at
				 * runtime. init() rejects machines above
				 * MLFQ_MAX_CPUS, so cand < nr_cpus <=
				 * MLFQ_MAX_CPUS and the mask never wraps
				 * a valid candidate.
				 */
				/* Tier A already probed the same-LLC set. */
				if (tier_a_ran &&
				    mlfq_cpu_llc[cand & (MLFQ_MAX_CPUS - 1)] == own_llc)
					continue;
				/*
				 * Gate on nr_queued first: a cheap lockless
				 * read that skips the peek for empty DSQs. Hoist dsq id.
				 */
				{
					u64 cand_dsq = mlfq_dsq_id(qid, cand);

					if (!scx_bpf_dsq_nr_queued(cand_dsq))
						continue;
					t = __COMPAT_scx_bpf_dsq_peek(cand_dsq);
					if (!t || !bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
						continue;
					/*
					 * Prefer the earlier deadline, the same
					 * time_before64() order the kernel's priq
					 * uses (scx_dsq_priq_less()).
					 */
					if (!best ||
					    mlfq_time_before(t->scx.dsq_vtime,
							     best->scx.dsq_vtime)) {
						best = t;
						best_dsq = cand_dsq;
						best_cpu = (s32)cand;
					}
				}
			}
		}

		/* Nothing eligible anywhere. This queue has no work. */
		if (!best)
			break;

		/*
		 * The move is not guaranteed to succeed: the kernel
		 * re-validates affinity on the move, so a concurrent
		 * cpuset change can fail it. Only a successful move
		 * counts and adjusts the runnable-ownership record.
		 */
		if (scx_bpf_dsq_move_to_local(best_dsq, 0)) {
			struct task_ctx *tctx = mlfq_lookup_task_ctx(best);

			/*
			 * The task moved into this CPU's local DSQ, so
			 * its LLC ownership moved to this CPU's domain.
			 * The helper's continuation path does the
			 * old-1/new+1 when the domain differs (the
			 * cross-LLC steal) and nothing when it does not.
			 * The queue cannot change at a dispatch move.
			 *
			 * The ownership adjust is approximate under
			 * concurrency. @best is the DSQ head at peek time,
			 * but consume_dispatch_q() pops the first head
			 * ELIGIBLE at move time under the DSQ lock, and a
			 * concurrent dispatcher or a cpuset change between
			 * this pre-check and the kernel move can make the
			 * moved task differ from @best. The head-pop API
			 * offers no post-move verification, so the adjust
			 * targets @best regardless; the gauges are advisory
			 * and self-heal at the moved task's next episode
			 * boundary (mlfq_runnable_exit()).
			 */
			if (tctx)
				mlfq_runnable_enter(tctx, qid,
						    mlfq_llc_of_cpu((u32)cpu));
			moved++;
			if (best_cpu != cpu) {
				__sync_fetch_and_add(&mlfq_stats.steals, 1);
				/*
				 * The same/cross-LLC split is defined only
				 * when LLC awareness is populated
				 * (mlfq_nr_llcs > 0 makes the
				 * mlfq_llc_of_cpu() domains valid). With it,
				 * a same-domain steal lands in
				 * steals_same_llc and a cross-domain one in
				 * steals_cross_llc. On a single-LLC machine
				 * every steal is same-domain by construction
				 * (Tier A only, Tier B dead), and on an
				 * LLC-disabled machine the split counters
				 * stay at zero.
				 */
				if (mlfq_nr_llcs > 0) {
					if (mlfq_llc_of_cpu((u32)best_cpu) ==
					    mlfq_llc_of_cpu((u32)cpu)) {
						__sync_fetch_and_add(&mlfq_stats.steals_same_llc,
								     1);
					} else {
						__sync_fetch_and_add(&mlfq_stats.steals_cross_llc,
								     1);
					}
				}
			}
		}
	}

	return moved;
}

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct mlfq_cpu_state *cpu_state = mlfq_lookup_cpu_state(cpu);
	const struct mlfq_llc_cpu_list *own_llc_list = NULL;
	u32 own_llc = MLFQ_MAX_LLCS;
	u64 nr_cpus = nr_cpu_ids;
	u32 remaining = mlfq_dispatch_max_batch;
	u64 op_lat_start = scx_bpf_now();

	/* Rate-limited adaptation step, before any state is touched. */
	mlfq_maybe_adapt_step(op_lat_start);

	if (nr_cpus == 0) {
		mlfq_op_lat_charge(MLFQ_OP_LAT_DISPATCH, op_lat_start);
		return;
	}

	/*
	 * Hoist the own-LLC CPU list lookup once per dispatch call, not
	 * per slot: the consuming CPU's domain membership fixes the
	 * Tier-A same-LLC steal window for all three queues. The map
	 * value is immutable after load, so the single lookup is valid
	 * for the whole call (the same contract as the primary-bitmap
	 * hoist in select_cpu). The lookup result is NULL when LLC
	 * awareness is disabled (mlfq_nr_llcs == 0) or the CPU is
	 * unmapped, which skips Tier A and degrades the dispatch to the
	 * plain rotating window.
	 */
	if (cpu >= 0 && (u32)cpu < MLFQ_MAX_CPUS) {
		own_llc = mlfq_cpu_llc[(u32)cpu];
		if (own_llc < mlfq_nr_llcs) {
			u32 key = own_llc;

			own_llc_list = bpf_map_lookup_elem(&mlfq_llc_cpus, &key);
		}
	}

	/*
	 * Advance the rotating scan start once per dispatch call. All
	 * three queues share the same bounded window: every slot scans at
	 * most the init-clamped mlfq_steal_scan candidates. On machines at
	 * or below the scan cap the window covers every CPU, so the offset
	 * rotation only matters on larger machines, where per-call rotation
	 * keeps the window fair across CPUs without a per-slot cost.
	 */
	if (cpu_state)
		cpu_state->steal_scan_off++;

	/*
	 * Keep the outgoing task when nothing else is dispatchable here.
	 * balance() runs before put_prev_task() in the scheduling pass,
	 * and with SCX_OPS_ENQ_LAST set the kernel does not keep prev
	 * automatically (ext.c). So when @prev is still queued and all
	 * three of the CPU's queue DSQs are empty, @prev is the only
	 * runnable work this CPU can take. The alternative is switching to
	 * idle with runnable work, which leaves the CPU parked until an
	 * external wakeup. Replenishing the queue slice alone makes
	 * balance_one()'s post-dispatch keep (prev_on_rq &&
	 * prev->scx.slice) run @prev again without a context switch, so
	 * the keep path grants the slice and returns without inserting
	 * @prev into the local DSQ. A resident local-DSQ entry would shadow
	 * the queue DSQs on every later dispatch cycle (ext.c takes the
	 * local DSQ before ops.dispatch()), because a kept prev is never
	 * popped (put_prev_set_next_task() early-returns on next == prev).
	 * The task would instead be served off that entry, refilled at the
	 * 20 ms SCX_SLICE_DFL granularity, with running()/stopping()
	 * accounting frozen until the next real context switch. With no
	 * DSQ entry, the next real context switch re-enqueues @prev
	 * through put_prev_task_scx(), with ops.enqueue() and flags == 0 on
	 * slice exhaustion and the SCX_ENQ_HEAD local insert when slice
	 * remains, so queue
	 * placement and accounting resume naturally.
	 *
	 * The keep is an accounting freeze. While it repeats, no context
	 * switch happens, so vruntime, the queue clock, the EMA gauges and
	 * the tree features see none of the real time that passes. The
	 * freeze is bounded by competition arrival or by @prev sleeping
	 * (the gate requires all three queue DSQs empty, so any enqueue
	 * ends it at the next dispatch), and the next real placement
	 * re-anchors under the lag clamp, so the bounded-lag safety
	 * property is unaffected. The cost is that a solo task's
	 * classification gauges under-count its run until the freeze ends.
	 *
	 * Before keeping, the three queue DSQ heads of one remote CPU (the
	 * rotating scan candidate) are probed: a CPU whose own queues are
	 * empty should still pull the most-owed remote task instead of
	 * running the previous task for a full slice. The probe is gated
	 * on nr_queued and is three lockless peeks.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu))) {
		struct task_ctx *tctx = mlfq_lookup_task_ctx(prev);
		u8 qid;

		if (tctx) {
			qid = tctx->queue;
			if (qid >= 1 && qid <= MLFQ_NR_QUEUES) {
				u64 slice = mlfq_queue_slice(qid);
				s32 cand;
				bool remote_work = false;

				if (nr_cpus > 1) {
					/*
					 * Probe the rotating scan candidate.
					 * On a one-CPU machine there is no
					 * remote CPU to probe.
					 */
					cand = cpu_state ?
						(s32)(cpu_state->steal_scan_off %
						      (u32)nr_cpus) : 0;
					if (cand == cpu)
						cand = (s32)(((u32)cand + 1) %
							     (u32)nr_cpus);
					remote_work = mlfq_remote_work_probe(cand, cpu);
				}
				if (!remote_work) {
					scx_bpf_task_set_slice(prev, slice);
					/*
					 * The keep grant runs @prev for a
					 * fresh slice without a context
					 * switch, so no ops.running() fires.
					 * Clear the enqueue stamp of the
					 * run-out re-enqueue, or the next
					 * measurement would charge the whole
					 * keep to the wait. Policy is
					 * untouched; only the measurement
					 * state is cleared.
					 */
					tctx->enq_at = 0;
					__sync_fetch_and_add(
						&mlfq_stats.keep_running, 1);
					mlfq_op_lat_charge(MLFQ_OP_LAT_DISPATCH,
							  op_lat_start);
					return;
				}
				/* Remote work present. The slot loops steal. */
			}
		}
	}

	/*
	 * Q1 then Q2 then Q3, each bounded by the dispatch batch. The
	 * quotas need no clamping. init() rejects configurations with
	 * Q1+Q2 >= dispatch_max_batch, so each fixed quota always fits in
	 * the batch remainder, and a zero remainder yields an empty slot
	 * loop.
	 */
	remaining -= mlfq_dispatch_queue(cpu, 1, mlfq_q1_quota,
					 cpu_state, nr_cpus,
					 own_llc_list, own_llc);
	remaining -= mlfq_dispatch_queue(cpu, 2, mlfq_q2_quota,
					 cpu_state, nr_cpus,
					 own_llc_list, own_llc);
	remaining -= mlfq_dispatch_queue(cpu, 3, remaining,
					 cpu_state, nr_cpus,
					 own_llc_list, own_llc);

	mlfq_op_lat_charge(MLFQ_OP_LAT_DISPATCH, op_lat_start);
}
