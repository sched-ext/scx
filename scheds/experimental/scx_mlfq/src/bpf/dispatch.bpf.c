/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Dispatch: queue service with quotas and cross-CPU stealing, included by
 * main.bpf.c via #include.
 *
 * The kernel serves SCX_DSQ_LOCAL before ops.dispatch() (the dispatch
 * loop in ext.c), so this callback only fills the local DSQ from the
 * per-CPU queue DSQs. Each CPU serves its own three queue DSQs in Q1..Q3
 * priority order, each queue bounded by dispatch_max_batch. Every slot
 * picks the earliest EEVDF deadline among the queue's own head and the
 * heads of remote CPUs' same-queue DSQs (affinity-prechecked), so an idle
 * CPU drains the most-owed task in the system for that queue, not only
 * its own. A remote task is migrated only when its deadline is at least
 * one of its virtual slices ahead of the local head, so a near-tie
 * deadline does not cost the task its cache warmth. The kernel enforces
 * affinity on the move itself: consume_dispatch_q() in ext.c skips heads
 * that cannot run on the consuming CPU, so the BPF pre-check only prefers
 * the earliest eligible head and avoids wasted moves.
 *
 * The three quotas are served by bounded loops: every queue scans a
 * rotating window of at most the init-clamped mlfq_steal_scan candidates,
 * starting at a per-CPU offset that drifts per dispatch call, so the
 * window is fair across the system and no remote CPU is permanently
 * excluded. Each slot is a constant number of peeks and one move, so the
 * loop bodies stay flat and the verifier state small.
 *
 * The keep path runs first, before the slot loops: when the CPU's queue
 * DSQs are empty and the outgoing task is still queued, the task is the
 * only runnable work this CPU can take, so it is kept with a fresh queue
 * slice instead of the CPU idling with runnable work. Before keeping, the
 * three queue heads of one remote CPU (the rotating scan candidate) are
 * probed: a CPU whose own queues are empty should still pull the
 * most-owed remote task instead of running the previous task for a full
 * slice. Resolving the keep up front reads the queue state once, before
 * the slot loops churn it, and keeps the loop bodies to a single job
 * each.
 */

/*
 * mlfq_remote_work_probe - Peek one remote CPU's queue DSQ heads.
 * @cand: Remote CPU to probe.
 * @cpu: Local CPU, the affinity target of the peeked tasks.
 *
 * Three lockless peeks, one per queue DSQ. A head that can run on @cpu
 * means the slot loops below have work to steal.
 *
 * Return: true if any queue DSQ head can run on @cpu.
 */
static __always_inline bool mlfq_remote_work_probe(s32 cand, s32 cpu)
{
	struct task_struct *t;

	t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(1, cand));
	if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
		return true;
	t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(2, cand));
	if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
		return true;
	t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(3, cand));
	if (t && bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
		return true;
	return false;
}

/*
 * mlfq_dispatch_queue - Serve one queue for up to @quota slots.
 * @cpu: CPU running dispatch.
 * @qid: Queue being served (1..3), a constant at each call site.
 * @quota: Number of slots granted to this queue; zero yields no slots.
 * @cpu_state: Per-CPU state of @cpu, may be NULL.
 * @nr_cpus: Snapshot of nr_cpu_ids.
 *
 * Each slot peeks the queue's own head and the heads of the candidate
 * CPUs' same-queue DSQs, affinity-checks each (migration-disabled tasks
 * fail this automatically), and moves the earliest-deadline candidate to
 * the local DSQ. A remote candidate must beat the local head by at least
 * one of its own virtual slices, otherwise the local head is served and
 * the task keeps its cache warmth; with no local head the earliest
 * eligible remote head is taken freely. The candidates are a rotating
 * window of at most mlfq_steal_scan CPUs starting at the per-CPU offset,
 * so the bounded window is fair across the system; on machines smaller
 * than the scan cap the window covers every CPU.
 *
 * Return: The number of tasks moved.
 */
static __always_inline u32
mlfq_dispatch_queue(s32 cpu, u8 qid, u32 quota,
		    struct mlfq_cpu_state *cpu_state, u64 nr_cpus)
{
	u64 own_dsq = mlfq_dsq_id(qid, cpu);
	u32 slot, moved = 0;

	bpf_for(slot, 0, quota) {
		struct task_struct *best = NULL;
		u64 best_dsq = 0;
		s32 best_cpu = cpu;
		u32 cand;
		u32 off = cpu_state ? cpu_state->steal_scan_off % (u32)nr_cpus : 0;
		u32 i;

		/* the queue's own head, affinity-prechecked */
		best = __COMPAT_scx_bpf_dsq_peek(own_dsq);
		if (best && !bpf_cpumask_test_cpu((u32)cpu, best->cpus_ptr))
			best = NULL;
		best_dsq = own_dsq;

		/*
		 * Every queue scans the same bounded rotating window: at
		 * most the init-clamped mlfq_steal_scan candidates starting
		 * at the per-CPU offset. The offset drifts per dispatch
		 * call, so the window is fair across the system.
		 */
		bpf_for(i, 0, mlfq_steal_scan) {
			struct task_struct *t;

			cand = (off + i) % (u32)nr_cpus;
			if (cand == (u32)cpu)
				continue;
			t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(qid, cand));
			if (!t || !bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
				continue;
			/*
			 * A remote candidate is taken only when it beats
			 * the local head by at least one of its own
			 * virtual slices; migrating a task for a smaller
			 * deadline difference would trade its cache
			 * warmth for nothing. Without a local head the
			 * earliest eligible remote head is taken freely.
			 */
			if (best_cpu == cpu && best &&
			    !mlfq_time_before(
				    t->scx.dsq_vtime +
					    calc_delta_fair_bpf(
						    mlfq_queue_slice(qid),
						    (u32)t->scx.weight),
				    best->scx.dsq_vtime))
				continue;
			/*
			 * Prefer the earlier deadline, the same
			 * time_before64() order the kernel's priq
			 * uses (scx_dsq_priq_less()).
			 */
			if (!best || mlfq_time_before(t->scx.dsq_vtime,
						    best->scx.dsq_vtime)) {
				best = t;
				best_dsq = mlfq_dsq_id(qid, cand);
				best_cpu = (s32)cand;
			}
		}

		/* nothing eligible anywhere: this queue has no work */
		if (!best)
			break;

		scx_bpf_dsq_move_to_local(best_dsq, 0);
		moved++;
		if (best_cpu != cpu)
			__sync_fetch_and_add(&mlfq_stats.steals, 1);
	}

	return moved;
}

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct mlfq_cpu_state *cpu_state = mlfq_lookup_cpu_state(cpu);
	u64 nr_cpus = nr_cpu_ids;
	u32 remaining = mlfq_dispatch_max_batch;

	if (nr_cpus == 0)
		return;

	/*
	 * Advance the rotating scan start once per dispatch call. Q1
	 * always scans every candidate, so only the bounded Q2/Q3 windows
	 * consume the offset; per-call rotation keeps the window fair
	 * across CPUs without a per-slot cost.
	 */
	if (cpu_state)
		cpu_state->steal_scan_off++;

	/*
	 * Keep the outgoing task when nothing else is dispatchable here.
	 * If @prev is still queued and all three of the CPU's queue DSQs
	 * are empty, @prev is the only runnable work this CPU can take;
	 * the alternative is switching to idle with runnable work, which
	 * leaves the CPU parked until an external wakeup. Replenish the
	 * queue slice and place @prev on the local DSQ; the pick path then
	 * runs it without a context switch. Spurious inserts are safe
	 * because the kernel claims the task again in finish_dispatch()
	 * (ext.c), dropping the insert if @prev was concurrently dequeued.
	 *
	 * Before keeping, the three queue DSQ heads of one remote CPU (the
	 * rotating scan candidate) are probed: a CPU whose own queues are
	 * empty should still pull the most-owed remote task instead of
	 * running the previous task for a full slice; the probe is three
	 * lockless peeks.
	 *
	 * The kernel's automatic keep path (balance_one() setting
	 * SCX_RQ_BAL_KEEP) is available only while SCX_OPS_ENQ_LAST is
	 * clear. This scheduler sets SCX_OPS_ENQ_LAST, so ops.dispatch()
	 * itself must make the keep effective.
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
					 * Probe the rotating scan candidate;
					 * on a one-CPU machine there is no
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
					if (scx_bpf_dsq_insert(prev, SCX_DSQ_LOCAL,
							       slice, 0)) {
						__sync_fetch_and_add(
							&mlfq_stats.keep_running, 1);
						return;
					}
					/*
					 * The outgoing task may have been
					 * stolen by a remote CPU between its
					 * re-enqueue and this dispatch; the
					 * insert then fails and the slot
					 * loops should run instead of
					 * aborting the cycle.
					 */
				}
				/* remote work or a failed keep insert: the slot loops steal */
			}
		}
	}

	/*
	 * Q1 then Q2 then Q3, each bounded by the dispatch batch. The
	 * quotas need no clamping: init() rejects configurations with
	 * Q1+Q2 >= dispatch_max_batch, so each fixed quota always fits in
	 * the batch remainder, and a zero remainder yields an empty slot
	 * loop.
	 */
	remaining -= mlfq_dispatch_queue(cpu, 1, mlfq_q1_quota,
					 cpu_state, nr_cpus);
	remaining -= mlfq_dispatch_queue(cpu, 2, mlfq_q2_quota,
					 cpu_state, nr_cpus);
	remaining -= mlfq_dispatch_queue(cpu, 3, remaining,
					 cpu_state, nr_cpus);
}
