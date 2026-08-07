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
 * priority order, each queue bounded by dispatch_max_batch. A queue's own
 * DSQ is consumed first, directly from its head: the kernel keeps each
 * vtime DSQ's list in deadline order (scx_dsq_priq_less), so every
 * scx_bpf_dsq_move_to_local() pops the min-deadline head without a peek
 * or a scan, and the kernel re-validates affinity on the move. When the
 * own queue does not fill its quota, the remaining slots scan a bounded
 * window of remote CPUs' same-queue DSQs, gated by a cheap nr_queued
 * check before each peek; among the eligible remote heads the earliest
 * deadline wins. The kernel enforces affinity on the move itself:
 * consume_dispatch_q() in ext.c skips heads that cannot run on the
 * consuming CPU, so the BPF pre-check only prefers the earliest eligible
 * head and avoids wasted moves.
 *
 * The three quotas are served by bounded loops: every queue consumes its
 * own DSQ with a quota-bounded move loop, then scans a rotating window of
 * at most the init-clamped mlfq_steal_scan candidates, starting at a
 * per-CPU offset that drifts per dispatch call, so the window is fair
 * across the system and no remote CPU is permanently excluded. The loop
 * bodies stay flat (one move per slot, one peek per gated candidate) and
 * the verifier state small.
 *
 * The keep path runs first, before the slot loops. balance() runs before
 * put_prev_task() in the scheduling pass, and with SCX_OPS_ENQ_LAST set
 * the kernel does not keep prev automatically, so when prev is still
 * queued and all three of the CPU's queue DSQs are empty, the keep path
 * grants prev a fresh slice and returns, without inserting prev into the
 * local DSQ; balance_one()'s post-dispatch keep (prev_on_rq && slice)
 * then runs the task without a context switch. The grant alone is the
 * whole keep: a resident local-DSQ entry would shadow the queue DSQs on
 * every later dispatch cycle (ext.c takes the local DSQ before
 * ops.dispatch()) because a kept prev is never popped
 * (put_prev_set_next_task() early-returns on next == prev), refilling the
 * task at the 20 ms SCX_SLICE_DFL granularity and freezing
 * running()/stopping() accounting until the next real context switch.
 * Before keeping, the three queue heads of one remote CPU (the rotating
 * scan candidate) are probed: a CPU whose own queues are empty should
 * still pull the most-owed remote task instead of running the previous
 * task for a full slice. Resolving the keep up front reads the queue
 * state once, before the slot loops churn it, and keeps the loop bodies
 * to a single job each.
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
 * @quota: Number of slots granted to this queue; zero yields no slots.
 * @cpu_state: Per-CPU state of @cpu, may be NULL.
 * @nr_cpus: Snapshot of nr_cpu_ids.
 *
 * Each slot serves the queue's own head first: scx_bpf_dsq_move_to_local()
 * pops the min-deadline head of the own DSQ (the kernel keeps a vtime
 * DSQ's list in deadline order, scx_dsq_priq_less) and re-validates
 * affinity on the move, so no peek or scan is needed for the local work.
 * Only when the own head is gone does the slot scan a rotating window of
 * remote CPUs' same-queue DSQs: at most the init-clamped mlfq_steal_scan
 * candidates starting at the per-CPU offset, so the bounded window is
 * fair across the system; on machines smaller than the scan cap the
 * window covers every CPU. Each candidate is gated on nr_queued before
 * its peek, and the earliest eligible deadline among the peeked heads is
 * moved once per slot.
 *
 * With the own head drained there is no local deadline to protect, so
 * the steal takes the earliest eligible remote head freely; the own-first
 * order still guarantees that every local head is served before any
 * remote one within the quota.
 *
 * The single slot loop also keeps the verifier's exploration bounded: a
 * second loop whose bound depends on how many moves the first one made
 * cannot converge within the kernel's jump-sequence limit.
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
		u32 cand, i;
		u32 off = cpu_state ? cpu_state->steal_scan_off % (u32)nr_cpus : 0;

		/*
		 * Own head first: move_to_local pops the min-deadline head
		 * of the own DSQ and returns false when the DSQ is empty
		 * or nothing can run on this CPU, which then falls through
		 * to the steal scan.
		 */
		if (scx_bpf_dsq_move_to_local(own_dsq, 0)) {
			moved++;
			continue;
		}

		/*
		 * The own queue is drained: scan the bounded rotating
		 * window of remote candidates, gated on nr_queued before
		 * each peek.
		 */
		bpf_for(i, 0, mlfq_steal_scan) {
			struct task_struct *t;

			cand = (off + i) % (u32)nr_cpus;
			if (cand == (u32)cpu)
				continue;
			/*
			 * Gate on nr_queued first: a cheap lockless read
			 * that skips the peek for empty DSQs.
			 */
			if (!scx_bpf_dsq_nr_queued(mlfq_dsq_id(qid, cand)))
				continue;
			t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(qid, cand));
			if (!t || !bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
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
	 * runnable work this CPU can take; the alternative is switching to
	 * idle with runnable work, which leaves the CPU parked until an
	 * external wakeup. Replenishing the queue slice alone makes
	 * balance_one()'s post-dispatch keep (prev_on_rq &&
	 * prev->scx.slice) run @prev again without a context switch, so
	 * the keep path grants the slice and returns without inserting
	 * @prev into the local DSQ. A resident local-DSQ entry would shadow
	 * the queue DSQs on every later dispatch cycle (ext.c takes the
	 * local DSQ before ops.dispatch()), because a kept prev is never
	 * popped (put_prev_set_next_task() early-returns on next == prev);
	 * the task would instead be served off that entry, refilled at the
	 * 20 ms SCX_SLICE_DFL granularity, with running()/stopping()
	 * accounting frozen until the next real context switch. With no
	 * DSQ entry, the next real context switch re-enqueues @prev
	 * through put_prev_task_scx() (slice-exhausted: ops.enqueue() with
	 * flags == 0; slice-left: SCX_ENQ_HEAD local insert), so queue
	 * placement and accounting resume naturally.
	 *
	 * Before keeping, the three queue DSQ heads of one remote CPU (the
	 * rotating scan candidate) are probed: a CPU whose own queues are
	 * empty should still pull the most-owed remote task instead of
	 * running the previous task for a full slice; the probe is gated
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
					__sync_fetch_and_add(
						&mlfq_stats.keep_running, 1);
					return;
				}
				/* remote work: the slot loops steal */
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
