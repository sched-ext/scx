// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops with adaptive slice plus reclaim.
 *
 * Running claims the segment start from zero with an unconditional
 * pid store and no BPF gauge. Only stopping charges.
 * The snapshot counts live pids for the on CPU gauge. Stopping claims
 * the start once, charges the raw segment to total runtime, advances
 * vruntime by the scaled delta, folds the CPU minimum forward, then
 * feeds the burst predictor average plus deviation from the same delta
 * with shifts, then adapts the slice by 64us up on a wall miss else
 * 128us down with clamp to 10us plus 1ms and no virtual change, then
 * carries the latency-critical slice up to one quantum clamped to 10us
 * plus 1ms, then counts one requeue per runnable stop else one
 * completion. Like fair.c, vruntime paces order, unlike rt.c, no fixed
 * priority holds. C holds burst else slice else quantum with no knob,
 * and V holds weight with zero mapped to 128, so the slice adapts
 * while virtual time stays untouched. A global saved credit at or past
 * 128us reclaims one value ordered reject with positive laxity plus
 * same key or strictly after with one bounded move. A runnable yield
 * before one quantum keeps the unused remainder only when wall time
 * still meets the deadline plus predictor slack holds critical, else
 * the wall miss step holds. A wall completion past the deadline counts one
 * miss with no wait and no kick, since the task already left the CPU.
 * Miss plus Term where Term equals completions stay counters only with
 * no queues, so misses plus completions record history with no extra
 * queue. Frozen rejects plus on CPU plus overflow hold wire compat
 * with no BPF writer. Enable
 * clears vruntime plus deadline plus stamps plus predictor plus
 * lag plus weight plus slice plus hint plus hint weight plus misses plus
 * adapt miss plus sat plus delta, and Disable plus exit clear with no
 * charge, so each segment meets exactly one charge in stopping with no
 * double count. Disable clears the cached hierarchy id like move plus
 * enable plus exit, so a reused pid never reads stale. A closed gate
 * still counts one reject with no charge. Release clears a stale
 * running view with no charge. The gate runs first in every op except
 * the exiting paths, so a stale CPU fails closed with one counter. See
 * intf.h for the shared helpers and enqueue.bpf.c for the fair time
 * choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	cpu = scx_bpf_task_cpu(p);
	/* The gate runs first with fail closed and no count on pass. */
	/* Exiting tasks never reach here through the running path. */
	if (unlikely(!flow_entry_ok(cpu, p, 0))) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	if (likely(tctx)) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The claim swaps from zero only, so a second running */
		/* without a stop keeps the first start with no second use. */
		/* The on CPU gauge lives in the snapshot with no BPF count, */
		/* so this path holds no gauge add. */
		stamp = now ? now : 1;
		__sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
	}
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return;
	st = flow_cpu((u32)cpu);
	if (likely(st)) {
		/* Claim the pid with an unconditional store, so a concurrent */
		/* clear plus run keeps the running task with no lost update. */
		/* The clear only clears when it still owns the pid, so the */
		/* store always wins over a stale clear with no torn write. A */
		/* compare and swap from the observed owner loses here, when */
		/* the clear wins the race to zero first, the swap fails and */
		/* leaves zero while this task still runs. The next running */
		/* would fold again, but the live view stays wrong until then. */
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
	}
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	u64 n_avg_keep = 0;
	u64 n_dev_keep = 0;
	bool have_pred = false;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so only stopping charges. */
	/* A zero claim means no counted start, */
	/* so this pass drops with no charge. The on CPU gauge lives in */
	/* the snapshot with no BPF drop, so every pass ends here with no */
	/* gauge use. */
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	/* Every segment counts raw time while vruntime counts scaled time. */
	/* The predictor average plus deviation update from the same */
	/* delta with shifts only plus a first deviation floor at average */
	/* quarter, so later deadlines track recent bursts with no extra */
	/* walk. A zero delta keeps the predictor with no train, so a */
	/* backward clock never pulls the average to 1ns. The vruntime */
	/* advance uses the effective share of task times stored hint over */
	/* 128 with no divide and no lookup, so heavy tasks move slowly */
	/* while light tasks move quickly with no neutral cliff. The CPU */
	/* minimum folds forward best effort with no regression past a */
	/* concurrent win. */
	flow_count_runtime(delta);
	if (delta) {
		u64 avg = (u64)READ_ONCE(tctx->avg_ns);
		u64 dev = (u64)READ_ONCE(tctx->dev_ns);
		u32 task_w = READ_ONCE(tctx->weight);
		u32 hint_w = READ_ONCE(tctx->hint_w);
		u32 eff_w;
		u64 n_avg = flow_pred_avg(avg, delta);
		/* Deviation trains from the new average, so a fresh mean */
		/* shapes the margin at once with no lagging bound. */
		u64 n_dev = flow_pred_dev(dev, n_avg, delta);
		u64 vrun = READ_ONCE(tctx->vruntime);
		u64 n_vrun;
		if (task_w == 0)
			task_w = (u32)FLOW_WEIGHT_BASE;
		eff_w = flow_task_effective_weight(task_w, hint_w);
		n_vrun = flow_ledger_advance(vrun, delta, eff_w);
		__sync_lock_test_and_set(&tctx->avg_ns, (u32)n_avg);
		__sync_lock_test_and_set(&tctx->dev_ns, (u32)n_dev);
		__sync_lock_test_and_set(&tctx->vruntime, n_vrun);
		flow_min_advance(cpu, n_vrun);
		n_avg_keep = n_avg;
		n_dev_keep = n_dev;
		have_pred = true;
	}
	/* Latency-critical slice carryover up to the quantum with no knob. */
	/* A runnable task that yields before one quantum keeps the unused */
	/* remainder as the next slice when wall time still meets the */
	/* deadline plus predictor slack still holds critical, so short */
	/* bursts earn a nearer virtual deadline with no extra slice. All */
	/* other stops adapt by 64us up on a wall miss else 128us down with */
	/* clamp to 10us plus 1ms and no virtual change, so the slice tracks */
	/* recent runs with no table walk. */
	/* Like fair.c, the step paces service, unlike rt.c, no fixed priority holds. */
	/* C holds burst else slice else quantum, and V holds weight with */
	/* zero mapped to 128. Exiting plus completion paths skip the carry */
	/* with adapt only, so only runnable waits carry with one kick per */
	/* wait at enqueue. Misses count lifetime with saturation, adapt */
	/* miss counts the consecutive wall miss streak with saturation, so */
	/* promotion latches on lifetime while adapt tracks the window. */
	if (runnable) {
		bool wmiss = !flow_deadline_ok(READ_ONCE(tctx->deadline), now);
		if (!wmiss && have_pred && delta > 0 &&
		    delta < (u64)FLOW_QUANTUM_NS &&
		    flow_lat_crit(n_avg_keep, n_dev_keep)) {
			u32 carry = flow_carry_for(delta);
			__sync_lock_test_and_set(&tctx->slice_ns, carry);
			tctx->adapt_miss = 0;
			{
				u16 sat = READ_ONCE(tctx->adapt_sat);
				if (carry == (u32)FLOW_SLICE_MIN_NS ||
				    carry == (u32)FLOW_QUANTUM_NS) {
					if (sat < 0xffffU)
						tctx->adapt_sat = sat + 1;
				} else {
					tctx->adapt_sat = 0;
				}
			}
			{
				u64 ccost = flow_red_cost(n_avg_keep,
				    READ_ONCE(tctx->slice_ns));
				u64 csaved = ccost > delta ? ccost - delta : 0;
				u32 cs = csaved > 0xffffffffULL ? 0xffffffffU :
				    (u32)csaved;
				tctx->adapt_delta = cs;
			}
		} else {
			u32 cur = READ_ONCE(tctx->slice_ns);
			u32 nxt;
			bool m = wmiss;
			if (m)
				nxt = flow_adapt_up(cur);
			else
				nxt = flow_adapt_down(cur);
			__sync_lock_test_and_set(&tctx->slice_ns, nxt);
			if (m) {
				u16 mm = READ_ONCE(tctx->adapt_miss);
				if (mm < 0xffffU)
					tctx->adapt_miss = mm + 1;
			} else {
				tctx->adapt_miss = 0;
			}
			{
				u16 sat = READ_ONCE(tctx->adapt_sat);
				if (nxt == (u32)FLOW_SLICE_MIN_NS ||
				    nxt == (u32)FLOW_QUANTUM_NS) {
					if (sat < 0xffffU)
						tctx->adapt_sat = sat + 1;
				} else {
					tctx->adapt_sat = 0;
				}
			}
			{
				u64 ccost = flow_red_cost(have_pred ? n_avg_keep : 0, cur);
				u64 csaved = ccost > delta ? ccost - delta : 0;
				u32 cs = csaved > 0xffffffffULL ? 0xffffffffU :
				    (u32)csaved;
				tctx->adapt_delta = cs;
			}
		}
	} else {
		/* Completion adapt with no carry and no kick. A miss grows */
		/* by 64us, a hit shrinks by 128us, both clamped with no */
		/* virtual change. The global credit funds reclaim below. */
		u32 cur = READ_ONCE(tctx->slice_ns);
		bool cmiss = !flow_deadline_ok(READ_ONCE(tctx->deadline), now);
		u32 nxt = cmiss ? flow_adapt_up(cur) : flow_adapt_down(cur);
		u64 ccost;
		u64 csaved;
		__sync_lock_test_and_set(&tctx->slice_ns, nxt);
		if (cmiss) {
			u16 m = READ_ONCE(tctx->adapt_miss);
			if (m < 0xffffU)
				tctx->adapt_miss = m + 1;
		} else {
			tctx->adapt_miss = 0;
		}
		{
			u16 sat = READ_ONCE(tctx->adapt_sat);
			if (nxt == (u32)FLOW_SLICE_MIN_NS ||
			    nxt == (u32)FLOW_QUANTUM_NS) {
				if (sat < 0xffffU)
					tctx->adapt_sat = sat + 1;
			} else {
				tctx->adapt_sat = 0;
			}
		}
		ccost = flow_red_cost(have_pred ? n_avg_keep : 0, cur);
		csaved = ccost > delta ? ccost - delta : 0;
		{
			u32 cs = csaved > 0xffffffffULL ? 0xffffffffU : (u32)csaved;
			tctx->adapt_delta = cs;
		}
		/* Reclaim runs in dispatch from the global credit at or past */
		/* 128us with tiers-empty fallback plus aged cover past one */
		/* period, so this path records only with no RCU walk here. */
		/* The global credit funds the retry with no share shaping. */
		/* Dispatch scans at most eight value ordered rejects with */
		/* positive laxity plus same key or strictly after plus mask */
		/* wins, so strict order holds with one bounded move. Zero */
		/* service completions fund nothing, so only a real delta with */
		/* a trained predictor adds credit. */
		if (delta > 0 && have_pred)
			flow_credit_add(csaved);
	}
	/* The pid view clears when owned with no gauge use. */
	/* The snapshot counts live pids for the on CPU gauge. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	/* A wall completion past the deadline counts one miss with no */
	/* wait and no kick, since the task already left the CPU. The miss */
	/* count stays lifetime by design with no reset here, so stopping */
	/* records only with no order write. The miss count paces */
	/* the adapt grow with no share shaping. */
	if (!runnable && !flow_deadline_ok(READ_ONCE(tctx->deadline), now))
		flow_count_miss(tctx);
	if (runnable) {
		flow_count_requeue(true);
		return;
	}
	flow_count_requeue(false);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no vruntime, no deadline, no stamps, no */
	/* predictor, no lag, neutral weight, fixed slice, no hint, neutral */
	/* hint weight, no misses, no adapt miss, no adapt sat, and no adapt */
	/* delta. The first enqueue clamps vruntime to the CPU minimum */
	/* minus the lag bound with a fallback deadline plus a virtual */
	/* deadline, so sleepers gain no more than one boost. The cached */
	/* hierarchy id clears too, so a reused pid never reads a stale */
	/* hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	tctx->vruntime = 0;
	tctx->deadline = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->hint_w = (u32)FLOW_WEIGHT_BASE;
	tctx->avg_ns = 0;
	tctx->dev_ns = 0;
	tctx->vlag = 0;
	tctx->weight = (u32)FLOW_WEIGHT_BASE;
	tctx->slice_ns = (u32)FLOW_QUANTUM_NS;
	tctx->hint_us = 0;
	tctx->misses = 0;
	tctx->adapt_miss = 0;
	tctx->adapt_sat = 0;
	tctx->adapt_delta = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	/* Clear the cached hierarchy id for ABA safety, so a later pid */
	/* reuse never reads a stale hierarchy like move plus enable plus */
	/* exit. A zero pid needs no clear with the zero sentinel. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	/* Charge lives only in stopping with no leftover, so disable */
	/* clears the pid view with no advance and no minimum fold. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	/* Exiting tasks stay exempt from the gate with no count. The */
	/* cached hierarchy id clears too, so a later pid reuse never */
	/* reads a stale hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	/* Charge lives only in stopping with no leftover, so exit clears */
	/* the pid view with no advance and no minimum fold. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* The gate runs with no task here, so only the CPU checks. */
	/* A stale CPU counts one reject with no clear. */
	if (cpu >= 0 && !flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
