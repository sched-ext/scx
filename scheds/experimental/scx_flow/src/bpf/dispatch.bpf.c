// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op
 *
 * Drains per CPU queues with overflow plus peer steal and a kick
 * safety net. One shared drain body feeds every trip with mask wins and move
 * to local, so only DSQ id selection branches. Own per CPU own group runs
 * at 31, own overflow at 4, own CPU other group at 4, other overflow at 4,
 * then same group peer steal visits bound same group peers first with single
 * move toward budget 32 and perf only cross second on same group miss with
 * one shared drain. Sweep covers zero move window only at 256 with reset on
 * move. Pinned tasks
 * rest in overflow, so trips visit them every pass. All trips share one
 * drain body with mask wins and move to local, so per queue order stays
 * bounded LIFO at K 8 with FIFO fallback on old kernels.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. Own, overflow, other CPU, other */
/* overflow, and peer use one for_each with mask wins and move to local, so */
/* only DSQ id selection branches outside with no duplicated loop body. */
/* Inlined into the trip loop, so the verifier merges states at the loop */
/* back edge with one body analysis instead of per-site repeats. Base */
/* carries moved so far with budget kept whole, so the break reads one wide */
/* sum with no narrow remainder beside it and states merge. Callers */
/* precompute DSQ and capped live already proven at dispatch top. No stats */
/* inside, so the caller aggregates moves once per dispatch with no per */
/* queue atomics. Miss caps the walk at 8 straight mask fails, so all mask */
/* miss walks stay bounded with no full scan and per queue cost stays */
/* capped with no extra wide sum beside the budget check. */
static __always_inline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved + base >= budget)
			break;
		if (miss >= 8U)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 scap;
	u32 own_cap;
	u8 sgroup = 0;
	u8 ogroup = 0;
	u64 own = 0;
	u64 own_over = 0;
	u64 other_cpu = 0;
	u64 other_over = 0;
	u32 off;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	sgroup = flow_group_live((u32)cpu,
	    nr_cpu_ids);
	ogroup = sgroup ^ 1U;
	own = flow_slot_cpu_dsq((u32)cpu, sgroup);
	own_over = flow_slot_overflow_dsq(sgroup);
	other_cpu = flow_slot_cpu_dsq((u32)cpu, ogroup);
	other_over = flow_slot_overflow_dsq(ogroup);
	scap = flow_slot_cap(budget);
	own_cap = flow_slot_own_cap(budget);
	/* Local trips at 4 with one body. Own runs at 31 with one slot left, */
	/* all trips skip empty with one read and no iterator, so idle pays no */
	/* empty scan. Bound 4 sits under the steal bound with one body analysis */
	/* at the loop back edge. */
	bpf_for(off, 0, 4) {
		u64 dsq;
		u32 cap;
		u32 lim;
		u32 got;
		if (off == 0) {
			dsq = own;
			cap = own_cap;
		} else if (off == 1) {
			dsq = own_over;
			cap = scap;
		} else if (off == 2) {
			dsq = other_cpu;
			cap = scap;
		} else {
			dsq = other_over;
			cap = scap;
		}
		if (scx_bpf_dsq_nr_queued(dsq) == 0)
			continue;
		lim = moved + cap;
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, dsq, lim, moved);
		moved += got;
		if (off == 1 || off == 3)
			over_moved += got;
	}
	/* Peer steal rotates from a cursor start with single move toward budget 32. */
	/* Start reads the masked cursor plus one with wrap once per dispatch, so */
	/* repeated passes spread across peers with no hot spot. Donor scan reads */
	/* bound same group peers from start with one read each and no iterator, so */
	/* shallow donors skip early. Need is 1 when idle empty, else 2, so idle */
	/* owners collect the last task with no strand while busy owners leave one. */
	/* Peers wrap with modulo plus live check, so high CPUs reach low peers with */
	/* no dead read. Self visit stays allowed with no extra branch, so small */
	/* hosts keep full cover with no dead pass. Same group scans first, so */
	/* groups keep cache apart in strict with no cross scan. Perf only cross */
	/* second scans bound other group peers from start plus 8 on same group */
	/* miss with same need and keep first, so perf adds cover with no extra */
	/* drain. Fold counts all peer moves in steal moves with post hoc LSB */
	/* compare in steal_xmoves with unconditional adds and zero keeps count */
	/* still, so no branch on cross with one shared drain. Single move keeps */
	/* tail smooth with no burst theft, so one peer task per pass is enough */
	/* with local trips owning the window. Cursor steps by 8 */

	/* with a bounded compare and swap in 4 tries that keeps stand */
	/* and drops on race, so contended owners skip the step with no stall. */
	/* When host size divides 8, step 8 is identity with no advance, */
	/* harmless as the bound 8 scan covers all peers while donor priority */
	/* goes stale. Window reads four local queues once after local trips */
	/* with no global scan, so need plus defer plus sweep share one window */
	/* with no extra reads. Scans keep */
	/* the first donor with work, then one shared drain moves a single task */
	/* with mask wins, so one bad head never blocks later work. Single CPU */
	/* hosts skip the whole pass with one check. See intf.h for need plus */
	/* cursor helpers. */
	{
		bool win_left;
		struct flow_cpu_state *st;
		bool idle = false;
		u64 need = 2ULL;
		win_left = scx_bpf_dsq_nr_queued(own) != 0 ||
		    scx_bpf_dsq_nr_queued(own_over) != 0 ||
		    scx_bpf_dsq_nr_queued(other_cpu) != 0 ||
		    scx_bpf_dsq_nr_queued(other_over) != 0;
		st = flow_cpu((u32)cpu);
		if (st && st->running_pid == 0)
			idle = true;
		if (idle && moved == 0 && !win_left)
			need = flow_steal_need(true);
		else
			need = flow_steal_need(false);
		if (moved < budget && nr_cpu_ids > 1 && st) {
			u32 start;
			u32 cas;
			u64 steal_dsq = 0;
			bool have = false;
			start = (flow_cursor_val(st->cursor) +
			    1U) % (u32)nr_cpu_ids;
			bpf_for(off, 0, FLOW_STEAL_BOUND) {
				u32 peer;
				u64 pdsq;
				u64 q;
				if (have)
					continue;
				peer = (start + off) %
				    (u32)nr_cpu_ids;
				if (!flow_cpu_live(peer))
					continue;
				pdsq = flow_slot_cpu_dsq(peer, sgroup);
				q = scx_bpf_dsq_nr_queued(pdsq);
				if (q < need)
					continue;
				steal_dsq = pdsq;
				have = true;
			}
			if (flow_perf_enabled() && !have &&
			    moved < budget && nr_cpu_ids > 1) {
				bpf_for(off, 0, FLOW_STEAL_BOUND) {
					u32 peer;
					u64 pdsq;
					u64 q;
					if (have)
						continue;
					peer = (start + 8U + off) %
					    (u32)nr_cpu_ids;
					if (!flow_cpu_live(peer))
						continue;
					pdsq = flow_slot_cpu_dsq(peer,
					    ogroup);
					q = scx_bpf_dsq_nr_queued(pdsq);
					if (q < need)
						continue;
					steal_dsq = pdsq;
					have = true;
				}
			}
			if (have) {
				u32 lim = moved + 1U;
				u32 got;
				if (lim > budget)
					lim = budget;
				got = flow_drain_one(cpu, steal_dsq, lim,
				    moved);
				moved += got;
				/* Fold counts all peer moves with no branch, */
				/* so same plus cross share one drain with one */
				/* state. Cross subset folds via post hoc LSB */
				/* compare with unconditional adds and zero */
				/* keeps count still. See intf.h for DSQ LSB. */
				{
					u64 x = ((steal_dsq & 1ULL) ^
					    ((u64)sgroup & 1ULL)) & 1ULL;
					__sync_fetch_and_add(
					    &flow_stats.steal_moves,
					    (u64)got);
					__sync_fetch_and_add(
					    &flow_stats.steal_xmoves,
					    (u64)got * x);
				}
			}
			bpf_for(cas, 0, 4) {
				u32 cur;
				u32 masked;
				u32 nxt_peer;
				u32 nxt;
				u32 got;
				cur = st->cursor;
				masked = flow_cursor_val(cur);
				nxt_peer = (masked + 8U) %
				    (u32)nr_cpu_ids;
				nxt = (nxt_peer &
				    (u32)FLOW_CURSOR_MASK) |
				    (cur & (u32)FLOW_CURSOR_STAND_BIT);
				got = __sync_val_compare_and_swap(
				    &st->cursor, cur, nxt);
				if (got == cur)
					break;
			}
		}
		if (moved != 0)
			__sync_fetch_and_add(&flow_stats.slot_moves,
			    (u64)moved);
		if (over_moved != 0)
			__sync_fetch_and_add(&flow_stats.park_moves,
			    (u64)over_moved);
		if (moved >= (u32)FLOW_SLOT_D && win_left)
			__sync_fetch_and_add(&flow_stats.slot_defer,
			    1);
		{
			volatile u32 vcpu3 = (u32)cpu;
			u32 sidx3 = vcpu3 & 1023U;
			u16 sweep = flow_slot_sweep_cnt[sidx3];
			bool kick = false;
			if (moved == 0 && win_left &&
			    sweep < (u16)FLOW_SLOT_SWEEP_MAX) {
				kick = true;
				flow_slot_sweep_cnt[sidx3] =
				    sweep + 1;
			}
			if (moved > 0)
				flow_slot_sweep_cnt[sidx3] = 0;
			if (kick) {
				scx_bpf_kick_cpu(cpu,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.slot_kicks, 1);
			}
		}
	}
}
