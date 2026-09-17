// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op
 *
 * Picks the target CPU in group with overflow fallback and stamps deadline and
 * delay. Inserts bounded LIFO at K 8 into the per CPU queue or overflow with
 * probe only, pinned tasks rest in the group overflow tail. Keeps mask wins
 * with group aware placement and coalesced idle kicks.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* New slice kfunc mirrors compat, so the kick win site gates on the new */
/* symbol with a direct store fallback on older kernels. */
bool scx_bpf_task_set_slice___new(struct task_struct *p,
    u64 slice) __ksym __weak;
/* New curr kfunc keeps the same gate, so old BTF skips the read with a */
/* kick only fallback and no static kfunc use. */
struct task_struct *scx_bpf_cpu_curr___new(s32 cpu) __ksym __weak;
/* Group of one task with light as default. */
static __always_inline u8 flow_task_group(
	struct flow_task_ctx *tctx)
{
	if (!tctx)
		return (u8)FLOW_GROUP_LIGHT;
	if (tctx->group == (u8)FLOW_GROUP_HOG)
		return (u8)FLOW_GROUP_HOG;
	return (u8)FLOW_GROUP_LIGHT;
}
/* True when one task cannot move to another CPU. */
static __always_inline bool flow_task_pinned(
	const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
/* Target in one group from selected and least. Least picks lowest per CPU */
/* queued depth with lowest id on ties. Strict keeps group only, perf */
/* widens to any allowed on miss with same least rule over the widened */
/* set. Mask always wins with no dispatch use. Placement only scans up */
/* to nr CPUs, bounded at nr<=1024, outside the queue-store O(1). */
static __always_inline s32 flow_pick_in_group(
	const struct task_struct *p, s32 sel,
	u8 group)
{
	s32 first;
	if (sel >= 0 && flow_cpu_ok(p, sel)) {
		u8 g = flow_group_live((u32)sel,
		    nr_cpu_ids);
		if (g == group)
			return sel;
		if (flow_perf_enabled())
			return sel;
		__sync_fetch_and_add(
		    &flow_stats.group_steal_skipped, 1);
	}
	first = flow_first_in_group(p, group);
	if (first >= 0)
		return first;
	if (flow_perf_enabled()) {
		first = flow_first_allowed(p);
		if (first >= 0)
			return first;
	}
	return -1;
}
static __always_inline u64 flow_ref_frontier(
	const struct task_struct *p, s32 ref_cpu)
{
	struct flow_cpu_state *rst;
	s32 first;
	if (!flow_cpu_ok(p, ref_cpu)) {
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			ref_cpu = first;
		else
			return 0;
	}
	/* No second sign check, the fallback above */
	/* already proves a live CPU with no dead branch. */
	/* Out of range still fails closed via a null */
	/* CPU state with no trap. */
	rst = flow_cpu((u32)ref_cpu);
	if (rst)
		return rst->frontier;
	return 0;
}
/* Insert one task with bounded LIFO at K 8 into the per CPU store. Pinned */
/* tasks rest in the group overflow tail with no per CPU use, so every owner */
/* dispatch visits them in the window with mask wins. The caller shares the */
/* pinned bit, so no second pinned test runs. The pinned fast path runs */
/* ahead of the probe with a direct quant error, so one probe feeds only */
/* migratable insert plus spend with no second pass. Migratable probes the */
/* deadline in vruntime to map quantised deadline, slot, error, and overflow, */
/* then inserts to the per CPU queue or the group overflow tail with the same */
/* slice and head or tail flag out of the per queue period. Counts tail pins */
/* past the horizon, counts head or bound hits, and reports the quant error */
/* to share the token spend. Returns the queue id to share one target with */
/* no reread, so idle and busy share one target. Bounded LIFO at K 8 only, */
/* never vtime, never preempt, so per DSQ one flavor holds with mask wins */
/* on drain. */
static __always_inline u64 flow_slot_insert(
	struct task_struct *p, s32 cpu, u8 group, u64 dl,
	u64 frontier, u64 slice, u64 *err_out, bool pinned)
{
	u64 slot = 0;
	u64 err = 0;
	bool over = false;
	u64 sdsq;
	u64 qdl;
	/* Pinned tasks rest in the group overflow tail */
	/* with bounded LIFO order and no per CPU use, so */
	/* every owner dispatch visits them in the window */
	/* with mask wins. Strict keeps the group, so the */
	/* owner group always holds the task with no widen. */
	if (pinned) {
		u32 lidx;
		u32 seq;
		bool head;
		u64 hflag = 0;
		sdsq = flow_slot_overflow_dsq(group);
		lidx = flow_lifo_idx(true, 0, group);
		seq = __sync_fetch_and_add(&flow_lifo_seq[lidx],
		    1);
		head = flow_lifo_take_head(seq);
#ifdef HAVE_SCX_ENQ_HEAD
		if (head)
			hflag = (u64)SCX_ENQ_HEAD;
#endif
		scx_bpf_dsq_insert(p, sdsq, slice, hflag);
		if (hflag != 0)
			__sync_fetch_and_add(&flow_stats.lifo_heads,
			    1);
		else
			__sync_fetch_and_add(
			    &flow_stats.lifo_bound_hits, 1);
		*err_out = dl & (u64)FLOW_WHEEL_QUANT_LO;
		return sdsq;
	}
	qdl = flow_wheel_probe(dl, frontier, &slot,
	    &err, &over);
	(void)qdl;
	{
		bool to_over = false;
		u32 lidx;
		u32 seq;
		bool head;
		u64 hflag = 0;
		if (slot >= (u64)FLOW_WHEEL_DIM)
			to_over = true;
		else if (cpu < 0 || !flow_cpu_live((u32)cpu))
			to_over = true;
		if (to_over)
			sdsq = flow_slot_overflow_dsq(group);
		else
			sdsq = flow_slot_cpu_dsq((u32)cpu, group);
		/* Bounded LIFO claims one period slot with a single atomic add, */
		/* so per queue order stays fresh with no starve or scan. */
		/* Head wins fast, tail keeps the bound with no preempt use. */
		/* Build gate keeps tail without HEAD with no trap, so old */
		/* kernels keep FIFO fallback with no preempt use. */
		if (to_over)
			lidx = flow_lifo_idx(true, 0, group);
		else
			lidx = flow_lifo_idx(false, (u32)cpu,
			    group);
		seq = __sync_fetch_and_add(&flow_lifo_seq[lidx],
		    1);
		head = flow_lifo_take_head(seq);
#ifdef HAVE_SCX_ENQ_HEAD
		if (head)
			hflag = (u64)SCX_ENQ_HEAD;
#endif
		scx_bpf_dsq_insert(p, sdsq, slice, hflag);
		if (hflag != 0)
			__sync_fetch_and_add(&flow_stats.lifo_heads,
			    1);
		else
			__sync_fetch_and_add(
			    &flow_stats.lifo_bound_hits, 1);
	}
	if (over)
		__sync_fetch_and_add(&flow_stats.wheel_overflow,
		    1);
	*err_out = err;
	return sdsq;
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 sel;
	s32 cpu = -1;
	bool is_requeue = false;
	bool is_fresh = false;
	bool pinned = false;
	u8 group;
	u64 est = 0;
	u64 slice = (u64)FLOW_SLICE_NS;
	/* Exiting tasks run at once on the task CPU via LOCAL_ON with no order */
	/* wait, so short exits never stall in a queue behind other work. Task CPU */
	/* wins over the enqueuer, so an exit enqueued elsewhere still runs where */
	/* the task lives. Single insert and return with no double enqueue. Falls */
	/* back when the task CPU is not allowed. Idle kick only with no coalesce */
	/* and no preempt. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    slice, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst && tst->running_pid == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	if (!tctx) {
		u64 frontier;
		u64 clamped;
		u64 scaled;
		u64 dl;
		u64 err = 0;
		frontier = flow_ref_frontier(p, sel);
		clamped = flow_clamp_vruntime(0, frontier,
		    slice);
		/* No task state, so weight stays 1024. */
		scaled = flow_scale_by_weight(
		    flow_clamp_est(slice),
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != 0)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		/* No task state, so the light group owns the insert with no */
		/* token use and no kick. Overflow holds it with steal plus */
		/* drain collect. A target scan would need a loop with storm */
		/* risk, so no kick is sent and the next pass collects it. */
		/* Shares the caller pinned bit with no test. */
		flow_slot_insert(p, -1,
		    (u8)FLOW_GROUP_LIGHT, dl, frontier,
		    slice, &err, pinned);
		return;
	}
	group = flow_task_group(tctx);
	if (tctx->est_ns == 0)
		is_fresh = true;
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here)) {
			cpu = here;
			group = flow_group_live((u32)here,
			    nr_cpu_ids);
			tctx->group = group;
		} else {
			cpu = flow_pick_in_group(p, sel,
			    group);
		}
	} else if (p->nr_cpus_allowed == 1) {
		s32 first;
		first = (s32)bpf_cpumask_first(
		    p->cpus_ptr);
		if (flow_cpu_ok(p, first)) {
			cpu = first;
			group = flow_group_live((u32)first,
			    nr_cpu_ids);
			tctx->group = group;
		} else {
			cpu = -1;
		}
	} else {
		s32 waker =
		    (s32)bpf_get_smp_processor_id();
		struct flow_cpu_state *wst =
		    flow_cpu((u32)waker);
		/* Waker CPU first, see select. Strict needs in */
		/* group, perf takes any allowed idle with mask win. */
		if (wst && wst->running_pid == 0 &&
		    flow_cpu_ok(p, waker) &&
		    (flow_group_live((u32)waker,
		    nr_cpu_ids) == group || flow_perf_enabled()))
			cpu = waker;
		else
			cpu = flow_pick_in_group(p, sel,
			    group);
		if (cpu < 0) {
			s32 first;
			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first)) {
				cpu = first;
				group = flow_group_live(
				    (u32)first,
				    nr_cpu_ids);
				tctx->group = group;
			}
		}
	}
	if (cpu < 0) {
		u64 frontier;
		u64 v;
		u64 clamped;
		u64 scaled;
		u64 dl;
		s32 nice;
		u32 w;
		u32 tok_cpu;
		u64 err = 0;
		bool was_c;
		if (is_fresh)
			est = slice;
		else
			est = flow_clamp_est(tctx->est_ns);
		tctx->est_ns = est;
		if (is_fresh) {
			tctx->vruntime = 0;
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		} else if (is_requeue) {
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		}
		v = tctx->vruntime;
		frontier = flow_ref_frontier(p, sel);
		nice = flow_nice_of(p);
		w = flow_weight_of(nice);
		clamped = flow_clamp_vruntime_w(v, frontier,
		    slice, w);
		scaled = flow_scale_by_weight(est, w);
		dl = flow_deadline(clamped, scaled);
		if (group == (u8)FLOW_GROUP_HOG &&
		    pinned) {
			dl = flow_inflate_deadline(dl);
			__sync_fetch_and_add(
			    &flow_stats.pinned_hog_inflated,
			    1);
		}
		if (dl == (u64)-1)
			dl = (u64)-2;
		tctx->deadline = dl;
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != v)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		was_c = clamped != v;
		flow_slot_insert(p, -1, group, dl, frontier,
		    slice, &err, pinned);
		/* Token spend keeps the sleeper conjunct with the enqueuer */
		/* owning the spend and no order change. */
		tok_cpu = (u32)bpf_get_smp_processor_id();
		if (flow_token_try_spend(tok_cpu, was_c,
		    est, tctx->burn, err))
			__sync_fetch_and_add(
			    &flow_stats.token_boosts, 1);
		/* No live allowed CPU after fallback, so no kick is sent. The */
		/* overflow tail holds the task in queue order, so the next */
		/* steal or drain pass collects it when the mask allows. A */
		/* target scan would need a loop with storm risk, so no kick */
		/* is sent. */
		return;
	}
	if (is_fresh)
		est = slice;
	else
		est = flow_clamp_est(tctx->est_ns);
	tctx->est_ns = est;
	if (is_fresh)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	else if (is_requeue)
		__sync_fetch_and_add(&flow_stats.requeues, 1);
	{
		u64 frontier = 0;
		u64 v = tctx->vruntime;
		u64 clamped;
		u64 scaled;
		u64 dl;
		u64 sdsq;
		s32 nice;
		u32 w;
		u64 target = 0;
		u64 ref_f = 0;
		u64 err = 0;
		bool was_c;
		u32 tok_cpu;
		st = flow_cpu((u32)cpu);
		if (st)
			target = st->frontier;
		ref_f = flow_ref_frontier(p, sel);
		/* Normal path only, no tctx and overflow keep their own probe. */
		/* Corrected feeds clamp and deadline with max wrap safety. */
		frontier = flow_frontier_max(ref_f, target);
		nice = flow_nice_of(p);
		w = flow_weight_of(nice);
		clamped = flow_clamp_vruntime_w(v, frontier,
		    slice, w);
		scaled = flow_scale_by_weight(est, w);
		dl = flow_deadline(clamped, scaled);
		if (group == (u8)FLOW_GROUP_HOG &&
		    pinned) {
			dl = flow_inflate_deadline(dl);
			__sync_fetch_and_add(
			    &flow_stats.pinned_hog_inflated,
			    1);
		}
		if (dl == (u64)-1)
			dl = (u64)-2;
		tctx->vruntime = clamped;
		tctx->deadline = dl;
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != v)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		was_c = clamped != v;
		sdsq = flow_slot_insert(p, cpu, group, dl,
		    frontier, slice, &err, pinned);
		/* Token spend keeps the sleeper conjunct with the enqueuer */
		/* owning the spend and no order change. */
		tok_cpu = (u32)bpf_get_smp_processor_id();
		if (flow_token_try_spend(tok_cpu, was_c,
		    est, tctx->burn, err))
			__sync_fetch_and_add(
			    &flow_stats.token_boosts, 1);
		/* Kick idle and busy bound preempt with delay. */
		/* Idle fast path first with one queued read on */
		/* the slot target. Q2 idle in 50us coalesces when */
		/* not pinned. Q1 always kicks, deep always kicks */
		/* with no quiet, so no idle CPU with queued work */
		/* sleeps unkicked. No slide. */
		/* Busy stamps max only, running owns count. */
		/* Dual max drops one sample max, decay intact. */
		/* Busy uses empty first plus deserved or hog plus same */
		/* plus mask plus rate with no armed check, so shallow */
		/* wakes preempt once per 1ms window with no storm. Empty */
		/* needs at most one queued, deserved needs woken deadline */
		/* past frontier plus granule plus slack or hog occupant */
		/* with no time cap, same keeps group with perf bypass, */
		/* mask keeps allowed, rate keeps one win per 1ms window. */
		/* Pinned plus deep count total only, others count total */
		/* plus reason. Kick uses PREEMPT with kicks count. */
		/* No loop. Delay persists across idle, next running */
		/* decays, delay shows stale idle. Kick at stays idle only, */
		/* rate at stays busy only, see main. */
		if (flow_cpu_ok(p, cpu)) {
			u64 q;
			u64 now;
			u64 last;
			u8 sample;
			u8 win;
			u8 cur;
			u8 swin;
			u8 scur;
			u64 granule;
			bool is_deserved;
			bool occupant_hog;
			bool same;
			bool mask_ok;
			if (!st)
				return;
			q = scx_bpf_dsq_nr_queued(sdsq);
			if (st->running_pid == 0) {
				if (q ==
				    (u64)FLOW_STEAL_MIN_DEPTH &&
				    !pinned &&
				    (u32)cpu < 1024) {
					now = flow_now();
					last =
					    flow_kick_at[
					    (u32)cpu];
					if (flow_kick_recent(
					    now, last)) {
						__sync_fetch_and_add(
						    &flow_stats.kick_coalesced,
						    1);
						return;
					}
					scx_bpf_kick_cpu(cpu,
					    SCX_KICK_IDLE);
					__sync_fetch_and_add(
					    &flow_stats.kicks,
					    1);
					flow_kick_at[
					    (u32)cpu] = now;
					return;
				}
				scx_bpf_kick_cpu(cpu,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
				if ((u32)cpu < 1024)
					flow_kick_at[
					    (u32)cpu] =
					    flow_now();
				return;
			}
			sample = flow_delay_from_queued(q);
			win = st->delay_win;
			cur = st->delay_cur;
			swin = flow_delay_max(win, sample);
			scur = flow_delay_max(cur, sample);
			st->delay_win = swin;
			st->delay_cur = scur;
			/* Stand clears, so the dots stay display with no gate use. */
			__sync_fetch_and_and(&st->cursor,
			    ~(u32)FLOW_CURSOR_STAND_BIT);
			/* Pinned counts total only with no kick. */
			if (pinned) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				return;
			}
			/* Empty first counts total only past one queued. */
			if (!flow_empty_ok(q)) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				return;
			}
			/* Deserved or hog counts total plus deserved on miss. */
			granule = flow_granule_for_weight(w,
			    slice);
			is_deserved = flow_deserved(dl,
			    st->frontier, granule);
			occupant_hog = st->occupant_group ==
			    (u8)FLOW_GROUP_HOG;
			if (!flow_deserved_or_hog(is_deserved,
			    occupant_hog)) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped_deserved,
				    1);
				return;
			}
			/* Same keeps group with perf bypass and no recount. */
			same = group == flow_group_live((u32)cpu,
			    nr_cpu_ids);
			if (flow_perf_enabled())
				same = true;
			if (!same) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped_group,
				    1);
				return;
			}
			/* Mask keeps allowed with total plus mask on miss. */
			mask_ok = bpf_cpumask_test_cpu((u32)cpu,
			    p->cpus_ptr);
			if (!mask_ok) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped_mask,
				    1);
				return;
			}
			/* Rate keeps one win per 1ms window with kicks count. */
			/* Zero last always wins with wrap, see main. */
			{
				volatile u32 vcpu = (u32)cpu;
				u32 idx = vcpu & 1023U;
				if ((u32)cpu < 1024 &&
				    flow_cpu_live((u32)cpu))
					last = flow_rate_at[idx];
				else
					last = 0;
				now = flow_now();
				if (last != 0 &&
				    now - last < 1000000ULL) {
					__sync_fetch_and_add(
					    &flow_stats.preempt_skipped,
					    1);
					__sync_fetch_and_add(
					    &flow_stats.preempt_skipped_rate,
					    1);
					return;
				}
				if ((u32)cpu < 1024 &&
				    flow_cpu_live((u32)cpu))
					flow_rate_at[idx] = now;
			}
			/* Soft preempt shortens the occupant slice out of */
			/* band to zero before the kick, so the kick sticks */
			/* on the waker. Zero stores the live remainder in */
			/* place with no insert, while the insert path keeps */
			/* prev behind a slice non-zero guard, so only this */
			/* direct write ever reaches zero. Full stick needs */
			/* 7.2 with the slice kfunc, 6.18 and 7.1 keep a best */
			/* effort direct store with the kick still sent. INF */
			/* slice never arrives, since every insert stamps the */
			/* uniform slice. A stale occupant shortens the same */
			/* task after a move, so harm stays bounded to an */
			/* early loss. The kick stays on the old CPU with a */
			/* spurious kick possible, but no wakeup is lost */
			/* since p queues there. Self never shortens, null or */
			/* self sends kick only, and false from the kfunc */
			/* keeps kick only with total plus rate, so stuck */
			/* shortens match preempt_kicks one for one, kicks */
			/* sent exceed it by declined plus null or self. */
			{
				struct task_struct *occupant = NULL;
				bool stuck;
				/* Old BTF lacks curr, so gate the read, */
				/* null falls to kick only with no use. */
				if (bpf_ksym_exists(
				    scx_bpf_cpu_curr___new))
					occupant =
					    scx_bpf_cpu_curr___new(cpu);
				if (!occupant || occupant == p) {
					scx_bpf_kick_cpu(cpu,
					    SCX_KICK_PREEMPT);
					return;
				}
				if (bpf_ksym_exists(
				    scx_bpf_task_set_slice___new))
					stuck =
					    scx_bpf_task_set_slice___new(
					    occupant, 0);
				else {
					occupant->scx.slice = 0;
					stuck = true;
				}
				if (stuck) {
					scx_bpf_kick_cpu(cpu,
					    SCX_KICK_PREEMPT);
					__sync_fetch_and_add(
					    &flow_stats.preempt_kicks,
					    1);
					return;
				}
				scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped_rate,
				    1);
				return;
			}
		}
	}
}
