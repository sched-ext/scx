/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
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
/* Target in one group from selected plus first. */
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
		__sync_fetch_and_add(
		    &flow_stats.group_steal_skipped, 1);
	}
	first = flow_first_in_group(p, group);
	if (first >= 0)
		return first;
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
	if (ref_cpu < 0)
		return 0;
	rst = flow_cpu((u32)ref_cpu);
	if (rst)
		return rst->frontier;
	return 0;
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
	/* Exiting tasks run at once on this CPU with */
	/* no order wait, so short exits never stall in */
	/* a queue behind other work. Falls back when */
	/* this CPU is not allowed. */
	if (p->flags & PF_EXITING) {
		s32 here =
		    (s32)bpf_get_smp_processor_id();
		if (flow_cpu_ok(p, here)) {
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL, slice,
			    enq_flags);
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
		scx_bpf_dsq_insert_vtime(p,
		    (u64)FLOW_DSQ_PARK, slice, dl, 0);
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
		/* Waker CPU first, see select. */
		if (wst && wst->running_pid == 0 &&
		    flow_cpu_ok(p, waker) &&
		    flow_group_live((u32)waker,
		    nr_cpu_ids) == group)
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
		u64 park;
		s32 nice;
		u32 w;
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
		park = flow_park_for_group(group);
		scx_bpf_dsq_insert_vtime(p, park, slice,
		    dl, 0);
		/* Park sends no kick. Park holds tasks with */
		/* no live allowed CPU after fallback, so no */
		/* single idle target can run them. The next */
		/* dispatch pass on any thief in the park */
		/* group collects them when the mask allows. */
		/* A target scan would need a loop with storm */
		/* risk, so no kick is sent. */
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
		u64 dsq;
		s32 nice;
		u32 w;
		st = flow_cpu((u32)cpu);
		if (st)
			frontier = st->frontier;
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
		dsq = flow_dsq_for_cpu((u32)cpu);
		scx_bpf_dsq_insert_vtime(p, dsq, slice, dl, 0);
		/* Kick idle plus busy preempt with delay. */
		/* Idle fast path first with one queued read. */
		/* Q2 idle in 50us coalesces when not pinned. */
		/* Q1 always kicks, deep stays quiet, no slide. */
		/* Busy stamps max only, running owns count. */
		/* Dual max drops one sample max, decay intact. */
		/* Needs latched arm 16 stand 8 plus deserved */
		/* woken dl before frontier plus quarter gran */
		/* plus atomic rate claim plus same group plus */
		/* mask with one kick per slice. Frontier is */
		/* the floor, so beating it by granule proves */
		/* earliness with no lookup. Fail closed with */
		/* no kick plus lumped skip on any clear. */
		/* No loop. Delay persists across idle, next */
		/* running decays, delay shows stale idle. */
		if (flow_cpu_ok(p, cpu)) {
			u64 q;
			u64 now;
			u64 last;
			u8 sample;
			u8 win;
			u8 cur;
			u8 swin;
			u8 scur;
			bool held;
			bool armed;
			bool is_deserved;
			u64 granule;
			bool same;
			bool mask_ok;
			if (!st)
				return;
			q = scx_bpf_dsq_nr_queued(dsq);
			if (st->running_pid == 0) {
				if (q >
				    (u64)FLOW_STEAL_MIN_DEPTH)
					return;
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
			held = flow_stand_held(st->cursor);
			armed = flow_delay_armed_latched(
			    swin, held);
			if (armed)
				__sync_fetch_and_or(&st->cursor,
				    (u32)FLOW_CURSOR_STAND_BIT);
			else
				__sync_fetch_and_and(&st->cursor,
				    ~(u32)FLOW_CURSOR_STAND_BIT);
			granule = flow_granule_for_weight(w,
			    slice);
			is_deserved = flow_deserved(dl,
			    st->frontier, granule);
			same = group ==
			    flow_group_live((u32)cpu,
			    nr_cpu_ids);
			mask_ok =
			    bpf_cpumask_test_cpu(
			    (u32)cpu, p->cpus_ptr);
			if (!flow_preempt_ok(armed,
			    is_deserved, true, same,
			    mask_ok)) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				return;
			}
			if (!flow_rate_claim(&st->cursor)) {
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped,
				    1);
				return;
			}
			scx_bpf_kick_cpu(cpu,
			    SCX_KICK_PREEMPT);
			__sync_fetch_and_add(
			    &flow_stats.preempt_kicks, 1);
		}
	}
}
