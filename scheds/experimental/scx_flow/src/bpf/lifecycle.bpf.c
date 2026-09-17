// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops
 *
 * Handles running, dequeue, stopping, and enable. It also handles disable,
 * exit, and CPU release. Tracks running state, estimates, and pressure with
 * no extra cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	if (tctx)
		tctx->run_at = flow_now();
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st) {
		u32 perf;
		u64 est;
		s32 nice;
		u32 w;
		u64 q;
		u8 sample;
		u8 nwin;
		u8 ncur;
		u16 ncnt;
		/* Pure-EMA hint at M2 uniform both groups. No group branch, so light and */
		/* hog share the same map from the stored EMA. Cold zero maps to zero until */
		/* the first climb. Keeps natural hints with no pin, so no hint split. */
		perf = flow_cpuperf_from_ema(
		    st->cpuperf_ema);
		if (scx_bpf_cpuperf_set)
			scx_bpf_cpuperf_set(cpu, perf);
		est = tctx ?
		    flow_clamp_est(tctx->est_ns) : 0;
		nice = flow_nice_of(p);
		w = flow_weight_of(nice);
		st->running_est = est;
		st->running_pid = (u32)p->pid;
		st->running_nice = (s16)nice;
		st->running_weight = (u16)w;
		/* Occupant group from live task state with LIGHT fallback, */
		/* written here and cleared with pid, read post-empty. */
		if (tctx &&
		    tctx->group == (u8)FLOW_GROUP_HOG)
			st->occupant_group = (u8)FLOW_GROUP_HOG;
		else
			st->occupant_group = (u8)FLOW_GROUP_LIGHT;
		/* Own count and close with no loop. Enqueue stamps max only, so 8 means 8 */
		/* runnings with no double count. Dual max drops one sample max, decay */
		/* intact, persists idle, decays at 1/8. Sample reads the per CPU */
		/* queue plus overflow. */
		q = 0;
		{
			u8 gg = flow_group_live((u32)cpu,
			    nr_cpu_ids);
			u64 bq = flow_slot_cpu_dsq((u32)cpu, gg);
			q = scx_bpf_dsq_nr_queued(bq);
			q += scx_bpf_dsq_nr_queued(
			    flow_slot_overflow_dsq(gg));
		}
		sample = flow_delay_from_queued(q);
		nwin = flow_delay_max(st->delay_win,
		    sample);
		ncur = flow_delay_max(st->delay_cur,
		    sample);
		ncnt = st->delay_cnt + 1;
		if ((u64)ncnt >=
		    (u64)FLOW_DELAY_WIN_LEN) {
			nwin = flow_delay_close(nwin,
			    ncur);
			ncur = 0;
			ncnt = 0;
		}
		st->delay_win = nwin;
		st->delay_cur = ncur;
		st->delay_cnt = ncnt;
		if (flow_delay_armed_latched(nwin,
		    flow_stand_held(st->cursor)))
			__sync_fetch_and_or(&st->cursor,
			    (u32)FLOW_CURSOR_STAND_BIT);
		else
			__sync_fetch_and_and(&st->cursor,
			    ~(u32)FLOW_CURSOR_STAND_BIT);
	} else {
		/* No state, so hold max with no EMA read. */
		if (scx_bpf_cpuperf_set)
			scx_bpf_cpuperf_set(cpu,
			    (u32)FLOW_CPUPERF_LEVEL);
	}
inc:
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
/* Pressure refresh from per CPU queued counts capped at 4. Sums light */
/* and hog queued tasks over own per CPU plus other per CPU plus both */
/* overflow tails with 4 reads and no full scan, so stopping pays window */
/* cost with no flood miss. Window holds own per CPU plus other per CPU */
/* plus both overflows, so quiet keeps 4ms and flood fills the window plus */
/* overflows to the 1ms floor. Placement uses the live table seeded by */
/* online rank with offline inert, so strict iff ready is zero, best effort */
/* iff ready is one. Stores depths and allowance for snapshot with no task */
/* field. Returns the allowance for the burst check. Stopping only, never */
/* dispatch. */
static __always_inline u64 flow_refresh_pressure(s32 cpu)
{
	u64 light = 0;
	u64 hog = 0;
	u64 allow;
	u64 own_n;
	u64 other_n;
	u64 lo_n;
	u64 ho_n;
	u8 g;
	u8 og;
	u64 own;
	u64 other;
	u64 lo;
	u64 ho;
	if (cpu < 0 || !flow_cpu_live((u32)cpu)) {
		light = scx_bpf_dsq_nr_queued(
		    flow_slot_overflow_dsq(
		    (u8)FLOW_GROUP_LIGHT));
		hog = scx_bpf_dsq_nr_queued(
		    flow_slot_overflow_dsq(
		    (u8)FLOW_GROUP_HOG));
		if (light > 4)
			light = 4;
		if (hog > 4)
			hog = 4;
		allow = flow_burst_allowance(light);
		flow_light_depth = light;
		flow_hog_depth = hog;
		flow_burst_allowance_ns = allow;
		return allow;
	}
	g = flow_group_live((u32)cpu, nr_cpu_ids);
	og = g ^ 1U;
	own = flow_slot_cpu_dsq((u32)cpu, g);
	other = flow_slot_cpu_dsq((u32)cpu, og);
	lo = flow_slot_overflow_dsq(
	    (u8)FLOW_GROUP_LIGHT);
	ho = flow_slot_overflow_dsq(
	    (u8)FLOW_GROUP_HOG);
	own_n = scx_bpf_dsq_nr_queued(own);
	other_n = scx_bpf_dsq_nr_queued(other);
	lo_n = scx_bpf_dsq_nr_queued(lo);
	ho_n = scx_bpf_dsq_nr_queued(ho);
	if (g == (u8)FLOW_GROUP_HOG) {
		light = other_n + lo_n;
		hog = own_n + ho_n;
	} else {
		light = own_n + lo_n;
		hog = other_n + ho_n;
	}
	if (light > 4)
		light = 4;
	if (hog > 4)
		hog = 4;
	allow = flow_burst_allowance(light);
	flow_light_depth = light;
	flow_hog_depth = hog;
	flow_burst_allowance_ns = allow;
	return allow;
}
/* Burn step for one stop with window, burst, and wake. Burst allowance */
/* adapts to light depth with 4ms quiet to 2ms mild to 1ms floor during */
/* flood. Short blocks below 1ms with burn below 4ms count toward 8 fast */
/* promote. A burst at the allowance clears wake hits. A short with burn at */
/* or past 4ms clears wake hits. A hot window at or past 16ms clears wake */
/* hits. A middle window at the end clears wake hits with low runs. A low */
/* window below 4ms keeps wake hits. A window in progress keeps wake hits. */
/* Slow path with 64 low wins stays intact. Stopping only, never dispatch. */
static __always_inline void flow_classify(
	struct flow_task_ctx *tctx, u64 now,
	u64 delta, s32 cpu)
{
	u8 group;
	u64 sum;
	u64 allow;
	if (!tctx)
		return;
	group = tctx->group;
	if (group != (u8)FLOW_GROUP_LIGHT &&
	    group != (u8)FLOW_GROUP_HOG) {
		group = (u8)FLOW_GROUP_LIGHT;
		tctx->group = group;
	}
	sum = (u64)tctx->burn + delta;
	if (sum > 0xffffffffULL)
		sum = 0xffffffffULL;
	tctx->burn = (u32)sum;
	allow = flow_refresh_pressure(cpu);
	if (flow_burst_hot_at(delta, allow)) {
		tctx->wake_hits = 0;
		if (group ==
		    (u8)FLOW_GROUP_LIGHT) {
			tctx->group =
			    (u8)FLOW_GROUP_HOG;
			tctx->low_runs = 0;
			tctx->win_start = now;
			tctx->burn = 0;
			__sync_fetch_and_add(
			    &flow_stats.group_demote,
			    1);
		} else {
			tctx->low_runs = 0;
		}
		return;
	}
	if (flow_wake_short(delta)) {
		if (group == (u8)FLOW_GROUP_HOG) {
			if (flow_burn_low(tctx->burn)) {
				u16 hits = tctx->wake_hits;
				if (hits < 0xffff)
					hits++;
				tctx->wake_hits = hits;
				if (flow_wake_ready(hits)) {
					tctx->group =
					    (u8)FLOW_GROUP_LIGHT;
					tctx->low_runs = 0;
					tctx->wake_hits = 0;
					tctx->win_start = now;
					tctx->burn = 0;
					__sync_fetch_and_add(
					    &flow_stats.group_promote,
					    1);
					__sync_fetch_and_add(
					    &flow_stats.group_wake_promote,
					    1);
					return;
				}
			} else {
				tctx->wake_hits = 0;
			}
		} else {
			tctx->wake_hits = 0;
		}
	}
	if (tctx->win_start == 0) {
		tctx->win_start = now;
		return;
	}
	if (!flow_win_ready(now, tctx->win_start))
		return;
	if (flow_burn_hot(tctx->burn)) {
		tctx->wake_hits = 0;
		if (group ==
		    (u8)FLOW_GROUP_LIGHT) {
			tctx->group =
			    (u8)FLOW_GROUP_HOG;
			tctx->low_runs = 0;
			__sync_fetch_and_add(
			    &flow_stats.group_demote,
			    1);
		} else {
			tctx->low_runs = 0;
		}
		tctx->win_start = now;
		tctx->burn = 0;
		return;
	}
	if (flow_burn_low(tctx->burn)) {
		if (group == (u8)FLOW_GROUP_HOG) {
			if (tctx->low_runs < 255)
				tctx->low_runs++;
			if (tctx->low_runs >=
			    (u8)FLOW_PROMOTE_WINS) {
				tctx->group =
				    (u8)FLOW_GROUP_LIGHT;
				tctx->low_runs = 0;
				tctx->wake_hits = 0;
				__sync_fetch_and_add(
				    &flow_stats.group_promote,
				    1);
			}
		} else {
			if (tctx->low_runs <
			    (u8)FLOW_PROMOTE_WINS)
				tctx->low_runs++;
		}
		tctx->win_start = now;
		tctx->burn = 0;
		return;
	}
	tctx->low_runs = 0;
	tctx->wake_hits = 0;
	tctx->win_start = now;
	tctx->burn = 0;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 est;
	u64 scaled;
	u64 nv;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	/* No minus one check, since zero init and never minus one. */
	if (!tctx || !tctx->run_at) {
		flow_clear_running_if_owner(cpu,
		    (u32)p->pid);
		if (!tctx)
			flow_on_cpu_dec();
		if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
			struct flow_cpu_state *est;
			u64 dsq_nr;
			u64 local_nr;
			u64 now_e = now;
			/* Decay only with no climb at M2. */
			/* Elapsed is wrap safe via time before, */
			/* so a zero at stays zero with no under. */
			est = flow_cpu((u32)cpu);
			if (est) {
				u64 at = est->cpuperf_ema_at;
				u64 elapsed = 0;
				if (at != 0 &&
				    !flow_time_before(now_e,
				    at))
					elapsed = now_e - at;
				est->cpuperf_ema =
				    flow_ema_decay(
				    est->cpuperf_ema,
				    elapsed,
				    (u64)FLOW_CPUPERF_HALF_LIFE_NS);
				est->cpuperf_ema_at = now_e;
			}
			/* Queue empty reads the per CPU queue plus overflow. */
			dsq_nr = 0;
			{
				u8 gg = flow_group_live((u32)cpu,
				    nr_cpu_ids);
				u64 bq = flow_slot_cpu_dsq((u32)cpu, gg);
				dsq_nr = scx_bpf_dsq_nr_queued(bq);
				dsq_nr += scx_bpf_dsq_nr_queued(
				    flow_slot_overflow_dsq(gg));
			}
			local_nr = scx_bpf_dsq_nr_queued(
			    (u64)SCX_DSQ_LOCAL_ON |
			    (u64)cpu);
			if (flow_should_restore_hint(runnable,
			    dsq_nr, local_nr)) {
				u32 perf =
				    (u32)FLOW_CPUPERF_IDLE;
				/* M2 maps the decayed EMA. */
				/* Long idle still maps to zero. */
				/* Keeps natural hints with no pin, */
				/* so no hint split. */
				if (est)
					perf =
					    flow_cpuperf_from_ema(
					    est->cpuperf_ema);
				if (scx_bpf_cpuperf_set)
					scx_bpf_cpuperf_set(cpu,
					    perf);
			}
			/* Token refill to full with no other change. */
			flow_token_refill((u32)cpu);
		}
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	est = flow_clamp_est(delta);
	tctx->est_ns = est;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_classify(tctx, now, delta, cpu);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
	tctx->run_at = 0;
	scaled = flow_scale_by_weight(est,
	    flow_weight_of(flow_nice_of(p)));
	nv = flow_vruntime_add(tctx->vruntime, scaled);
	tctx->vruntime = nv;
	if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
		struct flow_cpu_state *st;
		u64 dsq_nr;
		u64 local_nr;
		/* Queue empty reads the per CPU queue plus overflow. */
		dsq_nr = 0;
		{
			u8 gg = flow_group_live((u32)cpu,
			    nr_cpu_ids);
			u64 bq = flow_slot_cpu_dsq((u32)cpu, gg);
			dsq_nr = scx_bpf_dsq_nr_queued(bq);
			dsq_nr += scx_bpf_dsq_nr_queued(
			    flow_slot_overflow_dsq(gg));
		}
		local_nr = scx_bpf_dsq_nr_queued(
		    (u64)SCX_DSQ_LOCAL_ON |
		    (u64)cpu);
		st = flow_cpu((u32)cpu);
		/* Pure-EMA update at M2 before frontier. */
		/* Elapsed is wrap safe via time before with */
		/* zero at staying zero. Decays then climbs */
		/* when delta is past zero, then stamps now. */
		if (st) {
			u64 at = st->cpuperf_ema_at;
			u64 elapsed = 0;
			u64 ema;
			if (at != 0 &&
			    !flow_time_before(now, at))
				elapsed = now - at;
			ema = flow_ema_decay(st->cpuperf_ema,
			    elapsed,
			    (u64)FLOW_CPUPERF_HALF_LIFE_NS);
			if (delta > 0)
				ema = flow_ema_climb(ema,
				    delta);
			st->cpuperf_ema = ema;
			st->cpuperf_ema_at = now;
			/* Charge this segment once with fetch add. Run at clears earlier, so */
			/* disable and exit later see zero with no second charge. */
			__sync_fetch_and_add(&st->active_ns, delta);
		}
		if (st) {
			if (!runnable) {
				if (dsq_nr == 0 &&
				    local_nr == 0) {
					if (nv != 0)
						st->frontier =
						    flow_frontier_idle(nv);
				} else {
					st->frontier =
					    flow_frontier_max(
					    st->frontier, nv);
				}
			} else {
				st->frontier = flow_frontier_max(
				    st->frontier, nv);
			}
		}
		if (flow_should_restore_hint(runnable,
		    dsq_nr, local_nr)) {
			u32 perf =
			    (u32)FLOW_CPUPERF_IDLE;
			/* M2 keeps the M1 predicate but maps */
			/* the decayed EMA with no hard zero. */
			/* Long sleep decays to zero before */
			/* the climb, so zero delta maps zero. */
			/* Keeps natural hints with no pin, */
			/* so no hint split. */
			if (st)
				perf = flow_cpuperf_from_ema(
				    st->cpuperf_ema);
			if (scx_bpf_cpuperf_set)
				scx_bpf_cpuperf_set(cpu,
				    perf);
		}
		/* Token refill to full with no other change. */
		flow_token_refill((u32)cpu);
	}
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->est_ns = 0;
	tctx->run_at = 0;
	tctx->vruntime = 0;
	tctx->deadline = (u64)-1;
	tctx->win_start = 0;
	tctx->burn = 0;
	tctx->group = (u8)FLOW_GROUP_LIGHT;
	tctx->low_runs = 0;
	tctx->wake_hits = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	flow_clear_running_if_owner(cpu,
	    (u32)p->pid);
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	/* Charge a segment stopping never saw, at most once. */
	flow_charge_leftover(cpu, tctx);
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	flow_clear_running_if_owner(cpu,
	    (u32)p->pid);
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	/* Charge a segment stopping never saw, at most once. */
	flow_charge_leftover(cpu, tctx);
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* Clear the stale running view with no charge. The task segment still ends */
	/* through stopping, disable, and exit, which own the single charge through */
	/* run at, so release never double counts. */
	flow_clear_running(cpu);
}
