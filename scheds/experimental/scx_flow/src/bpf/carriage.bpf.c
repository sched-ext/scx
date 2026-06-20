/* Waiting Room — included by main.bpf.c via #include
 *
 * Non-wakeup tasks are dispatched to per-CPU DSQs
 * (FLOW_VTIME_DSQ_BASE + target_cpu) via scx_bpf_dsq_insert___v1.
 * This calls the base kfunc directly (___v1 resolves to type_id 128815
 * on 7.0.x), bypassing the compat inline which would route to
 * ___v2___compat (checks task_is_running, returns false at re-enqueue).
 *
 * The carriage pool records a rolling window of dispatched PIDs for the
 * web UI display.  It uses a simple counter (no state machine) so it
 * never returns -2 — every task is dispatched to a proper DSQ. */

/* Declare the base dsq_insert kfunc directly (bypass compat inline). */
void scx_bpf_dsq_insert___v1(struct task_struct *p, u64 dsq_id,
			      u64 slice, u64 enq_flags) __ksym __weak;

static __always_inline u64 compute_base_slice(struct task_ctx *tctx,
					       s32 target_cpu)
{
	u64 slice_ns, budget, core_freq, is_smt, thread_bw, bw_share, wshare;
	if (!tctx || tctx->budget_ns <= 0 || system_total_khz == 0 ||
	    target_cpu < 0 || (u32)target_cpu >= 1024)
		return task_slice_ns(tctx);
	budget = (u64)tctx->budget_ns;
	core_freq = per_cpu_max_freq_khz[target_cpu];
	is_smt = per_cpu_is_smt[target_cpu];
	thread_bw = is_smt ? core_freq / 2 : core_freq;
	bw_share = thread_bw * 10000ULL / system_total_khz;
	wshare = budget * 10000ULL / FLOW_BUDGET_MAX_NS;
	if (wshare > 10000ULL) wshare = 10000ULL;
	slice_ns = wshare * bw_share * FLOW_CARRIAGE_NS / 10000ULL / 10000ULL;
	if (slice_ns < FLOW_SLICE_MIN_NS) slice_ns = FLOW_SLICE_MIN_NS;
	if (slice_ns > FLOW_BUDGET_MAX_NS) slice_ns = FLOW_BUDGET_MAX_NS;
	return slice_ns;
}

static __always_inline u64 apply_slice_adjustments(u64 slice_ns,
						     struct task_ctx *tctx,
						     s32 target_cpu)
{
	if (tctx && tctx->last_cpu >= 0 && tctx->last_cpu != target_cpu) {
		s32 last_llc = tctx->last_llc, tllc = -1;
		if ((u32)target_cpu < 1024)
			tllc = (s32)per_cpu_llc_id[(u32)target_cpu];
		if (last_llc >= 0 && tllc >= 0 && last_llc == tllc)
			slice_ns = slice_ns * 90ULL / 100ULL;
		else
			slice_ns = slice_ns * 75ULL / 100ULL;
		if (slice_ns < FLOW_SLICE_MIN_NS) slice_ns = FLOW_SLICE_MIN_NS;
	}
	if ((u32)target_cpu < 1024) {
		u64 nr_run = per_cpu_runnable[target_cpu];
		if (nr_run > 0 && nr_cpu_ids > 0) {
			u64 factor = nr_run * 100ULL / nr_cpu_ids;
			if (factor > 50) factor = 50;
			slice_ns = slice_ns * (100ULL - factor) / 100ULL;
			if (slice_ns < FLOW_SLICE_MIN_NS)
				slice_ns = FLOW_SLICE_MIN_NS;
		}
	}
	return slice_ns;
}

static __always_inline u64 compute_task_slice(struct task_ctx *tctx,
					       s32 target_cpu)
{
	return apply_slice_adjustments(compute_base_slice(tctx, target_cpu),
				       tctx, target_cpu);
}

/*
 * Dispatch a non-wakeup task and record its PID for the web UI.
 * The task is always dispatched (never returned -2).
 * The carriage pool uses a simple rolling counter — no ring buffer
 * state machine, no producer/consumer indices, no FILLING/CALCULATING
 * states.  It always records, never blocks.
 */
static __always_inline void carriage_enqueue_task(struct task_struct *p,
						   struct task_ctx *tctx)
{
	u64 slot, slice_ns;
	s32 target_cpu;

	slot = __sync_fetch_and_add(&carriage_producer, 1)
		& (FLOW_NR_CARRIAGES - 1);

	target_cpu = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu
		     : scx_bpf_task_cpu(p);
	slice_ns = compute_task_slice(tctx, target_cpu);

	/* Dispatch to the target CPU's per-CPU DSQ via the base kfunc. */
	{
		u64 dsq_id; s32 tgt = target_cpu;
		if (tgt < 0 || (u32)tgt >= 1024)
			tgt = scx_bpf_task_cpu(p);
		dsq_id = FLOW_VTIME_DSQ_BASE + (u32)tgt;
		scx_bpf_dsq_insert___v1(p, dsq_id, slice_ns, 0);
	}

	/* Record PID (stats-only, simple rolling slot). */
	carriage_pool[slot].tasks[carriage_pool[slot].count %
				  FLOW_CARRIAGE_CAPACITY] = (u64)(s32)p->pid;
	carriage_pool[slot].count++;
}
