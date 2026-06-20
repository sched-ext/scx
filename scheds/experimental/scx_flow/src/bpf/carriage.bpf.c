/* Waiting Room — included by main.bpf.c via #include
 *
 * Non-wakeup tasks are dispatched to FLOW_BATCH_DSQ, a shared vtime-
 * ordered DSQ (matching cosmos's global vtime DSQ pattern).  Any idle
 * CPU drains from FLOW_BATCH_DSQ during ops.dispatch(), naturally
 * balancing load without per-enqueue CPU scanning.
 *
 * The bandwidth model computes each task's slice from the task's budget,
 * the target core's frequency, and the system's total bandwidth:
 *   slice = (budget / BUDGET_MAX) x (thread_bw / system_total_khz) x window
 * adjusted for migration cost (same-LLC: -10%, cross-LLC: -25%).
 *
 * The carriage pool records PIDs for the web UI (stats-only). */

void scx_bpf_dsq_insert___v1(struct task_struct *p, u64 dsq_id,
			      u64 slice, u64 enq_flags) __ksym __weak;

/* Base slice: budget x frequency x window (PRD Phase C). */
static __always_inline u64 compute_base_slice(struct task_ctx *tctx,
					       s32 target_cpu)
{
	u64 slice_ns, budget, core_freq, siblings, thread_bw, bw_share, wshare;
	if (!tctx || tctx->budget_ns <= 0 || system_total_khz == 0 ||
	    target_cpu < 0 || (u32)target_cpu >= 1024)
		return task_slice_ns(tctx);
	budget = (u64)tctx->budget_ns;
	core_freq = per_cpu_max_freq_khz[target_cpu];
	siblings = per_cpu_sibling_count[target_cpu];
	thread_bw = siblings > 1 ? core_freq / siblings : core_freq;
	bw_share = thread_bw * 10000ULL / system_total_khz;
	wshare = budget * 10000ULL / FLOW_BUDGET_MAX_NS;
	if (wshare > 10000ULL) wshare = 10000ULL;
	slice_ns = wshare * bw_share * FLOW_CARRIAGE_NS / 10000ULL / 10000ULL;
	if (slice_ns < FLOW_SLICE_MIN_NS) slice_ns = FLOW_SLICE_MIN_NS;
	if (slice_ns > FLOW_BUDGET_MAX_NS) slice_ns = FLOW_BUDGET_MAX_NS;
	return slice_ns;
}

/* Migration penalty: same-LLC -10%, cross-LLC -25%. */
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
	return slice_ns;
}

static __always_inline u64 compute_task_slice(struct task_ctx *tctx,
					       s32 target_cpu)
{
	return apply_slice_adjustments(compute_base_slice(tctx, target_cpu),
				       tctx, target_cpu);
}

/*
 * Dispatch a non-wakeup task to the shared FLOW_BATCH_DSQ with vtime
 * ordering.  The target CPU for the bandwidth model is the task's
 * last_cpu (cache warmth).  No per-CPU scanning — idle CPUs drain
 * FLOW_BATCH_DSQ during ops.dispatch().
 */
static __always_inline void carriage_enqueue_task(struct task_struct *p,
						   struct task_ctx *tctx)
{
	u64 slot, slice_ns;
	s32 target_cpu;

	slot = __sync_fetch_and_add(&carriage_producer, 1)
		& (FLOW_NR_CARRIAGES - 1);

	/* Use last_cpu for the bandwidth model (cache warmth).
	 * The actual dispatch goes to the shared FLOW_BATCH_DSQ. */
	target_cpu = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu
		     : scx_bpf_task_cpu(p);

	slice_ns = compute_task_slice(tctx, target_cpu);

	/* Shareed vtime-ordered DSQ — idle CPUs drain via ops.dispatch(). */
	if (!scx_bpf_dsq_insert_vtime(p, FLOW_BATCH_DSQ,
				      slice_ns, slice_ns, 0))
		scx_bpf_dsq_insert___v1(p, FLOW_BATCH_DSQ, slice_ns, 0);

	carriage_pool[slot].tasks[carriage_pool[slot].count %
				  FLOW_CARRIAGE_CAPACITY] = (u64)(s32)p->pid;
	carriage_pool[slot].count++;
}
