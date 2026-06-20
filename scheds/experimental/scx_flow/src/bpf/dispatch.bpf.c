/* Undefine the compat macro so we can declare base kfuncs directly. */
#ifdef scx_bpf_dsq_move_to_local
#undef scx_bpf_dsq_move_to_local
#endif

/* Dispatch hierarchy — included by main.bpf.c via #include
 *
 * Shared FLOW_BATCH_DSQ: non-wakeup tasks with vtime ordering.  Any
 * idle CPU steals from this DSQ, providing natural load balancing.
 * Per-CPU pinned DSQ: non-migratable tasks (nr_cpus_allowed == 1).
 *
 * flow_dsq_move_one wraps scx_bpf_dsq_move_to_local with fallback
 * chain for v2/v1/old/base variants across kernel versions. */

bool scx_bpf_dsq_move_to_local___v2(u64 dsq_id, u64 enq_flags) __ksym __weak;
bool scx_bpf_dsq_move_to_local___v1(u64 dsq_id) __ksym __weak;
bool scx_bpf_consume___old(u64 dsq_id) __ksym __weak;
bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym __weak;

static __always_inline bool flow_dsq_move_one(u64 dsq_id)
{
	if (bpf_ksym_exists(scx_bpf_dsq_move_to_local___v2))
		return scx_bpf_dsq_move_to_local___v2(dsq_id, 0);
	if (bpf_ksym_exists(scx_bpf_dsq_move_to_local___v1))
		return scx_bpf_dsq_move_to_local___v1(dsq_id);
	if (bpf_ksym_exists(scx_bpf_consume___old))
		return scx_bpf_consume___old(dsq_id);
	/* Fallback: base function (kernel 7.0.x). */
	return scx_bpf_dsq_move_to_local(dsq_id);
}

int BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	/* 1. Per-CPU pinned DSQ. */
	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_PINNED_DSQ_BASE + (u32)cpu)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return 0;
	}

	/* 2. Shared FLOW_BATCH_DSQ: non-wakeup tasks with vtime ordering.
	 *    Any idle CPU steals from this shared DSQ, balancing load
	 *    without per-enqueue CPU scanning. */
	if (scx_bpf_dsq_nr_queued(FLOW_BATCH_DSQ) > 0 &&
	    flow_dsq_move_one(FLOW_BATCH_DSQ)) {
		return 0;
	}

	/* 3. Previous task extension. */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
	return 0;
}
