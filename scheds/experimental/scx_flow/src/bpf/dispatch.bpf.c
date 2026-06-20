/* Undefine the compat macro so we can declare base kfuncs directly. */
#ifdef scx_bpf_dsq_move_to_local
#undef scx_bpf_dsq_move_to_local
#endif

/* Dispatch hierarchy — included by main.bpf.c via #include
 *
 * Per-CPU DSQ: non-wakeup tasks go to FLOW_VTIME_DSQ_BASE + cpu
 * (user-created).  ops.dispatch() moves tasks from the calling CPU's
 * DSQ to the local DSQ.
 *
 * The compat macro scx_bpf_dsq_move_to_local checks v2/v1/old variants,
 * but on kernel 7.0.x only the base scx_bpf_dsq_move_to_local(u64 dsq_id)
 * is registered.  We wrap it with a local fallback to ensure dispatch
 * works across all kernel versions. */

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

	/* 2. Per-CPU vtime DSQ. */
	if (scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_VTIME_DSQ_BASE + (u32)cpu)) {
		return 0;
	}

	/* 3. Previous task extension. */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
	return 0;
}
