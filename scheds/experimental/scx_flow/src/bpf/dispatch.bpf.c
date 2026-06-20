/* Undefine the compat macro so we can declare base kfuncs directly. */
#ifdef scx_bpf_dsq_move_to_local
#undef scx_bpf_dsq_move_to_local
#endif

/* Dispatch hierarchy — included by main.bpf.c via #include
 *
 * 1. Per-CPU pinned DSQ (non-migratable tasks)
 * 2. Per-CPU vtime DSQ (this CPU's own tasks)
 * 3. Peer CPU vtime DSQs (work stealing — idle CPU steals from busiest peer)
 * 4. Shared FLOW_BATCH_DSQ (fallback)
 * 5. Previous task extension
 *
 * flow_dsq_move_one wraps scx_bpf_dsq_move_to_local with fallback
 * chain for v2/v1/old/base variants. */

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
	return scx_bpf_dsq_move_to_local(dsq_id);
}

int BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 peer;
	u64 best_load = 0, load;
	s32 steal_from = -1;

	/* 1. Per-CPU pinned DSQ. */
	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_PINNED_DSQ_BASE + (u32)cpu)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return 0;
	}

	/* 2. Per-CPU vtime DSQ (this CPU's own tasks). */
	if (scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_VTIME_DSQ_BASE + (u32)cpu))
		return 0;

	/* 3. Work stealing: if this CPU is idle, steal from the busiest peer.
	 *    Scan peer DSQs (bounded by nr_cpu_ids ≤ 1024). */
	bpf_for(peer, 0, 1024) {
		if ((u32)peer >= nr_cpu_ids)
			break;
		if (peer == cpu)
			continue;
		if (scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)peer) > 0) {
			load = scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)peer);
			if (load > best_load) {
				best_load = load;
				steal_from = peer;
			}
		}
	}
	if (steal_from >= 0 &&
	    flow_dsq_move_one(FLOW_VTIME_DSQ_BASE + (u32)steal_from))
		return 0;

	/* 4. Shared FLOW_BATCH_DSQ fallback. */
	if (scx_bpf_dsq_nr_queued(FLOW_BATCH_DSQ) > 0 &&
	    flow_dsq_move_one(FLOW_BATCH_DSQ))
		return 0;

	/* 5. Previous task extension. */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
	return 0;
}
