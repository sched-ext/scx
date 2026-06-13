/* Dispatch hierarchy — included by main.bpf.c via #include */

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE + (u32)cpu) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_PINNED_DSQ_BASE + (u32)cpu, 0)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return;
	}

	if (scx_bpf_dsq_nr_queued(FLOW_TIER_PRIORITY_DSQ) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_TIER_PRIORITY_DSQ, 0)) {
		__sync_fetch_and_add(&tier_priority_dispatches, 1);
		return;
	}
	if (scx_bpf_dsq_nr_queued(FLOW_TIER_NORMAL_DSQ) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_TIER_NORMAL_DSQ, 0)) {
		__sync_fetch_and_add(&tier_normal_dispatches, 1);
		return;
	}
	if (scx_bpf_dsq_nr_queued(FLOW_TIER_LOW_DSQ) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_TIER_LOW_DSQ, 0)) {
		__sync_fetch_and_add(&tier_low_dispatches, 1);
		return;
	}
	if (scx_bpf_dsq_nr_queued(FLOW_TIER_DEFICIT_DSQ) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_TIER_DEFICIT_DSQ, 0)) {
		__sync_fetch_and_add(&tier_deficit_dispatches, 1);
		return;
	}

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
}
