/* Dispatch hierarchy — included by main.bpf.c via #include */

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct flow_cpu_state *cstate;

	cstate = lookup_cpu_state();
	if (!cstate)
		return;

	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE | (u32)cpu) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_PINNED_DSQ_BASE | (u32)cpu, 0)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return;
	}

	if (scx_bpf_dsq_nr_queued(FLOW_NORMAL_DSQ) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_NORMAL_DSQ, 0)) {
		FLOW_CPUSTAT_INC(cstate, normal_dispatches);
		return;
	}

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
}
