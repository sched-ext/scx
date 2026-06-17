/* Dispatch hierarchy — included by main.bpf.c via #include
 *
 * Rotating tier dispatch (Model A):
 *   gen & 3 selects the dispatch phase.  Each phase rotates which tier
 *   is checked FIRST.  Over 4 dispatches every tier starts the cascade
 *   exactly once, guaranteeing that no tier waits longer than 3 dispatch
 *   calls before it is serviced.  Starvation-free by construction.
 *
 *   Phase 0:  PRIORITY → NORMAL → LOW → DEFICIT
 *   Phase 1:  NORMAL   → LOW    → DEFICIT → PRIORITY
 *   Phase 2:  LOW      → DEFICIT → PRIORITY → NORMAL
 *   Phase 3:  DEFICIT  → PRIORITY → NORMAL → LOW
 *
 *   The per-CPU pinned DSQ (non-migratable tasks) is always checked first
 *   regardless of phase — it bypasses the tier system entirely. */

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 gen = __sync_fetch_and_add(&dispatch_gen, 1);

	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE + (u32)cpu) > 0 &&
	    scx_bpf_dsq_move_to_local(FLOW_PINNED_DSQ_BASE + (u32)cpu, 0)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return;
	}

	switch (gen & 3) {
	case 0:
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_PRIORITY_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_PRIORITY_DSQ, 0))
			{ __sync_fetch_and_add(&tier_priority_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_NORMAL_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_NORMAL_DSQ, 0))
			{ __sync_fetch_and_add(&tier_normal_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_LOW_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_LOW_DSQ, 0))
			{ __sync_fetch_and_add(&tier_low_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_DEFICIT_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_DEFICIT_DSQ, 0))
			{ __sync_fetch_and_add(&tier_deficit_dispatches, 1); return; }
		break;
	case 1:
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_NORMAL_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_NORMAL_DSQ, 0))
			{ __sync_fetch_and_add(&tier_normal_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_LOW_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_LOW_DSQ, 0))
			{ __sync_fetch_and_add(&tier_low_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_DEFICIT_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_DEFICIT_DSQ, 0))
			{ __sync_fetch_and_add(&tier_deficit_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_PRIORITY_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_PRIORITY_DSQ, 0))
			{ __sync_fetch_and_add(&tier_priority_dispatches, 1); return; }
		break;
	case 2:
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_LOW_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_LOW_DSQ, 0))
			{ __sync_fetch_and_add(&tier_low_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_DEFICIT_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_DEFICIT_DSQ, 0))
			{ __sync_fetch_and_add(&tier_deficit_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_PRIORITY_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_PRIORITY_DSQ, 0))
			{ __sync_fetch_and_add(&tier_priority_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_NORMAL_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_NORMAL_DSQ, 0))
			{ __sync_fetch_and_add(&tier_normal_dispatches, 1); return; }
		break;
	case 3:
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_DEFICIT_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_DEFICIT_DSQ, 0))
			{ __sync_fetch_and_add(&tier_deficit_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_PRIORITY_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_PRIORITY_DSQ, 0))
			{ __sync_fetch_and_add(&tier_priority_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_NORMAL_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_NORMAL_DSQ, 0))
			{ __sync_fetch_and_add(&tier_normal_dispatches, 1); return; }
		if (scx_bpf_dsq_nr_queued(FLOW_TIER_LOW_DSQ) > 0 &&
		    scx_bpf_dsq_move_to_local(FLOW_TIER_LOW_DSQ, 0))
			{ __sync_fetch_and_add(&tier_low_dispatches, 1); return; }
		break;
	}

	/* No tasks in any tier DSQ — check whether prev still has a slice.
	 * This path is identical across all phases. */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
}
