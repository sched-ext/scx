// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU thin wrapper over the SSF placement.
 *
 * Takes idle first with no state cost, then the previous CPU when it
 * meets the deadline, then the slowest sufficient fit in O(VISIT) with
 * VISIT at most eight peers in two node-local phases, then the best
 * sufficient fallback over the next four peers past the SSF window from
 * cursor plus 9 with drain plus minimum plus prev plus id tiebreak. The
 * two scans cover twelve unique peers with no overlap when the host holds at
 * least twelve CPUs, else the windows wrap, so the fallback extends
 * coverage instead of rescanning. The shared cursor with dispatch steal
 * advances by two with best effort races and no atomic order. Pinned
 * tasks stay where the mask allows with no scan. An empty mask falls
 * through to the machine tier at enqueue. One ktime read serves the
 * previous plus SSF plus BSF checks, and pow2 hosts mask with no divide.
 *
 * The op holds the idle plus scan helpers in select/ with the pinned
 * plus idle plus SSF plus BSF plus best plus scan noinline on scalar
 * input, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "select/idle.bpf.c"
#include "select/scan.bpf.c"
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 idle;
	u64 deadline = 0;
	struct flow_task_ctx *tctx;
	(void)wake_flags;
	this_cpu = (s32)bpf_get_smp_processor_id();
	if (unlikely(is_migration_disabled(p)))
		return flow_select_pinned_cpu(p, prev_cpu);
	if (unlikely(p->nr_cpus_allowed == 1))
		return flow_select_pinned_cpu(p, prev_cpu);
	idle = flow_select_idle_probe(p, this_cpu);
	if (idle >= 0)
		return idle;
	tctx = flow_lookup(p);
	if (likely(tctx))
		deadline = READ_ONCE(tctx->deadline);
	if (unlikely(deadline == 0) && likely(flow_cpu_ok(p, prev_cpu)))
		return prev_cpu;
	return flow_select_scan(p, prev_cpu, deadline, (u32)this_cpu);
}
