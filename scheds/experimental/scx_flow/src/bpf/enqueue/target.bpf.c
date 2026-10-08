// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue target for the flow scheduler.
 *
 * Holds the pinned test plus the target pick for the enqueue pass.
 * Pinned tasks stay where the mask allows with no scan, and every
 * other arrival falls back from the selected CPU to the first allowed
 * CPU with no topology walk. An empty mask falls through to the
 * machine tier at the caller. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task cannot migrate from its current CPU. */
/* Migration disabled plus a single allowed CPU both pin, so the */
/* caller waits in a tier queue with no scan and no direct jump. */
static __always_inline bool flow_task_pinned(const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
/* Pick the target CPU for one task from the select hint. */
/* Takes the selected CPU when live plus allowed, else the first */
/* allowed CPU when live, else negative with no scan, so the caller */
/* waits in the machine tier with no wait and no gate bypass. */
static __always_inline s32 flow_pick_target(struct task_struct *p, s32 sel)
{
	s32 first;
	if (sel >= 0 && flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
