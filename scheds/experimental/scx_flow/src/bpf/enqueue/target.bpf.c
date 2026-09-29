// SPDX-License-Identifier: GPL-2.0
/*
 * Target pick for the enqueue pass.
 *
 * Holds the pinned check plus the select trust pick with mask wins.
 * Runs inline with no walk, so the verifier stays small. Runs under
 * the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task cannot move to another CPU. */
static __always_inline bool flow_task_pinned(
	const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
/* Target CPU for one enqueue with trust in select. */
/* Open tasks keep select when allowed, else the first allowed CPU. */
/* Pinned tasks never reach here, they rest in overflow. */
static __always_inline s32 flow_pick_target(
	struct task_struct *p, s32 sel)
{
	s32 first;
	if (sel >= 0 && flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
