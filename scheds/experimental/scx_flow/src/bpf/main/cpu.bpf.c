// SPDX-License-Identifier: GPL-2.0
/*
 * CPU view plus entry gate helpers for the core.
 *
 * Holds the live plus mask checks plus the running pid and gauge
 * helpers plus the universal entry gate with no charge. The gate
 * runs first in every op, so bad CPUs plus bad queues plus bad tasks
 * fail closed with one counter. Runs inline with no walk, so the
 * verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when the id is a live CPU below nr and the bound. */
/* Live means below the nr snapshot at init with no kernel online read. */
/* Hotplug needs a restart with fail closed to overflow. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
/* True when the CPU is live and inside the task mask. */
/* Unknown CPUs fail closed to overflow with one direct kick. */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* Drop the on CPU gauge by one with no wrap and no clear. */
/* The gauge is display only with no scheduling use, so a lost race */
/* stays best effort with no correctness need. Retries the compare */
/* and swap to pair every counted start, and a lost race retries with */
/* no silent drop. The bound stays at 16 for the verifier, and the */
/* window is one swap, so 16 covers the worst burst with no growing */
/* leak past it. */
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 16) {
		u64 cur = flow_stats.on_cpu;
		u64 nxt;
		u64 old;
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
	}
}
/* Clear the running pid with a compare and swap loop. */
/* Retries the swap so a concurrent run pairs, and a lost race keeps */
/* the winner with no torn zero. Release carries no pid, so the loop */
/* claims whatever owner it finds. The segment still ends through */
/* stopping or disable with no charge here. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	s32 i;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	bpf_for(i, 0, 4) {
		u32 cur = READ_ONCE(st->running_pid);
		u32 old;
		if (cur == 0)
			break;
		old = __sync_val_compare_and_swap(
		    &st->running_pid, cur, 0);
		if (old == cur)
			break;
	}
}
/* Clear the running pid only when the pid owns it. */
/* Uses one compare and swap, so a stale exit never clears a new */
/* owner after a switch. A zero pid never owns, so it passes. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (pid == 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	__sync_val_compare_and_swap(&st->running_pid, pid, 0);
}
/* True when one task may enter an op on the given CPU. */
/* Checks the CPU live view plus the task mask plus the queue id, so */
/* a stale CPU plus a moved task plus a stale queue fail closed with */
/* one counter. Exiting tasks skip the gate at the caller, so they */
/* never count here. A null task fails closed with one count. */
static __always_inline bool flow_entry_ok(s32 cpu,
	const struct task_struct *p, u64 dsq)
{
	if (!p)
		return false;
	if (cpu >= 0 && !flow_cpu_live((u32)cpu))
		return false;
	if (cpu >= 0 && !bpf_cpumask_test_cpu((u32)cpu,
	    p->cpus_ptr))
		return false;
	if (dsq && !flow_dsq_valid(dsq))
		return false;
	return true;
}
/* Count one closed gate rejection with saturation. */
/* The add saturates, so a huge count clamps instead of wrapping. */
static __always_inline void flow_gate_reject(void)
{
	u64 cur = READ_ONCE(flow_stats.gate_rejects);
	if (cur == (u64)~0ULL)
		return;
	__sync_fetch_and_add(&flow_stats.gate_rejects, 1);
}
