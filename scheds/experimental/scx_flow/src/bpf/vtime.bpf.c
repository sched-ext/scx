// SPDX-License-Identifier: GPL-2.0
/*
 * Virtual time ledger plus CPU minimum for the core.
 *
 * Holds the clock plus task plus CPU lookups shared by every op plus
 * the vruntime ledger plus the CPU minimum fold. The ledger advances
 * by the fair delta with saturation, so heavy tasks move slowly while
 * light tasks move quickly with no divide beyond the scaler. The CPU
 * minimum folds forward best effort with bounded retry, so newly woken
 * tasks clamp without gaining past the lag bound. A stale minimum on
 * an idle CPU holds until the next charge and stays bounded by the 2ms
 * lag clamp plus eligibility, so no decay timer runs and rejoins keep
 * at most one slice of boost with no storm. Runs inline with no walk,
 * so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Monotonic clock in nanos for deadlines plus fair times. */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}
/* Task state without create for fast read paths. */
static struct flow_task_ctx *flow_lookup(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}
/* Task state with create for enqueue and enable paths. */
static struct flow_task_ctx *flow_get(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
/* CPU state or null when the id is past the bound. */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}
/* Topology view or null when the id is past the bound. */
static struct flow_topo *flow_topo(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&topo_stor, &key);
}
/* Capacity units of one CPU with base on miss. */
/* A zero row means unknown, so the base applies. */
static __always_inline u32 flow_cpu_units(u32 cpu)
{
	u32 key = cpu;
	u32 *v;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return (u32)FLOW_CAP_BASE;
	v = bpf_map_lookup_elem(&cap_stor, &key);
	if (!v || *v == 0)
		return (u32)FLOW_CAP_BASE;
	return READ_ONCE(*v);
}
/* Node of one CPU with zero on miss. */
static __always_inline u32 flow_cpu_node(u32 cpu)
{
	struct flow_topo *tp = flow_topo(cpu);
	if (!tp)
		return 0;
	if (tp->node >= (u32)FLOW_MAX_NODES)
		return 0;
	return READ_ONCE(tp->node);
}
/**
 * flow_ledger_advance - advance vruntime by one delta at one weight.
 * @vruntime: base vruntime in nanos.
 * @delta: raw service in nanos.
 * @weight: scheduling share, clamped to range.
 *
 * Adds the fair scaled service to the base through the shared scaler,
 * so heavy tasks advance slowly while light tasks advance quickly.
 *
 * Returns: advanced vruntime in nanos.
 */
static __always_inline u64 flow_ledger_advance(u64 vruntime,
	u64 delta, u32 weight)
{
	return flow_sat_add(vruntime, flow_scaled_delta(delta, weight));
}
/* Minimum vruntime of one CPU with zero on miss. */
/* A missing row means no history, so zero keeps new tasks eligible. */
/* A stale minimum on an idle CPU holds until the next charge, but the */
/* 2ms lag clamp plus eligibility bound the sleeper boost to one slice */
/* with no storm, so no decay is needed. */
static __always_inline u64 flow_cpu_min(u32 cpu)
{
	struct flow_cpu_state *st = flow_cpu(cpu);
	if (!st)
		return 0;
	return READ_ONCE(st->min_vruntime);
}
/* Fold one CPU minimum forward to at least the given vruntime. */
/* Takes the max best effort with a bounded compare and swap retry, so a */
/* lost race retries with no torn write and the next charge folds again */
/* with no stall. A zero vruntime never moves the minimum, so no history */
/* holds zero. A vruntime at max clamps with no wrap. A stale minimum */
/* never moves backward here, so idle CPUs rejoin through the lag clamp */
/* with at most one slice of boost and no timer. */
static __always_inline void flow_min_advance(s32 cpu,
	u64 vruntime)
{
	struct flow_cpu_state *st;
	s32 i;
	if (cpu < 0)
		return;
	if (vruntime == 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(st->min_vruntime);
		u64 old;
		if (cur == vruntime)
			break;
		if (!flow_time_before(cur, vruntime))
			break;
		old = __sync_val_compare_and_swap(&st->min_vruntime,
			    cur, vruntime);
		if (old == cur)
			break;
	}
}
/* Clear the running pid with a compare and swap loop. */
/* Retries the swap so a concurrent run pairs, and a lost race keeps */
/* the winner with no torn zero. Release carries no pid, so the loop */
/* claims whatever owner it finds. The segment still ends through */
/* stopping with no charge here. */
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
