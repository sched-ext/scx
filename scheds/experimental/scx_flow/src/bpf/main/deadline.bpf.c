// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline helpers for the core.
 *
 * Holds the release plus period plus deadline plus admission plus
 * drain readiness checks with saturating math. Only admitted inserts
 * touch the admitted rows, parks and homeless work never do. Runs
 * under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Share of one task on admission from hint else default. */
/* A zero hint means no hint, so the default period applies. */
static __always_inline u64 flow_admit_share(u32 hint_us)
{
	return flow_slice_permillle(flow_task_period(hint_us));
}
/* True when one task still meets its deadline from the given time. */
/* A zero deadline means no order yet, so the check passes with no */
/* miss. A time past the deadline fails, so the caller parks. */
static __always_inline bool flow_deadline_ok(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return true;
	if (flow_time_before(now, deadline))
		return true;
	if (now == deadline)
		return true;
	return false;
}
/* Drain depth of one CPU as queued slices times the quantum. */
/* Saturates on wrap, so a huge depth clamps instead of wrapping to */
/* an idle view. A bad read drops to zero with no boost. */
static __always_inline u64 flow_drain_ns(u64 dsq)
{
	s32 n = scx_bpf_dsq_nr_queued(dsq);
	u64 depth;
	if (n <= 0)
		return 0;
	depth = (u64)n;
	if (depth > (u64)~0ULL / (u64)FLOW_QUANTUM_NS)
		return (u64)~0ULL;
	return depth * (u64)FLOW_QUANTUM_NS;
}
/* True when one CPU can finish its local drain before a deadline. */
/* Adds now plus drain with saturation, so a huge drain fails closed */
/* with no wrap to an early view. */
static __always_inline bool flow_cpu_meets(u32 cpu,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_drain_ns(flow_local_dsq(cpu));
	ready = flow_sat_add(now, drain);
	if (ready == (u64)~0ULL)
		return false;
	if (flow_time_before(ready, deadline))
		return true;
	if (ready == deadline)
		return true;
	return false;
}
/* Add one admitted share to a CPU row with saturation. */
/* The add clamps, so a huge hint never wraps the row to idle. The */
/* store races best effort with last writer winning, and the stored */
/* share on the task adds once plus drops once, so concurrent passes */
/* never drift the row past one transient share. */
static __noinline void flow_admit_add(u32 cpu,
	u64 share)
{
	u32 key = cpu;
	u64 *v;
	u64 cur;
	u64 sum;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return;
	if (!flow_cpu_live(cpu))
		return;
	v = bpf_map_lookup_elem(&admit_stor, &key);
	if (!v)
		return;
	cur = READ_ONCE(*v);
	sum = cur + share;
	if (sum < cur)
		sum = (u64)~0ULL;
	__sync_lock_test_and_set(v, sum);
}
/* Drop one admitted share from a CPU row with floor at zero. */
/* A share past the row floors to zero, so a double drop never wraps. */
/* The store races best effort the same way, so a lost race leaves at */
/* most one transient share the next pass repairs. */
static __noinline void flow_admit_drop(u32 cpu,
	u64 share)
{
	u32 key = cpu;
	u64 *v;
	u64 cur;
	u64 want;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return;
	v = bpf_map_lookup_elem(&admit_stor, &key);
	if (!v)
		return;
	cur = READ_ONCE(*v);
	if (cur > share)
		want = cur - share;
	else
		want = 0;
	__sync_lock_test_and_set(v, want);
}
/* Drop the stored admit share of one task with floor at zero. */
/* Clears the stored share plus CPU, so a second drop stays empty */
/* with no double debit. Runs on stop plus disable plus exit, so a */
/* hint change between enqueue and stop never drifts the row. */
static __noinline void flow_admit_drop_stored(
	struct flow_task_ctx *tctx)
{
	u64 share;
	u32 cpu;
	if (!tctx)
		return;
	share = READ_ONCE(tctx->admit_share);
	cpu = READ_ONCE(tctx->admit_cpu);
	if (!share)
		return;
	flow_admit_drop(cpu, share);
	__sync_lock_test_and_set(&tctx->admit_share, 0);
	__sync_lock_test_and_set(&tctx->admit_cpu, 0);
}
