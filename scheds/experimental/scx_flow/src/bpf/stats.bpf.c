// SPDX-License-Identifier: GPL-2.0
/*
 * Per CPU stats with no shared read modify write.
 *
 * Each CPU owns one stats row keyed by its id, so updates touch only
 * the local row with no cross CPU atomic. Aggregation sums all rows
 * in userspace with saturation, so the hot paths pay no contention.
 * A zero row means idle with no history. Runs under the caller with
 * no lock and no shared modify.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Resolve the local row pointer for direct field adds. */
/* Returns null on an out of bound id with no fold to row zero, so a */
/* stale CPU never attributes to CPU zero. Callers skip on null. */
static __always_inline struct flow_sched_stats *flow_stat_row(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return NULL;
	if ((u64)cpu >= nr_cpu_ids)
		return NULL;
	return bpf_map_lookup_elem(&cpu_stats_stor, &cpu);
}
/* Count one closed gate rejection with saturation. */
static __always_inline void flow_gate_reject(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	u64 cur;
	if (!row)
		return;
	cur = READ_ONCE(row->gate_rejects);
	if (cur == (u64)~0ULL)
		return;
	__sync_fetch_and_add(&row->gate_rejects, 1);
}
/* Count one tier move batch with no lock on the local row. */
static __always_inline void flow_account_local(u32 n)
{
	struct flow_sched_stats *row;
	if (!n)
		return;
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->local_moves, (u64)n);
}
/* Count one node tier move batch on the local row. */
static __always_inline void flow_account_node(u32 n)
{
	struct flow_sched_stats *row;
	if (!n)
		return;
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->node_moves, (u64)n);
}
/* Count one machine tier move batch on the local row. */
static __always_inline void flow_account_machine(u32 n)
{
	struct flow_sched_stats *row;
	if (!n)
		return;
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->machine_moves, (u64)n);
}
/* Count one deadline miss on the local row plus the task row. */
static __noinline void flow_count_miss(struct flow_task_ctx *tctx)
{
	struct flow_sched_stats *row;
	u32 m;
	if (!tctx)
		return;
	m = READ_ONCE(tctx->misses);
	if (m != 0xffffffffU)
		__sync_fetch_and_add(&tctx->misses, 1);
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->misses, 1);
}
/* Count one admit on the local row with no shared modify. */
static __always_inline void flow_count_admit(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->admits, 1);
}
/* Count one insert on the local row with no shared modify. */
static __always_inline void flow_count_insert(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->inserts, 1);
}
/* Count one kick on the local row with no shared modify. */
static __always_inline void flow_count_kick(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->kicks, 1);
}
/* Count one runtime delta on the local row with saturation. */
static __always_inline void flow_count_runtime(u64 delta)
{
	struct flow_sched_stats *row;
	if (delta == 0)
		return;
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->total_runtime, delta);
}
/* Count one requeue or completion on the local row. */
static __always_inline void flow_count_requeue(bool runnable)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	if (runnable)
		__sync_fetch_and_add(&row->requeues, 1);
	else
		__sync_fetch_and_add(&row->completions, 1);
}
/* Count one preempt kick on the local row. */
static __always_inline void flow_count_preempt_kick(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->preempt_kicks, 1);
}
/* Count one held preempt on the local row with no missing fill. */
static __always_inline void flow_count_preempt_skip(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->preempt_skipped, 1);
}
/* Count one RED overload reject on the local row. */
static __always_inline void flow_count_red_reject(void)
{
	struct flow_sched_stats *row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->red_rejects, 1);
}
/* Count one RED reclaim move on the local row. */
static __always_inline void flow_count_red_reclaim(u32 n)
{
	struct flow_sched_stats *row;
	if (!n)
		return;
	row = flow_stat_row();
	if (!row)
		return;
	__sync_fetch_and_add(&row->red_reclaims, (u64)n);
}
