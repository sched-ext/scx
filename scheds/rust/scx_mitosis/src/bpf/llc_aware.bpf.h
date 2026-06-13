/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-LLC domain mappings and maintaining
 * per-task LLC candidate masks derived from the task's base cpumask.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

/* struct cell LLC bitmaps use u64. */
_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");

/*
 * Global arrays for LLC topology, populated by userspace before load.
 * cpu_to_llc: Maps each CPU index to its LLC domain ID.
 * llc_to_cpus: Maps each LLC domain ID to a cpumask of CPUs in that domain.
 */
extern u32 cpu_to_llc[MAX_CPUS];
extern struct llc_cpumask llc_to_cpus[MAX_LLCS];

static inline bool llc_is_valid(u32 llc_id)
{
	if (llc_id == LLC_INVALID)
		return false;

	return llc_id < MAX_LLCS;
}

static inline void init_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;
	tctx->llc_cpumask_id = LLC_INVALID;
}

static inline const struct cpumask *lookup_llc_cpumask(u32 llc)
{
	if (llc >= nr_llc || llc >= MAX_LLCS) {
		scx_bpf_error("llc index out of bounds: %d", llc);
		return NULL;
	}

	return (const struct cpumask *)&llc_to_cpus[llc];
}

static inline void invalidate_task_llc_cpumask(struct task_ctx *tctx)
{
	tctx->llc_cpumask_id = LLC_INVALID;
}

static inline s32 llc_from_cpu(s32 cpu)
{
	if (cpu < 0 || cpu >= nr_possible_cpus || cpu >= MAX_CPUS) {
		scx_bpf_error("cpu out of bounds for LLC lookup: %d", cpu);
		return LLC_INVALID;
	}

	u32 llc = cpu_to_llc[cpu];
	if (!llc_is_valid(llc) || llc >= nr_llc) {
		scx_bpf_error("cpu %d maps to invalid LLC %u", cpu, llc);
		return LLC_INVALID;
	}

	return (s32)llc;
}

static inline s32 choose_task_llc(struct task_ctx *tctx, s32 preferred_cpu)
{
	const struct cpumask *cpumask;
	s32 llc;

	cpumask = cast_mask(tctx->cpumask);
	if (!cpumask || bpf_cpumask_empty(cpumask))
		return LLC_INVALID;

	if (preferred_cpu >= 0 && preferred_cpu < nr_possible_cpus && preferred_cpu < MAX_CPUS &&
	    bpf_cpumask_test_cpu(preferred_cpu, cpumask)) {
		llc = llc_from_cpu(preferred_cpu);
		if (llc_is_valid(llc))
			return llc;
	}

	u32 cpu = bpf_cpumask_any_distribute(cpumask);
	return llc_from_cpu(cpu);
}

static inline int refresh_task_llc_cpumask(struct task_ctx *tctx, u32 llc)
{
	const struct cpumask *base_mask;
	const struct cpumask *cached_mask;
	const struct cpumask *llc_mask;
	struct bpf_cpumask *llc_cpumask;

	llc_cpumask = tctx->llc_cpumask;
	if (!llc_cpumask) {
		scx_bpf_error("tctx->llc_cpumask is NULL");
		return -EINVAL;
	}

	if (tctx->llc_cpumask_id == llc) {
		cached_mask = cast_mask(llc_cpumask);
		if (cached_mask && !bpf_cpumask_empty(cached_mask))
			return 0;
		tctx->llc_cpumask_id = LLC_INVALID;
	}

	base_mask = cast_mask(tctx->cpumask);
	if (!base_mask) {
		scx_bpf_error("tctx->cpumask is NULL");
		return -EINVAL;
	}

	llc_mask = lookup_llc_cpumask(llc);
	if (!llc_mask)
		return -ENOENT;

	bpf_cpumask_and(llc_cpumask, base_mask, llc_mask);
	if (bpf_cpumask_empty(cast_mask(llc_cpumask))) {
		tctx->llc_cpumask_id = LLC_INVALID;
		return -ENOENT;
	}

	tctx->llc_cpumask_id = llc;
	return 0;
}

static void zero_cell_vtimes(struct cell *cell)
{
	WRITE_ONCE(cell->llcs_to_drain, 0);
	WRITE_ONCE(cell->llcs_with_cpus, 0);

	if (enable_llc_awareness) {
		u32 llc_idx;
		bpf_for(llc_idx, 0, MAX_LLCS)
		{
			WRITE_ONCE(cell->llcs[llc_idx].vtime_now, 0);
		}
	} else {
		WRITE_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now, 0);
	}
}

static inline void cell_llc_drain_enable(struct cell *cell, u32 llc)
{
	if (llc >= MAX_LLCS)
		return;

	__sync_or_and_fetch(&cell->llcs_to_drain, 1LLU << llc);
}

static inline void cell_llc_drain_disable(struct cell *cell, u32 llc)
{
	if (llc >= MAX_LLCS)
		return;

	__sync_and_and_fetch(&cell->llcs_to_drain, ~(1LLU << llc));
}

static inline bool cell_mask_intersects_llc(const struct cpumask *cell_mask, u32 llc)
{
	const struct cpumask *llc_mask;

	if (!cell_mask)
		return false;

	llc_mask = lookup_llc_cpumask(llc);
	if (!llc_mask)
		return false;

	return bpf_cpumask_intersects(cell_mask, llc_mask);
}

static inline bool cell_llc_has_cpus(struct cell *cell, u32 llc)
{
	return READ_ONCE(cell->llcs_with_cpus) & (1LLU << llc);
}

static inline void kick_cell_idle_cpu(u32 cell_id)
{
	s32 cpu = -1;

	scoped_guard(rcu)
	{
		const struct cpumask *cell_mask = lookup_cell_cpumask(cell_id);

		if (!cell_mask)
			return;

		cpu = scx_bpf_pick_idle_cpu(cell_mask, SCX_PICK_IDLE_CORE);
		if (cpu < 0)
			cpu = scx_bpf_pick_idle_cpu(cell_mask, 0);
	}
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static inline int refresh_cell_llc_draining(u32 cell_id)
{
	struct cell *cell;
	u64 llcs_with_cpus = 0;
	u32 llc;

	if (!enable_llc_awareness)
		return 0;

	cell = lookup_cell(cell_id);
	if (!cell)
		return -EINVAL;

	scoped_guard(rcu)
	{
		const struct cpumask *cell_mask = lookup_cell_cpumask(cell_id);

		if (!cell_mask)
			return -EINVAL;

		bpf_for(llc, 0, nr_llc)
		{
			if (llc >= MAX_LLCS)
				break;

			if (cell_mask_intersects_llc(cell_mask, llc))
				llcs_with_cpus |= 1LLU << llc;
		}
	}
	WRITE_ONCE(cell->llcs_with_cpus, llcs_with_cpus);

	/*
	 * Pair the post-publication DSQ scan with enqueue's post-insert cached
	 * no-CPU check. Either this path sees already queued work, or a racing
	 * queued work, or a racing enqueue sees the CPU-less LLC and enables
	 * draining itself. BPF has no standalone full-barrier instruction, so
	 * use an atomic op on a stack slot to avoid bouncing a shared cacheline.
	 */
	volatile unsigned long mb = 0;
	__sync_fetch_and_add(&mb, 0);

	bpf_for(llc, 0, nr_llc)
	{
		dsq_id_t dsq;
		s32 nr_queued;

		if (llc >= MAX_LLCS)
			break;

		if (llcs_with_cpus & (1LLU << llc)) {
			cell_llc_drain_disable(cell, llc);
			continue;
		}

		dsq = get_cell_llc_dsq_id(cell_id, llc);
		nr_queued = scx_bpf_dsq_nr_queued(dsq.raw);
		if (nr_queued > 0) {
			cell_llc_drain_enable(cell, llc);
			kick_cell_idle_cpu(cell_id);
		}
	}

	return 0;
}

static inline int account_cell_llc_enqueue(u32 cell_id, u32 llc)
{
	struct cell *cell;

	if (!enable_llc_awareness)
		return 0;

	if (!llc_is_valid(llc) || llc >= nr_llc) {
		scx_bpf_error("account_cell_llc_enqueue: invalid LLC %u", llc);
		return -EINVAL;
	}

	cell = lookup_cell(cell_id);
	if (!cell) {
		scx_bpf_error("account_cell_llc_enqueue: invalid cell %u", cell_id);
		return -ENOENT;
	}

	if (cell_llc_has_cpus(cell, llc))
		return 0;

	cell_llc_drain_enable(cell, llc);
	kick_cell_idle_cpu(cell_id);
	return 0;
}

static inline s32 try_draining_work(u32 cell_id, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_draining_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct cell *cell = lookup_cell(cell_id);
	if (!cell)
		return -EINVAL;

	u64 drain_mask = READ_ONCE(cell->llcs_to_drain);
	if (!drain_mask)
		return -ENOENT;

	u32 i;
	bpf_for(i, 0, nr_llc)
	{
		u32 candidate_llc = (local_llc + i) % nr_llc;
		u64 bit;
		bool disabled = false;
		bool consumed;
		s32 nr_queued;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read will be safe
		barrier_var(candidate_llc);

		if (candidate_llc >= MAX_LLCS)
			continue;

		if (candidate_llc == local_llc)
			continue;

		bit = 1LLU << candidate_llc;
		if (!(drain_mask & bit))
			continue;

		dsq_id_t candidate_dsq = get_cell_llc_dsq_id(cell_id, candidate_llc);

		if (cell_llc_has_cpus(cell, candidate_llc)) {
			/*
			 * Normal dispatch can consume this DSQ now that the LLC
			 * has CPUs again. Don't clear the drain bit here:
			 * refresh/enqueue may be racing to mark it orphaned
			 * again, and disabling must be paired with checking
			 * whether queued work remains.
			 */
			continue;
		}

		/*
		 * Turn off draining before consuming if this consume is likely
		 * to empty the DSQ. If a racing enqueue adds more work, either
		 * it observes that this LLC has no CPUs and re-enables draining,
		 * or the recheck below sees the new depth and re-enables it.
		 */
		nr_queued = scx_bpf_dsq_nr_queued(candidate_dsq.raw);
		if (nr_queued <= 1) {
			cell_llc_drain_disable(cell, candidate_llc);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0);

		if (disabled) {
			nr_queued = scx_bpf_dsq_nr_queued(candidate_dsq.raw);
			/*
			 * If refresh repopulated this LLC while drain was
			 * temporarily disabled, this can leave an unnecessary
			 * drain bit set until the next refresh. That's harmless:
			 * the LLC's CPUs can consume the DSQ normally, and future
			 * drain attempts skip it while cell_llc_has_cpus() is true.
			 */
			if (nr_queued > 0)
				cell_llc_drain_enable(cell, candidate_llc);
		}

		if (consumed)
			return candidate_llc;
	}
	return -ENOENT;
}

static inline s32 try_stealing_work(u32 cell_id, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_stealing_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct cell *cell = lookup_cell(cell_id);
	if (!cell)
		return -EINVAL;

	u32 i;
	bpf_for(i, 0, nr_llc)
	{
		u32 candidate_llc = (local_llc + i) % nr_llc;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read will be safe
		barrier_var(candidate_llc);

		if (candidate_llc >= MAX_LLCS)
			continue;

		if (candidate_llc == local_llc)
			continue;

		if (!cell_llc_has_cpus(cell, candidate_llc))
			continue;

		dsq_id_t candidate_dsq = get_cell_llc_dsq_id(cell_id, candidate_llc);

		// Optimization: skip if faster than constructing an iterator
		// Not redundant with later checking if task found (race)
		if (scx_bpf_dsq_nr_queued(candidate_dsq.raw) <= 0)
			continue;

		/*
		 * Attempt the steal - can fail because it's a race. The task's
		 * LLC is updated from the CPU it actually runs on in running().
		 */
		if (!scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0))
			continue;

		return 0;
	}
	return -ENOENT;
}

static inline int set_task_llc(struct task_struct *p, struct task_ctx *tctx, u32 new_llc,
			       bool reset_vtime)
{
	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	if (!llc_is_valid(new_llc) || new_llc >= nr_llc || new_llc >= MAX_LLCS) {
		scx_bpf_error("invalid LLC assignment: %u", new_llc);
		return -EINVAL;
	}

	struct cell *cell = lookup_cell(tctx->cell);
	if (!cell) {
		scx_bpf_error("failed to lookup cell %u for LLC assignment", tctx->cell);
		return -ENOENT;
	}

	u32 old_llc = tctx->llc;
	if (refresh_task_llc_cpumask(tctx, new_llc)) {
		scx_bpf_error("failed to refresh task LLC cpumask for cell %u LLC %u", tctx->cell,
			      new_llc);
		return -EINVAL;
	}

	/*
	 * This writes a cell/LLC DSQ. Pinned tasks keep CPU DSQs.
	 */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, new_llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	if (reset_vtime || !llc_is_valid(old_llc) || old_llc >= nr_llc || old_llc >= MAX_LLCS) {
		p->scx.dsq_vtime = READ_ONCE(cell->llcs[new_llc].vtime_now);
	} else if (old_llc != new_llc) {
		s64 vtime_delta = p->scx.dsq_vtime - READ_ONCE(cell->llcs[old_llc].vtime_now);
		p->scx.dsq_vtime = READ_ONCE(cell->llcs[new_llc].vtime_now) + vtime_delta;
	}

	tctx->llc = new_llc;
	return 0;
}

static inline int update_task_llc_assignment(struct task_struct *p, struct task_ctx *tctx,
					     s32 preferred_cpu)
{
	s32 new_llc = choose_task_llc(tctx, preferred_cpu);
	if (!llc_is_valid(new_llc))
		return -EINVAL;

	return set_task_llc(p, tctx, (u32)new_llc, true);
}

static inline int maybe_update_task_llc(struct task_struct *p, struct task_ctx *tctx,
					s32 preferred_cpu)
{
	int ret;
	s32 new_llc;

	if (!tctx->all_cell_cpus_allowed)
		return 0;

	/* Retag only all-cell tasks; pinned tasks keep CPU DSQs. */
	new_llc = choose_task_llc(tctx, preferred_cpu);
	if (!llc_is_valid(new_llc))
		return 0;

	if (tctx->llc == new_llc) {
		ret = refresh_task_llc_cpumask(tctx, (u32)new_llc);
		if (ret && !llc_is_valid(tctx->llc))
			return -EINVAL;
		return 0;
	}

	ret = set_task_llc(p, tctx, (u32)new_llc, false);
	if (ret && llc_is_valid(tctx->llc))
		return 0;
	return ret;
}
