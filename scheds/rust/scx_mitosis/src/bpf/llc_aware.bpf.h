/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-LLC domain mappings. It provides code to
 * recalculate per-LLC CPU counts within cells and maintain per-task LLC
 * candidate masks derived from the task's base cpumask.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

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

/*
 * Recompute cell->llc_cpu_cnt[] for a cell cpumask.
 *
 * @cell_idx: The cell index to update LLC counts for
 * @explicit_mask: If non-NULL, use this cpumask instead of looking up current
 *                 cell cpumask. This allows pre-calculating counts for a new
 *                 cpumask BEFORE swapping it in, avoiding race conditions.
 */
static __always_inline int recalc_cell_llc_counts(u32 cell_idx, const struct cpumask *explicit_mask)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell)
		return -ENOENT;

	struct bpf_cpumask *tmp_mask __free(bpf_cpumask) = bpf_cpumask_create();
	if (!tmp_mask) {
		scx_bpf_error("recalc_cell_llc_counts: failed to create tmp mask");
		return -ENOMEM;
	}

	u32 llc, llcs_present = 0, total_cpus = 0;
	// Just so we don't hold the lock longer than necessary
	u32 llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

	const struct cpumask *cell_mask;
	if (explicit_mask) {
		cell_mask = explicit_mask;
	} else {
		cell_mask = lookup_cell_cpumask(cell_idx); // RCU ptr
		if (!cell_mask)
			return -EINVAL;
	}

	bpf_for(llc, 0, nr_llc)
	{
		const struct cpumask *llc_mask = lookup_llc_cpumask(llc);
		if (!llc_mask)
			return -ENOENT;

		bpf_cpumask_and(tmp_mask, cell_mask, llc_mask);

		u32 cnt = bpf_cpumask_weight((const struct cpumask *)tmp_mask);

		llc_cpu_cnt_tmp[llc] = cnt;

		// These are counted across the whole cell
		total_cpus += cnt;

		// Number of non-empty LLCs in this cell
		if (cnt)
			llcs_present++;
	}

	// Write to cell
	scoped_guard(spin_lock, &cell->lock)
	{
		for (u32 llc_idx = 0; llc_idx < nr_llc; llc_idx++) {
			cell->llcs[llc_idx].cpu_cnt = llc_cpu_cnt_tmp[llc_idx];
		}

		cell->llc_present_cnt = llcs_present;
		cell->cpu_cnt = total_cpus;
	}
	return 0;
}

static void zero_cell_vtimes(struct cell *cell)
{
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

enum steal_work_result {
	STEAL_WORK_NONE = 0,
	STEAL_WORK_STOLEN = 1,
	STEAL_WORK_DRAINED = 2,
};

/* Work stealing / orphan rescue:
 * Scan sibling (cell,LLC) DSQs in the same cell and steal the first queued task
 * if it can run on this cpu. Orphaned LLC DSQs are also scanned because CPU
 * reconfiguration can otherwise leave queued tasks in an old LLC DSQ that no
 * dispatching CPU will naturally check.
 *
 * Returns:
 *  STEAL_WORK_DRAINED; drained an orphaned LLC DSQ
 *  STEAL_WORK_STOLEN;  task was stolen from a non-orphaned LLC DSQ
 *  STEAL_WORK_NONE;    no tasks were moved
 *  error <0;           error encountered
 */
static inline s32 try_stealing_work(u32 cell, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_stealing_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct cell *cell_ptr = lookup_cell(cell);
	if (!cell_ptr)
		return -EINVAL;

	// Loop over all other LLCs, looking for a queued task to steal
	u32 i;
	bpf_for(i, 1, nr_llc)
	{
		// Start with the next one to spread out the load
		u32 candidate_llc = (local_llc + i) % nr_llc;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read will be safe
		barrier_var(candidate_llc);

		if (candidate_llc >= MAX_LLCS)
			continue;

		u32 candidate_cpu_cnt = READ_ONCE(cell_ptr->llcs[candidate_llc].cpu_cnt);

		dsq_id_t candidate_dsq = get_cell_llc_dsq_id(cell, candidate_llc);
		if (dsq_is_invalid(candidate_dsq))
			return -EINVAL; // already errored in get_cell_llc_dsq_id

		// Optimization: skip if faster than constructing an iterator
		// Not redundant with later checking if task found (race)
		if (!scx_bpf_dsq_nr_queued(candidate_dsq.raw))
			continue;

		/*
		 * Attempt the steal - can fail because it's a race. The task's
		 * LLC is updated from the CPU it actually runs on in running().
		 */
		if (!scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0))
			continue;

		return candidate_cpu_cnt == 0 ? STEAL_WORK_DRAINED : STEAL_WORK_STOLEN;
	}
	return STEAL_WORK_NONE;
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
