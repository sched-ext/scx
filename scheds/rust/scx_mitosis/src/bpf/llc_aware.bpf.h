/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-LLC domain mappings. It provides code to
 * recalculate per-LLC CPU counts within cells and implements weighted
 * random LLC selection for tasks. It also tracks work-stealing
 * statistics for cross-LLC task migrations.
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
extern u32		  cpu_to_llc[MAX_CPUS];
extern struct llc_cpumask llc_to_cpus[MAX_LLCS];

static inline bool	  llc_is_valid(u32 llc_id)
{
	if (llc_id == LLC_INVALID)
		return false;

	return llc_id < MAX_LLCS;
}

static inline void init_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;

	if (!enable_work_stealing)
		return;

	tctx->steal_count    = 0;
	tctx->last_stolen_at = 0;
}

static inline const struct cpumask *lookup_llc_cpumask(u32 llc)
{
	if (llc >= nr_llc) {
		scx_bpf_error("llc index out of bounds: %d", llc);
		return NULL;
	}

	return (const struct cpumask *)&llc_to_cpus[llc];
}

/*
 * Recompute cell->llc_cpu_cnt[] for a cell cpumask.
 *
 * @cell_idx: The cell index to update LLC counts for
 * @explicit_mask: If non-NULL, use this cpumask instead of looking up current
 *                 cell cpumask. This allows pre-calculating counts for a new
 *                 cpumask BEFORE swapping it in, avoiding race conditions.
 */
static __always_inline int
recalc_cell_llc_counts(u32 cell_idx, const struct cpumask *explicit_mask)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell)
		return -ENOENT;

	CPUMASK_GUARD(tmp_guard);
	if (!tmp_guard.mask) {
		scx_bpf_error(
			"recalc_cell_llc_counts: failed to create tmp mask");
		return -ENOMEM;
	}

	u32 llc, llcs_present = 0, total_cpus = 0;
	// Just so we don't hold the lock longer than necessary
	u32		      llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

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

		bpf_cpumask_and(tmp_guard.mask, cell_mask, llc_mask);

		u32 cnt = bpf_cpumask_weight(
			(const struct cpumask *)tmp_guard.mask);

		llc_cpu_cnt_tmp[llc] = cnt;

		// These are counted across the whole cell
		total_cpus += cnt;

		// Number of non-empty LLCs in this cell
		if (cnt)
			llcs_present++;
	}

	// Write to cell
	bpf_spin_lock(&cell->lock);
	for (u32 llc_idx = 0; llc_idx < nr_llc; llc_idx++) {
		cell->llcs[llc_idx].cpu_cnt = llc_cpu_cnt_tmp[llc_idx];
	}

	cell->llc_present_cnt = llcs_present;
	cell->cpu_cnt	      = total_cpus;
	bpf_spin_unlock(&cell->lock);
	return 0;
}

/**
 * Weighted random selection of an LLC cache domain for a task.
 *
 * Uses the CPU count in each LLC domain within the cell as weights to
 * probabilistically select an LLC. LLC domains with more CPUs in the cell
 * have higher probability of being selected.
 *
 * @cell_id: The cell ID to select an LLC from
 * @return: LLC ID on success, LLC_INVALID on error
 */
static inline s32 pick_llc_for_task(u32 cell_id)
{
	struct cell *cell;

	/* Look up the cell structure */
	if (!(cell = lookup_cell(cell_id)))
		return LLC_INVALID;

	/*
	 * Read only what we need under the lock to avoid putting the
	 * large cell struct on the stack (would exceed BPF stack limit).
	 */
	u32 llc_cpu_cnt[MAX_LLCS];

	bpf_spin_lock(&cell->lock);
	for (u32 i = 0; i < MAX_LLCS; i++)
		llc_cpu_cnt[i] = cell->llcs[i].cpu_cnt;

	u32 total_cpu_cnt = cell->cpu_cnt;
	bpf_spin_unlock(&cell->lock);

	if (!total_cpu_cnt) {
		scx_bpf_error(
			"pick_llc_for_task: cell %d has no CPUs accounted yet",
			cell_id);
		return LLC_INVALID;
	}

	/* Find the LLC domain corresponding to the target value using
	 * weighted selection - accumulate CPU counts until we exceed target */

	/* Generate random target value in range [0, cpu_cnt) */
	u32 target = bpf_get_prandom_u32() % total_cpu_cnt;
	u32 llc, cur = 0;
	s32 ret = LLC_INVALID;

	/* Linear scan: find first LLC where cumulative count exceeds target */
	bpf_for(llc, 0, nr_llc)
	{
		cur += llc_cpu_cnt[llc];
		if (target < cur) {
			ret = (s32)llc;
			break;
		}
	}

	if (ret == LLC_INVALID) {
		scx_bpf_error("pick_llc_for_task: invalid LLC");
		return LLC_INVALID;
	}

	return ret;
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

/*
 * Detect and handle cross-LLC task migration.
 * Called from running() to check if task's assigned LLC differs
 * from the CPU's LLC (indicating work stealing occurred).
 *
 * Caller must ensure enable_llc_awareness is true.
 */
static inline int maybe_retag_stolen_task(struct task_struct *p,
					  struct task_ctx    *tctx,
					  struct cpu_ctx     *cctx)
{
	/* No mismatch = no steal, fast path */
	if (tctx->llc == cctx->llc)
		return 0;

	/* Task was stolen to a different LLC - update accounting */
	tctx->steal_count++;
	tctx->last_stolen_at = scx_bpf_now();

	/* Assign task to new LLC */
	tctx->llc = cctx->llc;

	/*
	 * New LLC, need new cpumask. This updates the task vtime
	 * to that of the new cell-LLC DSQ.
	 */
	return update_task_cpumask(p, tctx);
}

/* Work stealing:
 * Scan sibling (cell,LLC) DSQs in the same cell and steal the first queued task if it can run on this cpu
 * Returns:
 *  true == 1;  task was stolen
 *  false == 0; no tasks were stolen
 *  error <0;   error encountered
*/
static inline s32 try_stealing_work(u32 cell, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_stealing_work: invalid local_llc: %d",
			      local_llc);
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

		/*
    * Skip if the cell doesn't have CPUs in this LLC.
    * Note: rechecking cell_ptr for verifier.
    * This is racy with try_stealing_this_task, but we don't care -
    * if the LLC actually doesn't have CPUs come steal time,
    * we will fail the steal and continue to the next LLC.
    */
		if (cell_ptr &&
		    READ_ONCE(cell_ptr->llcs[candidate_llc].cpu_cnt) == 0)
			continue;

		dsq_id_t candidate_dsq =
			get_cell_llc_dsq_id(cell, candidate_llc);
		if (dsq_is_invalid(candidate_dsq))
			return -EINVAL; // already errored in get_cell_llc_dsq_id

		// Optimization: skip if faster than constructing an iterator
		// Not redundant with later checking if task found (race)
		if (!scx_bpf_dsq_nr_queued(candidate_dsq.raw))
			continue;

		/*
		 * Attempt the steal - can fail because it's a race.
		 * We don't update task_ctx here because the peeked task_ctx
		 * may be stale (a different task may now be at head of DSQ).
		 * Actual retag and accounting happens in running() via
		 * mismatch detection.
		 */
		if (!scx_bpf_dsq_move_to_local(candidate_dsq.raw))
			continue;

		// Success, we got a task
		return true;
	}
	return false;
}

static inline int update_task_llc_assignment(struct task_struct *p,
					     struct task_ctx	*tctx)
{
	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	const struct cpumask *llc_mask = NULL;

	// Let's get a new LLC for this task
	s32 new_llc = pick_llc_for_task(tctx->cell);
	if (new_llc < 0)
		return -EINVAL;

	tctx->llc = new_llc;
	llc_mask  = lookup_llc_cpumask((u32)tctx->llc);
	if (!llc_mask)
		return -ENOENT;

	/* --- Narrow the effective cpumask by the chosen LLC --- */
	/* tctx->cpumask already contains (task_affinity & cell_mask) */
	struct bpf_cpumask *cpumask = tctx->cpumask;
	if (!cpumask) {
		scx_bpf_error("tctx->cpumask is NULL");
		return -EINVAL;
	}
	bpf_cpumask_and(cpumask, (const struct cpumask *)cpumask, llc_mask);

	/* If empty after intersection, nothing can run here */
	if (bpf_cpumask_empty((const struct cpumask *)cpumask)) {
		scx_bpf_error("Empty cpumask after intersection");
		return -EINVAL;
	}

	/* --- Point to the correct (cell,LLC) DSQ and set vtime baseline --- */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, tctx->llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	struct cell *cell = lookup_cell(tctx->cell);
	if (!cell)
		return -ENOENT;

	p->scx.dsq_vtime = READ_ONCE(cell->llcs[new_llc].vtime_now);
	return 0;
}
