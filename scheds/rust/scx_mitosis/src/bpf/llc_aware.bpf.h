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

	if (!enable_work_stealing)
		return;

	tctx->steal_count = 0;
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
 * Recompute subcell->llcs[].cpu_cnt for a subcell cpumask.
 *
 * @cell_idx: The cell index to update LLC counts for
 * @subcell_idx: The subcell index to update LLC counts for
 * @explicit_mask: If non-NULL, use this cpumask instead of looking up current
 *                 subcell cpumask. This allows pre-calculating counts for a new
 *                 cpumask BEFORE swapping it in, avoiding race conditions.
 */
static __always_inline int recalc_subcell_llc_counts(u32 cell_idx, u32 subcell_idx,
						     const struct cpumask *explicit_mask)
{
	struct cell *cell = lookup_cell(cell_idx);
	struct subcell *subcell;
	if (!cell)
		return -ENOENT;

	subcell = lookup_subcell(cell_idx, subcell_idx);
	if (!subcell)
		return -ENOENT;

	struct bpf_cpumask *tmp_mask __free(bpf_cpumask) = bpf_cpumask_create();
	if (!tmp_mask) {
		scx_bpf_error("recalc_subcell_llc_counts: failed to create tmp mask");
		return -ENOMEM;
	}

	u32 llc, total_cpus = 0;
	// Just so we don't hold the lock longer than necessary
	u32 llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

	const struct cpumask *cell_mask;
	if (explicit_mask) {
		cell_mask = explicit_mask;
	} else {
		cell_mask = lookup_subcell_cpumask(cell_idx, subcell_idx); // RCU ptr
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

		// These are counted across the whole subcell.
		total_cpus += cnt;
	}

	// Write to subcell
	scoped_guard(spin_lock, &cell->lock)
	{
		for (u32 llc_idx = 0; llc_idx < nr_llc; llc_idx++) {
			subcell->llcs[llc_idx].cpu_cnt = llc_cpu_cnt_tmp[llc_idx];
		}

		if (subcell_idx == 0)
			cell->cpu_cnt = total_cpus;
		subcell->cpu_cnt = total_cpus;
	}
	return 0;
}

/**
 * Weighted random selection of an LLC cache domain for a task.
 *
 * Uses the CPU count in each LLC domain within the subcell as weights to
 * probabilistically select an LLC. LLCs with more CPUs in the subcell
 * have higher probability of being selected.
 *
 * @cell_id: The cell ID to select an LLC from
 * @subcell_id: The subcell ID to select an LLC from
 * @return: LLC ID on success, LLC_INVALID on error
 */
static inline s32 pick_llc_for_task(u32 cell_id, u32 subcell_id)
{
	struct cell *cell;
	struct subcell *subcell;

	/* Look up the cell structure */
	if (!(cell = lookup_cell(cell_id)))
		return LLC_INVALID;
	subcell = lookup_subcell(cell_id, subcell_id);
	if (!subcell)
		return LLC_INVALID;

	/*
	 * Read only what we need under the lock to avoid putting the
	 * large cell struct on the stack (would exceed BPF stack limit).
	 */
	u32 llc_cpu_cnt[MAX_LLCS];
	u32 total_cpu_cnt;

	scoped_guard(spin_lock, &cell->lock)
	{
		for (u32 i = 0; i < MAX_LLCS; i++)
			llc_cpu_cnt[i] = subcell->llcs[i].cpu_cnt;

		total_cpu_cnt = subcell->cpu_cnt;
	}

	if (!total_cpu_cnt) {
		scx_bpf_error("pick_llc_for_task: cell %d subcell %d has no CPUs accounted yet",
			      cell_id, subcell_id);
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

static void zero_subcell_vtimes(struct subcell *subcell)
{
	if (enable_llc_awareness) {
		u32 llc_idx;
		bpf_for(llc_idx, 0, MAX_LLCS)
		{
			WRITE_ONCE(subcell->llcs[llc_idx].vtime_now, 0);
		}
	} else {
		WRITE_ONCE(subcell->llcs[FAKE_FLAT_SUBCELL_LLC].vtime_now, 0);
	}
}

/*
 * Detect and handle cross-LLC task migration.
 * Called from running() to check if task's assigned LLC differs
 * from the CPU's LLC (indicating work stealing occurred).
 *
 * Caller must ensure enable_llc_awareness is true.
 */
static inline int maybe_retag_stolen_task(struct task_struct *p, struct task_ctx *tctx,
					  struct cpu_ctx *cctx)
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
	 * to that of the new subcell+LLC DSQ.
	 */
	return update_task_cpumask(p, tctx);
}

/*
 * Work stealing:
 * Scan sibling subcell+LLC DSQs in the same subcell and steal the first queued
 * task if it can run on this CPU.
 * Returns:
 *  true == 1;  task was stolen
 *  false == 0; no tasks were stolen
 *  error <0;   error encountered
*/
static inline s32 try_stealing_work(u32 cell, u32 subcell_id, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_stealing_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct subcell *subcell = lookup_subcell(cell, subcell_id);
	if (!subcell)
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
		 * Skip if the subcell doesn't have CPUs in this LLC.
		 * This is racy with try_stealing_this_task, but we don't care -
		 * if the LLC actually doesn't have CPUs come steal time,
		 * we will fail the steal and continue to the next LLC.
		 */
		if (READ_ONCE(subcell->llcs[candidate_llc].cpu_cnt) == 0)
			continue;

		dsq_id_t candidate_dsq = get_subcell_llc_dsq_id(cell, subcell_id, candidate_llc);
		if (dsq_is_invalid(candidate_dsq))
			return -EINVAL; // already errored in get_subcell_llc_dsq_id

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
		if (!scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0))
			continue;

		// Success, we got a task
		return true;
	}
	return false;
}

static inline int update_task_llc_assignment(struct task_struct *p, struct task_ctx *tctx)
{
	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	const struct cpumask *llc_mask = NULL;

	// Let's get a new LLC for this task
	s32 new_llc = pick_llc_for_task(tctx->cell, 0);
	if (new_llc < 0)
		return -EINVAL;

	tctx->llc = new_llc;
	llc_mask = lookup_llc_cpumask((u32)tctx->llc);
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
	tctx->dsq = get_subcell_llc_dsq_id(tctx->cell, 0, tctx->llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	struct subcell *subcell = lookup_subcell(tctx->cell, 0);
	if (!subcell)
		return -ENOENT;

	p->scx.dsq_vtime = READ_ONCE(subcell->llcs[new_llc].vtime_now);
	return 0;
}
