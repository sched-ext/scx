/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-LLC domain mappings. It provides code to
 * recalculate per-LLC CPU counts within cells and implements weighted
 * random LLC selection for tasks.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

// A CPU -> LLC cache ID map
struct cpu_to_llc_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CPUS);
};

struct llc_to_cpus_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cpumask);
	__uint(max_entries, MAX_LLCS);
};

extern struct cpu_to_llc_map  cpu_to_llc;
extern struct llc_to_cpus_map llc_to_cpus;

static inline bool	      llc_is_valid(u32 llc_id)
{
	if (llc_id == LLC_INVALID)
		return false;

	return llc_id < MAX_LLCS;
}

static inline void init_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;
}

static inline const struct cpumask *lookup_llc_cpumask(u32 llc)
{
	struct cpumask *mask;

	if (!(mask = bpf_map_lookup_elem(&llc_to_cpus, &llc))) {
		scx_bpf_error("no llc cpumask, llc: %d, %p", llc, &llc_to_cpus);
		return NULL;
	}

	return mask;
}

/* Recompute cell->llc_cpu_cnt[] after cell cpumask changes */
static __always_inline void recalc_cell_llc_counts(u32 cell_idx)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell) {
		scx_bpf_error("recalc_cell_llc_counts: invalid cell %d",
			      cell_idx);
		return;
	}

	CPUMASK_GUARD(tmp_guard);
	if (!tmp_guard.mask) {
		scx_bpf_error(
			"recalc_cell_llc_counts: failed to create tmp mask");
		return;
	}

	u32 llc, llcs_present = 0, total_cpus = 0;
	// Just so we don't hold the lock longer than necessary
	u32 llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

	{ // RCU context
		RCU_READ_GUARD();
		const struct cpumask *cell_mask =
			lookup_cell_cpumask(cell_idx); // RCU ptr

		if (!cell_mask) {
			scx_bpf_error(
				"recalc_cell_llc_counts: invalid cell mask");
			return;
		}

		bpf_for(llc, 0, nr_llc)
		{
			const struct cpumask *llc_mask =
				lookup_llc_cpumask(llc);
			if (!llc_mask) {
				scx_bpf_error(
					"recalc_cell_llc_counts: invalid llc mask");
				return;
			}

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
	} // unlock RCU

	// Write to cell
	bpf_spin_lock(&cell->lock);
	for (u32 llc_idx = 0; llc_idx < nr_llc; llc_idx++) {
		cell->llc_cpu_cnt[llc_idx] = llc_cpu_cnt_tmp[llc_idx];
	}

	cell->llc_present_cnt = llcs_present;
	cell->cpu_cnt	      = total_cpus;
	bpf_spin_unlock(&cell->lock);
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
	if (!(cell = lookup_cell(cell_id))) {
		scx_bpf_error("pick_llc_for_task: invalid cell %d", cell_id);
		return LLC_INVALID;
	}

	// Snapshot the current state of the cell
	struct cell cell_snapshot;
	bpf_spin_lock(&cell->lock);
	copy_cell_skip_lock(&cell_snapshot, cell);
	bpf_spin_unlock(&cell->lock);

	// No cpus
	if (!cell_snapshot.cpu_cnt) {
		scx_bpf_error(
			"pick_llc_for_task: cell %d has no CPUs accounted yet",
			cell_id);
		return LLC_INVALID;
	}

	/* Find the LLC domain corresponding to the target value using
	 * weighted selection - accumulate CPU counts until we exceed target */

	/* Generate random target value in range [0, cpu_cnt) */
	u32 target = bpf_get_prandom_u32() % cell_snapshot.cpu_cnt;
	u32 llc, cur = 0;
	s32 ret = LLC_INVALID;

	// This could be a prefix sum. Find first llc where we exceed target
	bpf_for(llc, 0, nr_llc)
	{
		cur += cell_snapshot.llc_cpu_cnt[llc];
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

static inline int update_task_llc_assignment(struct task_struct *p,
					     struct task_ctx	*tctx,
					     struct cell	*cell)
{
	const struct cpumask *cell_cpumask = lookup_cell_cpumask(tctx->cell);
	const struct cpumask *llc_mask	   = NULL;
	if (tctx->llc != LLC_INVALID) {
		llc_mask = lookup_llc_cpumask((u32)tctx->llc);
		/* If the LLC no longer intersects the cell's cpumask, invalidate it */
		if (!llc_mask ||
		    !bpf_cpumask_intersects(cell_cpumask, llc_mask))
			tctx->llc = LLC_INVALID;
	}

	/* --- Pick a new LLC if needed --- */
	if (tctx->llc == LLC_INVALID) {
		s32 new_llc = pick_llc_for_task(tctx->cell);
		if (new_llc < 0) {
			scx_bpf_error("bad LLC: %d", new_llc);
			return -ENODEV;
		}
		tctx->llc = new_llc;
		llc_mask  = lookup_llc_cpumask((u32)tctx->llc);
		if (!llc_mask)
			return -ENOENT;
	}

	/* --- Narrow the effective cpumask by the chosen LLC --- */
	/* tctx->cpumask already contains (task_affinity & cell_mask) */
	bpf_cpumask_and(tctx->cpumask, (const struct cpumask *)tctx->cpumask,
			llc_mask);

	/* If empty after intersection, nothing can run here */
	if (bpf_cpumask_empty((const struct cpumask *)tctx->cpumask)) {
		scx_bpf_error("Empty cpumask after intersection");
		return -ENODEV;
	}

	/* --- Point to the correct (cell,LLC) DSQ and set vtime baseline --- */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, tctx->llc);

	if (!cell) {
		scx_bpf_error("Invalid cell");
		return -ENOENT;
	}

	if (!llc_is_valid(tctx->llc)) {
		scx_bpf_error("Invalid LLC %d", tctx->llc);
		return -EINVAL;
	}

	p->scx.dsq_vtime = READ_ONCE(cell->llc_vtime_now[tctx->llc]);
	return 0;
}
