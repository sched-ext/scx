/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding L3 cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-L3 domain mappings. It provides code to
 * recalculate per-L3 CPU counts within cells and implements weighted
 * random L3 selection for tasks. It also tracks work-stealing
 * statistics for cross-L3 task migrations.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 l3_id_t;
#define L3_INVALID ((l3_id_t) ~0u)

// Configure how aggressively we steal work.
// When task is detected as a steal candidate, skip it this many times
// On a web server workload, 100 reduced steal count by ~90%
#ifdef MITOSIS_ENABLE_STEALING
#define PREVENT_N_STEALS 0
#endif

/* Work stealing statistics map - accessible from both BPF and userspace */
struct steal_stats_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
};

// A CPU -> L3 cache ID map
struct cpu_to_l3_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CPUS);
};

struct l3_to_cpus_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cpumask);
	__uint(max_entries, MAX_L3S);
};

extern struct cpu_to_l3_map cpu_to_l3;
extern struct l3_to_cpus_map l3_to_cpus;
extern struct steal_stats_map steal_stats;

static inline const bool l3_is_valid(u32 l3_id) {
	if (l3_id == L3_INVALID)
		return false;

	return (l3_id >= 0) && (l3_id < MAX_L3S);
}

static inline void init_task_l3(struct task_ctx *tctx) {
	tctx->l3 = L3_INVALID;

#if MITOSIS_ENABLE_STEALING
	tctx->pending_l3 = L3_INVALID;
	tctx->steal_count = 0;
	tctx->last_stolen_at = 0;
	tctx->steals_prevented = 0;
#endif

}

static inline const struct cpumask *lookup_l3_cpumask(u32 l3)
{
	struct cpumask *mask;

	if (!(mask = bpf_map_lookup_elem(&l3_to_cpus, &l3))) {
		scx_bpf_error("no l3 cpumask, l3: %d, %p", l3, &l3_to_cpus);
		return NULL;
	}

	return mask;
}

/* Recompute cell->l3_cpu_cnt[] after cell cpumask changes */
static __always_inline void recalc_cell_l3_counts(u32 cell_idx)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell)
		return;

	struct bpf_cpumask *tmp = bpf_cpumask_create();
	if (!tmp)
		return;

	u32 l3, present = 0, total_cpus = 0;

	bpf_rcu_read_lock();
	const struct cpumask *cell_mask =
		lookup_cell_cpumask(cell_idx); // RCU ptr
	if (!cell_mask) {
		bpf_rcu_read_unlock();
		bpf_cpumask_release(tmp);
		return;
	}

	bpf_for(l3, 0, nr_l3)
	{
		const struct cpumask *l3_mask =
			lookup_l3_cpumask(l3); // plain map memory
		if (!l3_mask) {
			cell->l3_cpu_cnt[l3] = 0;
			continue;
		}

		bpf_cpumask_and(tmp, cell_mask, l3_mask);

		u32 cnt = bpf_cpumask_weight((const struct cpumask *)tmp);
		cell->l3_cpu_cnt[l3] = cnt;
		total_cpus += cnt;
		if (cnt)
			present++;
	}
	bpf_rcu_read_unlock();

	cell->l3_present_cnt = present;
	cell->cpu_cnt = total_cpus;
	bpf_cpumask_release(tmp);
}

/**
 * Weighted random selection of an L3 cache domain for a task.
 *
 * Uses the CPU count in each L3 domain within the cell as weights to
 * probabilistically select an L3. L3 domains with more CPUs in the cell
 * have higher probability of being selected.
 *
 * @cell_id: The cell ID to select an L3 from
 * @return: L3 ID on success, L3_INVALID on error
 */
static inline s32 pick_l3_for_task(u32 cell_id)
{
	struct cell *cell;
	u32 l3, target, cur = 0;
	s32 ret = L3_INVALID;

	/* Look up the cell structure */
	if (!(cell = lookup_cell(cell_id)))
		return L3_INVALID;

	/* Handle case where cell has no CPUs assigned yet */
	if (!cell->cpu_cnt) {
		scx_bpf_error(
			"pick_l3_for_task: cell %d has no CPUs accounted yet",
			cell_id);
		return L3_INVALID;
	}

	/* Generate random target value in range [0, cpu_cnt) */
	target = bpf_get_prandom_u32() % cell->cpu_cnt;

	/* Find the L3 domain corresponding to the target value using
	 * weighted selection - accumulate CPU counts until we exceed target */
	bpf_for(l3, 0, nr_l3)
	{
		cur += cell->l3_cpu_cnt[l3];
		if (target < cur) {
			ret = (s32)l3;
			break;
		}
	}
	return ret;
}

#ifdef MITOSIS_ENABLE_STEALING

static inline bool try_stealing_this_task(struct task_ctx *task_ctx,
					  s32 local_l3, u64 candidate_dsq)
{
	// Attempt the steal, can fail beacuse it's a race.
	if (!scx_bpf_dsq_move_to_local(candidate_dsq))
		return false;

	// We got the task!
	task_ctx->steal_count++;
	task_ctx->last_stolen_at = scx_bpf_now();
	/* Retag to thief L3 (the one for this cpu) */
	task_ctx->pending_l3 = local_l3;
	task_ctx->steals_prevented = 0;

	/* Increment steal counter in map */
	u32 key = 0;
	u64 *count = bpf_map_lookup_elem(&steal_stats, &key);
	// NOTE: This could get expensive, but I'm not anticipating that many steals. Percpu if we care.
	if (count)
		__sync_fetch_and_add(count, 1);

	return true;
}

/* Work stealing:
 * Scan sibling (cell,L3) DSQs in the same cell and steal the first queued task if it can run on this cpu
*/
static inline bool try_stealing_work(u32 cell, s32 local_l3)
{
	if (!l3_is_valid(local_l3))
		scx_bpf_error("try_stealing_work: invalid local_l3");

	struct cell *cell_ptr = lookup_cell(cell);
	if (!cell_ptr)
		scx_bpf_error("try_stealing_work: invalid cell");

	// Loop over all other L3s, looking for a queued task to steal
	u32 i;
	bpf_for(i, 1, nr_l3)
	{
		// Start with the next one to spread out the load
		u32 candidate_l3 = (local_l3 + i) % nr_l3;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read wil be safe
		barrier_var(candidate_l3);

		if (candidate_l3 >= MAX_L3S)
			continue;

		// Skip L3s that are not present in this cell
		// Note: rechecking cell_ptr for verifier
		if (cell_ptr && cell_ptr->l3_cpu_cnt[candidate_l3] == 0)
			continue;

		u64 candidate_dsq = get_cell_l3_dsq_id(cell, candidate_l3).raw;

		struct task_struct *task = NULL;
		struct task_ctx *task_ctx;
		// I'm only using this for the verifier
		bool found_task = false;

		// Optimization: skip if faster than constructing an iterator
		// Not redundant with later checking if task found (race)
		if (scx_bpf_dsq_nr_queued(candidate_dsq))
			continue;

		// Just a trick for peeking the head element
		bpf_for_each(scx_dsq, task, candidate_dsq, 0)
		{
	 		task_ctx = lookup_task_ctx(task);
			found_task = (task_ctx != NULL);
			break;
		}

		// No task? Try next L3
		if (!found_task)
			continue;

		// This knob throttles stealing.
		// TODO: make runtime configurable
		if (task_ctx->steals_prevented++ < PREVENT_N_STEALS) {
			continue;
		}

		if (!try_stealing_this_task(task_ctx, local_l3, candidate_dsq))
			continue;

		// Success, we got a task (no guarantee it was the one we peeked though... race)
		return true;
	}
	return false;
}
#endif
