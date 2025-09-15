/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header adds L3 cache awareness to scx_mitosis by defining BPF
 * maps for CPU-to-L3 domain mappings. It provides functions to
 * recalculate per-L3 CPU counts within cells and implements weighted
 * random L3 selection for tasks. It also tracks work-stealing
 * statistics for cross-L3 task migrations.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

// It's also an option to just compute this from the cpu_to_l3 map.
struct l3_cpu_mask {
	unsigned long cpumask[CPUMASK_LONG_ENTRIES];
};

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
	__type(value, struct l3_cpu_mask);
	__uint(max_entries, MAX_L3S);
};

extern struct cpu_to_l3_map cpu_to_l3 SEC(".maps");
extern struct l3_to_cpus_map l3_to_cpus SEC(".maps");
extern struct steal_stats_map steal_stats SEC(".maps");

static inline const struct cpumask *lookup_l3_cpumask(u32 l3)
{
	struct l3_cpu_mask *mask;

	if (!(mask = bpf_map_lookup_elem(&l3_to_cpus, &l3))) {
		scx_bpf_error("no l3 cpumask, l3: %d, %p", l3, &l3_to_cpus);
		return NULL;
	}

	return (const struct cpumask *)mask;
}

/* Recompute cell->l3_cpu_cnt[] after cell cpumask changes (no persistent kptrs). */
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

		/* ok: dst is bpf_cpumask*, sources are (RCU cpumask*, plain cpumask*) */
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
 * @return: L3 ID on success, INVALID_L3_ID on error, or 0 as fallback
 */
static inline s32 pick_l3_for_task(u32 cell_id)
{
	struct cell *cell;
	u32 l3, target, cur = 0;
	s32 ret = INVALID_L3_ID;

	/* Look up the cell structure */
	if (!(cell = lookup_cell(cell_id)))
		return INVALID_L3_ID;

	/* Handle case where cell has no CPUs assigned yet */
	if (!cell->cpu_cnt) {
		scx_bpf_error(
			"pick_l3_for_task: cell %d has no CPUs accounted yet",
			cell_id);
		return INVALID_L3_ID;
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
