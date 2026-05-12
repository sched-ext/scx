/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * Cell cpumask management for scx_mitosis.
 *
 * The scheduler publishes cell-owned cpumasks through kptr-backed map slots.
 * Each slot is double-buffered:
 * - cpumask: currently published mask visible to readers
 * - tmp_cpumask: scratch mask used to build the next generation
 *
 * Writers prepare updates in tmp_cpumask and only swap the fully prepared mask
 * into cpumask at publication time. This avoids mutating the published mask in
 * place and lets readers observe only complete generations.
 *
 * Published cpumasks are treated as scheduler invariants once initialized.
 * Lookup helpers are therefore strict by default and use scx_bpf_error() when
 * the invariant is violated. Other helpers return errors and let callers use
 * their discretion in handling failures or making them fatal.
 */

#pragma once

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"
#include <lib/cleanup.bpf.h>

/*
 * One publishable cell cpumask slot.
 *
 * @cpumask is the currently visible mask.
 * @tmp_cpumask is the reusable scratch buffer used to prepare the next mask.
 */
struct cell_cpumask_pair {
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *tmp_cpumask;
};

/*
 * Cell cpumask state.
 *
 * @primary describes CPUs owned by the cell.
 * @borrowable describes CPUs the cell may borrow from other cells.
 */
struct cell_cpumask_wrapper {
	struct cell_cpumask_pair primary;
	struct cell_cpumask_pair borrowable;
};

struct cell_cpumask_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell_cpumask_wrapper);
	__uint(max_entries, MAX_CELLS);
	__uint(map_flags, 0);
};

struct subcell_cpumask_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell_cpumask_wrapper);
	__uint(max_entries, MAX_CELLS * MAX_SUBCELLS_PER_CELL);
	__uint(map_flags, 0);
};

extern struct cell_cpumask_map cell_cpumasks;
extern struct subcell_cpumask_map subcell_cpumasks;
extern const volatile u32 nr_possible_cpus;

/* Strict lookup of the per-cell cpumask pair group stored in the cell_cpumasks map. */
static inline struct cell_cpumask_wrapper *lookup_cell_cpumask_wrapper(int idx)
{
	struct cell_cpumask_wrapper *cpumaskw;

	cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &idx);
	if (!cpumaskw)
		scx_bpf_error("no cell cpumask wrapper for cell %d", idx);

	return cpumaskw;
}

/* Get the currently published primary cpumask for a cell. */
static inline const struct cpumask *lookup_cell_cpumask(int idx)
{
	struct cell_cpumask_wrapper *cpumaskw;
	const struct cpumask *cpumask;

	cpumaskw = lookup_cell_cpumask_wrapper(idx);
	if (!cpumaskw)
		return NULL;

	cpumask = (const struct cpumask *)cpumaskw->primary.cpumask;
	if (!cpumask)
		scx_bpf_error("cell cpumask is NULL for cell %d", idx);

	return cpumask;
}

/* Get the currently published borrowable cpumask for a cell. */
static inline const struct cpumask *lookup_cell_borrowable_cpumask(int idx)
{
	struct cell_cpumask_wrapper *cpumaskw;
	const struct cpumask *cpumask;

	cpumaskw = lookup_cell_cpumask_wrapper(idx);
	if (!cpumaskw)
		return NULL;

	cpumask = (const struct cpumask *)cpumaskw->borrowable.cpumask;
	if (!cpumask)
		scx_bpf_error("borrowable cpumask is NULL for cell %d", idx);

	return cpumask;
}

static inline int subcell_cpumask_idx(u32 cell_id, u32 subcell_id)
{
	if (cell_id >= MAX_CELLS || subcell_id >= MAX_SUBCELLS_PER_CELL)
		return -EINVAL;
	return (cell_id * MAX_SUBCELLS_PER_CELL) + subcell_id;
}

static inline struct cell_cpumask_wrapper *lookup_subcell_cpumask_wrapper(u32 cell_id,
									  u32 subcell_id)
{
	int idx;
	u32 key;
	struct cell_cpumask_wrapper *cpumaskw;

	idx = subcell_cpumask_idx(cell_id, subcell_id);
	if (idx < 0) {
		scx_bpf_error("invalid subcell cpumask index cell=%u subcell=%u", cell_id,
			      subcell_id);
		return NULL;
	}

	key = idx;
	cpumaskw = bpf_map_lookup_elem(&subcell_cpumasks, &key);
	if (!cpumaskw)
		scx_bpf_error("no subcell cpumask wrapper for cell=%u subcell=%u", cell_id,
			      subcell_id);

	return cpumaskw;
}

static inline const struct cpumask *lookup_subcell_cpumask(u32 cell_id, u32 subcell_id)
{
	struct cell_cpumask_wrapper *cpumaskw;
	const struct cpumask *cpumask;

	cpumaskw = lookup_subcell_cpumask_wrapper(cell_id, subcell_id);
	if (!cpumaskw)
		return NULL;

	cpumask = (const struct cpumask *)cpumaskw->primary.cpumask;
	if (!cpumask)
		scx_bpf_error("subcell cpumask is NULL for cell=%u subcell=%u", cell_id,
			      subcell_id);

	return cpumask;
}

static inline const struct cpumask *lookup_subcell_borrowable_cpumask(u32 cell_id, u32 subcell_id)
{
	struct cell_cpumask_wrapper *cpumaskw;
	const struct cpumask *cpumask;

	cpumaskw = lookup_subcell_cpumask_wrapper(cell_id, subcell_id);
	if (!cpumaskw)
		return NULL;

	cpumask = (const struct cpumask *)cpumaskw->borrowable.cpumask;
	if (!cpumask)
		scx_bpf_error("subcell borrowable cpumask is NULL for cell=%u subcell=%u", cell_id,
			      subcell_id);

	return cpumask;
}

/* Return whether @cpu is set in serialized cell_cpumask_data. */
static inline int cell_cpumask_data_test_cpu(const struct cell_cpumask_data *data, u32 cpu,
					     bool *setp)
{
	u32 byte_idx = cpu / 8;
	u32 bit_idx = cpu % 8;
	const unsigned char *bytep;

	bytep = MEMBER_VPTR(data->mask, [byte_idx]);
	if (!bytep)
		return -EINVAL;

	*setp = *bytep & (1 << bit_idx);
	return 0;
}

/* Copy serialized cell_cpumask_data into the destination bpf_cpumask. */
static inline int build_cpumask_from_data(struct bpf_cpumask *dst,
					  const struct cell_cpumask_data *data)
{
	u32 cpu;

	bpf_cpumask_clear(dst);

	bpf_for(cpu, 0, nr_possible_cpus)
	{
		bool set;

		if (cell_cpumask_data_test_cpu(data, cpu, &set))
			return -EINVAL;

		if (set)
			bpf_cpumask_set_cpu(cpu, dst);
	}

	return 0;
}

/*
 * Remove and return the scratch cpumask for a pair.
 *
 * Ownership transfers to the caller. The intended usage is to bind the result
 * to a local `__free(bpf_cpumask)` variable, prepare the new contents there,
 * and then hand that owned variable to publish_prepared_cpumask().
 */
static inline struct bpf_cpumask *get_tmp_cpumask(struct cell_cpumask_pair *slot)
{
	return bpf_kptr_xchg(&slot->tmp_cpumask, NULL);
}

/*
 * Publish a fully prepared mask into a pair.
 *
 * @next_cpumaskp must point to an owned cpumask variable, typically declared
 * as `struct bpf_cpumask *next_cpumask __free(bpf_cpumask)`.
 *
 * This helper transfers ownership out of the caller's variable using
 * no_free_ptr(*next_cpumaskp), so on return the caller's variable is NULL.
 * The previously published mask is recycled back into tmp_cpumask for reuse.
 */
static inline int publish_prepared_cpumask(struct cell_cpumask_pair *slot,
					   struct bpf_cpumask **next_cpumaskp)
{
	struct bpf_cpumask *prev_cpumask;
	struct bpf_cpumask *stale __free(bpf_cpumask) = NULL;

	prev_cpumask = bpf_kptr_xchg(&slot->cpumask, no_free_ptr(*next_cpumaskp));
	if (!prev_cpumask)
		return -EINVAL;

	stale = bpf_kptr_xchg(&slot->tmp_cpumask, prev_cpumask);
	if (stale)
		return -EINVAL;

	return 0;
}

/*
 * Build and publish a pair from serialized cell_cpumask_data.
 *
 * This is the common path used by userspace-managed reconfiguration code once
 * the caller has decided which pair to update.
 */
static inline int set_cpumask_from_data(struct cell_cpumask_pair *slot,
					const struct cell_cpumask_data *data)
{
	struct bpf_cpumask *next_cpumask __free(bpf_cpumask) = get_tmp_cpumask(slot);

	if (!next_cpumask)
		return -EINVAL;
	if (build_cpumask_from_data(next_cpumask, data))
		return -EINVAL;
	if (publish_prepared_cpumask(slot, &next_cpumask))
		return -EINVAL;
	return 0;
}

/*
 * Initialize a slot during scheduler setup.
 *
 * set_all=true publishes a full mask initially.
 * set_all=false publishes an empty mask initially.
 */
static inline int init_cpumask_slot(struct cell_cpumask_pair *slot, bool set_all)
{
	struct bpf_cpumask *cpumask __free(bpf_cpumask) = NULL;
	struct bpf_cpumask *tmp_cpumask __free(bpf_cpumask) = NULL;
	struct bpf_cpumask *stale __free(bpf_cpumask) = NULL;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	tmp_cpumask = bpf_cpumask_create();
	if (!tmp_cpumask)
		return -ENOMEM;

	if (set_all)
		bpf_cpumask_setall(cpumask);
	else
		bpf_cpumask_clear(cpumask);

	stale = bpf_kptr_xchg(&slot->cpumask, no_free_ptr(cpumask));
	if (stale)
		return -EINVAL;

	stale = bpf_kptr_xchg(&slot->tmp_cpumask, no_free_ptr(tmp_cpumask));
	if (stale)
		return -EINVAL;

	return 0;
}
