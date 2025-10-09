/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This defines the core data structures, types, and constants
 * for the scx_mitosis scheduler, primarily containing `struct cell`
 * and `struct task_ctx`.
 */

#pragma once

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#endif

#include "intf.h"
#include "dsq.bpf.h"

/*
 * A couple of tricky things about checking a cgroup's cpumask:
 *
 * First, we need an RCU pointer to pass to cpumask kfuncs. The only way to get
 * this right now is to copy the cpumask to a map entry. Given that cgroup init
 * could be re-entrant we have a few per-cpu entries in a map to make this
 * doable.
 *
 * Second, cpumask can sometimes be stored as an array in-situ or as a pointer
 * and with different lengths. Some bpf_core_type_matches finagling can make
 * this all work.
 */
#define MAX_CPUMASK_ENTRIES (4)

/*
 * We don't know how big struct cpumask is at compile time, so just allocate a
 * large space and check that it is big enough at runtime
 * TODO: This should be deduplicated with the rust code and put in intf.h
 */
#define CPUMASK_LONG_ENTRIES (128)
#define CPUMASK_SIZE (sizeof(long) * CPUMASK_LONG_ENTRIES)

extern const volatile u32 nr_l3;

extern struct cell_map cells;

enum mitosis_constants {

	/* Root cell index */
	ROOT_CELL_ID = 0,

	/* Invalid/unset L3 value */
	// INVALID_L3_ID = -1,

	/* Default weight divisor for vtime calculation */
	DEFAULT_WEIGHT_MULTIPLIER = 100,

	/* Vtime validation multiplier (slice_ns * 8192) */
	VTIME_MAX_FUTURE_MULTIPLIER = 8192,

	/* Bits per u32 for cpumask operations */
	BITS_PER_U32 = 32,

	/* No NUMA constraint for DSQ creation */
	ANY_NUMA = -1,
};

static inline void copy_cell_skip_lock(struct cell *dst, const struct cell *src)
{
	/* Copy everything AFTER the lock field.
	 * Since lock is first and 4 bytes (verified by static assertions),
	 * we skip it and copy the remainder of the struct.
	 */
	__builtin_memcpy(&dst->in_use,
	                 &src->in_use,
	                 sizeof(struct cell) - sizeof(CELL_LOCK_T));
}

static inline struct cell *lookup_cell(int idx)
{
	struct cell *cell;

	cell = bpf_map_lookup_elem(&cells, &idx);

	if (!cell) {
		scx_bpf_error("Invalid cell %d", idx);
		return NULL;
	}
	return cell;
}

static inline struct bpf_spin_lock *get_cell_lock(u32 cell_idx)
{
	if (cell_idx >= MAX_CELLS) {
		scx_bpf_error("Invalid cell index %d", cell_idx);
		return NULL;
	}

	struct cell *cell = lookup_cell(cell_idx);
	if (!cell) {
		scx_bpf_error("Cell %d not found", cell_idx);
		return NULL;
	}
	return &cell->lock;
}

/*
 * task_ctx is the per-task information kept by scx_mitosis
 */
struct task_ctx {
	/* cpumask is the set of valid cpus this task can schedule on */
	/* (tasks cpumask anded with its cell cpumask) */
	struct bpf_cpumask __kptr *cpumask;
	/* started_running_at for recording runtime */
	u64 started_running_at;
	u64 basis_vtime;
	/* For the sake of monitoring, each task is owned by a cell */
	u32 cell;
	/* For the sake of scheduling, a task is exclusively owned by either a cell
	 * or a cpu */
	dsq_id_t dsq;
	/* latest configuration that was applied for this task */
	/* (to know if it has to be re-applied) */
	u32 configuration_seq;
	/* Is this task allowed on all cores of its cell? */
	bool all_cell_cpus_allowed;
	// Which L3 this task is assigned to
	s32 l3;

#if MITOSIS_ENABLE_STEALING
	/* When a task is stolen, dispatch() marks the destination L3 here.
	 * running() applies the retag and recomputes cpumask (vtime preserved).
	*/
	s32 pending_l3;
	u32 steal_count; /* how many times this task has been stolen */
	u64 last_stolen_at; /* ns timestamp of the last steal (scx_bpf_now) */
	u32 steals_prevented; /* how many times this task has been prevented from being stolen */
#endif
};

// These could go in mitosis.bpf.h, but we'll cross that bridge when we get
static inline const struct cpumask *lookup_cell_cpumask(int idx);

static inline struct task_ctx *lookup_task_ctx(struct task_struct *p);

/* MAP TYPES */
struct function_counters_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NR_COUNTERS);
};

struct cell_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell);
	__uint(max_entries, MAX_CELLS);
};

struct rcu_read_guard {
	bool active;
};

static inline struct rcu_read_guard rcu_read_lock_guard(void) {
	bpf_rcu_read_lock();
	return (struct rcu_read_guard){.active = true};
}

static inline void rcu_read_guard_release(struct rcu_read_guard *guard) {
	if (guard->active) {
		bpf_rcu_read_unlock();
		guard->active = false;
	}
}
#define RCU_READ_GUARD() \
	struct rcu_read_guard __rcu_guard __attribute__((__cleanup__(rcu_read_guard_release))) = rcu_read_lock_guard()

struct cpumask_guard {
	struct bpf_cpumask *mask;
};

static inline struct cpumask_guard cpumask_create_guard(void) {
	struct bpf_cpumask *mask = bpf_cpumask_create();
	return (struct cpumask_guard){.mask = mask};
}

static inline void cpumask_guard_release(struct cpumask_guard *guard) {
	if (guard->mask) {
		bpf_cpumask_release(guard->mask);
		guard->mask = NULL;
	}
}

#define CPUMASK_GUARD(var_name) \
	struct cpumask_guard var_name __attribute__((__cleanup__(cpumask_guard_release))) = cpumask_create_guard()
