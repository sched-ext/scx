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

#define MAX_L3S 16

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

struct cell {
	// Whether or not the cell is used or not
	u32 in_use;
	// Number of CPUs in this cell
	u32 cpu_cnt;
	// per-L3 vtimes within this cell
	u64 l3_vtime_now[MAX_L3S];
	// Number of CPUs from each L3 assigned to this cell
	u32 l3_cpu_cnt[MAX_L3S];
	// Number of L3s with at least one CPU in this cell
	u32 l3_present_cnt;

  // TODO XXX remove this, only here temporarily to make the code compile
  // current vtime of the cell
	u64 vtime_now;
};

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
	u64 dsq;
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
static inline struct cell *lookup_cell(int idx);
static inline const struct cpumask *lookup_cell_cpumask(int idx);

static inline struct task_ctx *lookup_task_ctx(struct task_struct *p);

/* MAP TYPES */
struct function_counters_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NR_COUNTERS);
};

// static __always_inline void task_release_cleanup(struct task_struct **pp)
// {
// 	if (*pp)
// 		bpf_task_release(*pp);
// }

// #define SCOPED_TASK __attribute__((cleanup(task_release_cleanup)))

// __always_inline struct task_struct * dsq_head_peek(u64 dsq_id, task_struct *p)
// {
// 	bpf_rcu_read_lock();
// 	struct task_struct *p = NULL;
// 	bpf_for_each(scx_dsq, p, dsq_id, 0) {
// 		bpf_task_acquire(p); /* extend lifetime beyond loop */
// 		break;               /* only want the head */
// 	}
// 	bpf_rcu_read_unlock();

// 	return p;
// }

// static __always_inline struct task_struct *
// dsq_head_peek(u64 dsq_id)
// {
// 	struct bpf_iter_scx_dsq it = {};
// 	struct task_struct *p;

// 	if (bpf_iter_scx_dsq_new(&it, dsq_id, 0))
// 		return NULL;

// 	/* First element in dispatch order is the head. */
// 	p = bpf_iter_scx_dsq_next(&it);

// 	/* Take a ref so the pointer remains valid after we destroy the iter. */
// 	if (p)
// 		bpf_task_acquire(p);

// 	bpf_iter_scx_dsq_destroy(&it);
// 	return p; /* caller must bpf_task_release(p) when done */
// }
