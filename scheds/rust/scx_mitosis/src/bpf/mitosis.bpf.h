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

extern const volatile u32 nr_l3;

/*
 * We don't know how big struct cpumask is at compile time, so just allocate a
 * large space and check that it is big enough at runtime
 */
#define CPUMASK_LONG_ENTRIES (128)
#define CPUMASK_SIZE (sizeof(long) * CPUMASK_LONG_ENTRIES)

enum mitosis_constants {
	/* Invalid/unset L3 value */
	INVALID_L3_ID = -1,
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
	u32 dsq;
	/* latest configuration that was applied for this task */
	/* (to know if it has to be re-applied) */
	u32 configuration_seq;
	/* Is this task allowed on all cores of its cell? */
	bool all_cell_cpus_allowed;

#if MITOSIS_ENABLE_STEALING
	/* When a task is stolen, dispatch() marks the destination L3 here.
	 * running() applies the retag and recomputes cpumask (vtime preserved).
	*/
	s32 pending_l3;
	u32 steal_count; /* how many times this task has been stolen */
	u64 last_stolen_at; /* ns timestamp of the last steal (scx_bpf_now) */
#endif
};

// These could go in mitosis.bpf.h, but we'll cross that bridge when we get
static inline struct cell *lookup_cell(int idx);
static inline const struct cpumask *lookup_cell_cpumask(int idx);
