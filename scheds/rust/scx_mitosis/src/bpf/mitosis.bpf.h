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
#endif

#include "intf.h"
#include "dsq.bpf.h"
#include "cleanup.bpf.h"

extern const volatile u32 nr_llc;

extern struct cell_map	  cells;

enum mitosis_constants {

	/* Root cell index */
	ROOT_CELL_ID = 0,

	/* No NUMA constraint for DSQ creation */
	ANY_NUMA = -1,
};

/*
 * Variables populated by userspace
 */
const volatile bool	   enable_llc_awareness = false;
const volatile bool	   enable_work_stealing = false;
const volatile u32	   nr_llc		= 1;

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

/*
 * task_ctx is the per-task information kept by scx_mitosis
 */
struct task_ctx {
	/* cpumask is the set of valid cpus this task can schedule on */
	/* (task's cpumask and-ed with its cell cpumask) */
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
	/* Last known cgroup ID for detecting cgroup moves (used when cpu_controller_disabled) */
	u64 cgid;
	/* Which LLC this task is assigned to */
	s32 llc;

	u32 steal_count; /* how many times this task has been stolen */
	u64 last_stolen_at; /* ns timestamp of the last steal (scx_bpf_now) */
};

static inline const struct cpumask *lookup_cell_cpumask(int idx);
static inline struct task_ctx	   *lookup_task_ctx(struct task_struct *p);

struct cell_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell);
	__uint(max_entries, MAX_CELLS);
};

static inline int update_task_cpumask(struct task_struct *p,
				      struct task_ctx	 *tctx);
