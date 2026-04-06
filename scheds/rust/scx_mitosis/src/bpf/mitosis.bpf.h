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
#include "cell_cpumask.bpf.h"
#include "dsq.bpf.h"
#include <lib/cleanup.bpf.h>

extern const volatile u32 nr_llc;

extern struct cell_map cells;

enum mitosis_constants {

	/* Root cell index */
	ROOT_CELL_ID = 0,

	/* No NUMA constraint for DSQ creation */
	ANY_NUMA = -1,
};

/*
 * Variables populated by userspace
 */
const volatile bool enable_llc_awareness = false;
const volatile bool enable_work_stealing = false;
const volatile u32 nr_llc = 1;

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
	/* Subcell within the task's cell. Defaults to subcell 0 for now. */
	u32 subcell;
	/* For the sake of scheduling, a task is exclusively owned by either a cell
	 * or a cpu */
	dsq_id_t dsq;
	/* latest configuration that was applied for this task */
	/* (to know if it has to be re-applied) */
	u32 configuration_seq;
	/* Is this task allowed on all cores of its cell? */
	bool all_cell_cpus_allowed;
	/* Set when task is dispatched to a borrowed CPU from another cell.
	 * Consumed and cleared in mitosis_stopping to avoid advancing the
	 * lending cell's per-CPU DSQ vtime with this task's execution.
	 */
	bool borrowed;
	/* Last known cgroup ID for detecting cgroup moves (used when cpu_controller_disabled) */
	u64 cgid;
	/* Which LLC this task is assigned to */
	s32 llc;

	u64 avg_runtime_ns; /* EWMA of per-wake runtimes (ns), init to 0 */

	u32 steal_count; /* how many times this task has been stolen */
	u64 last_stolen_at; /* ns timestamp of the last steal (scx_bpf_now) */
};

static inline struct task_ctx *lookup_task_ctx(struct task_struct *p);

/*
 * Smoothed average of a task's per-wake runtime (EWMA, alpha=1/8).
 * Updated in stopping() after each run. Starts at 0 and converges
 * over ~8 runs. Used by features like slice shrinking to estimate
 * how long a task typically runs.
 */
static inline void update_task_runtime_ewma(struct task_ctx *tctx, u64 used)
{
	if (unlikely(!tctx->avg_runtime_ns))
		/* Init */
		tctx->avg_runtime_ns = used;
	else
		tctx->avg_runtime_ns = (tctx->avg_runtime_ns * 7 + used) / 8;
}

extern const volatile bool use_lockless_peek;

/*
 * Peek at the head of a DSQ. Uses lockless kfunc when available,
 * otherwise falls back to bpf_for_each iterator.
 */
static inline struct task_struct *dsq_peek(u64 dsq_id)
{
	struct task_struct *p;

	if (use_lockless_peek)
		return __COMPAT_scx_bpf_dsq_peek(dsq_id);

	bpf_for_each(scx_dsq, p, dsq_id, 0)
		return p;
	return NULL;
}

static inline void cstat_add(enum cell_stat_idx idx, u32 cell, struct cpu_ctx *cctx, s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cctx, .cstats[cell][idx])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid cell or stat idxs: %d, %d", idx, cell);
}

static inline void cstat_inc(enum cell_stat_idx idx, u32 cell, struct cpu_ctx *cctx)
{
	cstat_add(idx, cell, cctx, 1);
}

struct cell_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell);
	__uint(max_entries, MAX_CELLS);
};

static inline int update_task_cpumask(struct task_struct *p, struct task_ctx *tctx);
