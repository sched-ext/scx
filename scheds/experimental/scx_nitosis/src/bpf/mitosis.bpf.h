/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This defines the core data structures, types, and constants
 * for the scx_nitosis scheduler, primarily containing `struct cell`
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
#include <lib/arena_map.h>
#include <lib/cleanup.bpf.h>
#include <lib/sdt_task.h>
#include <lib/topology.h>

extern struct cell __arena *cells;

/*
 * Force an arena map reference. The verifier associates a program with an arena
 * by finding an LD_IMM64 that loads the arena map. Programs that only
 * dereference arena pointers handed to them never emit one and get rejected at
 * the first addr_space_cast without this.
 */
#define MITOSIS_TOUCH_ARENA() do { asm volatile("" :: "r"(&arena)); } while (0)

enum mitosis_constants {

	/* Root cell index */
	ROOT_CELL_ID = 0,

	/* No NUMA constraint for DSQ creation */
	ANY_NUMA = -1,

	/* Bounded retries for idle claim scans, see pick_idle_cid_shards() */
	IDLE_PICK_RETRIES = 16,

	/* fixed backing size of one task cmask, capacity for MAX_CPUS cids */
	TASK_CMASK_SIZE = sizeof(struct scx_cmask) +
			  CMASK_NR_WORDS(MAX_CPUS) * sizeof(u64),
};

/*
 * Variables populated by userspace
 */
const volatile bool enable_llc_awareness = false;

/*
 * Cell vtimes live in the arena while the competing vtime sources are BPF map
 * values. Keep the arena access in a noinline helper so that clang cannot merge
 * loads from the two pointer classes into one instruction, which the verifier
 * rejects.
 */
static __noinline u64 cell_llc_vtime_read(struct cell __arena *cell, u32 llc)
{
	return READ_ONCE(cell->llcs[llc].vtime_now);
}

/*
 * Topology snapshot, taken once in ops.init() from the cid tables. cids are
 * dense and topology-ordered, so every topology unit is a contiguous [base,
 * base + nr) cid range.
 */
struct topo_range {
	s32 base;
	s32 nr;
};

struct mitosis_topo {
	u32 nr_cids;
	u32 nr_llcs;
	u32 nr_shards;
	struct scx_cid_topo cid[MAX_CPUS];
	/* cid range of each LLC */
	struct topo_range llc_cids[MAX_LLCS];
	/* shard index range of each LLC */
	struct topo_range llc_shards[MAX_LLCS];
	/* cid range of each shard */
	struct topo_range shard_cids[MAX_CPUS];
};

extern struct mitosis_topo __arena *topo;

/*
 * Idle state, maintained by ops.update_idle(). One base-windowed cmask per
 * shard for scalability. Shards are LLC-aligned and hold at most
 * SCX_CID_SHARD_MAX_CPUS cids. scx_cmask ends in a flex array, the overlay
 * gives the masks a fixed cacheline aligned stride for native indexing.
 */
union shard_cmask {
	struct scx_cmask cmask;
	u8 storage[sizeof(struct scx_cmask) +
		   CMASK_NR_WORDS(SCX_CID_SHARD_MAX_CPUS) * sizeof(u64)];
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

extern union shard_cmask __arena *idle_masks;

/* cids with load-time topology, offline-possible tail cids excluded */
extern struct scx_cmask __arena *topo_cids;

/* the cid-form analog of scx_bpf_test_and_clear_cpu_idle() */
static inline bool claim_idle_cid(s32 cid)
{
	return cmask_test_and_clear(cid, &idle_masks[topo->cid[cid].shard_idx].cmask);
}

/*
 * Per-cell cid masks. scx_cmask ends in a flex array, the overlay gives every
 * mask fixed MAX_CPUS capacity so that a configuration's masks form one
 * indexable generation.
 */
union cell_cmask {
	struct scx_cmask cmask;
	u8 storage[sizeof(struct scx_cmask) + CMASK_NR_WORDS(MAX_CPUS) * sizeof(u64)];
};

/*
 * One cell cmask generation. apply_cell_config() builds the complete array for
 * each configuration and publishes it in cell_masks with an xchg, freeing the
 * old one through scx_urcu behind a grace period, so a loaded generation is
 * always complete and stays valid until the end of the RCU section.
 */
struct cell_cmasks {
	union cell_cmask mask[MAX_CELLS];
	union cell_cmask borrowable[MAX_CELLS];
};

extern struct cell_cmasks __arena *cell_masks;

static inline struct cpu_ctx *lookup_cid_ctx(s32 cid);

/* in mitosis.bpf.c, shared with llc_aware.bpf.h */
static __always_inline s32 pick_idle_cid_shards(struct scx_cmask __arena *cand,
						u32 shard_base, u32 nr_shards, s32 prev_cid);

/*
 * task_ctx is the per-task information kept by scx_nitosis
 */
struct task_ctx {
	/* started_running_at for recording runtime */
	u64 started_running_at;
	/* Cell whose vtime domain should be charged for this task */
	u32 vtime_charge_cell;
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

	/*
	 * scx_cmask ends in a flex array, so a struct can hold at most one.
	 * Overlay them on fixed MAX_CPUS capacity storage so task_ctx can carry
	 * two as plain members.
	 */
	/* Task affinity in cid space, copied in ops.set_cmask() */
	union {
		struct scx_cmask allowed;
		u8 allowed_storage[TASK_CMASK_SIZE];
	};
	/* allowed AND cell, the mask scheduling decisions use */
	union {
		struct scx_cmask effective;
		u8 effective_storage[TASK_CMASK_SIZE];
	};
};

static inline struct task_ctx __arena *lookup_task_ctx(struct task_struct *p);
static inline struct cpu_ctx *lookup_cpu_ctx(int cpu);

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

static inline int update_task_cmask(struct task_struct *p, struct task_ctx __arena *tctx);
