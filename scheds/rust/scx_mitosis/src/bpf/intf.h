// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifdef __BINDGEN_RUNNING__
#include <stddef.h>
typedef unsigned long long u64;
typedef unsigned int	   u32;
typedef _Bool bool;
#endif

enum consts {
	CACHELINE_SIZE	      = 64,
	MAX_CPUS_SHIFT	      = 9,
	MAX_CPUS	      = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8	      = MAX_CPUS / 8,
	MAX_CELLS	      = 256,
	USAGE_HALF_LIFE	      = 100000000, /* 100ms */
	TIMER_INTERVAL_NS     = 100000000, /* 100 ms */
	CLOCK_BOOTTIME	      = 7,

	MAX_CG_DEPTH	      = 256,
	MAX_LLCS	      = 16,

	DEBUG_EVENTS_BUF_SIZE = 4096,

	/* Size of cpumask in unsigned longs (supports up to 8192 CPUs) */
	CPUMASK_LONG_ENTRIES = 128,
};

/*
 * LLC cpumask for topology arrays. This is a fixed-size structure that
 * matches the kernel's struct cpumask layout and can be used by both
 * BPF and userspace code.
 */
struct llc_cpumask {
	unsigned long bits[CPUMASK_LONG_ENTRIES];
};

/* Debug event types */
enum debug_event_type {
	DEBUG_EVENT_CGROUP_INIT,
	DEBUG_EVENT_INIT_TASK,
	DEBUG_EVENT_CGROUP_EXIT,
};

/* Debug event record - discriminated union */
struct debug_event {
	u64 timestamp;
	u32 event_type;
	union {
		struct {
			u64 cgid;
		} cgroup_init;
		struct {
			u64 cgid;
			u32 pid;
		} init_task;
		struct {
			u64 cgid;
		} cgroup_exit;
	};
};

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_CPU_DSQ,
	CSTAT_CELL_DSQ,
	CSTAT_AFFN_VIOL,
	CSTAT_STEAL,
	NR_CSTATS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u64 vtime_now;
	u32 cell;
	u32 llc;
};

struct cgrp_ctx {
	u32  cell;
	bool cell_owner;
};

/*
 * Per-LLC data is cacheline-aligned to prevent false sharing when
 * CPUs on different LLCs update their vtime concurrently.
 */
struct cell_llc {
	u64 vtime_now;
	u32 cpu_cnt;
} __attribute__((aligned(CACHELINE_SIZE)));

// Ensure we don't have multiple of these on the same cacheline.
_Static_assert(sizeof(struct cell_llc) >= CACHELINE_SIZE,
	       "cell_llc must be at least one cache line");

// CELL_LOCK_T is a lock for kernel and padding for user.
#if !defined(__BINDGEN_RUNNING__)
#define CELL_LOCK_T struct bpf_spin_lock
#else
// When userspaces acceses a cell, this pad is zero.
#define CELL_LOCK_T        \
	struct {           \
		u32 __pad; \
	}
#endif

/*
* Cell struct shared between kernel and userspace.
* Kernel uses spinlock for atomic updates.
* Userspace must read with BPF_F_LOCK to avoid torn reads.
* Lock field is padding (kernel zeros it to avoid leaking pointers).
*
* map.lookup(&key, MapFlags::ANY)  -> userspace may see torn state
* map.lookup(&key, MapFlags::LOCK) -> safe read
*/
struct cell {
	// This is a lock in the kernel and padding in userspace
	CELL_LOCK_T lock;

	// cgroup ID of the cell owner (0 for cell 0 or if no owner)
	u64 owner_cgid;
	// Whether or not the cell is used
	u32 in_use;

	// Number of CPUs in this cell
	u32 cpu_cnt;

	// Number of LLCs with at least one CPU in this cell
	u32 llc_present_cnt;

	// Per-LLC data (cacheline-aligned)
	struct cell_llc llcs[MAX_LLCS];
};

// Putting the lock first in the struct is our convention.
// We pad this space when in Rust code that will never see the lock value.
// It is a BPF constraint that it is 4 byte aligned.

// All assertions work for both BPF and userspace builds
_Static_assert(offsetof(struct cell, lock) == 0,
	       "lock/padding must be first field");

_Static_assert(sizeof(((struct cell *)0)->lock) == 4,
	       "lock/padding must be 4 bytes");

_Static_assert(_Alignof(CELL_LOCK_T) == 4,
	       "lock/padding must be 4-byte aligned");

// Verify these are the same size in both BPF and Rust.
_Static_assert(sizeof(struct cell) ==
		       (CACHELINE_SIZE + (CACHELINE_SIZE * MAX_LLCS)),
	       "struct cell size must be stable for Rust bindings");

/* Cell assignment entry: maps a cgroup to a cell */
struct cell_assignment {
	u64 cgid; /* cgroup ID (from cgroup file inode) */
	u32 cell_id; /* cell ID to assign */
};

/* Cell cpumask data for a single cell */
struct cell_cpumask_data {
	unsigned char mask[MAX_CPUS_U8];
};

/*
 * cell_config: Complete cell configuration populated by userspace.
 *
 * Contains all data needed to apply a cell configuration in a single
 * BPF program invocation:
 * - Cell-to-cgroup assignments (which cgroups own which cells)
 * - Cell cpumasks (which CPUs belong to each cell)
 */
struct cell_config {
	u32			 num_cell_assignments;
	u32			 num_cells;
	struct cell_assignment	 assignments[MAX_CELLS];
	struct cell_cpumask_data cpumasks[MAX_CELLS];
};

#endif /* __INTF_H */
