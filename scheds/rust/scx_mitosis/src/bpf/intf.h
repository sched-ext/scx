// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>

#ifndef __VMLINUX_H__
typedef unsigned long long u64;
typedef unsigned int u32;
#endif

enum consts {
	CACHELINE_SIZE = 64,
	MAX_CPUS_SHIFT = 9,
	MAX_CPUS = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8 = MAX_CPUS / 8,
	MAX_CELLS = 256,
	MAX_SUBCELLS_PER_CELL = 8,
	USAGE_HALF_LIFE = 100000000, /* 100ms */

	MAX_CG_DEPTH = 256,
	MAX_LLCS = 16,

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

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_CPU_DSQ,
	CSTAT_CELL_DSQ,
	CSTAT_AFFN_VIOL,
	CSTAT_BORROWED,
	CSTAT_STEAL,
	CSTAT_DRAIN_CNT,
	CSTAT_DRAIN_AFFN_CNT,
	CSTAT_CLAMP_USED,
	CSTAT_PIN_SKIP,
	CSTAT_SLICE_SHRINK_MAX,
	CSTAT_SLICE_SHRINK_PROPORTIONAL,
	CSTAT_SLICE_SHRINK_MIN,
	NR_CSTATS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u64 running_ns[MAX_CELLS];
	u64 vtime_now;
	u32 cell;
	u32 llc;
};

struct cgrp_ctx {
	u32 cell;
	bool cell_owner;
};

/*
 * Per-LLC data is cacheline-aligned to prevent false sharing when
 * CPUs on different LLCs update their vtime concurrently.
 */
struct cell_llc {
	u64 vtime_now;
	u32 nr_queued;
} __attribute__((aligned(CACHELINE_SIZE)));

// Ensure we don't have multiple of these on the same cacheline.
_Static_assert(sizeof(struct cell_llc) >= CACHELINE_SIZE,
	       "cell_llc must be at least one cache line");

/* Cell cpumask data for a single cell or subcell */
struct cell_cpumask_data {
	unsigned char mask[MAX_CPUS_U8];
};

/* Subcell state shared between kernel and userspace. */
struct subcell {
	u32 id;
	u32 in_use;
	struct cell_cpumask_data primary;
	struct cell_cpumask_data borrowable;
};

struct cell {
	// cgroup ID of the cell owner (0 for cell 0 or if no owner)
	u64 owner_cgid;
	// Whether or not the cell is used
	u32 in_use;
	// Bitmap of LLC DSQs that have queued work but no CPUs in this cell
	u64 llcs_to_drain;
	// Bitmap of LLCs that contain CPUs assigned to this cell
	u64 llcs_with_cpus;

	// Per-LLC data (cacheline-aligned)
	struct cell_llc llcs[MAX_LLCS];

	// Fixed-size subcell state owned by this cell.
	struct subcell subcells[MAX_SUBCELLS_PER_CELL];
};

// Verify these are the same size in both BPF and Rust.
_Static_assert(sizeof(struct cell) == (CACHELINE_SIZE + (CACHELINE_SIZE * MAX_LLCS) +
				       (sizeof(struct subcell) * MAX_SUBCELLS_PER_CELL)),
	       "struct cell size must be stable for Rust bindings");

/* Cell assignment entry: maps a cgroup to a cell */
struct cell_assignment {
	u64 cgid; /* cgroup ID (from cgroup file inode) */
	u32 cell_id; /* cell ID to assign */
};

/*
 * cell_config: Complete cell configuration populated by userspace.
 *
 * Contains all data needed to apply a cell configuration in a single
 * BPF program invocation:
 * - Cell-to-cgroup assignments (which cgroups own which cells)
 * - Cell cpumasks (which CPUs belong to each cell)
 * - Per-cell subcell cpumasks
 */
struct cell_config {
	u32 num_cell_assignments;
	u32 num_cells;
	struct cell_assignment assignments[MAX_CELLS];
	struct cell_cpumask_data cpumasks[MAX_CELLS];
	struct cell_cpumask_data borrowable_cpumasks[MAX_CELLS];
	struct subcell subcells[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
};

#endif /* __INTF_H */
