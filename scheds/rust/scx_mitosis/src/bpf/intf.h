// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifndef __BPF__
#include <stddef.h>
typedef unsigned long long u64;
typedef unsigned int u32;
typedef _Bool bool;
#endif

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/ravg.bpf.h"
#else
#include <scx/ravg.bpf.h>
#endif

/* ---- Work stealing config (compile-time) ------------------------------- */
#ifndef MITOSIS_ENABLE_STEALING
#define MITOSIS_ENABLE_STEALING 1
#endif
/* ----------------------------------------------------------------------- */

enum consts {
	CACHELINE_SIZE = 64,
	MAX_CPUS_SHIFT = 9,
	MAX_CPUS = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8 = MAX_CPUS / 8,
	MAX_CELLS = 16,
	USAGE_HALF_LIFE = 100000000, /* 100ms */

	PCPU_BASE = 0x80000000,
	MAX_CG_DEPTH = 256,

	MAX_L3S = 16,
};

/* Kernel side sees the real lock; userspace sees padded bytes of same size/alignment */
#if defined(__BPF__)
#define CELL_LOCK_T struct bpf_spin_lock
#else
/* userspace placeholder: kernel won’t copy spin_lock */
#define CELL_LOCK_T        \
	struct {           \
		u32 __pad; \
	} /* 4-byte aligned as required */
#endif

struct cell {
	// This is a lock in the kernel and padding in the user
	CELL_LOCK_T lock; // Assumed to be the first entry (see below)

	// Whether or not the cell is used
	u32 in_use;

	// Number of CPUs in this cell
	u32 cpu_cnt;

	// Number of L3s with at least one CPU in this cell
	u32 l3_present_cnt;

	// Number of CPUs from each L3 assigned to this cell
	u32 l3_cpu_cnt[MAX_L3S];

	// per-L3 vtimes within this cell
	u64 l3_vtime_now[MAX_L3S];
};

// Putting the lock first in the struct is our convention.
// We pad this space when in Rust code that will never see the lock value.
// We intentionally avoid it in copy_cell_no_lock to keep the verifier happy.
// It is a BPF constraint that it is 4 byte aligned.

// All assertions work for both BPF and userspace builds
_Static_assert(offsetof(struct cell, lock) == 0,
	       "lock/padding must be first field");

_Static_assert(sizeof(((struct cell *)0)->lock) == 4,
	       "lock/padding must be 4 bytes");

_Static_assert(_Alignof(CELL_LOCK_T) == 4,
	       "lock/padding must be 4-byte aligned");

_Static_assert(offsetof(struct cell, in_use) == 4,
	       "in_use must follow 4-byte lock/padding");

// Verify these are the same size in both BPF and Rust.
_Static_assert(sizeof(struct cell) ==
		       ((4 * sizeof(u32)) + (4 * MAX_L3S) + (8 * MAX_L3S)),
	       "struct cell size must be stable for Rust bindings");

_Static_assert(sizeof(struct cell) == 208,
	       "struct cell must be exactly 208 bytes");

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_CPU_DSQ,
	CSTAT_CELL_DSQ,
	CSTAT_AFFN_VIOL,
	NR_CSTATS,
};

/* Function invocation counters */
enum fn_counter_idx {
	COUNTER_SELECT_CPU,
	COUNTER_ENQUEUE,
	COUNTER_DISPATCH,
	NR_COUNTERS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u32 cell;
	u64 vtime_now;
};

struct cgrp_ctx {
	u32 cell;
	bool cell_owner;
};

#endif /* __INTF_H */
