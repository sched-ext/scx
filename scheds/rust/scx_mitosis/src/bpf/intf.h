// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
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

	PCPU_BASE	      = 0x80000000,
	MAX_CG_DEPTH	      = 256,

	DEBUG_EVENTS_BUF_SIZE = 4096,
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
	NR_CSTATS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u32 cell;
	u64 vtime_now;
};

struct cgrp_ctx {
	u32  cell;
	bool cell_owner;
};

/*
 * cell is the per-cell book-keeping
*/
struct cell {
	// current vtime of the cell
	u64 vtime_now;
	// Whether or not the cell is used or not
	u32 in_use;
};

#endif /* __INTF_H */
