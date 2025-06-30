// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __P2DQ_INTF_H
#define __P2DQ_INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif


enum consts {
	MAX_CPUS		= 512,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,
	MAX_DSQS_PER_LLC	= 8,
	MAX_TASK_PRIO		= 39,
	MAX_TOPO_NODES		= 1024,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	MIN_SLICE_USEC		= 10ULL,

	LOAD_BALANCE_SLACK	= 20ULL,

	P2DQ_MIG_DSQ		= 1LLU << 60,
	P2DQ_INTR_DSQ		= 1LLU << 32,

	// kernel definitions
	CLOCK_BOOTTIME		= 7,

	STATIC_ALLOC_PAGES_GRANULARITY = 8,
};

enum p2dq_timers_defs {
	EAGER_LOAD_BALANCER_TMR,
	MAX_TIMERS,
};

enum stat_idx {
	P2DQ_STAT_DIRECT,
	P2DQ_STAT_DSQ_SAME,
	P2DQ_STAT_DSQ_CHANGE,
	P2DQ_STAT_IDLE,
	P2DQ_STAT_LB_SELECT,
	P2DQ_STAT_LB_DISPATCH,
	P2DQ_STAT_LLC_MIGRATION,
	P2DQ_STAT_NODE_MIGRATION,
	P2DQ_STAT_KEEP,
	P2DQ_STAT_SELECT_PICK2,
	P2DQ_STAT_DISPATCH_PICK2,
	P2DQ_STAT_WAKE_PREV,
	P2DQ_STAT_WAKE_LLC,
	P2DQ_STAT_WAKE_MIG,
	P2DQ_NR_STATS,
};

enum scheduler_mode {
	MODE_PERFORMANCE,
};

enum enqueue_promise_kind {
	P2DQ_ENQUEUE_PROMISE_COMPLETE,
	P2DQ_ENQUEUE_PROMISE_VTIME,
	P2DQ_ENQUEUE_PROMISE_FIFO,
};

#endif /* __P2DQ_INTF_H */
