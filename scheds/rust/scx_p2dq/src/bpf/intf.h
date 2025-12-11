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
	MAX_LLC_SHARDS		= 32,
	MAX_TASK_PRIO		= 39,
	MAX_TOPO_NODES		= 1024,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	MIN_SLICE_USEC		= 10ULL,
	MIN_SLICE_NSEC		= (10ULL * NSEC_PER_USEC),

	LOAD_BALANCE_SLACK	= 20ULL,

	P2DQ_MIG_DSQ		= 1LLU << 60,
	P2DQ_INTR_DSQ		= 1LLU << 32,

	// PELT (Per-Entity Load Tracking) constants
	PELT_HALFLIFE_MS	= 32,		// 32ms half-life for exponential decay
	PELT_PERIOD_MS		= 1,		// 1ms update period (simplified from kernel's 1024us)
	PELT_MAX_UTIL		= 1024,		// Maximum utilization value
	PELT_DECAY_SHIFT	= 7,		// Decay factor: (127/128) ≈ 0.98 per ms
	PELT_SUM_MAX		= 131072,	// Maximum sum value (128 * 1024)

	// kernel definitions
	CLOCK_BOOTTIME		= 7,
};

enum p2dq_timers_defs {
	EAGER_LOAD_BALANCER_TMR,
	MAX_TIMERS,
};

enum p2dq_lb_mode {
	PICK2_LOAD,
	PICK2_NR_QUEUED,
};

enum stat_idx {
	P2DQ_STAT_ATQ_ENQ,
	P2DQ_STAT_ATQ_REENQ,
	P2DQ_STAT_DIRECT,
	P2DQ_STAT_DSQ_SAME,
	P2DQ_STAT_DSQ_CHANGE,
	P2DQ_STAT_IDLE,
	P2DQ_STAT_LB_SELECT,
	P2DQ_STAT_LB_DISPATCH,
	P2DQ_STAT_LLC_MIGRATION,
	P2DQ_STAT_NODE_MIGRATION,
	P2DQ_STAT_KEEP,
	P2DQ_STAT_ENQ_CPU,
	P2DQ_STAT_ENQ_LLC,
	P2DQ_STAT_ENQ_INTR,
	P2DQ_STAT_ENQ_MIG,
	P2DQ_STAT_SELECT_PICK2,
	P2DQ_STAT_DISPATCH_PICK2,
	P2DQ_STAT_WAKE_PREV,
	P2DQ_STAT_WAKE_LLC,
	P2DQ_STAT_WAKE_MIG,
	P2DQ_STAT_WAKE_SYNC_WAKER,
	P2DQ_STAT_FORK_BALANCE,
	P2DQ_STAT_EXEC_BALANCE,
	P2DQ_STAT_FORK_SAME_LLC,
	P2DQ_STAT_EXEC_SAME_LLC,
	P2DQ_STAT_THERMAL_KICK,
	P2DQ_STAT_THERMAL_AVOID,
	P2DQ_STAT_EAS_LITTLE_SELECT,
	P2DQ_STAT_EAS_BIG_SELECT,
	P2DQ_STAT_EAS_FALLBACK,
	P2DQ_NR_STATS,
};

enum scheduler_mode {
	MODE_DEFAULT,
	MODE_PERF,
	MODE_EFFICIENCY,
};

#endif /* __P2DQ_INTF_H */
