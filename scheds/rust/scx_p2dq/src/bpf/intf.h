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

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	// kernel definitions
	CLOCK_BOOTTIME		= 7,
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

struct p2dq_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

struct task_ctx {
	u64			dsq_id;
	int			dsq_index;
	u32			cpu;
	u32			llc_id;
	u32			node_id;
	bool			runnable;
	u32			weight;
	u64			last_dsq_id;
	int			last_dsq_index;
	u64 			last_run_at;
	u64			llc_runs; /* how many runs on the current LLC */

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed to run on all CPUs */
	bool			all_cpus;


	struct bpf_cpumask __kptr *mask;
};

struct cpu_ctx {
	int				id;
	u32				llc_id;
	u32				node_id;
	u64				dsq_index;
	u32				perf;
	bool				interactive;
	bool				is_big;
	u64				ran_for;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				max_load_dsq;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	u64				last_period_ns;
	u64				load;
	bool				all_big;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				dsq_max_vtime[MAX_DSQS_PER_LLC];
	u64				dsq_load[MAX_DSQS_PER_LLC];
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
	struct bpf_cpumask __kptr	*little_cpumask;
};

struct node_ctx {
	u32				id;
	bool				all_big;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

enum enqueue_promise_kind {
	P2DQ_ENQUEUE_PROMISE_COMPLETE,
	P2DQ_ENQUEUE_PROMISE_VTIME,
	P2DQ_ENQUEUE_PROMISE_FIFO,
};

struct enqueue_promise_vtime {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
	u64	vtime;
};

struct enqueue_promise_fifo {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
};

struct enqueue_promise {
	enum enqueue_promise_kind	kind;
	union {
		struct enqueue_promise_vtime	vtime;
		struct enqueue_promise_fifo	fifo;
	};
};

#endif /* __P2DQ_INTF_H */
