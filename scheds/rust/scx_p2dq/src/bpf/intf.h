// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

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

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/ravg.bpf.h"
#else
#include <scx/ravg.bpf.h>
#endif

enum consts {
	MAX_CPUS		= 512,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,
	MAX_DSQS_PER_LLC	= 8,
};

enum stat_idx {
	P2DQ_STAT_DSQ_SAME,
	P2DQ_STAT_DSQ_CHANGE,
	P2DQ_STAT_LLC_MIGRATION,
	P2DQ_STAT_KEEP,
	P2DQ_STAT_PICK2,
	P2DQ_NR_STATS,
};

enum scheduler_mode {
	MODE_PERFORMANCE,
};

struct task_ctx {
	u64			dsq_id;
	int			dsq_index;
	u32			cpu;
	u32			llc_id;
	bool			runnable;
	u32			weight;
	u64			last_dsq_id;
	int			last_dsq_index;
	u64 			last_run_at;

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed on all CPUs and eligible for DIRECT_GREEDY optimization */
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
	u64				dsq_load[MAX_DSQS_PER_LLC];
	u64				max_load_dsq;
	struct bpf_cpumask __kptr	*tmp_cpumask;
};

struct llc_ctx {
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u64				vtime;
	bool				all_big;
	u64				dsqs[MAX_DSQS_PER_LLC];
	u64				dsq_max_vtime[MAX_DSQS_PER_LLC];
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

struct node_ctx {
	u32				id;
	bool				all_big;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

#endif /* __INTF_H */
