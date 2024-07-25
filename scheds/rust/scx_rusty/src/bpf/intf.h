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
typedef long long s64;
#endif

#include <scx/ravg.bpf.h>

enum consts {
	MAX_CPUS		= 512,
	MAX_DOMS		= 64,	/* limited to avoid complex bitmask ops */
	MAX_NUMA_NODES		= MAX_DOMS,	/* Assume at least 1 domain per NUMA node */
	CACHELINE_SIZE		= 64,
	NO_DOM_FOUND		= MAX_DOMS + 1,

	LB_DEFAULT_WEIGHT	= 100,
	LB_MIN_WEIGHT		= 1,
	LB_MAX_WEIGHT		= 10000,
	LB_LOAD_BUCKETS		= 100,	/* Must be a factor of LB_MAX_WEIGHT */
	LB_WEIGHT_PER_BUCKET	= LB_MAX_WEIGHT / LB_LOAD_BUCKETS,

	/* Time constants */
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC           = USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC            = USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC            = NSEC_PER_USEC * USEC_PER_SEC,

	/* Constants used for determining a task's deadline */
	DL_RUNTIME_FACTOR	= 100,
	DL_FREQ_FT_MAX		= 100000,
	DL_MAX_LAT_PRIO		= 39,
	/*
	 * Duty cycle is the proportion of time in some interval during which a
	 * task could have used CPU. In other words, for some time interval
	 * [t_0, t_1], a task's duty cycle is the value between [0, 1]
	 * corresponding to how much time in the interval it _could_ have used.
	 * For example, if it could have run the entire time its duty cycle
	 * would be 1, and if it could only have run for half of the interval
	 * its duty cycle would be .5. Note that a task that's runnable for the
	 * first half of the interval, and running for the second half at which
	 * point it blocks, would still have a duty cycle of .5.
	 *
	 * We track duty cycle in BPF using the running average helpers. The
	 * value below is approximately the value that is observed in the
	 * kernel when a task has duty cycle ~= 1. In user space we can do
	 * floating point arithmetic in e.g. the rust implementation of
	 * ravg_read(), but here in the kernel we're stuck with fixed-point
	 * integer arithmetic and must therefore use values like this when
	 * determining a task's latency priority when calculating its deadline.
	 */
	DL_FULL_DCYCLE		= 650000,

	/*
	 * When userspace load balancer is trying to determine the tasks to push
	 * out from an overloaded domain, it looks at the the following number
	 * of recently active tasks of the domain. While this may lead to
	 * spurious migration victim selection failures in pathological cases,
	 * this isn't a practical problem as the LB rounds are best-effort
	 * anyway and will be retried until loads are balanced.
	 */
	MAX_DOM_ACTIVE_PIDS	= 1024,
};

/* Statistics */
enum stat_idx {
	/* The following fields add up to all dispatched tasks */
	RUSTY_STAT_WAKE_SYNC,
	RUSTY_STAT_SYNC_PREV_IDLE,
	RUSTY_STAT_PREV_IDLE,
	RUSTY_STAT_GREEDY_IDLE,
	RUSTY_STAT_PINNED,
	RUSTY_STAT_DIRECT_DISPATCH,
	RUSTY_STAT_DIRECT_GREEDY,
	RUSTY_STAT_DIRECT_GREEDY_FAR,
	RUSTY_STAT_DSQ_DISPATCH,
	RUSTY_STAT_GREEDY_LOCAL,
	RUSTY_STAT_GREEDY_XNUMA,

	/* Extra stats that don't contribute to total */
	RUSTY_STAT_REPATRIATE,
	RUSTY_STAT_KICK_GREEDY,
	RUSTY_STAT_LOAD_BALANCE,

	/* Errors */
	RUSTY_STAT_TASK_GET_ERR,

	/* Deadline related stats */
	RUSTY_STAT_DL_CLAMP,
	RUSTY_STAT_DL_PRESET,

	RUSTY_NR_STATS,
};

struct task_ctx {
	/* The domains this task can run on */
	u64 dom_mask;
	u64 preferred_dom_mask;

	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *tmp_cpumask;
	u32 dom_id;
	u32 weight;
	bool runnable;
	u64 dom_active_pids_gen;
	u64 deadline;

	u64 sum_runtime;
	u64 avg_runtime;
	u64 last_run_at;

	/* frequency with which a task is blocked (consumer) */
	u64 blocked_freq;
	u64 last_blocked_at;

	/* frequency with which a task wakes other tasks (producer) */
	u64 waker_freq;
	u64 last_woke_at;

	s64 lat_prio;

	/*
	 * vruntime tracked by the scheduler. Separate from p->scx.dsq_vtime as
	 * this is set by the scheduler.
	 */
	u64 vruntime;

	/* The task is a workqueue worker thread */
	bool is_kworker;

	/* Allowed on all CPUs and eligible for DIRECT_GREEDY optimization */
	bool all_cpus;

	/* select_cpu() telling enqueue() to queue directly on the DSQ */
	bool dispatch_local;

	struct ravg_data dcyc_rd;
};

struct bucket_ctx {
	u64 dcycle;
	struct ravg_data rd;
};

struct dom_ctx {
	u32 id;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *direct_greedy_cpumask;
	struct bpf_cpumask __kptr *node_cpumask;

	u64 min_vruntime;

	u64 dbg_dcycle_printed_at;
	struct bucket_ctx buckets[LB_LOAD_BUCKETS];
};

struct node_ctx {
	struct bpf_cpumask __kptr *cpumask;
};

#endif /* __INTF_H */
