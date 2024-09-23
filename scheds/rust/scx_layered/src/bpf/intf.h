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
typedef int s32;
typedef long long s64;
typedef unsigned u32;
typedef unsigned long long u64;
#endif

#include <scx/ravg.bpf.h>

enum consts {
	MAX_CPUS_SHIFT		= 9,
	MAX_CPUS		= 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8		= MAX_CPUS / 8,
	MAX_TASKS		= 131072,
	MAX_PATH		= 4096,
	MAX_NUMA_NODES		= 64,
	MAX_DOMS		= 64,
	MAX_COMM		= 16,
	MAX_LAYER_MATCH_ORS	= 32,
	MAX_LAYERS		= 16,
	USAGE_HALF_LIFE		= 100000000,	/* 100ms */

	HI_FALLBACK_DSQ_BASE	= MAX_LAYERS * MAX_DOMS,
	LO_FALLBACK_DSQ		= (MAX_LAYERS * MAX_DOMS) + MAX_DOMS + 1,

	/* XXX remove */
	MAX_CGRP_PREFIXES = 32
};

/* Statistics */
enum global_stat_idx {
	GSTAT_EXCL_IDLE,
	GSTAT_EXCL_WAKEUP,
	NR_GSTATS,
};

enum layer_stat_idx {
	LSTAT_SEL_LOCAL,
	LSTAT_ENQ_WAKEUP,
	LSTAT_ENQ_EXPIRE,
	LSTAT_ENQ_REENQ,
	LSTAT_MIN_EXEC,
	LSTAT_MIN_EXEC_NS,
	LSTAT_OPEN_IDLE,
	LSTAT_AFFN_VIOL,
	LSTAT_KEEP,
	LSTAT_KEEP_FAIL_MAX_EXEC,
	LSTAT_KEEP_FAIL_BUSY,
	LSTAT_PREEMPT,
	LSTAT_PREEMPT_FIRST,
	LSTAT_PREEMPT_XLLC,
	LSTAT_PREEMPT_XNUMA,
	LSTAT_PREEMPT_IDLE,
	LSTAT_PREEMPT_FAIL,
	LSTAT_EXCL_COLLISION,
	LSTAT_EXCL_PREEMPT,
	LSTAT_KICK,
	LSTAT_YIELD,
	LSTAT_YIELD_IGNORE,
	LSTAT_MIGRATION,
	LSTAT_XNUMA_MIGRATION,
	LSTAT_XLLC_MIGRATION,
	LSTAT_XLAYER_WAKE,
	LSTAT_XLAYER_REWAKE,
	NR_LSTATS,
};

struct cpu_ctx {
	bool			current_preempt;
	bool			current_exclusive;
	bool			prev_exclusive;
	bool			maybe_idle;
	bool			yielding;
	bool			try_preempt_first;
	u64			layer_cycles[MAX_LAYERS];
	u64			gstats[NR_GSTATS];
	u64			lstats[MAX_LAYERS][NR_LSTATS];
	u64			ran_current_for;
	u32			layer_idx;
	u32			cache_idx;
	u32			node_idx;
};

struct cache_ctx {
	u32 id;
	struct bpf_cpumask __kptr *cpumask;
	u32 nr_cpus;
};

struct node_ctx {
	u32 id;
	struct bpf_cpumask __kptr *cpumask;
	u32 nr_llcs;
	u32 nr_cpus;
	u64 llc_mask;
};

enum layer_match_kind {
	MATCH_CGROUP_PREFIX,
	MATCH_COMM_PREFIX,
	MATCH_PCOMM_PREFIX,
	MATCH_NICE_ABOVE,
	MATCH_NICE_BELOW,
	MATCH_NICE_EQUALS,
	MATCH_USER_ID_EQUALS,
	MATCH_GROUP_ID_EQUALS,
	MATCH_PID_EQUALS,
	MATCH_PPID_EQUALS,
	MATCH_TGID_EQUALS,

	NR_LAYER_MATCH_KINDS,
};

struct layer_match {
	int		kind;
	char		cgroup_prefix[MAX_PATH];
	char		comm_prefix[MAX_COMM];
	char		pcomm_prefix[MAX_COMM];
	int		nice;
	u32		user_id;
	u32		group_id;
	u32		pid;
	u32		ppid;
	u32		tgid;
};

struct layer_match_ands {
	struct layer_match	matches[NR_LAYER_MATCH_KINDS];
	int			nr_match_ands;
};

struct layer {
	struct layer_match_ands	matches[MAX_LAYER_MATCH_ORS];
	unsigned int		nr_match_ors;
	unsigned int		idx;
	u64			min_exec_ns;
	u64			max_exec_ns;
	u64			yield_step_ns;
	u64			slice_ns;
	bool			open;
	bool			preempt;
	bool			preempt_first;
	bool			exclusive;

	u64			vtime_now;
	u64			nr_tasks;

	u64			load;
	struct ravg_data	load_rd;

	u64			cpus_seq;
	u64			node_mask;
	u64			cache_mask;
	unsigned int		refresh_cpus;
	unsigned char		cpus[MAX_CPUS_U8];
	unsigned int		nr_cpus;	// managed from BPF side
	unsigned int		perf;
};

#endif /* __INTF_H */
