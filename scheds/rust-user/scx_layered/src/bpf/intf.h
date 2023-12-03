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
typedef unsigned long long u64;
typedef long long s64;
#endif

#include <scx/ravg.bpf.h>

enum consts {
	MAX_CPUS_SHIFT		= 9,
	MAX_CPUS		= 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8		= MAX_CPUS / 8,
	MAX_TASKS		= 131072,
	MAX_PATH		= 4096,
	MAX_COMM		= 16,
	MAX_LAYER_MATCH_ORS	= 32,
	MAX_LAYERS		= 16,
	USAGE_HALF_LIFE		= 100000000,	/* 100ms */

	/* XXX remove */
	MAX_CGRP_PREFIXES = 32
};

/* Statistics */
enum global_stat_idx {
	GSTAT_TASK_CTX_FREE_FAILED,
	NR_GSTATS,
};

enum layer_stat_idx {
	LSTAT_LOCAL,
	LSTAT_GLOBAL,
	LSTAT_OPEN_IDLE,
	LSTAT_AFFN_VIOL,
	LSTAT_PREEMPT,
	NR_LSTATS,
};

struct cpu_ctx {
	bool			current_preempt;
	u64			layer_cycles[MAX_LAYERS];
	u64			gstats[NR_GSTATS];
	u64			lstats[MAX_LAYERS][NR_LSTATS];
};

enum layer_match_kind {
	MATCH_CGROUP_PREFIX,
	MATCH_COMM_PREFIX,
	MATCH_NICE_ABOVE,
	MATCH_NICE_BELOW,

	NR_LAYER_MATCH_KINDS,
};

struct layer_match {
	int		kind;
	char		cgroup_prefix[MAX_PATH];
	char		comm_prefix[MAX_COMM];
	int		nice_above_or_below;
};

struct layer_match_ands {
	struct layer_match	matches[NR_LAYER_MATCH_KINDS];
	int			nr_match_ands;
};

struct layer {
	struct layer_match_ands	matches[MAX_LAYER_MATCH_ORS];
	unsigned int		nr_match_ors;
	unsigned int		idx;
	bool			open;
	bool			preempt;

	u64			vtime_now;
	u64			nr_tasks;

	u64			load;
	struct ravg_data	load_rd;

	u64			cpus_seq;
	unsigned int		refresh_cpus;
	unsigned char		cpus[MAX_CPUS_U8];
	unsigned int		nr_cpus;	// managed from BPF side
};

#endif /* __INTF_H */
