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
typedef unsigned short u16;
typedef int s32;
typedef unsigned u32;
typedef long long s64;
typedef unsigned long long u64;
#endif

enum consts {
	CACHELINE_SIZE		= 64,
	MAX_CPUS_SHIFT		= 9,
	MAX_CPUS		= 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8		= MAX_CPUS / 8,
	MAX_TASKS		= 131072,
	MAX_PATH		= 4096,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,
	MAX_COMM		= 16,
	MAX_LAYER_MATCH_ORS	= 32,
	MAX_LAYER_NAME		= 64,
	MAX_LAYERS		= 16,
	MAX_LAYER_WEIGHT	= 10000,
	MIN_LAYER_WEIGHT	= 1,
	DEFAULT_LAYER_WEIGHT	= 100,
	USAGE_HALF_LIFE		= 100000000,	/* 100ms */
	RUNTIME_DECAY_FACTOR	= 4,
	LAYER_LAT_DECAY_FACTOR	= 32,

	DSQ_ID_SPECIAL_MASK	= 0xc0000000,
	HI_FB_DSQ_BASE		= 0x40000000,
	LO_FB_DSQ_BASE		= 0x80000000,

	DSQ_ID_LAYER_SHIFT	= 16,
	DSQ_ID_LLC_MASK		= (1LLU << DSQ_ID_LAYER_SHIFT) - 1,		/* 0x0000ffff */
	DSQ_ID_LAYER_MASK	= ~DSQ_ID_LAYER_SHIFT & ~DSQ_ID_SPECIAL_MASK,	/* 0x3fff0000 */

	/* XXX remove */
	MAX_CGRP_PREFIXES	= 32,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	SCXCMD_OP_NONE 		= 0,
	SCXCMD_OP_JOIN 		= 1,
	SCXCMD_OP_LEAVE 	= 2,

	SCXCMD_PREFIX		= 0x5C10,
	SCXCMD_COMLEN		= 13,
	MAX_GPU_PIDS 		= 100000,
};

static inline void ___consts_sanity_check___(void) {
	/* layer->llcs_to_drain uses u64 as LLC bitmap */
	_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");
	_Static_assert(MAX_LLCS <= (1 << DSQ_ID_LAYER_SHIFT), "MAX_LLCS too high");
	_Static_assert(MAX_LAYERS <= (DSQ_ID_LAYER_MASK >> DSQ_ID_LAYER_SHIFT) + 1,
		       "MAX_LAYERS too high");
}

enum layer_kind {
	LAYER_KIND_OPEN,
	LAYER_KIND_GROUPED,
	LAYER_KIND_CONFINED,
};

enum layer_usage {
	LAYER_USAGE_OWNED,
	LAYER_USAGE_OPEN,
	LAYER_USAGE_SUM_UPTO = LAYER_USAGE_OPEN,

	LAYER_USAGE_PROTECTED,
	LAYER_USAGE_PROTECTED_PREEMPT,

	NR_LAYER_USAGES,
};

/* Statistics */
enum global_stat_id {
	GSTAT_EXCL_IDLE,
	GSTAT_EXCL_WAKEUP,
	GSTAT_HI_FB_EVENTS,
	GSTAT_HI_FB_USAGE,
	GSTAT_LO_FB_EVENTS,
	GSTAT_LO_FB_USAGE,
	GSTAT_FB_CPU_USAGE,
	GSTAT_ANTISTALL,
	NR_GSTATS,
};

enum layer_stat_id {
	LSTAT_SEL_LOCAL,
	LSTAT_ENQ_LOCAL,
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
	LSTAT_YIELD,
	LSTAT_YIELD_IGNORE,
	LSTAT_MIGRATION,
	LSTAT_XNUMA_MIGRATION,
	LSTAT_XLLC_MIGRATION,
	LSTAT_XLLC_MIGRATION_SKIP,
	LSTAT_XLAYER_WAKE,
	LSTAT_XLAYER_REWAKE,
	LSTAT_LLC_DRAIN_TRY,
	LSTAT_LLC_DRAIN,
	NR_LSTATS,
};

enum llc_layer_stat_id {
	LLC_LSTAT_LAT,
	LLC_LSTAT_CNT,
	NR_LLC_LSTATS,
};

/* CPU proximity map from closest to farthest, starts with self */
struct cpu_prox_map {
	u16			cpus[MAX_CPUS];
	u32			core_end;
	u32			llc_end;
	u32			node_end;
	u32			sys_end;
};

struct cpu_ctx {
	s32			cpu;
	bool			current_preempt;
	bool			current_exclusive;
	bool			prev_exclusive;
	bool			maybe_idle;
	bool			yielding;
	bool			try_preempt_first;
	bool			is_big;

	bool			protect_owned;
	bool			protect_owned_preempt;
	bool			running_owned;
	bool			running_open;
	bool			running_fallback;
	u64			running_at;

	u64			layer_usages[MAX_LAYERS][NR_LAYER_USAGES];
	u64			gstats[NR_GSTATS];
	u64			lstats[MAX_LAYERS][NR_LSTATS];
	u64			ran_current_for;

	u64			usage;
	u64			usage_at_idle;

	u64			hi_fb_dsq_id;
	u64			lo_fb_dsq_id;
	bool			in_open_layers;
	u32			layer_id;
	u32			task_layer_id;
	u32			llc_id;
	u32			node_id;
	u32			perf;

	u64			lo_fb_seq;
	u64			lo_fb_seq_at;
	u64			lo_fb_usage_base;

	u32			ogp_layer_order[MAX_LAYERS];	/* open/grouped preempt */
	u32			ogn_layer_order[MAX_LAYERS];	/* open/grouped non-preempt */

	u32			op_layer_order[MAX_LAYERS];	/* open preempt */
	u32			on_layer_order[MAX_LAYERS];	/* open non-preempt */
	u32			gp_layer_order[MAX_LAYERS];	/* grouped preempt */
	u32			gn_layer_order[MAX_LAYERS];	/* grouped non-preempt */

	struct cpu_prox_map	prox_map;
};

struct llc_prox_map {
	u16			llcs[MAX_LLCS];
	u32			node_end;
	u32			sys_end;
};

struct llc_ctx {
	u32			id;
	struct bpf_cpumask __kptr *cpumask;
	u32			nr_cpus;
	u64			vtime_now[MAX_LAYERS];
	u64			queued_runtime[MAX_LAYERS];
	u64			lo_fb_seq;
	u64			lstats[MAX_LAYERS][NR_LLC_LSTATS];
	struct llc_prox_map	prox_map;
};

struct node_ctx {
	u32			id;
	struct bpf_cpumask __kptr *cpumask;
	u32			nr_llcs;
	u32			nr_cpus;
	u64			llc_mask;
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
	MATCH_NSPID_EQUALS,
	MATCH_NS_EQUALS,
	MATCH_SCXCMD_JOIN,
	MATCH_IS_GROUP_LEADER,
	MATCH_IS_KTHREAD,
	MATCH_USED_GPU_TID,
	MATCH_USED_GPU_PID,

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
	u64		nsid;
	bool		is_group_leader;
	bool		is_kthread;
	bool		used_gpu_tid;
	bool		used_gpu_pid;
};

struct layer_match_ands {
	struct layer_match	matches[NR_LAYER_MATCH_KINDS];
	int			nr_match_ands;
};

enum layer_growth_algo {
	GROWTH_ALGO_STICKY,
	GROWTH_ALGO_LINEAR,
	GROWTH_ALGO_REVERSE,
	GROWTH_ALGO_RANDOM,
	GROWTH_ALGO_TOPO,
	GROWTH_ALGO_ROUND_ROBIN,
	GROWTH_ALGO_BIG_LITTLE,
	GROWTH_ALGO_LITTLE_BIG,
	GROWTH_ALGO_NODE_SPREAD,
	GROWTH_ALGO_RANDOM_TOPO,
};

struct layer {
	struct layer_match_ands	matches[MAX_LAYER_MATCH_ORS];
	unsigned int		nr_match_ors;
	unsigned int		id;
	u64			min_exec_ns;
	u64			max_exec_ns;
	u64			yield_step_ns;
	u64			slice_ns;
	bool			fifo;
	u32			weight;
	u64			disallow_open_after_ns;
	u64			disallow_preempt_after_ns;
	u64			xllc_mig_min_ns;

	int			kind;
	bool			preempt;
	bool			preempt_first;
	bool			exclusive;
	bool			allow_node_aligned;
	int			growth_algo;

	u64			nr_tasks;

	u64			cpus_seq;
	u64			node_mask;
	u64			llc_mask;
	bool			check_no_idle;
	u32			perf;
	u64			refresh_cpus;
	u8			cpus[MAX_CPUS_U8];

	u32			nr_cpus;
	u32			nr_llc_cpus[MAX_LLCS];

	u64			llcs_to_drain;
	u32			llc_drain_cnt;

	char			name[MAX_LAYER_NAME];
};

struct scx_cmd {
	u16			prefix;
	u8 			opcode;
	u8			cmd[SCXCMD_COMLEN];
} __attribute__((packed));

#endif /* __INTF_H */
