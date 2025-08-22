/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <lib/topology.h>
#include <lib/cgroup.h>
#include <lib/atq.h>

extern int scx_cgroup_bw_enqueue_cb(u64 taskc);

enum scx_cgroup_consts {
	/* cache line size of an architecture */
	SCX_CACHELINE_SIZE		= 64,
	/* clock boottime constant */
	CBW_CLOCK_BOOTTIME		= 7,
	/* normalized period in nsec: 100 msec */
	CBW_NPERIOD			= (100ULL * 1000ULL * 1000ULL),
	/* maximum number of cgroups */
	CBW_NR_CGRP_MAX			= 2048,
	/* maximum number of scx_cgroup_llc_ctx: 2048 cgroups * 32 LLCs */
	CBW_NR_CGRP_LLC_MAX		= (CBW_NR_CGRP_MAX * 32),
	/* The maximum height of a cgroup tree. */
	CBW_CGRP_TREE_HEIGHT_MAX	= 16,
};

/**
 * Per-cgroup data structure containing cpu.max-related information.
 * In the future, it can be extended to support other features of cgroup
 * beyond cpu.max.
 */
struct scx_cgroup_ctx {
	/* cgroup id */
	u64		id;

	/*
	 * Given @quota, @period, and @burst in nanoseconds.
	 */
	u64		quota;
	u64		period;
	u64		burst;

	/*
	 * Normalized quota by period of 100 msec. By using the same period,
	 * we can use a single BPF timer to handle all the cgroups.
	 */
	u64		nquota;

	/*
	 * The upper bound of a cgroup’s quota, which is the minimum
	 * normalized quota of all its ancestors and itself.
	 */
	u64		nquota_ub;

	/*
	 * @period_start_clk represents when a new period starts.
	 * @burst_remaining is the maximum burst that can be accumulated
	 * until the end of the period from @period_start_clk.
	 */
	u64		period_start_clk;
	s64		burst_remaining;

	/*
	 * The amount of remaining time out of @quota after LLC contexts
	 * deduct the budget for execution. It can be negative when the quota
	 * is over-allocated.
	 */
	s64		budget_remaining;

	/*
	 * Total amount of time executed once replenished. It includes
	 * @runtime_total of all LLC contexts of this cgroup. It is sloppy
	 * since it is updated only before asking more budget to its parent.
	 * In other words, it is not updated as @runtime_total of its LLC
	 * contexts are updated, so it could be outdated. When it is greater
	 * than @quota_ub, we cannot ask for more budget from the parent,
	 * so there will be no more updates on @runtime_total_sloppy before
	 * the next period starts.
	 */
	s64		runtime_total_sloppy;

	/*
	 * Total runtime at the last replenishment period.
	 */
	s64		runtime_total_last;

	/*
	 * The budget allocation from a parent cgroup to a child cgroup in nsec.
	 */
	u64		budget_p2c;

	/*
	 * The budget allocation from a cgroup to its LLC context in nsec.
	 */
	u64		budget_c2l;

	/*
	 * The number of descendent cgroups that can have tasks.
	 */
	int		nr_taskable_descendents;

	/*
	 * A boolean flag indicating whether the cgroup has LLC contexts.
	 */
	bool		has_llcx;

	/*
	 * A boolean flag indicating whether the cgroup is throttled or not.
	 * Note that the cgroup can be throttled before reaching the upper
	 * bound (nquota_nb) if the subrooot cgroup runs out of the time.
	 */
	bool		is_throttled;
};


/**
 * If a cgroup is either at a leaf level or threaded, we manage per-LLC-cgroup
 * contexts to reduce cross-LLC cache coherence traffic. Otherwise, the cgroup
 * stats are used only for distributing remaining budgets. In this case, we do
 * not manage per-LLC context since they will be accessed much less frequently.
 */
struct scx_cgroup_llc_ctx {
	/* cgroup id */
	u64		id;

	/*
	 * The amount of remaining time reserved before task execution.
	 * When @budget_remaining becomes zero (or negative), we ask
	 * more time budget to the scx_cgroup_ctx. When no budget remains
	 * the scx_cgroup_ctx, we walk up the cgroup hierarchy. It can be
	 * negative when the quota is over-booked.
	 *
	 * The budget that was chunk-allocated from the upper level may not
	 * be fully used. Such remaining time at the LLC level will be carried
	 * over to the next period for eventual quota enforcement.
	 */
	s64		budget_remaining;

	/*
	 * Total amount of time executed once replenished. It should not
	 * exceed @quota_ub.
	 */
	s64		runtime_total;

	/*
	 * Tasks that can not be enqueued when the cgroup is running out
	 * of time (i.e., throttled). In this case, tasks will be enqueued
	 * to the backlog task queue (BTQ) for later execution. Tasks in the
	 * BTQ are ordered by vtime and will be enqueued to a proper DSQ
	 * for execution when the cgroup becomes unthrottled again.
	 *
 	 * When moving a task from BTQ to a proper DSQ, we need to choose a
 	 * target CPU by considering CPU idle status, task’s previous CPU, etc.
 	 * Since DSQ does not support a pop-like operation that dispatches a
	 * task from the DSQ without moving to another DSQ, we use ATQ as a
	 * backend of BTQ.
	 */
	scx_atq_t	*btq;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

/*
 * Library-wide configuration for CPU bandwidth control.
 */
static struct scx_cgroup_bw_config cbw_config;

/*
 * A map to store scx_cgroup_ctx. It is accessed through a cgroup pointer. 
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scx_cgroup_ctx);
} cbw_cgrp_map SEC(".maps");

/*
 * A map to store scx_cgroup_llc_ctx. It is accessed through a pair of
 * cgroup id and LLC id (struct cgroup_llc_id).
 */
struct cgroup_llc_id {
	u64		cgrp_id;
	int		llc_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct cgroup_llc_id);
	__type(value, struct scx_cgroup_llc_ctx);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, CBW_NR_CGRP_LLC_MAX);
} cbw_cgrp_llc_map SEC(".maps");

/*
 * A per-CPU map to store levels in traversing a cgroup hierarchy while
 * updating runtime_total_sloppy. The per-CPU map is used to reduce the
 * stack size of cbw_update_runtime_total_sloppy().
 */
struct tree_levels {
	s64		levels[CBW_CGRP_TREE_HEIGHT_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct tree_levels);
	__uint(max_entries, 1);
} tree_levels_map SEC(".maps");

/*
 * Timer to replenish time budget for all cgroups periodically.
 */
struct replenish_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct replenish_timer);
} replenish_timer SEC(".maps") __weak;

static u64		cbw_last_replenish_at;

static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer);

/*
 * Debug macros.
 */
#define cbw_err(fmt, ...) do { 							\
	bpf_printk("[%s:%d] ERROR: " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
} while(0)

#define cbw_info(fmt, ...) do { 						\
	bpf_printk("[%s:%d] INFO: " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
} while(0)

#define cbw_dbg(fmt, ...) do { 							\
	if (cbw_config.verbose > 0)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
} while(0)

/*
 * Check if the kernel support cpu.max for scx schedulers.
 */
static
bool is_kernel_compatible(void)
{
	return bpf_core_field_exists(struct scx_cgroup_init_args, bw_period_us);
}

/**
 * scx_cgroup_bw_lib_init - Initialize the library with a configuration.
 * @config: tunnables, see the struct definition.
 *
 * It should be called for the library initialization before calling any
 * other API.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config)
{
	struct bpf_timer *timer;
	int ret;
	u32 key = 0;

	/* If the kernel does not support cpu.max, let's stop here. */
	if (!is_kernel_compatible()) {
		cbw_err("The kernel does not support the cpu.max for scx.");
		return -ENOTSUP;
	}

	/* Initialize the library-wide configuration. */
	if (!config)
		return -EINVAL;
	cbw_config = *config;

	/* Initialize the replenish timer. */
	timer = bpf_map_lookup_elem(&replenish_timer, &key);
	if (!timer) {
		cbw_err("Failed to lookup replenish timer");
		return -ESRCH;
	}

	cbw_last_replenish_at = scx_bpf_now();
	bpf_timer_init(timer, &replenish_timer, CBW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, replenish_timerfn);
	if ((ret = bpf_timer_start(timer, CBW_NPERIOD, 0))) {
		cbw_err("Failed to start replenish timer");
		return ret;
	}

	return 0;
}

__hidden
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, u64 consumed_ns)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 taskc, u64 vtime, struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_reenqueue(void)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_cancel(u64 taskc)
{
	return -ENOTSUP;
/*
 * A handler function for the replenish timer.
 */
static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	/* TODO: to be implemented */
	return 0;
}
