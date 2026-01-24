/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
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
	/* unlimited quota ("max") from scx_cgroup_init_args and scx_cgroup_bw_set() */
	CBW_RUNTUME_INF_RAW		= ((u64)~0ULL),
	/* unlimited quota ("max"); This is for easier comparison between signed vs. unsigned integers. */
	CBW_RUNTUME_INF			= ((s64)~((u64)1 << 63)),
	/* preferred lower bound of budget transfer unit in nsec (100 msec) */
	CBW_BUDGET_XFER_LB		= (100ULL * 1000ULL * 1000ULL),
	/* absolute minimum budget transfer unit in nsec (20 msec) */
	CBW_BUDGET_XFER_MIN		= (20ULL * 1000ULL * 1000ULL),
	/* maximum budget transfer is (nquota_ub / 2**2) */
	CBW_BUDGET_XFER_MAX_SHIFT	= 2,
	/* maximum number of re-enqueue tasks in one dispatch */
	CBW_REENQ_MAX_BATCH		= 2,
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
 * An array of cgroups that can have tasks. This is necessary to iterate
 * cgroups without holding an RCU lock.
 */
static u64		cbw_nr_taskable_cgroups;
static u64		cbw_taskable_cgroup_ids[CBW_NR_CGRP_MAX];

/*
 * An array of throttled cgroups that need to be reenqueued.
 */
static u64		cbw_nr_throttled_cgroups;
static u64		cbw_throttled_cgroup_ids[CBW_NR_CGRP_MAX];

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
 * The replenish timer running status. The replenish timer is split into two
 * parts: the top half and the bottom half. The top half -- the actual BPF
 * timer function -- runs the essential, critical part, such as refilling the
 * time budget. On the other hand, the bottom half -- scx_cgroup_bw_reenqueue()
 * -- runs on a BPF scheduler's ops.dispatch() and requeues the backlogged
 *  tasks to proper DSQs.
 *
 *    +----------------+
 *    |                |
 *   \+/               |
 *  [IDLE] -> [TOP_HALF_RUNNING] -> [BOTTOM_HALF_READY] -> [BOTTOM_HALF_RUNNING]
 *   /+\             /+\                                            |
 *    |               |                                             |
 *    +-------------------------------------------------------------+
 */
enum replenish_stats {
	/* Nothing related to the replenishment is going on. */
	CBW_REPLENISH_STAT_IDLE			= 0,
	/* The top half of the replenish timer is running. */
	CBW_REPLENISH_STAT_TOP_HALF_RUNNING	= 1,
	/* The top half was done. It is ready to start the bottom-half part. */
	CBW_REPLENISH_STAT_BOTTOM_HALF_READY	= 2,
	/* The bottom half of the replenish timer is running at ops.dispatch(). */
	CBW_REPLENISH_STAT_BOTTOM_HALF_RUNNING	= 3,
};

struct replenish_stat {
	int			s;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

static struct replenish_stat cbw_replenish_stat;

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

#define cbw_dbg_cgrp(fmt, ...) do { 						\
	if (cbw_config.verbose > 0)						\
		bpf_printk("[%s:%d/cgid%llu] " fmt, __func__, __LINE__,		\
			   cgrp->kn->id, ##__VA_ARGS__);			\
} while(0)

#define dbg_cgx(cgx, str, ...) do {						\
	cbw_dbg(str "cgid%llu -- cgx:budget_remaining: %lld -- "		\
		"cgx:runtime_total_last: %lld -- "				\
		"cgx:runtime_total_sloppy: %lld -- "				\
		"cgx:nquota: %lld -- "						\
		"cgx:nquota_ub: %lld -- "					\
		"cgx:is_throttled: %d -- cgx:nr_taskable_descendents: %d -- "	\
		"cgx:budget_p2c: %llu -- cgx:budget_c2l: %llu",			\
		##__VA_ARGS__,							\
		cgx->id, cgx->budget_remaining,					\
		cgx->runtime_total_last, cgx->runtime_total_sloppy,		\
		cgx->nquota, cgx->nquota_ub, cgx->is_throttled,			\
		cgx->nr_taskable_descendents, cgx->budget_p2c, cgx->budget_c2l);\
} while (0);

#define dbg_llcx(llcx, str, ...) do {						\
	cbw_dbg(str "cgid%llu -- llcx:budget_remaining: %lld -- "		\
		"llcx:runtime_total: %lld",					\
		##__VA_ARGS__,							\
		llcx->id,							\
		llcx->budget_remaining, llcx->runtime_total);			\
} while (0);

#define info_cgx(cgx, str, ...) do {						\
	cbw_info(str "cgid%llu -- cgx:budget_remaining: %lld -- "		\
		 "cgx:runtime_total_last: %lld -- "				\
		 "cgx:runtime_total_sloppy: %lld -- "				\
		 "cgx:nquota: %lld -- "						\
		 "cgx:nquota_ub: %lld -- "					\
		 "cgx:is_throttled: %d -- cgx:nr_taskable_descendents: %d -- "	\
		 "cgx:budget_p2c: %llu -- cgx:budget_c2l: %llu",		\
		 ##__VA_ARGS__,							\
		 cgx->id, cgx->budget_remaining,				\
		 cgx->runtime_total_last, cgx->runtime_total_sloppy,		\
		 cgx->nquota, cgx->nquota_ub, cgx->is_throttled,		\
		 cgx->nr_taskable_descendents, cgx->budget_p2c, cgx->budget_c2l);\
} while (0);

/*
 * Arithmetic helpers.
 */
#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef clamp
#define clamp(val, lo, hi) min(max(val, lo), hi)
#endif

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

static
bool cgroup_is_threaded(struct cgroup *cgrp)
{
	return cgrp->dom_cgrp != cgrp;
}

static
u64 cgroup_get_id(struct cgroup *cgrp)
{
	return cgrp->kn->id;
}

static
struct scx_cgroup_ctx *cbw_get_cgroup_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cbw_cgrp_map, cgrp, 0, 0);
}

long cbw_del_cgroup_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_delete(&cbw_cgrp_map, cgrp);
}

static
struct scx_cgroup_llc_ctx *cbw_alloc_llc_ctx(struct cgroup *cgrp,
					     struct scx_cgroup_ctx *cgx,
					     int llc_id)
{
	static const struct scx_cgroup_llc_ctx llcx0;
	struct scx_cgroup_llc_ctx *llcx;
	struct cgroup_llc_id key = {
		.cgrp_id = cgroup_get_id(cgrp),
		.llc_id = llc_id,
	};

	/* Allocate an LLC context on the map. */
	if (bpf_map_update_elem(&cbw_cgrp_llc_map, &key, &llcx0, BPF_NOEXIST))
		return NULL;

	llcx = bpf_map_lookup_elem(&cbw_cgrp_llc_map, &key);
	if (!llcx)
		return NULL;
	llcx->id = cgroup_get_id(cgrp);

	/* Create an associated BTQ. */
	llcx->btq = (scx_atq_t *)scx_atq_create(false);
	if (!llcx->btq) {
		cbw_err("Fail to allocate a BTQ");
		bpf_map_delete_elem(&cbw_cgrp_llc_map, &key);
		return NULL;
	}

	/*
	 * Set beduget_remaining to infinity in advance
	 * if there is no upper bound.
	 */
	if (cgx->nquota_ub == CBW_RUNTUME_INF)
		llcx->budget_remaining = CBW_RUNTUME_INF;

	return llcx;
}

static
struct scx_cgroup_llc_ctx *cbw_get_llc_ctx_with_id(u64 cgrp_id, int llc_id)
{
	struct cgroup_llc_id key = {
		.cgrp_id = cgrp_id,
		.llc_id = llc_id,
	};

	return bpf_map_lookup_elem(&cbw_cgrp_llc_map, &key);
}

static
struct scx_cgroup_llc_ctx *cbw_get_llc_ctx(struct cgroup *cgrp, int llc_id)
{
	return cbw_get_llc_ctx_with_id(cgroup_get_id(cgrp), llc_id);
}

static
long cbw_del_llc_ctx(struct cgroup *cgrp, int llc_id)
{
	struct cgroup_llc_id key = {
		.cgrp_id = cgroup_get_id(cgrp),
		.llc_id = llc_id,
	};

	return bpf_map_delete_elem(&cbw_cgrp_llc_map, &key);
}

static
int cbw_init_llc_ctx(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	int i;

	if (!cgx || !cgrp)
		return -EINVAL;

	bpf_for(i, 0, TOPO_NR(LLC)) {
		struct scx_cgroup_llc_ctx *llcx;

		llcx = cbw_alloc_llc_ctx(cgrp, cgx, i);
		if (!llcx)
			return -ENOMEM;
	}
	cgx->has_llcx = true;

	return 0;
}

static
void cbw_free_llc_ctx(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_llc_ctx *llcx;
	int i;

	if (!cgrp || !cgx || !cgx->has_llcx)
		return;

	cgx->has_llcx = false;
	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx(cgrp, i);
		if (!llcx)
			break;

		if (scx_atq_nr_queued(llcx->btq)) {
			cbw_err("Throttled tasks should not be in an existing cgroup: [%llu/%d]",
				cgx->id, i);
		}

		if (cbw_del_llc_ctx(cgrp, i)) {
			cbw_err("Failed to delete an LLC context: [%llu/%d]",
				cgx->id, i);
			continue;
		}

		/* TODO: Note that ATQ does not provide an API to delete itself. */
	}
}

static
void cbw_set_bandwidth(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx,
		       u64 period_us, u64 quota_us, u64 burst_us)
{
	cgx->quota = quota_us * 1000;
	cgx->period = period_us * 1000;
	cgx->period_start_clk = scx_bpf_now();

	if (quota_us == CBW_RUNTUME_INF_RAW) {
		cgx->nquota = CBW_RUNTUME_INF;
		cgx->burst = 0;
	} else {
		cgx->nquota = div_round_up(quota_us * CBW_NPERIOD, period_us);
		cgx->burst = burst_us * 1000;
	}
	cgx->burst_remaining = cgx->burst;
}

static
s64 cbw_calc_budget_tx(struct scx_cgroup_ctx *cgx, s64 base_unit, int nr_branch)
{
	s64 tgt_unit, budget_tx;

	if (nr_branch <= 0)
		nr_branch = 1;

	if (nr_branch > 1)
		nr_branch <<= CBW_BUDGET_XFER_MAX_SHIFT;

	if (base_unit == 0)
		base_unit = cgx->nquota_ub;

	tgt_unit = div_round_up((u64)base_unit, (u64)nr_branch);

	if (cgx->nquota_ub <= CBW_BUDGET_XFER_LB)
		budget_tx = clamp(tgt_unit, CBW_BUDGET_XFER_MIN, cgx->nquota_ub);
	else
		budget_tx = clamp(tgt_unit, CBW_BUDGET_XFER_LB, cgx->nquota_ub);

	cbw_dbg("cgid%llu -- base_unit: %lld -- nr_branch: %d -- "
		"tgt_unit: %lld -- budget_tx: %lld -- nquota_ub: %lld",
		cgx->id, base_unit, nr_branch, tgt_unit, budget_tx, cgx->nquota_ub);

	return budget_tx;
}

static
void cbw_update_budget_tx(struct scx_cgroup_ctx *subroot_cgx,
			  struct scx_cgroup_ctx *cgx)
{
	int nr_branch_cgs;
	s64 base;

	base = (subroot_cgx == cgx) ? subroot_cgx->nquota_ub :
				      subroot_cgx->budget_p2c;
	if (base != CBW_RUNTUME_INF) {
		nr_branch_cgs = ((subroot_cgx == cgx) ? cgx->nr_taskable_descendents : 0) +
				(cgx->has_llcx ? 1 : 0);
		cgx->budget_p2c = cbw_calc_budget_tx(cgx, base, nr_branch_cgs);
	} else
		cgx->budget_p2c = CBW_RUNTUME_INF;

	base = cgx->budget_p2c;
	if (base != CBW_RUNTUME_INF)
		cgx->budget_c2l = cbw_calc_budget_tx(cgx, base, TOPO_NR(LLC));
	else
		cgx->budget_c2l = CBW_RUNTUME_INF;
}

__noinline
int cbw_update_nquota_ub(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_ctx *parentx, *subroot_cgx;
	struct cgroup *parent, *subroot_cgrp;

	if (!cgx || !cgrp)
		return -EINVAL;

	/*
	 * We assume that all its ancestors' nquota_ub are already updated
	 * (e.g., pre-order traversal of the cgroup tree). Hence, we don't
	 * need to walk up all its ancestors to get the minimum, so we compare
	 * against its parent's nquota_ub.
	 */
	cgx->nquota_ub = cgx->nquota;
	if ((cgrp->level > 1) &&
	    (parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1))) {
		parentx = cbw_get_cgroup_ctx(parent);
		if (!parentx) {
			cbw_err("Fail to lookup a cgroup context: %llu",
				cgroup_get_id(parent));
			bpf_cgroup_release(parent);
			return -ESRCH;
		}

		cgx->nquota_ub = min(cgx->nquota_ub, parentx->nquota);
		bpf_cgroup_release(parent);
	}

	/* Update the budget transfer unit according to the new nquota_ub. */
	if (cgrp->level > 1) {
		subroot_cgrp = bpf_cgroup_ancestor(cgrp, 1);
		if (!subroot_cgrp) {
			cbw_err("Failed to lookup a subroot cgroup: %llu",
				cgroup_get_id(cgrp));
			return -ESRCH;
		}

		subroot_cgx = cbw_get_cgroup_ctx(subroot_cgrp);
		if (!subroot_cgx) {
			cbw_err("Failed to lookup a subroot context: %llu",
				cgroup_get_id(subroot_cgrp));
			bpf_cgroup_release(subroot_cgrp);
			return -ESRCH;
		}
		bpf_cgroup_release(subroot_cgrp);
	} else
		subroot_cgx = cgx;

	cbw_update_budget_tx(subroot_cgx, cgx);
	return 0;
}

static
int cbw_update_nr_taskable_descendents(struct cgroup *cgrp, int delta)
{
	struct cgroup_subsys_state *subroot_css, *pos;
	struct scx_cgroup_ctx *subroot_cgx, *cur_cgx;
	struct cgroup *subroot_cgrp, *cur_cgrp;

	/* It is above the subroot-level (i.e., root). Skip it. */
	if (cgrp->level < 1)
		return 0;

	/*
	 * Update the number of taskable descendants of the cgroup's subroot.
	 *
	 * Note that we distribute the budget in two cases:
	 *  1) a subroot cgroup * distributes the budget to all its taskable
	 *     descendents; and
	 *  2) a taskable cgroup distributes the budget to all its LLC domains.
	 * So nr_taskable_descendents matters only for subroot cgroups.
	 */
	subroot_cgrp = bpf_cgroup_ancestor(cgrp, 1);
	if (!subroot_cgrp) {
		cbw_err("Failed to lookup a subroot cgroup: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	subroot_cgx = cbw_get_cgroup_ctx(subroot_cgrp);
	if (!subroot_cgx) {
		cbw_err("Failed to lookup a subroot context: %llu",
			cgroup_get_id(subroot_cgrp));
		bpf_cgroup_release(subroot_cgrp);
		return -ESRCH;
	}

	/*
	 * Update the budget transfer unit accordingto the new
	 * nr_taskable_descendents of a subroot. Since a budget transfer
	 * unit of a subroot cgroup is updated, all its descendants
	 * should be updated as well.
	 */
	subroot_cgx->nr_taskable_descendents += delta;
	cbw_update_budget_tx(subroot_cgx, subroot_cgx);

	bpf_rcu_read_lock();
	subroot_css = &subroot_cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx)
			continue;
		cbw_update_budget_tx(subroot_cgx, cur_cgx);
	}
	bpf_rcu_read_unlock();

	bpf_cgroup_release(subroot_cgrp);
	return 0;
}

/**
 * scx_cgroup_bw_init - Initialize a cgroup for CPU bandwidth control.
 * @cgrp: cgroup being initialized.
 * @args: init arguments, see the struct definition.
 *
 * Either the BPF scheduler is being loaded or @cgrp created, initialize
 * @cgrp for CPU bandwidth control. When being loaded, cgroups are initialized
 * in a pre-order from the root. This operation may block.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted)
{
	struct scx_cgroup_ctx *cgx, *parentx;
	struct cgroup *parent;
	int ret;

	cbw_dbg_cgrp(" level: %d -- period_us: %llu -- quota_us: %llu -- burst_us: %llu ",
		     cgrp->level, args->bw_period_us, args->bw_quota_us, args->bw_burst_us);

	/*
	 * Allocate and initialize scx_cgroup_ctx for @cgrp.
	 *
	 * For the cgroup directly under the root cgroup
	 * (i.e., its level == 1), budget the full quota to itself,
	 * so the cgroup can distribute the budget to its descendants
	 * when requested.
	 */
	cgx = bpf_cgrp_storage_get(&cbw_cgrp_map, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgx) {
		cbw_err("Failed to allocate cgroup ctx: %llu",
			cgroup_get_id(cgrp));
		return -ENOMEM;
	}

	cgx->id = cgroup_get_id(cgrp);
	cbw_set_bandwidth(cgrp, cgx, args->bw_period_us, args->bw_quota_us,
			  args->bw_burst_us);
	cbw_update_nquota_ub(cgrp, cgx);
	cgx->runtime_total_sloppy = 0;
	cgx->budget_remaining = (cgrp->level == 1)? cgx->nquota : 0;
	cgx->is_throttled = false;

	/*
	 * The parent of @cgrp becomes non-leaf. If the parent is not
	 * threaded, it cannot have tasks. So, we should free its
	 * per-LLC-cgroup contexts.
	 *
	 * Note that the root cgroup always has LLC contexts and its
	 * associated BTQs since its level is 0.
	 */
	if ((cgrp->level > 0) &&
	    (parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1))) {
		parentx = cbw_get_cgroup_ctx(parent);
		if (parentx && !cgroup_is_threaded(parent)) {
			cbw_free_llc_ctx(parent, parentx);
			cbw_update_nr_taskable_descendents(parent, -1);
		}
		bpf_cgroup_release(parent);
	}

	/*
	 * Create per-LLC-cgroup contexts if @cgrp can have tasks (i.e.,
	 * a cgroup is either at the leaf level or threaded). Here, @cgrp
	 * is at the leaf (a cgroup is a leaf until its child is created),
	 * so we will create per-LLC-cgroup contexts anyway.
	 */
	ret = cbw_init_llc_ctx(cgrp, cgx);
	if (ret)
		return ret;

	/*
	 * Increase the number of taskable descendants of the cgroup's subroot.
	 */
	cgx->nr_taskable_descendents = 1;
	return cbw_update_nr_taskable_descendents(cgrp, 1);
}

/**
 * scx_cgroup_bw_exit - Exit a cgroup.
 * @cgrp: cgroup being exited
 *
 * Either the BPF scheduler is being unloaded or @cgrp destroyed, exit
 * @cgrp for sched_ext. This operation my block.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted)
{
	int ret;

	cbw_dbg_cgrp();
	if (cgrp->level > 1) {
		if ((ret = cbw_update_nr_taskable_descendents(cgrp, -1)))
			return ret;
	}

	cbw_del_cgroup_ctx(cgrp);
	cbw_free_llc_ctx(cgrp, NULL);
	return 0;
}

/**
 * scx_cgroup_bw_set - A cgroup's bandwidth is being changed.
 * @cgrp: cgroup whose bandwidth is being updated
 * @period_us: bandwidth control period
 * @quota_us: bandwidth control quota
 * @burst_us: bandwidth control burst
 *
 * Update @cgrp's bandwidth control parameters. This is from the cpu.max
 * cgroup interface.
 *
 * @quota_us / @period_us determines the CPU bandwidth @cgrp is entitled
 * to. For example, if @period_us is 1_000_000 and @quota_us is
 * 2_500_000. @cgrp is entitled to 2.5 CPUs. @burst_us can be
 * interpreted in the same fashion and specifies how much @cgrp can
 * burst temporarily. The specific control mechanism and thus the
 * interpretation of @period_us and burstiness is upto to the BPF
 * scheduler.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us)
{
	struct cgroup *cur_cgrp, *cur_cgrp_trusted;
	struct scx_cgroup_ctx *cgx, *cur_cgx;
	struct cgroup_subsys_state *subroot_css, *pos;
	int ret = 0;

	cbw_dbg_cgrp();

	/* Update the cgroup's bandwidth. */
	cgx = cbw_get_cgroup_ctx(cgrp);
	if (!cgx) {
		cbw_err("Failed to lookup a cgroup ctx: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	cbw_set_bandwidth(cgrp, cgx, period_us, quota_us, burst_us);

	/*
	 * Update nquota_ub of the cgroup and all its descendents in a
	 * top-down-like manner (pre-order traversal: self -> left -> right).
	 */
	bpf_rcu_read_lock();
	subroot_css = &cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgrp_trusted = bpf_cgroup_from_id(cgroup_get_id(cur_cgrp));
		if (!cur_cgrp_trusted)
			continue;
	
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp_trusted);
		if (!cur_cgx) {
			/*
			 * The CPU controller is not enabled for this cgroup.
			 * Let's move on.
			 */
			bpf_cgroup_release(cur_cgrp_trusted);
			continue;
		}

		ret = cbw_update_nquota_ub(cur_cgrp_trusted, cur_cgx);
		bpf_cgroup_release(cur_cgrp_trusted);
		if (ret)
			goto unlock_out;
	}
unlock_out:
	bpf_rcu_read_unlock();
	return ret;
}

static
bool is_llc_id_valid(int llc_id)
{
	return llc_id >= 0 && llc_id < TOPO_NR(LLC);
}

static
s64 cbw_sum_rumtime_total_llcx(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_llc_ctx *llcx;
	s64 sum;
	int i;

	if (!cgx->has_llcx)
		return 0;

	sum = 0;
	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx(cgrp, i);
		if (!llcx)
			break;
		sum += READ_ONCE(llcx->runtime_total);
	}
	return sum;
}

static
struct tree_levels *get_clean_tree_levels(void)
{
	const u32 idx = 0;
	struct tree_levels *tree;

	tree = bpf_map_lookup_elem(&tree_levels_map, &idx);
	if (tree)
		__builtin_memset(tree, 0, sizeof(*tree));

	return tree;
}

static
int cbw_update_runtime_total_sloppy(struct cgroup *cgrp)
{
	u32 cur_level, prev_level = CBW_CGRP_TREE_HEIGHT_MAX;
	struct cgroup_subsys_state *subroot_css, *pos;
	struct scx_cgroup_ctx *cur_cgx = NULL;
	struct tree_levels *tree;
	struct cgroup *cur_cgrp;
	s64 rt_llcx;
	int ret = 0;


	tree = get_clean_tree_levels();
	if (!tree)
		return -ENOMEM;

	/*
	 * Suppose the following cgroup hierarchy with cgroup name and level.
	 * (cgroup_root:0
	 *	(A:1
	 *		(D:2
	 *		 E:2))
	 *	(B:1)
	 *	(C:1
	 *		(F:2
	 *		 G:2)))
	 *
	 * The post-order traversal of the tree is as follows:
	 *   D:2 -> E:2 -> A:1 -> B:1 -> F:2 -> G:2 -> C:1 -> cgroup_root:0
	 *
	 * We traverse the tree in a post-order (left-right-self). We first
	 * update the runtime_total_sloppy (rts) to the fresh value. Then,
	 * we aggregate the runtime_total_sloppy values at the same level
	 * (e.g., D:2 and E:2). When we visit an upper level (e.g., A:1),
	 * we put the aggregate value in the upper level (A:1).
	 *
	 * Note that refreshing runtime_total_sloppy is racy because we do
	 * not coordinate multiple, concurrent CPUs to consume budget and
	 * update runtime_total_sloppy intentionally. That is because the
	 * coordination (e.g., locking) is more expensive than computation,
	 * especially on the critical path. Furthermore, the slight inaccuracy
	 * does not harm and will be compensated for over time.
	 */
	bpf_rcu_read_lock();
	subroot_css = &cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
		/*
		 * We first obtain the up-to-date value of runtime_total
		 * of its LLC contexts if they exist.
		 */
		cur_cgrp = pos->cgroup;
		cur_level = cur_cgrp->level;
		if (cur_level == 0 && can_loop) /* cgroup_root */
			break;
		if (cur_level >= CBW_CGRP_TREE_HEIGHT_MAX) {
			ret = -E2BIG;
			break;
		}
		if (prev_level == CBW_CGRP_TREE_HEIGHT_MAX)
			prev_level = cur_level;

		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			/*
			 * The CPU controller of this cgroup is not enabled
			 * so that we can skip it safely.
			 */
			continue;
		}

		rt_llcx = cbw_sum_rumtime_total_llcx(cur_cgrp, cur_cgx);

		/*
		 * When traversing the siblings (e.g., D:2 -> E2, A:1 -> B:1,
		 * B:1 -> C:1), the previous and current levels are the same.
		 *
		 * This means the current cgroup does not have children.
		 * Hence, its runtime_total_sloppy is the sum of runtime_total
		 * of its LLC contexts (i.e., rt_llcx).
		 */
		if (prev_level == cur_level) {
			WRITE_ONCE(cur_cgx->runtime_total_sloppy, rt_llcx);
		}
		/*
		 * When starting to travel the subtree of a sibling (e.g.,
		 * B:1 -> F:2), the current level is larger than the previous
		 * level.
		 *
		 * This means the current cgroup does not have children.
		 * Hence, its runtime_total_sloppy is the sum of runtime_total
		 * of its LLC contexts (i.e., rt_llcx).
		 */
		else if (prev_level < cur_level) {
			WRITE_ONCE(cur_cgx->runtime_total_sloppy, rt_llcx);
		}
		/*
		 * Once finishing the traversal of all its siblings (e.g.,
		 * D:2 E:2 -> A1, F:2 G:2 -> C:1), the current level is smaller
		 * than the previous level.
		 *
		 * This means that the current cgroup is a parent of cgroups
		 * in the previous level. Hence, we should aggregate all
		 * children's runtime_total_sloppy (i.e., levels[prev_level])
		 * and the sum of runtime_total of its LLC contexts (i.e.,
		 * rt_llcx).
		 *
		 * Since we finished a subtree, we should reset the accumulated
		 * runtime_total_sloppy value of the previous level (i.e.,
		 * levels[prev_level] = 0).
		 */
		else if (prev_level > cur_level) {
			WRITE_ONCE(cur_cgx->runtime_total_sloppy,
				   tree->levels[prev_level] + rt_llcx);
			tree->levels[prev_level] = 0;
		}

		/* If the cgroup reached the upper bound, mark it throttled. */
		if (cur_cgx->runtime_total_sloppy >= cur_cgx->nquota_ub)
			WRITE_ONCE(cur_cgx->is_throttled, true);

		/* Aggregate this cgroup's runtime_total_sloppy to the level. */
		tree->levels[cur_level] += cur_cgx->runtime_total_sloppy;
		
		/* Update the previous level. */
		prev_level = cur_level;

		cbw_dbg("cgid%llu -- rt_llcx: %lld -- runtime_total_sloppy: %lld",
			cur_cgx->id, rt_llcx, cur_cgx->runtime_total_sloppy);
	}
	bpf_rcu_read_unlock();

	return ret;
}

static
s64 cbw_transfer_budget_c2l(struct scx_cgroup_ctx *src_cgx, int src_level,
			    struct scx_cgroup_llc_ctx *tgt_llcx)
{
	s64 remaining, debt, b;

	/*
	 * We move the budget from a cgroup level to the LLC level by
	 * budget_c2l at a time until enough budget is secured at the LLC
	 * level, or the budget at the cgroup level becomes empty.
	 */
	do {
		remaining = READ_ONCE(tgt_llcx->budget_remaining);
		if (remaining > 0)
			return remaining;
		debt = -remaining;

		remaining = READ_ONCE(src_cgx->budget_remaining);
		if (remaining <= 0)
			break;
		b = min(debt + src_cgx->budget_c2l, remaining);

		__sync_fetch_and_sub(&src_cgx->budget_remaining, b);
		__sync_fetch_and_add(&tgt_llcx->budget_remaining, b);
	} while ((READ_ONCE(tgt_llcx->budget_remaining) <= 0) &&
		 (READ_ONCE(src_cgx->budget_remaining) > 0) && can_loop);

	/*
	 * When there is no remaining budget in the subroot cgroup,
	 * throttle the cgroup here. That is because there is nowhere
	 * to borrow budget.
	 */
	if ((src_level == 1) && (READ_ONCE(tgt_llcx->budget_remaining) < 0))
		WRITE_ONCE(src_cgx->is_throttled, true);

	return READ_ONCE(tgt_llcx->budget_remaining);
}

static
s64 cbw_transfer_budget_p2c(struct scx_cgroup_ctx *subroot_cgx,
			    struct scx_cgroup_ctx *tgt_cgx)
{
	s64 remaining, debt, b;

	/*
	 * We move the budget from a subroot cgroup level to the leaf/threaded
	 * cgroup level by budget_p2c at a time until enough budget is secured
	 * or the budget at the subroot cgroup level becomes empty.
	 */
	do {
		remaining = READ_ONCE(tgt_cgx->budget_remaining);
		if (remaining > 0)
			return remaining;
		debt = -remaining;

		remaining = READ_ONCE(subroot_cgx->budget_remaining);
		if (remaining <= 0)
			break;
		b = min(debt + subroot_cgx->budget_p2c, remaining);

		__sync_fetch_and_sub(&subroot_cgx->budget_remaining, b);
		__sync_fetch_and_add(&tgt_cgx->budget_remaining, b);
	} while ((READ_ONCE(tgt_cgx->budget_remaining) <= 0) &&
		 (READ_ONCE(subroot_cgx->budget_remaining) > 0) && can_loop);

	/*
	 * When there is no remaining budget in the subroot cgroup,
	 * throttle the subroot cgroup here. That is because there is
	 * nowhere to borrow budget. Note that we always borrow budget
	 * from the subroot cgroup, so a source cgroup is always a
	 * subroot cgroup.
	 */
	if (READ_ONCE(subroot_cgx->budget_remaining) < 0)
		WRITE_ONCE(subroot_cgx->is_throttled, true);

	return READ_ONCE(tgt_cgx->budget_remaining);
}

static
s64 cbw_transfer_budget_p2l(struct scx_cgroup_ctx *subroot_cgx,
			    struct scx_cgroup_ctx *tgt_cgx,
			    int tgt_level,
			    struct scx_cgroup_llc_ctx *tgt_llcx)
{
	s64 remaining;

	if (READ_ONCE(subroot_cgx->budget_remaining) <= 0)
		return READ_ONCE(tgt_llcx->budget_remaining);

	/*
	 * We move the budget from the subroot cgroup to the target cgroup,
	 * then finally to the target LLC context.
	 */
	do {
		remaining = cbw_transfer_budget_p2c(subroot_cgx, tgt_cgx);
		if (remaining <= 0) {
			/*
			 * If there is no remaining budget in the subroot
			 * cgroup, we should throttle the cgroup.
			 */
			WRITE_ONCE(tgt_cgx->is_throttled, true);
			break;
		}

		remaining = cbw_transfer_budget_c2l(tgt_cgx, tgt_level, tgt_llcx);
	} while((remaining <= 0) && can_loop);

	return READ_ONCE(tgt_llcx->budget_remaining);
}

static 
void cbw_consume_budget(struct scx_cgroup_ctx *cgx,
			struct scx_cgroup_llc_ctx *llcx, u64 consumed_ns)
{
	s64 period_duration;

	/*
	 * If the runtime is infinite, we don't need to update runtime_total
	 * and budget_remaining, which saves cache coherence traffic.
	 */
	if (llcx->budget_remaining == CBW_RUNTUME_INF)
		return;

	/*
	 * When budget consumption occurs across two periods,
	 * account only for the time of this period.
	 *
	 *  <-- period 1 --><-- period 2 -->
	 *       \== consumed_ns ==/
	 */
	period_duration = time_delta(scx_bpf_now(),
				     READ_ONCE(cgx->period_start_clk));
	if (consumed_ns > period_duration) {
		consumed_ns = period_duration;
	}

	/* Decrease the budget budget_remaining */
	__sync_fetch_and_sub(&llcx->budget_remaining, consumed_ns);

	/* Increase the total runtime */
	__sync_fetch_and_add(&llcx->runtime_total, consumed_ns);
}

static
int cbw_get_current_llc_id(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	return topo_cpu_to_llc_id(cpu);
}

int cbw_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted, int llc_id)
{
	struct scx_cgroup_ctx *cgx, *subroot_cgx;
	struct scx_cgroup_llc_ctx *llcx;
	struct cgroup *subroot_cgrp;
	int ret;

	/* Always go ahead with the root cgroup. */
	if (cgrp->level == 0)
		return 0;

	/* Sanity check of the LLC id. */
	if (!is_llc_id_valid(llc_id)) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * If the budget remains at the LLC level, let's reserve it and go
	 * ahead.
	 *
	 * Note that we overbook the time on purpose. That is because it is
	 * better to overbook the cgroup. If underbooked, the cgroup's
	 * quota won't be fully consumed, and the remaining time won't be
	 * accumulated. On the other hand, if overbooked, the cgroup's quota
	 * will be fully utilized, and its debt will be charged over time.
	 */
	llcx = cbw_get_llc_ctx(cgrp, llc_id);
	if (!llcx) {
		cbw_err("Failed to lookup an LLC ctx: [%llu/%d]",
			cgroup_get_id(cgrp), llc_id);
		return -ESRCH;
	}
	cbw_dbg_cgrp("  llc_id: %d -- llcx:budget_remaining: %lld",
		     llc_id, READ_ONCE(llcx->budget_remaining));

	if (READ_ONCE(llcx->budget_remaining) > 0)
		return 0;

	/*
	 * If the budget remains at the cgroup level, transfer the cgroup's
	 * budget to the LLC level by budget_c2l.
	 */
	cgx = cbw_get_cgroup_ctx(cgrp);
	if (!cgx) {
		cbw_err("Failed to lookup a cgroup ctx: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	if (READ_ONCE(cgx->is_throttled)) {
		dbg_cgx(cgx, "throttled: ");
		return -EAGAIN;
	}

	if (cbw_transfer_budget_c2l(cgx, cgrp->level, llcx) > 0) {
		dbg_cgx(cgx, "budget-transfer-to-leaf: ");
		dbg_llcx(llcx, "budget-transfer-to-llcx: ");
		return 0;
	}

	/*
	 * There is no budget remaining at the cgroup level. Before asking
	 * more budget to its subroot cgroup, let's first check whether the
	 * cgroup is already hit the upper bound.
	 */
	cbw_update_runtime_total_sloppy(cgrp);

	if (READ_ONCE(cgx->is_throttled)) {
		dbg_cgx(cgx, "throttled: ");
		return -EAGAIN;
	}

	/*
	 * There is no budget remaining at the cgroup level, and the cgroup is
	 * not throttled yet. Let's secure budget from the subroot cgroup.
	 * If this cgroup is a subroot (level == 1), there is nothing to do.
	 */
	if (cgrp->level == 1) {
		dbg_cgx(cgx, "throttled: ");
		return -EAGAIN;
	}

	subroot_cgrp = bpf_cgroup_ancestor(cgrp, 1);
	if (!subroot_cgrp) {
		cbw_err("Failed to lookup a subroot cgroup: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	subroot_cgx = cbw_get_cgroup_ctx(subroot_cgrp);
	if (!subroot_cgx) {
		cbw_err("Failed to lookup a cgroup ctx: %llu",
			cgroup_get_id(subroot_cgrp));
		ret = -ESRCH;
		goto release_out;
	}

	if (cbw_transfer_budget_p2l(subroot_cgx, cgx, cgrp->level, llcx) > 0) {
		dbg_cgx(subroot_cgx, "budget-transfer-to-subroot_cgx: ");
		dbg_cgx(cgx, "budget-transfer-to-cgx: ");
		dbg_llcx(llcx, "budget-transfer-to-llcx: ");
		ret = 0;
		goto release_out;
	}

	/*
	 * Unfortunately, there is not enough budget in the subroot cgroup.
	 * The cgroup is throttled before reaching the upper bound (nquota_ub).
	 * This can happen in various cases. For example, this cgroup's
	 * siblings have already spent too much budget, so there is no
	 * remaining budget for this cgroup.
	 */
	ret = -EAGAIN;
	dbg_cgx(subroot_cgx, "subroot_cgx:throttled: ");
	dbg_cgx(cgx, "cgx:throttled: ");
	dbg_llcx(llcx, "llcx:throttled: ");
release_out:
	bpf_cgroup_release(subroot_cgrp);
	return ret;
}

/**
 * scx_cgroup_bw_throttled - Check if the cgroup is throttled or not.
 * @cgrp: cgroup where a task belongs to.
 *
 * Return 0 when the cgroup is not throttled,
 * -EAGAIN when the cgroup is throttled, and
 * -errno for some other failures.
 */
__hidden
int scx_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted)
{
	int llc_id;

	/* Get the current LLC ID. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	return cbw_cgroup_bw_throttled(cgrp, llc_id);
}

/**
 * scx_cgroup_bw_consume - Consume the time actually used after the task execution.
 * @cgrp: cgroup where a task belongs to.
 * @consumed_ns: amount of time actually used.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, u64 consumed_ns)
{
	struct scx_cgroup_llc_ctx *llcx;
	struct scx_cgroup_ctx *cgx;
	int llc_id;

	/* Always go ahead with the root cgroup. */
	if (cgrp->level == 0)
		return 0;

	/* Get the current LLC ID. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * Update the budget usage.
	 *
	 * Note that the budget can be reserved in an LLC domain and then
	 * actually used in another LLC domain. However, that is not a problem
	 * because LLC's runtime_total will be aggregated to the cgroup level
	 * at reservation.
	 */
	cgx = cbw_get_cgroup_ctx(cgrp);
	llcx = cbw_get_llc_ctx(cgrp, llc_id);
	if (!cgx || !llcx) {
		/*
		 * When exiting a scx scheduler, the sched_ext kernel shuts
		 * down cgroup support before tasks. Hence, failing to look
		 * up an LLC context is quite normal in this case.
		 */
		return 0;
	}

	cbw_consume_budget(cgx, llcx, consumed_ns);

	cbw_dbg_cgrp("  llc_id: %d -- reserved_ns: %llu -- consumed_ns: %llu -- llcx:budget_remaining: %lld -- llcx:runtime_total: %lld",
		     llc_id, consumed_ns, READ_ONCE(llcx->budget_remaining),
		     READ_ONCE(llcx->runtime_total));
	return 0;
}

/**
 * scx_cgroup_bw_put_aside - Put aside a task to execute it when the cgroup is
 * unthrottled later.
 * @p: a task to be put aside since the cgroup is throttled.
 * @taskc: a task-embedded pointer to scx_task_common.
 * @vtime: vtime of a task @p.
 * @cgrp: cgroup where a task belongs to.
 *
 * When a cgroup is throttled (i.e., scx_cgroup_bw_reserve() returns -EAGAIN),
 * a task that is in the ops.enqueue() path should be put aside to the BTQ of
 * its associated LLC context. When the cgroup becomes unthrottled again,
 * the registered enqueue_cb() will be called to re-enqueue the task for
 * execution.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 ctx, u64 vtime, struct cgroup *cgrp __arg_trusted)
{
	scx_task_common *taskc = (scx_task_common *)ctx;
	struct scx_cgroup_llc_ctx *llcx;
	int llc_id, ret;

	cbw_dbg_cgrp(" [%s/%d]", p->comm, p->pid);

	/* Get the current LLC ID. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * Put aside the task to the BTQ of the LLC context.
	 */
	llcx = cbw_get_llc_ctx(cgrp, llc_id);
	if (!llcx) {
		cbw_err("Failed to lookup an LLC ctx: [%llu/%d]",
			cgroup_get_id(cgrp), llc_id);
		return -ESRCH;
	}

	if (!llcx->btq) {
		cbw_err("BTQ of an LLC ctx is not properly initialized.");
		return -ESRCH;
	}

	ret = scx_atq_lock(llcx->btq);
	if (ret) {
		cbw_err("Failed to lock ATQ.");
		return -EBUSY;
	}

	if (taskc->atq != NULL) {
		/* 
		 * Not really a bug: The initial .enqueue() may race with
		 * a pair of .dequeue()/.enqueue() calls, and cause two
		 * instances of this function to happen simultaneously
		 * for the task. This should be rare, but possible.
		 * The spinlock turns the race into a benign one.
		 */
		cbw_dbg("Possible double enqueue detected.");
		scx_atq_unlock(llcx->btq);
		return 0;
	}

	ret = scx_atq_insert_vtime_unlocked(llcx->btq, taskc, vtime);
	if (ret)
		cbw_err("Failed to insert a task to BTQ: %d", ret);

	scx_atq_unlock(llcx->btq);

	return ret;
}

static
bool cbw_has_backlogged_tasks(struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_llc_ctx *llcx;
	int i;

	if (!cgx || !cgx->has_llcx)
		return false;

	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx_with_id(cgx->id, i);
		if (!llcx)
			break;

		if (scx_atq_nr_queued(llcx->btq))
			return true;
	}

	return false;
}

static
bool cbw_replenish_taskable_cgroup(struct scx_cgroup_ctx *cgx, int level, u64 now)
{
	struct scx_cgroup_llc_ctx *llcx;
	s64 burst = 0, debt = 0, budget;
	bool period_end;
	int i;

	/*
	 * If the quota is infinite, we don't need to replenish the cgroup.
	 */
	if (cgx->nquota == CBW_RUNTUME_INF)
		goto out_no_replenish;

	/*
	 * Calculate the burst time, which is the remaining time to carry over.
	 */
	period_end = time_delta(now, cgx->period_start_clk) >= cgx->period;
	if (period_end)
		WRITE_ONCE(cgx->period_start_clk, now);

	debt = cgx->runtime_total_last - cgx->nquota_ub;
	if ((cgx->burst > 0) && (debt < 0)) {
		burst = min(-debt, cgx->burst_remaining);

		if (period_end)
			cgx->burst_remaining = cgx->burst;
		else
			cgx->burst_remaining -= burst;
	}

	/*
	 * Replenish the quota at the cgroup level, considering the burst.
	 *
	 * We need to replenish budget_remaining at the subroot level
	 * (level == 1) because only the subroot cgroup distributes the budget
	 * to its descendants. For the non-sburoot level, we only carry over
	 * the burst.
	 *
	 * Note that the carry-over of the (positive) remaining budget is
	 * limited by the burst. However, the debt should be paid off for
	 * eventual bandwidth control.
	 */
	dbg_cgx(cgx, "replenishing: ");
	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx_with_id(cgx->id, i);
		if (llcx && (READ_ONCE(llcx->budget_remaining) < 0))
			WRITE_ONCE(llcx->budget_remaining, 0);
	}

	budget = ((level == 1) ? cgx->nquota_ub : 0) +
		 ((debt > 0) ? -debt : burst);
	WRITE_ONCE(cgx->budget_remaining, budget);
	dbg_cgx(cgx, "replenished: ");

out_no_replenish:
	/*
	 * If the cgroup is throttled or has backlogged tasks, return true
	 * so the cgroup's backlogged tasks can be reenqueued. Note that
	 * unthrottled tasks can still have backlogged tasks if reenqueuing
	 * them could not finish within one replenish period.
	 */
	WRITE_ONCE(cgx->is_throttled, false);
	return READ_ONCE(cgx->is_throttled) || cbw_has_backlogged_tasks(cgx);
}

static
int cbw_get_replenish_stat(void)
{
	return READ_ONCE(cbw_replenish_stat.s);
}

static
bool cbw_transit_replenish_stat(int from, int to)
{
	if (cbw_get_replenish_stat() != from)
		return false;
	return __sync_bool_compare_and_swap(&cbw_replenish_stat.s, from, to);
}

/**
 * scx_cgroup_bw_cancel - Cancel throttling for a task.
 *
 * @taskc: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 *
 * Tasks may be dequeued from the BPF side by the scx core during system
 * calls like sched_setaffinity(2). In that case, we must cancel any
 * throttling-related ATQ insert operations for the task:
 * - We must avoid double inserts caused by the dequeued task being
 *   reenqueed and throttled again while still in an ATQ.
 * - We want to remove tasks not in scx anymore from throttling. While
 *   inserting non-scx tasks into a DSQ is a no-op, we would like our
 *   accounting to be as accurate as possible.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_cancel(u64 ctx)
{
	return scx_atq_cancel((scx_task_common *)ctx);
}

/*
 * A handler function for the replenish timer.
 */
static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	struct cgroup_subsys_state *subroot_css, *pos;
	struct cgroup *root_cgrp, *cur_cgrp;
	struct scx_cgroup_llc_ctx *cur_llcx;
	const struct cpumask *online_mask;
	struct scx_cgroup_ctx *cur_cgx;
	s64 interval, jitter, period;
	int i, cur_level, ret;
	u64 *ids, now;
	s32 idle_cpu;

	/* Attach the timer function to the BPF area context. */
	scx_arena_subprog_init();

	/*
	 * Get the current time to calculate when to re-arm the timer.
	 */
	now = scx_bpf_now();

	/*
	 * Let's start running the top half.
	 *
	 * The bottom half may still be running (BOTTOM_HALF_RUNNING) when the
	 * new timer expires. In such a case, it is appropriate to proceed to
	 * refill the time budget. Hence, we allow the transition from
	 * {BOTTOM_HALF_RUNNING, IDLE} to TOP_HALF_RUNNING.
	 */
	if (!cbw_transit_replenish_stat(CBW_REPLENISH_STAT_IDLE,
					CBW_REPLENISH_STAT_TOP_HALF_RUNNING) &&
	    !cbw_transit_replenish_stat(CBW_REPLENISH_STAT_BOTTOM_HALF_RUNNING,
					CBW_REPLENISH_STAT_TOP_HALF_RUNNING)) {
		cbw_err("Incorrect replenish state: %d -- %d => %d",
			cbw_replenish_stat.s, CBW_REPLENISH_STAT_IDLE,
			CBW_REPLENISH_STAT_TOP_HALF_RUNNING);
		return 0;
	}
	cbw_dbg("at %llu", now);

	/*
	 * Update the runtime total before replenishing budgets.
	 */
	root_cgrp = bpf_cgroup_from_id(1);
	if (!root_cgrp) {
		cbw_err("Failed to fetch the root cgroup pointer.");
		goto idle_out;
	}
	cbw_update_runtime_total_sloppy(root_cgrp);

	/*
	 * Reset the runtime_total of each LLC context in a post order (i.e.,
	 * bottom-up manner). This prevents the runtime_total_sloppy at the
	 * cgroup level from being mixed with the runtime_total of the LLC
	 * level in a previous period.
	 *
	 * Also, keep the updated runtime_total_sloppy for later budget
	 * replenishment calculations.
	 */
	bpf_rcu_read_lock();
	subroot_css = &root_cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
		cur_cgrp = pos->cgroup;
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			/*
			 * The CPU controller of this cgroup is not enabled
			 * so that we can skip it safely.
			 */
			continue;
		}

		if (cur_cgx->has_llcx) {
			bpf_for(i, 0, TOPO_NR(LLC)) {
				cur_llcx = cbw_get_llc_ctx(cur_cgrp, i);
				if (cur_llcx)
					WRITE_ONCE(cur_llcx->runtime_total, 0);
			}
		}
		WRITE_ONCE(cur_cgx->runtime_total_last,
			   READ_ONCE(cur_cgx->runtime_total_sloppy));
		WRITE_ONCE(cur_cgx->runtime_total_sloppy, 0);
	}
	bpf_rcu_read_unlock();

	/*
	 * Update the array of taskable or subroot-level (level == 1) cgroup
	 * IDs (cbw_taskable_cgroup_ids) in a pre order (i.e., top-down
	 * manner), so we can replenish cgroups in a pre order. This avoids
	 * the case such that a lower-level cgroup is throttled before
	 * upper-lever cgroups are replenished.
	 */
	bpf_rcu_read_lock();
	cbw_nr_taskable_cgroups = 0;
	subroot_css = &root_cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			/*
			 * The CPU controller of this cgroup is not enabled
			 * so that we can skip it safely.
			 */
			continue;
		}

		if (cur_cgx->has_llcx || cur_cgrp->level == 1) {
			ids = MEMBER_VPTR(cbw_taskable_cgroup_ids,
					  [cbw_nr_taskable_cgroups]);
			if (!ids) {
				cbw_err("Failed to fetch a taskable cgroup table.");
				continue;
			}
			*ids = cgroup_get_id(cur_cgrp);
			cbw_nr_taskable_cgroups++;
		}
	}
	bpf_rcu_read_unlock();
	bpf_cgroup_release(root_cgrp);

	/*
	 * Replenish all the taskable cgroups in a pre order.
	 *
	 * Note that we do not use the cgroup iterator here since it requires
	 * an RCU read lock. We should not acquire the RCU read lock here since
	 * the enqueue callback could hold an RCU read lock.
	 *
	 * Note that there is a time gap between the time of update (when
	 * runtime_total_sloppy is updated) and the time of use (when the
	 * cgroup is replenished). Hence, there is an inaccuracy in calculating
	 * the burst time. However, relaxing some accuracy in burst time
	 * calculation has more benefits than drawbacks.
	 */
	cbw_dbg("Start replenish %llu taskable cgroups.", cbw_nr_taskable_cgroups);
	cbw_nr_throttled_cgroups = 0;
	bpf_for(i, 0, cbw_nr_taskable_cgroups) {
		ids = MEMBER_VPTR(cbw_taskable_cgroup_ids, [i]);
		if (!ids) {
			cbw_err("Failed to fetch a taskable cgroup table.");
			continue;
		}

		cur_cgrp = bpf_cgroup_from_id(ids[0]);
		if (!cur_cgrp) {
			cbw_err("Failed to fetch a cgroup pointer: cgid%llu", ids[0]);
			continue;
		}

		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			cbw_err("Failed to lookup a cgroup ctx: cgid%llu", ids[0]);
			bpf_cgroup_release(cur_cgrp);
			continue;
		}

		cur_level = cur_cgrp->level;
		bpf_cgroup_release(cur_cgrp);

		/*
		 * Replenish a taskable cgroup. If it was throttled,
		 * add it to the throttled cgroup table.
		 */
		if (cbw_replenish_taskable_cgroup(cur_cgx, cur_level, now)) {
			ids = MEMBER_VPTR(cbw_throttled_cgroup_ids,
					  [cbw_nr_throttled_cgroups]);
			if (!ids) {
				cbw_err("Failed to fetch a throttled cgroup table.");
				continue;
			}
			WRITE_ONCE(ids[0], cur_cgx->id);
			cbw_nr_throttled_cgroups++;
		}
	}

	/*
	 * If there are thtottled cgroups, transit from a top-half running
	 * to a bottom-half ready. After this, the bottom half can start.
	 */
	if (cbw_nr_throttled_cgroups > 0) {
		if (!cbw_transit_replenish_stat(
				CBW_REPLENISH_STAT_TOP_HALF_RUNNING,
				CBW_REPLENISH_STAT_BOTTOM_HALF_READY)) {
			cbw_err("Fail to transit the replenish state");
		}
	
		/*
		 * scx_cgroup_bw_reenqueue() may be called from ops.dispatch().
		 * In the worst case, when all CPUs are idle and all runnable
		 * tasks are backlogged, ops.dispatch() may be deferred
		 * indefinitely.
		 *
		 * Avoid this by selecting and kicking an idle CPU to guarantee
		 * that ops.dispatch() runs immediately. If no idle CPU is
		 * available, this is fine since ops.dispatch() will be invoked
		 * shortly anyway.
		 */
		online_mask = scx_bpf_get_online_cpumask();
		idle_cpu = scx_bpf_pick_idle_cpu(online_mask, SCX_PICK_IDLE_CORE);
		if (idle_cpu == -EBUSY)
			idle_cpu = scx_bpf_pick_idle_cpu(online_mask, 0);
		if (idle_cpu >= 0)
			scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
		scx_bpf_put_cpumask(online_mask);
	}
	/*
	 * If there is no thtottled cgroup, let's return to the idle state.
	 */
	else {
idle_out:
		if (!cbw_transit_replenish_stat(
				CBW_REPLENISH_STAT_TOP_HALF_RUNNING,
				CBW_REPLENISH_STAT_IDLE)) {
			cbw_err("Fail to transit the replenish state");
		}
	}

	/*
	 * Re-arm the replenish timer. We calculate the jitter to compensate
	 * for the delay of the timer execution.CBW_NPERIOD,
	 */
	interval = time_delta(now, cbw_last_replenish_at);
	jitter = time_delta(interval, CBW_NPERIOD);
	period = max(time_delta(CBW_NPERIOD, jitter), CBW_BUDGET_XFER_MIN);
	if ((ret = bpf_timer_start(timer, period, 0)))
		cbw_err("Failed to re-arm replenish timer: %d", ret);
	cbw_last_replenish_at = now;

	return 0;
}

static
int cbw_drain_btq_until_throttled(struct scx_cgroup_ctx *cgx,
				  struct scx_cgroup_llc_ctx *llcx)
{
	scx_task_common *taskc;
	int i;

	/*
	 * Pop the tasks in the BTQ and ask the BPF scheduler to enqueue
	 * them to a DSQ for execution until the BTQ becomes empty or
	 * the cgroup is throttled.
	 *
	 * The .pop() operation is concurrency-safe because all ATQ operations
	 * serialize on its lock. The task we retrieve with it is guaranteed
	 * to have been enqueued and not been dequeued. ATQ integrity aside,
	 * the main problem is that because a .dequeue() callback can happen
	 * at any point.
	 */
	for (i = 0; i < CBW_REENQ_MAX_BATCH &&
		    !READ_ONCE(cgx->is_throttled) &&
		    (taskc = (scx_task_common *)scx_atq_pop(llcx->btq)) &&
		    can_loop; i++) {
		/*
		 * Note that we do not worry about racing with .dequeue() here,
		 * because even if we do, the callback's insert_vtime call will
		 * fail silently in the scx core. 
		 */

		scx_cgroup_bw_enqueue_cb((u64)taskc);
		cbw_dbg("cgid%llu", cgx->id);
	}

	return i;
}

static
int cbw_reenqueue_cgroup(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx,
			 u64 cgrp_id, u64 nuance)
{
	struct scx_cgroup_llc_ctx *llcx;
	int i, idx, nr_enq = 0;

	/*
	 * Drain BTQ of each LLC level until the BTQ becomes empty or
	 * the cgroup is throttled.
	 *
	 * Note that we start with a random LLC to give each LLC a fair
	 * chance to be reenqueued.
	 */
	if (!cgx->has_llcx)
		return false;
	cbw_dbg("cgid%llu", cgrp_id);

	bpf_for(i, 0, TOPO_NR(LLC)) {
		idx = (nuance + i) % TOPO_NR(LLC);
		llcx = cbw_get_llc_ctx_with_id(cgrp_id, idx);
		if (!llcx) {
			cbw_err("Failed to lookup an LLC context");
			continue;
		}

		/* Update cgx->is_throttled before draining BTQ. */
		if (cbw_cgroup_bw_throttled(cgrp, idx) == -EAGAIN)
			continue;

		nr_enq += cbw_drain_btq_until_throttled(cgx, llcx);
		if (nr_enq >= CBW_REENQ_MAX_BATCH)
			break;
	}

	return nr_enq;
}

static
bool cbw_try_lock(u64 *lock)
{
	if (READ_ONCE(*lock) == 1)
		return false;
	return __sync_bool_compare_and_swap(lock, 0, 1);
}

static
void cbw_unlock(u64 *lock)
{
	WRITE_ONCE(*lock, 0);
}

/*
 * scx_cgroup_bw_reenqueue - Reenqueue backlogged tasks.
 *
 * When a cgroup is throttled, a task should be put aside at the ops.enqueue()
 * path. Once the cgroup becomes unthrottled again, such backlogged tasks
 * should be requeued for execution. To this end, a BPF scheduler should call
 * this at the beginning of its ops.dispatch() method, so that backlogged tasks
 * can be reenqueued if necessary.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_reenqueue(void)
{
	static u64 reenq_lock = 0;

	struct scx_cgroup_ctx *cur_cgx;
	struct cgroup *cur_cgrp;
	int i, idx, n, nr_enq = 0;
	u64 nuance, nuance2, nr_tcgs;
	u64 *ids, cur_cgrp_id;

	/*
	 * If it is in the BOTTOM_HALF_RUNNING state, the started bottom half
	 * hasn't finished yet. So, let's continue to run.
	 *
	 * If the bottom half is ready to run, go ahead after changing the
	 * state to the bottom-half running. Otherwise, stop here.
	 */
	if ((cbw_get_replenish_stat() !=
		CBW_REPLENISH_STAT_BOTTOM_HALF_RUNNING) &&
	    (!cbw_transit_replenish_stat(
		CBW_REPLENISH_STAT_BOTTOM_HALF_READY,
		CBW_REPLENISH_STAT_BOTTOM_HALF_RUNNING))) {
		return 0;
	}

	/*
	 * If another task is already performing the reenqueue operation,
	 * don't start another concurrent reenqueue operation.
	 *
	 * That is because the concurrent reenqueue operation has more harm
	 * than good, especially on a beefy machine, slowing down its caller,
	 * ops.dispatch().
	 */
	if (!cbw_try_lock(&reenq_lock))
		return 0;

	/*
	 * Reqneueue backlogged tasks of the throttled cgroups.
	 *
	 * Note that we start from a randomly chosen cgroup to give a fair
	 * chance to reenqueue throttled tasks, especially when extremely
	 * throttled.
	 *
	 * Note that we intentionally ignore the error to reenqueue all the
	 * tasks, ensuring it always returns 0.
	 */
	cbw_dbg();
	nuance = bpf_get_prandom_u32();
	nr_tcgs = READ_ONCE(cbw_nr_throttled_cgroups);
	bpf_for(i, 0, nr_tcgs) {
		nuance2 = nuance + i;
		idx = nuance2 % nr_tcgs;
		ids = MEMBER_VPTR(cbw_throttled_cgroup_ids, [idx]);
		if (!ids) {
			cbw_err("Failed to fetch a throttled cgroup table.");
			continue;
		}

		/*
		 * If the cgroup at this spot was purged (cgid == 0),
		 * there are no backlogged tasks on that cgroup. So skip it.
		 */
		cur_cgrp_id = READ_ONCE(ids[0]);
		if (cur_cgrp_id == 0)
			continue;

		cur_cgrp = bpf_cgroup_from_id(cur_cgrp_id);
		if (!cur_cgrp) {
			cbw_err("Failed to fetch a cgroup pointer: %llu", ids[0]);
			continue;
		}

		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			cbw_err("Failed to lookup a cgroup ctx");
			bpf_cgroup_release(cur_cgrp);
			continue;
		}

		/* Reqneueue backlogged tasks. */
		n = cbw_reenqueue_cgroup(cur_cgrp, cur_cgx, cur_cgrp_id, nuance2);
		bpf_cgroup_release(cur_cgrp);

		/*
		 * The reenqueue operation finished before hitting the upper
		 * bound (CBW_REENQ_MAX_BATCH). That means there are no more
		 * backlogged tasks under the cgroup. So, let's purge the task
		 * from the throttled cgroup table.
		 */
		if (n < CBW_REENQ_MAX_BATCH) {
			/*
			 * The CAS might fail if the replenish timer is running
			 * and updating the throttled cgroup table.
			 * Even if it happens, we don't care since it does not
			 * break the correctness.
			 */
			__sync_bool_compare_and_swap(ids, cur_cgrp_id, 0);
		}

		/*
		 * When hitting the upper bound, stop here to avoid the
		 * "dispatch buffer overflow" error.
		 */
		nr_enq += n;
		if (nr_enq >= CBW_REENQ_MAX_BATCH)
			break;
	}

	/*
	 * Unlock the reenqueue lock so that others can start
	 * the reqneueue operation.
	 */
	cbw_unlock(&reenq_lock);

	/*
	 * If we didn't reach the max reenqueue batch, transit from a
	 * bottom-half running to an idle state. After this,
	 * the top half can start.
	 */
	if (nr_enq < CBW_REENQ_MAX_BATCH) {
		cbw_transit_replenish_stat(
			CBW_REPLENISH_STAT_BOTTOM_HALF_RUNNING,
			CBW_REPLENISH_STAT_IDLE);
	}
	return 0;
}
