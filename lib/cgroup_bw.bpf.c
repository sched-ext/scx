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

#define cbw_dbg_cgrp(fmt, ...) do { 						\
	if (cbw_config.verbose > 0)						\
		bpf_printk("[%s:%d/cgid%llu] " fmt, __func__, __LINE__,		\
			   cgrp->kn->id, ##__VA_ARGS__);			\
} while(0)

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

static
int cbw_update_nquota_ub(struct cgroup *cgrp __arg_trusted,
			 struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_ctx *parentx, *subroot_cgx;
	struct cgroup *parent, *subroot_cgrp;

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
int cbw_update_nr_taskable_descendents(struct cgroup *cgrp __arg_trusted,
				       int delta)
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

__hidden
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

/**
 * scx_cgroup_bw_set - 
 * @cgrp:
 *
 * Returns
 */
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
