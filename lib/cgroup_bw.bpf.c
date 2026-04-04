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
	/* replenish period in nsec: 100 msec */
	CBW_REPLENISH_PERIOD		= (100ULL * 1000ULL * 1000ULL),
	/* min replenish period in nsec after jitter compensation: 1 msec */
	CBW_REPLENISH_PERIOD_MIN	= (1ULL * 1000ULL * 1000ULL),
	/* min/max accounting period in nsec: 3 msec and 20 msec */
	CBW_ACCOUNTING_PERIOD_MIN	= (3ULL * 1000ULL * 1000ULL),
	CBW_ACCOUNTING_PERIOD_MAX	= (20ULL * 1000ULL * 1000ULL),
	/*
	 * Divisor for converting time-to-throttle to accounting interval.
	 * The accounting timer fires CBW_ACCOUNTING_PERIOD_DIVISOR times
	 * before the predicted throttle point, giving multiple chances to
	 * observe rate changes before overuse occurs.
	 */
	CBW_ACCOUNTING_PERIOD_DIVISOR	= 4,
	/* fixed-point scale for consumption rate: 1024 = 100% quota consumed */
	CBW_SHIFT			= 10,
	CBW_SCALE			= (1 << CBW_SHIFT),
	/*
	 * EWMA decay factor for avg_consumption_rate. With decay=3 and
	 * CBW_REPLENISH_PERIOD=100ms, the half-lifetime is ~520ms.
	 */
	CBW_CONSUMPTION_RATE_DECAY	= 3,
	/* maximum number of cgroups */
	CBW_NR_CGRP_MAX			= 2048,
	/* maximum number of scx_cgroup_llc_ctx: 2048 cgroups * 32 LLCs */
	CBW_NR_CGRP_LLC_MAX		= (CBW_NR_CGRP_MAX * 32),
	/* The maximum height of a cgroup tree.
	 * cgroupv2 default maximum depth is 32 (kernel CGROUPS_DEPTH_MAX). */
	CBW_CGRP_TREE_HEIGHT_MAX	= 32,
	/* unlimited quota ("max") from scx_cgroup_init_args and scx_cgroup_bw_set() */
	CBW_RUNTUME_INF_RAW		= ((u64)~0ULL),
	/* unlimited quota ("max"); This is for easier comparison between signed vs. unsigned integers. */
	CBW_RUNTUME_INF			= ((s64)~((u64)1 << 63)),
	/* maximum number of re-enqueue tasks in one dispatch */
	CBW_REENQ_MAX_BATCH		= 2,
	/* size of the deferred BTQ destroy queue */
	CBW_DEFERRED_BTQ_SIZE		= 256,
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
	 * A boolean flag indicating whether the cgroup has LLC contexts.
	 */
	bool		has_llcx;

	/*
	 * A boolean flag indicating whether the cgroup is throttled or not.
	 * Note that the cgroup can be throttled before reaching the upper
	 * bound (nquota_nb) if the subrooot cgroup runs out of the time.
	 */
	bool		is_throttled;

	/*
	 * How many time this cgroup is throttled so far.
	 */
	u32		nr_throttled_periods;

	/*
	 * @period_start_clk represents when a new period starts.
	 * @burst_remaining is the maximum burst that can be accumulated
	 * until the end of the period from @period_start_clk.
	 */
	u64		period_start_clk;
	s64		burst_remaining;

	/*
	 * Effective quota for the current period: nquota_ub adjusted for
	 * debt (overspend from the previous period, subtracted) and burst
	 * credit (underspend carried forward, added). Set at each period
	 * boundary by replenish_timerfn(). Used by cbw_update_runtime_total_sloppy()
	 * as the throttle threshold instead of the bare nquota_ub, so that
	 * long-run average utilization converges to the configured quota.
	 */
	s64		period_budget;

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
	 * EWMA of CPU consumption rate within a replenish interval, in
	 * CBW_SCALE fixed-point. CBW_SCALE (1024) represents consuming the
	 * full CBW_REPLENISH_PERIOD worth of CPU time, i.e., 100% of one CPU
	 * core. Updated only when the cgroup was active (runtime_total_last
	 * > 0) to avoid pulling the average toward zero during idle periods.
	 * With CBW_CONSUMPTION_RATE_DECAY=3, the half-lifetime is ~5.2
	 * replenish intervals (~520ms at CBW_REPLENISH_PERIOD = 100ms).
	 *
	 * Default is 0 (zero-initialized by BPF map). This is reasonable
	 * because __calc_avg() uses a 50/50 blend when the old value is small
	 * (< 1 << decay), so the average ramps up quickly on the first few
	 * active intervals rather than warming up slowly.
	 *
	 * For unconstrained cgroups (nquota_ub == CBW_RUNTUME_INF),
	 * cbw_replenish_cgroup() returns early, so avg_consumption_rate stays
	 * 0. This is correct: a cgroup with no quota limit has no meaningful
	 * consumption rate to track.
	 */
	u64		avg_consumption_rate;
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
static u64		cbw_nr_cgroups;
static u64		cbw_cgroup_ids[CBW_NR_CGRP_MAX];

/*
 * An array of throttled cgroups that need to be reenqueued.
 */
static u64		cbw_throttled_cgroup_ids[CBW_NR_CGRP_MAX];

/*
 * Timer to replenish time budget for all cgroups periodically.
 *
 * The replenish timer is split into two parts: the top half and the bottom
 * half. The top half -- the actual BPF timer function -- runs the essential,
 * critical part, such as refilling the time budget. On the other hand,
 * the bottom half -- scx_cgroup_bw_reenqueue() - runs on a BPF scheduler's
 * ops.dispatch() and reenqueues the backlogged tasks to proper DSQs.
 *
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
 * Timer to account runtime_total for all cgroups periodically.
 */
struct accounting_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct accounting_timer);
} accounting_timer SEC(".maps") __weak;

static
int accounting_timerfn(void *map, int *key, struct bpf_timer *timer);

/*
 * Backlog status related functions
 */
union backlog_stat {
	struct {
		/* sequence counter for replenish operation. */
		u32 rp_seq;
		/* number of cbw_throttled_cgroup_ids */
		u16 nr_throttled_cgroups;
		/* a flag denoting if there is a throttled task */
		u16 has_throttled_tasks;
	};
	u64 val;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

static union backlog_stat cbw_backlog_stat;

static inline
bool cbw_update_backlog_stat_cas(union backlog_stat *old,
				 u32 rp_seq,
				 u16 nr_throttled_cgroups,
				 u16 has_throttled_tasks)
{
	union backlog_stat new = {
		.rp_seq = rp_seq,
		.nr_throttled_cgroups = nr_throttled_cgroups,
		.has_throttled_tasks = has_throttled_tasks,
	};

	return __sync_bool_compare_and_swap(&cbw_backlog_stat.val, old->val,
					    new.val);
}

static inline
bool cbw_top_half_running(void)
{
	/*
	 * The sequence counter increments at the beginning and end of the
	 * replenishment timer, respectively. So if the counter is an odd
	 * number, that means the replenishment timer is running.
	 */
	union backlog_stat stat;

	stat.val = smp_load_acquire(&cbw_backlog_stat.val);
	return stat.rp_seq & 0x1;
}

static inline
void cbw_top_half_begin(void)
{
	/*
	 * Increase the sequence counter, making it an odd number.
	 * Only one caller is permitted at a time (the replenish timer).
	 */
	union backlog_stat old, new, ret;

	ret.val = smp_load_acquire(&cbw_backlog_stat.val);
	do {
		new.val = old.val = ret.val;
		new.rp_seq++;
		ret.val = __sync_val_compare_and_swap(&cbw_backlog_stat.val,
						      old.val, new.val);
	} while ((ret.val != old.val) && can_loop);
}

static inline
void cbw_top_half_abort(void)
{
	/*
	 * The top half was started (rp_seq is odd) but cannot proceed.
	 * Increment rp_seq again to make it even, restoring the "top half
	 * not running" state so the bottom half can continue normally.
	 */
	cbw_top_half_begin();
}

static inline
void cbw_top_half_end(u16 nr_throttled_cgroups, u16 has_throttled_tasks)
{
	/* Increase the sequence counter, making it an even number. */
	union backlog_stat old, new, ret;

	ret.val = smp_load_acquire(&cbw_backlog_stat.val);
	do {
		new.val = old.val = ret.val;
		new.rp_seq++;
		new.nr_throttled_cgroups = nr_throttled_cgroups;
		new.has_throttled_tasks = has_throttled_tasks;
		ret.val = __sync_val_compare_and_swap(&cbw_backlog_stat.val,
						      old.val, new.val);
	} while ((ret.val != old.val) && can_loop);
}

/*
 * Debug macros.
 */
#define cbw_err(fmt, ...) do { 							\
	bpf_printk("[%s:%d] ERROR: " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
} while(0)

#define cbw_warn(fmt, ...) do { 						\
	bpf_printk("[%s:%d] WARNING: " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
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
	cbw_dbg(str "cgid%llu -- cgx:period_budget: %lld -- "			\
		"cgx:runtime_total_last: %lld -- "				\
		"cgx:runtime_total_sloppy: %lld -- "				\
		"cgx:nquota: %lld -- "						\
		"cgx:nquota_ub: %lld -- "					\
		"cgx:is_throttled: %d -- "					\
		"cgx:avg_consumption_rate: %llu "				\
		##__VA_ARGS__,							\
		cgx->id, cgx->period_budget,					\
		cgx->runtime_total_last, cgx->runtime_total_sloppy,		\
		cgx->nquota, cgx->nquota_ub, cgx->is_throttled,		\
		cgx->avg_consumption_rate);					\
} while (0);

#define dbg_llcx(llcx, str, ...) do {						\
	cbw_dbg(str "cgid%llu -- llcx:runtime_total: %lld",			\
		##__VA_ARGS__,							\
		llcx->id, llcx->runtime_total);					\
} while (0);

#define info_llcx(llcx, str, ...) do {						\
	cbw_dbg(str "cgid%llu -- llcx:runtime_total: %lld",			\
		##__VA_ARGS__,							\
		llcx->id, llcx->runtime_total);					\
} while (0);

#define info_cgx(cgx, str, ...) do {						\
	cbw_info(str "cgid%llu -- cgx:period_budget: %lld -- "			\
		 "cgx:runtime_total_last: %lld -- "				\
		 "cgx:runtime_total_sloppy: %lld -- "				\
		 "cgx:nquota: %lld -- "						\
		 "cgx:nquota_ub: %lld -- "					\
		 "cgx:is_throttled: %d -- "					\
		 "cgx:avg_consumption_rate: %llu"				\
		 ##__VA_ARGS__,							\
		 cgx->id, cgx->period_budget,					\
		 cgx->runtime_total_last, cgx->runtime_total_sloppy,		\
		 cgx->nquota, cgx->nquota_ub, cgx->is_throttled,		\
		 cgx->avg_consumption_rate);					\
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
	struct bpf_timer *rp_timer, *ac_timer;
	u32 key = 0;
	int ret;

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
	rp_timer = bpf_map_lookup_elem(&replenish_timer, &key);
	if (!rp_timer) {
		cbw_err("Failed to lookup replenish timer");
		return -ESRCH;
	}

	cbw_last_replenish_at = scx_bpf_now();
	bpf_timer_init(rp_timer, &replenish_timer, CBW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(rp_timer, replenish_timerfn);
	if ((ret = bpf_timer_start(rp_timer, CBW_REPLENISH_PERIOD, 0))) {
		cbw_err("Failed to start replenish timer");
		return ret;
	}

	/* Initialize the accounting timer. */
	ac_timer = bpf_map_lookup_elem(&accounting_timer, &key);
	if (!ac_timer) {
		cbw_err("Failed to lookup accounting timer");
		return -ESRCH;
	}

	bpf_timer_init(ac_timer, &accounting_timer, CBW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(ac_timer, accounting_timerfn);
	if ((ret = bpf_timer_start(ac_timer, CBW_ACCOUNTING_PERIOD_MAX, 0))) {
		cbw_err("Failed to start accounting timer");
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
long cbw_del_llc_ctx_with_id(u64 cgrp_id, int llc_id)
{
	struct cgroup_llc_id key = {
		.cgrp_id = cgrp_id,
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

__hidden
int cbw_put_aside(u64 ctx, u64 vtime, u64 cgrp_id);

static void schedule_atq_destroy(scx_atq_t *btq)
{
	static u64 slots[CBW_DEFERRED_BTQ_SIZE] __attribute__((aligned(SCX_CACHELINE_SIZE)));
	static u64 tail __attribute__((aligned(SCX_CACHELINE_SIZE)));
	u64 slot, old, prev;

	do {
		/*
		 * Atomically claim the slot. If the slot is empty, we are done.
		 */
		slot = __sync_fetch_and_add(&tail, 1) % CBW_DEFERRED_BTQ_SIZE;
		old = __sync_val_compare_and_swap(&slots[slot], 0, (u64)btq);
		if (!old)
			return;

		/*
		 * If it is occupied, the tail has wrapped around: replace old
		 * with the new BTQ via CAS to make the eviction atomic and
		 * prevent a double-free.
		 */
		prev = __sync_val_compare_and_swap(&slots[slot], old, (u64)btq);
		if (likely(old == prev)) {
			scx_atq_destroy((scx_atq_t *)old);
			return;
		}

		/*
		 * The CAS can fail if CBW_DEFERRED_BTQ_SIZE concurrent
		 * destroyer claimed the same slot. If the CAS fails,
		 * retry to work on a new slot.
		 */
	} while (can_loop);

	/*
	 * Atomically updating tail and slots could be a potential memory hot
	 * spot, causing a lot of cache coherence traffic. However, it is
	 * unlikely that real-world workloads will continuously and concurrently
	 * destroy cgroups. So, let’s keep the design simple for now.
	 */
}

static __always_inline
int cbw_free_llc_ctx(struct scx_cgroup_ctx *cgx, u64 cgrp_id)
{
	struct scx_cgroup_llc_ctx *llcx;
	volatile int nr_moved = 0; /* Add volatile to satisfy the verifier. */
	int i, ret;
	scx_atq_t *btq;
	u64 taskc;

	if (cgx) {
		if (!cgx->has_llcx)
			return 0;
		cgx->has_llcx = false;
	}

	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx_with_id(cgrp_id, i);
		if (!llcx || !(btq = READ_ONCE(llcx->btq)))
			continue;

		/*
		 * Atomically null llcx->btq to signal
		 * cbw_drain_btq_until_throttled() that this ATQ is being
		 * destroyed. The CAS acts as a full memory barrier, ordering
		 * this store before scx_atq_destroy(). Only the CAS winner
		 * proceeds to drain and destroy; the loser skips via the
		 * branch below.
		 */
		if (!__sync_bool_compare_and_swap(&llcx->btq, btq, NULL)) {
			/*
			 * Another CPU concurrently zeroed llcx->btq via the
			 * same CAS. That CPU is the winner and is responsible
			 * for draining this LLC context, freeing it, and
			 * scheduling BTQ destruction. The loser (this CPU)
			 * will just move on to the next LLC context. Hence,
			 * cbw_free_llc_ctx() is multi-CPU-reentrant.
			 */
			continue;
		}
		/*
		 * This CPU won the CAS - proceed to drain, delete, and destroy.
		 */

		/*
		 * Move all the throttled exiting tasks into the root cgroup.
		 * Then, delete the LLC context and its associated BTQ.
		 */
		if (cgrp_id != 1) {
			while ((taskc = scx_atq_pop(btq)) && can_loop) {
				/*
				 * Set task's vtime to zero so we can reap the
				 * the throttled exiting task as soon as possible.
				 *
				 * We will try to reenqueue the throttled exiting
				 * task in the next replenishment interval. This
				 * is fair since the task was throttled under the
				 * cgroup, so it has to wait until the next
				 * replenishment interval anyway.
				 */
				ret = cbw_put_aside(taskc, 0, 1);
				if (likely(!ret)) {
					nr_moved++;
				} else {
					cbw_err("Failed to put aside a task "
						"while exiting cgid%llu: %d",
						cgrp_id, ret);
				}
			}
		}

		if (cbw_del_llc_ctx_with_id(cgrp_id, i)) {
			cbw_err("Failed to delete an LLC context: [%llu/%d]",
				cgrp_id, i);
			/*
			 * Even if the map delete fails, it is still safe to
			 * call schedule_atq_destroy() below. We won the CAS
			 * above, so we hold exclusive ownership of btq -- no
			 * other CPU will access it. The stale LLC map entry
			 * will be harmless: future lookups will find
			 * llcx->btq == NULL and skip it.
			 */
		}

		/*
		 * Defer scx_atq_destroy() to avoid a use-after-free in
		 * cbw_drain_btq_batch(): that function snapshots llcx->btq
		 * under READ_ONCE(), and cbw_free_llc_ctx() may destroy the
		 * BTQ in the window between the snapshot and scx_atq_pop().
		 */
		schedule_atq_destroy(btq);
	}

	return nr_moved;
}

static
void cbw_set_bandwidth(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx,
		       u64 period_us, u64 quota_us, u64 burst_us)
{
	cgx->period = period_us * 1000;
	cgx->period_start_clk = scx_bpf_now();

	if (quota_us == CBW_RUNTUME_INF_RAW) {
		cgx->quota = CBW_RUNTUME_INF_RAW;
		cgx->nquota = CBW_RUNTUME_INF;
		cgx->burst = 0;
	} else {
		cgx->quota = quota_us * 1000;
		cgx->nquota = div_round_up(quota_us * CBW_REPLENISH_PERIOD,
					   period_us);
		cgx->burst = burst_us * 1000;
	}
	cgx->burst_remaining = cgx->burst;
}

__noinline
int cbw_update_nquota_ub(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_ctx *cgx)
{
	struct scx_cgroup_ctx *parentx;
	struct cgroup *parent;

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
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted)
{
	struct scx_cgroup_ctx *cgx, *parentx;
	struct cgroup *parent;

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
	cgx->period_budget = cgx->nquota_ub;
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
		if (cgroup_get_id(parent) != 1) {
			parentx = cbw_get_cgroup_ctx(parent);
			if (parentx && !cgroup_is_threaded(parent)) {
				cbw_free_llc_ctx(parentx, parentx->id);
			}
		}
		bpf_cgroup_release(parent);
	}

	/*
	 * Create per-LLC-cgroup contexts if @cgrp can have tasks (i.e.,
	 * a cgroup is either at the leaf level or threaded). Here, @cgrp
	 * is at the leaf (a cgroup is a leaf until its child is created),
	 * so we will create per-LLC-cgroup contexts anyway.
	 */
	return cbw_init_llc_ctx(cgrp, cgx);
}

static
int cbw_unthrottle_cgroup_for_exit(struct cgroup *cgrp)
{
	struct scx_cgroup_ctx *cgx;

	/*
	 * Stop throttling the cgroup by setting its upper bound and
	 * budget remaining to infinite.
	 */
	if (!(cgx = cbw_get_cgroup_ctx(cgrp))) {
		cbw_err("Failed to lookup a cgroup ctx: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	if (cgx->nquota_ub == CBW_RUNTUME_INF)
		return 0;

	WRITE_ONCE(cgx->nquota_ub, CBW_RUNTUME_INF);
	WRITE_ONCE(cgx->period_budget, CBW_RUNTUME_INF);
	/*
	 * Ensure nquota_ub = INF is globally visible before clearing
	 * is_throttled. Without this, the accounting timer could observe
	 * is_throttled = false, evaluate runtime_total_sloppy >= nquota_ub
	 * with the stale (finite) quota, and spuriously re-throttle the
	 * cgroup.
	 */
	smp_mb();

	WRITE_ONCE(cgx->is_throttled, false);

	/*
	 * Make the unthrottling changes visible before draining its BTQs.
	 */
	smp_mb();
	return 0;
}

static __always_inline
int cbw_cgroup_bw_offline(u64 cgrp_id)
{
	/*
	 * The cgroup destruction path is asynchronous: after rmdir(2) removes
	 * the cgroup's sysfs entry (kernfs_remove()), the kernel must complete
	 * an RCU grace period and a workqueue hop on cgroup_offline_wq before
	 * css_offline() - and thus scx_cgroup_bw_exit() - is invoked.
	 *
	 * This creates a gap between:
	 *   1) kernfs_remove(): bpf_cgroup_from_id() starts returning NULL
	 *      because the kernfs node is deactivated.
	 *   2) scx_cgroup_bw_exit() called from css_offline() on
	 *      cgroup_offline_wq: the normal safety net that drains the
	 *      BTQ to the root cgroup.
	 *
	 * If a cgroup has throttled tasks in its BTQ during this window and
	 * the window exceeds 30 s, those tasks stall long enough to trigger
	 * the SCX watchdog. To close the gap, as soon as we observe that
	 * bpf_cgroup_from_id() fails for a cgroup, we proactively drain its
	 * BTQ to the root cgroup here, rather than waiting for css_offline().
	 */

	/*
	 * Note that this function and cbw_free_llc_ctx() must be
	 * __always_inline to stay within BPF's 8-frame call-stack limit.
	 * This function is called from replenish_timerfn() and
	 * scx_cgroup_bw_reenqueue(), both of which already have deep call
	 * chains.
	 */
	cbw_dbg("Offline a cgroup: %llu", cgrp_id);
	return cbw_free_llc_ctx(NULL, cgrp_id);
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
	int ret = 0;

	cbw_dbg_cgrp();

	/*
	 * A cgroup can exit when there are exiting tasks (TASK_DEAD) under it,
	 * because the kernel does not count them as living tasks. So, care
	 * should be taken to properly handle the race between cgroup exit
	 * and task exit, especially when exiting tasks under an exiting cgroup
	 * are throttled. We first stop throttling the cgroup to prevent any
	 * more tasks from being throttled. 
	 */
	cbw_unthrottle_cgroup_for_exit(cgrp);

	cbw_del_cgroup_ctx(cgrp);
	cbw_free_llc_ctx(NULL, cgroup_get_id(cgrp));
	return ret;
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
	struct cgroup_subsys_state *start_css, *pos;
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
	start_css = &cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
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
	struct cgroup_subsys_state *start_css, *pos;
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
	start_css = &cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
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

		/*
		 * If the cgroup has consumed its effective period budget, mark
		 * it throttled. period_budget = nquota_ub - debt + burst_credit
		 * reflects any debt carried from the previous period, so the
		 * comparison enforces long-run average convergence.
		 */
		if (READ_ONCE(cur_cgx->runtime_total_sloppy) >= cur_cgx->period_budget)
			WRITE_ONCE(cur_cgx->is_throttled, true);

		/* Aggregate this cgroup's runtime_total_sloppy to the level. */
		tree->levels[cur_level] += READ_ONCE(cur_cgx->runtime_total_sloppy);
		
		/* Update the previous level. */
		prev_level = cur_level;

		cbw_dbg("cgid%llu -- rt_llcx: %lld -- runtime_total_sloppy: %lld",
			cur_cgx->id, rt_llcx, cur_cgx->runtime_total_sloppy);
	}
	bpf_rcu_read_unlock();

	return ret;
}

static
int cbw_throttle_cgroups(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *start_css, *pos, *anc_css;
	struct scx_cgroup_ctx *cur_cgx, *cur_anc_cgx;
	struct cgroup *cur_anc_cgrp;
	int i;

	/*
	 * We traverse the cgroup hierarchy in post-order (left-right-self,
	 * i.e., bottom-up). For each cgroup, check if there is any throttled
	 * ancestor. If so, throttle itself.
	 *
	 * Before this, each cgroup’s runtime_total_sloppy should be updated
	 * by calling cbw_update_runtime_total_sloppy().
	 */
	bpf_rcu_read_lock();
	start_css = &cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
		cur_cgx = cbw_get_cgroup_ctx(pos->cgroup);
		if (!cur_cgx) {
			/*
			 * The CPU controller of this cgroup is not enabled
			 * so that we can skip it safely.
			 */
			continue;
		}

		/*
		 * This cgroup has an unlimited quota,
		 * so it cannot be throttled; skip it.
		 */
		if (cur_cgx->nquota_ub == CBW_RUNTUME_INF)
			continue;

		/*
		 * This cgroup is already throttled;
		 * there is no need to check its ancestors.
		 */
		if (READ_ONCE(cur_cgx->is_throttled))
			continue;

		/*
		 * If the top half is running, stop here since
		 * the top half will replenish and unthrottle
		 * all the cgroups anyway.
		 */
		if (unlikely(cbw_top_half_running()))
			break;

		/*
		 * If there is a throttled ancestor, all its descendants should
		 * be throttled; so this cgroup should be throttled too.
		 */
		anc_css = pos->parent;
		bpf_for(i, 0, CBW_CGRP_TREE_HEIGHT_MAX) {
			if (!anc_css)
				break;
			cur_anc_cgrp = anc_css->cgroup;
			if (!cur_anc_cgrp || cur_anc_cgrp->level == 0)
				break;
			cur_anc_cgx = cbw_get_cgroup_ctx(cur_anc_cgrp);
			if (cur_anc_cgx && READ_ONCE(cur_anc_cgx->is_throttled)) {
				WRITE_ONCE(cur_cgx->is_throttled, true);
				break;
			}
			anc_css = anc_css->parent;
		}
	}
	bpf_rcu_read_unlock();
	return 0;
}

static
int cbw_get_current_llc_id(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	return topo_cpu_to_llc_id(cpu);
}

static
int cbw_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted)
{
	struct scx_cgroup_ctx *cgx;

	/*
	 * The throttle decision is based solely on cgx->is_throttled, which is
	 * maintained asynchronously by the accounting timer via a two-step
	 * process:
	 *
	 *   Step 1 (cbw_update_runtime_total_sloppy): aggregates runtime_total
	 *   from LLC contexts bottom-up and sets is_throttled when
	 *   runtime_total_sloppy reaches nquota_ub.
	 *
	 *   Step 2 (cbw_throttle_cgroups): propagates is_throttled top-down to
	 *   all descendants of a throttled ancestor.
	 *
	 * The flag is cleared at the replenish period boundary. A stale read
	 * is harmless: at worst it allows one extra accounting interval of
	 * overspend, which is recovered via debt carry-over at the next period.
	 */

	/* Always go ahead with the root cgroup. */
	if (cgrp->level == 0)
		return 0;

	cgx = cbw_get_cgroup_ctx(cgrp);
	if (!cgx) {
		/*
		 * The CPU controller is not enabled for this cgroup.
		 */
		cbw_dbg("Failed to lookup a cgroup ctx: %llu",
			cgroup_get_id(cgrp));
		return -ESRCH;
	}

	if (READ_ONCE(cgx->is_throttled)) {
		dbg_cgx(cgx, "throttled: ");
		return -EAGAIN;
	}

	return 0;
}

/**
 * scx_cgroup_bw_throttled - Check if the cgroup is throttled or not.
 * @cgrp: cgroup where a task belongs to.
 * @p: a task to be tested.
 *
 * Return 0 when the cgroup is not throttled,
 * -EAGAIN when the cgroup is throttled, and
 * -errno for some other failures.
 */
__hidden
int scx_cgroup_bw_throttled(struct cgroup *cgrp __arg_trusted, struct task_struct *p __arg_trusted)
{
	/*
	 * Never throttle an exiting task. In do_exit(), a task is removed from
	 * the PID map by __unhash_process() (called from exit_notify()) in the
	 * window between PF_EXITING being set and TASK_DEAD being set. If the
	 * task is preempted in this window and throttled into the BTQ, the BTQ
	 * drain calls scx_cgroup_bw_enqueue_cb() to reenqueue it. The callback
	 * looks up the task pointer via bpf_task_from_pid(), which returns NULL
	 * for an unhashed task. With no way to reenqueue it, the task is
	 * permanently lost from all runqueues, causing a watchdog timeout.
	 */
	if (p->flags & PF_EXITING)
		return 0;

	return cbw_cgroup_bw_throttled(cgrp);
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
	llcx = cbw_get_llc_ctx(cgrp, llc_id);
	if (!llcx) {
		/*
		 * When exiting a scx scheduler, the sched_ext kernel shuts
		 * down cgroup support before tasks. Hence, failing to look
		 * up an LLC context is quite normal in this case.
		 */
		return 0;
	}

	/*
	 * consumed_ns may span a CBW_REPLENISH_PERIOD boundary when a task
	 * runs across it. Since this function is called on every tick
	 * (ops.stopping() and ops.tick()), consumed_ns per call is bounded by
	 * roughly one tick interval (~1-4ms). Any cross-period overcount is
	 * therefore a bounded approximation error: it appears as overspend in
	 * runtime_total, which cbw_replenish_cgroup() converts into debt that
	 * is subtracted from the next period's budget, keeping long-term CPU
	 * bandwidth correct.
	 */
	__sync_fetch_and_add(&llcx->runtime_total, consumed_ns);

	cbw_dbg_cgrp("  llc_id: %d -- consumed_ns: %llu -- llcx:runtime_total: %lld",
		     llc_id, consumed_ns, READ_ONCE(llcx->runtime_total));
	return 0;
}

__hidden
int cbw_put_aside(u64 ctx, u64 vtime, u64 cgrp_id)
{
	scx_task_common *taskc = (scx_task_common *)ctx;
	struct scx_cgroup_llc_ctx *llcx;
	scx_atq_t *btq;
	int llc_id, ret;

	/* Get the current LLC ID. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * Put aside the task to the BTQ of the LLC context.
	 */
	llcx = cbw_get_llc_ctx_with_id(cgrp_id, llc_id);
	if (!llcx) {
		cbw_err("Failed to lookup an LLC ctx: [%llu/%d]",
			cgrp_id, llc_id);
		return -ESRCH;
	}

	/*
	 * Snapshot llcx->btq. cbw_free_llc_ctx() nulls this field before
	 * destroying the ATQ, so observing NULL means the ATQ is gone.
	 */
	btq = READ_ONCE(llcx->btq);
	if (!btq)
		return -ESRCH;

	ret = scx_atq_lock(btq);
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
		scx_atq_unlock(btq);
		return 0;
	}

	ret = scx_atq_insert_vtime_unlocked(btq, taskc, vtime);
	if (ret)
		cbw_err("Failed to insert a task to BTQ: %d", ret);

	scx_atq_unlock(btq);

	return ret;
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
	cbw_dbg_cgrp(" [%s/%d]", p->comm, p->pid);
	return cbw_put_aside(ctx, vtime, cgroup_get_id(cgrp));
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
			continue;

		if (scx_atq_nr_queued(llcx->btq))
			return true;
	}

	return false;
}

static
bool cbw_replenish_cgroup(struct scx_cgroup_ctx *cgx, u64 now)
{
	s64 burst_credit = 0, debt = 0, budget;
	bool period_end, was_throttled, keep_throttled = false;

	/*
	 * If the nquota_ub is infinite, we don’t need to replenish the cgroup.
	 */
	if (cgx->nquota_ub == CBW_RUNTUME_INF)
		goto out_no_replenish;

	/*
	 * Detect whether the cpu.max period boundary has been crossed.
	 * CBW_REPLENISH_PERIOD normalizes nquota_ub to a fixed 100ms window,
	 * but cgx->period is the user-configured period from cpu.max, which
	 * may differ. The burst allowance (burst_remaining) resets to its
	 * cap (cgx->burst) at each cpu.max period boundary.
	 *
	 */
	period_end = time_delta(now, cgx->period_start_clk) >= cgx->period;
	if (period_end)
		WRITE_ONCE(cgx->period_start_clk, now);

	/*
	 * Debt and burst credit are computed independently:
	 *
	 * Debt: overspend relative to period_budget (the effective budget for
	 * the just-completed interval). Using period_budget rather than bare
	 * nquota_ub is correct: if burst was granted last interval, spending
	 * up to period_budget is not a violation and should not incur debt.
	 *
	 * Burst credit: underspend relative to nquota (the cgroup's own
	 * quota), clamped to [0, burst_remaining], matching cpu.max.burst
	 * semantics. Using nquota rather than nquota_ub means burst is earned
	 * against the cgroup's own quota regardless of ancestor constraints,
	 * consistent with how the kernel cpu.max.burst is defined. Ancestor
	 * quota enforcement is handled separately through the bottom-up
	 * aggregation and top-down propagation in the accounting timer.
	 *
	 * When burst is not configured (cgx->burst = 0), burst_remaining is
	 * also 0, so clamp(..., 0LL, 0LL) = 0 and burst_credit is always
	 * zero without any special casing.
	 */
	debt = max(cgx->runtime_total_last - cgx->period_budget, 0LL);
	burst_credit = clamp((s64)cgx->nquota - cgx->runtime_total_last,
			     0LL, cgx->burst_remaining);

	dbg_cgx(cgx, "replenishing: ");

	/*
	 * Update burst_remaining. On period_end, reset to the full burst cap
	 * for the new cpu.max period. Otherwise, decrease by the credit
	 * consumed this interval.
	 */
	if (period_end)
		WRITE_ONCE(cgx->burst_remaining, cgx->burst);
	else
		WRITE_ONCE(cgx->burst_remaining,
			   cgx->burst_remaining - burst_credit);

	budget = (s64)cgx->nquota_ub + burst_credit - debt;
	WRITE_ONCE(cgx->period_budget, budget);

	/*
	 * If budget <= 0, the cgroup's debt exceeds its quota and burst for
	 * this period, so it has no CPU time to spend. Keep it throttled so
	 * that (a) the bottom half does not drain its BTQ and (b) the caller
	 * can propagate the throttle to descendants immediately via
	 * cbw_throttle_cgroups() without waiting for the next accounting tick.
	 */
	keep_throttled = (budget <= 0);

	/*
	 * Update the EWMA consumption rate (CBW_SCALE = 1024 means 100% of
	 * one CPU core consumed within CBW_REPLENISH_PERIOD). Only updated
	 * when the cgroup was active this interval to avoid pulling the average
	 * toward zero during idle periods.
	 */
	if (cgx->runtime_total_last > 0) {
		u64 rate = (u64)cgx->runtime_total_last * CBW_SCALE /
			   CBW_REPLENISH_PERIOD;
		cgx->avg_consumption_rate =
			__calc_avg(cgx->avg_consumption_rate, rate,
				   CBW_CONSUMPTION_RATE_DECAY);
	}

	dbg_cgx(cgx, "replenished: ");

out_no_replenish:
	/*
	 * Ensure the runtime_total_sloppy = 0 resets performed earlier in the
	 * replenish top half are globally visible before is_throttled is
	 * cleared. Without this, on non-TSO architectures like ARM64, the
	 * accounting timer could observe is_throttled = false, read stale
	 * runtime_total_sloppy values, and spuriously re-throttle the cgroup.
	 */
	smp_mb();

	/*
	 * Snapshot is_throttled before updating it. The following conditions
	 * mean the cgroup needs reenqueue attention next period:
	 *
	 * - was_throttled: budget was exhausted this period. Even if the BTQ
	 *   appears empty (e.g., the bottom half just popped the last task but
	 *   hasn't reenqueued it yet), we must not miss this cgroup.
	 *
	 * - keep_throttled: budget <= 0, so the cgroup stays throttled into
	 *   the new period. was_throttled is almost always true in this case,
	 *   but keep_throttled guards the rare edge where it is not.
	 *
	 * - cbw_has_backlogged_tasks: tasks remain in the BTQ from an
	 *   incomplete drain (reenqueuing couldn't finish within one period).
	 *
	 * Set is_throttled to keep_throttled: true when budget <= 0 so the
	 * cgroup stays throttled for the new period; false otherwise. For
	 * unlimited-quota cgroups that jumped to out_no_replenish,
	 * keep_throttled is always false.
	 */
	was_throttled = READ_ONCE(cgx->is_throttled);
	WRITE_ONCE(cgx->is_throttled, keep_throttled);
	return was_throttled || keep_throttled || cbw_has_backlogged_tasks(cgx);
}

/*
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
 * A handler function for the accounting timer.
 */
static
int accounting_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	struct cgroup *root_cgrp;
	u64 now;
	int ret;

	/*
	 * Update the runtime total and throttle cgroups.
	 *
	 * If the top half is running, we can skip the accounting since the top
	 * half will replenish and unthrottle all the cgroups anyway.
	 */
	root_cgrp = bpf_cgroup_from_id(1);
	if (unlikely(!root_cgrp)) {
		cbw_err("Failed to fetch the root cgroup pointer.");
		goto rearm_out;
	}

	if (unlikely(cbw_top_half_running()))
		goto release_out;

	now = scx_bpf_now();
	cbw_dbg("at %llu", now);

	cbw_update_runtime_total_sloppy(root_cgrp);
	cbw_throttle_cgroups(root_cgrp);
	smp_mb();

release_out:
	bpf_cgroup_release(root_cgrp);
rearm_out:
	if ((ret = bpf_timer_start(timer, CBW_ACCOUNTING_PERIOD, 0)))
		cbw_err("Failed to re-arm accounting timer: %d", ret);
	return 0;
}

/*
 * A handler function for the replenish timer.
 */
static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	static int nr_throttled; /* Add `static` to work around the verifier error (-E2BIG) */
	struct cgroup *root_cgrp, *cur_cgrp;
	struct cgroup_subsys_state *root_css, *pos;
	struct scx_cgroup_ctx *cur_cgx;
	struct scx_cgroup_llc_ctx *cur_llcx;
	const struct cpumask *online_mask;
	s64 interval, jitter, period;
	int i, ret, nr_moved = 0;
	bool root_added = false;
	u64 *ids, now;
	s32 idle_cpu;

	/* Attach the timer function to the BPF area context. */
	scx_arena_subprog_init();

	/*
	 * Let's start running the top half.
	 * Get the current time to calculate when to re-arm the timer.
	 */
	now = scx_bpf_now();
	cbw_top_half_begin();
	cbw_dbg("at %llu", now);

	/*
	 * Update the runtime total before replenishing budgets.
	 */
	root_cgrp = bpf_cgroup_from_id(1);
	if (!root_cgrp) {
		cbw_err("Failed to fetch the root cgroup pointer.");
		cbw_top_half_abort();
		goto rearm_out;
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
	root_css = &root_cgrp->self;
	bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_POST) {
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
	 * Build the list of all cgroups that have a context in a pre-order
	 * (top-down) traversal so that parents are replenished before their
	 * children. This ensures that when we clear a parent's is_throttled
	 * flag, the top-down propagation in the next accounting tick does
	 * not spuriously re-throttle children before the parent's flag is
	 * cleared.
	 */
	bpf_rcu_read_lock();
	cbw_nr_cgroups = 0;
	root_css = &root_cgrp->self;
	bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			/*
			 * The CPU controller of this cgroup is not enabled
			 * so that we can skip it safely.
			 */
			continue;
		}

		ids = MEMBER_VPTR(cbw_cgroup_ids,
				  [cbw_nr_cgroups]);
		if (!ids) {
			cbw_err("Failed to fetch a cgroup table.");
			continue;
		}
		*ids = cgroup_get_id(cur_cgrp);
		cbw_nr_cgroups++;
	}
	bpf_rcu_read_unlock();
	bpf_cgroup_release(root_cgrp);

	/*
	 * Replenish all cgroups in a pre order.
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
	cbw_dbg("Start replenish %llu cgroups.", cbw_nr_cgroups);
	nr_throttled = 0;
	bpf_for(i, 0, cbw_nr_cgroups) {
		ids = MEMBER_VPTR(cbw_cgroup_ids, [i]);
		if (!ids) {
			cbw_err("Failed to fetch a cgroup table.");
			continue;
		}

		/*
		 * Fetch the cgroup context. A cgroup can exit during the
		 * replenishment process, leading to context-lookup failures.
		 */
		cur_cgrp = bpf_cgroup_from_id(ids[0]);
		if (!cur_cgrp) {
			cbw_dbg("Failed to fetch a cgroup pointer: cgid%llu", ids[0]);
			/*
			 * This cgroup is already offline: its kernfs node is
			 * deactivated so bpf_cgroup_from_id() returns NULL,
			 * but css_offline() / ops.cgroup_exit() has not yet
			 * run. Move all its throttled tasks to the root cgroup
			 * for immediate draining.
			 */
			nr_moved += cbw_cgroup_bw_offline(ids[0]);
			continue;
		}

		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			cbw_dbg("Failed to lookup a cgroup ctx: cgid%llu", ids[0]);
			bpf_cgroup_release(cur_cgrp);
			continue;
		}

		if (READ_ONCE(cur_cgx->is_throttled)) {
			cur_cgx->nr_throttled_periods++;
		}

		bpf_cgroup_release(cur_cgrp);

		/*
		 * Replenish the cgroup. If it was throttled, add it to the
		 * throttled cgroup table.
		 *
		 * These writes are ordered before cbw_top_half_end() publishes
		 * has_throttled_tasks=true via its __sync_val_compare_and_swap()
		 * (which acts as a full memory barrier), ensuring the bottom half
		 * observes a consistent cbw_throttled_cgroup_ids[].
		 */
		if (cbw_replenish_cgroup(cur_cgx, now)) {
			ids = MEMBER_VPTR(cbw_throttled_cgroup_ids,
					  [nr_throttled]);
			if (!ids) {
				cbw_err("Failed to fetch a throttled cgroup table.");
				continue;
			}
			WRITE_ONCE(ids[0], cur_cgx->id);
			if (cur_cgx->id == 1)
				root_added = true;
			nr_throttled++;
		}
	}
	/*
	 * At least one throttled task was moved to the root cgroup and the
	 * root cgroup is not in the table. So we should add the root cgroup
	 * to the table.
	 */
	if (nr_moved > 0 && !root_added) {
		ids = MEMBER_VPTR(cbw_throttled_cgroup_ids, [nr_throttled]);
		if (ids) {
			WRITE_ONCE(ids[0], 1);
			nr_throttled++;
		} else {
			cbw_err("Failed to fetch a throttled cgroup table.");
		}
	}

	/*
	 * If there are throttled cgroups, let's transit to the non-empty state
	 * so the bottom half can start.
	 */
	if (nr_throttled > 0) {
		cbw_top_half_end(nr_throttled, true);

		/*
		 * Propagate is_throttled to descendants of cgroups that were
		 * kept throttled due to a non-positive budget. This must be
		 * called after cbw_top_half_end() — before that point,
		 * cbw_top_half_running() is true and cbw_throttle_cgroups()
		 * would bail out early. The race with accounting_timerfn, which
		 * may also call cbw_throttle_cgroups() concurrently, is benign:
		 * cbw_throttle_cgroups() only sets is_throttled (never clears
		 * it), so two concurrent calls are idempotent.
		 */
		root_cgrp = bpf_cgroup_from_id(1);
		if (root_cgrp) {
			cbw_throttle_cgroups(root_cgrp);
			bpf_cgroup_release(root_cgrp);
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
	 * If there is no throttled cgroup, let's transit to the empty state
	 * so the bottom half can stop.
	 */
	else {
		cbw_top_half_end(0, false);
	}

	/*
	 * Re-arm the replenish timer. We calculate the jitter to compensate
	 * for the delay of the timer execution, CBW_REPLENISH_PERIOD.
	 */
rearm_out:
	interval = time_delta(now, cbw_last_replenish_at);
	jitter = time_delta(interval, CBW_REPLENISH_PERIOD);
	period = max(time_delta(CBW_REPLENISH_PERIOD, jitter), CBW_REPLENISH_PERIOD_MIN);
	if ((ret = bpf_timer_start(timer, period, 0)))
		cbw_err("Failed to re-arm replenish timer: %d", ret);
	cbw_last_replenish_at = now;

	return 0;
}

static
int cbw_drain_btq_batch(struct scx_cgroup_ctx *cgx,
			struct scx_cgroup_llc_ctx *llcx)
{
	scx_task_common *taskc;
	scx_atq_t *btq;
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
	 *
	 * Re-read llcx->btq on every iteration. cbw_free_llc_ctx() nulls
	 * this field before destroying the ATQ; catching NULL between
	 * iterations prevents operating on a freed ATQ.
	 */
	for (i = 0; i < CBW_REENQ_MAX_BATCH &&
		    (btq = READ_ONCE(llcx->btq)) &&
		    (taskc = (scx_task_common *)scx_atq_pop(btq)) &&
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
			cbw_err("Failed to lookup an LLC context: cgid%llu", cgrp_id);
			continue;
		}

		/*
		 * If the cgroup is throttled, all its LLC contexts are
		 * throttled too. Stop draining immediately.
		 */
		if (cbw_cgroup_bw_throttled(cgrp) == -EAGAIN)
			break;

		nr_enq += cbw_drain_btq_batch(cgx, llcx);
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

static
bool cbw_has_throttled_tasks(union backlog_stat *stat)
{
	/*
	 * Check if there are throttled tasks and populate *stat with a
	 * consistent snapshot of cbw_backlog_stat for the caller to use.
	 *
	 * Test twice -- first with a plain volatile read as a cheap fast path,
	 * then with smp_load_acquire() which pairs with the
	 * __sync_val_compare_and_swap() in cbw_top_half_end(), ensuring that
	 * if has_throttled_tasks=true is observed, all preceding writes to
	 * cbw_throttled_cgroup_ids[] are also visible.
	 */
	stat->val = READ_ONCE(cbw_backlog_stat.val);
	if (unlikely(stat->has_throttled_tasks)) {
		stat->val = smp_load_acquire(&cbw_backlog_stat.val);
		return stat->has_throttled_tasks;
	}
	return false;
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

	union backlog_stat backlog_stat;
	struct scx_cgroup_ctx *cur_cgx;
	struct cgroup *cur_cgrp;
	int i, idx, n, nr_enq = 0;
	u64 nuance, nuance2, nr_tcgs;
	u64 *ids, cur_cgrp_id;
	bool root_added = false;

	/*
	 * If there are throttled tasks in BTQ, let’s reenqueue them.
	 */
	if (likely(!cbw_has_throttled_tasks(&backlog_stat)))
		return 0;

	/*
	 * If another task is already performing the reenqueue operation,
	 * don't start another concurrent reenqueue operation.
	 *
	 * That is because the concurrent reenqueue operation has more harm
	 * than good, especially on a beefy machine, slowing down its caller,
	 * ops.dispatch().
	 *
	 * Note that the reenqueue operation can happen concurrently with
	 * the replenish timer operation.
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
	nr_tcgs = backlog_stat.nr_throttled_cgroups;
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
			cbw_dbg("Failed to fetch a cgroup pointer: %llu", ids[0]);

			/*
			 * This cgroup is already offline: its kernfs node is
			 * deactivated so bpf_cgroup_from_id() returns NULL,
			 * but css_offline() / ops.cgroup_exit() has not yet
			 * run. Move all its throttled tasks to the root cgroup
			 * for immediate draining.
			 */
			if (cbw_cgroup_bw_offline(cur_cgrp_id) > 0) {
				/*
				 * At least one throttled task was moved to
				 * the root cgroup. So we should not transition
				 * to the empty state to stop reenqueue
				 * operations.
				 */
				root_added = true;
			}

			/*
			 * Drain the offline cgroup's BTQ to the root cgroup.
			 * Replace this slot with the root cgroup ID (1) so
			 * the next reenqueue cycle drains the root BTQ
			 * immediately, rather than waiting for the next
			 * replenish timer tick.
			 *
			 * Use CAS rather than a plain write: the replenish
			 * timer may have concurrently overwritten this slot
			 * with a new cgroup ID. If so, the CAS fails and
			 * leaves the new ID intact. This is safe: the root
			 * cgroup always has LLC contexts (has_llcx is
			 * permanently true), so the replenish timer will
			 * detect its backlogged tasks via
			 * cbw_has_backlogged_tasks() and add it to
			 * cbw_throttled_cgroup_ids at the next interval anyway.
			 */
			__sync_bool_compare_and_swap(ids, cur_cgrp_id, 1);
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
		 * When there are no more backlogged tasks under the cgroup,
		 * let's purge the cgroup entry from the throttled cgroup table.
		 */
		if ((n == 0) && !cbw_top_half_running()) {
			/*
			 * There is a TOCTOU window between the
			 * !cbw_top_half_running() check above and this CAS.
			 * cbw_top_half_begin() may fire in that window and
			 * overwrite ids[idx] with a new cgroup ID. The CAS
			 * handles this safely: it is keyed on the old
			 * cur_cgrp_id, so it fails if the entry was already
			 * overwritten by the timer.
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
	 * Unlock before the final state update so other CPUs can start a new
	 * reenqueue cycle. The processing loop above must be serialized, but
	 * the final state update below is protected by CAS and does not need
	 * the lock.
	 */
	cbw_unlock(&reenq_lock);

	/*
	 * If there is nothing that we can reenqueue (because the BTQs are
	 * empty or the cgroups are throttled again), transit to the empty
	 * state. The CAS is keyed on the full backlog_stat snapshot including
	 * rp_seq. If cbw_top_half_begin() fired since the snapshot was taken,
	 * rp_seq in cbw_backlog_stat.val will have changed and the CAS will
	 * fail safely, leaving has_throttled_tasks for the new cycle to manage.
	 */
	if ((nr_enq == 0) && !root_added && !cbw_top_half_running()) {
		cbw_update_backlog_stat_cas(&backlog_stat,
					    backlog_stat.rp_seq,
					    backlog_stat.nr_throttled_cgroups,
					    false);
	}
	return 0;
}

/**
 * scx_cgroup_bw_is_cgroup_throttled - Test if a cgroup is throttled or not.
 *
 * @cgrp_id: cgroup id
 *
 * Return true if the cgroup is throttled. Otherwise, return false.
 */
__hidden
int scx_cgroup_bw_is_cgroup_throttled(u64 cgrp_id)
{
	struct scx_cgroup_ctx *cgx;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		return 0;

	cgx = cbw_get_cgroup_ctx(cgrp);
	bpf_cgroup_release(cgrp);
	if (!cgx)
		return 0;

	return READ_ONCE(cgx->is_throttled);
}


/**
 * scx_cgroup_bw_is_task_throttled - Test if a task is throttled or not.
 *
 * @taskc: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 *
 * Return true if the task is throttled. Otherwise, return false.
 */
__hidden
int scx_cgroup_bw_is_task_throttled(u64 taskc)
{
	scx_task_common *ctx = (scx_task_common *)taskc;
	return ctx && (ctx->atq != NULL);
}

/**
 * scx_cgroup_bw_move - Move a task from a cgroup to another (@from -> @to).
 *
 * @p: task being moved
 * @taskc: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 * @from: cgroup @p is being moved from
 * @to: cgroup @p is being moved to
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_move(struct task_struct *p __arg_trusted, u64 taskc,
		       struct cgroup *from __arg_trusted,
		       struct cgroup *to __arg_trusted)
{
	int ret;

	/*
	 * If a task is throttled, remove it from the @from cgroup,
	 * then add it to the BTQ of the @to cgroup.
	 *
	 * We will try to reenqueue it in the next replenishment interval.
	 * This is fair because the task was throttled under @from cgroup,
	 * so it has to wait until the next replenishment interval anyway.
	 */
	if (!scx_cgroup_bw_is_task_throttled(taskc))
		return 0;

	if ((ret = scx_cgroup_bw_cancel(taskc))) {
		cbw_err("Fail to cancel a throttled task (%s:%d) from a cgroup (cgid%llu): %d",
			p->comm, p->pid, cgroup_get_id(from), ret);
		return ret;
	}

	if ((ret = scx_cgroup_bw_put_aside(p, taskc,  p->scx.dsq_vtime, to))) {
		cbw_err("Fail to put aside a throttled task (%s:%d) to a cgroup (cgid%llu): %d",
			p->comm, p->pid, cgroup_get_id(to), ret);
	}

	return ret;
}

static __noinline
int cbw_dump_cgroup(struct cgroup *cgrp __arg_trusted, bool indent)
{
	static const char indent_strs[][64] = {
		"",
		"  ",
		"    ",
		"      ",
		"        ",
		"          ",
		"            ",
		"              ",
		"                ",
		"                  ",
		"                    ",
		"                      ",
		"                        ",
		"                          ",
		"                            ",
		"                              ",
		"                                ",
		"                                  ",
		"                                    ",
		"                                      ",
		"                                        ",
		"                                          ",
		"                                            ",
		"                                              ",
		"                                                ",
		"                                                  ",
		"                                                    ",
		"                                                      ",
		"                                                        ",
		"                                                          ",
		"                                                            ",
		"                                                              ",
	};
	static const u32 indent_max = sizeof(indent_strs) / sizeof(indent_strs[0]);

	struct scx_cgroup_llc_ctx *llcx;
	int i, nr_throttled_tasks = 0;
	struct scx_cgroup_ctx *cgx;
	const char *indent_str;
	scx_atq_t *btq;
	char name[64];

	/* Attach the timer function to the BPF area context. */
	scx_arena_subprog_init();

	cgx = cbw_get_cgroup_ctx(cgrp);
	if (!cgx) {
		cbw_dbg("Failed to lookup a cgroup context: %llu", cgroup_get_id(cgrp));
		return -ESRCH;
	}

	indent_str = indent_strs[ clamp((u32)cgrp->level, 0, indent_max - 1) ];

	bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(cgrp->kn, name));
	bpf_printk("%s +-- %s (id: %llu, level: %d)", indent_str,
			name, cgroup_get_id(cgrp), (u32)cgrp->level);

	if (cgx->nquota_ub == CBW_RUNTUME_INF)
		return 0;

	if (cgx->has_llcx) {
		bpf_for(i, 0, TOPO_NR(LLC)) {
			llcx = cbw_get_llc_ctx(cgrp, i);
			if (!llcx || !(btq = READ_ONCE(llcx->btq)))
				continue;
			nr_throttled_tasks += scx_atq_nr_queued(btq);
		}
	}

	bpf_printk("%s   \\_ quota: %llu/%llu/%llu, period: %llu, burst: %llu", indent_str,
			cgx->quota, cgx->period, cgx->burst);
	bpf_printk("%s   \\_ nquota: %llu, nquota_ub: %llu, has_llcx: %d", indent_str,
			cgx->nquota, cgx->nquota_ub, cgx->has_llcx);
	bpf_printk("%s   \\_ is_throttled: %d, nr_throttled_periods: %d/%d, nr_throttled_tasks: %d", indent_str,
			cgx->is_throttled,
			cgx->nr_throttled_periods, READ_ONCE(cbw_backlog_stat.rp_seq) / 2,
			nr_throttled_tasks);
	bpf_printk("%s   \\_ period_budget: %lld, burst_remaining: %lld", indent_str,
			cgx->period_budget, cgx->burst_remaining);
	bpf_printk("%s   \\_ runtime_total_sloppy: %lld, runtime_total_last: %lld", indent_str,
			cgx->runtime_total_sloppy, cgx->runtime_total_last);
					
	return 0;
}

/**
 * scx_cgroup_bw_dump - Dump the cgroup status
 *
 * @cgrp_id: cgroup id
 * @descendent: If true, dump the cgroup and its descendent in preorder.
 * Otherwise, dump only itself.
 * @accurate: If true, update runtime total before dumping the status to
 * get more accurate information. Otherwise, dump the currently collected
 * snapshot of runtime values.
 * @indent: If true, indent the output. Otherwise, do not indent the output.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_dump(u64 cgrp_id, bool descendent, bool accurate, bool indent)
{
	struct cgroup_subsys_state *start_css, *pos;
	struct cgroup *start_cgrp, *cur_cgrp;

	start_cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!start_cgrp) {
		cbw_dbg("Failed to fetch a cgroup pointer: cgid%llu", cgrp_id);
		return -ESRCH;
	}

	if (accurate)
		cbw_update_runtime_total_sloppy(start_cgrp);

	if (!descendent) {
		cbw_dump_cgroup(start_cgrp, indent);
		goto release_out;
	}

	bpf_rcu_read_lock();
	start_css = &start_cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cbw_dump_cgroup(cur_cgrp, indent);
	}
	bpf_rcu_read_unlock();

release_out:
	bpf_cgroup_release(start_cgrp);
	return 0;
}
