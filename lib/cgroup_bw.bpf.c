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

#ifndef U64_MAX
#define U64_MAX		((u64)~0ULL)
#endif

extern int scx_cgroup_bw_enqueue_cb(u64 taskc);

enum scx_cgroup_consts {
	/* clock boottime constant */
	CBW_CLOCK_BOOTTIME		= 7,
	/* replenish period in nsec: 100 msec */
	CBW_REPLENISH_PERIOD		= (100ULL * 1000ULL * 1000ULL),
	/* min replenish period in nsec after jitter compensation: 1 msec */
	CBW_REPLENISH_PERIOD_MIN	= (1ULL * 1000ULL * 1000ULL),
	/* min/max accounting period in nsec: 1 msec and 20 msec */
	CBW_ACCOUNTING_PERIOD_MIN	= (1ULL * 1000ULL * 1000ULL),
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
	/* The maximum height of a cgroup tree.
	 * cgroupv2 default maximum depth is 32 (kernel CGROUPS_DEPTH_MAX). */
	CBW_CGRP_TREE_HEIGHT_MAX	= 32,
	/* unlimited quota ("max") from scx_cgroup_init_args and scx_cgroup_bw_set() */
	CBW_RUNTUME_INF_RAW		= ((u64)~0ULL),
	/* unlimited quota ("max"); This is for easier comparison between signed vs. unsigned integers. */
	CBW_RUNTUME_INF			= ((s64)~((u64)1 << 63)),
	/* maximum number of re-enqueue tasks in one dispatch */
	CBW_REENQ_MAX_BATCH		= 2,
};

/*
 * Root cgroup id.  This is the kernel-level cgroup_id of the
 * cgroup-v2 default hierarchy root, which is always 1 on a
 * standard kernel configuration (kernfs allocates the root with
 * inode 1 in cgrp_dfl_root.kf_root).  Cgroup namespaces do not
 * change this value -- they create a virtual root *view* but the
 * underlying struct cgroup objects keep their kernel-level ids.
 *
 * Kept as a named constant rather than a literal 1 so future
 * cgroup-namespace-aware support (where the scheduler's effective
 * scope is some non-root cgroup) has a clear hook to plug into.
 */
#define ROOT_CGID	1ULL

/*
 * TGID of the loader process (e.g., scx_lavd) captured at
 * scx_cgroup_bw_lib_init() time.  Used by cbw_get_root_cgrp() to
 * resolve the root cgroup pointer; see that function for details.
 */
static u32 cbw_loader_tgid;

/**
 * Per-cgroup data structure containing cpu.max-related information.
 * In the future, it can be extended to support other features of cgroup
 * beyond cpu.max.
 */
struct scx_cgroup_ctx {
	/* read-only cache line */
	struct {
		/*
		 * Free-list link.  Must be the first field so that
		 * cbw_freelist_pop() and cbw_freelist_push() can operate on any
		 * arena struct generically.  Only valid while the object is on
		 * the free list; overwritten by scx_cgroup_bw_init() on reuse.
		 */
		u64		free_next;

		/* cgroup id */
		u64		id;

		/*
		 * Id of the nearest ancestor with a context -- the effective
		 * parent in the tree of tracked cgroups: the nearest limited
		 * (finite cpu.max) ancestor, or the root. Infinite ancestors are
		 * skipped. 0 for the root itself. Set once at init.
		 */
		u64		eff_parent_id;

		/* cgroup tree depth (root = 0); set once at init */
		u32		level;

		/*
		 * Given @quota, @period, and @burst in nanoseconds.
		 */
		u64		quota;
		u64		period;
		u64		burst;
	
		/*
		 * Normalized quota by period of 100 msec. By using the same
		 * period, we can use a single BPF timer to handle all the
		 * cgroups.
		 */
		u64		nquota;
	
		/*
		 * The upper bound of a cgroup’s quota, which is the minimum
		 * normalized quota of all its ancestors and itself.
		 */
		u64		nquota_ub;
	} __attribute__((aligned(SCX_CACHELINE_SIZE)));

	/* read-write cache line */
	struct {
		/*
		 * A boolean flag indicating whether the cgroup is throttled or
		 * not. Note that the cgroup can be throttled before reaching
		 * the upper bound (nquota_ub) if its ancestor runs out of the
		 * time.
		 */
		bool		is_throttled;

		/*
		 * How many times this cgroup is throttled so far.
		 */
		u32		nr_throttled_periods;

		/* Run of consecutive throttled periods: current and max seen. */
		bool		was_throttled;	/* is_throttled at the previous period */
		u32		nr_consec_throttled_periods;
		u32		max_consec_throttled_periods;

		/*
		 * @period_start_clk represents when a new period starts.
		 * @burst_remaining is the maximum burst that can be accumulated
		 * until the end of the period from @period_start_clk.
		 */
		u64		period_start_clk;
		s64		burst_remaining;

		/*
		 * Effective quota for the current period: nquota_ub adjusted
		 * for debt (overspend from the previous period, subtracted) and
		 * burst credit (underspend carried forward, added). Set at each
		 * period boundary by replenish_timerfn(). Used by
		 * cbw_update_runtime_total_sloppy() as the throttle threshold
		 * instead of the bare nquota_ub, so that long-run average
		 * utilization converges to the configured quota.
		 */
		s64		period_budget;

		/*
		 * Total amount of time executed once replenished. It includes
		 * @runtime_total of all LLC contexts of this cgroup. It is
		 * sloppy since it is update only before asking more budget to
		 * its parent. In other words, it is not updated as
		 * @runtime_total of its LLC contexts are updated, so it could
		 * be outdated. When it is greater than @quota_ub, we cannot ask
		 * for more budget from the parent, so there will be no more
		 * updates on @runtime_total_sloppy before the next period
		 * starts.
		 */
		s64		runtime_total_sloppy;

		/*
		 * Total runtime at the last replenishment period.
		 */
		s64		runtime_total_last;

		/*
		 * EWMA of CPU consumption rate within a replenish interval, in
		 * CBW_SCALE fixed-point. CBW_SCALE (1024) represents consuming
		 * the full CBW_REPLENISH_PERIOD worth of CPU time, i.e., 100%
		 * of one CPU core. Updated only when the cgroup was active
		 * (runtime_total_last > 0) to avoid pulling the average toward
		 * zero during idle periods. With CBW_CONSUMPTION_RATE_DECAY=3,
		 * the half-lifetime is ~5.2 replenish intervals (~520ms at
		 * CBW_REPLENISH_PERIOD = 100ms).
		 *
		 * Default is 0 (zero-initialized by BPF map). This is
		 * reasonable because __calc_avg() uses a 50/50 blend when the
		 * old value is small (< 1 << decay), so the average ramps up
		 * quickly on the first few active intervals rather than warming
		 * up slowly.
		 *
		 * For unconstrained cgroups (nquota_ub == CBW_RUNTUME_INF),
		 * cbw_replenish_cgroup() returns early, so avg_consumption_rate
		 * stays 0. This is correct: a cgroup with no quota limit has no
		 * meaningful consumption rate to track.
		 */
		u64		avg_consumption_rate;
	} __attribute__((aligned(SCX_CACHELINE_SIZE)));
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

typedef struct scx_cgroup_ctx __arena scx_cgroup_ctx_t;

/**
 * If a cgroup is either at a leaf level or threaded, we manage per-LLC-cgroup
 * contexts to reduce cross-LLC cache coherence traffic. Otherwise, the cgroup
 * stats are used only for distributing remaining budgets. In this case, we do
 * not manage per-LLC context since they will be accessed much less frequently.
 */
struct scx_cgroup_llc_ctx {
	/*
	 * Free-list link.  Must be the first field so that cbw_freelist_pop()
	 * and cbw_freelist_push() can operate on any arena struct generically.
	 * When this object is on the free list, holds the raw u64 arena address
	 * of the next free node (0 = end of list).  Only valid between
	 * cbw_free_llcx() pushing and cbw_alloc_llcx_sleepable() popping.
	 */
	u64		free_next;

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

typedef struct scx_cgroup_llc_ctx __arena scx_cgroup_llc_ctx_t;

/*
 * Library-wide configuration for CPU bandwidth control.
 */
static struct scx_cgroup_bw_config cbw_config;

/*
 * Load-time cap on the number of managed cgroups. Defaults to CBW_NR_CGRP_MAX;
 * userspace may set this before load and resize the backing maps to match
 * (cbw_cgrp_map, cbw_cgrp_llc_map, cbw_cgroup_ids, cbw_throttled_cgroup_ids).
 */
const volatile u32 nr_cgrp_max = CBW_NR_CGRP_MAX;

/*
 * Load-time cap on cgroup nesting depth. Defaults to CBW_CGRP_TREE_HEIGHT_MAX;
 * userspace may set this before load and resize tree_levels_map to match.
 */
const volatile u32 tree_height_max = CBW_CGRP_TREE_HEIGHT_MAX;

/*
 * Whether ops.cgroup_set_bandwidth() runs in a sleepable context, which the
 * kernel allows only with the "sched_ext: allow ops.cgroup_set_bandwidth() to
 * be sleepable" change. Userspace probes for it and sets this together with the
 * program's BPF_F_SLEEPABLE flag before load.
 *
 * When true, a cgroup that gains a finite cpu.max at runtime materializes its
 * context by allocating on demand, so no memory is pre-reserved. When false,
 * the non-sleepable path pre-reserves a spare set per unmanaged cgroup during
 * the sleepable ops.cgroup_init() and claims it at materialize. This is a
 * const so the verifier prunes the unused (and, for the non-sleepable load,
 * verifier-illegal sleepable-allocation) branch.
 */
const volatile bool bw_set_sleepable;

/*
 * A map to store scx_cgroup_ctx. It is accessed through a cgroup pointer.
 *
 * scx_cgroup_ctx objects are allocated in the BPF arena via
 * scx_static_alloc(); the map holds only an arena pointer to each object.
 */
struct cbw_cgrp_entry {
	u64	cgx;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct cbw_cgrp_entry);
	__uint(max_entries, CBW_NR_CGRP_MAX);
} cbw_cgrp_map SEC(".maps");

/*
 * A map to store scx_cgroup_llc_ctx. It is accessed through a pair of
 * cgroup id and LLC id (struct cgroup_llc_id).
 *
 * scx_cgroup_llc_ctx objects are allocated in the BPF arena via
 * scx_static_alloc(); the map holds only an arena pointer to each object.
 */
struct cgroup_llc_id {
	u64		cgrp_id;
	int		llc_id;
} __attribute__((packed));

struct cbw_llc_entry {
	u64	llcx;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct cgroup_llc_id);
	__type(value, struct cbw_llc_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	/* single-LLC default; userspace grows it to CBW_NR_CGRP_MAX * nr_llcs */
	__uint(max_entries, CBW_NR_CGRP_MAX);
} cbw_cgrp_llc_map SEC(".maps");

/*
 * Generic Treiber-stack free list for arena objects.
 *
 * Any arena struct using these helpers must place a u64 free_next field first.
 * The head is a plain u64 BSS variable holding the raw arena address of the
 * top-of-stack object (0 = empty).  Both push and pop use CAS with can_loop-
 * bounded retries; arena pointers are reconstructed via addr_space_cast on pop.
 */
static inline void __arena *cbw_freelist_pop(u64 *head)
{
	u64 old_head, new_head;
	u64 __arena *node;

	old_head = *head;
	while (can_loop && old_head) {
		node = (u64 __arena *)old_head;	/* first field is free_next */
		new_head = *node;
		if (__sync_bool_compare_and_swap(head, old_head, new_head))
			return (void __arena *)node;
		old_head = *head;
	}
	return NULL;
}

static inline void cbw_freelist_push(u64 *head, void __arena *ptr)
{
	u64 __arena *node = (u64 __arena *)ptr;	/* first field is free_next */
	u64 old_head;

	old_head = *head;
	do {
		*node = old_head;
		if (__sync_bool_compare_and_swap(head, old_head, (u64)node))
			return;
		old_head = *head;
	} while (can_loop);
}

/*
 * CPU-bandwidth reserve accounting.
 *
 * A cgroup that gains a finite cpu.max at runtime is materialized from the
 * non-sleepable ops.cgroup_set_bandwidth(), which cannot allocate. To guarantee
 * it always finds a ready context set, every unmanaged (infinite) cgroup
 * reserves one spare set -- 1 cgx plus one llcx-with-BTQ per LLC -- during its
 * sleepable ops.cgroup_init(). cbw_nr_pending_reservations counts those
 * reservations; cbw_nr_free_{cgx,llcx} (declared with their free lists below)
 * count the objects currently parked on the lists. The invariant held at every
 * instant is
 *
 *     cbw_nr_free_cgx  >= cbw_nr_pending_reservations, and
 *     cbw_nr_free_llcx >= cbw_nr_pending_reservations * TOPO_NR(LLC),
 *
 * so a burst of concurrent materializations can never exhaust the reserve.
 *
 * Free-list discipline that makes the counters safe to act on: push the object
 * onto the list *before* incrementing the counter, and (atomically) decrement
 * the counter *before* popping. The counter then never exceeds the list length,
 * so a successful decrement always has a real object to pop.
 */
static s64 cbw_nr_pending_reservations;

/*
 * Atomically claim one object from *counter while keeping it above the reserve
 * floor cbw_nr_pending_reservations * @floor_mult. Returns true after the
 * decrement (the caller then pops), or false if nothing is available above the
 * floor. @floor_mult is 1 for cgx and TOPO_NR(LLC) for llcx in the sleepable
 * managed allocator, and 0 in the non-sleepable materialize allocator (which is
 * entitled to the reserve). The counter (supply) is read before the floor
 * (demand): since a reservation publishes the demand before pushing the spare,
 * a counter that already reflects the spare pairs with a freshly read floor
 * that reflects the reservation -- so a managed init cannot claim a fresh
 * reserve through a stale-low floor.
 */
static inline bool cbw_claim_free(u64 *counter, u64 floor_mult)
{
	u64 f, floor;
	s64 pending;

	while (can_loop) {
		f = READ_ONCE(*counter);
		/*
		 * Complete the pairing with the reservation side, which orders
		 * its two updates with full barriers: keep the supply and floor
		 * loads below from being satisfied out of order on a weakly
		 * ordered CPU, which would pair a new supply with a stale floor.
		 */
		smp_rmb();
		pending = READ_ONCE(cbw_nr_pending_reservations);
		floor = (pending > 0 ? (u64)pending : 0) * floor_mult;
		if (f <= floor)
			return false;
		if (__sync_bool_compare_and_swap(counter, f, f - 1))
			return true;
	}
	return false;
}

/*
 * Per-type free-list heads and alloc/free wrappers for scx_cgroup_llc_ctx.
 * Cacheline-aligned to avoid false sharing with adjacent globals.
 */
static u64 cbw_llcx_free_head __attribute__((aligned(SCX_CACHELINE_SIZE)));
static u64 cbw_nr_free_llcx;	/* objects on cbw_llcx_free_head */

static inline scx_cgroup_llc_ctx_t *cbw_alloc_llcx_sleepable(void)
{
	/*
	 * Managed (sleepable) allocation: reuse a recycled llcx only from the
	 * surplus beyond the reserve; otherwise allocate fresh, leaving the
	 * reserve intact. A recycled llcx carries its BTQ; a fresh one is
	 * BTQ-less and the caller (__cbw_init_llcx_sleepable()) creates one.
	 */
	if (cbw_claim_free(&cbw_nr_free_llcx, TOPO_NR(LLC))) {
		scx_cgroup_llc_ctx_t *llcx = cbw_freelist_pop(&cbw_llcx_free_head);

		if (llcx)
			return llcx;
		/* Claimed a slot but the pop lost a CAS race; undo and fall back. */
		__sync_fetch_and_add(&cbw_nr_free_llcx, 1);
	}
	return scx_static_alloc(sizeof(scx_cgroup_llc_ctx_t), SCX_CACHELINE_SIZE);
}

/*
 * Materialize (non-sleepable) allocation: claim a reserved llcx-with-BTQ, or
 * NULL when the reserve is empty. Never allocates. A rare BTQ-less spare (left
 * by a failed BTQ create) is discarded and the next tried.
 */
static inline scx_cgroup_llc_ctx_t *cbw_alloc_llcx_atomic(void)
{
	scx_cgroup_llc_ctx_t *llcx;

	while (can_loop) {
		if (!cbw_claim_free(&cbw_nr_free_llcx, 0))
			return NULL;
		llcx = cbw_freelist_pop(&cbw_llcx_free_head);
		if (!llcx) {
			/* Claimed a slot but the pop lost a CAS race; undo and bail. */
			__sync_fetch_and_add(&cbw_nr_free_llcx, 1);
			return NULL;
		}
		if (llcx->btq)
			return llcx;
		/*
		 * BTQ-less spare: its claim already removed it from the list, so
		 * drop it (arena never frees) and try the next.
		 */
	}
	return NULL;
}

static inline void cbw_free_llcx(scx_cgroup_llc_ctx_t *llcx)
{
	const int btq_off = __builtin_offsetof(struct scx_cgroup_llc_ctx, btq);
	int i;

	/*
	 * Zero every field except btq. BTQs are never destroyed, so a recycled
	 * llcx keeps its (drained, empty) BTQ for reuse by a later init.
	 * btq is left untouched -- not zeroed and restored -- so that a
	 * concurrent stale drain re-reading llcx->btq never observes a torn
	 * pointer during recycling.
	 */
	for (i = 0; can_loop && i < sizeof(*llcx); i++) {
		if (i >= btq_off && i < btq_off + sizeof(llcx->btq))
			continue;
		((char __arena *)llcx)[i] = 0;
	}
	cbw_freelist_push(&cbw_llcx_free_head, llcx);
	__sync_fetch_and_add(&cbw_nr_free_llcx, 1);	/* push before count */
}

/*
 * Per-type free-list head and alloc/free wrappers for scx_cgroup_ctx.
 * Cacheline-aligned to avoid false sharing with adjacent globals.
 */
static u64 cbw_cgx_free_head __attribute__((aligned(SCX_CACHELINE_SIZE)));
static u64 cbw_nr_free_cgx;	/* objects on cbw_cgx_free_head */

static inline scx_cgroup_ctx_t *cbw_alloc_cgx_sleepable(void)
{
	/* Managed (sleepable): reuse surplus beyond the reserve, else fresh. */
	if (cbw_claim_free(&cbw_nr_free_cgx, 1)) {
		scx_cgroup_ctx_t *cgx = cbw_freelist_pop(&cbw_cgx_free_head);

		if (cgx)
			return cgx;
		/* Claimed a slot but the pop lost a CAS race; undo and fall back. */
		__sync_fetch_and_add(&cbw_nr_free_cgx, 1);
	}
	return scx_static_alloc(sizeof(scx_cgroup_ctx_t), SCX_CACHELINE_SIZE);
}

/* Materialize (non-sleepable): claim a reserved cgx, or NULL. Never allocates. */
static inline scx_cgroup_ctx_t *cbw_alloc_cgx_atomic(void)
{
	if (cbw_claim_free(&cbw_nr_free_cgx, 0)) {
		scx_cgroup_ctx_t *cgx = cbw_freelist_pop(&cbw_cgx_free_head);

		if (cgx)
			return cgx;
		/* Claimed a slot but the pop lost a CAS race; undo and bail. */
		__sync_fetch_and_add(&cbw_nr_free_cgx, 1);
	}
	return NULL;
}

static inline void cbw_free_cgx(scx_cgroup_ctx_t *cgx)
{
	int i;

	for (i = 0; can_loop && i < sizeof(*cgx); i++)
		((char __arena *)cgx)[i] = 0;
	cbw_freelist_push(&cbw_cgx_free_head, cgx);
	__sync_fetch_and_add(&cbw_nr_free_cgx, 1);	/* push before count */
}

/*
 * Build the spare context set (1 cgx + one llcx-with-BTQ per LLC) that a
 * context-less cgroup's reservation covers, so a later non-sleepable
 * ops.cgroup_set_bandwidth() can materialize from it. The caller has already
 * published the demand (cbw_nr_pending_reservations++), so throughout the build
 * a concurrent managed init already sees the raised floor and cannot claim the
 * spare being pushed as if it were surplus. The transient
 * cbw_nr_free_* < cbw_nr_pending gap this opens is exactly this cgroup's
 * not-yet-built set, and this cgroup cannot materialize until its init returns,
 * so no materialize consumes it early. Any allocation failure is fatal: the
 * reservation is already published, so a partial spare would break the
 * cbw_nr_free_* >= cbw_nr_pending invariant and later strand a correctly-
 * reserved cgroup; call scx_bpf_error() to eject. MUST run in a sleepable
 * context.
 */
static void cbw_build_spare(void)
{
	scx_cgroup_ctx_t *cgx;
	scx_cgroup_llc_ctx_t *llcx;
	int i;

	cgx = scx_static_alloc(sizeof(*cgx), SCX_CACHELINE_SIZE);
	if (!cgx) {
		scx_bpf_error("cgroup_bw: failed to build spare cgx");
		return;
	}
	cbw_free_cgx(cgx);

	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = scx_static_alloc(sizeof(*llcx), SCX_CACHELINE_SIZE);
		if (!llcx) {
			scx_bpf_error("cgroup_bw: failed to build spare llcx");
			return;
		}
		llcx->btq = (scx_atq_t *)scx_atq_create(false);
		if (!llcx->btq) {
			scx_bpf_error("cgroup_bw: failed to build spare BTQ");
			return;	/* llcx orphaned; arena never frees */
		}
		cbw_free_llcx(llcx);
	}
}

/*
 * A per-CPU map of per-level accumulators used while traversing a cgroup
 * hierarchy in cbw_update_runtime_total_sloppy(). Keyed by cgroup level, it
 * keeps the aggregation off the (limited) BPF stack. Sized to
 * CBW_CGRP_TREE_HEIGHT_MAX by default; userspace may resize it to
 * tree_height_max before load.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, s64);
	__uint(max_entries, CBW_CGRP_TREE_HEIGHT_MAX);
} tree_levels_map SEC(".maps");

/*
 * An array of cgroups that can have tasks. This is necessary to iterate
 * cgroups without holding an RCU lock.
 */
static u64		cbw_nr_cgroups;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, CBW_NR_CGRP_MAX);
} cbw_cgroup_ids SEC(".maps");

/*
 * Number of allocated cgroup contexts, i.e. the live occupancy of
 * cbw_cgrp_map. Bumped atomically on a successful init and dropped on exit,
 * and used to cap the number of managed cgroups at CBW_NR_CGRP_MAX. This is
 * distinct from cbw_nr_cgroups above, which is only the fill count of
 * cbw_cgroup_ids[] rebuilt on every replenish.
 */
static u64		cbw_nr_cgx;

/*
 * An array of throttled cgroups that need to be reenqueued.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, CBW_NR_CGRP_MAX);
} cbw_throttled_cgroup_ids SEC(".maps");

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
	} while (can_loop && (ret.val != old.val));
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
	} while (can_loop && (ret.val != old.val));
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
		return -EOPNOTSUPP;
	}

	/* Initialize the library-wide configuration. */
	if (!config)
		return -EINVAL;
	cbw_config = *config;

	/* Capture the loader's TGID; see cbw_get_root_cgrp(). */
	cbw_loader_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

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
u64 cgroup_get_id(struct cgroup *cgrp)
{
	return cgrp->kn->id;
}

static __always_inline
u64 cbw_get_cgroup_ctx_raw(u64 cgrp_id)
{
	struct cbw_cgrp_entry *entry;

	entry = bpf_map_lookup_elem(&cbw_cgrp_map, &cgrp_id);
	return entry ? entry->cgx : 0;
}

static __always_inline
scx_cgroup_ctx_t *cbw_get_cgroup_ctx_with_id(u64 cgrp_id)
{
	return (scx_cgroup_ctx_t *)cbw_get_cgroup_ctx_raw(cgrp_id);
}

static __always_inline
scx_cgroup_ctx_t *cbw_get_cgroup_ctx(struct cgroup *cgrp)
{
	return (scx_cgroup_ctx_t *)cbw_get_cgroup_ctx_raw(cgroup_get_id(cgrp));
}

long cbw_del_cgroup_ctx(u64 cgrp_id)
{
	scx_cgroup_ctx_t *cgx = cbw_get_cgroup_ctx_with_id(cgrp_id);
	long ret = bpf_map_delete_elem(&cbw_cgrp_map, &cgrp_id);

	/*
	 * Unpublish the context before recycling it: with the map entry gone a
	 * concurrent lookup resolves to the cgroup's effective parent instead of
	 * reading the zeroed cgx -- or, once the object is reused, another
	 * cgroup's cgx.
	 */
	if (cgx)
		cbw_free_cgx(cgx);
	return ret;
}

static __always_inline
u64 cbw_get_llc_ctx_raw_with_id(u64 cgrp_id, int llc_id)
{
	struct cbw_llc_entry *entry;
	struct cgroup_llc_id key = {
		.cgrp_id = cgrp_id,
		.llc_id = llc_id,
	};

	entry = bpf_map_lookup_elem(&cbw_cgrp_llc_map, &key);
	return entry ? entry->llcx : 0;
}

static __always_inline
scx_cgroup_llc_ctx_t *cbw_get_llc_ctx_with_id(u64 cgrp_id, int llc_id)
{
	return (scx_cgroup_llc_ctx_t *)cbw_get_llc_ctx_raw_with_id(cgrp_id, llc_id);
}

static __always_inline
scx_cgroup_llc_ctx_t *cbw_get_llc_ctx(struct cgroup *cgrp, int llc_id)
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

/*
 * Sleepable implementation of cbw_init_llcx(): allocate each per-LLC context on
 * demand and publish it in cbw_cgrp_llc_map under BPF_NOEXIST. A recycled llcx
 * carries its BTQ (never destroyed); reuse it and only create one for a fresh,
 * BTQ-less object.
 *
 * Returns -EEXIST if a concurrent materialize of @cgrp published first.
 */
static
int __cbw_init_llcx_sleepable(struct cgroup *cgrp, scx_cgroup_ctx_t *cgx)
{
	u64 cgrp_id = cgroup_get_id(cgrp);
	int i, ret;

	if (!cgx || !cgrp)
		return -EINVAL;

	bpf_for(i, 0, TOPO_NR(LLC)) {
		struct cbw_llc_entry entry = {};
		struct cgroup_llc_id key = {
			.cgrp_id = cgrp_id,
			.llc_id = i,
		};
		scx_cgroup_llc_ctx_t *llcx = cbw_alloc_llcx_sleepable();

		if (llcx && !llcx->btq) {
			llcx->btq = (scx_atq_t *)scx_atq_create(false);
			if (!llcx->btq) {
				cbw_err("Fail to allocate a BTQ");
				cbw_free_llcx(llcx);
				llcx = NULL;
			}
		}
		if (!llcx)
			return -ENOMEM;

		llcx->id = cgrp_id;
		entry.llcx = (u64)llcx;
		ret = bpf_map_update_elem(&cbw_cgrp_llc_map, &key, &entry,
					  BPF_NOEXIST);
		if (ret) {
			cbw_free_llcx(llcx);
			return ret;
		}
	}
	return 0;
}

/*
 * Non-sleepable counterpart of __cbw_init_llcx_sleepable(): claim each per-LLC context
 * from the reserve built during ops.cgroup_init() (each already owns a drained
 * BTQ) rather than allocating, and publish it under BPF_NOEXIST.
 *
 * Returns -EEXIST if a concurrent materialize of @cgrp published first.
 */
static
int __cbw_init_llcx_atomic(struct cgroup *cgrp, scx_cgroup_ctx_t *cgx)
{
	u64 cgrp_id = cgroup_get_id(cgrp);
	int i, ret;

	bpf_for(i, 0, TOPO_NR(LLC)) {
		struct cbw_llc_entry entry = {};
		struct cgroup_llc_id key = {
			.cgrp_id = cgrp_id,
			.llc_id = i,
		};
		scx_cgroup_llc_ctx_t *llcx = cbw_alloc_llcx_atomic();

		if (!llcx)
			return -ENOMEM;

		llcx->id = cgrp_id;
		entry.llcx = (u64)llcx;
		ret = bpf_map_update_elem(&cbw_cgrp_llc_map, &key, &entry,
					  BPF_NOEXIST);
		if (ret) {
			cbw_free_llcx(llcx);
			return ret;
		}
	}
	return 0;
}

/*
 * Populate @cgx's per-LLC contexts and publish them. The sleepable path
 * (patched kernel) allocates on demand; the non-sleepable path claims the
 * reserve built during ops.cgroup_init(). The bw_set_sleepable const prunes the
 * branch not in use, so a non-sleepable load never verifies the sleepable
 * allocation. Both publish under BPF_NOEXIST and return -EEXIST if a concurrent
 * materialize of @cgrp published first, so the caller leaves it to that winner.
 */
static
int cbw_init_llcx(struct cgroup *cgrp, scx_cgroup_ctx_t *cgx)
{
	if (bw_set_sleepable)
		return __cbw_init_llcx_sleepable(cgrp, cgx);
	return __cbw_init_llcx_atomic(cgrp, cgx);
}

__hidden
int cbw_put_aside(u64 ctx, u64 vtime, u64 bill_id);

static __always_inline
int cbw_free_llc_ctx(u64 cgrp_id)
{
	scx_cgroup_llc_ctx_t *llcx;
	volatile int nr_moved = 0; /* Add volatile to satisfy the verifier. */
	int i, ret;
	scx_atq_t *btq;
	u64 taskc;

	/*
	 * Root's LLC contexts are invariant for the scheduler's
	 * lifetime; refuse to tear them down regardless of caller.
	 */
	if (unlikely(cgrp_id == ROOT_CGID))
		return 0;

	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx_with_id(cgrp_id, i);
		if (!llcx || !(btq = READ_ONCE(llcx->btq)))
			continue;

		/*
		 * Winner-takes-all via the map delete: bpf_map_delete_elem is
		 * atomic, so exactly one CPU removes the entry and then owns the
		 * now-unmapped llcx exclusively; the losers skip and move on to
		 * the next LLC context (cbw_free_llc_ctx() is multi-CPU-reentrant).
		 * Deleting first also stops new put-asides into this cgroup's BTQ
		 * during the drain (lookups return NULL), and cbw_put_aside()
		 * re-checks the map under the BTQ lock to catch one in flight.
		 */
		if (cbw_del_llc_ctx_with_id(cgrp_id, i))
			continue;

		/*
		 * Move all the throttled exiting tasks into the root cgroup.
		 */
		if (cgrp_id != ROOT_CGID) {
			while (can_loop && (taskc = scx_atq_pop(btq, true))) {
				scx_task_cgroup_bw_t *t = (scx_task_cgroup_bw_t *)taskc;
				/*
				 * Invalidate the per-task cgx/llcx caches before
				 * moving the task to the root BTQ. The old cgroup
				 * context will be freed by cbw_del_cgroup_ctx()
				 * shortly; a stale cgx_raw would cause throttle
				 * checks to read freed or reallocated memory
				 * (ABA), potentially throttling the task under
				 * the wrong cgroup.
				 *
				 * No smp_mb() is needed here: cbw_put_aside()
				 * acquires and releases the BTQ spinlock, whose
				 * store-release orders these stores before the
				 * task becomes visible in the BTQ. The drain
				 * path's lock-acquire provides the matching
				 * load-acquire.
				 */
				WRITE_ONCE(t->bill_cgrp_id, 0);
				WRITE_ONCE(t->cgx_raw, 0);
				WRITE_ONCE(t->llcx_raw, 0);
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
				ret = cbw_put_aside(taskc, 0, ROOT_CGID);
				if (likely(!ret)) {
					nr_moved++;
				} else {
					cbw_err("Failed to put aside a task "
						"while exiting cgid%llu: %d",
						cgrp_id, ret);
				}
				scx_atq_task_drop((scx_task_common *)taskc);
			}
		}

		/*
		 * Recycle the llcx with its (drained) BTQ intact -- BTQs are
		 * never destroyed. A drain that snapshotted this BTQ before the
		 * delete above may still pop from it after it is recycled and
		 * reused, but that is only a transient inaccuracy (a task briefly
		 * reenqueued from the wrong cgroup, then re-evaluated), never a
		 * use-after-free, since the memory stays valid and BTQ operations
		 * are lock-serialized.
		 */
		cbw_free_llcx(llcx);
	}

	return nr_moved;
}

__noinline
int cbw_set_bandwidth(u64 cgx_raw, u64 period_us, u64 quota_us, u64 burst_us)
{
	scx_cgroup_ctx_t *cgx = (scx_cgroup_ctx_t *)cgx_raw;

	/* Attach the timer function to the BPF area context. */
	scx_arena_subprog_init();

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
	return 0;
}

__noinline
int cbw_update_nquota_ub(u64 cgx_raw)
{
	/*
	 * Accept cgx as u64 rather than scx_cgroup_ctx_t * to avoid a BPF
	 * verifier type mismatch.  When cgx comes from scx_static_alloc() the
	 * compiler tracks it as a scalar; __noinline call sites with arena
	 * pointer parameters require an arena-qualified register, which the
	 * compiler does not emit from a scalar.  Passing u64 and casting here
	 * causes the compiler to emit addr_space_cast inside the subprogram.
	 */
	scx_cgroup_ctx_t *cgx = (scx_cgroup_ctx_t *)cgx_raw;
	scx_cgroup_ctx_t *eff_parentx;
	u64 ub;

	if (!cgx)
		return -EINVAL;

	/*
	 * Cap against the effective parent -- the nearest ancestor with a
	 * context (cgx->eff_parent_id). Callers update in pre-order, so the
	 * effective parent's nquota_ub is already current; a managed cgroup keeps
	 * its context for life, so a live descendant's effective parent always
	 * resolves, and only the root (eff_parent_id 0) has none. Commit the
	 * bound once: the replenish path reads nquota_ub concurrently and must
	 * never observe the uncapped value.
	 */
	ub = cgx->nquota;
	eff_parentx = cbw_get_cgroup_ctx_with_id(READ_ONCE(cgx->eff_parent_id));
	if (eff_parentx)
		ub = min(ub, READ_ONCE(eff_parentx->nquota_ub));
	WRITE_ONCE(cgx->nquota_ub, ub);
	return 0;
}

/*
 * Id of @cgrp's effective parent -- the nearest ancestor that has a context:
 * the nearest limited (finite cpu.max) ancestor, or the root; infinite
 * ancestors are skipped. 0 if @cgrp is the root (it has no ancestor).
 * Ref-counted walk, so no RCU read lock is required.
 */
static __always_inline
u64 cbw_eff_parent_cgid(struct cgroup *cgrp)
{
	struct cgroup *anc;
	u64 id = 0;
	int i, level = cgrp->level;

	bpf_for(i, 1, level + 1) {
		anc = bpf_cgroup_ancestor(cgrp, level - i);
		if (!anc)
			break;
		if (cbw_get_cgroup_ctx(anc))
			id = cgroup_get_id(anc);
		bpf_cgroup_release(anc);
		if (id)
			break;
	}
	return id;
}

/*
 * Billing cgroup for @cgrp: the cgroup itself if it has a context (is limited),
 * otherwise its effective parent (nearest managed ancestor). The root always
 * terminates the walk, so a cgroup under only-infinite ancestors bills to the
 * root. @cgrp is borrowed, not released.
 *
 * @cgrp must come from a source that is not filtered by the caller's cgroup
 * namespace -- scx_bpf_task_cgroup() (from the task) or a trusted cgroup
 * argument -- never bpf_cgroup_from_id(), which returns NULL for an id outside
 * current's namespace on kernels before v6.18.
 */
static __always_inline
u64 cbw_resolve_bill_cgid(struct cgroup *cgrp)
{
	u64 bill;

	if (cbw_get_cgroup_ctx(cgrp))
		bill = cgroup_get_id(cgrp);
	else
		bill = cbw_eff_parent_cgid(cgrp);

	return bill ? bill : ROOT_CGID;
}

/*
 * Resolve and cache a task's billing cgroup id from its own cgroup. Resolved
 * once (0 = unresolved) and reused; invalidated when the task changes cgroup
 * (scx_cgroup_bw_move) or its cgroup context is torn down (cbw_free_llc_ctx).
 * Resolution uses scx_bpf_task_cgroup(), so @p must be the task the current op
 * is operating on. A NULL @p is a cache-only caller (a non-subject op): return
 * the cached id, or 0 (unknown) when the cache is cold, without resolving.
 */
static __always_inline
u64 cbw_bill_task(scx_task_cgroup_bw_t *taskc, struct task_struct *p)
{
	struct cgroup *cgrp;
	u64 bill;

	if (taskc && taskc->bill_cgrp_id)
		return taskc->bill_cgrp_id;

	/*
	 * A NULL @p marks a cache-only caller: a non-subject op (e.g.
	 * ops.dispatch() accounting the previous task) where scx_bpf_task_cgroup()
	 * is illegal. With the cache cold, report the billing cgroup as unknown
	 * (0); the caller then skips, and it is resolved on @p's next subject op.
	 */
	if (!p)
		return 0;

	cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp) {
		scx_bpf_error("cgroup_bw: failed to get cgroup for task %d", p->pid);
		return 0;
	}
	bill = cbw_resolve_bill_cgid(cgrp);
	bpf_cgroup_release(cgrp);

	if (taskc)
		taskc->bill_cgrp_id = bill;
	return bill;
}

/*
 * Generation id of the managed-cgroup set. Bumped when a cgroup's managed
 * status flips -- it gains a finite cpu.max and becomes its subtree's nearest
 * managed billing target, or loses it and hands its billers up to its effective
 * parent -- because either moves live tasks' billing target. A task stamps its
 * cached billing state (bill_cgrp_id/cgx_raw/llcx_raw) with the generation id it
 * resolved against (bill_gen); cbw_sync_bill_gen() drops the cache when this
 * generation id no longer matches.
 */
static u64 cbw_bill_gen;

/*
 * Drop a task's cached billing state (bill_cgrp_id/cgx_raw/llcx_raw) and
 * restamp bill_gen when it lags cbw_bill_gen. Runs before any cached field is
 * read on the hot paths, including the cgx_raw fast path that does not go
 * through cbw_bill_task().
 */
static inline void cbw_sync_bill_gen(scx_task_cgroup_bw_t *taskc)
{
	u64 gen = READ_ONCE(cbw_bill_gen);

	if (unlikely(taskc->bill_gen != gen)) {
		/*
		 * Atomic exchanges, not plain stores: LLVM folds constant stores
		 * into base+offset addressing and drops the arena addr_space_cast,
		 * which the verifier rejects (same reason as scx_cgroup_bw_move()).
		 */
		__sync_lock_test_and_set(&taskc->bill_cgrp_id, 0);
		__sync_lock_test_and_set(&taskc->cgx_raw, 0);
		__sync_lock_test_and_set(&taskc->llcx_raw, 0);
		__sync_lock_test_and_set(&taskc->bill_gen, gen);
	}
}

/*
 * Initialize a freshly allocated context for @cgrp with the given bandwidth
 * parameters: cache its effective parent (nearest ancestor with a context), set
 * the quota and its effective upper bound, and clear the runtime state. Shared
 * by the sleepable init path and the non-sleepable manage path, which differ
 * only in how they allocate and populate the LLC contexts.
 */
static
void cbw_init_cgx(struct cgroup *cgrp, u64 cgx_raw,
		   u64 period_us, u64 quota_us, u64 burst_us)
{
	scx_cgroup_ctx_t *cgx = (scx_cgroup_ctx_t *)cgx_raw;

	cgx->id = cgroup_get_id(cgrp);
	cgx->level = cgrp->level;
	cgx->eff_parent_id = cbw_eff_parent_cgid(cgrp);
	cbw_set_bandwidth(cgx_raw, period_us, quota_us, burst_us);
	cbw_update_nquota_ub(cgx_raw);
	cgx->runtime_total_sloppy = 0;
	cgx->period_budget = cgx->nquota_ub;
	cgx->is_throttled = false;
}

/*
 * Tear down a partially or fully built context after a failed build: recycle
 * its LLC contexts and itself onto the free lists and release the managed slot.
 */
static
void cbw_deinit_cgx(u64 cgx_raw, u64 cgrp_id)
{
	scx_cgroup_ctx_t *cgx = (scx_cgroup_ctx_t *)cgx_raw;

	cbw_free_llc_ctx(cgrp_id);
	cbw_free_cgx(cgx);
	__sync_fetch_and_sub(&cbw_nr_cgx, 1);
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
	struct cbw_cgrp_entry entry;
	scx_cgroup_ctx_t *cgx;
	u64 cgrp_id;
	int ret;

	cbw_dbg_cgrp(" level: %d -- period_us: %llu -- quota_us: %llu -- burst_us: %llu ",
		     cgrp->level, args->bw_period_us, args->bw_quota_us, args->bw_burst_us);

	cgrp_id = cgroup_get_id(cgrp);

	/*
	 * Abort past the static limits rather than run a cgroup unmanaged.
	 */
	if (cgrp->level >= tree_height_max) {
		cbw_err("cgroup %llu level %d exceeds max tree height %d; aborting",
			cgrp_id, cgrp->level, tree_height_max);
		return -E2BIG;
	}

	/*
	 * When ops.cgroup_set_bandwidth() is non-sleepable it cannot allocate, so
	 * a cgroup that may gain a finite cpu.max at runtime needs its context set
	 * pre-reserved here, in this sleepable ops.cgroup_init(). Take a
	 * reservation for every non-root cgroup under the height cap and hold it
	 * until the cgroup either publishes a context below or exits, so
	 * cbw_nr_pending_reservations always equals the number of live non-root
	 * cgroups that have no context, and scx_cgroup_bw_exit() releases on
	 * context-absence alone. When set_bandwidth is sleepable, materialize
	 * allocates on demand and nothing is reserved.
	 */
	if (!bw_set_sleepable && cgrp->level > 0)
		__sync_fetch_and_add(&cbw_nr_pending_reservations, 1);

	/*
	 * Manage only cgroups that define a limit -- a finite cpu.max -- plus
	 * the root. A non-root cgroup with an infinite cpu.max gets no context:
	 * its tasks are billed to the nearest limited ancestor, and the roll-up
	 * and throttle propagation treat it as a pass-through gap.
	 */
	if (cgrp->level > 0 && args->bw_quota_us == CBW_RUNTUME_INF_RAW) {
		/* Build the spare its reservation covers (non-sleepable path). */
		if (!bw_set_sleepable)
			cbw_build_spare();
		return 0;
	}

	if (READ_ONCE(cbw_nr_cgx) >= nr_cgrp_max) {
		cbw_err("cgroup %llu exceeds max cgroups %d; aborting",
			cgrp_id, nr_cgrp_max);
		ret = -ENOSPC;
		goto out_unreserve;
	}
	if (__sync_fetch_and_add(&cbw_nr_cgx, 1) >= nr_cgrp_max) {
		/* Raced past the limit after the fast-path check; give the slot back. */
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
		cbw_err("cgroup %llu exceeds max cgroups %d; aborting",
			cgrp_id, nr_cgrp_max);
		ret = -ENOSPC;
		goto out_unreserve;
	}

	/*
	 * Allocate and initialize scx_cgroup_ctx for @cgrp.
	 *
	 * For the cgroup directly under the root cgroup
	 * (i.e., its level == 1), budget the full quota to itself,
	 * so the cgroup can distribute the budget to its descendants
	 * when requested.
	 */
	cgx = cbw_alloc_cgx_sleepable();
	if (!cgx) {
		cbw_err("Failed to allocate cgroup ctx: %llu", cgrp_id);
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
		ret = -ENOMEM;
		goto out_unreserve;
	}

	cbw_init_cgx(cgrp, (u64)cgx, args->bw_period_us, args->bw_quota_us,
		      args->bw_burst_us);

	/*
	 * A managed cgroup keeps its per-LLC contexts and BTQs even after it
	 * becomes non-leaf: tasks in unlimited descendants bill to their nearest
	 * managed ancestor, which must own LLC contexts to account for and park
	 * them. The managed set is small, so retaining them is cheap.
	 *
	 * ops.cgroup_init() is always sleepable and allocates fresh, so it uses
	 * the sleepable path directly rather than the bw_set_sleepable dispatch.
	 */
	if ((ret = __cbw_init_llcx_sleepable(cgrp, cgx))) {
		/*
		 * -EEXIST means a concurrent materialize (cbw_manage_cgroup())
		 * of @cgrp published the LLC set first and owns @cgrp's context,
		 * having already released @cgrp's reservation. Return only the
		 * cgx claimed here and leave @cgrp to that winner: routing
		 * through cbw_deinit_cgx() would delete the winner's LLC entries,
		 * and out_unreserve would release the reservation a second time.
		 */
		if (ret == -EEXIST) {
			cbw_free_cgx(cgx);
			__sync_fetch_and_sub(&cbw_nr_cgx, 1);
			return 0;
		}
		cbw_err("Failed to init LLC contexts: %llu (%d)", cgrp_id, ret);
		cbw_deinit_cgx((u64)cgx, cgrp_id);
		goto out_unreserve;
	}

	/*
	 * Publish the fully-initialized context into cbw_cgrp_map as the very
	 * last step. Making @cgrp reachable only after its LLC contexts and BTQs
	 * exist upholds the invariant that any cgroup found through the map can
	 * hold tasks.
	 */
	entry.cgx = (u64)cgx;
	if (bpf_map_update_elem(&cbw_cgrp_map, &cgrp_id, &entry, BPF_ANY)) {
		cbw_err("Failed to insert cgroup entry: %llu", cgrp_id);
		cbw_deinit_cgx((u64)cgx, cgrp_id);
		ret = -ENOMEM;
		goto out_unreserve;
	}

	ret = 0;
out_unreserve:
	/*
	 * Release the reservation taken above on every outcome except the
	 * infinite-quota early return: a managed cgroup consumes it once its
	 * context is published, and a failed init leaves no cgroup for
	 * scx_cgroup_bw_exit() to release later. Only the non-sleepable path
	 * reserves (see the init gate).
	 */
	if (!bw_set_sleepable && cgrp->level > 0)
		__sync_fetch_and_sub(&cbw_nr_pending_reservations, 1);

	return ret;
}

__noinline
int cbw_unthrottle_cgroup_for_exit(u64 cgrp_id)
{
	scx_cgroup_ctx_t *cgx;

	/*
	 * Stop throttling the cgroup by setting its upper bound and
	 * budget remaining to infinite.
	 */
	if (!(cgx = cbw_get_cgroup_ctx_with_id(cgrp_id))) {
		cbw_err("Failed to lookup a cgroup ctx: %llu", cgrp_id);
		return -ESRCH;
	}

	if (READ_ONCE(cgx->nquota_ub) == CBW_RUNTUME_INF)
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
	u64 cgrp_id;

	cbw_dbg_cgrp();

	/*
	 * A cgroup can exit when there are exiting tasks (TASK_DEAD) under it,
	 * because the kernel does not count them as living tasks. So, care
	 * should be taken to properly handle the race between cgroup exit
	 * and task exit, especially when exiting tasks under an exiting cgroup
	 * are throttled. We first stop throttling the cgroup to prevent any
	 * more tasks from being throttled. 
	 */
	cgrp_id = cgroup_get_id(cgrp);

	/*
	 * A cgroup we never managed -- skipped at init for exceeding the static
	 * limits, or CPU controller not enabled -- has no context; nothing to
	 * tear down.
	 */
	if (!cbw_get_cgroup_ctx_with_id(cgrp_id)) {
		/*
		 * Release the reservation @cgrp took in scx_cgroup_bw_init().
		 * Every non-root cgroup under the height cap holds one for as
		 * long as it has no context, so context-absence alone decides
		 * this -- @cgrp's current cpu.max does not matter, and a limit
		 * that changed while it stayed context-less cannot unbalance it.
		 * Only the non-sleepable path reserves (see the init gate).
		 */
		if (!bw_set_sleepable &&
		    cgrp->level > 0 && cgrp->level < tree_height_max)
			__sync_fetch_and_sub(&cbw_nr_pending_reservations, 1);
		return 0;
	}

	cbw_unthrottle_cgroup_for_exit(cgrp_id);
	if (!cbw_del_cgroup_ctx(cgrp_id))
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
	cbw_free_llc_ctx(cgrp_id);
	return 0;
}

/*
 * Move every managed cgroup in @cgrp's subtree that caps against @from_id over
 * to @to_id, and recompute the subtree's quota bounds (pre-order: self before
 * descendants). @cgrp gaining a context passes (its effective parent -> @cgrp);
 * @cgrp losing one passes (@cgrp -> its effective parent).
 */
static
int cbw_repoint_subtree(struct cgroup *cgrp, u64 from_id, u64 to_id)
{
	struct cgroup_subsys_state *start_css, *pos;
	scx_cgroup_ctx_t *cur_cgx;
	u64 self_id = cgroup_get_id(cgrp);
	u64 cur_id;
	int ret = 0;

	bpf_rcu_read_lock();
	start_css = &cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_id = cgroup_get_id(pos->cgroup);

		/*
		 * Only a managed cgroup carries the state updated below. Confirm
		 * the context still belongs to cur_id: one freed while the walk
		 * runs (cbw_free_cgx() zeroes it) can be reissued to another
		 * cgroup, and an id mismatch means this resolution is stale.
		 */
		cur_cgx = cbw_get_cgroup_ctx_with_id(cur_id);
		if (unlikely(!cur_cgx || READ_ONCE(cur_cgx->id) != cur_id))
			continue;

		/*
		 * eff_parent_id names the nearest ancestor that has a context, so
		 * a descendant pointing at @from_id has nothing managed between
		 * itself and @from_id -- which is exactly where @cgrp now sits
		 * (materialize) or no longer sits (retire). Moving those and only
		 * those to @to_id keeps every eff_parent_id correct without
		 * walking any ancestors. @cgrp's own effective parent is set by
		 * the caller; rewriting it here would point it at itself.
		 */
		if (cur_id != self_id && READ_ONCE(cur_cgx->eff_parent_id) == from_id)
			WRITE_ONCE(cur_cgx->eff_parent_id, to_id);

		/*
		 * Pre-order, so an effective parent inside this subtree has its
		 * own bound updated before the descendants capping against it.
		 */
		if ((ret = cbw_update_nquota_ub((u64)cur_cgx)))
			break;
	}
	bpf_rcu_read_unlock();
	return ret;
}

/*
 * Bring @cgrp, which gained a finite cpu.max while unmanaged, under bandwidth
 * management. It builds the context by allocating on demand when
 * ops.cgroup_set_bandwidth() may sleep, or from a spare reserved during
 * ops.cgroup_init() otherwise.
 * On success @cgrp joins the managed set: its reservation is released,
 * cbw_bill_gen is bumped so cached billers re-resolve, and its subtree is
 * re-pointed. Over the static caps, or with no spare available, it aborts
 * with -errno, failing the cpu.max update.
 */
static
int cbw_manage_cgroup(struct cgroup *cgrp, u64 period_us, u64 quota_us, u64 burst_us)
{
	struct cbw_cgrp_entry entry = {};
	scx_cgroup_ctx_t *cgx;
	u64 cgrp_id = cgroup_get_id(cgrp);
	int ret;

	/* Abort past the static limits; see scx_cgroup_bw_init(). */
	if (cgrp->level >= tree_height_max) {
		cbw_err("cgroup %llu level %d exceeds max tree height %d; aborting",
			cgrp_id, cgrp->level, tree_height_max);
		return -E2BIG;
	}

	if (READ_ONCE(cbw_nr_cgx) >= nr_cgrp_max) {
		cbw_err("cgroup %llu exceeds max cgroups %d; aborting",
			cgrp_id, nr_cgrp_max);
		return -ENOSPC;
	}
	if (__sync_fetch_and_add(&cbw_nr_cgx, 1) >= nr_cgrp_max) {
		/* Raced past the limit after the fast-path check; give the slot back. */
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
		cbw_err("cgroup %llu exceeds max cgroups %d; aborting",
			cgrp_id, nr_cgrp_max);
		return -ENOSPC;
	}

	/*
	 * Sleepable: allocate on demand. Non-sleepable: claim the spare reserved
	 * during ops.cgroup_init() -- abort if that build came up short.
	 */
	if (bw_set_sleepable)
		cgx = cbw_alloc_cgx_sleepable();
	else
		cgx = cbw_alloc_cgx_atomic();
	if (!cgx) {
		cbw_err("cgroup %llu: failed to obtain a context; aborting", cgrp_id);
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
		return -ENOMEM;
	}

	cbw_init_cgx(cgrp, (u64)cgx, period_us, quota_us, burst_us);

	ret = cbw_init_llcx(cgrp, cgx);
	if (ret == -EEXIST) {
		/*
		 * Lost a concurrent materialize of @cgrp: the winner owns the
		 * published LLC set, so return only the cgx claimed here and
		 * leave @cgrp to it. Nothing was published from this call --
		 * both racers start at LLC 0, so the loser fails there.
		 */
		cbw_free_cgx(cgx);
		__sync_fetch_and_sub(&cbw_nr_cgx, 1);
		return 0;
	}
	if (ret) {
		cbw_err("cgroup %llu: failed to obtain LLC contexts; aborting", cgrp_id);
		cbw_deinit_cgx((u64)cgx, cgrp_id);
		return ret;
	}

	entry.cgx = (u64)cgx;
	if (bpf_map_update_elem(&cbw_cgrp_map, &cgrp_id, &entry, BPF_ANY)) {
		cbw_err("cgroup %llu: failed to publish the context; aborting", cgrp_id);
		cbw_deinit_cgx((u64)cgx, cgrp_id);
		return -ENOMEM;
	}

	/*
	 * @cgrp is managed now: consume the reservation it held while unmanaged
	 * (non-sleepable path only -- the sleepable path reserves nothing), bump
	 * the generation so cached billers re-resolve to it, and re-point the
	 * subtree so descendants cap against it.
	 */
	if (!bw_set_sleepable)
		__sync_fetch_and_sub(&cbw_nr_pending_reservations, 1);
	__sync_fetch_and_add(&cbw_bill_gen, 1);

	/* Re-point descendants to cap against @cgrp. */
	return cbw_repoint_subtree(cgrp, READ_ONCE(cgx->eff_parent_id), cgrp_id);
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
	struct cgroup *cur_cgrp;
	u64 cgx_raw, cur_cgx_raw;
	struct cgroup_subsys_state *start_css, *pos;
	int ret = 0;

	cbw_dbg_cgrp();

	/* Update the cgroup's bandwidth. */
	cgx_raw = cbw_get_cgroup_ctx_raw(cgroup_get_id(cgrp));
	if (!cgx_raw) {
		/*
		 * Unmanaged cgroup. A finite cpu.max makes it eligible for
		 * management: materialize a context from a reserved spare. An
		 * infinite quota (or being over the static limits) leaves it
		 * unmanaged, with nothing to configure.
		 */
		if (quota_us == CBW_RUNTUME_INF_RAW)
			return 0;
		return cbw_manage_cgroup(cgrp, period_us, quota_us, burst_us);
	}

	/*
	 * A managed cgroup keeps its context for the rest of its life, even
	 * once its cpu.max goes back to infinite: an unlimited managed cgroup
	 * caps nobody (nquota_ub becomes infinite), so it costs a context but
	 * changes no behaviour. Never handing a live context back is a
	 * deliberate simplification: a context is then freed only at cgroup
	 * exit, when the cgroup is already empty and childless, so no task
	 * bills to it and no descendant points at it. That removes every
	 * use-after-recycle window this concurrent code would otherwise face
	 * and the deferred-free (RCU-style) machinery that closing them would
	 * require.
	 */
	cbw_set_bandwidth(cgx_raw, period_us, quota_us, burst_us);

	/*
	 * Update nquota_ub of the cgroup and all its descendents in a
	 * top-down-like manner (pre-order traversal: self -> left -> right).
	 */
	bpf_rcu_read_lock();
	start_css = &cgrp->self;
	bpf_for_each(css, pos, start_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgx_raw = cbw_get_cgroup_ctx_raw(cgroup_get_id(cur_cgrp));
		if (!cur_cgx_raw) {
			/* The CPU controller is not enabled for this cgroup. */
			continue;
		}

		ret = cbw_update_nquota_ub(cur_cgx_raw);
		if (ret)
			goto unlock_out;
	}
unlock_out:
	bpf_rcu_read_unlock();
	return ret;
}

static
s64 cbw_sum_rumtime_total_llcx(struct cgroup *cgrp, scx_cgroup_ctx_t *cgx)
{
	scx_cgroup_llc_ctx_t *llcx;
	s64 sum;
	int i;

	sum = 0;
	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx(cgrp, i);
		/*
		 * A set can be missing an entry while it is being built or
		 * torn down; the remaining LLCs still count.
		 */
		if (!llcx)
			continue;
		sum += READ_ONCE(llcx->runtime_total);
	}
	return sum;
}

static
s64 *tree_level(u32 level)
{
	return bpf_map_lookup_elem(&tree_levels_map, &level);
}

static
int clean_tree_levels(void)
{
	s64 *lv;
	u32 l;

	bpf_for(l, 0, tree_height_max) {
		lv = bpf_map_lookup_elem(&tree_levels_map, &l);
		if (!lv)
			return -ENOMEM;
		*lv = 0;
	}

	return 0;
}

/*
 * Sum and clear every per-level accumulator below @level. In a post-order
 * pass these hold the subtree totals of the current cgroup's descendants,
 * which infinite cgroups may separate from it by deeper levels.
 */
static
s64 tree_absorb_deeper(u32 level)
{
	s64 sum = 0, *lv;
	u32 l;

	bpf_for(l, level + 1, tree_height_max) {
		lv = tree_level(l);
		if (!lv)
			continue;
		sum += *lv;
		*lv = 0;
	}

	return sum;
}

static
int cbw_update_runtime_total_sloppy(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *start_css, *pos;
	scx_cgroup_ctx_t *cur_cgx = NULL;
	struct cgroup *cur_cgrp;
	s64 rt_llcx, rts, *lv;
	u32 cur_level;
	int ret = 0;


	ret = clean_tree_levels();
	if (ret)
		return ret;

	/*
	 * Refresh each cgroup's runtime_total_sloppy to the CPU time consumed by
	 * its whole subtree, in a single post-order (left-right-self) pass.
	 *
	 * Post-order visits an entire subtree before its root, so by the time we
	 * reach a cgroup every deeper cgroup has already deposited its own subtree
	 * total into the per-level scratch (tree_levels_map, indexed by cgroup
	 * level). A cgroup absorbs and clears all deeper levels, adds its own LLC
	 * runtime, and deposits the result at its own level for an ancestor to
	 * absorb in turn.
	 *
	 * Only limited cgroups (finite cpu.max) and the root have a context; they
	 * are marked '+' below. With every cgroup limited:
	 *   (P:0+
	 *	(Q:1+
	 *		(S:2+
	 *		 T:2+))
	 *	(R:1+))
	 * post-order is S:2 -> T:2 -> Q:1 -> R:1 -> P:0: S and T deposit at level
	 * 2, then Q absorbs level 2 (S+T) into its own total; leaf R has nothing
	 * deeper. The root P:0 is never throttled, so the sweep stops there.
	 *
	 * A cgroup with an infinite cpu.max has no context: it records nothing of
	 * its own, but still forwards its descendants' totals up to its own level,
	 * so a context-bearing ancestor absorbs them. Here V has a limited child W
	 * and an infinite child X, and X has a limited child Y:
	 *   (U:0+
	 *	(V:1+
	 *		(W:2+)
	 *		(X:2
	 *			(Y:3+))))
	 * post-order is W:2 -> Y:3 -> X:2 -> V:1 -> U:0: W deposits at level 2 and
	 * Y at level 3; X, though it has no context, forwards Y up to level 2
	 * (clearing level 3); V then absorbs level 2 and gets both W and Y. W keeps
	 * only its own runtime, since it absorbs only levels deeper than 2 and so
	 * never picks up Y.
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
		cur_cgrp = pos->cgroup;
		cur_level = cur_cgrp->level;
		if (can_loop && cur_level == 0) /* cgroup_root */
			break;
		/*
		 * A cgroup deeper than the height cap has no accumulator slot
		 * and was already left unmanaged at init, so skip it and keep
		 * rolling up the rest of the tree. Its subtree contributes no
		 * runtime; every cgroup visited after it still gets an accurate
		 * total for this period.
		 */
		if (cur_level >= tree_height_max)
			continue;

		/*
		 * Roll the subtree up whether or not this cgroup has a context:
		 * absorb and clear all deeper levels and deposit the result at
		 * this level. A contextless cgroup contributes no runtime of its
		 * own but still forwards its descendants' totals up to its own
		 * level, so a context-bearing ancestor -- never a sibling --
		 * absorbs them.
		 */
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		rt_llcx = cur_cgx ? cbw_sum_rumtime_total_llcx(cur_cgrp, cur_cgx) : 0;
		rts = rt_llcx + tree_absorb_deeper(cur_level);
		lv = tree_level(cur_level);
		if (lv)
			*lv += rts;

		if (!cur_cgx)
			continue;

		WRITE_ONCE(cur_cgx->runtime_total_sloppy, rts);

		/*
		 * If the cgroup has consumed its effective period budget, mark
		 * it throttled. period_budget = nquota_ub - debt + burst_credit
		 * reflects any debt carried from the previous period, so the
		 * comparison enforces long-run average convergence.
		 */
		if (rts >= cur_cgx->period_budget)
			WRITE_ONCE(cur_cgx->is_throttled, true);

		cbw_dbg("cgid%llu -- rt_llcx: %lld -- runtime_total_sloppy: %lld",
			cur_cgx->id, rt_llcx, rts);
	}
	bpf_rcu_read_unlock();

	return ret;
}

static
u64 cbw_throttle_cgroups(struct cgroup *cgrp)
{
	/*
	 * Throttle cgroups that have exhausted their budget and compute the
	 * next accounting timer interval in a single traversal.
	 *
	 * We traverse the cgroup hierarchy in post-order (left-right-self,
	 * i.e., bottom-up). For each cgroup, check if there is any throttled
	 * ancestor. If so, throttle itself.
	 *
	 * Before this, each cgroup’s runtime_total_sloppy should be updated
	 * by calling cbw_update_runtime_total_sloppy().
	 *
	 * For the interval, each non-throttled constrained cgroup with a
	 * non-zero consumption rate contributes a predicted time-to-throttle:
	 *
	 *   time_to_throttle = (period_budget - runtime_total_sloppy)
	 *                    * CBW_SCALE / avg_consumption_rate
	 *
	 * avg_consumption_rate is in CBW_SCALE units per CBW_REPLENISH_PERIOD
	 * (CPU ns / wall ns * CBW_SCALE), so this directly yields wall-time ns.
	 * The minimum across all such cgroups drives the next interval:
	 *
	 *   next_interval = clamp(min / CBW_ACCOUNTING_PERIOD_DIVISOR,
	 *                         CBW_ACCOUNTING_PERIOD_MIN,
	 *                         CBW_ACCOUNTING_PERIOD_MAX)
	 */
	struct cgroup_subsys_state *start_css, *pos, *anc_css;
	scx_cgroup_ctx_t *cur_cgx, *cur_anc_cgx;
	struct cgroup *cur_anc_cgrp;
	u64 min_time_to_throttle = U64_MAX;
	u64 time_to_throttle;
	s64 remaining;
	int i;

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
		if (READ_ONCE(cur_cgx->nquota_ub) == CBW_RUNTUME_INF)
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
		if (unlikely(cbw_top_half_running())) {
			min_time_to_throttle = U64_MAX;
			break;
		}

		/*
		 * If there is a throttled ancestor, all its descendants should
		 * be throttled; so this cgroup should be throttled too.
		 */
		anc_css = pos->parent;
		bpf_for(i, 0, tree_height_max) {
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

		/*
		 * If this cgroup is still not throttled after the ancestor
		 * check, estimate its time-to-throttle and track the minimum.
		 */
		if (!READ_ONCE(cur_cgx->is_throttled) &&
		    cur_cgx->avg_consumption_rate > 0) {
			remaining = READ_ONCE(cur_cgx->period_budget) -
				    READ_ONCE(cur_cgx->runtime_total_sloppy);
			if (remaining > 0) {
				time_to_throttle = (u64)remaining * CBW_SCALE /
						   cur_cgx->avg_consumption_rate;
				if (time_to_throttle < min_time_to_throttle)
					min_time_to_throttle = time_to_throttle;
			}
		}
	}
	bpf_rcu_read_unlock();

	return clamp(min_time_to_throttle / CBW_ACCOUNTING_PERIOD_DIVISOR,
		     (u64)CBW_ACCOUNTING_PERIOD_MIN,
		     (u64)CBW_ACCOUNTING_PERIOD_MAX);
}

static
int cbw_get_current_llc_id(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	return topo_cpu_to_llc_id(cpu);
}

/*
 * Whether the billing cgroup @bill_id (already resolved to the task's nearest
 * managed ancestor) is throttled.
 *
 * The throttle decision is based solely on cgx->is_throttled, which is
 * maintained asynchronously by the accounting timer via a two-step process:
 *
 *   Step 1 (cbw_update_runtime_total_sloppy): aggregates runtime_total from LLC
 *   contexts bottom-up and sets is_throttled when runtime_total_sloppy reaches
 *   nquota_ub.
 *
 *   Step 2 (cbw_throttle_cgroups): propagates is_throttled top-down to all
 *   descendants of a throttled ancestor.
 *
 * The flag is cleared at the replenish period boundary. A stale read is
 * harmless: at worst it allows one extra accounting interval of overspend,
 * which is recovered via debt carry-over at the next period.
 */
static
int cbw_billed_throttled(u64 bill_id, scx_task_cgroup_bw_t *taskc)
{
	scx_cgroup_ctx_t *cgx;
	u64 cgx_raw;

	if (bill_id == ROOT_CGID || unlikely(bill_id == 0))
		return 0;

	if (taskc && taskc->cgx_raw) {
		cgx_raw = taskc->cgx_raw;
	} else {
		cgx_raw = cbw_get_cgroup_ctx_raw(bill_id);
		if (!cgx_raw) {
			/* The billing cgroup has no context (e.g. it exited). */
			cbw_dbg("Failed to lookup a cgroup ctx: %llu", bill_id);
			return -ESRCH;
		}
		if (taskc)
			taskc->cgx_raw = cgx_raw;
	}

	cgx = (scx_cgroup_ctx_t *)cgx_raw;
	if (READ_ONCE(cgx->is_throttled)) {
		dbg_cgx(cgx, "throttled: ");
		return -EAGAIN;
	}

	return 0;
}

/**
 * scx_cgroup_bw_throttled - Check if the cgroup is throttled or not.
 * @p: a task to be tested; must be the current op's subject task.
 * @taskc_raw: per-task context (scx_task_cgroup_bw *) cast to u64 for caching.
 *
 * Return 0 when the cgroup is not throttled,
 * -EAGAIN when the cgroup is throttled, and
 * -errno for some other failures.
 */
__hidden
int scx_cgroup_bw_throttled(struct task_struct *p __arg_trusted __arg_nullable, u64 taskc_raw)
{
	scx_task_cgroup_bw_t *taskc = (scx_task_cgroup_bw_t *)taskc_raw;

	/*
	 * Never throttle an exiting task. In do_exit(), a task is removed from
	 * the PID map by __unhash_process() (called from exit_notify()) in the
	 * window between PF_EXITING being set and TASK_DEAD being set. If the
	 * task is preempted in this window and throttled into the BTQ, the BTQ
	 * drain calls scx_cgroup_bw_enqueue_cb() to reenqueue it. The callback
	 * looks up the task pointer via bpf_task_from_pid(), which returns NULL
	 * for an unhashed task. With no way to reenqueue it, the task is
	 * permanently lost from all runqueues, causing a watchdog timeout.
	 *
	 * A NULL @p is a cache-only caller (see cbw_bill_task); skip this check.
	 */
	if (p && (p->flags & PF_EXITING))
		return 0;

	if (!taskc)
		return 0;

	cbw_sync_bill_gen(taskc);

	/*
	 * Fast path for the common case: a task in the root or a fully-unlimited
	 * subtree bills to the root, which is never throttled. bill_cgrp_id is
	 * cached after the first resolution below.
	 */
	if (taskc->bill_cgrp_id == ROOT_CGID)
		return 0;

	return cbw_billed_throttled(cbw_bill_task(taskc, p), taskc);
}

/**
 * scx_cgroup_bw_consume - Consume the time actually used after the task execution.
 * @p: the task being accounted; the current op's subject task, or NULL for a
 *     cache-only call (a non-subject op such as ops.dispatch()).
 * @taskc_raw: per-task context (scx_task_cgroup_bw *) cast to u64 for caching.
 * @consumed_ns: amount of time actually used.
 *
 * Return 0 on success -- billed now, nothing to bill (root/unlimited), or
 * deferred: a cache-only caller (@p == NULL) whose billing cgroup is not yet
 * resolved has this interval carried in the task and billed on the next
 * resolved call, so the caller never has to defer its own accounting. Returns
 * -errno only on a hard failure.
 */
__hidden
int scx_cgroup_bw_consume(struct task_struct *p __arg_trusted __arg_nullable, u64 taskc_raw,
			  u64 consumed_ns)
{
	scx_task_cgroup_bw_t *taskc = (scx_task_cgroup_bw_t *)taskc_raw;
	scx_cgroup_llc_ctx_t *llcx;
	scx_cgroup_ctx_t *cgx;
	u64 cgx_raw, llcx_raw, carry = 0;
	int llc_id;

	if (!taskc)
		return 0;

	cbw_sync_bill_gen(taskc);

	/*
	 * Absorb any interval an earlier cache-only call could not attribute to a
	 * billing cgroup (see the deferral below) and bill it together with this
	 * one. The carry shares this interval's fate: billed at the accounting
	 * site, re-deferred if this call also cannot resolve, or dropped if the
	 * billing cgroup is root/unlimited or gone -- exactly what would have
	 * happened had the carried time been measured now.
	 */
	if (taskc->pending_ns)
		carry = __sync_lock_test_and_set(&taskc->pending_ns, 0);

	/*
	 * Fast path for the common case: a task in the root or a fully-unlimited
	 * subtree bills to the root and needs no accounting. bill_cgrp_id is
	 * cached after the first resolution below.
	 */
	if (taskc->bill_cgrp_id == ROOT_CGID)
		return 0;

	/*
	 * Resolve the billing cgroup's context, cached in the task on the first
	 * call from its billing cgroup (nearest managed ancestor-or-self).
	 */
	if (taskc->cgx_raw) {
		cgx_raw = taskc->cgx_raw;
	} else {
		u64 bill_id = cbw_bill_task(taskc, p);

		/*
		 * Cache-only caller (@p == NULL) with a cold cache: the billing
		 * cgroup is unknown here. Defer -- carry this interval (plus any
		 * already carried) and bill it on the next call that resolves,
		 * which lands on @p's current billing cgroup.
		 */
		if (bill_id == 0) {
			__sync_fetch_and_add(&taskc->pending_ns, carry + consumed_ns);
			return 0;
		}
		if (bill_id == ROOT_CGID)
			return 0;
		cgx_raw = cbw_get_cgroup_ctx_raw(bill_id);
		if (!cgx_raw)
			return 0;
		taskc->cgx_raw = cgx_raw;
	}
	cgx = (scx_cgroup_ctx_t *)cgx_raw;

	/*
	 * Infinite-quota fast path: skip accounting entirely for unconstrained
	 * cgroups. cbw_get_current_llc_id() is not called in this path.
	 */
	if (READ_ONCE(cgx->nquota_ub) == CBW_RUNTUME_INF)
		return 0;

	/* Get the current LLC ID only when accounting is needed. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * Use the cached llcx if the LLC id matches; otherwise look up by
	 * cgx->id (avoids cgroup_get_id() pointer dereferences) and update
	 * the cache.
	 */
	if (taskc->llcx_raw && taskc->last_llc_id == llc_id) {
		llcx = (scx_cgroup_llc_ctx_t *)taskc->llcx_raw;
	} else {
		llcx_raw = cbw_get_llc_ctx_raw_with_id(cgx->id, llc_id);
		if (!llcx_raw)
			return 0;
		taskc->llcx_raw = llcx_raw;
		taskc->last_llc_id = llc_id;
		llcx = (scx_cgroup_llc_ctx_t *)llcx_raw;
	}

	/*
	 * Update the budget usage.
	 *
	 * Note that the budget can be reserved in an LLC domain and then
	 * actually used in another LLC domain. However, that is not a problem
	 * because LLC's runtime_total will be aggregated to the cgroup level
	 * at reservation.
	 *
	 * consumed_ns may span a CBW_REPLENISH_PERIOD boundary when a task
	 * runs across it. Since this function is called on every tick
	 * (ops.stopping() and ops.tick()), consumed_ns per call is bounded by
	 * roughly one tick interval (~1-4ms). Any cross-period overcount is
	 * therefore a bounded approximation error: it appears as overspend in
	 * runtime_total, which cbw_replenish_cgroup() converts into debt that
	 * is subtracted from the next period's budget, keeping long-term CPU
	 * bandwidth correct.
	 */
	__sync_fetch_and_add(&llcx->runtime_total, consumed_ns + carry);

	cbw_dbg("  bill cgid%llu -- llc_id: %d -- consumed_ns: %llu -- llcx:runtime_total: %lld",
		cgx->id, llc_id, consumed_ns, READ_ONCE(llcx->runtime_total));
	return 0;
}

__hidden
int cbw_put_aside(u64 ctx, u64 vtime, u64 bill_id)
{
	scx_task_common *taskc = (scx_task_common *)ctx;
	scx_cgroup_llc_ctx_t *llcx;
	scx_atq_t *btq;
	scx_atq_t *task_atq;
	int llc_id, ret;

	/*
	 * @bill_id is the billing cgroup (the task's nearest managed ancestor),
	 * already resolved by the caller, whose BTQ the drain reenqueues from.
	 */

	/* Get the current LLC ID. */
	if ((llc_id = cbw_get_current_llc_id()) < 0) {
		cbw_err("Invalid LLC id: %d", llc_id);
		return -EINVAL;
	}

	/*
	 * Put aside the task to the BTQ of the LLC context.
	 */
	llcx = cbw_get_llc_ctx_with_id(bill_id, llc_id);
	if (!llcx) {
		cbw_err("Failed to lookup an LLC ctx: [%llu/%d]",
			bill_id, llc_id);
		return -ESRCH;
	}

	/* A mapped llcx always owns a live BTQ (BTQs are never destroyed). */
	btq = READ_ONCE(llcx->btq);

	ret = scx_atq_lock(btq);
	if (ret) {
		cbw_err("Failed to lock ATQ.");
		return -EBUSY;
	}

	/*
	 * Re-verify under the BTQ lock that bill_id still maps to this llcx.
	 * cbw_free_llc_ctx() deletes the map entry before draining the BTQ, so
	 * if the cgroup is exiting the re-lookup returns a different pointer (or
	 * none) and we bail rather than park a task in a doomed BTQ. If it still
	 * matches, a concurrent free can only drain after we unlock, and it reaps
	 * the task we insert.
	 */
	if (cbw_get_llc_ctx_with_id(bill_id, llc_id) != llcx) {
		scx_atq_unlock(btq);
		cbw_warn("put_aside skipped: cgroup exited: cgid=%llu", bill_id);
		return -ESRCH;
	}

	/*
	 * A task can be claimed by only one BTQ at a time. The atomic cmpxchg
	 * of ->atq inside scx_atq_insert_vtime_unlocked() elects a single
	 * winner; the loser sees the task already queued. That benign case is
	 * detected either here on the fast path or as EALREADY returned by the
	 * insert below.
	 */
	task_atq = (scx_atq_t *)READ_ONCE(taskc->atq);
	if (task_atq == (scx_atq_t *)SCX_ATQ_DEAD) {
		scx_atq_unlock(btq);
		return 0;
	}
	if (task_atq) {
		cbw_dbg("Possible double enqueue detected.");
		scx_atq_unlock(btq);
		cbw_warn("put_aside skipped: already in BTQ; cgid=%llu", bill_id);
		return 0;
	}

	ret = scx_atq_insert_vtime_unlocked(btq, taskc, vtime);
	scx_atq_unlock(btq);

	if (unlikely(ret == -ECANCELED)) {
		return 0;
	} else if (unlikely(ret == -EALREADY)) {
		cbw_warn("put_aside skipped: already in BTQ; cgid=%llu", bill_id);
		return 0;
	} else if (unlikely(ret)) {
		cbw_err("Failed to insert a task to BTQ: %d", ret);
	}

	return ret;
}

/**
 * scx_cgroup_bw_put_aside - Put aside a task to execute it when the cgroup is
 * unthrottled later.
 * @p: a task to be put aside since the cgroup is throttled.
 * @taskc: a task-embedded pointer to scx_task_common.
 * @vtime: vtime of a task @p.
 * @cgrp_id: cgroup id where a task belongs to.
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
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 ctx, u64 vtime)
{
	cbw_dbg(" [%s/%d]", p->comm, p->pid);

	if (ctx)
		cbw_sync_bill_gen((scx_task_cgroup_bw_t *)ctx);
	/* Park @p under its own billing cgroup (resolved from @p, cache-hot). */
	return cbw_put_aside(ctx, vtime,
			     cbw_bill_task((scx_task_cgroup_bw_t *)ctx, p));
}

static
bool cbw_has_backlogged_tasks(scx_cgroup_ctx_t *cgx)
{
	scx_cgroup_llc_ctx_t *llcx;
	int i;

	if (!cgx)
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
bool cbw_replenish_cgroup(scx_cgroup_ctx_t *cgx, u64 now)
{
	s64 burst_credit = 0, debt = 0, budget;
	bool period_end, was_throttled, keep_throttled = false;

	/*
	 * If the nquota_ub is infinite, we don’t need to replenish the cgroup.
	 */
	if (READ_ONCE(cgx->nquota_ub) == CBW_RUNTUME_INF)
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

	budget = (s64)READ_ONCE(cgx->nquota_ub) + burst_credit - debt;
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
		u64 avg = cgx->avg_consumption_rate;

		cgx->avg_consumption_rate =
			__calc_avg(avg, rate, CBW_CONSUMPTION_RATE_DECAY);
	}

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
 * scx_cgroup_bw_cancel - Cancel a task's BTQ membership.
 *
 * @taskc: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 * @flags: bitmask of enum scx_cgroup_bw_cancel_flags.
 *
 * Return 0 for success, -errno for failure.
 */
__hidden
int scx_cgroup_bw_cancel(u64 ctx, u64 flags)
{
	scx_task_common *taskc = (scx_task_common *)ctx;
	int ret;

	if (flags & SCX_CGROUP_BW_CANCEL_DROP)
		return scx_atq_task_detach(taskc);

	ret = scx_atq_task_fini(taskc);
	return ret < 0 ? ret : 0;
}

/*
 * Remove @taskc from its current BTQ and hold it across the temporary
 * ->atq == NULL window. The hold prevents ops.exit_task from freeing the task
 * context while the caller relocates or reenqueues it.
 *
 * Return 0 for success or -errno on failure. On success, @cancelled is true
 * iff this caller removed the task and now owns a hold.
 */
static __always_inline
int cbw_cancel_with_hold(scx_task_common __arg_arena *taskc, bool *cancelled)
{
	scx_atq_t *atq;
	int ret;

	*cancelled = false;

	while (can_loop) {
		atq = (scx_atq_t *)READ_ONCE(taskc->atq);
		if (!atq || atq == (scx_atq_t *)SCX_ATQ_DEAD)
			return 0;

		if ((ret = scx_atq_lock(atq))) {
			cbw_err("Failed to lock BTQ while moving task: %d", ret);
			return ret;
		}

		if (READ_ONCE(taskc->atq) != atq) {
			scx_atq_unlock(atq);
			continue;
		}

		scx_atq_task_hold(taskc);
		ret = scx_atq_remove_unlocked(atq, taskc);
		scx_atq_unlock(atq);

		if (ret) {
			scx_atq_task_drop(taskc);
			return ret;
		}

		*cancelled = true;
		return 0;
	}

	return 0;
}

static struct cgroup *cbw_get_root_cgrp(void)
{
	struct task_struct *task;
	struct cgroup *cgrp, *root = NULL;

	/*
	 * Resolve the root cgroup pointer through the BPF scheduler's
	 * loader task (whose tgid was captured by scx_cgroup_bw_lib_init).
	 *
	 * Why not bpf_cgroup_from_id(ROOT_CGID)?  On kernels < v6.18,
	 * bpf_cgroup_from_id() routes through cgroup_get_from_id() which
	 * filters against `current`'s cgroup namespace.  When called from
	 * BPF timers (softirq) or ops.dispatch, `current` is whichever
	 * task happened to be on the CPU -- frequently a containerised
	 * service whose cgroup namespace root is not the host root.  The
	 * lookup then returns NULL even though ROOT_CGID is valid.
	 * Upstream commit 2c8951339506 ("bpf: Do not limit
	 * bpf_cgroup_from_id to current's namespace") fixes this in
	 * v6.18+.
	 *
	 * Resolving via the loader task avoids the issue on every
	 * kernel: bpf_task_from_pid() looks up against init_pid_ns
	 * regardless of `current`, and bpf_cgroup_ancestor() walks the
	 * kernel-side cgrp->ancestors[] array which is not namespace-
	 * aware.
	 *
	 * Caller owns the returned reference and must release it via
	 * bpf_cgroup_release().
	 */

	if (unlikely(!cbw_loader_tgid))
		goto out;

	task = bpf_task_from_pid((s32)cbw_loader_tgid);
	if (!task)
		goto out;

	bpf_rcu_read_lock();
	cgrp = task->cgroups->dfl_cgrp;
	if (cgrp)
		root = bpf_cgroup_ancestor(cgrp, 0);
	bpf_rcu_read_unlock();

	bpf_task_release(task);

out:
	if (unlikely(!root)) {
		cbw_err("Failed to resolve root cgroup via loader task "
			"(tgid=%u)", cbw_loader_tgid);
	}

	return root;
}


/*
 * A handler function for the accounting timer.
 */
static
int accounting_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	struct cgroup *root_cgrp;
	u64 now, next_interval = CBW_ACCOUNTING_PERIOD_MAX;
	int ret;

	/*
	 * Update the runtime total and throttle cgroups.
	 *
	 * If the top half is running, we can skip the accounting since the top
	 * half will replenish and unthrottle all the cgroups anyway; use the
	 * maximum interval so we do not busy-wait.
	 */
	root_cgrp = cbw_get_root_cgrp();
	if (unlikely(!root_cgrp))
		goto rearm_out;

	if (unlikely(cbw_top_half_running()))
		goto release_out;

	now = scx_bpf_now();
	cbw_dbg("at %llu", now);

	cbw_update_runtime_total_sloppy(root_cgrp);
	next_interval = cbw_throttle_cgroups(root_cgrp);
	smp_mb();

release_out:
	bpf_cgroup_release(root_cgrp);
rearm_out:
	if ((ret = bpf_timer_start(timer, next_interval, 0)))
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
	u64 *ids, now;
	struct cgroup_subsys_state *root_css, *pos;
	scx_cgroup_ctx_t *cur_cgx;
	scx_cgroup_llc_ctx_t *cur_llcx;
	const struct cpumask *online_mask;
	s64 interval, jitter, period;
	int i, ret;
	s32 idle_cpu;
	u32 slot;
	bool is_throttled;

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
	root_cgrp = cbw_get_root_cgrp();
	if (!root_cgrp) {
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

		bpf_for(i, 0, TOPO_NR(LLC)) {
			cur_llcx = cbw_get_llc_ctx(cur_cgrp, i);
			if (cur_llcx)
				WRITE_ONCE(cur_llcx->runtime_total, 0);
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

		slot = cbw_nr_cgroups;
		ids = bpf_map_lookup_elem(&cbw_cgroup_ids, &slot);
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
		slot = i;
		ids = bpf_map_lookup_elem(&cbw_cgroup_ids, &slot);
		if (!ids) {
			cbw_err("Failed to fetch a cgroup table.");
			continue;
		}

		/*
		 * Fetch the cgroup context by id. A cgroup can exit during
		 * the replenishment process, leading to context-lookup
		 * failures.
		 */
		cur_cgx = cbw_get_cgroup_ctx_with_id(ids[0]);
		if (!cur_cgx) {
			cbw_dbg("Failed to lookup a cgroup ctx: cgid%llu", ids[0]);
			/*
			 * The cgroup is on its way out -- scx_cgroup_bw_exit()
			 * has removed the map entry and will drain its BTQ.
			 * Skip this cycle.
			 */
			continue;
		}

		is_throttled = READ_ONCE(cur_cgx->is_throttled);
		if (is_throttled) {
			cur_cgx->nr_throttled_periods++;
			/* Consecutive only if throttled in the previous period too. */
			if (cur_cgx->was_throttled &&
			    ++cur_cgx->nr_consec_throttled_periods >
			    cur_cgx->max_consec_throttled_periods)
				cur_cgx->max_consec_throttled_periods =
					cur_cgx->nr_consec_throttled_periods;
		} else {
			cur_cgx->nr_consec_throttled_periods = 0;
		}
		cur_cgx->was_throttled = is_throttled;

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
			slot = nr_throttled;
			ids = bpf_map_lookup_elem(&cbw_throttled_cgroup_ids, &slot);
			if (!ids) {
				cbw_err("Failed to fetch a throttled cgroup table.");
				continue;
			}
			WRITE_ONCE(ids[0], cur_cgx->id);
			nr_throttled++;
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
		root_cgrp = cbw_get_root_cgrp();
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
int cbw_drain_btq_batch(scx_cgroup_ctx_t *cgx,
			scx_cgroup_llc_ctx_t *llcx)
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
	 * The BTQ comes from the mapped llcx and is never destroyed, so popping
	 * is always safe even if the cgroup is concurrently exiting: at worst a
	 * task is drained from a recycled BTQ and re-evaluated on reenqueue.
	 */
	for (i = 0; can_loop && i < CBW_REENQ_MAX_BATCH &&
		    (btq = READ_ONCE(llcx->btq)) &&
		    (taskc = (scx_task_common *)scx_atq_pop(btq, true)); i++) {
		/*
		 * Note that we do not worry about racing with .dequeue() here,
		 * because even if we do, the callback's insert_vtime call will
		 * fail silently in the scx core. 
		 */

		scx_cgroup_bw_enqueue_cb((u64)taskc);
		scx_atq_task_drop(taskc);
		cbw_dbg("cgid%llu", cgx->id);
	}

	return i;
}

static
int cbw_reenqueue_cgroup(scx_cgroup_ctx_t *cgx, u64 cgrp_id, u64 nuance)
{
	scx_cgroup_llc_ctx_t *llcx;
	int i, idx, nr_enq = 0;

	/*
	 * Drain BTQ of each LLC level until the BTQ becomes empty or
	 * the cgroup is throttled.
	 *
	 * Note that we start with a random LLC to give each LLC a fair
	 * chance to be reenqueued.
	 */
	cbw_dbg("cgid%llu", cgrp_id);

	bpf_for(i, 0, TOPO_NR(LLC)) {
		idx = (nuance + i) % TOPO_NR(LLC);
		llcx = cbw_get_llc_ctx_with_id(cgrp_id, idx);
		if (!llcx) {
			/*
			 * A concurrent teardown can free this cgroup's LLC
			 * contexts while the drain runs, so a missing entry is an
			 * expected transient here, not an error: skip it and move
			 * on to the next LLC.
			 */
			cbw_dbg("Failed to lookup an LLC context: cgid%llu", cgrp_id);
			continue;
		}

		/*
		 * If the cgroup is throttled, all its LLC contexts are
		 * throttled too. Stop draining immediately.
		 */
		if (cbw_billed_throttled(cgrp_id, NULL) == -EAGAIN)
			break;

		nr_enq += cbw_drain_btq_batch(cgx, llcx);
		if (nr_enq >= CBW_REENQ_MAX_BATCH)
			break;
	}

	return nr_enq;
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
	union backlog_stat backlog_stat;
	scx_cgroup_ctx_t *cur_cgx;
	int i, idx, n, nr_enq = 0;
	u64 nuance, nuance2, nr_tcgs;
	u64 *ids, cur_cgrp_id;
	u32 slot;

	/*
	 * If there are throttled tasks in BTQ, let’s reenqueue them.
	 */
	if (likely(!cbw_has_throttled_tasks(&backlog_stat)))
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
		slot = idx;
		ids = bpf_map_lookup_elem(&cbw_throttled_cgroup_ids, &slot);
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

		cur_cgx = cbw_get_cgroup_ctx_with_id(cur_cgrp_id);
		if (!cur_cgx) {
			/* Never tear down root; see cbw_get_root_cgrp(). */
			if (cur_cgrp_id == ROOT_CGID)
				continue;
			cbw_dbg("Failed to lookup a cgroup ctx: cgid%llu",
				cur_cgrp_id);

			/*
			 * The cgroup is on its way out: scx_cgroup_bw_exit()
			 * has deleted its map entry and will drain its BTQ.
			 * Purge the dead slot via CAS. If the replenish timer
			 * concurrently overwrote this slot with a new cgroup
			 * ID, the CAS fails and leaves that new ID intact.
			 */
			__sync_bool_compare_and_swap(ids, cur_cgrp_id, 0);
			continue;
		}

		/* Reqneueue backlogged tasks. */
		n = cbw_reenqueue_cgroup(cur_cgx, cur_cgrp_id, nuance2);

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
	 * If there is nothing that we can reenqueue (because the BTQs are
	 * empty or the cgroups are throttled again), transit to the empty
	 * state. The CAS is keyed on the full backlog_stat snapshot including
	 * rp_seq. If cbw_top_half_begin() fired since the snapshot was taken,
	 * rp_seq in cbw_backlog_stat.val will have changed and the CAS will
	 * fail safely, leaving has_throttled_tasks for the new cycle to manage.
	 */
	if ((nr_enq == 0) && !cbw_top_half_running()) {
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
 * @cgrp: the cgroup to test
 *
 * Return true if the cgroup is throttled. Otherwise, return false.
 */
__hidden
int scx_cgroup_bw_is_cgroup_throttled(struct cgroup *cgrp __arg_trusted)
{
	scx_cgroup_ctx_t *cgx = cbw_get_cgroup_ctx_with_id(cgroup_get_id(cgrp));

	/*
	 * Unmanaged (e.g. infinite cpu.max): its tasks are throttled against the
	 * nearest managed ancestor, so report that.
	 */
	if (!cgx)
		cgx = cbw_get_cgroup_ctx_with_id(cbw_resolve_bill_cgid(cgrp));

	return cgx ? READ_ONCE(cgx->is_throttled) : 0;
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
	scx_atq_t *atq;

	if (!ctx)
		return false;

	atq = READ_ONCE(ctx->atq);
	return atq != NULL && atq != (scx_atq_t *)SCX_ATQ_DEAD;
}

/**
 * scx_cgroup_bw_move - Move a task from a cgroup to another (@from -> @to).
 *
 * @p: task being moved
 * @task_ptr: Pointer to the scx_task_common task context. Passed as a u64
 * to avoid exposing the scx_task_common type to the scheduler.
 * @from: cgroup @p is being moved from
 * @to: cgroup @p is being moved to
 *
 * Return 0 for success, -errno for failure.
 */
__hidden __noinline
int scx_cgroup_bw_move(struct task_struct *p __arg_trusted, u64 task_ptr,
		       struct cgroup *from __arg_trusted,
		       struct cgroup *to __arg_trusted)
{
	volatile scx_task_cgroup_bw_t *tc; /* Add `volatile` to work around the verifier error */
	scx_task_common *taskc = (scx_task_common *)task_ptr;
	bool cancelled;
	int ret;

	scx_arena_subprog_init();
	/*
	 * Drain any time an earlier cache-only call deferred (pending_ns) and
	 * charge it to @from below, before repointing @p -- otherwise it would be
	 * billed to @to. The atomic drain is race-safe against a concurrent
	 * consume: only one side sees the value.
	 *
	 * Then invalidate the per-task cache: bill_cgrp_id, cgx_raw and llcx_raw
	 * belong to the old cgroup. They are re-resolved from @p's new cgroup on
	 * the next throttle/consume call.
	 *
	 * Use atomic exchanges instead of plain stores: LLVM folds constant
	 * stores into base+offset addressing and omits addr_space_cast for the
	 * arena pointer, which the BPF verifier rejects.  Atomics always emit
	 * addr_space_cast for the base register regardless of offset.
	 */
	tc = (scx_task_cgroup_bw_t *)taskc;
	if (tc) {
		u64 carry = __sync_lock_test_and_set(&tc->pending_ns, 0);

		/*
		 * Charge the deferred time to @from's billing cgroup, where it was
		 * consumed. Prefer @p's cached contexts -- read before the
		 * invalidation below, they still point at the old cgroup: the
		 * cached LLC ctx charges with no lookup; a cached cgroup ctx (e.g.
		 * warmed by a throttle check, which caches no LLC ctx) needs only
		 * an LLC lookup. Fall back to resolving @from when the cache is
		 * fully cold. Any LLC works; runtime_total rolls up to the cgroup.
		 */
		if (carry) {
			u64 llcx_raw = tc->llcx_raw;
			u64 cgx_raw = tc->cgx_raw;

			if (!llcx_raw) {
				int llc_id = cbw_get_current_llc_id();

				if (!cgx_raw)
					cgx_raw = cbw_get_cgroup_ctx_raw(
							cbw_resolve_bill_cgid(from));
				if (cgx_raw && llc_id >= 0)
					llcx_raw = cbw_get_llc_ctx_raw_with_id(
						((scx_cgroup_ctx_t *)cgx_raw)->id,
						llc_id);
			}
			if (llcx_raw)
				__sync_fetch_and_add(&((scx_cgroup_llc_ctx_t *)
						     llcx_raw)->runtime_total, carry);
		}

		__sync_lock_test_and_set(&tc->bill_cgrp_id, 0);
		__sync_lock_test_and_set(&tc->cgx_raw, 0);
		__sync_lock_test_and_set(&tc->llcx_raw, 0);
	}

	/*
	 * If a task is throttled, remove it from its current BTQ, hold it
	 * across the transient ->atq == NULL state, then add it to @to's BTQ.
	 * A concurrent ops.exit_task may latch SCX_ATQ_DEAD during the window,
	 * but it must wait for our hold before freeing the task context; the
	 * subsequent put_aside sees DEAD and skips reinsertion safely.
	 *
	 * We will try to reenqueue it in the next replenishment interval.
	 * This is fair because the task was throttled under @from cgroup,
	 * so it has to wait until the next replenishment interval anyway.
	 */
	if (!scx_cgroup_bw_is_task_throttled(task_ptr))
		return 0;

	ret = cbw_cancel_with_hold(taskc, &cancelled);
	if (ret) {
		cbw_err("Fail to cancel a throttled task (%s:%d) from a cgroup (cgid%llu): %d",
			p->comm, p->pid, cgroup_get_id(from), ret);
		return ret;
	}
	if (!cancelled)
		return 0;

	/*
	 * Put the task aside into @to's cgroup. If that fails -- e.g., the
	 * target cgroup is exiting or unmanaged, or a transient internal error
	 * occurred -- fall back to the root cgroup rather than lose the task.
	 *
	 * Note that we cannot call scx_cgroup_bw_enqueue_cb() here: the BPF
	 * verifier rejects calling scx_bpf_dsq_insert_vtime() from the
	 * ops.cgroup_move() callback.
	 */
	if ((ret = cbw_put_aside(task_ptr, p->scx.dsq_vtime,
				 cbw_resolve_bill_cgid(to)))) {
		if (ret == -ESRCH) {
			cbw_warn("Destination cgroup unavailable while moving throttled task (%s:%d) to cgid%llu",
				 p->comm, p->pid, cgroup_get_id(to));
		}

		if (!(ret = cbw_put_aside(task_ptr, 0, ROOT_CGID)))
			goto out_drop;
		cbw_err("Fail to put aside a throttled task (%s:%d) to a cgroup (cgid%llu): %d",
			p->comm, p->pid, cgroup_get_id(to), ret);
	}

out_drop:
	scx_atq_task_drop(taskc);
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

	scx_cgroup_llc_ctx_t *llcx;
	int i, nr_throttled_tasks = 0;
	scx_cgroup_ctx_t *cgx;
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

	bpf_for(i, 0, TOPO_NR(LLC)) {
		llcx = cbw_get_llc_ctx(cgrp, i);
		if (!llcx || !(btq = READ_ONCE(llcx->btq)))
			continue;
		nr_throttled_tasks += scx_atq_nr_queued(btq);
	}

	bpf_printk("%s   \\_ quota: %llu/%llu/%llu, period: %llu, burst: %llu", indent_str,
			cgx->quota, cgx->period, cgx->burst);
	bpf_printk("%s   \\_ nquota: %llu, nquota_ub: %llu", indent_str,
			cgx->nquota, cgx->nquota_ub);
	bpf_printk("%s   \\_ is_throttled: %d, nr_throttled_periods: %d/%d (%u/%u), nr_throttled_tasks: %d", indent_str,
			cgx->is_throttled,
			cgx->nr_throttled_periods, READ_ONCE(cbw_backlog_stat.rp_seq) / 2,
			cgx->nr_consec_throttled_periods, cgx->max_consec_throttled_periods,
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

	/*
	 * Resolve the start cgroup. Dumping from the root is the common
	 * case; cbw_get_root_cgrp() handles it. Other ids fall through
	 * to bpf_cgroup_from_id().
	 */
	if (cgrp_id == ROOT_CGID)
		start_cgrp = cbw_get_root_cgrp();
	else
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
