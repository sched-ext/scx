/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_nitosis is a dynamic affinity scheduler. Cgroups (and their tasks) are
 * assigned to Cells which are affinitized to discrete sets of CPUs. The number
 * of cells is dynamic, as is cgroup to cell assignment and cell to CPU
 * assignment (all are determined by userspace).
 *
 * Each cell has one or more DSQs for vtime scheduling. With LLC-awareness
 * enabled, each cell has a DSQ per LLC domain; otherwise a single flat DSQ.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

/*
 * When LLC awareness is disabled, we use a single "fake" LLC index to flatten
 * the entire cell's topology into one scheduling domain. All CPUs in the cell
 * share the same DSQ and vtime, ignoring actual LLC cache boundaries.
 */
#define FAKE_FLAT_CELL_LLC 0

#include "mitosis.bpf.h"
#include "dsq.bpf.h"
#include "slice_shrinking.bpf.h"
#include "llc_aware.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Variables populated by userspace
 */
const volatile u32 nr_possible_cpus = 1;

const volatile u64 slice_ns;
const volatile u64 root_cgid = 1;
const volatile bool exiting_task_workaround_enabled = true;
const volatile bool cpu_controller_disabled = false;
const volatile bool reject_multicpu_pinning = false;
const volatile bool enable_borrowing = false;
const volatile bool use_lockless_peek = false;
const volatile bool dynamic_affinity_cpu_selection = false;

/* applied_configuration_seq is bumped when a userspace-pushed config finishes applying. */
u32 applied_configuration_seq;
u32 cpuset_seq;
u32 applied_cpuset_seq;

/* Configuration struct for apply_cell_config, populated by userspace */
struct cell_config cell_config;

private(root_cgrp) struct cgroup __kptr *root_cgrp;

UEI_DEFINE(uei);

struct cell __arena *cells;
struct mitosis_topo __arena *topo;
union shard_cmask __arena *idle_masks;
union shard_cmask __arena *idle_smt_masks;
struct scx_cmask __arena *topo_cids;
/* Cell cmask generations, published in cell_masks and freed via scx_urcu */
static struct scx_allocator cell_cmask_allocator;
static struct scx_urcu cell_cmask_urcu;

struct cell_cmasks __arena *cell_masks;

/* A fresh generation with every mask initialized empty. */
static __always_inline struct cell_cmasks __arena *cell_cmasks_alloc(u32 nr_cids)
{
	struct cell_cmasks __arena *gen = scx_alloc(&cell_cmask_allocator);
	u32 i;

	if (!gen)
		return NULL;
	bpf_for(i, 0, MAX_CELLS) {
		cmask_init(&gen->mask[i].cmask, 0, nr_cids);
		cmask_init(&gen->borrowable[i].cmask, 0, nr_cids);
	}
	return gen;
}

/*
 * Publish @gen as the current cell cmask generation. The xchg orders the mask
 * fills before the publication, and the old generation is freed behind a grace
 * period as readers hold loaded generations to the end of their RCU sections.
 */
static __always_inline void cell_cmasks_publish(struct cell_cmasks __arena *gen)
{
	u64 old = __sync_lock_test_and_set((u64 *)&cell_masks, (u64)gen);

	if (old)
		scx_urcu_free(&cell_cmask_urcu, &cell_cmask_allocator, (void __arena *)old);
}

/* Forward declaration for init_cgrp_ctx_with_ancestors (defined later) */
static int init_cgrp_ctx_with_ancestors(struct cgroup *cgrp);

/*
 * We store per-cpu values along with per-cell values. Helper functions to
 * translate.
 */

static inline struct cgroup *lookup_cgrp_ancestor(struct cgroup *cgrp, u32 ancestor)
{
	struct cgroup *cg;

	if (!(cg = bpf_cgroup_ancestor(cgrp, ancestor))) {
		scx_bpf_error("Failed to get ancestor level %d for cgid %llu", ancestor,
			      cgrp->kn->id);
		return NULL;
	}

	return cg;
}

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctxs SEC(".maps");

static inline struct cgrp_ctx *lookup_cgrp_ctx_fallible(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0, 0))) {
		return NULL;
	}

	return cgc;
}

static inline struct cgrp_ctx *lookup_cgrp_ctx(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc = lookup_cgrp_ctx_fallible(cgrp);

	if (!cgc)
		scx_bpf_error("cgrp_ctx lookup failed for cgid %llu", cgrp->kn->id);

	return cgc;
}

static inline struct cgroup *task_cgroup(struct task_struct *p)
{
	struct cgroup *cgrp;

	if (!cpu_controller_disabled) {
		cgrp = scx_bpf_task_cgroup(p);
	} else {
		/*
		 * When CPU controller is disabled, scx_bpf_task_cgroup() returns
		 * root. Use p->cgroups->dfl_cgrp to get the task's actual cgroup
		 * in the default (unified) hierarchy.
		 *
		 * p->cgroups is RCU-protected, so we need RCU lock.
		 */
		scoped_guard(rcu)
		{
			cgrp = bpf_cgroup_acquire(p->cgroups->dfl_cgrp);
		}
	}

	if (!cgrp)
		scx_bpf_error("Failed to get cgroup for task %d", p->pid);

	return cgrp;
}

static inline struct task_ctx __arena *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx __arena *tctx = scx_task_data(p);

	if (!tctx)
		scx_bpf_error("task_ctx lookup failed");
	return tctx;
}

/*
 * Per-cid contexts, one per cid in a flat arena array. Userspace reads the
 * pointer from BSS and accesses the array directly for stats, see
 * read_cpu_ctxs() in main.rs.
 */
struct cpu_ctx __arena *cpu_ctxs;
u32 nr_cid_ctxs;

/* ctx of the cid this invocation is running on */
static inline struct cpu_ctx __arena *cur_cpu_ctx(void)
{
	return &cpu_ctxs[scx_bpf_this_cid()];
}

static inline int update_task_cmask(struct task_struct *p, struct task_ctx __arena *tctx)
{
	struct cell_cmasks __arena *cm = READ_ONCE(cell_masks);
	struct scx_cmask __arena *cell_mask = &cm->mask[tctx->cell].cmask;
	struct scx_cmask __arena *allowed = &tctx->allowed;
	struct scx_cmask __arena *effective = &tctx->effective;
	bool all_cell_cpus_allowed;
	s32 cid;
	int ret;

	cmask_copy(effective, allowed);
	cmask_and(effective, cell_mask);

	/*
	 * An empty allowed mask means all of the task's cpus are offline. The
	 * task cannot become runnable before a wakeup rewrites its affinity,
	 * and the ops.set_cmask() the rewrite fires lands back here, so park
	 * the task unassigned. Only ops.select_cid() runs before the rewrite on
	 * that wakeup and can see the parked state, and it punts. An enqueue
	 * that sees it is a bug and fails loudly on the invalid DSQ.
	 */
	if (cmask_empty(allowed)) {
		if (enable_llc_awareness)
			tctx->llc = LLC_INVALID;
		tctx->dsq = DSQ_INVALID;
		tctx->all_cell_cpus_allowed = false;
		return 0;
	}

	/*
	 * Set only after tctx->dsq matches it:
	 * false => cid DSQ, true => cell DSQ.
	 */
	all_cell_cpus_allowed = cmask_subset(cell_mask, allowed);

	if (all_cell_cpus_allowed && enable_borrowing) {
		struct scx_cmask __arena *borrowable = &cm->borrowable[tctx->cell].cmask;

		if (!cmask_subset(borrowable, allowed))
			all_cell_cpus_allowed = false;
	}

	/*
	 * Single-CPU pinning is fine (even if outside this cell).
	 * However, multi-CPU pinning that doesn't cover the entire
	 * cell is not supported - the scheduler can't efficiently
	 * handle partial affinity restrictions.
	 *
	 * When a new cell is created, or any cpuset change occurs,
	 * there's a window where many tasks don't have the same
	 * cpumask as their cell (since cell cpumasks are updated
	 * later via apply_cell_config). We don't abort on these
	 * tasks by checking cpuset_seq vs applied_cpuset_seq.
	 */
	if (tctx->cell != 0 && reject_multicpu_pinning && !all_cell_cpus_allowed &&
	    cmask_weight(allowed) > 1) {
		if (READ_ONCE(cpuset_seq) != READ_ONCE(applied_cpuset_seq)) {
			cstat_inc(CSTAT_PIN_SKIP, tctx->cell, cur_cpu_ctx());
		} else {
			scx_bpf_error("multi-CPU pinning within cell %d not supported", tctx->cell);
			return -EINVAL;
		}
	}

	/*
	 * XXX - To be correct, we'd need to calculate the vtime
	 * delta in the previous dsq, scale it by the load
	 * fraction difference and then offset from the new
	 * dsq's vtime_now. For now, just do the simple thing
	 * and assume the offset to be zero.
	 *
	 * Revisit if high frequency dynamic cell switching
	 * needs to be supported.
	 */

	/*
	 * A destroyed or zero-cpu-configured cell reads as an empty mask in the
	 * current generation, which also makes the subset test above pass
	 * vacuously. Take the pinned path instead of riding a cell DSQ that no
	 * cid serves. The next applied_configuration_seq bump re-refreshes the
	 * task.
	 */
	if (all_cell_cpus_allowed && cmask_empty(effective))
		all_cell_cpus_allowed = false;

	/* Pinned path, outside the cell */
	if (!all_cell_cpus_allowed) {
		if (enable_llc_awareness) {
			tctx->llc = LLC_INVALID;
		}

		cid = cmask_any_distribute(allowed);
		if (cid >= cmask_end(allowed))
			return -EINVAL;

		tctx->dsq = get_cid_dsq_id(cid);
		if (dsq_is_invalid(tctx->dsq))
			return -EINVAL;

		scx_bpf_task_set_dsq_vtime(p, READ_ONCE(cpu_ctxs[cid].vtime_now));
		tctx->all_cell_cpus_allowed = false;
		return 0;
	}

	if (enable_llc_awareness) {
		ret = update_task_llc_assignment(p, tctx, scx_bpf_task_cid(p));
		if (ret)
			return ret;
		tctx->all_cell_cpus_allowed = true;
		return 0;
	}

	/* Non-LLC aware version */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, FAKE_FLAT_CELL_LLC);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	scx_bpf_task_set_dsq_vtime(p, cell_llc_vtime_read(&cells[tctx->cell],
							  FAKE_FLAT_CELL_LLC));
	tctx->all_cell_cpus_allowed = true;

	return 0;
}

/*
 * Figure out the task's cell, dsq and store the corresponding cpumask in the
 * task_ctx.
 */
static inline int update_task_cell(struct task_struct *p, struct task_ctx __arena *tctx,
				   struct cgroup *cg)
{
	struct cgrp_ctx *cgc;

	cgc = lookup_cgrp_ctx_fallible(cg);

	if (!cgc) {
		/*
		 * Cgroup lookup failed - this can happen during scheduler load
		 * for tasks that were forked before the scheduler was loaded,
		 * whose cgroups went offline before scx_cgroup_init() ran.
		 * Only fall back to root cgroup if the workaround is enabled
		 * and the task is exiting.
		 */
		if (exiting_task_workaround_enabled && (p->flags & PF_EXITING)) {
			/*
			 * We may be invoked from sleepable context (init_task),
			 * thus require RCU protection to ensure that kptr
			 * loaded for the root cgroup remains valid while
			 * performing cgroup context lookup.
			 */
			scoped_guard(rcu)
			{
				struct cgroup *rootcg = READ_ONCE(root_cgrp);
				if (!rootcg) {
					scx_bpf_error("Unexpected uninitialized rootcg");
					return -ENOENT;
				}
				cgc = lookup_cgrp_ctx(rootcg);
			}
		}

		if (!cgc) {
			scx_bpf_error(
				"cgrp_ctx lookup failed for cgid %llu (task %d, flags 0x%x, tctx->cgid %llu)",
				cg->kn->id, p->pid, p->flags, tctx->cgid);
			return -ENOENT;
		}
	}

	/*
	 * This ordering is pretty important, we read applied_configuration_seq
	 * before reading everything else expecting that the updater will update
	 * everything and then bump applied_configuration_seq last. This ensures
	 * that we cannot miss an update.
	 */
	tctx->configuration_seq = READ_ONCE(applied_configuration_seq);
	barrier();
	tctx->cell = cgc->cell;
	tctx->cgid = cg->kn->id;

	return update_task_cmask(p, tctx);
}

/*
 * Get task's cgroup, update its cell, and release the cgroup.
 */
static __always_inline int refresh_task_cell(struct task_struct *p,
					     struct task_ctx __arena *tctx)
{
	struct cgroup *cgrp __free(cgroup) = task_cgroup(p);
	if (!cgrp)
		return -1;
	return update_task_cell(p, tctx, cgrp);
}

/* True when the task's cell/cpumask mapping is stale, read-only */
static __always_inline bool task_needs_refresh(struct task_struct *p,
					       struct task_ctx __arena *tctx)
{
	if (tctx->configuration_seq != READ_ONCE(applied_configuration_seq))
		return true;

	/*
	 * When not using CPU controller, check if task's cgroup changed.
	 * The cgroup is already initialized by tp_cgroup_mkdir which
	 * fires before the task can be scheduled in the new cgroup.
	 */
	if (cpu_controller_disabled) {
		u64 current_cgid;

		scoped_guard(rcu)
		{
			current_cgid = p->cgroups->dfl_cgrp->kn->id;
		}

		if (current_cgid != tctx->cgid)
			return true;
	}

	return false;
}

/* Check if we need to update the cell/cpumask mapping */
static __always_inline int maybe_refresh_cell(struct task_struct *p,
					      struct task_ctx __arena *tctx)
{
	if (task_needs_refresh(p, tctx))
		return refresh_task_cell(p, tctx);
	return 0;
}

/*
 * Claim @cid's idle bit in @im. Mirrors scx_idle_test_and_clear_cpu(): the
 * core's range is cleared from the idle_smt mask whether or not the claim wins.
 * The core is not wholly idle either way and a stale set range could trap the
 * core-idle scans.
 */
static __always_inline bool claim_idle_cid_masks(struct mitosis_topo __arena *t, s32 cid,
						  struct scx_cmask __arena *im)
{
	if (t->smt_active) {
		s32 core = t->cid[cid].core_idx;
		struct scx_cmask __arena *ism = &idle_smt_masks[t->cid[cid].shard_idx].cmask;

		if (core >= 0)
			cmask_clear_range(ism, t->core_cids[core].base,
					  t->core_cids[core].nr);
	}
	return cmask_test_and_clear(cid, im);
}

/* the cid-form analog of scx_bpf_test_and_clear_cpu_idle() */
static inline bool claim_idle_cid(s32 cid)
{
	return claim_idle_cid_masks(topo, cid, &idle_masks[topo->cid[cid].shard_idx].cmask);
}

/*
 * Locate @prev_cid's shard when it falls inside the scan window, MAX_CPUS
 * otherwise.
 */
static __always_inline u32 pick_prev_shard(struct mitosis_topo __arena *t,
					   struct scx_cmask __arena *cand, u32 shard_base,
					   u32 nr_shards, s32 prev_cid)
{
	if (prev_cid >= 0 && cmask_test(prev_cid, cand)) {
		u32 ps = t->cid[prev_cid].shard_idx;

		if (ps >= shard_base && ps < shard_base + nr_shards)
			return ps;
	}
	return MAX_CPUS;
}

/*
 * Scan rotation anchor: @prev_cid's shard when usable, otherwise a pseudo
 * random shard so that no-prev scans, drain kicks for example, spread
 * regardless of how narrow the window is.
 */
static __always_inline u32 pick_start_shard(u32 shard_base, u32 nr_shards, u32 pshard)
{
	if (pshard < MAX_CPUS)
		return pshard;
	return shard_base + bpf_get_prandom_u32() % nr_shards;
}

/*
 * One scan pass over the shard index range [@shard_base, @shard_base +
 * @nr_shards) rotated to start at @start_shard, intersecting each shard's idle
 * mask (or idle_smt mask when @idle_core) with @cand and claiming with bounded
 * retries. Returns the claimed cid, -EBUSY if nothing was claimed.
 */
static __always_inline s32 pick_idle_scan(struct mitosis_topo __arena *t,
					  struct scx_cmask __arena *cand, u32 shard_base,
					  u32 nr_shards, u32 start_shard, bool idle_core)
{
	u32 i;

	bpf_for(i, 0, nr_shards) {
		u32 si = shard_base + (start_shard - shard_base + i) % nr_shards;
		struct scx_cmask __arena *im = &idle_masks[si].cmask;
		struct scx_cmask __arena *scan;
		u32 end, r;

		if (idle_core)
			scan = &idle_smt_masks[si].cmask;
		else
			scan = im;

		end = scan->base + scan->nr_cids;
		bpf_for(r, 0, IDLE_PICK_RETRIES) {
			s32 cid = cmask_any_and_distribute(scan, cand);

			if (cid < 0 || cid >= end)
				break;
			if (claim_idle_cid_masks(t, cid, im))
				return cid;
		}
	}

	return -EBUSY;
}

/*
 * Core-idle phase over one shard window: @prev_cid if its whole core is idle,
 * then a scan of the idle_smt masks. No-op without SMT. A real subprog, the
 * scan inlines a lot of state, see pick_idle_cid_partial().
 */
static __noinline s32 pick_idle_cid_cores(struct scx_cmask __arena *cand, u32 shard_base,
					  u32 nr_shards, s32 prev_cid)
{
	struct mitosis_topo __arena *t = topo;
	u32 pshard;

	if (!nr_shards || !t->smt_active)
		return -EBUSY;

	pshard = pick_prev_shard(t, cand, shard_base, nr_shards, prev_cid);
	if (pshard < MAX_CPUS) {
		struct scx_cmask __arena *ism = &idle_smt_masks[pshard].cmask;
		struct scx_cmask __arena *im = &idle_masks[pshard].cmask;

		/* prev in a wholly idle core is the cheapest pick */
		if (cmask_test(prev_cid, ism) && claim_idle_cid_masks(t, prev_cid, im))
			return prev_cid;
	}

	return pick_idle_scan(t, cand, shard_base, nr_shards,
			      pick_start_shard(shard_base, nr_shards, pshard), true);
}

/*
 * Partial phase over one shard window: @prev_cid if idle, then a scan of the
 * idle masks. A real subprog: inlining the scans into every caller blows the
 * 512 byte stack limit once LLC awareness stacks a second pick level into
 * select_cid.
 */
static __noinline s32 pick_idle_cid_partial(struct scx_cmask __arena *cand, u32 shard_base,
					    u32 nr_shards, s32 prev_cid)
{
	struct mitosis_topo __arena *t = topo;
	u32 pshard;

	if (!nr_shards)
		return -EBUSY;

	pshard = pick_prev_shard(t, cand, shard_base, nr_shards, prev_cid);
	if (pshard < MAX_CPUS) {
		struct scx_cmask __arena *im = &idle_masks[pshard].cmask;

		/* partially idle prev is the cheapest partial pick */
		if (claim_idle_cid_masks(t, prev_cid, im))
			return prev_cid;
	}

	return pick_idle_scan(t, cand, shard_base, nr_shards,
			      pick_start_shard(shard_base, nr_shards, pshard), false);
}

/*
 * Claim an idle cid out of @cand within the shard index range [@shard_base,
 * @shard_base + @nr_shards). Idle state lives in per-shard windowed cmasks
 * maintained by ops.update_idle(), so the scans walk shards and intersect each
 * with @cand. Claims race with other pickers and with idle transitions.
 * cmask_test_and_clear() arbitrates and the scans are bounded.
 *
 * The phase order matches the cpu form: with SMT, a wholly idle core beats a
 * partially idle @prev_cid, which beats any partially idle cid, all within one
 * window at a time, see pick_idle_cid().
 *
 * Returns the claimed cid, -EBUSY if nothing idle was found.
 */
static __always_inline s32 pick_idle_cid_shards(struct scx_cmask __arena *cand,
						u32 shard_base, u32 nr_shards, s32 prev_cid)
{
	s32 cid = pick_idle_cid_cores(cand, shard_base, nr_shards, prev_cid);

	if (cid >= 0)
		return cid;
	return pick_idle_cid_partial(cand, shard_base, nr_shards, prev_cid);
}

static __always_inline s32 pick_idle_cid(struct task_struct *p, s32 prev_cid,
					  struct cpu_ctx __arena *cctx,
					  struct task_ctx __arena *tctx)
{
	struct mitosis_topo __arena *t = topo;
	s32 cid;

	/* no overlap between cell and task cpus, find some idle cid */
	if (cmask_empty(&tctx->effective)) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		return pick_idle_cid_shards(&tctx->allowed, 0, t->nr_shards, prev_cid);
	}

	if (enable_llc_awareness && tctx->all_cell_cpus_allowed) {
		s32 llc = choose_task_llc(tctx, prev_cid);
		bool in_llc = llc < t->nr_llcs;
		u32 lbase = 0, lnr = 0;

		if (in_llc) {
			lbase = t->llc_shards[llc].base;
			lnr = t->llc_shards[llc].nr;
		}

		/*
		 * Exhaust the LLC window, core-idle then partial, before the
		 * full range: a partially idle cpu in the task's LLC beats a
		 * wholly idle core outside it. The builtin ladder orders the
		 * other way, core-idle everywhere first.
		 */
		if (in_llc) {
			cid = pick_idle_cid_shards(&tctx->effective, lbase, lnr, prev_cid);
			if (cid >= 0)
				return cid;
		}
	}

	return pick_idle_cid_shards(&tctx->effective, 0, t->nr_shards, prev_cid);
}

/*
 * Try to find an idle cid for a task. First searches within the cell's own
 * cids, then tries borrowing from other cells if enabled.
 *
 * On success, bumps CSTAT_LOCAL or CSTAT_BORROWED as appropriate and dispatches
 * the task to SCX_DSQ_LOCAL. If @kick is true, the idle cid is also kicked.
 *
 * Returns: cid >= 0 on success, -EBUSY if no idle cid found.
 */
static __always_inline s32 try_pick_idle_cid(struct task_struct *p, s32 prev_cid,
					     struct cpu_ctx __arena *cctx,
					     struct task_ctx __arena *tctx, bool kick)
{
	s32 cid;

	cid = pick_idle_cid(p, prev_cid, cctx, tctx);
	if (cid >= 0) {
		cstat_inc(CSTAT_LOCAL, tctx->cell, cctx);
		/*
		 * Use SCX_DSQ_LOCAL_ON to explicitly target the idle cid we
		 * found. In the select_cid path this is redundant
		 * (SCX_DSQ_LOCAL already resolves to the selected cid), but
		 * from the enqueue path (put_prev_task_scx -> enqueue),
		 * SCX_DSQ_LOCAL resolves to task_rq(p) rather than the idle cid
		 * we picked.
		 */
		tctx->vtime_charge_cell = tctx->cell;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid, slice_ns, 0);
		if (kick)
			scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
		return cid;
	}
	/* cid == -EBUSY: no idle cid in cell, try borrowing */
	if (enable_borrowing) {
		struct scx_cmask __arena *borrowable =
			&READ_ONCE(cell_masks)->borrowable[tctx->cell].cmask;

		cid = pick_idle_cid_shards(borrowable, 0, topo->nr_shards, prev_cid);
		if (cid >= 0) {
			tctx->borrowed = true;
			cstat_inc(CSTAT_BORROWED, tctx->cell, cctx);
			tctx->vtime_charge_cell = tctx->cell;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid, slice_ns, 0);
			if (kick)
				scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
			return cid;
		}
	}

	return -EBUSY;
}

/*
 * Switch task to a new cid's DSQ with vtime reset. Returns new_cid on success,
 * -1 on failure (tctx unchanged).
 */
static __always_inline s32 update_pinned_dsq(struct task_struct *p,
					     struct task_ctx __arena *tctx, s32 new_cid)
{
	s32 current_cid = get_cid_from_dsq(tctx->dsq);
	if (current_cid < 0)
		return -1;

	if (current_cid == new_cid)
		return new_cid; /* already on this DSQ */

	tctx->dsq = get_cid_dsq_id(new_cid);
	scx_bpf_task_set_dsq_vtime(p, READ_ONCE(cpu_ctxs[new_cid].vtime_now));
	return new_cid;
}

static __always_inline s32 select_pinned_cid(struct task_struct *p, s32 prev_cid,
					     struct task_ctx __arena *tctx,
					     bool *idle_cid_cleared)
{
	s32 cid;

	/*
	 * Dynamic affinity balancing: claim an idle cid out of the task's
	 * allowed mask. If nothing is idle, return prev_cid and let enqueue()
	 * handle placement.
	 */
	cid = pick_idle_cid_shards(&tctx->allowed, 0, topo->nr_shards, prev_cid);

	if (cid < 0)
		return prev_cid;

	*idle_cid_cleared = true;

	if (update_pinned_dsq(p, tctx, cid) < 0)
		return -1;

	return cid;
}

/*
 * select_cid is where we update each task's cell assignment and then try to
 * dispatch to an idle cid in the cell if possible
 */
s32 BPF_STRUCT_OPS(mitosis_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
	s32 cid;
	struct cpu_ctx __arena *cctx;
	struct task_ctx __arena *tctx;

	cctx = cur_cpu_ctx();
	if (!(tctx = lookup_task_ctx(p)))
		return prev_cid;

	if (maybe_refresh_cell(p, tctx) < 0)
		return prev_cid;

	if (!tctx->all_cell_cpus_allowed) {
		/*
		 * Empty means all of the task's cpus are offline and this very
		 * wakeup is about to fix that: the affinity rewrite runs after
		 * this callback and fires ops.set_cmask(). Any pick from here
		 * would be discarded, return prev_cid untouched.
		 */
		if (cmask_empty(&tctx->allowed))
			return prev_cid;

		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		bool idle_cid_cleared = false;

		if (cmask_weight(&tctx->allowed) == 1) {
			/* If we're pinned to a single cid, just use that */
			cid = get_cid_from_dsq(tctx->dsq);
		} else if (dynamic_affinity_cpu_selection) {
			/* Multicpu pinning, try to find an idle cid */
			cid = select_pinned_cid(p, prev_cid, tctx, &idle_cid_cleared);
		} else {
			/* legacy pinned cid, stay on the initial DSQ */
			cid = get_cid_from_dsq(tctx->dsq);
		}

		if (cid < 0)
			return prev_cid;

		if (idle_cid_cleared || claim_idle_cid(cid)) {
			tctx->vtime_charge_cell = tctx->cell;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		}
		return cid;
	}

	if ((cid = try_pick_idle_cid(p, prev_cid, cctx, tctx, false)) >= 0)
		return cid;

	/*
	 * All else failed, send it to the prev cid (if that's valid), otherwise
	 * any valid cid.
	 */
	if (!cmask_test(prev_cid, &tctx->effective)) {
		cid = cmask_any_distribute(&tctx->effective);
		if (cid >= cmask_end(&tctx->effective))
			return prev_cid;
	} else {
		cid = prev_cid;
	}

	return cid;
}

static __always_inline s32 enqueue_pinned_cid(struct task_struct *p,
					      struct task_ctx __arena *tctx)
{
	/*
	 * Dynamic affinity balancing: if the current cid has tasks queued,
	 * distribute over the allowed cids to balance load over time.
	 */
	s32 cid = get_cid_from_dsq(tctx->dsq);

	if (cid < 0)
		return -1;

	/* Simple heuristic, consider checking runnable time */
	if (scx_bpf_dsq_nr_queued(tctx->dsq.raw) > 0) {
		s32 new_cid;

		new_cid = cmask_any_distribute(&tctx->allowed);
		if (new_cid >= cmask_end(&tctx->allowed)) {
			scx_bpf_error("no allowed cid for pinned task");
			return -1;
		}
		if (update_pinned_dsq(p, tctx, new_cid) < 0)
			return -1;
		cid = new_cid;
	}
	return cid;
}

void BPF_STRUCT_OPS(mitosis_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx __arena *cctx;
	struct task_ctx __arena *tctx;
	s32 task_cid = scx_bpf_task_cid(p);
	u64 vtime;
	s32 cid = -1;
	u64 basis_vtime;

	if (!(tctx = lookup_task_ctx(p)))
		return;
	cctx = cur_cpu_ctx();

	if (maybe_refresh_cell(p, tctx) < 0)
		return;

	/*
	 * CPU -> cell mappings can change between enqueue() and stopping().
	 * If that happens, the task's dsq_vtime may no longer belong to the
	 * CPU-local or shared cell vtime domains visible at stopping(), and
	 * advancing either one would charge the wrong domain.
	 * Direct local insert paths snapshot the same state before inserting.
	 *
	 * Snapshot the cell whose vtime domain this placement expects to
	 * charge. stopping() only advances local and cell vtime if the task
	 * is not borrowed and the CPU it stops on is still in this same cell.
	 */
	tctx->vtime_charge_cell = tctx->cell;

	if (!tctx->all_cell_cpus_allowed) {
		if (dynamic_affinity_cpu_selection) {
			cid = enqueue_pinned_cid(p, tctx);
			/* kick the picked cid, select_cid() may differ */
			if (cid >= 0)
				scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
		} else {
			cid = get_cid_from_dsq(tctx->dsq);
		}

		if (cid < 0)
			return;

	} else if (!__COMPAT_is_enq_cpu_selected(enq_flags) || (enq_flags & SCX_ENQ_LAST)) {
		/*
		 * If we haven't selected a cid, then we haven't looked for and
		 * kicked an idle cid. Let's do the lookup now. SCX_ENQ_LAST
		 * enqueues skip select_cid() and this cpu is going idle, tested
		 * explicitly as they must end in a kick to guarantee a
		 * follow-up scheduling event.
		 */
		cid = try_pick_idle_cid(p, task_cid, cctx, tctx, true);
		if (cid >= 0)
			return;

		/* -EBUSY, nothing idle: kick a distributed pick instead */
		cid = cmask_any_distribute(&tctx->effective);
		if (cid >= cmask_end(&tctx->effective))
			cid = -1;
	}

	if (tctx->all_cell_cpus_allowed) {
		cstat_inc(CSTAT_CELL_DSQ, tctx->cell, cctx);

		/* Task can use any CPU in its cell, so use the cell DSQ */
		if (enable_llc_awareness) {
			s32 llc;

			if (maybe_update_task_llc(p, tctx, task_cid))
				return;

			llc = tctx->llc;
			if (llc < 0) {
				scx_bpf_error("Invalid LLC ID: %d", tctx->llc);
				return;
			}

			basis_vtime = cell_llc_vtime_read(&cells[tctx->cell], llc);
		} else {
			basis_vtime = cell_llc_vtime_read(&cells[tctx->cell],
							  FAKE_FLAT_CELL_LLC);
		}
	} else {
		cstat_inc(CSTAT_CPU_DSQ, tctx->cell, cctx);

		/*
		 * cctx is the local cid (where enqueue is running), not the one
		 * the task belongs to. Fetch the right cctx
		 */
		cctx = &cpu_ctxs[cid];
		/* Task is pinned to specific cids, use per-cid DSQ */
		basis_vtime = READ_ONCE(cctx->vtime_now);
	}

	/*
	 * Ensure this is done *AFTER* refreshing cell and enqueue_pinned_cpu()
	 * or maybe_update_task_llc(), which might manipulate vtime.
	 */
	vtime = p->scx.dsq_vtime;
	tctx->basis_vtime = basis_vtime;

	if (time_after(vtime, basis_vtime + 8192 * slice_ns)) {
		scx_bpf_error("vtime too far ahead: pid=%d vtime=%llu basis=%llu diff=%llu cell=%u",
			      p->pid, p->scx.dsq_vtime, basis_vtime, p->scx.dsq_vtime - basis_vtime,
			      tctx->cell);
		return;
	}
	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (time_before(vtime, basis_vtime - slice_ns))
		vtime = basis_vtime - slice_ns;

	scx_bpf_dsq_insert_vtime(p, tctx->dsq.raw, slice_ns, vtime, enq_flags);

	/*
	 * Account after insertion: cell reconfiguration can orphan the selected
	 * LLC between LLC selection and enqueue, so this is where we interlock
	 * with refresh_cell_llc_draining() and enable draining if needed.
	 */
	if (enable_llc_awareness && tctx->all_cell_cpus_allowed) {
		if (account_cell_llc_enqueue(tctx->cell, tctx->llc))
			return;
	}

	/* Shrink the running task's slice for this pinned waiter.
	 * We know this task is pinned (!all_cell_cpus_allowed). */
	if (!tctx->all_cell_cpus_allowed && enable_slice_shrinking) {
		struct task_struct *curr = scx_bpf_cid_curr(cid);
		/* Likely overly defensive bc no other should read */
		if (curr && !(curr->flags & PF_IDLE))
			slice_shrink_on_enqueue(curr, tctx, tctx->cell, cctx);
	}

	/* Kick the cid if needed */
	if ((!__COMPAT_is_enq_cpu_selected(enq_flags) || (enq_flags & SCX_ENQ_LAST)) && cid >= 0)
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(mitosis_dispatch, s32 cid, struct task_struct *prev)
{
	scx_arena_subprog_init();

	struct cpu_ctx __arena *cctx;
	u32 cell;

	cctx = cur_cpu_ctx();
	cell = READ_ONCE(cctx->cell);

	bool found = false;
	dsq_id_t min_vtime_dsq = DSQ_INVALID;
	u64 min_vtime = 0;

	struct task_struct *p;

	/* Check the cell-LLC DSQ (use FAKE_FLAT_CELL_LLC when not LLC-aware) */
	u32 llc = enable_llc_awareness ? cctx->llc : FAKE_FLAT_CELL_LLC;
	dsq_id_t cell_dsq = get_cell_llc_dsq_id(cell, llc);
	dsq_id_t cid_dsq = get_cid_dsq_id(cid);

	if (dsq_is_invalid(cell_dsq) || dsq_is_invalid(cid_dsq))
		return;

	if (enable_llc_awareness && READ_ONCE(cells[cell].llcs_to_drain) &&
	    !try_draining_work(cell, llc, cctx)) {
		cstat_inc(CSTAT_DRAIN_CNT, cell, cctx);
		return;
	}

	/* Peek at cell-LLC DSQ head */
	p = dsq_peek(cell_dsq.raw);
	if (p) {
		min_vtime = p->scx.dsq_vtime;
		min_vtime_dsq = cell_dsq;
		found = true;
	}

	/* Peek at cid DSQ head, prefer if lower vtime */
	p = dsq_peek(cid_dsq.raw);
	if (p && (!found || time_before(p->scx.dsq_vtime, min_vtime))) {
		min_vtime = p->scx.dsq_vtime;
		min_vtime_dsq = cid_dsq;
		found = true;
	}

	/* If we failed to find an eligible task, try the sibling LLC DSQs. */
	if (!found) {
		if (enable_llc_awareness && !try_stealing_work(cell, llc)) {
			cstat_inc(CSTAT_STEAL, cell, cctx);
			return;
		}

		/*
		 * Nothing to run. Extend the slice of a still-runnable prev
		 * whose placement is current and still names this cpu.
		 * Otherwise let the SCX_ENQ_LAST enqueue re-place the task, its
		 * kicks provide the follow-up scheduling event while this cpu
		 * goes idle.
		 */
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
			struct task_ctx __arena *tctx;
			bool stay = false;

			if (!(tctx = lookup_task_ctx(prev)))
				return;

			if (!task_needs_refresh(prev, tctx)) {
				if (tctx->all_cell_cpus_allowed)
					stay = tctx->cell == cell;
				else
					stay = tctx->dsq.raw == cid_dsq.raw;
			}

			if (stay)
				scx_bpf_task_set_slice(prev, slice_ns);
		}
		return;
	}

	/*
	 * The move_to_local can fail if we raced with some other cpu in the cell
	 * and now the cell is empty. We have to ensure to try the cpu_dsq or else
	 * we might never wakeup.
	 */

	/* Try the winner first */
	if (scx_bpf_dsq_move_to_local(min_vtime_dsq.raw, 0)) {
		if (enable_llc_awareness && min_vtime_dsq.raw == cell_dsq.raw) {
			cell_llc_nr_queued_dec(&cells[cell], llc);
		}
		return;
	}

	/* Winner was cell DSQ but failed - try the cid DSQ */
	if (min_vtime_dsq.raw == cell_dsq.raw)
		scx_bpf_dsq_move_to_local(cid_dsq.raw, 0);
}

/*
 * This array keeps track of the cgroup ancestor's cell as we iterate over the
 * cgroup hierarchy.
 */
u32 level_cells[MAX_CG_DEPTH];
static inline void advance_cell_llc_vtime(struct cell __arena *cell, u32 llc_idx,
					      u64 task_vtime)
{
	if (time_before(READ_ONCE(cell->llcs[llc_idx].vtime_now), task_vtime))
		WRITE_ONCE(cell->llcs[llc_idx].vtime_now, task_vtime);
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct cpu_ctx __arena *cctx;
	struct task_ctx __arena *tctx;

	cctx = cur_cpu_ctx();
	if (!(tctx = lookup_task_ctx(p)))
		return;

	if (enable_llc_awareness && tctx->all_cell_cpus_allowed) {
		/*
		 * The actual running CPU is known once the task starts running
		 * after dispatch or sibling LLC stealing. Refresh the task's LLC
		 * here so its assignment and vtime domain follow where it really
		 * ran.
		 */
		if (maybe_update_task_llc(p, tctx, scx_bpf_task_cid(p)) < 0)
			return;

		/* single read, a drain can invalidate tctx->llc remotely */
		s32 llc = READ_ONCE(tctx->llc);

		if (llc >= 0)
			advance_cell_llc_vtime(&cells[tctx->cell], llc, p->scx.dsq_vtime);
	}

	/* Record the running slice start time. */
	tctx->started_running_at = scx_bpf_now();

	/* Shrink our slice if a pinned task is queued on this CPU's DSQ. */
	if (enable_slice_shrinking) {
		int ret = slice_shrink_on_running(p, tctx->cell, cctx);
		if (ret < 0)
			return;
	}
}

/*
 * Smoothed average of a task's per-wake runtime (EWMA, alpha=1/8). Updated in
 * stopping() after each run. Starts at 0 and converges over ~8 runs. Used by
 * features like slice shrinking to estimate how long a task typically runs.
 */
static inline void update_task_runtime_ewma(struct task_ctx __arena *tctx, u64 used)
{
	if (unlikely(!tctx->avg_runtime_ns))
		/* Init */
		tctx->avg_runtime_ns = used;
	else
		tctx->avg_runtime_ns = (tctx->avg_runtime_ns * 7 + used) / 8;
}

void BPF_STRUCT_OPS(mitosis_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx __arena *cctx;
	struct task_ctx __arena *tctx;
	struct cell __arena *cell;
	u64 now, used;
	u32 cidx;

	cctx = cur_cpu_ctx();
	if (!(tctx = lookup_task_ctx(p)))
		return;

	/*
	 * Use CPU's cell (not task's cell) to match dispatch() logic.
	 * Prevents starvation when a task is pinned outside its cell.
	 * E.g. a cell 0 kworker pinned to a cell 1 CPU.
	 */
	cidx = cctx->cell;
	cell = &cells[cidx];

	now = scx_bpf_now();
	/*
	 * scx_bpf_now() is per-CPU (uses this_rq()) and not monotonic
	 * across CPUs. Clamp negative deltas to zero to prevent
	 * unsigned underflow from corrupting vtime.
	 */
	if (now < tctx->started_running_at)
		cstat_inc(CSTAT_CLAMP_USED, cidx, cctx);
	used = time_delta(now, tctx->started_running_at);
	tctx->started_running_at = now;

	update_task_runtime_ewma(tctx, used);

	/* scale the execution time by the inverse of the weight and charge */
	if (p->scx.weight == 0) {
		scx_bpf_error("Task %d has zero weight", p->pid);
		return;
	}
	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + (used * 100 / p->scx.weight));

	/*
	 * Only advance this CPU's local vtime when the slice ends on a CPU
	 * whose cell matches this task's vtime charge cell and the task was
	 * not borrowed. If execution ends in some other cell, drop the local
	 * charge rather than risk charging an unexpected domain.
	 */
	if (!tctx->borrowed && tctx->vtime_charge_cell == cidx) {
		if (time_before(READ_ONCE(cctx->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cctx->vtime_now, p->scx.dsq_vtime);
	}

	/*
	 * Only advance cell vtime when the task stops on a CPU whose cell
	 * still matches this task's vtime charge cell and the task was not
	 * borrowed. If the CPU was retagged into a different cell after the
	 * task was placed, drop the charge rather than advance the wrong cell
	 * domain.
	 */
	if (!tctx->borrowed && tctx->vtime_charge_cell == cidx) {
		u32 llc_idx = FAKE_FLAT_CELL_LLC;

		if (enable_llc_awareness) {
			if (cctx->llc >= topo->nr_llcs) {
				scx_bpf_error("invalid CPU LLC in stopping: %u", cctx->llc);
				return;
			}
			llc_idx = cctx->llc;
		}
		advance_cell_llc_vtime(cell, llc_idx, p->scx.dsq_vtime);
	}

	/* Clear the borrowed flag — it is one-shot, consumed above */
	tctx->borrowed = false;

	cctx->running_ns[tctx->cell] += used;
}

SEC("fentry/cpuset_write_resmask")
int BPF_PROG(fentry_cpuset_write_resmask, struct kernfs_open_file *of, char *buf, size_t nbytes,
	     loff_t off, ssize_t retval)
{
	/*
	 * On a write to cpuset.cpus, userspace must re-read cpusets and push a
	 * fresh cell configuration.
	 */
	__atomic_add_fetch(&cpuset_seq, 1, __ATOMIC_RELEASE);
	return 0;
}

/* From linux/percpu-refcount.h */
#define __PERCPU_REF_DEAD (1LU << 1)

/*
 * Check if a cgroup is dying (being destroyed).
 */
static bool cgrp_is_dying(struct cgroup *cgrp)
{
	unsigned long refcnt_ptr;
	bpf_core_read(&refcnt_ptr, sizeof(refcnt_ptr), &cgrp->self.refcnt.percpu_count_ptr);
	return refcnt_ptr & __PERCPU_REF_DEAD;
}

/*
 * Cgroup initialization - creates cgrp_ctx. Root cgroup is assigned cell 0.
 * Other cgroups inherit their parent's cell until userspace assigns them
 * explicitly via apply_cell_config().
 */
static int init_cgrp_ctx(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu", cgrp->kn->id);
		return -ENOENT;
	}

	if (cgrp->kn->id == root_cgid) {
		WRITE_ONCE(cgc->cell, 0);
		return 0;
	}

	/* Initialize to parent's cell */
	struct cgroup *parent_cg __free(cgroup) = lookup_cgrp_ancestor(cgrp, cgrp->level - 1);
	if (!parent_cg)
		return -ENOENT;

	struct cgrp_ctx *parent_cgc;
	if (!(parent_cgc = lookup_cgrp_ctx(parent_cg)))
		return -ENOENT;

	cgc->cell = parent_cgc->cell;
	return 0;
}

/*
 * Initialize cgroup and all its ancestors. Handles dying cgroups gracefully.
 * Used when CPU controller is disabled since SCX cgroup callbacks won't fire.
 */
static int init_cgrp_ctx_with_ancestors(struct cgroup *cgrp)
{
	u32 target_level = cgrp->level;
	u32 level;
	int ret;

	/* Skip dying cgroups */
	if (cgrp_is_dying(cgrp))
		return 0;

	/* Initialize ancestors first (replicates SCX cgroup_init order) */
	bpf_for(level, 1, target_level)
	{
		struct cgroup *ancestor __free(cgroup) = lookup_cgrp_ancestor(cgrp, level);
		if (!ancestor)
			return -ENOENT;

		/* Skip if dying or already initialized */
		if (!cgrp_is_dying(ancestor) && !lookup_cgrp_ctx_fallible(ancestor)) {
			ret = init_cgrp_ctx(ancestor);
			if (ret)
				return ret;
		}
	}

	/* Skip if already initialized */
	if (lookup_cgrp_ctx_fallible(cgrp))
		return 0;

	return init_cgrp_ctx(cgrp);
}

/*
 * SCX cgroup callbacks - called by the SCX framework when the CPU controller
 * is enabled.
 */
s32 BPF_STRUCT_OPS(mitosis_cpuctl_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	if (cpu_controller_disabled)
		return 0;
	return init_cgrp_ctx(cgrp);
}

void BPF_STRUCT_OPS(mitosis_cpuctl_exit, struct cgroup *cgrp)
{
	if (cpu_controller_disabled)
		return;
}

void BPF_STRUCT_OPS(mitosis_cpuctl_move, struct task_struct *p, struct cgroup *from,
		    struct cgroup *to)
{
	struct task_ctx __arena *tctx;

	if (cpu_controller_disabled)
		return;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	update_task_cell(p, tctx, to);
}

/*
 * Tracepoint fallbacks - only active when CPU controller is disabled.
 * These provide cgroup tracking when SCX cgroup callbacks don't fire.
 */
SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(tp_cgroup_mkdir, struct cgroup *cgrp, const char *cgrp_path)
{
	int ret;
	if (!cpu_controller_disabled)
		return 0;

	ret = init_cgrp_ctx_with_ancestors(cgrp);
	if (ret) {
		scx_bpf_error(
			"tp_cgroup_mkdir: init_cgrp_ctx_with_ancestors failed for cgid %llu: %d",
			cgrp->kn->id, ret);
	}
	return 0;
}

SEC("tp_btf/cgroup_rmdir")
int BPF_PROG(tp_cgroup_rmdir, struct cgroup *cgrp, const char *cgrp_path)
{
	if (!cpu_controller_disabled)
		return 0;

	return 0;
}

void BPF_STRUCT_OPS(mitosis_set_cmask, struct task_struct *p, struct scx_cmask __arena *cmask)
{
	struct task_ctx __arena *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	cmask_copy(&tctx->allowed, cmask);
	cmask_and(&tctx->allowed, topo_cids);
	update_task_cmask(p, tctx);
}

s32 validate_userspace_data()
{
	if (nr_possible_cpus > MAX_CPUS) {
		scx_bpf_error("nr_possible_cpus %d exceeds MAX_CPUS %d", nr_possible_cpus,
			      MAX_CPUS);
		return -EINVAL;
	}
	return 0;
}

/*
 * Task ctxs are RCU protected and freed when the task leaves the scheduler: a
 * lookup fails once the task is gone and a looked-up ctx stays valid until the
 * end of the RCU section.
 */
void BPF_STRUCT_OPS(mitosis_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	scx_task_free_rcu(p);
}

/* scx_urcu driver programs, discovered by name and run by the userspace side */
SEC("syscall")
int scx_urcu_cellmask_pending(void *ctx)
{
	return scx_urcu_pending(&cell_cmask_urcu);
}

SEC("syscall")
int scx_urcu_cellmask_reclaim(void *ctx)
{
	return scx_urcu_reclaim(&cell_cmask_urcu, &cell_cmask_allocator);
}

static int init_task_impl(struct task_struct *p, struct cgroup *cgrp)
{
	struct task_ctx __arena *tctx;
	struct mitosis_topo __arena *t = topo;
	int ret;

	tctx = scx_task_alloc(p);
	if (!tctx) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	cmask_init(&tctx->allowed, 0, t->nr_cids);
	cmask_init(&tctx->effective, 0, t->nr_cids);

	/*
	 * p->cpus_ptr for the allowed mask seeding is RCU-trusted only inside
	 * an RCU critical section, which this sleepable path is not implicitly
	 * in.
	 */
	scoped_guard(rcu) {
		/*
		 * Seed the allowed mask from the task's current affinity.
		 * ops.set_cmask() keeps it in sync from here on.
		 */
		cmask_from_cpumask(&tctx->allowed, p->cpus_ptr);
		cmask_and(&tctx->allowed, topo_cids);

		/* Initialize LLC assignment fields */
		if (enable_llc_awareness)
			tctx->llc = LLC_INVALID;

		ret = update_task_cell(p, tctx, cgrp);
	}

	/* a failed init gets no ops.exit_task() and no one saw the ctx */
	if (ret)
		scx_task_free(p);

	return ret;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mitosis_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct cgroup *cgrp __free(cgroup) = NULL;
	int ret;

	/*
	 * When CPU controller is disabled, args->cgroup is root, so we need
	 * to get the task's actual cgroup for both logging and cell assignment.
	 * We also need to ensure the cgroup hierarchy is initialized since
	 * SCX cgroup callbacks won't fire.
	 */
	if (cpu_controller_disabled) {
		cgrp = task_cgroup(p);
		if (!cgrp) {
			scx_bpf_error("task_cgroup() failed");
			return -ENOENT;
		}

		/* Ensure cgroup hierarchy is initialized (handles ancestors + this cgroup) */
		ret = init_cgrp_ctx_with_ancestors(cgrp);
		if (ret) {
			scx_bpf_error("init_cgrp_ctx_with_ancestors() failed");
			return ret;
		}

		ret = init_task_impl(p, cgrp);
		if (ret) {
			scx_bpf_error("init_task_impl failed");
			return ret;
		}
		return 0;
	}
	/*
	 * Extra refcount bump below can be dropped and args->cgroup can be used
	 * directly when minimum kernel version advances to >= v7.4, per the patch
	 * https://lore.kernel.org/bpf/95d7ccc17681aa3a4a2eeb1b073f00f7@kernel.org.
	 */
	cgrp = bpf_cgroup_from_id(args->cgroup->kn->id);
	if (!cgrp) {
		/*
		 * The ID lookup fails for a cgroup that has already been
		 * removed, which can happen for an exiting task getting
		 * initialized during scheduler load. Fall back to the root
		 * cgroup. This lands the task in the root cell even when the
		 * dying cgroup's ctx, which update_task_cell() would have
		 * preferred, is still around.
		 */
		if (!(exiting_task_workaround_enabled && (p->flags & PF_EXITING))) {
			scx_bpf_error("bpf_cgroup_from_id() failed");
			return -ENOENT;
		}

		cgrp = bpf_cgroup_from_id(root_cgid);
		if (!cgrp)
			return -ENOENT;
	}
	ret = init_task_impl(p, cgrp);
	if (ret) {
		scx_bpf_error("init_task_impl() failed");
		return ret;
	}
	return 0;
}

static void dump_cmask(struct scx_cmask __arena *m)
{
	u32 nr_words = (topo->nr_cids + 63) / 64;
	u32 w;

	bpf_for(w, 0, nr_words) {
		u64 word = m->bits[nr_words - w - 1];

		if (w)
			scx_bpf_dump(",");
		scx_bpf_dump("%016llx", word);
	}
}

static void dump_cell_cmask(int id)
{
	dump_cmask(&READ_ONCE(cell_masks)->mask[id].cmask);
}

void BPF_STRUCT_OPS(mitosis_dump, struct scx_dump_ctx *dctx)
{
	scx_arena_subprog_init();

	dsq_id_t dsq_id;
	int i;
	u32 llc;
	struct cell __arena *cell;
	struct cpu_ctx __arena *cpu_ctx;

	scx_bpf_dump_header();

	bpf_for(i, 0, MAX_CELLS)
	{
		cell = &cells[i];

		if (!cell->in_use)
			continue;

		scx_bpf_dump("CELL[%d] CPUS=", i);
		dump_cell_cmask(i);
		scx_bpf_dump("\n");

		if (enable_llc_awareness) {
			u64 drain_mask = READ_ONCE(cell->llcs_to_drain);
			u64 llcs_with_cpus = READ_ONCE(cell->llcs_with_cpus);

			scx_bpf_dump("CELL[%d] llcs_to_drain=%llx llcs_with_cpus=%llx\n", i,
				     drain_mask, llcs_with_cpus);

			bpf_for(llc, 0, topo->nr_llcs) {
				u64 bit;
				s32 nr_queued;
				u32 tracked_nr_queued;

				dsq_id = get_cell_llc_dsq_id(i, llc);
				if (dsq_is_invalid(dsq_id))
					return;

				bit = 1LLU << llc;
				nr_queued = scx_bpf_dsq_nr_queued(dsq_id.raw);
				tracked_nr_queued = READ_ONCE(cell->llcs[llc].nr_queued);
				if (!nr_queued && !tracked_nr_queued && !(drain_mask & bit) &&
				    !(llcs_with_cpus & bit))
					continue;

				scx_bpf_dump(
					"CELL[%d] LLC[%d] vtime=%llu nr_queued=%d drain=%d has_cpus=%d tracked_nr_queued=%u\n",
					i, llc, cell_llc_vtime_read(cell, llc), nr_queued,
					!!(drain_mask & bit), !!(llcs_with_cpus & bit),
					tracked_nr_queued);
			}
		} else {
			dsq_id = get_cell_llc_dsq_id(i, FAKE_FLAT_CELL_LLC);
			if (dsq_is_invalid(dsq_id))
				return;

			scx_bpf_dump("CELL[%d] vtime=%llu nr_queued=%d\n", i,
				     cell_llc_vtime_read(cell, FAKE_FLAT_CELL_LLC),
				     scx_bpf_dsq_nr_queued(dsq_id.raw));
		}
	}

	bpf_for(i, 0, topo->nr_cids) {
		cpu_ctx = &cpu_ctxs[i];
		dsq_id = get_cid_dsq_id(i);
		if (dsq_is_invalid(dsq_id))
			return;
		if (enable_llc_awareness) {
			scx_bpf_dump("CID[%d] cell=%d llc=%d vtime=%llu nr_queued=%d\n", i,
				     cpu_ctx->cell, cpu_ctx->llc, READ_ONCE(cpu_ctx->vtime_now),
				     scx_bpf_dsq_nr_queued(dsq_id.raw));
		} else {
			scx_bpf_dump("CPU[%d] cell=%d vtime=%llu nr_queued=%d\n", i, cpu_ctx->cell,
				     READ_ONCE(cpu_ctx->vtime_now),
				     scx_bpf_dsq_nr_queued(dsq_id.raw));
		}
	}
}

void BPF_STRUCT_OPS(mitosis_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	struct task_ctx __arena *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	scx_bpf_dump(
		"Task[%d] vtime=%llu basis_vtime=%llu cell=%u llc=%d dsq=%llx all_cell_cpus_allowed=%d\n",
		p->pid, p->scx.dsq_vtime, tctx->basis_vtime, tctx->cell, tctx->llc, tctx->dsq.raw,
		tctx->all_cell_cpus_allowed);
	scx_bpf_dump("Task[%d] CIDS=", p->pid);
	dump_cmask(&tctx->allowed);
	scx_bpf_dump("\n");
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mitosis_init)
{
	u32 nr_cids, nr_llcs = 0, nr_shards = 0, nr_cores = 0, nr_topo = 0;
	struct cell_cmasks __arena *gen;
	struct mitosis_topo __arena *t;
	u32 i;
	s32 ret;

	cells = bpf_arena_alloc_pages(&arena, NULL,
				      div_round_up(MAX_CELLS * sizeof(struct cell),
						   PAGE_SIZE), NUMA_NO_NODE, 0);
	if (!cells)
		return -ENOMEM;

	/* Check data from userspace. */
	if ((ret = validate_userspace_data()))
		return ret;

	struct cgroup *rootcg __free(cgroup) = bpf_cgroup_from_id(root_cgid);
	if (!rootcg)
		return -ENOENT;

	/* Initialize root cgroup storage so tasks can always fall back to cell 0. */
	if (!bpf_cgrp_storage_get(&cgrp_ctxs, rootcg, 0, BPF_LOCAL_STORAGE_GET_F_CREATE)) {
		scx_bpf_error("cgrp_ctx creation failed for rootcg");
		return -ENOENT;
	}

	struct cgroup *old __free(cgroup) = bpf_kptr_xchg(&root_cgrp, no_free_ptr(rootcg));

	/* Snapshot the cid topology and set up the derived tables. */
	nr_cids = scx_bpf_nr_cids();
	if (!nr_cids || nr_cids > MAX_CPUS) {
		scx_bpf_error("nr_cids %u out of range", nr_cids);
		return -EINVAL;
	}

	topo = bpf_arena_alloc_pages(&arena, NULL, div_round_up(sizeof(struct mitosis_topo),
				     PAGE_SIZE), NUMA_NO_NODE, 0);
	if (!(t = topo))
		return -ENOMEM;

	t->nr_cids = nr_cids;

	bpf_for(i, 0, nr_cids) {
		struct scx_cid_topo ct = {};

		scx_bpf_cid_topo(i, &ct);
		t->cid[i] = ct;

		/*
		 * Offline-possible cpus get no-topo tail cids with -1
		 * core/LLC/node indices, which keeps them out of the llc
		 * tables. They do get valid shard assignments and enter the
		 * shard tables, but their idle bits are never set as
		 * update_idle() cannot fire for offline cpus, so the pick scans
		 * skip them.
		 */
		if (ct.llc_idx >= MAX_LLCS) {
			scx_bpf_error("llc_idx %d exceeds MAX_LLCS %d", ct.llc_idx, MAX_LLCS);
			return -EINVAL;
		}
		if (ct.llc_idx >= 0) {
			if (!t->llc_cids[ct.llc_idx].nr)
				t->llc_cids[ct.llc_idx].base = ct.llc_cid;
			t->llc_cids[ct.llc_idx].nr++;
			if ((u32)ct.llc_idx + 1 > nr_llcs)
				nr_llcs = ct.llc_idx + 1;
		}
		if (!t->shard_cids[ct.shard_idx].nr)
			t->shard_cids[ct.shard_idx].base = ct.shard_cid;
		t->shard_cids[ct.shard_idx].nr++;
		if ((u32)ct.shard_idx + 1 > nr_shards)
			nr_shards = ct.shard_idx + 1;
		if (ct.core_idx >= 0) {
			if (!t->core_cids[ct.core_idx].nr)
				t->core_cids[ct.core_idx].base = ct.core_cid;
			t->core_cids[ct.core_idx].nr++;
			if ((u32)ct.core_idx + 1 > nr_cores)
				nr_cores = ct.core_idx + 1;
			nr_topo++;
		}
	}
	t->nr_llcs = nr_llcs;
	t->nr_shards = nr_shards;
	t->nr_cores = nr_cores;
	/* multiple cids in a core means SMT, no-topo tails excluded */
	t->smt_active = nr_topo != nr_cores;

	if (enable_llc_awareness && !nr_llcs) {
		scx_bpf_error("LLC-aware mode requires LLC topology");
		return -EINVAL;
	}

	/* Shards are LLC-aligned, an LLC is a contiguous shard run. */
	bpf_for(i, 0, nr_llcs) {
		s32 base = t->llc_cids[i].base;
		s32 last = base + t->llc_cids[i].nr - 1;

		t->llc_shards[i].base = t->cid[base].shard_idx;
		t->llc_shards[i].nr = t->cid[last].shard_idx - t->cid[base].shard_idx + 1;
	}

	/* Offline-possible cpus have no topology, collect the cids that do. */
	topo_cids = bpf_arena_alloc_pages(&arena, NULL, div_round_up(sizeof(union cell_cmask),
					  PAGE_SIZE), NUMA_NO_NODE, 0);
	if (!topo_cids)
		return -ENOMEM;
	cmask_init(topo_cids, 0, nr_cids);
	bpf_for(i, 0, nr_cids) {
		if (t->cid[i].core_idx >= 0)
			__cmask_set(i, topo_cids);
	}

	/* Per-shard idle masks, windowed to each shard's cid range. */
	u32 mask_pgs = div_round_up(nr_shards * sizeof(union shard_cmask), PAGE_SIZE);

	idle_masks = bpf_arena_alloc_pages(&arena, NULL, mask_pgs, NUMA_NO_NODE, 0);
	if (!idle_masks)
		return -ENOMEM;
	idle_smt_masks = bpf_arena_alloc_pages(&arena, NULL, mask_pgs, NUMA_NO_NODE, 0);
	if (!idle_smt_masks)
		return -ENOMEM;
	bpf_for(i, 0, nr_shards) {
		cmask_init(&idle_masks[i].cmask, t->shard_cids[i].base, t->shard_cids[i].nr);
		cmask_init(&idle_smt_masks[i].cmask, t->shard_cids[i].base,
			   t->shard_cids[i].nr);
	}

	/*
	 * Cell cmasks. Primaries start with every topology-backed cid until
	 * userspace pushes the first explicit cell configuration immediately
	 * after attach. Borrowables start empty.
	 */
	ret = scx_alloc_init(&cell_cmask_allocator, sizeof(struct cell_cmasks), 8);
	if (ret)
		return ret;
	gen = cell_cmasks_alloc(nr_cids);
	if (!gen)
		return -ENOMEM;
	bpf_for(i, 0, MAX_CELLS)
		cmask_copy(&gen->mask[i].cmask, topo_cids);
	cell_cmasks_publish(gen);

	/* Per-cid contexts, read directly by userspace for stats. */
	u32 ctx_pgs = div_round_up(nr_cids * sizeof(struct cpu_ctx), PAGE_SIZE);

	cpu_ctxs = bpf_arena_alloc_pages(&arena, NULL, ctx_pgs, NUMA_NO_NODE, 0);
	if (!cpu_ctxs)
		return -ENOMEM;
	nr_cid_ctxs = nr_cids;

	/* Per-cid DSQs and the per-cid LLC cache in cpu_ctx. */
	bpf_for(i, 0, nr_cids) {
		dsq_id_t dsq_id = get_cid_dsq_id(i);
		struct cpu_ctx __arena *cpu_ctx;

		if (dsq_is_invalid(dsq_id))
			return -EINVAL;
		ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
		if (ret < 0) {
			scx_bpf_error("Failed to create dsq for cid %d, ret: %d", i, ret);
			return ret;
		}

		cpu_ctx = &cpu_ctxs[i];
		cpu_ctx->cpu = scx_bpf_cid_to_cpu(i);
		if (enable_llc_awareness)
			cpu_ctx->llc = t->cid[i].llc_idx >= 0 ?
				t->cid[i].llc_idx : LLC_INVALID;
		else
			cpu_ctx->llc = FAKE_FLAT_CELL_LLC;
	}

	/*
	 * When CPU controller is disabled, initialize cgrp_ctx for all existing
	 * cgroups. This replicates SCX cgroup_init callback behavior - all
	 * cgroups get initialized in hierarchical order during scheduler attach.
	 * The tracepoint handles new cgroups created after attach.
	 */
	if (cpu_controller_disabled) {
		struct cgroup *iter_root __free(cgroup) = NULL;

		scoped_guard(rcu)
		{
			if (root_cgrp)
				iter_root = bpf_cgroup_acquire(root_cgrp);
		}

		if (!iter_root) {
			scx_bpf_error("Failed to acquire root cgroup for initialization");
			return -ENOENT;
		}

		struct cgroup_subsys_state *root_css = &iter_root->self;
		struct cgroup_subsys_state *pos;

		scoped_guard(rcu)
		{
			bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
				/*
				 * pos->cgroup dereference loses RCU tracking in verifier,
				 * so we can't use it directly with bpf_cgroup_acquire or
				 * pass it to functions that call bpf_cgroup_ancestor.
				 * Instead, read the cgroup ID and use bpf_cgroup_from_id
				 * to get a trusted, acquired reference.
				 */
				u64 cgid = pos->cgroup->kn->id;
				struct cgroup *cgrp __free(cgroup) = bpf_cgroup_from_id(cgid);
				if (cgrp)
					init_cgrp_ctx(cgrp);
			}
		}
	}

	bpf_for(i, 0, MAX_CELLS)
	{
		if (enable_llc_awareness) {
			u32 llc;
			bpf_for(llc, 0, t->nr_llcs)
			{
				dsq_id_t dsq_id = get_cell_llc_dsq_id(i, llc);
				if (dsq_is_invalid(dsq_id))
					return -EINVAL; // scx_bpf_error called in get_cell_llc_dsq_id

				ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
				if (ret < 0)
					return ret;
			}
		} else {
			dsq_id_t dsq_id = get_cell_llc_dsq_id(i, FAKE_FLAT_CELL_LLC);
			if (dsq_is_invalid(dsq_id))
				return -EINVAL; // scx_bpf_error called in get_cell_llc_dsq_id

			ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
			if (ret < 0)
				return ret;
		}
	}

	{
		struct cell __arena *cell = &cells[0];

		cell->in_use = true;
	}

	return 0;
}

void BPF_STRUCT_OPS(mitosis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Fill @gen, a fresh cell cmask generation, from cell_config and derive the
 * cid-to-cell mappings in one pass. The config carries cpu-indexed bits from
 * userspace, so each cpu is translated to its cid. The caller publishes @gen
 * once it is complete.
 */
static int apply_cell_cmasks(struct cell_cmasks __arena *gen, u32 num_cells)
{
	struct cell_config *config = &cell_config;
	struct cpu_ctx __arena *cctx;
	u32 cell_id, cpu;

	bpf_for(cell_id, 0, num_cells) {
		struct cell_cpumask_data *cpumask_data;
		struct scx_cmask __arena *cell_mask;

		cpumask_data = MEMBER_VPTR(config->cpumasks, [cell_id]);
		if (!cpumask_data) {
			scx_bpf_error("cell_id %d out of bounds", cell_id);
			return -EINVAL;
		}

		cell_mask = &gen->mask[cell_id].cmask;

		bpf_for(cpu, 0, nr_possible_cpus) {
			bool cpu_in_cell;
			s32 cid;

			if (cell_cpumask_data_test_cpu(cpumask_data, cpu, &cpu_in_cell)) {
				scx_bpf_error("failed to decode cpumask for cell_id %d",
					      cell_id);
				return -EINVAL;
			}

			if (!cpu_in_cell)
				continue;

			/* cids without topology stay out of cell masks */
			cid = scx_bpf_cpu_to_cid(cpu);
			if (cid < 0 || topo->cid[cid].core_idx < 0)
				continue;

			__cmask_set(cid, cell_mask);

			cctx = &cpu_ctxs[cid];
			/*
			 * If the cid is changing cells, advance the new cell's
			 * vtime to at least match this cid's vtime. Otherwise
			 * the per-cid DSQ and cell DSQ are in different vtime
			 * domains and dispatch will starve the per-cid DSQ
			 * tasks.
			 */
			if (cctx->cell != cell_id) {
				struct cell __arena *cell = &cells[cell_id];
				u32 llc_idx = FAKE_FLAT_CELL_LLC;

				if (enable_llc_awareness && cctx->llc < topo->nr_llcs)
					llc_idx = cctx->llc;
				advance_cell_llc_vtime(cell, llc_idx, cctx->vtime_now);
			}
			cctx->cell = cell_id;
		}

		/* Apply borrowable cmask for this cell */
		if (enable_borrowing) {
			struct cell_cpumask_data *borrowable_data;
			struct scx_cmask __arena *borrowable;

			borrowable_data = MEMBER_VPTR(config->borrowable_cpumasks, [cell_id]);
			if (!borrowable_data) {
				scx_bpf_error("cell_id %d out of bounds for borrowable",
					      cell_id);
				return -EINVAL;
			}

			borrowable = &gen->borrowable[cell_id].cmask;
			bpf_for(cpu, 0, nr_possible_cpus) {
				bool cpu_in;
				s32 cid;

				if (cell_cpumask_data_test_cpu(borrowable_data, cpu, &cpu_in))
					return -EINVAL;
				if (!cpu_in)
					continue;
				cid = scx_bpf_cpu_to_cid(cpu);
				if (cid >= 0 && topo->cid[cid].core_idx >= 0)
					__cmask_set(cid, borrowable);
			}
		}
	}

	return 0;
}

/*
 * Apply a complete cell configuration.
 *
 * Configuration data is read from the cell_config global struct,
 * which is populated by userspace before invoking this program.
 *
 * The function operates in five phases:
 * 1. Mark all cells (except cell 0) as not in use
 * 2. Apply cell cpumasks and CPU-to-cell mappings
 * 3. Apply cell assignments for owner cgroups
 * 4. Walk cgroup hierarchy to propagate cells to children
 * 5. Bump applied_configuration_seq to signal completion
 *
 * Note: This is not atomic - tasks may observe intermediate states during
 * execution. On error, the scheduler may be left in a partially-configured
 * state. This is acceptable because userspace treats errors as fatal and
 * exits, causing the scheduler to be unloaded.
 */
SEC("syscall")
int apply_cell_config(void *ctx)
{
	scx_arena_subprog_init();

	struct cgrp_ctx *cgc;
	struct cell __arena *cell;
	struct cell_cmasks __arena *gen;
	struct cgroup_subsys_state *root_css, *pos;
	struct cgroup *cur_cgrp;
	u32 i, cell_id, num_cells;
	int ret;

	/* Read configuration from global struct (populated by userspace) */
	struct cell_config *config = &cell_config;

	/*
	 * Phase 1: Mark all cells (except cell 0) as not in use.
	 * This handles cell destruction - cells not in the new config
	 * will remain marked as not in use.
	 */
	bpf_for(i, 1, MAX_CELLS)
	{
		cell = &cells[i];

		WRITE_ONCE(cell->in_use, 0);
		cell->owner_cgid = 0;
	}

	/*
	 * Phase 2: Build the new cell cmask generation, deriving CPU-to-cell
	 * mappings along the way, and publish it in one flip. Refresh the
	 * per-cell drain state against the published masks afterwards.
	 *
	 * This is done before cgroup assignments so that any task
	 * initialized mid-operation that reads a new cell ID will find
	 * correct cpumasks already in place.
	 */
	/* config is userspace-writable bss, cap the loop bounds on one read */
	num_cells = config->num_cells;
	if (num_cells > MAX_CELLS)
		return -EINVAL;

	gen = cell_cmasks_alloc(topo->nr_cids);
	if (!gen)
		return -ENOMEM;
	ret = apply_cell_cmasks(gen, num_cells);
	if (ret) {
		scx_free(&cell_cmask_allocator, gen);
		return ret;
	}
	/*
	 * scx_urcu frees must run inside an RCU read section so that the
	 * reclaim grace period waits them out, see scx_urcu_free().
	 */
	scoped_guard(rcu)
		cell_cmasks_publish(gen);

	bpf_for(cell_id, 0, num_cells) {
		scoped_guard(rcu)
		{
			if (refresh_cell_llc_draining(cell_id)) {
				scx_bpf_error("failed to refresh LLC draining for cell_id %d",
					      cell_id);
				return -EINVAL;
			}
		}
	}

	/* Phase 3: Apply cell-to-cgroup assignments for owner cgroups */
	if (config->num_cell_assignments > MAX_CELLS)
		return -EINVAL;

	bpf_for(i, 0, MAX_CELLS)
	{
		struct cell_assignment *assignment;

		if (i >= config->num_cell_assignments)
			break;

		assignment = &config->assignments[i];

		u64 cgid = assignment->cgid;
		cell_id = assignment->cell_id;

		if (cell_id >= MAX_CELLS)
			return -EINVAL;

		struct cgroup *cg __free(cgroup) = bpf_cgroup_from_id(cgid);
		if (!cg)
			/*
			 * The cgroup may have been deleted between when
			 * userspace populated the config and now. Skip it;
			 * userspace will discover the deletion via inotify
			 * and remove it from the next config.
			 */
			continue;

		cgc = lookup_cgrp_ctx(cg);
		if (!cgc)
			return -ENOENT;

		cell = &cells[cell_id];

		cell->in_use = 1;
		cell->owner_cgid = cgid;

		cgc->cell = cell_id;
		cgc->cell_owner = true;
	}

	/*
	 * Phase 4: Walk the cgroup hierarchy to propagate cell assignments
	 * to children. Non-owner cgroups inherit their parent's cell.
	 */
	scoped_guard(rcu)
	{
		if (!root_cgrp) {
			scx_bpf_error("root_cgrp should not be null");
			return -EINVAL;
		}

		struct cgroup *root_cgrp_ref __free(cgroup) = bpf_cgroup_acquire(root_cgrp);
		if (!root_cgrp_ref) {
			scx_bpf_error("Failed to acquire reference to root_cgrp");
			return -EINVAL;
		}
		root_css = &root_cgrp_ref->self;

		/* Initialize level_cells[0] to cell 0 (root cell) */
		level_cells[0] = 0;

		/*
		 * Walk all cgroups in pre-order traversal. For each cgroup:
		 * - If it's a cell owner, record its cell in level_cells
		 * - If not, inherit the parent's cell from level_cells[level-1]
		 */
		bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
			cur_cgrp = pos->cgroup;

			/*
			 * Look up cgrp_ctx for this cgroup. For dying cgroups
			 * or those without storage, this may fail - that's OK
			 * since they can't have tasks anyway.
			 */
			struct cgrp_ctx *cgrp_ctx;
			cgrp_ctx = lookup_cgrp_ctx_fallible(cur_cgrp);
			if (!cgrp_ctx)
				continue;

			u32 level = cur_cgrp->level;
			if (level >= MAX_CG_DEPTH) {
				scx_bpf_error("Cgroup hierarchy too deep: %d", level);
				return -EINVAL;
			}

			if (cgrp_ctx->cell_owner) {
				/*
				 * Check if this cell is still in use and owned
				 * by this cgroup. If not, this cgroup was a
				 * former owner but is no longer in the new
				 * config (or the cell ID was reused for a
				 * different cgroup). Clear cell_owner and
				 * inherit from parent.
				 */
				cell = &cells[cgrp_ctx->cell];
				if (cell->in_use && cell->owner_cgid == cur_cgrp->kn->id) {
					/* Cell owner with active cell - record in level_cells */
					level_cells[level] = cgrp_ctx->cell;
					continue;
				}
				/* Former owner, cell no longer in use - clear flag and fall through */
				cgrp_ctx->cell_owner = false;
			}

			/* Not a cell owner (or was, but cell no longer active) - inherit from parent */
			u32 parent_cell;
			if (level > 0)
				parent_cell = level_cells[level - 1];
			else
				parent_cell = 0;

			WRITE_ONCE(cgrp_ctx->cell, parent_cell);
			level_cells[level] = parent_cell;
		}
	}

	/* Phase 5: Bump configuration sequence to make changes visible */
	__atomic_add_fetch(&applied_configuration_seq, 1, __ATOMIC_RELEASE);

	return 0;
}

// clang-format off
/*
 * The only source of idle state in the cid form. Keep the per-shard idle and
 * idle_smt masks in sync. Pickers claim bits with claim_idle_cid_masks().
 */
void BPF_STRUCT_OPS(mitosis_update_idle, s32 cid, bool idle)
{
	struct mitosis_topo __arena *t;
	struct scx_cmask __arena *im, *ism;
	s32 core;

	MITOSIS_TOUCH_ARENA();

	t = topo;
	im = &idle_masks[t->cid[cid].shard_idx].cmask;
	if (idle)
		cmask_set(cid, im);
	else
		cmask_clear(cid, im);

	if (!t->smt_active)
		return;

	core = t->cid[cid].core_idx;
	if (core < 0)
		return;

	ism = &idle_smt_masks[t->cid[cid].shard_idx].cmask;

	/*
	 * Mirror the builtin idle core tracking, racy but self-correcting: the
	 * core range is set only when every sibling is idle and cleared on any
	 * busy transition.
	 */
	if (idle) {
		if (!cmask_full_range(im, t->core_cids[core].base, t->core_cids[core].nr))
			return;
		cmask_set_range(ism, t->core_cids[core].base, t->core_cids[core].nr);
	} else {
		cmask_clear_range(ism, t->core_cids[core].base, t->core_cids[core].nr);
	}
}

SCX_OPS_CID_DEFINE(mitosis,
	       /*
		* Placement refresh is enqueue-driven: without ENQ_LAST the core
		* keeps a solo task running with no enqueue, so it never notices
		* a configuration change. dispatch() extends the slice of a solo
		* task whose placement remains valid, so the enqueue only fires
		* when the task must leave the cpu.
		*/
	       .flags			= SCX_OPS_ENQ_LAST,
	       .select_cid		= (void *)mitosis_select_cid,
	       .enqueue			= (void *)mitosis_enqueue,
	       .dispatch		= (void *)mitosis_dispatch,
	       .running			= (void *)mitosis_running,
	       .stopping		= (void *)mitosis_stopping,
	       .set_cmask		= (void *)mitosis_set_cmask,
	       .update_idle		= (void *)mitosis_update_idle,
	       .init_task		= (void *)mitosis_init_task,
	       .exit_task		= (void *)mitosis_exit_task,
	       .cpuctl_init		= (void *)mitosis_cpuctl_init,
	       .cpuctl_exit		= (void *)mitosis_cpuctl_exit,
	       .cpuctl_move		= (void *)mitosis_cpuctl_move,
	       .dump 			= (void *)mitosis_dump,
	       .dump_task		= (void *)mitosis_dump_task,
	       .init			= (void *)mitosis_init,
	       .exit			= (void *)mitosis_exit,
	       .name			= "mitosis");
// clang-format on
