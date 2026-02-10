/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_mitosis is a dynamic affinity scheduler. Cgroups (and their tasks) are
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
#include "llc_aware.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Variables populated by userspace
 */
const volatile u32	     nr_possible_cpus = 1;
const volatile bool	     smt_enabled      = true;
const volatile unsigned char all_cpus[MAX_CPUS_U8];

const volatile u64	     slice_ns;
const volatile u64	     root_cgid			     = 1;
const volatile bool	     debug_events_enabled	     = false;
const volatile bool	     exiting_task_workaround_enabled = true;
const volatile bool	     cpu_controller_disabled	     = false;
const volatile bool	     reject_multicpu_pinning	     = false;
const volatile bool	     userspace_managed_cell_mode     = false;
const volatile bool	     enable_borrowing		     = false;

/*
 * Global arrays for LLC topology, populated by userspace before load.
 * Declared in llc_aware.bpf.h as extern.
 */
u32		   cpu_to_llc[MAX_CPUS];
struct llc_cpumask llc_to_cpus[MAX_LLCS];

/*
 * CPU assignment changes aren't fully in effect until a subsequent tick()
 * configuration_seq is bumped on each assignment change
 * applied_configuration_seq is bumped when the effect is fully applied
 */
u32 configuration_seq;
u32 applied_configuration_seq;

/*
 * Debug events circular buffer
 */
u32 debug_event_pos;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DEBUG_EVENTS_BUF_SIZE);
	__type(key, u32);
	__type(value, struct debug_event);
} debug_events SEC(".maps");

/* Configuration struct for apply_cell_config, populated by userspace */
struct cell_config cell_config;

struct update_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct update_timer);
} update_timer SEC(".maps") __weak;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
private(root_cgrp) struct cgroup __kptr *root_cgrp;

UEI_DEFINE(uei);

struct cell_map cells SEC(".maps");

/* Forward declaration for init_cgrp_ctx_with_ancestors (defined later) */
static int init_cgrp_ctx_with_ancestors(struct cgroup *cgrp);

/*
 * We store per-cpu values along with per-cell values. Helper functions to
 * translate.
 */

static inline struct cgroup *lookup_cgrp_ancestor(struct cgroup *cgrp,
						  u32		 ancestor)
{
	struct cgroup *cg;

	if (!(cg = bpf_cgroup_ancestor(cgrp, ancestor))) {
		scx_bpf_error("Failed to get ancestor level %d for cgid %llu",
			      ancestor, cgrp->kn->id);
		return NULL;
	}

	return cg;
}

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctxs		       SEC(".maps");

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
		scx_bpf_error("cgrp_ctx lookup failed for cgid %llu",
			      cgrp->kn->id);

	return cgc;
}

static inline struct cgroup *task_cgroup(struct task_struct *p)
{
	struct cgroup *cgrp;

	if (!cpu_controller_disabled) {
		cgrp = __COMPAT_scx_bpf_task_cgroup(p);
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

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs		       SEC(".maps");

static inline struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	if ((tctx = bpf_task_storage_get(&task_ctxs, p, 0, 0))) {
		return tctx;
	}

	scx_bpf_error("task_ctx lookup failed");
	return NULL;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctxs		      SEC(".maps");

static inline struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cctx;
	u32		zero = 0;

	if (cpu < 0)
		cctx = bpf_map_lookup_elem(&cpu_ctxs, &zero);
	else
		cctx = bpf_map_lookup_percpu_elem(&cpu_ctxs, &zero, cpu);

	if (!cctx) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cctx;
}

/*
 * Cells are allocated in the timer callback and freed in cgroup exit handlers.
 * allocate_cell and free_cell use atomic operations to handle concurrent access.
 */
static inline int allocate_cell()
{
	int cell_idx;
	bpf_for(cell_idx, 0, MAX_CELLS)
	{
		struct cell *c;
		if (!(c = lookup_cell(cell_idx)))
			return -1;

		if (__sync_bool_compare_and_swap(&c->in_use, 0, 1)) {
			zero_cell_vtimes(c);
			return cell_idx;
		}
	}
	scx_bpf_error("No available cells to allocate");
	return -1;
}

static inline int free_cell(int cell_idx)
{
	struct cell *c;

	if (cell_idx < 0 || cell_idx >= MAX_CELLS) {
		scx_bpf_error("Invalid cell %d", cell_idx);
		return -1;
	}

	if (!(c = lookup_cell(cell_idx)))
		return -1;

	WRITE_ONCE(c->in_use, 0);
	return 0;
}

/*
 * Record debug events to the circular buffer
 */
static inline void record_cgroup_init(u64 cgid)
{
	struct debug_event *event;
	u32		    pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos   = __sync_fetch_and_add(&debug_event_pos, 1);
	idx   = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp	= scx_bpf_now();
	event->event_type	= DEBUG_EVENT_CGROUP_INIT;
	event->cgroup_init.cgid = cgid;
}

static inline void record_init_task(u64 cgid, u32 pid)
{
	struct debug_event *event;
	u32		    pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos   = __sync_fetch_and_add(&debug_event_pos, 1);
	idx   = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp      = scx_bpf_now();
	event->event_type     = DEBUG_EVENT_INIT_TASK;
	event->init_task.cgid = cgid;
	event->init_task.pid  = pid;
}

static inline void record_cgroup_exit(u64 cgid)
{
	struct debug_event *event;
	u32		    pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos   = __sync_fetch_and_add(&debug_event_pos, 1);
	idx   = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp	= scx_bpf_now();
	event->event_type	= DEBUG_EVENT_CGROUP_EXIT;
	event->cgroup_exit.cgid = cgid;
}

/*
 * Store the cpumask for each cell (owned by BPF logic). We need this in an
 * explicit map to allow for these to be kptrs.
 */
struct cell_cpumask_wrapper {
	struct bpf_cpumask __kptr *cpumask;
	/*
	 * To avoid allocation on the reconfiguration path, have a second cpumask we
	 * can just do an xchg on.
	 */
	struct bpf_cpumask __kptr *tmp_cpumask;
	/* Borrowable cpumask: CPUs this cell can borrow from other cells */
	struct bpf_cpumask __kptr *borrowable_cpumask;
	struct bpf_cpumask __kptr *borrowable_tmp_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell_cpumask_wrapper);
	__uint(max_entries, MAX_CELLS);
	__uint(map_flags, 0);
} cell_cpumasks			    SEC(".maps");

static inline const struct cpumask *lookup_cell_cpumask(int idx)
{
	struct cell_cpumask_wrapper *cpumaskw;

	if (!(cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &idx))) {
		scx_bpf_error("no cell cpumask");
		return NULL;
	}

	if (!cpumaskw->cpumask) {
		scx_bpf_error("cell cpumask is NULL");
		return NULL;
	}

	return (const struct cpumask *)cpumaskw->cpumask;
}

static inline const struct cpumask *lookup_cell_borrowable_cpumask(int idx)
{
	struct cell_cpumask_wrapper *cpumaskw;

	if (!(cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &idx))) {
		scx_bpf_error("no cell cpumask wrapper for cell %d", idx);
		return NULL;
	}

	return (const struct cpumask *)cpumaskw->borrowable_cpumask;
}

/*
 * Helper functions for bumping per-cell stats
 */
static void cstat_add(enum cell_stat_idx idx, u32 cell, struct cpu_ctx *cctx,
		      s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cctx, .cstats[cell][idx])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid cell or stat idxs: %d, %d", idx, cell);
}

static void cstat_inc(enum cell_stat_idx idx, u32 cell, struct cpu_ctx *cctx)
{
	cstat_add(idx, cell, cctx, 1);
}

static inline int update_task_cpumask(struct task_struct *p,
				      struct task_ctx	 *tctx)
{
	const struct cpumask *cell_cpumask;
	struct cpu_ctx	     *cpu_ctx;
	u32		      cpu;

	if (!(cell_cpumask = lookup_cell_cpumask(tctx->cell)))
		return -ENOENT;

	if (!tctx->cpumask)
		return -EINVAL;

	bpf_cpumask_and(tctx->cpumask, cell_cpumask, p->cpus_ptr);

	if (cell_cpumask)
		tctx->all_cell_cpus_allowed =
			bpf_cpumask_subset(cell_cpumask, p->cpus_ptr);

	if (tctx->all_cell_cpus_allowed && enable_borrowing) {
		const struct cpumask *borrowable =
			lookup_cell_borrowable_cpumask(tctx->cell);
		if (!borrowable)
			return -ENOENT;
		if (!bpf_cpumask_subset(borrowable, p->cpus_ptr))
			tctx->all_cell_cpus_allowed = false;
	}

	/*
	* Single-CPU pinning is fine (even if outside this cell).
	* However, multi-CPU pinning that doesn't cover the entire
	* cell is not supported - the scheduler can't efficiently
	* handle partial affinity restrictions.
	*/
	if (tctx->cell != 0 && reject_multicpu_pinning &&
	    !tctx->all_cell_cpus_allowed &&
	    bpf_cpumask_weight(p->cpus_ptr) > 1) {
		scx_bpf_error("multi-CPU pinning within cell %d not supported",
			      tctx->cell);
		return -EINVAL;
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

	/* Per-CPU pinned path */
	if (!tctx->all_cell_cpus_allowed) {
		cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
		if (!(cpu_ctx = lookup_cpu_ctx(cpu)))
			return -ENOENT;

		tctx->dsq = get_cpu_dsq_id(cpu);
		if (dsq_is_invalid(tctx->dsq))
			return -EINVAL;

		p->scx.dsq_vtime = READ_ONCE(cpu_ctx->vtime_now);
		return 0;
	}

	/* Cell-wide path */
	/* LLC aware version */
	if (enable_llc_awareness) {
		return update_task_llc_assignment(p, tctx);
	}

	/* Non-LLC aware version */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, FAKE_FLAT_CELL_LLC);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	struct cell *cell;
	if (!(cell = lookup_cell(tctx->cell)))
		return -ENOENT;

	p->scx.dsq_vtime = READ_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now);

	return 0;
}

/*
 * Figure out the task's cell, dsq and store the corresponding cpumask in the
 * task_ctx.
 */
static inline int update_task_cell(struct task_struct *p, struct task_ctx *tctx,
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
		if (exiting_task_workaround_enabled &&
		    (p->flags & PF_EXITING)) {
			struct cgroup *rootcg = READ_ONCE(root_cgrp);
			if (!rootcg) {
				scx_bpf_error(
					"Unexpected uninitialized rootcg");
				return -ENOENT;
			}

			cgc = lookup_cgrp_ctx(rootcg);
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

	return update_task_cpumask(p, tctx);
}

/*
 * Get task's cgroup, update its cell, and release the cgroup.
 */
static __always_inline int refresh_task_cell(struct task_struct *p,
					     struct task_ctx	*tctx)
{
	struct cgroup *cgrp __free(cgroup) = task_cgroup(p);
	if (!cgrp)
		return -1;
	return update_task_cell(p, tctx, cgrp);
}

/* Helper function for picking an idle cpu out of a candidate set */
static s32 pick_idle_cpu_from(struct task_struct   *p,
			      const struct cpumask *cand_cpumask, s32 prev_cpu,
			      const struct cpumask *idle_smtmask)
{
	bool prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, cand_cpumask);
	s32  cpu;

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if (smt_enabled) {
		if (prev_in_cand &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		cpu = scx_bpf_pick_idle_cpu(cand_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
	}

	if (prev_in_cand && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	return scx_bpf_pick_idle_cpu(cand_cpumask, 0);
}

/* Check if we need to update the cell/cpumask mapping */
static __always_inline int maybe_refresh_cell(struct task_struct *p,
					      struct task_ctx	 *tctx)
{
	if (tctx->configuration_seq != READ_ONCE(applied_configuration_seq))
		return refresh_task_cell(p, tctx);

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
			return refresh_task_cell(p, tctx);
	}

	return 0;
}

static __always_inline s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
					 struct cpu_ctx	 *cctx,
					 struct task_ctx *tctx)
{
	struct cpumask *task_cpumask;

	if (!(task_cpumask = (struct cpumask *)tctx->cpumask)) {
		scx_bpf_error("Failed to get task cpumask");
		return -1;
	}

	const struct cpumask *idle_smtmask __free(idle_cpumask) =
		scx_bpf_get_idle_smtmask();
	if (!idle_smtmask) {
		scx_bpf_error("Failed to get idle smtmask");
		return -1;
	}

	/* No overlap between cell cpus and task cpus, just find some idle cpu */
	if (bpf_cpumask_empty(task_cpumask)) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		return pick_idle_cpu_from(p, p->cpus_ptr, prev_cpu,
					  idle_smtmask);
	}

	return pick_idle_cpu_from(p, task_cpumask, prev_cpu, idle_smtmask);
}

/*
 * Try to find an idle CPU for a task. First searches within the cell's
 * own CPUs, then tries borrowing from other cells if enabled.
 *
 * On success, bumps CSTAT_LOCAL or CSTAT_BORROWED as appropriate and
 * dispatches the task to SCX_DSQ_LOCAL. If @kick is true, the idle CPU
 * is also kicked.
 *
 * Returns: CPU number >= 0 on success, -1 on error, -EBUSY if no idle CPU found.
 */
static __always_inline s32 try_pick_idle_cpu(struct task_struct *p,
					     s32 prev_cpu, struct cpu_ctx *cctx,
					     struct task_ctx *tctx, bool kick)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, cctx, tctx);
	if (cpu >= 0) {
		cstat_inc(CSTAT_LOCAL, tctx->cell, cctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		if (kick)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return cpu;
	}
	if (cpu == -1)
		return -1; /* error from pick_idle_cpu, propagate */

	/* cpu == -EBUSY: no idle CPU in cell, try borrowing */
	if (enable_borrowing) {
		const struct cpumask *borrowable =
			lookup_cell_borrowable_cpumask(tctx->cell);
		if (!borrowable)
			return -1;
		const struct cpumask *idle_smtmask __free(idle_cpumask) =
			scx_bpf_get_idle_smtmask();
		if (!idle_smtmask) {
			scx_bpf_error("Failed to get idle smtmask");
			return -1;
		}
		cpu = pick_idle_cpu_from(p, borrowable, prev_cpu, idle_smtmask);
		if (cpu >= 0) {
			cstat_inc(CSTAT_BORROWED, tctx->cell, cctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
			if (kick)
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return cpu;
		}
	}

	return -EBUSY;
}

/*
 * select_cpu is where we update each task's cell assignment and then try to
 * dispatch to an idle core in the cell if possible
 */
s32 BPF_STRUCT_OPS(mitosis_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32		 cpu;
	struct cpu_ctx	*cctx;
	struct task_ctx *tctx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return prev_cpu;

	if (maybe_refresh_cell(p, tctx) < 0)
		return prev_cpu;

	if (!tctx->all_cell_cpus_allowed) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		cpu = get_cpu_from_dsq(tctx->dsq);
		if (cpu < 0)
			return prev_cpu;

		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

	if ((cpu = try_pick_idle_cpu(p, prev_cpu, cctx, tctx, false)) >= 0)
		return cpu;

	if (!tctx->cpumask) {
		scx_bpf_error("tctx->cpumask should never be NULL");
		return prev_cpu;
	}
	/*
	 * All else failed, send it to the prev cpu (if that's valid), otherwise any
	 * valid cpu.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, cast_mask(tctx->cpumask)) &&
	    tctx->cpumask)
		cpu = bpf_cpumask_any_distribute(cast_mask(tctx->cpumask));
	else
		cpu = prev_cpu;

	return cpu;
}

void BPF_STRUCT_OPS(mitosis_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx	*cctx;
	struct task_ctx *tctx;
	struct cell	*cell;
	s32		 task_cpu = scx_bpf_task_cpu(p);
	u64		 vtime;
	s32		 cpu = -1;
	u64		 basis_vtime;

	if (!(tctx = lookup_task_ctx(p)) || !(cctx = lookup_cpu_ctx(-1)))
		return;

	if (maybe_refresh_cell(p, tctx) < 0)
		return;

	/* Ensure this is done *AFTER* refreshing cell which might manipulate vtime */
	vtime = p->scx.dsq_vtime;

	if (!tctx->all_cell_cpus_allowed) {
		cpu = get_cpu_from_dsq(tctx->dsq);
		if (cpu < 0)
			return;
	} else if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		/*
		 * If we haven't selected a cpu, then we haven't looked for and kicked an
		 * idle CPU. Let's do the lookup now.
		 */
		if (!(cctx = lookup_cpu_ctx(-1)))
			return;
		cpu = try_pick_idle_cpu(p, task_cpu, cctx, tctx, true);
		if (cpu >= 0)
			return;
		if (cpu == -1)
			return;
		if (cpu == -EBUSY) {
			/*
			 * Verifier gets unhappy claiming two different pointer types for
			 * the same instruction here. This fixes it
			 */
			barrier_var(tctx);
			if (tctx->cpumask)
				cpu = bpf_cpumask_any_distribute(
					(const struct cpumask *)tctx->cpumask);
		}
	}

	if (tctx->all_cell_cpus_allowed) {
		cstat_inc(CSTAT_CELL_DSQ, tctx->cell, cctx);
		/* Task can use any CPU in its cell, so use the cell DSQ */
		if (!(cell = lookup_cell(tctx->cell)))
			return;

		if (enable_llc_awareness) {
			if (!llc_is_valid(tctx->llc)) {
				scx_bpf_error("Invalid LLC ID: %d", tctx->llc);
				return;
			}

			basis_vtime =
				READ_ONCE(cell->llcs[tctx->llc].vtime_now);
		} else {
			basis_vtime = READ_ONCE(
				cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now);
		}
	} else {
		cstat_inc(CSTAT_CPU_DSQ, tctx->cell, cctx);

		/*
		 * cctx is the local core cpu (where enqueue is running), not the core
		 * the task belongs to. Fetch the right cctx
		 */
		if (!(cctx = lookup_cpu_ctx(cpu)))
			return;
		/* Task is pinned to specific CPUs, use per-CPU DSQ */
		basis_vtime = READ_ONCE(cctx->vtime_now);
	}

	tctx->basis_vtime = basis_vtime;

	if (time_after(vtime, basis_vtime + 8192 * slice_ns)) {
		scx_bpf_error(
			"vtime too far ahead: pid=%d vtime=%llu basis=%llu diff=%llu cell=%u",
			p->pid, p->scx.dsq_vtime, basis_vtime,
			p->scx.dsq_vtime - basis_vtime, tctx->cell);
		return;
	}
	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (time_before(vtime, basis_vtime - slice_ns))
		vtime = basis_vtime - slice_ns;

	scx_bpf_dsq_insert_vtime(p, tctx->dsq.raw, slice_ns, vtime, enq_flags);

	/* Kick the CPU if needed */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(mitosis_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx;
	u32		cell;

	if (!(cctx = lookup_cpu_ctx(-1)))
		return;

	cell				  = READ_ONCE(cctx->cell);

	bool		    found	  = false;
	dsq_id_t	    min_vtime_dsq = DSQ_INVALID;
	u64		    min_vtime	  = 0;

	struct task_struct *p;

	/* Check the cell-LLC DSQ (use FAKE_FLAT_CELL_LLC when not LLC-aware) */
	u32	 llc = enable_llc_awareness ? cctx->llc : FAKE_FLAT_CELL_LLC;
	dsq_id_t cell_dsq = get_cell_llc_dsq_id(cell, llc);
	dsq_id_t cpu_dsq  = get_cpu_dsq_id(cpu);

	if (dsq_is_invalid(cell_dsq) || dsq_is_invalid(cpu_dsq)) {
		return;
	}

	/* Peek at cell-LLC DSQ head */
	p = __COMPAT_scx_bpf_dsq_peek(cell_dsq.raw);
	if (p) {
		min_vtime     = p->scx.dsq_vtime;
		min_vtime_dsq = cell_dsq;
		found	      = true;
	}

	/* Peek at CPU DSQ head, prefer if lower vtime */
	p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq.raw);
	if (p && (!found || time_before(p->scx.dsq_vtime, min_vtime))) {
		min_vtime     = p->scx.dsq_vtime;
		min_vtime_dsq = cpu_dsq;
		found	      = true;
	}

	/*
	 * If we failed to find an eligible task, try work stealing if enabled.
	 * Otherwise, scx will keep running prev if prev->scx.flags &
	 * SCX_TASK_QUEUED (we don't set SCX_OPS_ENQ_LAST), and otherwise go idle.
	 */
	if (!found) {
		/* Try work stealing if enabled */
		if (enable_llc_awareness && enable_work_stealing) {
			/* Returns: <0 error, 0 no steal, >0 stole work */
			s32 ret = try_stealing_work(cell, llc);
			if (ret < 0)
				return;
			if (ret > 0) {
				cstat_inc(CSTAT_STEAL, cell, cctx);
			}
		}
		return;
	}

	/*
	 * The move_to_local can fail if we raced with some other cpu in the cell
	 * and now the cell is empty. We have to ensure to try the cpu_dsq or else
	 * we might never wakeup.
	 */

	/* Try the winner first */
	if (scx_bpf_dsq_move_to_local(min_vtime_dsq.raw))
		return;

	/* Winner was cell DSQ but failed - try the CPU DSQ */
	if (min_vtime_dsq.raw == cell_dsq.raw)
		scx_bpf_dsq_move_to_local(cpu_dsq.raw);
}

/*
 * A couple of tricky things about checking a cgroup's cpumask:
 *
 * First, we need an RCU pointer to pass to cpumask kfuncs. The only way to get
 * this right now is to copy the cpumask to a map entry. Given that cgroup init
 * could be re-entrant we have a few per-cpu entries in a map to make this
 * doable.
 *
 * Second, cpumask can sometimes be stored as an array in-situ or as a pointer
 * and with different lengths. Some bpf_core_type_matches finagling can make
 * this all work.
 */
#define MAX_CPUMASK_ENTRIES (4)

/*
 * We don't know how big struct cpumask is at compile time, so just allocate a
 * large space and check that it is big enough at runtime.
 * CPUMASK_LONG_ENTRIES is defined in intf.h.
 */
#define CPUMASK_SIZE (sizeof(long) * CPUMASK_LONG_ENTRIES)

struct cpumask_entry {
	unsigned long cpumask[CPUMASK_LONG_ENTRIES];
	u64	      used;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpumask_entry);
	__uint(max_entries, MAX_CPUMASK_ENTRIES);
} cgrp_init_percpu_cpumask	    SEC(".maps");

static inline struct cpumask_entry *allocate_cpumask_entry()
{
	int cpumask_idx;
	bpf_for(cpumask_idx, 0, MAX_CPUMASK_ENTRIES)
	{
		struct cpumask_entry *ent = bpf_map_lookup_elem(
			&cgrp_init_percpu_cpumask, &cpumask_idx);
		if (!ent) {
			scx_bpf_error("Failed to fetch cpumask_entry");
			return NULL;
		}
		if (__sync_bool_compare_and_swap(&ent->used, 0, 1))
			return ent;
	}
	scx_bpf_error("All cpumask entries are in use");
	return NULL;
}

static inline void free_cpumask_entry(struct cpumask_entry *entry)
{
	WRITE_ONCE(entry->used, 0);
}

/* Cpumask entry — uses RAII framework from mitosis.bpf.h */
DEFINE_FREE(cpumask_entry, struct cpumask_entry *,
	    if (_T) free_cpumask_entry(_T))

/* Define types for cpumasks in-situ vs as a ptr in struct cpuset */
struct cpumask___local {};

typedef struct cpumask___local *cpumask_var_t___ptr;

struct cpuset___cpumask_ptr {
	cpumask_var_t___ptr cpus_allowed;
};

typedef struct cpumask___local cpumask_var_t___arr[1];

struct cpuset___cpumask_arr {
	cpumask_var_t___arr cpus_allowed;
};

/*
 * Given a cgroup, get its cpumask (populated in entry), returns 0 if no
 * cpumask, < 0 on error and > 0 on a populated cpumask.
 */
static inline int get_cgroup_cpumask(struct cgroup	  *cgrp,
				     struct cpumask_entry *entry)
{
	if (!cgrp->subsys[cpuset_cgrp_id])
		return 0;

	struct cpuset *cpuset =
		container_of(cgrp->subsys[cpuset_cgrp_id], struct cpuset, css);

	if (!cpuset)
		return 0;

	unsigned long runtime_cpumask_size = bpf_core_type_size(struct cpumask);
	if (runtime_cpumask_size > CPUMASK_SIZE) {
		scx_bpf_error(
			"Definition of struct cpumask is too large. Please increase CPUMASK_LONG_ENTRIES");
		return -EINVAL;
	}

	int err;
	if (bpf_core_type_matches(struct cpuset___cpumask_arr)) {
		struct cpuset___cpumask_arr *cpuset_typed =
			(void *)bpf_core_cast(cpuset, struct cpuset);
		err = bpf_core_read(&entry->cpumask, runtime_cpumask_size,
				    &cpuset_typed->cpus_allowed);
	} else if (bpf_core_type_matches(struct cpuset___cpumask_ptr)) {
		struct cpuset___cpumask_ptr *cpuset_typed =
			(void *)bpf_core_cast(cpuset, struct cpuset);
		err = bpf_core_read(&entry->cpumask, runtime_cpumask_size,
				    cpuset_typed->cpus_allowed);
	} else {
		scx_bpf_error(
			"Definition of struct cpuset did not match any expected struct");
		return -EINVAL;
	}

	if (err < 0) {
		scx_bpf_error(
			"bpf_core_read of cpuset->cpus_allowed failed for cgid %llu",
			cgrp->kn->id);
		return err;
	}

	if (bpf_cpumask_empty((const struct cpumask *)&entry->cpumask))
		return 0;

	if (!all_cpumask) {
		scx_bpf_error("all_cpumask should not be NULL");
		return -EINVAL;
	}

	if (bpf_cpumask_subset((const struct cpumask *)all_cpumask,
			       (const struct cpumask *)&entry->cpumask))
		return 0;

	return 1;
}

/*
 * This array keeps track of the cgroup ancestor's cell as we iterate over the
 * cgroup hierarchy.
 */
u32 level_cells[MAX_CG_DEPTH];

/*
 * On tick, we identify new cells and apply CPU assignment
 */
static int update_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	int ret;
	if ((ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0))) {
		scx_bpf_error("Failed to arm update timer: %d", ret);
		return 0;
	}

	u32 local_configuration_seq = READ_ONCE(configuration_seq);
	if (local_configuration_seq == READ_ONCE(applied_configuration_seq))
		return 0;

	struct cpumask_entry *entry __free(cpumask_entry) =
		allocate_cpumask_entry();
	if (!entry)
		return 0;

	/* Get the root cell (cell 0) and its cpumask */
	int			     zero = 0;
	struct cell_cpumask_wrapper *root_cell_cpumaskw;
	if (!(root_cell_cpumaskw =
		      bpf_map_lookup_elem(&cell_cpumasks, &zero))) {
		scx_bpf_error("Failed to find root cell cpumask");
		return 0;
	}

	struct bpf_cpumask *root_bpf_cpumask __free(bpf_cpumask) =
		bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask, NULL);
	if (!root_bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should never be null");
		return 0;
	}
	if (!root_cell_cpumaskw->cpumask) {
		scx_bpf_error("root cpumasks should never be null");
		return 0;
	}

	guard(rcu)();
	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return 0;
	}

	/*
	 * Initialize root cell cpumask to all cpus, and then remove from it as we
	 * go
	 */
	bpf_cpumask_copy(root_bpf_cpumask, (const struct cpumask *)all_cpumask);

	struct cgroup_subsys_state *root_css, *pos;
	struct cgroup		   *cur_cgrp;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		return 0;
	}

	struct cgrp_ctx *root_cgrp_ctx;
	if (!(root_cgrp_ctx = lookup_cgrp_ctx(root_cgrp)))
		return 0;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		return 0;
	}

	struct cgroup *root_cgrp_ref __free(cgroup) =
		bpf_cgroup_acquire(root_cgrp);
	if (!root_cgrp_ref) {
		scx_bpf_error("Failed to acquire reference to root_cgrp");
		return 0;
	}
	root_css = &root_cgrp_ref->self;

	/*
	 * Iterate over all cgroups, check if any have a cpumask and populate them
	 * as a separate cell.
	 */
	bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;

		/*
		 * We can iterate over dying cgroups, in which case this lookup will
		 * fail. These cgroups can't have tasks in them so just continue.
		 */
		struct cgrp_ctx *cgrp_ctx;
		if (!(cgrp_ctx = lookup_cgrp_ctx_fallible(cur_cgrp)))
			continue;

		int rc = get_cgroup_cpumask(cur_cgrp, entry);
		if (!rc) {
			/*
			 * TODO: If this was a cell owner that just had its cpuset removed,
			 * it should free the cell. Doing so would require draining
			 * in-flight tasks scheduled to the dsq.
			 */
			/* No cpuset, assign to parent cell and continue */
			if (cur_cgrp->kn->id != root_cgid) {
				u32 level = cur_cgrp->level;
				if (level <= 0 || level >= MAX_CG_DEPTH) {
					scx_bpf_error(
						"Cgroup hierarchy is too deep: %d",
						level);
					return 0;
				}
				/*
				 * This is a janky way of getting the parent cell, ideally we'd
				 * lookup the parent cgrp_ctx and get it that way, but some
				 * cgroup lookups don't work here because they are (erroneously)
				 * only operating on the cgroup namespace of current. Given this
				 * is a tick() it could be anything. See
				 * https://lore.kernel.org/bpf/20250811175045.1055202-1-memxor@gmail.com/
				 * for details.
				 *
				 * Instead, we just track the parent cells as we walk the cgroup
				 * hierarchy in a separate array. Because the iteration is
				 * pre-order traversal, we're guaranteed to have the current
				 * cgroup's ancestor's cells in level_cells.
				 */
				u32 parent_cell = level_cells[level - 1];
				WRITE_ONCE(cgrp_ctx->cell, parent_cell);
				level_cells[level] = parent_cell;
			}
			continue;
		} else if (rc < 0)
			return 0;

		/*
		 * cgroup has a cpumask, allocate a new cell if needed, and assign cpus
		 */
		int cell_idx = READ_ONCE(cgrp_ctx->cell);
		if (!cgrp_ctx->cell_owner) {
			cell_idx = allocate_cell();
			if (cell_idx < 0)
				return 0;
			cgrp_ctx->cell_owner = true;
		}

		struct cell_cpumask_wrapper *cell_cpumaskw;
		if (!(cell_cpumaskw =
			      bpf_map_lookup_elem(&cell_cpumasks, &cell_idx))) {
			scx_bpf_error("Failed to find cell cpumask: %d",
				      cell_idx);
			return 0;
		}

		struct bpf_cpumask *bpf_cpumask __free(bpf_cpumask) =
			bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, NULL);
		if (!bpf_cpumask) {
			scx_bpf_error("tmp_cpumask should never be null");
			return 0;
		}
		bpf_cpumask_copy(bpf_cpumask,
				 (const struct cpumask *)&entry->cpumask);
		int cpu_idx;
		bpf_for(cpu_idx, 0, nr_possible_cpus)
		{
			if (bpf_cpumask_test_cpu(
				    cpu_idx,
				    (const struct cpumask *)&entry->cpumask)) {
				struct cpu_ctx *cpu_ctx;
				if (!(cpu_ctx = lookup_cpu_ctx(cpu_idx)))
					return 0;
				cpu_ctx->cell = cell_idx;
				bpf_cpumask_clear_cpu(cpu_idx,
						      root_bpf_cpumask);
			}
		}

		/*
		 * Recalc LLC counts BEFORE making cpumask visible.
		 * Pass the new mask explicitly to avoid race
		 * if recalc did a lookup_cell_cpumask()
		 */
		if (enable_llc_awareness) {
			if (recalc_cell_llc_counts(
				    cell_idx,
				    (const struct cpumask *)bpf_cpumask))
				return 0;
		}

		bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->cpumask,
					    no_free_ptr(bpf_cpumask));
		if (!bpf_cpumask) {
			scx_bpf_error("cpumask should never be null");
			return 0;
		}

		/* bpf_cpumask now holds the old cpumask, put it back as tmp */
		struct bpf_cpumask *stale __free(bpf_cpumask) = bpf_kptr_xchg(
			&cell_cpumaskw->tmp_cpumask, no_free_ptr(bpf_cpumask));
		if (stale) {
			scx_bpf_error("tmp_cpumask should be null");
			return 0;
		}

		barrier();
		WRITE_ONCE(cgrp_ctx->cell, cell_idx);
		u32 level = cur_cgrp->level;
		if (level <= 0 || level >= MAX_CG_DEPTH) {
			scx_bpf_error("Cgroup hierarchy is too deep: %d",
				      level);
			return 0;
		}
		level_cells[level] = cell_idx;
	}

	/*
	 * assign root cell cpus that are left over
	 */
	int cpu_idx;
	bpf_for(cpu_idx, 0, nr_possible_cpus)
	{
		if (bpf_cpumask_test_cpu(cpu_idx, (const struct cpumask *)
							  root_bpf_cpumask)) {
			struct cpu_ctx *cpu_ctx;
			if (!(cpu_ctx = lookup_cpu_ctx(cpu_idx)))
				return 0;
			cpu_ctx->cell = 0;
		}
	}

	/*
	 * Recalc LLC counts for root cell BEFORE making cpumask visible.
	 * Pass the new mask explicitly to avoid race if recalc did a
	 * lookup_cell_cpumask()
	 */
	if (enable_llc_awareness)
		if (recalc_cell_llc_counts(
			    ROOT_CELL_ID,
			    (const struct cpumask *)root_bpf_cpumask))
			return 0;

	/*
	 * Publish: swap new cpumask in, get old one back.
	 * After this point, all CPUs see the new mask.
	 */
	root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->cpumask,
					 no_free_ptr(root_bpf_cpumask));
	if (!root_bpf_cpumask) {
		scx_bpf_error("root cpumask should never be null");
		return 0;
	}

	/* root_bpf_cpumask now holds the old mask, put it back as tmp */
	struct bpf_cpumask *root_stale __free(bpf_cpumask) =
		bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask,
			      no_free_ptr(root_bpf_cpumask));
	if (root_stale) {
		scx_bpf_error("root tmp_cpumask should be null");
		return 0;
	}

	barrier();
	WRITE_ONCE(applied_configuration_seq, local_configuration_seq);

	return 0;
}

void advance_dsq_vtimes(struct cell *cell, struct cpu_ctx *cctx,
			struct task_ctx *tctx, u64 task_vtime)
{
	/* If the CPU DSQ's vtime is behind the task's, advance it. */
	if (time_before(READ_ONCE(cctx->vtime_now), task_vtime))
		WRITE_ONCE(cctx->vtime_now, task_vtime);

	if (!enable_llc_awareness) {
		/* If the cell DSQ's vtime is behind the task's, advance it. */
		if (time_before(
			    READ_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now),
			    task_vtime))
			WRITE_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now,
				   task_vtime);
		return;
	}

	/* We are in the llc aware case  */
	if (llc_is_valid(tctx->llc)) {
		if (time_before(READ_ONCE(cell->llcs[tctx->llc].vtime_now),
				task_vtime))
			WRITE_ONCE(cell->llcs[tctx->llc].vtime_now, task_vtime);
	}
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct cpu_ctx	*cctx;
	struct task_ctx *tctx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	/* Handle stolen task retag (LLC-aware mode only) */
	if (enable_llc_awareness && enable_work_stealing) {
		if (maybe_retag_stolen_task(p, tctx, cctx) < 0)
			return;
	}

	tctx->started_running_at = scx_bpf_now();
}

void BPF_STRUCT_OPS(mitosis_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx	*cctx;
	struct task_ctx *tctx;
	struct cell	*cell;
	u64		 now, used;
	u32		 cidx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	/*
	 * Use CPU's cell (not task's cell) to match dispatch() logic.
	 * Prevents starvation when a task is pinned outside its cell.
	 * E.g. a cell 0 kworker pinned to a cell 1 CPU.
	 */
	cidx = cctx->cell;
	if (!(cell = lookup_cell(cidx)))
		return;

	now			 = scx_bpf_now();
	used			 = now - tctx->started_running_at;
	tctx->started_running_at = now;
	/* scale the execution time by the inverse of the weight and charge */
	if (p->scx.weight == 0) {
		scx_bpf_error("Task %d has zero weight", p->pid);
		return;
	}
	p->scx.dsq_vtime += used * 100 / p->scx.weight;

	if (tctx->cell != cidx) {
		/*
		 * Task is on a borrowed CPU from a different cell.
		 * Advance the task's (borrowing) cell's vtime_now,
		 * not the CPU's (lending) cell. Skip cctx->vtime_now
		 * since the per-CPU DSQ vtime is unrelated to the
		 * borrowed task.
		 */
		struct cell *task_cell = lookup_cell(tctx->cell);
		if (task_cell) {
			u32 llc_idx = enable_llc_awareness &&
						      llc_is_valid(tctx->llc) ?
					      tctx->llc :
					      FAKE_FLAT_CELL_LLC;
			if (time_before(
				    READ_ONCE(
					    task_cell->llcs[llc_idx].vtime_now),
				    p->scx.dsq_vtime))
				WRITE_ONCE(task_cell->llcs[llc_idx].vtime_now,
					   p->scx.dsq_vtime);
		}
	} else {
		/* Advance cell and cpu dsq vtime to keep in sync with task vtime. */
		advance_dsq_vtimes(cell, cctx, tctx, p->scx.dsq_vtime);
	}

	if (cidx != 0 || tctx->all_cell_cpus_allowed) {
		u64 *cell_cycles = MEMBER_VPTR(cctx->cell_cycles, [cidx]);
		if (!cell_cycles) {
			scx_bpf_error("Cell index is too large: %d", cidx);
			return;
		}
		*cell_cycles += used;
	}
}

SEC("fentry/cpuset_write_resmask")
int BPF_PROG(fentry_cpuset_write_resmask, struct kernfs_open_file *of,
	     char *buf, size_t nbytes, loff_t off, ssize_t retval)
{
	/*
	 * On a write to cpuset.cpus, we'll need to configure new cells, bump
	 * configuration_seq so tick() does that.
	 */
	__atomic_add_fetch(&configuration_seq, 1, __ATOMIC_RELEASE);
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
	bpf_core_read(&refcnt_ptr, sizeof(refcnt_ptr),
		      &cgrp->self.refcnt.percpu_count_ptr);
	return refcnt_ptr & __PERCPU_REF_DEAD;
}

/*
 * Cgroup initialization - creates cgrp_ctx. Root cgroup is assigned cell 0.
 * Other cgroups inherit parent's cell, and if a cpuset is configured,
 * configuration_seq is bumped so the timer assigns a dedicated cell.
 */
static int init_cgrp_ctx(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	record_cgroup_init(cgrp->kn->id);

	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	if (cgrp->kn->id == root_cgid) {
		WRITE_ONCE(cgc->cell, 0);
		return 0;
	}

	struct cpumask_entry *entry __free(cpumask_entry) =
		allocate_cpumask_entry();
	if (!entry)
		return -EINVAL;
	int rc = get_cgroup_cpumask(cgrp, entry);
	if (rc < 0)
		return rc;
	else if (rc > 0) {
		/*
		 * This cgroup has a cpuset, bump configuration_seq so tick()
		 * configures it.
		 */
		__atomic_add_fetch(&configuration_seq, 1, __ATOMIC_RELEASE);
	}

	/* Initialize to parent's cell */
	struct cgroup *parent_cg __free(cgroup) =
		lookup_cgrp_ancestor(cgrp, cgrp->level - 1);
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
		struct cgroup *ancestor __free(cgroup) =
			lookup_cgrp_ancestor(cgrp, level);
		if (!ancestor)
			return -ENOENT;

		/* Skip if dying or already initialized */
		if (!cgrp_is_dying(ancestor) &&
		    !lookup_cgrp_ctx_fallible(ancestor)) {
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
s32 BPF_STRUCT_OPS(mitosis_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	if (cpu_controller_disabled)
		return 0;
	return init_cgrp_ctx(cgrp);
}

s32 BPF_STRUCT_OPS(mitosis_cgroup_exit, struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;
	int		 ret;

	if (cpu_controller_disabled)
		return 0;

	if (userspace_managed_cell_mode)
		return 0;

	record_cgroup_exit(cgrp->kn->id);

	/*
	 * Use lookup without CREATE since this is the exit path. If the cgroup
	 * doesn't have storage, it's not a cell owner anyway.
	 */
	if (!(cgc = lookup_cgrp_ctx(cgrp))) {
		/* Errors above on failure, verifier. */
		return 0;
	}

	if (cgc->cell_owner) {
		if ((ret = free_cell(cgc->cell)))
			return ret;
		/*
		 * Need to make sure the cpus of this cell are freed back to the root
		 * cell and the root cell cpumask can be expanded. Bump
		 * configuration_seq so tick() does that.
		 */
		__atomic_add_fetch(&configuration_seq, 1, __ATOMIC_RELEASE);
	}

	return 0;
}

void BPF_STRUCT_OPS(mitosis_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx;

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
	struct cgrp_ctx *cgc;

	if (!cpu_controller_disabled)
		return 0;

	if (userspace_managed_cell_mode)
		return 0;

	/*
	 * Use fallible lookup since this tracepoint fires for ALL cgroups,
	 * including ones created after scheduler attach that never had tasks.
	 * If the cgroup doesn't have storage, it's not a cell owner anyway.
	 */
	if (!(cgc = lookup_cgrp_ctx_fallible(cgrp)))
		return 0;

	record_cgroup_exit(cgrp->kn->id);

	if (cgc->cell_owner) {
		int ret;
		if ((ret = free_cell(cgc->cell)))
			scx_bpf_error("Failed to free cell %d: %d", cgc->cell,
				      ret);
		/*
		 * Need to make sure the cpus of this cell are freed back to the root
		 * cell and the root cell cpumask can be expanded. Bump
		 * configuration_seq so tick() does that.
		 */
		__atomic_add_fetch(&configuration_seq, 1, __ATOMIC_RELEASE);
	}

	return 0;
}

void BPF_STRUCT_OPS(mitosis_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return;
	}

	update_task_cpumask(p, tctx);
}

s32 validate_flags()
{
	/* Need valid llc */
	if (enable_llc_awareness && (nr_llc < 1 || nr_llc > MAX_LLCS)) {
		scx_bpf_error(
			"LLC-aware mode requires nr_llc between 1 and %d inclusive, got %d",
			MAX_LLCS, nr_llc);
		return -EINVAL;
	}

	/* Work stealing only makes sense when enable_llc_awareness. */
	if (enable_work_stealing && (!enable_llc_awareness)) {
		scx_bpf_error(
			"Work stealing requires LLC-aware mode to be enabled");
		return -EINVAL;
	}

	return 0;
}

s32 validate_userspace_data()
{
	if (nr_possible_cpus > MAX_CPUS) {
		scx_bpf_error("nr_possible_cpus %d exceeds MAX_CPUS %d",
			      nr_possible_cpus, MAX_CPUS);
		return -EINVAL;
	}
	return 0;
}

static int init_task_impl(struct task_struct *p, struct cgroup *cgrp)
{
	struct task_ctx	   *tctx;
	struct bpf_cpumask *cpumask;

	record_init_task(cgrp->kn->id, p->pid);

	tctx = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(&tctx->cpumask, cpumask);
	if (cpumask) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		scx_bpf_error("tctx cpumask is unexpectedly populated on init");
		return -EINVAL;
	}

	if (!all_cpumask) {
		scx_bpf_error("missing all_cpumask");
		return -EINVAL;
	}

	/* Initialize LLC assignment fields */
	if (enable_llc_awareness)
		init_task_llc(tctx);

	return update_task_cell(p, tctx, cgrp);
}

s32 BPF_STRUCT_OPS(mitosis_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	/*
	 * When CPU controller is disabled, args->cgroup is root, so we need
	 * to get the task's actual cgroup for both logging and cell assignment.
	 * We also need to ensure the cgroup hierarchy is initialized since
	 * SCX cgroup callbacks won't fire.
	 */
	if (cpu_controller_disabled) {
		struct cgroup *cgrp __free(cgroup) = task_cgroup(p);
		if (!cgrp)
			return -ENOENT;

		/* Ensure cgroup hierarchy is initialized (handles ancestors + this cgroup) */
		int ret = init_cgrp_ctx_with_ancestors(cgrp);
		if (ret)
			return ret;

		return init_task_impl(p, cgrp);
	}

	return init_task_impl(p, args->cgroup);
}

__hidden void dump_cpumask_word(s32 word, const struct cpumask *cpumask)
{
	u32 u, v = 0;

	bpf_for(u, 0, 32)
	{
		s32 cpu = 32 * word + u;
		if (cpu < nr_possible_cpus &&
		    bpf_cpumask_test_cpu(cpu, cpumask))
			v |= 1 << u;
	}
	scx_bpf_dump("%08x", v);
}

static void dump_cpumask(const struct cpumask *cpumask)
{
	u32 word, nr_words = (nr_possible_cpus + 31) / 32;

	bpf_for(word, 0, nr_words)
	{
		if (word)
			scx_bpf_dump(",");
		dump_cpumask_word(nr_words - word - 1, cpumask);
	}
}

static void dump_cell_cpumask(int id)
{
	const struct cpumask *cell_cpumask;

	if (!(cell_cpumask = lookup_cell_cpumask(id)))
		return;

	dump_cpumask(cell_cpumask);
}

void BPF_STRUCT_OPS(mitosis_dump, struct scx_dump_ctx *dctx)
{
	dsq_id_t	dsq_id;
	int		i;
	struct cell    *cell;
	struct cpu_ctx *cpu_ctx;

	scx_bpf_dump_header();

	bpf_for(i, 0, MAX_CELLS)
	{
		if (!(cell = lookup_cell(i)))
			return;

		if (!cell->in_use)
			continue;

		scx_bpf_dump("CELL[%d] CPUS=", i);
		dump_cell_cpumask(i);
		scx_bpf_dump("\n");
		/* Per-LLC stats deferred: FAKE_FLAT_CELL_LLC used for now */
		dsq_id_t dsq_id = get_cell_llc_dsq_id(i, FAKE_FLAT_CELL_LLC);
		if (dsq_is_invalid(dsq_id))
			return;

		scx_bpf_dump(
			"CELL[%d] vtime=%llu nr_queued=%d\n", i,
			READ_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now),
			scx_bpf_dsq_nr_queued(dsq_id.raw));
	}

	bpf_for(i, 0, nr_possible_cpus)
	{
		if (!(cpu_ctx = lookup_cpu_ctx(i)))
			return;

		dsq_id = get_cpu_dsq_id(i);
		if (dsq_is_invalid(dsq_id))
			return;
		scx_bpf_dump("CPU[%d] cell=%d vtime=%llu nr_queued=%d\n", i,
			     cpu_ctx->cell, READ_ONCE(cpu_ctx->vtime_now),
			     scx_bpf_dsq_nr_queued(dsq_id.raw));
	}

	if (!debug_events_enabled)
		return;

	/* Dump debug events */
	scx_bpf_dump("\n");
	scx_bpf_dump("DEBUG EVENTS (last %d):\n", DEBUG_EVENTS_BUF_SIZE);

	u32 total_events = READ_ONCE(debug_event_pos);
	u32 start_idx	 = total_events > DEBUG_EVENTS_BUF_SIZE ?
				   total_events - DEBUG_EVENTS_BUF_SIZE :
				   0;

	bpf_for(i, 0, DEBUG_EVENTS_BUF_SIZE)
	{
		u32 event_num = start_idx + i;
		if (event_num >= total_events)
			break;

		u32		    idx = event_num % DEBUG_EVENTS_BUF_SIZE;
		struct debug_event *event =
			bpf_map_lookup_elem(&debug_events, &idx);
		if (!event)
			continue;

		switch (event->event_type) {
		case DEBUG_EVENT_CGROUP_INIT:
			scx_bpf_dump("[%3d] CGROUP_INIT cgid=%llu ts=%llu\n",
				     event_num, event->cgroup_init.cgid,
				     event->timestamp);
			break;
		case DEBUG_EVENT_INIT_TASK:
			scx_bpf_dump(
				"[%3d] INIT_TASK   cgid=%llu pid=%u ts=%llu\n",
				event_num, event->init_task.cgid,
				event->init_task.pid, event->timestamp);
			break;
		case DEBUG_EVENT_CGROUP_EXIT:
			scx_bpf_dump("[%3d] CGROUP_EXIT cgid=%llu ts=%llu\n",
				     event_num, event->cgroup_exit.cgid,
				     event->timestamp);
			break;
		default:
			scx_bpf_dump("[%3d] UNKNOWN     type=%u ts=%llu\n",
				     event_num, event->event_type,
				     event->timestamp);
			break;
		}
	}
}

void BPF_STRUCT_OPS(mitosis_dump_task, struct scx_dump_ctx *dctx,
		    struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	scx_bpf_dump(
		"Task[%d] vtime=%llu basis_vtime=%llu cell=%u dsq=%llx all_cell_cpus_allowed=%d\n",
		p->pid, p->scx.dsq_vtime, tctx->basis_vtime, tctx->cell,
		tctx->dsq.raw, tctx->all_cell_cpus_allowed);
	scx_bpf_dump("Task[%d] CPUS=", p->pid);
	dump_cpumask(p->cpus_ptr);
	scx_bpf_dump("\n");
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mitosis_init)
{
	struct bpf_cpumask *cpumask;
	u32		    i;
	s32		    ret;

	u32		    key = 0;

	/* Sanity check the flags we get from userspace. */
	if ((ret = validate_flags()))
		return ret;

	/* Check data from userspace. */
	if ((ret = validate_userspace_data()))
		return ret;

	struct cgroup *rootcg __free(cgroup) = bpf_cgroup_from_id(root_cgid);
	if (!rootcg)
		return -ENOENT;

	/* initialize cgrp storage for rootcg so that it is always available in the timer */
	if (!bpf_cgrp_storage_get(&cgrp_ctxs, rootcg, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE)) {
		scx_bpf_error("cgrp_ctx creation failed for rootcg");
		return -ENOENT;
	}

	struct cgroup *old __free(cgroup) =
		bpf_kptr_xchg(&root_cgrp, no_free_ptr(rootcg));

	/* setup all_cpumask - must be done before cgroup iteration */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_for(i, 0, nr_possible_cpus)
	{
		const volatile u8 *u8_ptr;

		if ((u8_ptr = MEMBER_VPTR(all_cpus, [i / 8]))) {
			if (*u8_ptr & (1 << (i % 8))) {
				bpf_cpumask_set_cpu(i, cpumask);
				dsq_id_t dsq_id = get_cpu_dsq_id(i);
				if (dsq_is_invalid(dsq_id)) {
					bpf_cpumask_release(cpumask);
					scx_bpf_error(
						"Invalid dsq_id for cpu %d, dsq_id: %llx",
						i, dsq_id.raw);
					return -EINVAL;
				}
				ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
				if (ret < 0) {
					bpf_cpumask_release(cpumask);
					scx_bpf_error(
						"Failed to create dsq for cpu %d, dsq_id: %llx, ret: %d",
						i, dsq_id.raw, ret);
					return ret;
				}
			}
		} else {
			return -EINVAL;
		}

		/* Store the LLC that each cpu belongs to. Used in Dispatch. */
		struct cpu_ctx *cpu_ctx = lookup_cpu_ctx(i);
		if (!cpu_ctx) {
			bpf_cpumask_release(cpumask);
			return -EINVAL;
		}

		if (enable_llc_awareness) {
			if (i < MAX_CPUS) // explicit bounds check for verifier
				cpu_ctx->llc = cpu_to_llc[i];
		} else {
			cpu_ctx->llc = FAKE_FLAT_CELL_LLC;
		}
	}

	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

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
			scx_bpf_error(
				"Failed to acquire root cgroup for initialization");
			return -ENOENT;
		}

		struct cgroup_subsys_state *root_css = &iter_root->self;
		struct cgroup_subsys_state *pos;

		scoped_guard(rcu)
		{
			bpf_for_each(css, pos, root_css,
				     BPF_CGROUP_ITER_DESCENDANTS_PRE) {
				/*
				 * pos->cgroup dereference loses RCU tracking in verifier,
				 * so we can't use it directly with bpf_cgroup_acquire or
				 * pass it to functions that call bpf_cgroup_ancestor.
				 * Instead, read the cgroup ID and use bpf_cgroup_from_id
				 * to get a trusted, acquired reference.
				 */
				u64		    cgid = pos->cgroup->kn->id;
				struct cgroup *cgrp __free(cgroup) =
					bpf_cgroup_from_id(cgid);
				if (cgrp)
					init_cgrp_ctx(cgrp);
			}
		}
	}

	bpf_for(i, 0, MAX_CELLS)
	{
		struct cell_cpumask_wrapper *cpumaskw;

		if (enable_llc_awareness) {
			u32 llc;
			bpf_for(llc, 0, nr_llc)
			{
				dsq_id_t dsq_id = get_cell_llc_dsq_id(i, llc);
				if (dsq_is_invalid(dsq_id))
					return -EINVAL; // scx_bpf_error called in get_cell_llc_dsq_id

				ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
				if (ret < 0)
					return ret;
			}
		} else {
			dsq_id_t dsq_id =
				get_cell_llc_dsq_id(i, FAKE_FLAT_CELL_LLC);
			if (dsq_is_invalid(dsq_id))
				return -EINVAL; // scx_bpf_error called in get_cell_llc_dsq_id

			ret = scx_bpf_create_dsq(dsq_id.raw, ANY_NUMA);
			if (ret < 0)
				return ret;
		}

		if (!(cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &i)))
			return -ENOENT;

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;

		/*
		 * Start with full cpumask for all cells. The timer will set up
		 * the correct cpumasks based on cgroup configuration.
		 */
		bpf_cpumask_setall(cpumask);

		cpumask = bpf_kptr_xchg(&cpumaskw->cpumask, cpumask);
		if (cpumask) {
			/* Should be impossible, we just initialized the cell cpumask */
			bpf_cpumask_release(cpumask);
			return -EINVAL;
		}

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;
		cpumask = bpf_kptr_xchg(&cpumaskw->tmp_cpumask, cpumask);
		if (cpumask) {
			/* Should be impossible, we just initialized the cell tmp_cpumask */
			bpf_cpumask_release(cpumask);
			return -EINVAL;
		}

		if (enable_borrowing) {
			cpumask = bpf_cpumask_create();
			if (!cpumask)
				return -ENOMEM;

			/* Start with empty borrowable masks */
			cpumask = bpf_kptr_xchg(&cpumaskw->borrowable_cpumask,
						cpumask);
			if (cpumask) {
				bpf_cpumask_release(cpumask);
				return -EINVAL;
			}

			cpumask = bpf_cpumask_create();
			if (!cpumask)
				return -ENOMEM;
			cpumask = bpf_kptr_xchg(
				&cpumaskw->borrowable_tmp_cpumask, cpumask);
			if (cpumask) {
				bpf_cpumask_release(cpumask);
				return -EINVAL;
			}
		}
	}

	if (enable_llc_awareness) {
		{
			guard(rcu)();
			if (recalc_cell_llc_counts(ROOT_CELL_ID, NULL))
				return -EINVAL;
		}
	}

	{
		struct cell *cell = lookup_cell(0);
		if (!cell)
			return -ENOENT;

		cell->in_use = true;
	}

	/*
	 * Only start the update timer if not in userspace managed cell mode.
	 * In userspace managed mode, configuration is applied via apply_cell_config.
	 */
	if (!userspace_managed_cell_mode) {
		struct bpf_timer *timer =
			bpf_map_lookup_elem(&update_timer, &key);
		if (!timer) {
			scx_bpf_error("Failed to lookup update timer");
			return -ESRCH;
		}
		bpf_timer_init(timer, &update_timer, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, update_timer_cb);
		if ((ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0))) {
			scx_bpf_error("Failed to arm update timer");
			return ret;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(mitosis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Apply a complete cell configuration.
 *
 * Configuration data is read from the cell_config global struct,
 * which is populated by userspace before invoking this program.
 *
 * The function operates in five phases:
 * 1. Mark all cells (except cell 0) as not in use
 * 2. Apply cell assignments for owner cgroups
 * 3. Walk cgroup hierarchy to propagate cells to children
 * 4. Apply cell cpumasks and CPU-to-cell mappings
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
	struct cgrp_ctx		    *cgc;
	struct cell		    *cell;
	struct cpu_ctx		    *cctx;
	struct cell_cpumask_wrapper *cpumaskw;
	struct cgroup_subsys_state  *root_css, *pos;
	struct cgroup		    *cur_cgrp;
	u32			     i, cell_id;

	/* Read configuration from global struct (populated by userspace) */
	struct cell_config *config = &cell_config;

	/*
	 * Phase 1: Mark all cells (except cell 0) as not in use.
	 * This handles cell destruction - cells not in the new config
	 * will remain marked as not in use.
	 */
	bpf_for(i, 1, MAX_CELLS)
	{
		cell = lookup_cell(i);
		if (!cell)
			return -EINVAL;

		WRITE_ONCE(cell->in_use, 0);
		cell->owner_cgid = 0;
	}

	/*
	 * Phase 2: Apply cell cpumasks and derive CPU-to-cell mappings.
	 * For each cell, we update the cell's cpumask and set each CPU's
	 * cell assignment based on which cell's cpumask contains it.
	 *
	 * This is done before cgroup assignments so that any task
	 * initialized mid-operation that reads a new cell ID will find
	 * correct cpumasks already in place.
	 */
	if (config->num_cells > MAX_CELLS)
		return -EINVAL;

	bpf_for(cell_id, 0, MAX_CELLS)
	{
		struct cell_cpumask_data *cpumask_data;

		if (cell_id >= config->num_cells)
			break;

		cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &cell_id);
		if (!cpumaskw)
			continue;

		cpumask_data = MEMBER_VPTR(config->cpumasks, [cell_id]);
		if (!cpumask_data) {
			scx_bpf_error("cell_id %d out of bounds", cell_id);
			return -EINVAL;
		}

		/* Get the tmp_cpumask to build the new mask */
		struct bpf_cpumask *new_cpumask __free(bpf_cpumask) =
			bpf_kptr_xchg(&cpumaskw->tmp_cpumask, NULL);
		if (!new_cpumask) {
			scx_bpf_error("tmp_cpumask is NULL for cell %d",
				      cell_id);
			return -EINVAL;
		}

		/* Clear the cpumask and set bits based on the config data */
		bpf_cpumask_clear(new_cpumask);

		/* Set cpumask bits and CPU-to-cell mappings */
		u32 cpu;
		bpf_for(cpu, 0, nr_possible_cpus)
		{
			u32		     byte_idx = cpu / 8;
			u32		     bit_idx  = cpu % 8;

			const unsigned char *bytep =
				MEMBER_VPTR(cpumask_data->mask, [byte_idx]);
			if (!bytep) {
				scx_bpf_error("byte_idx %d out of bounds",
					      byte_idx);
				return -EINVAL;
			}

			if (*bytep & (1 << bit_idx)) {
				bpf_cpumask_set_cpu(cpu, new_cpumask);
				cctx = bpf_map_lookup_percpu_elem(
					&cpu_ctxs, &(u32){ 0 }, cpu);
				if (!cctx)
					return -ENOENT;
				cctx->cell = cell_id;
			}
		}

		/* Swap the new cpumask into place */
		new_cpumask = bpf_kptr_xchg(&cpumaskw->cpumask,
					    no_free_ptr(new_cpumask));
		if (!new_cpumask) {
			scx_bpf_error("cpumask should never be null");
			return -EINVAL;
		}

		/* Put the old cpumask into tmp_cpumask for reuse */
		struct bpf_cpumask *stale __free(bpf_cpumask) = bpf_kptr_xchg(
			&cpumaskw->tmp_cpumask, no_free_ptr(new_cpumask));
		if (stale) {
			scx_bpf_error("tmp_cpumask should be null");
			return -EINVAL;
		}

		/* Apply borrowable cpumask for this cell */
		if (enable_borrowing) {
			struct cell_cpumask_data *borrowable_data;

			borrowable_data = MEMBER_VPTR(
				config->borrowable_cpumasks, [cell_id]);
			if (!borrowable_data) {
				scx_bpf_error(
					"cell_id %d out of bounds for borrowable",
					cell_id);
				return -EINVAL;
			}

			struct bpf_cpumask *bmask __free(bpf_cpumask) =
				bpf_kptr_xchg(&cpumaskw->borrowable_tmp_cpumask,
					      NULL);
			if (!bmask) {
				scx_bpf_error(
					"borrowable_tmp_cpumask is NULL for cell %d",
					cell_id);
				return -EINVAL;
			}

			bpf_cpumask_clear(bmask);

			u32 bcpu;
			bpf_for(bcpu, 0, nr_possible_cpus)
			{
				u32		     byte_idx = bcpu / 8;
				u32		     bit_idx  = bcpu % 8;

				const unsigned char *bytep    = MEMBER_VPTR(
					   borrowable_data->mask, [byte_idx]);
				if (!bytep) {
					scx_bpf_error(
						"byte_idx %d out of bounds",
						byte_idx);
					return -EINVAL;
				}

				if (*bytep & (1 << bit_idx))
					bpf_cpumask_set_cpu(bcpu, bmask);
			}

			bmask = bpf_kptr_xchg(&cpumaskw->borrowable_cpumask,
					      no_free_ptr(bmask));
			if (!bmask) {
				scx_bpf_error(
					"borrowable cpumask should never be null");
				return -EINVAL;
			}

			struct bpf_cpumask *bstale __free(bpf_cpumask) =
				bpf_kptr_xchg(&cpumaskw->borrowable_tmp_cpumask,
					      no_free_ptr(bmask));
			if (bstale) {
				scx_bpf_error(
					"borrowable tmp_cpumask should be null");
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

		u64 cgid   = assignment->cgid;
		cell_id	   = assignment->cell_id;

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

		cell = lookup_cell(cell_id);
		if (!cell)
			return -EINVAL;

		cell->in_use	 = 1;
		cell->owner_cgid = cgid;

		cgc->cell	 = cell_id;
		cgc->cell_owner	 = true;
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

		struct cgroup *root_cgrp_ref __free(cgroup) =
			bpf_cgroup_acquire(root_cgrp);
		if (!root_cgrp_ref) {
			scx_bpf_error(
				"Failed to acquire reference to root_cgrp");
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
		bpf_for_each(css, pos, root_css,
			     BPF_CGROUP_ITER_DESCENDANTS_PRE) {
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
				scx_bpf_error("Cgroup hierarchy too deep: %d",
					      level);
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
				cell = lookup_cell(cgrp_ctx->cell);
				if (!cell)
					return -EINVAL;
				if (cell->in_use &&
				    cell->owner_cgid == cur_cgrp->kn->id) {
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
SCX_OPS_DEFINE(mitosis,
	       .select_cpu		= (void *)mitosis_select_cpu,
	       .enqueue			= (void *)mitosis_enqueue,
	       .dispatch		= (void *)mitosis_dispatch,
	       .running			= (void *)mitosis_running,
	       .stopping		= (void *)mitosis_stopping,
	       .set_cpumask		= (void *)mitosis_set_cpumask,
	       .init_task		= (void *)mitosis_init_task,
	       .cgroup_init		= (void *)mitosis_cgroup_init,
	       .cgroup_exit		= (void *)mitosis_cgroup_exit,
	       .cgroup_move		= (void *)mitosis_cgroup_move,
	       .dump 			= (void *)mitosis_dump,
	       .dump_task		= (void *)mitosis_dump_task,
	       .init			= (void *)mitosis_init,
	       .exit			= (void *)mitosis_exit,
	       .name			= "mitosis");
// clang-format on
