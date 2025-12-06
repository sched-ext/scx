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
 * Each cell has an associated DSQ which it uses for vtime scheduling of the
 * cgroups belonging to the cell.
 */

#include "intf.h"

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

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
const volatile bool	     split_vtime_updates	     = false;

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

/*
 * We store per-cpu values along with per-cell values. Helper functions to
 * translate.
 */
static inline u32 cpu_dsq(u32 cpu)
{
	return PCPU_BASE | cpu;
}

static inline u32 cell_dsq(u32 cell)
{
	return cell;
}

static inline u32 dsq_to_cpu(u32 dsq)
{
	return dsq & ~PCPU_BASE;
}

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
	struct cgroup *cgrp = __COMPAT_scx_bpf_task_cgroup(p);
	if (!cgrp) {
		scx_bpf_error("Failed to get cgroup for task %d", p->pid);
	}
	return cgrp;
}

/*
 * task_ctx is the per-task information kept by scx_mitosis
 */
struct task_ctx {
	/* cpumask is the set of valid cpus this task can schedule on */
	/* (tasks cpumask anded with its cell cpumask) */
	struct bpf_cpumask __kptr *cpumask;
	/* started_running_at for recording runtime */
	u64 started_running_at;
	u64 basis_vtime;
	/* For the sake of monitoring, each task is owned by a cell */
	u32 cell;
	/* For the sake of scheduling, a task is exclusively owned by either a cell
	 * or a cpu */
	u32 dsq;
	/* latest configuration that was applied for this task */
	/* (to know if it has to be re-applied) */
	u32 configuration_seq;
	/* Is this task allowed on all cores of its cell? */
	bool all_cell_cpus_allowed;
};

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

struct cell		   cells[MAX_CELLS];

static inline struct cell *lookup_cell(int idx)
{
	struct cell *cell;

	cell = MEMBER_VPTR(cells, [idx]);
	if (!cell) {
		scx_bpf_error("Invalid cell %d", idx);
		return NULL;
	}
	return cell;
}

/*
 * Cells are allocated concurrently in some cases (e.g. cgroup_init).
 * allocate_cell and free_cell enable these allocations to be done safely
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
			WRITE_ONCE(c->vtime_now, 0);
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

	return (const struct cpumask *)cpumaskw->cpumask;
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
	struct cell	     *cell;
	u32		      cpu;

	if (!(cell_cpumask = lookup_cell_cpumask(tctx->cell)))
		return -ENOENT;

	if (!tctx->cpumask)
		return -EINVAL;

	bpf_cpumask_and(tctx->cpumask, cell_cpumask, p->cpus_ptr);

	if (cell_cpumask)
		tctx->all_cell_cpus_allowed =
			bpf_cpumask_subset(cell_cpumask, p->cpus_ptr);

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
	if (tctx->all_cell_cpus_allowed) {
		tctx->dsq = cell_dsq(tctx->cell);
		if (!(cell = lookup_cell(tctx->cell)))
			return -ENOENT;
		p->scx.dsq_vtime = READ_ONCE(cell->vtime_now);
	} else {
		cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
		if (!(cpu_ctx = lookup_cpu_ctx(cpu)))
			return -ENOENT;
		tctx->dsq	 = cpu_dsq(cpu);
		p->scx.dsq_vtime = READ_ONCE(cpu_ctx->vtime_now);
	}

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
				"cgrp_ctx lookup failed for cgid %llu (task %d, flags 0x%x)",
				cg->kn->id, p->pid, p->flags);
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

	return update_task_cpumask(p, tctx);
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
	struct cgroup *cgrp;
	int	       ret = 0;
	if (tctx->configuration_seq != READ_ONCE(applied_configuration_seq)) {
		if (!(cgrp = task_cgroup(p)))
			return -1;
		if (update_task_cell(p, tctx, cgrp))
			ret = -1;
		bpf_cgroup_release(cgrp);
	}
	return ret;
}

static __always_inline s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
					 struct cpu_ctx	 *cctx,
					 struct task_ctx *tctx)
{
	struct cpumask	     *task_cpumask;
	const struct cpumask *idle_smtmask;
	s32		      cpu;

	if (!(task_cpumask = (struct cpumask *)tctx->cpumask) ||
	    !(idle_smtmask = scx_bpf_get_idle_smtmask())) {
		scx_bpf_error("Failed to get task cpumask or idle smtmask");
		return -1;
	}

	/* No overlap between cell cpus and task cpus, just find some idle cpu */
	if (bpf_cpumask_empty(task_cpumask)) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		cpu = pick_idle_cpu_from(p, p->cpus_ptr, prev_cpu,
					 idle_smtmask);
		goto out;
	}

	cpu = pick_idle_cpu_from(p, task_cpumask, prev_cpu, idle_smtmask);
out:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;
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
		cpu = dsq_to_cpu(tctx->dsq);
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

	if ((cpu = pick_idle_cpu(p, prev_cpu, cctx, tctx)) >= 0) {
		cstat_inc(CSTAT_LOCAL, tctx->cell, cctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

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
		cpu = dsq_to_cpu(tctx->dsq);
	} else if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		/*
		 * If we haven't selected a cpu, then we haven't looked for and kicked an
		 * idle CPU. Let's do the lookup now and kick at the end.
		 */
		if (!(cctx = lookup_cpu_ctx(-1)))
			return;
		cpu = pick_idle_cpu(p, task_cpu, cctx, tctx);
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
		basis_vtime = READ_ONCE(cell->vtime_now);
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

	scx_bpf_dsq_insert_vtime(p, tctx->dsq, slice_ns, vtime, enq_flags);

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

	cell			  = READ_ONCE(cctx->cell);

	bool		    found = false;
	u64		    min_vtime_dsq;
	u64		    min_vtime;

	struct task_struct *p;
	bpf_for_each(scx_dsq, p, cell, 0) {
		min_vtime     = p->scx.dsq_vtime;
		min_vtime_dsq = cell;
		found	      = true;
		break;
	}

	u64 dsq = cpu_dsq(cpu);
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (!found || time_before(p->scx.dsq_vtime, min_vtime)) {
			min_vtime     = p->scx.dsq_vtime;
			min_vtime_dsq = dsq;
			found	      = true;
		}
		break;
	}

	/*
	 * If we failed to find an eligible task, scx will keep running prev if
	 * prev->scx.flags & SCX_TASK_QUEUED (we don't set SCX_OPS_ENQ_LAST), and
	 * otherwise go idle.
	 */
	if (!found)
		return;
	/*
	 * The move_to_local can fail if we raced with some other cpu in the cell
	 * and now the cell is empty. We have to ensure to try the cpu_dsq or else
	 * we might never wakeup.
	 */

	if (!scx_bpf_dsq_move_to_local(min_vtime_dsq) && min_vtime_dsq != dsq)
		scx_bpf_dsq_move_to_local(dsq);
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
 * large space and check that it is big enough at runtime
 */
#define CPUMASK_LONG_ENTRIES (128)
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

/* For use by cleanup attribute */
static inline void __free_cpumask_entry(struct cpumask_entry **entry)
{
	if (entry)
		if (*entry)
			free_cpumask_entry(*entry);
}

#define DECLARE_CPUMASK_ENTRY(var) \
	struct cpumask_entry *var __attribute__((cleanup(__free_cpumask_entry)))

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

	DECLARE_CPUMASK_ENTRY(entry) = allocate_cpumask_entry();
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

	struct bpf_cpumask *root_bpf_cpumask;
	root_bpf_cpumask =
		bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask, NULL);
	if (!root_bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should never be null");
		return 0;
	}
	if (!root_cell_cpumaskw->cpumask) {
		scx_bpf_error("root cpumasks should never be null");
		goto out;
	}

	bpf_rcu_read_lock();
	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		goto out_rcu_unlock;
	}

	/*
	 * Initialize root cell cpumask to all cpus, and then remove from it as we
	 * go
	 */
	bpf_cpumask_copy(root_bpf_cpumask, (const struct cpumask *)all_cpumask);

	struct cgroup_subsys_state *root_css, *pos;
	struct cgroup		   *cur_cgrp, *root_cgrp_ref;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		goto out_rcu_unlock;
	}

	struct cgrp_ctx *root_cgrp_ctx;
	if (!(root_cgrp_ctx = lookup_cgrp_ctx(root_cgrp)))
		goto out_rcu_unlock;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		goto out_rcu_unlock;
	}

	if (!(root_cgrp_ref = bpf_cgroup_acquire(root_cgrp))) {
		scx_bpf_error("Failed to acquire reference to root_cgrp");
		goto out_rcu_unlock;
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
					goto out_root_cgrp;
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
			goto out_root_cgrp;

		/*
		 * cgroup has a cpumask, allocate a new cell if needed, and assign cpus
		 */
		int cell_idx = READ_ONCE(cgrp_ctx->cell);
		if (!cgrp_ctx->cell_owner) {
			cell_idx = allocate_cell();
			if (cell_idx < 0)
				goto out_root_cgrp;
			cgrp_ctx->cell_owner = true;
		}

		struct cell_cpumask_wrapper *cell_cpumaskw;
		if (!(cell_cpumaskw =
			      bpf_map_lookup_elem(&cell_cpumasks, &cell_idx))) {
			scx_bpf_error("Failed to find cell cpumask: %d",
				      cell_idx);
			goto out_root_cgrp;
		}

		struct bpf_cpumask *bpf_cpumask;
		bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, NULL);
		if (!bpf_cpumask) {
			scx_bpf_error("tmp_cpumask should never be null");
			goto out_root_cgrp;
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
				if (!(cpu_ctx = lookup_cpu_ctx(cpu_idx))) {
					bpf_cpumask_release(bpf_cpumask);
					goto out_root_cgrp;
				}
				cpu_ctx->cell = cell_idx;
				bpf_cpumask_clear_cpu(cpu_idx,
						      root_bpf_cpumask);
			}
		}
		bpf_cpumask =
			bpf_kptr_xchg(&cell_cpumaskw->cpumask, bpf_cpumask);
		if (!bpf_cpumask) {
			scx_bpf_error("cpumask should never be null");
			goto out_root_cgrp;
		}

		bpf_cpumask =
			bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, bpf_cpumask);
		if (bpf_cpumask) {
			scx_bpf_error("tmp_cpumask should be null");
			bpf_cpumask_release(bpf_cpumask);
			goto out_root_cgrp;
		}

		barrier();
		WRITE_ONCE(cgrp_ctx->cell, cell_idx);
		u32 level = cur_cgrp->level;
		if (level <= 0 || level >= MAX_CG_DEPTH) {
			scx_bpf_error("Cgroup hierarchy is too deep: %d",
				      level);
			goto out_root_cgrp;
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
				goto out_root_cgrp;
			cpu_ctx->cell = 0;
		}
	}

	root_bpf_cpumask =
		bpf_kptr_xchg(&root_cell_cpumaskw->cpumask, root_bpf_cpumask);
	if (!root_bpf_cpumask) {
		scx_bpf_error("root cpumask should never be null");
		bpf_rcu_read_unlock();
		bpf_cgroup_release(root_cgrp_ref);
		return 0;
	}

	root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask,
					 root_bpf_cpumask);
	if (root_bpf_cpumask) {
		scx_bpf_error("root tmp_cpumask should be null");
		goto out_root_cgrp;
	}

	barrier();
	WRITE_ONCE(applied_configuration_seq, local_configuration_seq);

	bpf_rcu_read_unlock();
	bpf_cgroup_release(root_cgrp_ref);
	return 0;
out_root_cgrp:
	bpf_cgroup_release(root_cgrp_ref);
out_rcu_unlock:
	bpf_rcu_read_unlock();
out:
	bpf_cpumask_release(root_bpf_cpumask);
	return 0;
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct cpu_ctx	*cctx;
	struct task_ctx *tctx;
	struct cell	*cell;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	/*
	 * Legacy approach: Update vtime_now before task runs.
	 * Only used when split vtime updates is enabled.
	 */
	if (split_vtime_updates) {
		if (!(cctx = lookup_cpu_ctx(-1)) ||
		    !(cell = lookup_cell(cctx->cell)))
			return;

		if (time_before(READ_ONCE(cell->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cell->vtime_now, p->scx.dsq_vtime);

		if (time_before(READ_ONCE(cctx->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cctx->vtime_now, p->scx.dsq_vtime);
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

	/*
	 * Default approach: Update cell and cpu dsq vtime after updating task's vtime
	 * to keep them in sync and prevent "vtime too far ahead" errors.
	 */
	if (!split_vtime_updates) {
		if (time_before(READ_ONCE(cell->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cell->vtime_now, p->scx.dsq_vtime);

		if (time_before(READ_ONCE(cctx->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cctx->vtime_now, p->scx.dsq_vtime);
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

s32 BPF_STRUCT_OPS(mitosis_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
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

	DECLARE_CPUMASK_ENTRY(entry) = allocate_cpumask_entry();
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
	struct cgroup *parent_cg;
	if (!(parent_cg = lookup_cgrp_ancestor(cgrp, cgrp->level - 1)))
		return -ENOENT;

	struct cgrp_ctx *parent_cgc;
	if (!(parent_cgc = lookup_cgrp_ctx(parent_cg))) {
		bpf_cgroup_release(parent_cg);
		return -ENOENT;
	}

	bpf_cgroup_release(parent_cg);
	cgc->cell = parent_cgc->cell;
	return 0;
}

s32 BPF_STRUCT_OPS(mitosis_cgroup_exit, struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;
	int		 ret;

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

	if (!(tctx = lookup_task_ctx(p)))
		return;

	update_task_cell(p, tctx, to);
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

s32 BPF_STRUCT_OPS(mitosis_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx	   *tctx;
	struct bpf_cpumask *cpumask;

	record_init_task(args->cgroup->kn->id, p->pid);

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

	return update_task_cell(p, tctx, args->cgroup);
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
	u64		dsq_id;
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
		scx_bpf_dump("CELL[%d] vtime=%llu nr_queued=%d\n", i,
			     READ_ONCE(cell->vtime_now),
			     scx_bpf_dsq_nr_queued(i));
	}

	bpf_for(i, 0, nr_possible_cpus)
	{
		if (!(cpu_ctx = lookup_cpu_ctx(i)))
			return;

		dsq_id = cpu_dsq(i);
		scx_bpf_dump("CPU[%d] cell=%d vtime=%llu nr_queued=%d\n", i,
			     cpu_ctx->cell, READ_ONCE(cpu_ctx->vtime_now),
			     scx_bpf_dsq_nr_queued(dsq_id));
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
		"Task[%d] vtime=%llu basis_vtime=%llu cell=%u dsq=%x all_cell_cpus_allowed=%d\n",
		p->pid, p->scx.dsq_vtime, tctx->basis_vtime, tctx->cell,
		tctx->dsq, tctx->all_cell_cpus_allowed);
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

	struct cgroup	   *rootcg;
	if (!(rootcg = bpf_cgroup_from_id(root_cgid)))
		return -ENOENT;

	/* initialize cgrp storage for rootcg so that it is always available in the timer */
	if (!bpf_cgrp_storage_get(&cgrp_ctxs, rootcg, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE)) {
		scx_bpf_error("cgrp_ctx creation failed for rootcg");
		bpf_cgroup_release(rootcg);
		return -ENOENT;
	}

	rootcg = bpf_kptr_xchg(&root_cgrp, rootcg);
	if (rootcg)
		bpf_cgroup_release(rootcg);

	/* setup all_cpumask */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_for(i, 0, nr_possible_cpus)
	{
		const volatile u8 *u8_ptr;

		if ((u8_ptr = MEMBER_VPTR(all_cpus, [i / 8]))) {
			if (*u8_ptr & (1 << (i % 8))) {
				bpf_cpumask_set_cpu(i, cpumask);
				ret = scx_bpf_create_dsq(cpu_dsq(i), -1);
				if (ret < 0) {
					bpf_cpumask_release(cpumask);
					return ret;
				}
			}
		} else {
			return -EINVAL;
		}
	}

	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	bpf_for(i, 0, MAX_CELLS)
	{
		struct cell_cpumask_wrapper *cpumaskw;

		ret = scx_bpf_create_dsq(i, -1);
		if (ret < 0)
			return ret;

		if (!(cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &i)))
			return -ENOENT;

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;

		/*
		 * Start with all full cpumask for all cells. They'll get setup in
		 * cgroup_init
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
	}

	cells[0].in_use		= true;
	struct bpf_timer *timer = bpf_map_lookup_elem(&update_timer, &key);
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
	return 0;
}

void BPF_STRUCT_OPS(mitosis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
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
