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
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#endif

char _license[] SEC("license") = "GPL";

/*
 * Variables populated by userspace
 */
const volatile u32 nr_possible_cpus = 1;
const volatile bool smt_enabled = true;
const volatile unsigned char all_cpus[MAX_CPUS_U8];

const volatile u64 slice_ns;

/*
 * CPU assignment changes aren't fully in effect until a subsequent tick()
 * configuration_seq is bumped on each assignment change
 * applied_configuration_seq is bumped when the effect is fully applied
 */
u32 configuration_seq;
u32 applied_configuration_seq;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;

UEI_DEFINE(uei);

static inline struct cgroup *lookup_cgrp_ancestor(struct cgroup *cgrp,
						  u32 ancestor)
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
} cgrp_ctxs SEC(".maps");

static inline struct cgrp_ctx *lookup_cgrp_ctx(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0, 0))) {
		scx_bpf_error("cgrp_ctx lookup failed for cgid %llu",
			      cgrp->kn->id);
		return NULL;
	}

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
	/* cell assignment */
	u32 cell;
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
} task_ctxs SEC(".maps");

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
} cpu_ctxs SEC(".maps");

static inline struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cctx;
	u32 zero = 0;

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

struct cell cells[MAX_CELLS];

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

		if (__sync_bool_compare_and_swap(&c->in_use, 0, 1))
			return cell_idx;
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

	c->in_use = 0;
	return 0;
}

/*
 * Store the cpumask for each cell (owned by BPF logic). We need this in an
 * explicit map to allow for these to be kptrs.
 */
struct cell_cpumask_wrapper {
	struct bpf_cpumask __kptr *cpumask;
	/* To avoid allocation on the reconfiguration path, have a second cpumask we
	   can just do an xchg on. */
	struct bpf_cpumask __kptr *tmp_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell_cpumask_wrapper);
	__uint(max_entries, MAX_CELLS);
	__uint(map_flags, 0);
} cell_cpumasks SEC(".maps");

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
 * This is an RCU-like implementation to keep track of scheduling events so we
 * can establish when cell assignments have propagated completely.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} percpu_critical_sections SEC(".maps");

/* Same implementation for enter/exit */
static __always_inline int critical_section()
{
	u32 zero = 0;
	u32 *data;

	if (!(data = bpf_map_lookup_elem(&percpu_critical_sections, &zero))) {
		scx_bpf_error("no percpu_critical_sections");
		return -1;
	}

	/*
	 * Bump the counter, the LSB indicates we are in a critical section and the
	 * rest of the bits keep track of how many critical sections.
	 */
	WRITE_ONCE(*data, *data + 1);
	return 0;
}

#define critical_section_enter() critical_section()
#define critical_section_exit() critical_section()

u32 critical_section_state[MAX_CPUS];
/*
 * Write side will record the current state and then poll to check that the
 * generation has advanced (somewhat like call_rcu)
 */
static __always_inline __maybe_unused int critical_section_record()
{
	u32 zero = 0;
	u32 *data;
	int nr_cpus = nr_possible_cpus;
	if (nr_cpus > MAX_CPUS)
		nr_cpus = MAX_CPUS;

	for (int i = 0; i < nr_cpus; ++i) {
		if (!(data = bpf_map_lookup_percpu_elem(
			      &percpu_critical_sections, &zero, i))) {
			scx_bpf_error("no percpu_critical_sections");
			return -1;
		}

		critical_section_state[i] = READ_ONCE(*data);
	}
	return 0;
}

static __always_inline __maybe_unused int critical_section_poll()
{
	u32 zero = 0;
	u32 *data;

	int nr_cpus = nr_possible_cpus;
	if (nr_cpus > MAX_CPUS)
		nr_cpus = MAX_CPUS;

	for (int i = 0; i < nr_cpus; ++i) {
		/* If not in a critical section at the time of record, then it passes */
		if (!(critical_section_state[i] & 1))
			continue;

		if (!(data = bpf_map_lookup_percpu_elem(
			      &percpu_critical_sections, &zero, i))) {
			scx_bpf_error("no percpu_critical_sections");
			return -1;
		}

		if (READ_ONCE(*data) == critical_section_state[i])
			return 1;
	}

	return 0;
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
				      struct task_ctx *tctx)
{
	const struct cpumask *cell_cpumask;

	if (!(cell_cpumask = lookup_cell_cpumask(tctx->cell)))
		return -ENOENT;

	if (!tctx->cpumask)
		return -EINVAL;

	bpf_cpumask_and(tctx->cpumask, cell_cpumask, p->cpus_ptr);

	if (cell_cpumask)
		tctx->all_cell_cpus_allowed =
			bpf_cpumask_subset(cell_cpumask, p->cpus_ptr);

	return 0;
}

/*
 * Figure out the task's cell and store the corresponding cpumask in the
 * task_ctx.
*/
static inline int update_task_cell(struct task_struct *p, struct task_ctx *tctx,
				   struct cgroup *cg)
{
	struct cell *cell;
	struct cgrp_ctx *cgc;

	if (!(cgc = lookup_cgrp_ctx(cg)))
		return -ENOENT;

	/*
	 * This ordering is pretty important, we read applied_configuration_seq
	 * before reading everything else expecting that the updater will update
	 * everything and then bump applied_configuration_seq last. This ensures
	 * that we cannot miss an update.
	 */
	tctx->configuration_seq = READ_ONCE(applied_configuration_seq);
	barrier();
	tctx->cell = cgc->cell;

	if (!(cell = lookup_cell(tctx->cell)))
		return -ENOENT;
	/*
	 * XXX - To be correct, we'd need to calculate the vtime
	 * delta in the previous cell, scale it by the load
	 * fraction difference and then offset from the new
	 * cell's vtime_now. For now, just do the simple thing
	 * and assume the offset to be zero.
	 *
	 * Revisit if high frequency dynamic cell switching
	 * needs to be supported.
	 */
	p->scx.dsq_vtime = cell->vtime_now;

	return update_task_cpumask(p, tctx);
}

/* Helper function for picking an idle cpu out of a candidate set */
static s32 pick_idle_cpu_from(struct task_struct *p,
			      const struct cpumask *cand_cpumask, s32 prev_cpu,
			      const struct cpumask *idle_smtmask)
{
	bool prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, cand_cpumask);
	s32 cpu;

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
					      struct task_ctx *tctx)
{
	struct cgroup *cgrp;
	if (tctx->configuration_seq != READ_ONCE(applied_configuration_seq)) {
		if (!(cgrp = task_cgroup(p)))
			return -1;
		if (update_task_cell(p, tctx, cgrp)) {
			bpf_cgroup_release(cgrp);
			return -1;
		}
		bpf_cgroup_release(cgrp);
	}
	return 0;
}

static __always_inline s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
					 struct cpu_ctx *cctx,
					 struct task_ctx *tctx)
{
	struct cpumask *task_cpumask;
	const struct cpumask *idle_smtmask;
	s32 cpu;

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
	s32 cpu;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return prev_cpu;

	/*
	 * This is a lightweight (RCU-like) critical section covering from when we
	 * refresh cell information to when we enqueue onto the task's assigned
	 * cell's DSQ. This allows us to publish new cell assignments and establish
	 * a point at which all future enqueues will be on the new assignments.
	 */
	critical_section_enter();
	if (maybe_refresh_cell(p, tctx) < 0) {
		cpu = prev_cpu;
		goto out;
	}

	if ((cpu = pick_idle_cpu(p, prev_cpu, cctx, tctx)) >= 0) {
		cstat_inc(CSTAT_LOCAL, tctx->cell, cctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		goto out;
	}

	if (tctx->cpumask && bpf_cpumask_empty(cast_mask(tctx->cpumask))) {
		/*
		 * This is an affinity violation (no overlap between task cpus and cell
		 * cpus) but we also failed to find an idle cpu in the task cpus. No
		 * need to count this as an AFFN_VIOL (we've already done so in
		 * pick_idle_cpu), just distribute it to some core.
		 */
		cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
		goto out;
	}

	if (!tctx->cpumask) {
		scx_bpf_error("tctx->cpumask should never be NULL");
		cpu = prev_cpu;
		goto out;
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

out:
	critical_section_exit();
	return cpu;
}

static __always_inline bool pick_idle_cpu_and_kick(struct task_struct *p,
						   s32 task_cpu,
						   struct cpu_ctx *cctx,
						   struct task_ctx *tctx)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, task_cpu, cctx, tctx);

	if (cpu >= 0) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return true;
	} else {
		return false;
	}
}

void BPF_STRUCT_OPS(mitosis_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	/*
	 * This is a lightweight (RCU-like) critical section covering from when we
	 * refresh cell information to when we enqueue onto the task's assigned
	 * cell's DSQ. This allows us to publish new cell assignments and establish
	 * a point at which all future enqueues will be on the new assignments.
	 */
	critical_section_enter();
	if (maybe_refresh_cell(p, tctx) < 0)
		goto out;

	if (!(cell = lookup_cell(tctx->cell)))
		goto out;

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (time_before(vtime, cell->vtime_now - slice_ns))
		vtime = cell->vtime_now - slice_ns;

	if (p->flags & PF_KTHREAD && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, HI_FALLBACK_DSQ, slice_ns, 0);
		cstat_inc(CSTAT_HI_FALLBACK_Q, tctx->cell, cctx);
	} else if (!tctx->all_cell_cpus_allowed) {
		scx_bpf_dsq_insert(p, LO_FALLBACK_DSQ, slice_ns, 0);
		cstat_inc(CSTAT_LO_FALLBACK_Q, tctx->cell, cctx);
	} else {
		scx_bpf_dsq_insert_vtime(p, tctx->cell, slice_ns, vtime,
					 enq_flags);
		cstat_inc(CSTAT_DEFAULT_Q, tctx->cell, cctx);
	}

	/*
	 * If we aren't in the wakeup path, layered_select_cpu() hasn't run and thus
	 * we haven't looked for and kicked an idle CPU. Let's do it now.
	 */
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		pick_idle_cpu_and_kick(p, task_cpu, cctx, tctx);
out:
	critical_section_exit();
}

void BPF_STRUCT_OPS(mitosis_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx;
	u32 cell;

	if (!(cctx = lookup_cpu_ctx(-1)))
		return;

	cell = READ_ONCE(cctx->cell);

	if (scx_bpf_dsq_move_to_local(HI_FALLBACK_DSQ))
		return;

	if (scx_bpf_dsq_move_to_local(cell))
		return;

	scx_bpf_dsq_move_to_local(LO_FALLBACK_DSQ);
}

/*
 * On tick, we apply CPU assignment
*/
void BPF_STRUCT_OPS(mitosis_tick, struct task_struct *p_run)
{
	if (bpf_get_smp_processor_id())
		return;

	u32 local_configuration_seq = READ_ONCE(configuration_seq);
	if (local_configuration_seq == READ_ONCE(applied_configuration_seq))
		return;

	// Get the root cell (cell 0) and its cpumask
	struct cell_cpumask_wrapper *root_cell_cpumaskw;
	int zero = 0;
	if (!(root_cell_cpumaskw =
		      bpf_map_lookup_elem(&cell_cpumasks, &zero))) {
		scx_bpf_error("Failed to find root cell cpumask");
		return;
	}

	struct bpf_cpumask *root_bpf_cpumask;
	root_bpf_cpumask =
		bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask, NULL);
	if (!root_bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should never be null");
		return;
	}
	if (!root_cell_cpumaskw->cpumask) {
		scx_bpf_error("root cpumasks should never be null");
		goto out;
	}

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		goto out;
	}
	bpf_cpumask_copy(root_bpf_cpumask, (const struct cpumask *)all_cpumask);

	// Iterate through the rest of the cells and (if in_use), clear their cpus
	// from the root cell and assign them to the correct core
	// TODO: Handle freed cells by giving their cores back to the root cell
	int cell_idx;
	bpf_for(cell_idx, 1, MAX_CELLS)
	{
		struct cell *cell;
		if (!(cell = lookup_cell(cell_idx)))
			goto out;

		if (!cell->in_use)
			continue;

		int cpu_idx;
		const struct cpumask *cpumask;
		struct cpu_ctx *cctx;
		bpf_for(cpu_idx, 0, nr_possible_cpus)
		{
			if (!(cpumask = lookup_cell_cpumask(cell_idx)))
				goto out;
			if (bpf_cpumask_test_cpu(cpu_idx, cpumask)) {
				bpf_cpumask_clear_cpu(cpu_idx,
						      root_bpf_cpumask);
				if (!(cctx = lookup_cpu_ctx(cpu_idx)))
					goto out;
				WRITE_ONCE(cctx->cell, cell_idx);
			}
		}
	}
	root_bpf_cpumask =
		bpf_kptr_xchg(&root_cell_cpumaskw->cpumask, root_bpf_cpumask);
	if (!root_bpf_cpumask) {
		scx_bpf_error("root cpumasks should never be null");
		return;
	}
	root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask,
					 root_bpf_cpumask);
	if (root_bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should be null");
		goto out;
	}

	barrier();
	WRITE_ONCE(applied_configuration_seq, local_configuration_seq);

	return;
out:
	bpf_cpumask_release(root_bpf_cpumask);
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cell *cell;

	if (!(tctx = lookup_task_ctx(p)) || !(cell = lookup_cell(tctx->cell)))
		return;

	if (time_before(cell->vtime_now, p->scx.dsq_vtime))
		cell->vtime_now = p->scx.dsq_vtime;

	tctx->started_running_at = scx_bpf_now();
}

void BPF_STRUCT_OPS(mitosis_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;
	u64 now, used;
	u32 cidx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	cidx = tctx->cell;
	if (!(cell = lookup_cell(cidx)))
		return;

	now = scx_bpf_now();
	used = now - tctx->started_running_at;
	tctx->started_running_at = now;
	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += used * 100 / p->scx.weight;

	if (cidx != 0 || tctx->all_cell_cpus_allowed) {
		u64 *cell_cycles = MEMBER_VPTR(cctx->cell_cycles, [cidx]);
		if (!cell_cycles) {
			scx_bpf_error("Cell index is too large: %d", cidx);
			return;
		}
		*cell_cycles += used;
	}
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

/* We don't know how big struct cpumask is at compile time, so just allocate a
   large space and check that it is big enough at runtime */
#define CPUMASK_LONG_ENTRIES (128)
#define CPUMASK_SIZE (sizeof(long) * CPUMASK_LONG_ENTRIES)

struct cpumask_entry {
	unsigned long cpumask[CPUMASK_LONG_ENTRIES];
	u64 used;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpumask_entry);
	__uint(max_entries, MAX_CPUMASK_ENTRIES);
} cgrp_init_percpu_cpumask SEC(".maps");

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
 * If we see a cgroup with a cpuset, that will define a new cell and we can
 * allocate it right here. Note, full core assignment must be synchronized so
 * that happens in tick()
*/
static inline int cgroup_init_with_cpuset(struct cgrp_ctx *cgc,
					  struct cgroup *cgrp)
{
	if (!cgrp->subsys[cpuset_cgrp_id])
		return 0;

	struct cpuset *cpuset =
		container_of(cgrp->subsys[cpuset_cgrp_id], struct cpuset, css);

	if (cpuset == NULL)
		return 0;

	struct cpumask_entry *entry = allocate_cpumask_entry();
	if (!entry)
		return -EINVAL;

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
		return -EINVAL;
	}

	if (bpf_cpumask_empty((const struct cpumask *)&entry->cpumask))
		goto free_entry;

	if (!all_cpumask) {
		scx_bpf_error("all_cpumask should not be NULL");
		return -EINVAL;
	}

	if (bpf_cpumask_subset((const struct cpumask *)all_cpumask,
			       (const struct cpumask *)&entry->cpumask))
		goto free_entry;

	int cell_idx = allocate_cell();
	if (cell_idx < 0)
		return -EBUSY;

	struct cell *cell = lookup_cell(cell_idx);
	if (!cell)
		return -ENOENT;

	struct cell_cpumask_wrapper *cell_cpumaskw;
	if (!(cell_cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &cell_idx))) {
		scx_bpf_error("Failed to find cell cpumask");
		return -ENOENT;
	}

	struct bpf_cpumask *bpf_cpumask;
	bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, NULL);
	if (!bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should never be null");
		return -ENOENT;
	}
	bpf_cpumask_copy(bpf_cpumask, (const struct cpumask *)&entry->cpumask);
	int cpu_idx;
	bpf_for(cpu_idx, 0, nr_possible_cpus)
	{
		if (bpf_cpumask_test_cpu(
			    cpu_idx, (const struct cpumask *)&entry->cpumask)) {
			struct cpu_ctx *cpu_ctx;
			if (!(cpu_ctx = lookup_cpu_ctx(cpu_idx))) {
				bpf_cpumask_release(bpf_cpumask);
				return -ENOENT;
			}
			cpu_ctx->cell = cell_idx;
		}
	}
	bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->cpumask, bpf_cpumask);
	if (!bpf_cpumask) {
		scx_bpf_error("cpumask should never be null");
		return -ENOENT;
	}

	bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, bpf_cpumask);
	if (bpf_cpumask) {
		scx_bpf_error("tmp_cpumask should be null");
		bpf_cpumask_release(bpf_cpumask);
		return -ENOENT;
	}

	cgc->cell = cell_idx;
	cgc->cell_owner = true;
	free_cpumask_entry(entry);
	barrier();
	__atomic_add_fetch(&configuration_seq, 1, __ATOMIC_RELEASE);
	return 1;
free_entry:
	free_cpumask_entry(entry);
	return 0;
}

s32 BPF_STRUCT_OPS(mitosis_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;
	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	if (cgrp->kn->id == 1) {
		cgc->cell = 0;
		return 0;
	}

	int rc = cgroup_init_with_cpuset(cgc, cgrp);
	if (rc < 0)
		return rc;
	if (rc)
		return 0;

	struct cgroup *parent_cg;
	if (!(parent_cg = lookup_cgrp_ancestor(cgrp, cgrp->level - 1)))
		return -ENOENT;

	struct cgrp_ctx *parent_cgc;
	if (!(parent_cgc = lookup_cgrp_ctx(parent_cg))) {
		bpf_cgroup_release(parent_cg);
		return -ENOENT;
	}

	bpf_cgroup_release(parent_cg);
	// Otherwise initialize to parent's cell
	cgc->cell = parent_cgc->cell;
	return 0;
}

s32 BPF_STRUCT_OPS(mitosis_cgroup_exit, struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;
	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	if (cgc->cell_owner)
		return free_cell(cgc->cell);

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
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;
	int ret;

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

	if ((ret = update_task_cell(p, tctx, args->cgroup))) {
		return ret;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mitosis_init)
{
	struct bpf_cpumask *cpumask;
	u32 i;
	s32 ret;

	ret = scx_bpf_create_dsq(HI_FALLBACK_DSQ, -1);
	if (ret < 0)
		return ret;

	ret = scx_bpf_create_dsq(LO_FALLBACK_DSQ, -1);
	if (ret < 0)
		return ret;

	// setup all_cpumask
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_for(i, 0, nr_possible_cpus)
	{
		const volatile u8 *u8_ptr;

		if ((u8_ptr = MEMBER_VPTR(all_cpus, [i / 8]))) {
			if (*u8_ptr & (1 << (i % 8))) {
				bpf_cpumask_set_cpu(i, cpumask);
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

	cells[0].in_use = true;

	return 0;
}

void BPF_STRUCT_OPS(mitosis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops mitosis = {
	.select_cpu = (void *)mitosis_select_cpu,
	.enqueue = (void *)mitosis_enqueue,
	.dispatch = (void *)mitosis_dispatch,
	.tick = (void *)mitosis_tick,
	.running = (void *)mitosis_running,
	.stopping = (void *)mitosis_stopping,
	.set_cpumask = (void *)mitosis_set_cpumask,
	.init_task = (void *)mitosis_init_task,
	.cgroup_init = (void *)mitosis_cgroup_init,
	.cgroup_exit = (void *)mitosis_cgroup_exit,
	.cgroup_move = (void *)mitosis_cgroup_move,
	.init = (void *)mitosis_init,
	.exit = (void *)mitosis_exit,
	.name = "mitosis",
};
