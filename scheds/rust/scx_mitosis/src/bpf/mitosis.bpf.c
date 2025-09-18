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

// TODO: fix debug printer.
#include "intf.h"

#include "mitosis.bpf.h"
#include "dsq.bpf.h"
#include "l3_aware.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Variables populated by userspace
 */
const volatile u32 nr_possible_cpus = 1;
const volatile bool smt_enabled = true;
const volatile unsigned char all_cpus[MAX_CPUS_U8];

const volatile u64 slice_ns;
const volatile u64 root_cgid = 1;

const volatile u32 nr_l3 = 1;
/*
 * CPU assignment changes aren't fully in effect until a subsequent tick()
 * configuration_seq is bumped on each assignment change
 * applied_configuration_seq is bumped when the effect is fully applied
 */
u32 configuration_seq;
u32 applied_configuration_seq;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
private(root_cgrp) struct cgroup __kptr *root_cgrp;

UEI_DEFINE(uei);

/*
 * Maps used for L3-aware scheduling
*/
struct cpu_to_l3_map cpu_to_l3 SEC(".maps");
struct l3_to_cpus_map l3_to_cpus SEC(".maps");

/*
 * Maps for statistics
*/
struct function_counters_map function_counters SEC(".maps");
struct steal_stats_map steal_stats SEC(".maps");

static inline void increment_counter(enum fn_counter_idx idx) {
	u64 *counter;
	u32 key = idx;

	counter = bpf_map_lookup_elem(&function_counters, &key);
	if (counter)
		(*counter)++;
}

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

		if (__sync_bool_compare_and_swap(&c->in_use, 0, 1)) {
			// TODO XXX, I think we need to make this concurrent safe
			__builtin_memset(c->l3_cpu_cnt, 0, sizeof(c->l3_cpu_cnt));
			c->l3_present_cnt = 0;
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
	struct cpu_ctx *cpu_ctx;
	u32 cpu;

	if (!(cell_cpumask = lookup_cell_cpumask(tctx->cell)))
		return -ENOENT;

	if (!tctx->cpumask)
		return -EINVAL;

	/*
	 * Calculate the intersection of CPUs that are both:
	 * 1. In this task's assigned cell (cell_cpumask)
	 * 2. Allowed by the task's CPU affinity (p->cpus_ptr)
	 * Store result in tctx->cpumask - this becomes the effective CPU set
	 * where this task can actually run.
	 */
	bpf_cpumask_and(tctx->cpumask, cell_cpumask, p->cpus_ptr);

	/*
	 * Check if the task can run on ALL CPUs in its assigned cell.
	 * If cell_cpumask is a subset of p->cpus_ptr, it means the task's
	 * CPU affinity doesn't restrict it within the cell - it can use
	 * any CPU in the cell. This affects scheduling decisions later.
	 * True if all the bits in cell_cpumask are set in p->cpus_ptr.
	 */
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

	// We want to set the task vtime to that of the cell it's joining.
	if (tctx->all_cell_cpus_allowed) {

		const struct cpumask *l3_mask = NULL;
		if (tctx->l3 != L3_INVALID) {
			l3_mask = lookup_l3_cpumask((u32)tctx->l3);
			/* If the L3 no longer intersects the cell's cpumask, invalidate it */
			if (!l3_mask || !bpf_cpumask_intersects(cell_cpumask, l3_mask))
				tctx->l3 = L3_INVALID;
		}

		/* --- Pick a new L3 if needed --- */
		if (tctx->l3 == L3_INVALID) {
			s32 new_l3 = pick_l3_for_task(tctx->cell);
			if (new_l3 < 0)
				return -ENODEV;
			tctx->l3 = new_l3;
			l3_mask = lookup_l3_cpumask((u32)tctx->l3);
			if (!l3_mask)
				return -ENOENT;
		}

		/* --- Narrow the effective cpumask by the chosen L3 --- */
		/* tctx->cpumask already contains (task_affinity ∧ cell_mask) */
		if (tctx->cpumask)
			bpf_cpumask_and(tctx->cpumask, (const struct cpumask *)tctx->cpumask, l3_mask);

		/* If empty after intersection, nothing can run here */
		if (tctx->cpumask && bpf_cpumask_empty((const struct cpumask *)tctx->cpumask))
			return -ENODEV;

		/* --- Point to the correct (cell,L3) DSQ and set vtime baseline --- */
		tctx->dsq = get_cell_l3_dsq_id(tctx->cell, tctx->l3);

		struct cell *cell = lookup_cell(tctx->cell);
		if (!cell)
			return -ENOENT;

		if (!l3_is_valid(tctx->l3))
			return -EINVAL;

		p->scx.dsq_vtime = READ_ONCE(cell->l3_vtime_now[tctx->l3]);
	} else {
		/* Task is CPU-restricted, use task mask */
		cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
		if (!(cpu_ctx = lookup_cpu_ctx(cpu)))
			return -ENOENT;
		tctx->dsq = get_cpu_dsq_id(cpu);
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
	int ret = 0;
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

	increment_counter(COUNTER_SELECT_CPU);

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return prev_cpu;

	if (maybe_refresh_cell(p, tctx) < 0)
		return prev_cpu;

	/* Pinned path: only if our task really requires a per-CPU queue. */
	if (!tctx->all_cell_cpus_allowed) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);
		cpu = get_cpu_from_dsq(tctx->dsq);
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

	// Grab an idle core
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
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;
	s32 cpu = -1;
	u64 basis_vtime;

	increment_counter(COUNTER_ENQUEUE);

	if (!(tctx = lookup_task_ctx(p)) || !(cctx = lookup_cpu_ctx(-1)))
		return;

	if (maybe_refresh_cell(p, tctx) < 0)
		return;

	// Cpu pinned work
	if (!tctx->all_cell_cpus_allowed) {
		cpu = get_cpu_from_dsq(tctx->dsq);
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
		// This is a task that can run on any cpu in the cell

		cstat_inc(CSTAT_CELL_DSQ, tctx->cell, cctx);

		/* Task can use any CPU in its cell, set basis_vtime from per-(cell, L3) vtime */
		if (!(cell = lookup_cell(tctx->cell)))
			return;

		if (!l3_is_valid(tctx->l3)) {
			scx_bpf_error("Invalid L3 ID for task %d in enqueue", p->pid);
			return;
		}
		basis_vtime = READ_ONCE(cell->l3_vtime_now[tctx->l3]);

	} else {
		// This is a task that can only run on a specific cpu
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

	if (time_after(vtime,
		       basis_vtime + VTIME_MAX_FUTURE_MULTIPLIER * slice_ns)) {
		scx_bpf_error("vtime is too far in the future for %d", p->pid);
		return;
	}
	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	// TODO: Should this be time_before64?
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
	u32 cell;

	increment_counter(COUNTER_DISPATCH);

	if (!(cctx = lookup_cpu_ctx(-1)))
		return;

	cell = READ_ONCE(cctx->cell);

	/* Start from a valid DSQ */
	u64 local_dsq = get_cpu_dsq_id(cpu);

	bool found = false;
	u64 min_vtime_dsq = local_dsq;
	u64 min_vtime = ~0ULL; /* U64_MAX */
	struct task_struct *p;

	// Get L3
	u32 cpu_key = (u32)cpu;
	u32 *l3_ptr = bpf_map_lookup_elem(&cpu_to_l3, &cpu_key);
	s32 l3 = l3_ptr ? (s32)*l3_ptr : L3_INVALID;

	/* Check the L3 queue */
	if (l3 != L3_INVALID) {
		u64 cell_l3_dsq = get_cell_l3_dsq_id(cell, l3);
		bpf_for_each(scx_dsq, p, cell_l3_dsq, 0) {
			min_vtime = p->scx.dsq_vtime;
			min_vtime_dsq = cell_l3_dsq;
			found = true;
			break;
		}
	}

	/* Check the CPU DSQ for a lower vtime */
	bpf_for_each(scx_dsq, p, local_dsq, 0) {
		if (!found || time_before(p->scx.dsq_vtime, min_vtime)) {
			min_vtime = p->scx.dsq_vtime;
			min_vtime_dsq = local_dsq;
			found = true;
		}
		break;
	}

	/*
	* The move_to_local can fail if we raced with some other cpu in the cell
	* and now the cell is empty. We have to ensure to try the cpu_dsq or else
	* we might never wakeup.
	*/


	if (found) {
		// We found a task in the local or cell-L3 DSQ

		// If it was in the per cpu DSQ, there is no competation, grab it and return
		if (min_vtime_dsq == local_dsq) {
			scx_bpf_dsq_move_to_local(min_vtime_dsq);
			return;
		}

		// If it was in the cell L3 DSQ, we are competing with other cpus in the cell-l3
		// try to move it to the local DSQ
		if (scx_bpf_dsq_move_to_local(min_vtime_dsq)) {
			// We won the race and got the task, return
			return;
		}
	}

#if MITOSIS_ENABLE_STEALING
	// We didn't find a task in either DSQ, or lost the race.
	// Instead of going straight to idle, attempt to steal a task from another
	// L3 in the cell.

	// Try stealing. If successful, this moves the task to the local runqueue
	try_stealing_work(cell, l3);
#endif
}

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
static inline int get_cgroup_cpumask(struct cgroup *cgrp,
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
int running;

/* The guard is a stack variable. When it falls out of scope,
 * we drop the running lock. */
static inline void __running_unlock(int *guard) {
	(void)guard; /* unused */
	WRITE_ONCE(running, 0);
}

/*
 * On tick, we identify new cells and apply CPU assignment
 */
void BPF_STRUCT_OPS(mitosis_tick, struct task_struct *p_run)
{

	u32 local_configuration_seq = READ_ONCE(configuration_seq);
	if (local_configuration_seq == READ_ONCE(applied_configuration_seq))
		return;

	int zero = 0;
	if (!__atomic_compare_exchange_n(&running, &zero, 1, false,
					 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		return;

	int __attribute__((cleanup(__running_unlock), unused)) __running_guard;

	DECLARE_CPUMASK_ENTRY(entry) = allocate_cpumask_entry();
	if (!entry)
		return;

	/* Get the root cell (cell 0) and its cpumask */
	struct cell_cpumask_wrapper *root_cell_cpumaskw;
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

	/*
	 * Initialize root cell cpumask to all cpus, and then remove from it as we go
	 */
	bpf_cpumask_copy(root_bpf_cpumask, (const struct cpumask *)all_cpumask);

	struct cgroup_subsys_state *root_css, *pos;
	struct cgroup *cur_cgrp, *root_cgrp_ref;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		goto out;
	}

	struct cgrp_ctx *root_cgrp_ctx;
	if (!(root_cgrp_ctx = lookup_cgrp_ctx(root_cgrp)))
		goto out;

	if (!root_cgrp) {
		scx_bpf_error("root_cgrp should not be null");
		goto out;
	}

	if (!(root_cgrp_ref = bpf_cgroup_acquire(root_cgrp))) {
		scx_bpf_error("Failed to acquire reference to root_cgrp");
		goto out;
	}
	root_css = &root_cgrp_ref->self;

	bpf_rcu_read_lock();
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
					goto out_rcu_unlock;
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
			goto out_rcu_unlock;

		/*
		 * cgroup has a cpumask, allocate a new cell if needed, and assign cpus
		 */
		int cell_idx = READ_ONCE(cgrp_ctx->cell);
		if (!cgrp_ctx->cell_owner) {
			cell_idx = allocate_cell();
			if (cell_idx < 0)
				goto out_rcu_unlock;
			cgrp_ctx->cell_owner = true;
		}

		struct cell_cpumask_wrapper *cell_cpumaskw;
		if (!(cell_cpumaskw =
			      bpf_map_lookup_elem(&cell_cpumasks, &cell_idx))) {
			scx_bpf_error("Failed to find cell cpumask: %d",
				      cell_idx);
			goto out_rcu_unlock;
		}

		struct bpf_cpumask *bpf_cpumask;
		bpf_cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, NULL);
		if (!bpf_cpumask) {
			scx_bpf_error("tmp_cpumask should never be null");
			goto out_rcu_unlock;
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
					goto out_rcu_unlock;
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
			goto out_rcu_unlock;
		}

		bpf_cpumask =
			bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, bpf_cpumask);
		if (bpf_cpumask) {
			scx_bpf_error("tmp_cpumask should be null");
			bpf_cpumask_release(bpf_cpumask);
			goto out_rcu_unlock;
		}

		barrier();
		WRITE_ONCE(cgrp_ctx->cell, cell_idx);
		u32 level = cur_cgrp->level;
		if (level <= 0 || level >= MAX_CG_DEPTH) {
			scx_bpf_error("Cgroup hierarchy is too deep: %d",
				      level);
			goto out_rcu_unlock;
		}
		level_cells[level] = cell_idx;
	}
	bpf_rcu_read_unlock();

	/*
	 * assign root cell cpus that are left over
	 */
	int cpu_idx;
	bpf_for(cpu_idx, 0, nr_possible_cpus)
	{
		if (bpf_cpumask_test_cpu( cpu_idx, (const struct cpumask *)root_bpf_cpumask)) {
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
		bpf_cgroup_release(root_cgrp_ref);
		return;
	}

	root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask,
					 root_bpf_cpumask);
	if (root_bpf_cpumask) {
		scx_bpf_error("root tmp_cpumask should be null");
		goto out_root_cgrp;
	}

	int cell_idx;
	/* Recalculate L3 counts for all active cells after CPU assignment changes */
	bpf_for(cell_idx, 1, MAX_CELLS) {
		struct cell *cell;
		if (!(cell = lookup_cell(cell_idx))) {
			scx_bpf_error("Lookup for cell %d failed in tick()", cell_idx);
			goto out_root_cgrp;
		}

		if (!cell->in_use)
			continue;

		/* Recalculate L3 counts for each active cell */
		recalc_cell_l3_counts(cell_idx);
	}

	/* Recalculate root cell's L3 counts after cpumask update */
	recalc_cell_l3_counts(ROOT_CELL_ID);

	barrier();
	WRITE_ONCE(applied_configuration_seq, local_configuration_seq);

	bpf_cgroup_release(root_cgrp_ref);
	return;

out_rcu_unlock:
	bpf_rcu_read_unlock();
out_root_cgrp:
	bpf_cgroup_release(root_cgrp_ref);
out:
	if (root_bpf_cpumask)
		bpf_cpumask_release(root_bpf_cpumask);
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;

	if (!(tctx = lookup_task_ctx(p)) || !(cctx = lookup_cpu_ctx(-1)) ||
	    !(cell = lookup_cell(cctx->cell)))
		return;

	/*
	 * If this task was stolen across L3s, retag to thief L3 and recompute
	 * effective cpumask+DSQ. Preserve vtime to keep fairness.
	 */
#if MITOSIS_ENABLE_STEALING
	if (l3_is_valid(tctx->pending_l3)) {
		u64 save_v = p->scx.dsq_vtime;
		tctx->l3 = tctx->pending_l3;
		tctx->pending_l3 = L3_INVALID;
		update_task_cpumask(p, tctx);
		p->scx.dsq_vtime = save_v;
	}
#endif

	/* Validate task's DSQ before it starts running */
	if (tctx->dsq == DSQ_INVALID) {
		if (tctx->all_cell_cpus_allowed) {
			scx_bpf_error(
				"Task %d has invalid DSQ 0 in running callback (CELL-SCHEDULABLE task, can run on any CPU in cell %d)",
				p->pid, tctx->cell);
		} else {
			scx_bpf_error(
				"Task %d has invalid DSQ 0 in running callback (CORE-PINNED task, restricted to specific CPUs)",
				p->pid);
		}
		return;
	}

	/*
	 * Update per-(cell, L3) vtime for cell-schedulable tasks
	 */
	if (tctx->all_cell_cpus_allowed && l3_is_valid(tctx->l3)) {
		if (time_before(READ_ONCE(cell->l3_vtime_now[tctx->l3]), p->scx.dsq_vtime))
			WRITE_ONCE(cell->l3_vtime_now[tctx->l3], p->scx.dsq_vtime);
	}

	/*
	 * Update CPU vtime for CPU-pinned tasks
	 */
	if (time_before(READ_ONCE(cctx->vtime_now), p->scx.dsq_vtime))
		WRITE_ONCE(cctx->vtime_now, p->scx.dsq_vtime);

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
	p->scx.dsq_vtime += used * DEFAULT_WEIGHT_MULTIPLIER / p->scx.weight;

	if (cidx != 0 || tctx->all_cell_cpus_allowed) {
		u64 *cell_cycles = MEMBER_VPTR(cctx->cell_cycles, [cidx]);
		if (!cell_cycles) {
			scx_bpf_error("Cell index is too large: %d", cidx);
			return;
		}
		*cell_cycles += used;

		/*
		 * For cell-schedulable tasks, also accumulate vtime into
		 * per-cell per-L3 queues
		 */
		if (tctx->all_cell_cpus_allowed && l3_is_valid(tctx->l3)) {
			/* Accumulate weighted execution time into per-(cell, L3) vtime */
			cell->l3_vtime_now[tctx->l3] +=
				used * DEFAULT_WEIGHT_MULTIPLIER /
				p->scx.weight;
		}
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
	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	// Special case for root cell
	if (cgrp->kn->id == root_cgid) {
		WRITE_ONCE(cgc->cell, ROOT_CELL_ID);
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
	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	if (cgc->cell_owner) {
		int ret;
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

	/* Initialize L3 to invalid before cell assignment */
	init_task_l3(tctx);

	// TODO clean this up
	if ((ret = update_task_cell(p, tctx, args->cgroup))) {
		return ret;
	}

	return 0;
}

__hidden void dump_cpumask_word(s32 word, const struct cpumask *cpumask)
{
	u32 u, v = 0;

	bpf_for(u, 0, BITS_PER_U32)
	{
		s32 cpu = BITS_PER_U32 * word + u;
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

/* Print cell state for debugging */
static __always_inline void dump_cell_state(u32 cell_idx)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell) {
		scx_bpf_dump("Cell %d: NOT FOUND", cell_idx);
		return;
	}

	scx_bpf_dump("Cell %d: in_use=%d, cpu_cnt=%d, l3_present_cnt=%d",
		   cell_idx, cell->in_use, cell->cpu_cnt, cell->l3_present_cnt);

	u32 l3;
	// Print vtimes for L3s
	bpf_for(l3, 0, nr_l3) {
		if (cell->l3_cpu_cnt[l3] > 0) {
			scx_bpf_dump("  L3[%d]: %d CPUs", l3, cell->l3_cpu_cnt[l3]);
		}
	}
}

// TODO: FIX THIS
static __always_inline void dump_l3_state(){
}

void BPF_STRUCT_OPS(mitosis_dump, struct scx_dump_ctx *dctx)
{
	u64 dsq_id;
	int i;
	struct cell *cell;
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
		dump_cell_state(i);
	}

	bpf_for(i, 0, nr_possible_cpus)
	{
		if (!(cpu_ctx = lookup_cpu_ctx(i)))
			return;

		dsq_id = get_cpu_dsq_id(i);
		scx_bpf_dump("CPU[%d] cell=%d vtime=%llu nr_queued=%d\n", i,
			     cpu_ctx->cell, READ_ONCE(cpu_ctx->vtime_now),
			     scx_bpf_dsq_nr_queued(dsq_id));
	}

	dump_l3_state();

}

void BPF_STRUCT_OPS(mitosis_dump_task, struct scx_dump_ctx *dctx,
		    struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	scx_bpf_dump(
		"Task[%d] vtime=%llu basis_vtime=%llu cell=%u dsq=%llu all_cell_cpus_allowed=%d\n",
		p->pid, p->scx.dsq_vtime, tctx->basis_vtime, tctx->cell,
		tctx->dsq, tctx->all_cell_cpus_allowed);
	scx_bpf_dump("Task[%d] CPUS=", p->pid);
	dump_cpumask(p->cpus_ptr);
	scx_bpf_dump("\n");
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mitosis_init)
{
	struct bpf_cpumask *cpumask;
	u32 i;
	s32 ret;

	struct cgroup *rootcg;
	if (!(rootcg = bpf_cgroup_from_id(root_cgid)))
		return -ENOENT;

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
				ret = scx_bpf_create_dsq(get_cpu_dsq_id(i), ANY_NUMA);
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

	/* setup cell cpumasks */
	bpf_for(i, 0, MAX_CELLS)
	{
		struct cell_cpumask_wrapper *cpumaskw;
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

	/* Configure root cell (cell 0) topology at init time using nr_l3 and l3_to_cpu masks */
	recalc_cell_l3_counts(ROOT_CELL_ID);

	/* Create (cell,L3) DSQs for all pairs. Userspace will populate maps. */
	// This is a crazy over-estimate
	bpf_for(i, 0, MAX_CELLS)
	{
		u32 l3;
		bpf_for(l3, 0, nr_l3)
		{
			u64 id = get_cell_l3_dsq_id(i, l3);
			ret = scx_bpf_create_dsq(id, ANY_NUMA);
			if (ret < 0)
				scx_bpf_error( "Failed to create DSQ for cell %d, L3 %d: err %d", i, l3, ret);
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(mitosis_exit, struct scx_exit_info *ei)
{
	// int i;
	// bpf_for(i, 0, MAX_CELLS); {
	// 	dump_cell_state((u32)i);
	// }

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
	.dump = (void *)mitosis_dump,
	.dump_task = (void *)mitosis_dump_task,
	.init = (void *)mitosis_init,
	.exit = (void *)mitosis_exit,
	.name = "mitosis",
};
