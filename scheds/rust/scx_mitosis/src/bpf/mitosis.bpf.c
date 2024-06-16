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
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>

char _license[] SEC("license") = "GPL";

/*
 * Variables populated by userspace
 */
/* Adds additional checks to ensure correctness */
const volatile bool debug = false;
const volatile u64 slice_ns = SCX_SLICE_DFL;
const volatile u32 nr_possible_cpus = 1;
const volatile bool smt_enabled = true;
const volatile unsigned char all_cpus[MAX_CPUS_U8];

/*
* user_global_seq is bumped by userspace to indicate that a new configuration
* (e.g. cgroup -> cell or cell -> cpu) has been provided
*/
volatile u32 user_global_seq;
/* BPF-logic uses this to keep track of the last configuration completed */
u32 global_seq;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;

UEI_DEFINE(uei);

/*
 * cgrp locking for load tracking
 */
struct cgrp_lock_wrapper {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_lock_wrapper);
} cgrp_locks SEC(".maps");

static inline struct cgrp_lock_wrapper *lookup_cgrp_lock(struct cgroup *cgrp)
{
	struct cgrp_lock_wrapper *lockw;

	if (!(lockw = bpf_cgrp_storage_get(&cgrp_locks, cgrp, 0,
					   0))) {
		scx_bpf_error("cgrp_lock_wrapper lookup failed for cgid %llu",
			      cgrp->kn->id);
		return NULL;
	}

	return lockw;
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
} cgrp_ctx SEC(".maps");

static inline struct cgrp_ctx *lookup_cgrp_ctx(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0,
					 0))) {
		scx_bpf_error("cgrp_ctx lookup failed for cgid %llu",
			      cgrp->kn->id);
		return NULL;
	}

	return cgc;
}

static inline struct cgrp_ctx *lookup_cgrp_ctx_fallible(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Map from cgrp -> cell populated by userspace for reconfiguration */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, u32); /* cell */
} cgrp_cell_assignment SEC(".maps");

static inline struct cgroup *task_cgroup(struct task_struct *p)
{
	struct cgroup *cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp) {
		scx_bpf_error("Failed to get cgroup for task %d", p->pid);
	}
	return cgrp;
}

struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	u64 started_running_at;
	u32 cell;
	u32 global_seq;
	bool all_cpus_allowed;
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

struct cell {
	u64 vtime_now;
	u32 dsq;
	// The following field is populated from userspace to indicate
	// which cpus the cell should belong to.
	unsigned char cpus[MAX_CPUS_U8];
};

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
 * Store the cpumask for each cell (owned by BPF logic)
 */
struct cell_cpumask_wrapper {
	struct bpf_cpumask __kptr *cpumask;
	/* To avoid allocation on the reconfiguration path, have a second cpumask we
	   can just do an xchg on */
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
* Along with a user_global_seq bump, indicates that cgroup->cell assignment
* changed
*/
volatile bool update_cell_assignment;
bool draining;

/*
 * This is the main driver for reconfiguration. It only runs on CPU 0
 */
SEC("fentry")
int BPF_PROG(sched_tick_fentry)
{
	int cell_idx, cpu_idx;
	struct cpu_ctx *cpu_ctx;
	struct bpf_cpumask *cpumask;
	struct cell_cpumask_wrapper *cell_cpumaskw;
	struct cgroup_subsys_state *root_css, *pos;
	struct cgroup *root_cgrp;

	if (bpf_get_smp_processor_id() != 0)
		return 0;

	/*
	 * To handle races where tasks are assigned to cells that are getting
	 * removed, we ensure cpus dispatch from their previous cell for an entire
	 * scheduler tick. This is a crude way of mimicing RCU synchronization.
	 */
	if (draining) {
		bpf_for(cpu_idx, 0, nr_possible_cpus)
		{
			if (!(cpu_ctx = lookup_cpu_ctx(cpu_idx)))
				return 0;

			cpu_ctx->prev_cell = cpu_ctx->cell;
		}
		barrier();
		draining = false;
	}

	if (global_seq == user_global_seq)
		return 0;

	draining = true;
	barrier();
	/* Iterate through each cell and create its cpumask according to what
	   userspace says */
	bpf_for(cell_idx, 0, MAX_CELLS)
	{
		if (!(cell_cpumaskw =
			      bpf_map_lookup_elem(&cell_cpumasks, &cell_idx))) {
			scx_bpf_error("Failed to find cell cpumask");
			return 0;
		}

		cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, NULL);
		if (!cpumask) {
			scx_bpf_error("tmp_cpumask should never be null");
			return 0;
		}
		bpf_cpumask_clear(cpumask);

		bpf_for(cpu_idx, 0, nr_possible_cpus)
		{
			u8 *u8_ptr;

			if ((u8_ptr = MEMBER_VPTR(
				     cells, [cell_idx].cpus[cpu_idx / 8]))) {
				if (*u8_ptr & (1 << (cpu_idx % 8))) {
					bpf_cpumask_set_cpu(cpu_idx, cpumask);
					if (!(cpu_ctx = lookup_cpu_ctx(
						      cpu_idx))) {
						bpf_cpumask_release(cpumask);
						return 0;
					}

					cpu_ctx->cell = cell_idx;
				}
			}
		}
		cpumask = bpf_kptr_xchg(&cell_cpumaskw->cpumask, cpumask);
		if (!cpumask) {
			scx_bpf_error("cpumask should never be null");
			return 0;
		}
		cpumask = bpf_kptr_xchg(&cell_cpumaskw->tmp_cpumask, cpumask);
		/* We just xchg'd NULL into it, so tmp_cpumask should be NULL */
		if (cpumask) {
			scx_bpf_error("tmp_cpumask should be null");
			bpf_cpumask_release(cpumask);
			return 0;
		}
	}

	if (update_cell_assignment) {
		if (!(root_cgrp = bpf_cgroup_from_id(1))) {
			scx_bpf_error("Could not get rootcg");
			return 0;
		}

		root_css = &root_cgrp->self;

		bpf_rcu_read_lock();
		/* Userspace gives us the full assignment of cgroup -> cell (for cgroups
		   that its aware of). We update the cgroup_ctx with that
		   information. */
		bpf_for_each(css, pos, root_css,
			     BPF_CGROUP_ITER_DESCENDANTS_PRE)
		{
			struct cgrp_ctx *cgc;
			u32 *cell;

			if (!(cell = bpf_cgrp_storage_get(&cgrp_cell_assignment,
							  pos->cgroup, 0, 0)))
				continue;

			if (!(cgc = lookup_cgrp_ctx_fallible(pos->cgroup)))
				continue;

			cgc->cell = *cell;
		}

		/*
		 * Any new cgroups created after this point, should inherit their
		 * parent's cell (e.g. in cgroup_init). However, it's possible that
		 * cgroup creation raced with the above iterator and inherited their
		 * parent's previous cell. We loop through all cgroups again to find any
		 * without a userspace assignment to correct their cell assignment.
		 */
		bpf_for_each(css, pos, root_css,
			     BPF_CGROUP_ITER_DESCENDANTS_PRE)
		{
			struct cgrp_ctx *cgc;
			u32 *cell;

			if (!(cell = bpf_cgrp_storage_get(&cgrp_cell_assignment,
							  pos->cgroup, 0, 0))) {
				struct cgroup *cg, *parent_cg;
				if (!(cgc = lookup_cgrp_ctx_fallible(pos->cgroup)))
					continue;
				/*
				 * We don't have any assignment from userspace, this cgroup must
				 * have been created after userspace assigned. Use its parent's
				 * assigment. Parent assignment is guaranteed to be fine since we
				 * are doing pre-order traversal.
				 *
				 * We need an RCU-protected pointer to lookup_cgrp_ancestor,
				 * hence this awkward bpf_cgroup_id dance
				 */
				if (!(cg = bpf_cgroup_from_id(
					      pos->cgroup->kn->id)))
					/* This can happen with a dying cgroup, just skip */
					continue;

				if (!(parent_cg =
					      lookup_cgrp_ancestor(cg, 1))) {
					bpf_cgroup_release(cg);
					break;
				}

				struct cgrp_ctx *parent_cgc;
				if (!(parent_cgc =
					      lookup_cgrp_ctx(parent_cg))) {
					bpf_cgroup_release(parent_cg);
					bpf_cgroup_release(cg);
					break;
				}

				bpf_cgroup_release(parent_cg);
				bpf_cgroup_release(cg);
				cgc->cell = parent_cgc->cell;
			} else
				bpf_cgrp_storage_delete(&cgrp_cell_assignment,
							pos->cgroup);
		}

		bpf_rcu_read_unlock();
		bpf_cgroup_release(root_cgrp);
		update_cell_assignment = false;
	}

	barrier();
	global_seq++;

	return 0;
}

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

static inline void adj_load(struct task_struct *p, struct task_ctx *tctx,
			    struct cgroup *cgrp, s64 adj, u64 now)
{
	struct cgrp_ctx *cgc;
	struct cgrp_lock_wrapper *lockw;

	if (!(cgc = lookup_cgrp_ctx(cgrp)) || !(lockw = lookup_cgrp_lock(cgrp)))
		return;

	bpf_spin_lock(&lockw->lock);
	/* We handle any tasks that are affinitized to a subset of cpus somewhat
	   uniquely, track their load separately */
	if (tctx->all_cpus_allowed) {
		cgc->load += adj;
		ravg_accumulate(&cgc->load_rd, cgc->load, now, USAGE_HALF_LIFE);
	} else {
		cgc->pinned_load += adj;
		ravg_accumulate(&cgc->pinned_load_rd, cgc->pinned_load, now,
				USAGE_HALF_LIFE);
	}
	bpf_spin_unlock(&lockw->lock);

	if (debug && adj < 0 && (s64)cgc->load < 0) {
		char comm[16];
		if (bpf_probe_read_kernel_str(comm, 16, p->comm) >= 0)
			scx_bpf_error(
				"cpu%d cgroup(%llu) comm(%s) load underflow (load=%lld adj=%lld)",
				bpf_get_smp_processor_id(), cgrp->kn->id, comm,
				cgc->load, adj);
	}
}

static inline int update_task_cpumask(struct task_struct *p, struct task_ctx *tctx)
{
	const struct cpumask *cell_cpumask;

	if (!(cell_cpumask = lookup_cell_cpumask(tctx->cell)))
		return -ENOENT;

	if (!tctx->cpumask)
		return -EINVAL;
	bpf_cpumask_and(tctx->cpumask, cell_cpumask, p->cpus_ptr);
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
	 * This ordering is pretty important, we read global_seq before reading
	 * everything else expecting that the updater will update everything and
	 * then bump global_seq last. This ensures that we cannot miss an update.
	 *
	 * Ideally I'd use __atomic_load intrinsics. Instead I'm using a regular
	 * load + compiler barrier.
	 */
	tctx->global_seq = global_seq;
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

static s32 pick_idle_cpu_from(const struct cpumask *cand_cpumask, s32 prev_cpu,
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

/*
 * select_cpu is where we update each task's cell assignment and then try to
 * dispatch to an idle core in the cell if possible
 */
s32 BPF_STRUCT_OPS(mitosis_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct cgroup *cgrp;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cpumask *task_cpumask;
	const struct cpumask *idle_smtmask;
	s32 cpu;
	bool local = false;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return prev_cpu;

	/* Check if we need to update the cell/cpumask mapping */
	if (tctx->global_seq != global_seq) {
		if (!(cgrp = task_cgroup(p)))
			return prev_cpu;
		if (update_task_cell(p, tctx, cgrp)) {
			bpf_cgroup_release(cgrp);
			return prev_cpu;
		}
		bpf_cgroup_release(cgrp);
	}

	if (!(task_cpumask = (struct cpumask *)tctx->cpumask) ||
	    !(idle_smtmask = scx_bpf_get_idle_smtmask()))
		return prev_cpu;

	/* No overlap between cell cpus and task cpus, just send it to global */
	if (bpf_cpumask_empty(task_cpumask)) {
		cstat_inc(CSTAT_AFFN_VIOL, tctx->cell, cctx);

		if ((cpu = pick_idle_cpu_from(p->cpus_ptr, prev_cpu,
					      idle_smtmask)) >= 0)
			goto dispatch_local;

		cstat_inc(CSTAT_GLOBAL, tctx->cell, cctx);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_ns, 0);
		scx_bpf_put_idle_cpumask(idle_smtmask);
		return prev_cpu;
	}

	if ((cpu = pick_idle_cpu_from(task_cpumask, prev_cpu, idle_smtmask)) >=
	    0)
		goto dispatch_local;

	if (bpf_cpumask_test_cpu(prev_cpu, task_cpumask))
		cpu = prev_cpu;
	else
		cpu = bpf_cpumask_any_distribute(task_cpumask);
	goto out_put_idle_smtmask;

dispatch_local:
	local = true;
	cstat_inc(CSTAT_LOCAL, tctx->cell, cctx);
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
out_put_idle_smtmask:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	if (debug && !draining && tctx->all_cpus_allowed &&
	    (cctx = lookup_cpu_ctx(cpu)) && cctx->cell != tctx->cell)
		scx_bpf_error(
			"select_cpu returned cpu %d belonging to cell %d but task belongs to cell %d, local %d",
			cpu, cctx->cell, tctx->cell, local);
	return cpu;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

void BPF_STRUCT_OPS(mitosis_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;
	u64 vtime = p->scx.dsq_vtime;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(cell = lookup_cell(tctx->cell)))
		return;

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (vtime_before(vtime, cell->vtime_now - slice_ns))
		vtime = cell->vtime_now - slice_ns;

	scx_bpf_dispatch_vtime(p, tctx->cell, slice_ns, vtime, enq_flags);
}

void BPF_STRUCT_OPS(mitosis_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx;
	u32 prev_cell, cell;

	if (!(cctx = lookup_cpu_ctx(-1)))
		return;

	prev_cell = *(volatile u32 *)&cctx->prev_cell;
	cell = *(volatile u32 *)&cctx->cell;

	/*
	 * cpu <=> cell assignment can change dynamically. In order to deal with
	 * scheduling racing with assignment change, we schedule from the previous
	 * cell first to make sure it drains.
	 */
	if (prev_cell != cell && scx_bpf_consume(prev_cell))
		return;

	scx_bpf_consume(cell);
}

static inline void runnable(struct task_struct *p, struct task_ctx *tctx,
			    struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;

	if (tctx->cell == -1) {
		if (!(cgc = lookup_cgrp_ctx(cgrp)))
			return;

		tctx->cell = cgc->cell;
	}

	adj_load(p, tctx, cgrp, p->scx.weight, bpf_ktime_get_ns());
}

void BPF_STRUCT_OPS(mitosis_runnable, struct task_struct *p, u64 enq_flags)
{
	struct cgroup *cgrp;
	struct task_ctx *tctx;

	if (!(cgrp = task_cgroup(p)))
		return;

	if (!(tctx = lookup_task_ctx(p)))
		goto out;

	runnable(p, tctx, cgrp);
out:
	bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cell *cell;

	if (!(tctx = lookup_task_ctx(p)) || !(cell = lookup_cell(tctx->cell)))
		return;

	if (vtime_before(cell->vtime_now, p->scx.dsq_vtime))
		cell->vtime_now = p->scx.dsq_vtime;

	tctx->started_running_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(mitosis_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct cell *cell;
	u64 used;
	u32 cidx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	cidx = tctx->cell;
	if (!(cell = lookup_cell(cidx)))
		return;

	used = bpf_ktime_get_ns() - tctx->started_running_at;
	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += used * 100 / p->scx.weight;

	if (tctx->all_cpus_allowed) {
		u64 *cell_cycles = MEMBER_VPTR(cctx->cell_cycles, [cidx]);
		if (!cell_cycles) {
			scx_bpf_error("Cell index is too large: %d", cidx);
			return;
		}
		*cell_cycles += used;
	}
}

static inline void quiescent(struct task_struct *p, struct cgroup *cgrp)
{
	struct task_ctx *tctx;
	if (!(tctx = lookup_task_ctx(p)))
		return;

	adj_load(p, tctx, cgrp, -(s64)p->scx.weight, bpf_ktime_get_ns());
}

void BPF_STRUCT_OPS(mitosis_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct cgroup *cgrp;
	if (!(cgrp = task_cgroup(p)))
		return;

	quiescent(p, cgrp);
	bpf_cgroup_release(cgrp);
}

s32 BPF_STRUCT_OPS(mitosis_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;
	if (!(cgc = bpf_cgrp_storage_get(&cgrp_ctx, cgrp, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("cgrp_ctx creation failed for cgid %llu",
			      cgrp->kn->id);
		return -ENOENT;
	}

	// Just initialize the cgroup lock
	if (!bpf_cgrp_storage_get(&cgrp_locks, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE)) {
		scx_bpf_error("cgrp_lock_wrapper creation failed for cgid %llu",
					  cgrp->kn->id);
		return -ENOENT;
	}

	// Initialize the rootcg to cell 0
	if (!cgrp->level) {
		cgc->cell = 0;
		return 0;
	}

	struct cgroup *parent_cg;
	if (!(parent_cg = lookup_cgrp_ancestor(cgrp, 1)))
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

void BPF_STRUCT_OPS(mitosis_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	if (p->scx.flags & SCX_TASK_QUEUED) {
		quiescent(p, from);
		runnable(p, tctx, to);
	}

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

	tctx->all_cpus_allowed = bpf_cpumask_subset(
		(const struct cpumask *)all_cpumask, cpumask);
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
		return -EINVAL;
	}

	if (all_cpumask)
		tctx->all_cpus_allowed = bpf_cpumask_subset(
			(const struct cpumask *)all_cpumask, p->cpus_ptr);
	else {
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
		struct cell *cell = &cells[i];

		ret = scx_bpf_create_dsq(i, -1);
		if (ret < 0)
			return ret;
		cell->dsq = i;

		if (!(cpumaskw = bpf_map_lookup_elem(&cell_cpumasks, &i)))
			return -ENOENT;

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;

		/*
		 * Start with all full cpumask for all cells. It only matters for cell 0
		 * to start with, all others will get reconfigured by userspace before
		 * being used.
		 */
		bpf_cpumask_setall(cpumask);

		cpumask = bpf_kptr_xchg(&cpumaskw->cpumask, cpumask);
		if (cpumask) {
			bpf_cpumask_release(cpumask);
			return -EINVAL;
		}

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;
		cpumask = bpf_kptr_xchg(&cpumaskw->tmp_cpumask, cpumask);
		if (cpumask) {
			bpf_cpumask_release(cpumask);
			return -EINVAL;
		}

	}

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
	.runnable = (void *)mitosis_runnable,
	.running = (void *)mitosis_running,
	.stopping = (void *)mitosis_stopping,
	.quiescent = (void *)mitosis_quiescent,
	.set_cpumask = (void *)mitosis_set_cpumask,
	.init_task = (void *)mitosis_init_task,
	.cgroup_init = (void *)mitosis_cgroup_init,
	.cgroup_move = (void *)mitosis_cgroup_move,
	.init = (void *)mitosis_init,
	.exit = (void *)mitosis_exit,
	.name = "mitosis",
};
