/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_p2dq is a scheduler where the load balancing is done using a pick 2
 * algorithm.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)


/*
 * Domains and cpus
 */
const volatile u32 nr_llcs = 32;
const volatile u32 nr_nodes = 32;
const volatile u32 nr_cpus = 64;
const volatile u32 nr_dsqs_per_llc = 3;
const volatile u64 dsq_shift = 2;
const volatile int init_dsq_index = 0;
const volatile u64 min_slice_us = 100;

const volatile bool smt_enabled = true;
const volatile bool has_little_cores = false;
const volatile bool kthreads_local;
const volatile u32 debug = 2;

const u32 zero_u32 = 0;
u64 cpu_llc_ids[MAX_CPUS];
u64 cpu_node_ids[MAX_CPUS];
u64 big_core_ids[MAX_CPUS];
u64 dsq_time_slices[MAX_DSQS_PER_LLC];

u64 max_exec_ns;
u32 sched_mode = MODE_PERFORMANCE;


private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *big_cpumask;


static __always_inline u64 dsq_time_slice(int dsq_id)
{
	if (dsq_id > nr_dsqs_per_llc || dsq_id < 0) {
		scx_bpf_error("Invalid DSQ id");
		return 0;
	}
	return dsq_time_slices[dsq_id];
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctxs SEC(".maps");

static struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cpuc;

	if (cpu < 0)
		cpuc = bpf_map_lookup_elem(&cpu_ctxs, &zero_u32);
	else
		cpuc = bpf_map_lookup_percpu_elem(&cpu_ctxs, &zero_u32, cpu);

	if (!cpuc) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cpuc;
}

static __always_inline u64 cpu_dsq_id(int dsq_index, struct cpu_ctx *cpuc) {
	if (dsq_index < 0 || dsq_index > nr_dsqs_per_llc || dsq_index >= MAX_DSQS_PER_LLC) {
		scx_bpf_error("invalid dsq index: %d", dsq_index);
		return 0;
	}
	return *MEMBER_VPTR(cpuc->dsqs, [dsq_index]);
}


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct llc_ctx);
	__uint(max_entries, MAX_LLCS);
} llc_ctxs SEC(".maps");

static struct llc_ctx *lookup_llc_ctx(u32 llc_id)
{
	struct llc_ctx *llcx;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc_id);
	if (!llcx) {
		scx_bpf_error("no llc_ctx for llc %u", llc_id);
		return NULL;
	}

	return llcx;
}


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
	__uint(map_flags, 0);
} node_ctxs SEC(".maps");

static struct node_ctx *lookup_node_ctx(u32 node_id)
{
	struct node_ctx *nodec;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node_id);
	if (!nodec) {
		scx_bpf_error("no node_ctx for node %u", node_id);
		return NULL;
	}

	return nodec;
}


struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

static struct task_ctx *lookup_task_ctx_may_fail(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc = lookup_task_ctx_may_fail(p);

	if (!taskc)
		scx_bpf_error("task_ctx lookup failed");

	return taskc;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, P2DQ_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 amount)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += amount;
}

static inline void stat_inc(enum stat_idx idx)
{
	stat_add(idx, 1);
}

/*
 * Returns if the task is interactive based on the last DSQ.
 */
static bool is_interactive(struct task_ctx *taskc)
{
	if (nr_dsqs_per_llc <= 1)
		return false;
	return nr_dsqs_per_llc / 2 > taskc->dsq_index;
}

/*
 * Returns a random llc_ctx
 */
static struct llc_ctx *rand_llc_ctx(void)
{
	return lookup_llc_ctx(bpf_get_prandom_u32() % nr_llcs);
}

static bool keep_running(struct cpu_ctx *cpuc, struct task_struct *p)
{
	struct llc_ctx *llcx;
	int i;

	// Only tasks in the least non interactive DSQ can keep running
	if (cpuc->dsq_index != nr_dsqs_per_llc - 1 ||
	    p->scx.flags & SCX_TASK_QUEUED ||
	    cpuc->ran_for >= max_exec_ns)
		return false;

	if (!(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return false;

	int nr_queued = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		// ignore interactive tasks
		if (i == 0)
			continue;
		nr_queued += scx_bpf_dsq_nr_queued(llcx->dsqs[i]);
	}

	if (nr_queued >= llcx->nr_cpus)
		return false;


	u64 slice_ns = dsq_time_slice(cpuc->dsq_index);
	cpuc->ran_for += slice_ns;
	p->scx.slice = slice_ns;
	stat_inc(P2DQ_STAT_KEEP);
	return true;
}

static s32 pick_two(struct task_ctx *taskc, bool *is_idle)
{
	struct llc_ctx *left = rand_llc_ctx();
	struct llc_ctx *right = rand_llc_ctx();
	int dsq_index = taskc->dsq_index;
	s32 cpu;

	if (!left || !right || dsq_index > nr_dsqs_per_llc) {
		return -EINVAL;
	}

	// last ditch effort if same are picked.
	if (left->id == right->id) {
		right = rand_llc_ctx();
		if (!right || left->id == right->id)
			return -EINVAL;
	}

	u64 left_dsq_id = *MEMBER_VPTR(left->dsqs, [dsq_index]);
	s32 left_queued = scx_bpf_dsq_nr_queued(left_dsq_id);
	u64 right_dsq_id = *MEMBER_VPTR(right->dsqs, [dsq_index]);
	s32 right_queued = scx_bpf_dsq_nr_queued(right_dsq_id);

	stat_inc(P2DQ_STAT_PICK2);
	if (left_queued < right_queued) {
		if (!left->cpumask)
			return -EINVAL;

		cpu = scx_bpf_pick_idle_cpu(cast_mask(left->cpumask), 0);
		if (cpu < nr_cpus) {
			*is_idle = true;
			return cpu;
		}

		// couldn't find idle, but still return a CPU.
		if (!left->cpumask)
			return -EINVAL;
		cpu = bpf_cpumask_any_distribute(cast_mask(left->cpumask));
		if (cpu < nr_cpus)
			return cpu;
	} else {
		if (!right->cpumask)
			return -EINVAL;

		cpu = scx_bpf_pick_idle_cpu(cast_mask(right->cpumask), 0);
		if (cpu < nr_cpus) {
			*is_idle = true;
			return cpu;
		}

		// couldn't find idle, but still return a CPU.
		if (!right->cpumask)
			return -EINVAL;
		cpu = bpf_cpumask_any_distribute(cast_mask(right->cpumask));
		if (cpu < nr_cpus)
			return cpu;
	}

	return -ENOENT;
}

static s32 pick_idle_cpu(struct task_struct *p, struct task_ctx *taskc,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct cpu_ctx *prev_cpuc;
	struct node_ctx *nodec;
	struct llc_ctx *llcx;
	bool is_prev_llc_affine = false;
	bool interactive = is_interactive(taskc);
	s32 cpu = prev_cpu;

	if (!(prev_cpuc = lookup_cpu_ctx(prev_cpu)) ||
	    !(llcx = lookup_llc_ctx(prev_cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(prev_cpuc->node_id)))
		return prev_cpu;

	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();


	if (!llcx->cpumask || !llcx->cpumask || !idle_cpumask || !idle_smtmask)
		goto out_put_cpumask;

	is_prev_llc_affine = bpf_cpumask_test_cpu(prev_cpu, cast_mask(llcx->cpumask));
	if (!llcx->cpumask || !idle_cpumask)
		goto out_put_cpumask;

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		// TODO: implement this
	}

	// If last CPU is idle then run again
	if (is_prev_llc_affine &&
	    bpf_cpumask_test_cpu(prev_cpu, idle_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (smt_enabled) {
		if (is_prev_llc_affine &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same LLC domain.
		 */
		if (llcx->cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->cpumask), SCX_PICK_IDLE_CORE);
			if (cpu < nr_cpus && cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}
	}

	if (has_little_cores) {
		if (interactive) {
			if (!llcx->cpumask)
				goto out_put_cpumask;
			/*
			 * Interactive tasks can run anywhere, first try in the local LLC.
			 */
			cpu = bpf_cpumask_any_and_distribute(idle_cpumask, cast_mask(llcx->cpumask));
			if (cpu < nr_cpus) {
				*is_idle = true;
				goto out_put_cpumask;
			}

			if (!nodec->cpumask)
				goto out_put_cpumask;
			cpu = bpf_cpumask_any_and_distribute(idle_cpumask, cast_mask(nodec->cpumask));
			if (cpu < nr_cpus) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		} else {
			if (!llcx->big_cpumask)
				goto out_put_cpumask;
			/*
			 * If not interactive try a big core in the local domain first.
			 */
			cpu = bpf_cpumask_any_and_distribute(idle_cpumask, cast_mask(llcx->big_cpumask));
			if (cpu < nr_cpus) {
				*is_idle = true;
				goto out_put_cpumask;
			}

			if (!nodec->big_cpumask)
				goto out_put_cpumask;
			/*
			 * Next try a big core in the local node.
			 */
			cpu = bpf_cpumask_any_and_distribute(idle_cpumask, cast_mask(nodec->big_cpumask));
			if (cpu < nr_cpus) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}
	}

	if (!llcx->cpumask)
		goto out_put_cpumask;

	// Next try in the local LLC.
	cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->cpumask), 0);
	if (cpu < nr_cpus && cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (!nodec->cpumask)
		goto out_put_cpumask;

	// Next try in the local node.
	cpu = scx_bpf_pick_idle_cpu(cast_mask(nodec->cpumask), 0);
	if (cpu < nr_cpus && cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (interactive) {
		/*
		 * Interactive tasks can go on the same CPU, even if it isn't idle.
		 */
		cpu = prev_cpu;
		goto out_put_cpumask;
	} else {
		cpu = pick_two(taskc, is_idle);
		if (cpu >= 0) {
			goto out_put_cpumask;
		}
	}
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu < nr_cpus) {
		*is_idle = true;
		goto out_put_cpumask;
	}
	cpu = prev_cpu;

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);
	if (cpu >= nr_cpus || cpu < 0)
		cpu = prev_cpu;

	return cpu;
}


s32 BPF_STRUCT_OPS(p2dq_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *taskc;
	bool is_idle = false;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	cpu = pick_idle_cpu(p, taskc, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		u64 slice_ns = dsq_time_slice(taskc->dsq_index);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
	}

	return cpu;
}


void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc, *task_cpuc;
	struct llc_ctx *llcx, *prev_llcx;
	u64 dsq_id;

	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(cpuc = lookup_cpu_ctx(-1)) ||
	    !(task_cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(taskc = lookup_task_ctx(p)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	u64 vtime_now = llcx->vtime;
	u64 slice_ns = dsq_time_slice(taskc->dsq_index);

	// If the task in in another LLC need to update vtime.
	if (taskc->llc_id != cpuc->llc_id) {
		if (!(prev_llcx = lookup_llc_ctx(task_cpuc->llc_id)))
			return;


		u64 vtime_delta = p->scx.dsq_vtime - prev_llcx->vtime;
		p->scx.dsq_vtime = vtime_now + vtime_delta;
	}

	u64 vtime = p->scx.dsq_vtime;

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice for the dsq.
	 */
	if (time_before(vtime, vtime_now - slice_ns))
		vtime = vtime_now - slice_ns;

	p->scx.dsq_vtime = vtime;

	/*
	 * Push per-cpu kthreads at the head of local dsq's and preempt the
	 * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
	 * behind other threads which is necessary for forward progress
	 * guarantee as we depend on the BPF timer which may run from ksoftirqd.
	 */
	if ((p->flags & PF_KTHREAD) && (p->nr_cpus_allowed < nr_cpus) && kthreads_local) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	/* 
	 * Affinitized tasks just get dispatched directly, need to handle this better 
	 */
	if ((!taskc->all_cpus)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	dsq_id = cpu_dsq_id(taskc->dsq_index, cpuc);
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, enq_flags);

	if (dsq_id >= 0 && dsq_id < nr_dsqs_per_llc && vtime > llcx->dsq_max_vtime[dsq_id]) {
		llcx->dsq_max_vtime[dsq_id] = vtime;
		trace("LLC[%d] DSQ[%d] max_vtime %llu", llcx->id, dsq_id, vtime);
	}
}


void BPF_STRUCT_OPS(p2dq_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *wakee_ctx;

	if (!(wakee_ctx = lookup_task_ctx(p)))
		return;

	wakee_ctx->is_kworker = p->flags & PF_WQ_WORKER;
}


void BPF_STRUCT_OPS(p2dq_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(taskc = lookup_task_ctx(p)) ||
	   !(cpuc = lookup_cpu_ctx(task_cpu)) ||
	   !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	if (taskc->llc_id != cpuc->llc_id)
		stat_inc(P2DQ_STAT_LLC_MIGRATION);

	trace("RUNNING %d prev_cpu %d prev_llc %d llc %d", p->pid, taskc->cpu, taskc->llc_id, llcx->id);
	taskc->last_run_at = scx_bpf_now();
	taskc->llc_id = llcx->id;
	llcx->vtime = p->scx.dsq_vtime;
	cpuc->dsq_index = taskc->dsq_index;
	cpuc->ran_for = 0;
	taskc->cpu = task_cpu;

	// In perf mode give interactive tasks a perf boost.
	if (sched_mode == MODE_PERFORMANCE || is_interactive(taskc)) {
		cpuc->perf = 1024;
		scx_bpf_cpuperf_set(task_cpu, cpuc->perf);
	}
}


void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 used, last_dsq_slice_ns;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	u64 now = scx_bpf_now();
	last_dsq_slice_ns = dsq_time_slice(taskc->dsq_index);
	used = now - taskc->last_run_at;
	taskc->last_run_at = now;
	taskc->last_dsq_id = taskc->dsq_id;
	taskc->last_dsq_index = taskc->dsq_index;
	cpuc->dsq_index = taskc->dsq_index;

	// On stopping determine if the task can move to a longer DSQ by
	// comparing the used time to the scaled DSQ slice.
	if (used >= ((9 * last_dsq_slice_ns) / 10)) {
		if (taskc->dsq_id < nr_dsqs_per_llc) {
			taskc->dsq_index += 1;
			stat_inc(P2DQ_STAT_DSQ_CHANGE);
			trace("%s[%p]: DSQ %u -> %u, slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_index, dsq_time_slice(taskc->dsq_index));
		}
	// If under half the slice was consumed move the task back down.
	} else if (used < last_dsq_slice_ns / 2) {
		if (taskc->dsq_index > 0) {
			taskc->dsq_index -= 1;
			stat_inc(P2DQ_STAT_DSQ_CHANGE);
			trace("%s[%p]: DSQ %u -> %u slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_index, dsq_time_slice(taskc->dsq_index));
		}
	} else {
		stat_inc(P2DQ_STAT_DSQ_SAME);
	}
}



void BPF_STRUCT_OPS(p2dq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 dsq_id = 0;
	int i;

	if (!(cpuc = lookup_cpu_ctx(cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	if (prev && keep_running(cpuc, prev))
		return;

	if (nr_dsqs_per_llc > MAX_DSQS_PER_LLC) {
		scx_bpf_error("can't happen");
		return;
	}

	// In the dispatch path we first figure out the load factor for each dsq.
	s32 nr_queued = 0;
	int max_dsq = 0;
	u64 dsq_load = 0;
	u64 max_load = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		nr_queued = scx_bpf_dsq_nr_queued(*MEMBER_VPTR(cpuc->dsqs, [i]));
		if (nr_queued <= 0)
			continue;

		dsq_load = i <= nr_queued ? nr_queued : nr_queued / i;
		if (dsq_load > max_load) {
			max_load = dsq_load;
			max_dsq = i;
		}
	}

	// First try the DSQ with the most load.
	if (max_dsq >= 0 && max_load > 0) {
		dsq_id = *MEMBER_VPTR(cpuc->dsqs, [max_dsq]);
		if (scx_bpf_dsq_move_to_local(dsq_id))
			return;
	}

	// Try the last DSQ, this is to keep tasks sticky to their dsq type.
	if (cpuc->dsq_index == 0 &&
	    scx_bpf_dsq_move_to_local(cpuc->dsqs[cpuc->dsq_index]))
		return;

	u64 max_vtime = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		if (llcx->dsq_max_vtime[i] > max_vtime) {
			max_vtime = llcx->dsq_max_vtime[i];
			dsq_id = cpuc->dsqs[i];
		}
	}
	if (dsq_id > 0 && dsq_id < nr_dsqs_per_llc)
		scx_bpf_dsq_move_to_local(cpuc->dsqs[dsq_id]);
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)) || !all_cpumask)
		return;

	taskc->all_cpus =
		bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct bpf_cpumask *cpumask;
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;

	s32 task_cpu = scx_bpf_task_cpu(p);

	taskc = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if (!(cpumask = bpf_cpumask_create())) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if ((cpumask = bpf_kptr_xchg(&taskc->mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		scx_bpf_error("task_ctx allocation failure");
		return -EINVAL;
	}

	if (!(cpuc = lookup_cpu_ctx(task_cpu)))
		return -EINVAL;

	taskc->dsq_id = SCX_DSQ_INVALID;
	taskc->llc_id = cpuc->llc_id;
	taskc->dsq_index = init_dsq_index;
	taskc->last_dsq_index = init_dsq_index;
	taskc->runnable = true;
	taskc->all_cpus = p->nr_cpus_allowed == nr_cpus;

	return 0;
}


static int init_llc(u32 llc_id)
{
	struct bpf_cpumask *cpumask, *big_cpumask;
	struct llc_ctx *llcx;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc_id);
	if (!llcx) {
		scx_bpf_error("No llc %u", llc_id);
		return -ENOENT;
	}

	llcx->vtime = 0;
	llcx->id = llc_id;
	llcx->nr_cpus = 0;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&llcx->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	llcx->all_big = true;

	// big cpumask
	big_cpumask = bpf_cpumask_create();
	if (!big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	big_cpumask = bpf_kptr_xchg(&llcx->big_cpumask, big_cpumask);
	if (big_cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(big_cpumask);
	}

	return 0;
}

static int init_node(u32 node_id)
{
	struct bpf_cpumask *cpumask, *big_cpumask;
	struct node_ctx *nodec;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node_id);
	if (!nodec) {
		scx_bpf_error("No node %u", node_id);
		return -ENOENT;
	}

	nodec->id = node_id;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("failed to create cpumask for node %u", node_id);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&nodec->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	nodec->all_big = true;

	// big cpumask
	big_cpumask = bpf_cpumask_create();
	if (!big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	big_cpumask = bpf_kptr_xchg(&nodec->big_cpumask, big_cpumask);
	if (big_cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(big_cpumask);
	}
	dbg("CFG NODE[%u] configured", node_id);

	return 0;
}

// Initializes per CPU data structures.
static s32 init_cpu(int cpu)
{
	struct bpf_cpumask *tmp_cpumask;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	struct node_ctx *nodec;

	if (!(cpuc = lookup_cpu_ctx(cpu)))
		return -ENOENT;

	cpuc->llc_id = cpu_llc_ids[cpu];
	cpuc->node_id = cpu_node_ids[cpu];
	cpuc->is_big = big_core_ids[cpu] == 1;

	if (!(llcx = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(cpuc->node_id))) {
		scx_bpf_error("failed to get ctxs for cpu %u", cpu);
		return -ENOENT;
	}

	// copy for each cpu, doesn't matter if it gets overwritten.
	llcx->nr_cpus += 1;
	llcx->id = cpu_llc_ids[cpu];
	llcx->node_id = cpu_node_ids[cpu];
	nodec->id = cpu_node_ids[cpu];

	if (cpuc->is_big) {
		bpf_rcu_read_lock();
		trace("CPU[%d] is big", cpu);
		if (big_cpumask)
			bpf_cpumask_set_cpu(cpu, big_cpumask);
		if (nodec->big_cpumask)
			bpf_cpumask_set_cpu(cpu, nodec->big_cpumask);
		if (llcx->big_cpumask)
			bpf_cpumask_set_cpu(cpu, llcx->big_cpumask);
		bpf_rcu_read_unlock();
	} else {
		llcx->all_big = false;
		nodec->all_big = false;
	}

	bpf_rcu_read_lock();
	if (nodec->cpumask)
		bpf_cpumask_set_cpu(cpu, nodec->cpumask);
	if (llcx->cpumask)
		bpf_cpumask_set_cpu(cpu, llcx->cpumask);
	bpf_rcu_read_unlock();

	tmp_cpumask = bpf_cpumask_create();
	if (!tmp_cpumask) {
		scx_bpf_error("failed to create tmp cpumask");
		return -ENOMEM;
	}

	tmp_cpumask = bpf_kptr_xchg(&cpuc->tmp_cpumask, tmp_cpumask);
	if (tmp_cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(tmp_cpumask);
	}
	trace("CFG CPU[%d]NODE[%d]LLC[%d] initialized",
	    cpu, cpuc->node_id, cpuc->llc_id);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init)
{
	int i, ret;
	struct bpf_cpumask *tmp_cpumask, *tmp_big_cpumask;

	tmp_big_cpumask = bpf_cpumask_create();
	if (!tmp_big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	if (init_dsq_index >= nr_dsqs_per_llc) {
		scx_bpf_error("invalid init_dsq_index");
		return -EINVAL;
	}

	tmp_big_cpumask = bpf_kptr_xchg(&big_cpumask, tmp_big_cpumask);
	if (tmp_big_cpumask)
		bpf_cpumask_release(tmp_big_cpumask);

	tmp_cpumask = bpf_cpumask_create();
	if (!tmp_cpumask) {
		scx_bpf_error("failed to create all cpumask");
		return -ENOMEM;
	}

	tmp_cpumask = bpf_kptr_xchg(&all_cpumask, tmp_cpumask);
	if (tmp_cpumask)
		bpf_cpumask_release(tmp_cpumask);

	// First we initialize LLCs because DSQs are created at the LLC level.
	bpf_for(i, 0, nr_llcs) {
		ret = init_llc(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_nodes) {
		ret = init_node(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpus) {
		ret = init_cpu(i);
		if (ret)
			return ret;
	}

	// Create DSQs for the LLCs
	struct llc_ctx *llcx;
	u64 dsq_id;
	int llc_id;
	bpf_for(llc_id, 0, nr_llcs) {
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return -EINVAL;

		bpf_for(i, 0, nr_dsqs_per_llc) {
			dsq_id = (llc_id << nr_dsqs_per_llc) | i;
			dbg("CFG creating DSQ[%d][%llu] slice_us %llu for LLC[%u]",
			    i, dsq_id, dsq_time_slice(i), llc_id);
			ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
			if (ret < 0) {
				scx_bpf_error("failed to create DSQ %llu", dsq_id);
				return ret;
			}

			llcx->dsqs[i] = dsq_id;
			llcx->dsq_max_vtime[i] = 0;
		}
	}
	struct cpu_ctx *cpuc;
	bpf_for(i, 0, nr_cpus) {
		if (!(cpuc = lookup_cpu_ctx(i)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
			return -EINVAL;

		bpf_for(dsq_id, 0, nr_dsqs_per_llc) {
			cpuc->dsqs[dsq_id] = llcx->dsqs[dsq_id];
		}
	}

	max_exec_ns = 10 * dsq_time_slice(nr_dsqs_per_llc);

	return 0;
}


void BPF_STRUCT_OPS(p2dq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(p2dq,
	       .select_cpu		= (void *)p2dq_select_cpu,
	       .enqueue			= (void *)p2dq_enqueue,
	       .dispatch		= (void *)p2dq_dispatch,
	       .runnable		= (void *)p2dq_runnable,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
	       .init_task		= (void *)p2dq_init_task,
	       .init			= (void *)p2dq_init,
	       .exit			= (void *)p2dq_exit,
	       .timeout_ms		= 20000,
	       .name			= "p2dq");
