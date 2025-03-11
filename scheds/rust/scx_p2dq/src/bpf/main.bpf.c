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
const volatile u64 min_llc_runs_pick2 = 5;
const volatile u32 interactive_ratio = 10;
const volatile u32 min_nr_queued_pick2 = 10;

const volatile bool autoslice = true;
const volatile bool dispatch_pick2_disable = false;
const volatile bool eager_load_balance = true;
const volatile bool greedy_idle = false;
const volatile bool interactive_sticky = false;
const volatile bool keep_running_enabled = true;
const volatile bool kthreads_local = true;
const volatile bool max_dsq_pick2 = false;

const volatile bool smt_enabled = true;
const volatile bool has_little_cores = false;
const volatile u32 debug = 2;

const u32 zero_u32 = 0;
u64 cpu_llc_ids[MAX_CPUS];
u64 cpu_node_ids[MAX_CPUS];
u64 big_core_ids[MAX_CPUS];
u64 dsq_time_slices[MAX_DSQS_PER_LLC];

u64 max_exec_ns;
u64 min_slice_ns = 500;
u32 sched_mode = MODE_PERFORMANCE;


private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *big_cpumask;


static u64 max(u64 a, u64 b)
{
	return a >= b ? a : b;
}

static __always_inline u64 dsq_time_slice(int dsq_id)
{
	if (dsq_id > nr_dsqs_per_llc || dsq_id < 0) {
		scx_bpf_error("Invalid DSQ id");
		return 0;
	}
	return dsq_time_slices[dsq_id];
}

struct p2dq_timer p2dq_timers[MAX_TIMERS] = {
	{250LLU * NSEC_PER_MSEC, CLOCK_BOOTTIME, 0},
};

struct timer_wrapper {
	struct bpf_timer timer;
	int	key;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} timer_data SEC(".maps");


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
	if (dsq_index < 0 ||
	    dsq_index > nr_dsqs_per_llc ||
	    dsq_index >= MAX_DSQS_PER_LLC) {
		scx_bpf_error("cpuc invalid dsq index: %d", dsq_index);
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
 * Returns if the task is interactive based on the tasks DSQ index.
 */
static bool is_interactive(struct task_ctx *taskc)
{
	if (nr_dsqs_per_llc <= 1)
		return false;
	// For now only the shortest duration DSQ is considered interactive.
	return taskc->dsq_index == 0;
}

/*
 * Returns if the task is able to load balance using pick2.
 */
static bool can_pick2(struct task_ctx *taskc)
{
	if (is_interactive(taskc) ||
	    (max_dsq_pick2 && taskc->dsq_id < nr_dsqs_per_llc))
		return false;

	return true;
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
	if (!keep_running_enabled ||
	    cpuc->dsq_index != nr_dsqs_per_llc - 1 ||
	    p->scx.flags & SCX_TASK_QUEUED ||
	    cpuc->ran_for >= max_exec_ns)
		return false;

	if (!(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return false;

	int nr_queued = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
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

static struct llc_ctx *pick_two_llc_ctx(struct llc_ctx *left,
					struct llc_ctx *right, bool most_loaded)
{
	s32 left_queued = 0, right_queued = 0;
	u64 left_load = 0, right_load = 0;
	int i;

	if (!left || !right)
		return left;

	bpf_for(i, 0, nr_llcs) {
		if (i >= nr_dsqs_per_llc || i < 0)
			continue;

		u64 left_dsq_id = *MEMBER_VPTR(left->dsqs, [i]);
		left_queued += scx_bpf_dsq_nr_queued(left_dsq_id);
		left_load += *MEMBER_VPTR(left->dsq_load, [i]);
		u64 right_dsq_id = *MEMBER_VPTR(right->dsqs, [i]);
		right_queued += scx_bpf_dsq_nr_queued(right_dsq_id);
		right_load += *MEMBER_VPTR(right->dsq_load, [i]);
	}

	if (min_nr_queued_pick2 > 0 &&
	    (left_queued < min_nr_queued_pick2 &&
	     right_queued < min_nr_queued_pick2))
		return NULL;

	if (left_queued < right_queued || left_load > right_load)
		return most_loaded ? right : left;

	return most_loaded ? right : left;
}

static s32 pick_two_cpu(struct task_ctx *taskc, bool *is_idle)
{
	if ((min_llc_runs_pick2 > 0 && taskc->llc_runs < min_llc_runs_pick2) ||
	    !can_pick2(taskc))
		return -EINVAL;

	struct llc_ctx *chosen;
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
	u64 left_load = *MEMBER_VPTR(left->dsq_load, [dsq_index]);
	u64 right_dsq_id = *MEMBER_VPTR(right->dsqs, [dsq_index]);
	s32 right_queued = scx_bpf_dsq_nr_queued(right_dsq_id);
	u64 right_load = *MEMBER_VPTR(right->dsq_load, [dsq_index]);

	if (((left_queued > 0 || right_queued > 0) &&
	    left_queued < right_queued) ||
	    left_load > right_load) {
		chosen = left;
		goto pick_llc;
	} else {
		chosen = right;
		goto pick_llc;
	}

pick_llc:
	if (!chosen)
		return -EINVAL;

	if (!chosen->cpumask)
		return -EINVAL;

	cpu = scx_bpf_pick_idle_cpu(cast_mask(chosen->cpumask), 0);
	if (cpu < nr_cpus && cpu >= 0) {
		*is_idle = true;
		return cpu;
	}

	// couldn't find idle, but still return a CPU.
	if (!chosen->cpumask)
		return -EINVAL;
	cpu = bpf_cpumask_any_distribute(cast_mask(chosen->cpumask));
	if (cpu < nr_cpus)
		return cpu;

	return -EINVAL;
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

	idle_cpumask = scx_bpf_get_idle_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();

	if (!idle_cpumask || !idle_smtmask || bpf_cpumask_empty(idle_cpumask))
		goto out_put_cpumask;

	if (!(prev_cpuc = lookup_cpu_ctx(prev_cpu)) ||
	    !(llcx = lookup_llc_ctx(prev_cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(prev_cpuc->node_id)) ||
	    !llcx->cpumask)
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
		struct task_struct *current = (void *)bpf_get_current_task_btf();
		if (!current)
			goto out_put_cpumask;

		struct task_ctx *cur_taskc = lookup_task_ctx_may_fail(current);
		if (!cur_taskc)
			goto out_put_cpumask;

		// If the waking task is in the same LLC then use the current
		// CPU if available.
		s32 cur_cpu = bpf_get_smp_processor_id();
		if (llcx->id == cur_taskc->llc_id &&
		    scx_bpf_test_and_clear_cpu_idle(cur_cpu)) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	// If last CPU is idle then run again
	if (is_prev_llc_affine &&
	    bpf_cpumask_test_cpu(prev_cpu, smt_enabled ? idle_smtmask : idle_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (eager_load_balance && nr_llcs > 1) {
		llcx = pick_two_llc_ctx(rand_llc_ctx(), rand_llc_ctx(), false);
		if (!llcx) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}
	}

	if (has_little_cores) {
		if (!llcx->big_cpumask)
			goto out_put_cpumask;

		cpu = bpf_cpumask_any_and_distribute(smt_enabled ? idle_smtmask : idle_cpumask,
						     cast_mask(llcx->big_cpumask));
		if (cpu < nr_cpus) {
			*is_idle = true;
			goto out_put_cpumask;
		}

		if (!nodec->big_cpumask)
			goto out_put_cpumask;

		/*
		 * Next try a big core in the local node.
		 */
		if (!interactive) {
			cpu = bpf_cpumask_any_and_distribute(smt_enabled ? idle_smtmask : idle_cpumask,
							     cast_mask(nodec->big_cpumask));
			if (cpu < nr_cpus) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}
	}

	if (smt_enabled) {
		if (is_prev_llc_affine &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	if (!llcx->cpumask)
		goto out_put_cpumask;

	// Next try in the local LLC.
	cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->cpumask), SCX_PICK_IDLE_CORE);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (interactive_sticky && interactive) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	// Greedy idle tries to grab any idle CPU in the LLC
	if (greedy_idle && llcx->cpumask) {
		cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->cpumask), 0);
		if (cpu >= 0) {
			*is_idle = true;
			stat_inc(P2DQ_STAT_GREEDY_IDLE);
			goto out_put_cpumask;
		}
	}

	if (!nodec->cpumask)
		goto out_put_cpumask;

	cpu = scx_bpf_pick_idle_cpu(cast_mask(nodec->cpumask), SCX_PICK_IDLE_CORE);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (nr_llcs > 1) {
		// Try to keep interactive tasks local to the LLC and let non
		// interactive tasks load balance via pick2.
		if (interactive && nodec->cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(nodec->cpumask), 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		} else {
			cpu = pick_two_cpu(taskc, is_idle);
			if (cpu >= 0) {
				stat_inc(P2DQ_STAT_SELECT_PICK2);
				goto out_put_cpumask;
			}
		}
	}

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
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
		stat_inc(P2DQ_STAT_IDLE);
		u64 slice_ns = dsq_time_slice(taskc->dsq_index);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns, 0);
	}

	return cpu;
}


void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	const struct cpumask *idle_cpumask, *llc_mask;
	struct llc_ctx *llcx, *prev_llcx;
	struct cpu_ctx *cpuc, *task_cpuc;
	struct task_ctx *taskc;
	u64 dsq_id;

	s32 cpu, task_cpu = scx_bpf_task_cpu(p);

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
		trace("vtime change %llu, new vtime %llu",
		      vtime_delta, p->scx.dsq_vtime);
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
	if ((p->flags & PF_KTHREAD) && (p->nr_cpus_allowed < nr_cpus) &&
	    kthreads_local) {
		stat_inc(P2DQ_STAT_DIRECT);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	/*
	 * Affinitized tasks just get dispatched directly, need to handle this
	 * better.
	 */
	if ((!taskc->all_cpus)) {
		stat_inc(P2DQ_STAT_DIRECT);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	dsq_id = cpu_dsq_id(taskc->dsq_index, cpuc);
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, enq_flags);
	if (taskc->dsq_index < 0 || taskc->dsq_index >= nr_dsqs_per_llc) {
		scx_bpf_error("can't happen");
		return;
	}

	if (vtime > llcx->dsq_max_vtime[taskc->dsq_index]) {
		llcx->dsq_max_vtime[taskc->dsq_index] = vtime;
		trace("LLC[%d]DSQ[%d] max_vtime %llu", llcx->id, dsq_id, vtime);
	}


	llc_mask = cast_mask(llcx->cpumask);
	if (!llc_mask) {
		scx_bpf_error("invalid llc cpumask");
		return;

	}

	idle_cpumask = scx_bpf_get_idle_cpumask();
	cpu = bpf_cpumask_any_and_distribute(llc_mask, idle_cpumask);
	scx_bpf_put_cpumask(idle_cpumask);

	// If there is an idle CPU in the LLC kick it.
	if (cpu < nr_cpus)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
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

	if (taskc->llc_id != cpuc->llc_id) {
		taskc->llc_runs = 0;
		stat_inc(P2DQ_STAT_LLC_MIGRATION);
		trace("RUNNING %d cpu %d->%d llc %d->%d",
		      p->pid, cpuc->id, taskc->cpu,
		      taskc->llc_id, llcx->id);
	} else {
		taskc->llc_runs += 1;
	}
	if (taskc->node_id != cpuc->node_id) {
		stat_inc(P2DQ_STAT_NODE_MIGRATION);
	}

	taskc->last_run_at = scx_bpf_now();
	taskc->llc_id = llcx->id;
	taskc->node_id = llcx->node_id;
	cpuc->dsq_index = taskc->dsq_index;
	cpuc->ran_for = 0;
	taskc->cpu = task_cpu;
	// racy, but don't care
	if (p->scx.dsq_vtime > llcx->vtime)
		__sync_val_compare_and_swap(&llcx->vtime, llcx->vtime, p->scx.dsq_vtime);
	else
		p->scx.dsq_vtime = llcx->vtime;

	if (sched_mode == MODE_PERFORMANCE && taskc->dsq_index == 0) {
		scx_bpf_cpuperf_set(task_cpu, 1024);
	}
}


void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 used, last_dsq_slice_ns;
	u64 now = scx_bpf_now();

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(cpuc = lookup_cpu_ctx(-1)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	last_dsq_slice_ns = dsq_time_slice(taskc->dsq_index);

	// can't happen, appease the verifier
	int dsq_index = taskc->dsq_index;
	if (dsq_index < 0 || dsq_index >= nr_dsqs_per_llc) {
		scx_bpf_error("taskc invalid dsq index");
		return;
	}

	used = now - taskc->last_run_at;
	p->scx.dsq_vtime = scale_by_task_weight(p, used);
	taskc->last_dsq_id = taskc->dsq_id;
	taskc->last_dsq_index = dsq_index;
	__sync_fetch_and_add(&llcx->vtime, used);
	__sync_fetch_and_add(&llcx->dsq_max_vtime[dsq_index], used);
	__sync_fetch_and_add(&llcx->dsq_load[dsq_index], used);

	// On stopping determine if the task can move to a longer DSQ by
	// comparing the used time to the scaled DSQ slice.
	if (used >= ((9 * last_dsq_slice_ns) / 10)) {
		if (taskc->dsq_index < nr_dsqs_per_llc - 1) {
			taskc->dsq_index += 1;
			stat_inc(P2DQ_STAT_DSQ_CHANGE);
			trace("%s[%p]: DSQ change %u -> %u, slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_index, dsq_time_slice(taskc->dsq_index));
		} else {
			stat_inc(P2DQ_STAT_DSQ_SAME);
		}
	// If under half the slice was consumed move the task back down.
	} else if (used < last_dsq_slice_ns / 2) {
		if (taskc->dsq_index > 0) {
			taskc->dsq_index -= 1;
			stat_inc(P2DQ_STAT_DSQ_CHANGE);
			trace("%s[%p]: DSQ change %u -> %u slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_index, dsq_time_slice(taskc->dsq_index));
		} else {
			stat_inc(P2DQ_STAT_DSQ_SAME);
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

	u64 min_vtime = llcx->vtime;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		if (llcx->dsq_max_vtime[i] < min_vtime) {
			min_vtime = llcx->dsq_max_vtime[i];
			dsq_id = llcx->dsqs[i];
		}
	}

	if (scx_bpf_dsq_move_to_local(dsq_id))
		return;

	// Try the last DSQ, this is to keep tasks sticky to their dsq type.
	if (cpuc->dsq_index >= 0 && cpuc->dsq_index < nr_dsqs_per_llc &&
	    scx_bpf_dsq_move_to_local(cpuc->dsqs[cpuc->dsq_index]))
		return;

	bpf_for(i, 0, nr_dsqs_per_llc) {
		if (i != cpuc->dsq_index &&
		    i != dsq_id &&
		    scx_bpf_dsq_move_to_local(cpuc->dsqs[i]))
		    return;
	}

	// If on a single LLC there isn't anything left to try.
	if (nr_llcs == 1 || dispatch_pick2_disable)
		return;

	// Last ditch effort try consuming from the most loaded DSQ.
	llcx = pick_two_llc_ctx(rand_llc_ctx(), rand_llc_ctx(), false);
	if (!llcx || cpuc->dsq_index < 0 || cpuc->dsq_index > nr_dsqs_per_llc)
		return;

	// Start with least interactive DSQs to avoid migrating interactive
	// tasks.
	bpf_for(i, 1, nr_dsqs_per_llc) {
		if (scx_bpf_dsq_move_to_local(llcx->dsqs[nr_dsqs_per_llc - i])) {
			stat_inc(P2DQ_STAT_DISPATCH_PICK2);
			return;
		}
	}
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)) || !all_cpumask)
		return;

	taskc->all_cpus = p->nr_cpus_allowed == nr_cpus;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct bpf_cpumask *cpumask;
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;

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

	if (!(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return -EINVAL;

	taskc->cpu = task_cpu;
	taskc->dsq_id = SCX_DSQ_INVALID;
	taskc->llc_id = cpuc->llc_id;
	taskc->node_id = cpuc->node_id;
	taskc->dsq_index = init_dsq_index;
	taskc->last_dsq_index = init_dsq_index;
	taskc->runnable = true;
	taskc->all_cpus = p->nr_cpus_allowed == nr_cpus;
	p->scx.dsq_vtime = llcx->vtime;

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
	struct node_ctx *nodec;
	struct llc_ctx *llcx;
	struct cpu_ctx *cpuc;

	if (!(cpuc = lookup_cpu_ctx(cpu)))
		return -ENOENT;

	cpuc->id = cpu;
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
		trace("CPU[%d] is big", cpu);
		bpf_rcu_read_lock();
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

	trace("CFG CPU[%d]NODE[%d]LLC[%d] initialized",
	    cpu, cpuc->node_id, cpuc->llc_id);

	return 0;
}

static bool load_balance_timer(void)
{
	struct llc_ctx *llcx;
	int llc_id, j;
	u64 ideal_sum, load_sum = 0, interactive_sum = 0;

	if (nr_llcs == 1 && !autoslice)
		return false;

	if (!autoslice)
		goto reset_load;

	bpf_for(llc_id, 0, nr_llcs) {
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return false;

		bpf_for(j, 0, nr_dsqs_per_llc) {
			load_sum += llcx->dsq_load[j];
			if (j == 0)
				interactive_sum += llcx->dsq_load[j];
		}
	}
	dbg("load %llu interactive %llu", load_sum, interactive_sum);

	if (load_sum == 0 || load_sum < interactive_sum)
		goto reset_load;

	if (interactive_sum == 0) {
		dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;
		bpf_for(j, 1, nr_dsqs_per_llc) {
			dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
		}
	} else {
		ideal_sum = (load_sum * interactive_ratio) / 100;
		dbg("ideal/sum %llu/%llu", ideal_sum, interactive_sum);
		if (interactive_sum < ideal_sum) {
			dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;

			bpf_for(j, 1, nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
			}
		} else {
			dsq_time_slices[0] = max((10 * dsq_time_slices[0]) / 11, min_slice_ns);
			bpf_for(j, 1, nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << dsq_shift;
			}
		}

	}


reset_load:

	bpf_for(llc_id, 0, nr_llcs) {
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return false;

		bpf_for(j, 0, nr_dsqs_per_llc) {
			llcx->dsq_load[j] = 0;
			if (llc_id == 0 && autoslice) {
				if (j > 0 && dsq_time_slices[j] < dsq_time_slices[j-1]) {
					dsq_time_slices[j] = dsq_time_slices[j-1] << dsq_shift;
				}
				dbg("interactive slice %llu", dsq_time_slices[j]);
			}
		}
	}

	return true;
}

static bool run_timer_cb(int key)
{
	switch (key) {
	case EAGER_LOAD_BALANCER_TMR:
		return load_balance_timer();
	default:
		return false;
	}
}


static int timer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	if (timerw->key < 0 || timerw->key > MAX_TIMERS) {
		return 0;
	}

	struct p2dq_timer *cb_timer = &p2dq_timers[timerw->key];
	bool resched = run_timer_cb(timerw->key);

	if (!resched || !cb_timer || cb_timer->interval_ns == 0) {
		trace("TIMER timer %d stopped", timerw->key);
		return 0;
	}

	bpf_timer_start(&timerw->timer,
			cb_timer->interval_ns,
			cb_timer->start_flags);

	return 0;
}


s32 static start_timers(void)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&timer_data, &timer_id);
		if (!timerw || timer_id < 0 || timer_id > MAX_TIMERS) {
			scx_bpf_error("Failed to lookup timer");
			return -ENOENT;
		}

		struct p2dq_timer *new_timer = &p2dq_timers[timer_id];
		if (!new_timer) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
		timerw->key = timer_id;

		err = bpf_timer_init(&timerw->timer, &timer_data, new_timer->init_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_set_callback(&timerw->timer, &timer_cb);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_start(&timerw->timer,
				      new_timer->interval_ns,
				      new_timer->start_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
	}

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
			llcx->vtime = 0;
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
	min_slice_ns = 1000 * min_slice_us;

	if (start_timers() < 0)
		return -EINVAL;

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
