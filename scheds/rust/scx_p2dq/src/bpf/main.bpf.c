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
#include "../../../../include/scx/bpf_arena_common.bpf.h"
#include "../../../../include/scx/percpu.bpf.h"
#include "../../../../include/lib/atq.h"
#include "../../../../include/lib/cpumask.h"
#include "../../../../include/lib/minheap.h"
#include "../../../../include/lib/percpu.h"
#include "../../../../include/lib/sdt_task.h"
#include "../../../../include/lib/topology.h"
#else
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/atq.h>
#include <lib/cpumask.h>
#include <lib/minheap.h>
#include <lib/percpu.h>
#include <lib/sdt_task.h>
#include <lib/topology.h>
#endif

#include "intf.h"
#include "types.h"


#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef P2DQ_CREATE_STRUCT_OPS
#define P2DQ_CREATE_STRUCT_OPS 1
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

const volatile struct {
	u32 nr_cpus;
	u32 nr_llcs;
	u32 nr_nodes;

	bool smt_enabled;
	bool has_little_cores;
} topo_config = {
	.nr_cpus = 64,
	.nr_llcs = 32,
	.nr_nodes = 32,

	.smt_enabled = true,
	.has_little_cores = false,
};

const volatile struct {
	u64 min_slice_us;
	u64 max_exec_ns;
	bool autoslice;
	bool deadline;
} timeline_config = {
	.min_slice_us = 100,
	.max_exec_ns = 20 * NSEC_PER_MSEC,
	.autoslice = true,
	.deadline = true,
};

const volatile struct {
	u64 backoff_ns;
	u64 dispatch_lb_busy;
	u64 min_llc_runs_pick2;
	u64 min_nr_queued_pick2;
	u64 slack_factor;
	u64 wakeup_lb_busy;

	bool dispatch_lb_interactive;
	bool dispatch_pick2_disable;
	bool eager_load_balance;
	bool max_dsq_pick2;
	bool wakeup_llc_migrations;
} lb_config = {
	.backoff_ns = 5LLU * NSEC_PER_MSEC,
	.dispatch_lb_busy = 75,
	.min_llc_runs_pick2 = 4,
	.min_nr_queued_pick2 = 10,
	.slack_factor = LOAD_BALANCE_SLACK,
	.wakeup_lb_busy = 90,

	.dispatch_lb_interactive = false,
	.dispatch_pick2_disable = false,
	.eager_load_balance = true,
	.max_dsq_pick2 = false,
	.wakeup_llc_migrations = false,
};

const volatile struct {
	u32 nr_dsqs_per_llc;
	int init_dsq_index;
	u64 dsq_shift;
	u32 interactive_ratio;
	u32 saturated_percent;
	u32 sched_mode;
	u32 llc_shards;

	bool atq_enabled;
	bool cpu_priority;
	bool task_slice;
	bool freq_control;
	bool interactive_sticky;
	bool keep_running_enabled;
	bool kthreads_local;
} p2dq_config = {
	.sched_mode = MODE_DEFAULT,
	.nr_dsqs_per_llc = 3,
	.init_dsq_index = 0,
	.dsq_shift = 2,
	.interactive_ratio = 10,
	.saturated_percent = 5,
	.llc_shards = 0,

	.atq_enabled = false,
	.cpu_priority = false,
	.task_slice = true,
	.freq_control = false,
	.interactive_sticky = false,
	.keep_running_enabled = true,
	.kthreads_local = true,
};

const volatile u32 debug = 2;
const u32 zero_u32 = 0;
extern const volatile u32 nr_cpu_ids;

const u64 lb_timer_intvl_ns = 250LLU * NSEC_PER_MSEC;

static u32 llc_lb_offset = 1;
static u64 min_llc_runs_pick2 = 1;
static bool saturated = false;
static bool overloaded = false;

u64 llc_ids[MAX_LLCS];
u32 cpu_core_ids[MAX_CPUS];
u64 cpu_llc_ids[MAX_CPUS];
u64 cpu_node_ids[MAX_CPUS];
u64 big_core_ids[MAX_CPUS];
u64 dsq_time_slices[MAX_DSQS_PER_LLC];

u64 min_slice_ns = 500;

private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *big_cpumask;

static u64 max(u64 a, u64 b)
{
	return a >= b ? a : b;
}

static u64 min(u64 a, u64 b)
{
	return a <= b ? a : b;
}

static __always_inline u64 dsq_time_slice(int dsq_index)
{
	if (dsq_index > p2dq_config.nr_dsqs_per_llc || dsq_index < 0) {
		scx_bpf_error("Invalid DSQ index");
		return 0;
	}
	return dsq_time_slices[dsq_index];
}

static __always_inline bool valid_dsq(u64 dsq_id)
{
	return dsq_id != 0 && dsq_id != SCX_DSQ_INVALID;
}

static __always_inline u64 max_dsq_time_slice(void)
{
	return dsq_time_slices[p2dq_config.nr_dsqs_per_llc - 1];
}

static __always_inline u64 min_dsq_time_slice(void)
{
	return dsq_time_slices[0];
}

static __always_inline u64 clamp_slice(u64 slice_ns)
{
	return min(max(min_dsq_time_slice(), slice_ns),
		   max_dsq_time_slice());
}

static __always_inline u64 shard_dsq_id(u32 llc_id, u32 shard_id)
{
	return ((MAX_DSQS_PER_LLC * MAX_LLCS) << 3) + (llc_id * MAX_DSQS_PER_LLC) + shard_id;
}

static __always_inline u64 cpu_dsq_id(s32 cpu)
{
	return ((MAX_DSQS_PER_LLC * MAX_LLCS) << 2) + cpu;
}

static __always_inline u32 wrap_index(u32 index, u32 min, u32 max)
{
	if (min > max) {
		scx_bpf_error("invalid min");
		return min;
	}
	u32 range = max - min + 1;
	return min + (index % range);
}

static __always_inline s32 __pick_idle_cpu(struct bpf_cpumask *mask, int flags)
{
	return scx_bpf_pick_idle_cpu(cast_mask(mask), flags);
}

static int init_cpumask(struct bpf_cpumask **mask_p)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(mask_p, cpumask);
	if (cpumask) {
		bpf_cpumask_release(cpumask);
		return -ENOMEM;
	}

	return 0;
}

static s32 pref_idle_cpu(struct llc_ctx *llcx)
{
	struct scx_minheap_elem helem;
	int ret;

	if ((ret = arena_spin_lock((void __arena *)&llcx->idle_lock)))
		return ret;
	ret = scx_minheap_pop(llcx->idle_cpu_heap, &helem);
	arena_spin_unlock((void __arena *)&llcx->idle_lock);
	if (ret)
		return -EINVAL;

	return (s32)helem.elem;
}

static u32 nr_idle_cpus(const struct cpumask *idle_cpumask)
{
	u32 nr_idle;

	nr_idle = bpf_cpumask_weight(idle_cpumask);

	return nr_idle;
}

static u32 idle_cpu_percent(const struct cpumask *idle_cpumask)
{
	return (100 * nr_idle_cpus(idle_cpumask)) / topo_config.nr_cpus;
}

static u64 task_slice_ns(struct task_struct *p, u64 slice_ns)
{
	return clamp_slice(scale_by_task_weight(p, slice_ns));
}

static u64 task_dsq_slice_ns(struct task_struct *p, int dsq_index)
{
	return task_slice_ns(p, dsq_time_slice(dsq_index));
}

static void task_refresh_llc_runs(task_ctx *taskc)
{
	taskc->llc_runs = min_llc_runs_pick2;
}

static u64 llc_nr_queued(struct llc_ctx *llcx)
{
	if (!llcx)
		return 0;

	u64 nr_queued = scx_bpf_dsq_nr_queued(llcx->dsq);

	if (topo_config.nr_llcs > 1) {
		if (p2dq_config.atq_enabled)
			nr_queued += scx_atq_nr_queued(llcx->mig_atq);
		else
			nr_queued += scx_bpf_dsq_nr_queued(llcx->mig_dsq);
	}

	return nr_queued;
}

static int llc_create_atqs(struct llc_ctx *llcx)
{
	if (!p2dq_config.atq_enabled)
		return 0;

	if (topo_config.nr_llcs > 1) {
		llcx->mig_atq = (scx_atq_t *)scx_atq_create_size(false,
								 topo_config.nr_cpus);
		if (!llcx->mig_atq) {
			scx_bpf_error("ATQ failed to create ATQ for LLC %u",
				      llcx->id);
			return -ENOMEM;
		}
		trace("ATQ mig_atq %llu created for LLC %llu",
		      (u64)llcx->mig_atq, llcx->id);
	}

	return 0;
}

struct p2dq_timer p2dq_timers[MAX_TIMERS] = {
	{lb_timer_intvl_ns,
	     CLOCK_BOOTTIME, 0},
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

	if (cpu < 0) {
		cpuc = bpf_map_lookup_elem(&cpu_ctxs, &zero_u32);
	} else {
		cpuc = bpf_map_lookup_percpu_elem(&cpu_ctxs,
						  &zero_u32, cpu);
	}

	if (!cpuc) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cpuc;
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

static struct llc_ctx *lookup_cpu_llc_ctx(s32 cpu)
{
	if (cpu >= topo_config.nr_cpus || cpu < 0) {
		scx_bpf_error("invalid CPU");
		return NULL;
	}

	return lookup_llc_ctx(cpu_llc_ids[cpu]);
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

struct mask_wrapper {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mask_wrapper);
} task_masks SEC(".maps");

static task_ctx *lookup_task_ctx(struct task_struct *p)
{
	task_ctx *taskc = scx_task_data(p);

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
static bool is_interactive(task_ctx *taskc)
{
	if (p2dq_config.nr_dsqs_per_llc <= 1)
		return false;
	// For now only the shortest duration DSQ is considered interactive.
	return taskc->dsq_index == 0;
}

/*
 * Returns if a task is allowed to run on all CPUs.
 */
static inline bool task_all_cpus(struct task_struct *p)
{
	return p->cpus_ptr == &p->cpus_mask &&
		p->nr_cpus_allowed == topo_config.nr_cpus;
}

/*
 * Runtime check during complete_p2dq_enqueue to validate that the task is
 * still able to run on the assigned DSQ. Returns the corrected DSQ if task
 * affinity has changed.
 */
static u64 task_enqueue_dsq(struct task_struct *p, u64 dsq_id)
{
	// If dispatching to a specific CPU via SCX_DSQ_LOCAL_ON,
	// re-validate that the task can still run there. Task affinity
	// may have changed between enqueue and completion.
	if (dsq_id & SCX_DSQ_LOCAL_ON) {
		s32 target_cpu = dsq_id & (~SCX_DSQ_LOCAL_ON);
		if (!bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr)) {
			stat_inc(P2DQ_STAT_AFFINITY_CHANGED);
			return SCX_DSQ_LOCAL;
		}
	}
	return dsq_id;
}


static bool can_migrate(task_ctx *taskc, struct llc_ctx *llcx)
{
	if (topo_config.nr_llcs < 2 ||
	    !taskc->all_cpus ||
	    (!lb_config.dispatch_lb_interactive && taskc->interactive))
		return false;

	if (lb_config.max_dsq_pick2 &&
	    taskc->dsq_index != p2dq_config.nr_dsqs_per_llc - 1)
		return false;

	if (taskc->llc_runs > 0)
		return false;

	if (saturated || overloaded)
		return true;

	return llcx->saturated;
}

static void set_deadline_slice(struct task_struct *p, task_ctx *taskc,
			       struct llc_ctx *llcx)
{
	u64 nr_idle;
	u64 max_ns = scale_by_task_weight(p, max_dsq_time_slice());
	u64 nr_queued = llc_nr_queued(llcx);

	const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
	nr_idle = bpf_cpumask_weight(idle_cpumask);
	scx_bpf_put_cpumask(idle_cpumask);

	if (nr_idle == 0)
		nr_idle = 1;

	if (nr_queued > nr_idle)
		taskc->slice_ns = (max_ns * nr_idle) / nr_queued;
	else
		taskc->slice_ns = max_ns;

	taskc->slice_ns = clamp_slice(taskc->slice_ns);
}

/*
 * Updates a tasks vtime based on the newly assigned cpu_ctx and returns the
 * updated vtime.
 */
static void update_vtime(struct task_struct *p, struct cpu_ctx *cpuc,
			 task_ctx *taskc, struct llc_ctx *llcx)
{
	/*
	 * If in the same LLC we only need to clamp the vtime to ensure no task
	 * accumulates too much vtime.
	 */
	if (taskc->llc_id == cpuc->llc_id) {
		if (p->scx.dsq_vtime >= llcx->vtime)
			return;

		u64 scaled_min = scale_by_task_weight(p, max_dsq_time_slice());

		if (p->scx.dsq_vtime < llcx->vtime - scaled_min)
			p->scx.dsq_vtime = llcx->vtime - scaled_min;

		return;
	}

	p->scx.dsq_vtime = llcx->vtime;

	return;
}

/*
 * Returns a random llc_ctx
 */
static struct llc_ctx *rand_llc_ctx(void)
{
	return lookup_llc_ctx(bpf_get_prandom_u32() % topo_config.nr_llcs);
}

static bool keep_running(struct cpu_ctx *cpuc, struct llc_ctx *llcx,
			 struct task_struct *p)
{
	// Only tasks in the most interactive DSQs can keep running.
	if (!p2dq_config.keep_running_enabled ||
	    !llcx || !cpuc ||
	    cpuc->dsq_index == p2dq_config.nr_dsqs_per_llc - 1 ||
	    p->scx.flags & SCX_TASK_QUEUED ||
	    cpuc->ran_for >= timeline_config.max_exec_ns)
		return false;

	int nr_queued = llc_nr_queued(llcx);

	if (nr_queued >= llcx->nr_cpus)
		return false;

	u64 slice_ns = task_slice_ns(p, cpuc->slice_ns);
	cpuc->ran_for += slice_ns;
	p->scx.slice = slice_ns;
	stat_inc(P2DQ_STAT_KEEP);
	return true;
}

static s32 pick_idle_affinitized_cpu(struct task_struct *p, task_ctx *taskc,
				     s32 prev_cpu, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct mask_wrapper *wrapper;
	struct bpf_cpumask *mask;
	struct llc_ctx *llcx;
	s32 cpu = prev_cpu;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();

	if (!(llcx = lookup_llc_ctx(taskc->llc_id)) ||
	    !llcx->cpumask)
		goto found_cpu;

	// First try last CPU
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		*is_idle = true;
		goto found_cpu;
	}

	wrapper = bpf_task_storage_get(&task_masks, p, 0, 0);
	if (!wrapper)
		goto found_cpu;

	mask = wrapper->mask;
	if (!mask)
		goto found_cpu;

	if (llcx->cpumask)
		bpf_cpumask_and(mask, cast_mask(llcx->cpumask),
				p->cpus_ptr);

	// First try to find an idle SMT in the LLC
	if (topo_config.smt_enabled) {
		cpu = __pick_idle_cpu(mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Next try to find an idle CPU in the LLC
	cpu = __pick_idle_cpu(mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Next try to find an idle CPU in the node
	if (llcx->node_cpumask && mask) {
		bpf_cpumask_and(mask,
				cast_mask(llcx->node_cpumask),
				p->cpus_ptr);

		cpu = __pick_idle_cpu(mask, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Fallback to anywhere the task can run
	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);

found_cpu:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	return cpu;
}

static s32 pick_idle_cpu(struct task_struct *p, task_ctx *taskc,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct llc_ctx *llcx;
	s32 pref_cpu, cpu = prev_cpu;
	bool migratable = false;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();

	if (!idle_cpumask || !idle_smtmask)
		goto found_cpu;

	if (p2dq_config.interactive_sticky && taskc->interactive) {
		*is_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
		goto found_cpu;
	}

	// First check if last CPU is idle
	if (bpf_cpumask_test_cpu(prev_cpu,
				 (topo_config.smt_enabled && !taskc->interactive) ?
				 idle_smtmask : idle_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		*is_idle = true;
		goto found_cpu;
	}

	if (!(llcx = lookup_llc_ctx(taskc->llc_id)) ||
	    !llcx->cpumask)
		goto found_cpu;

	migratable = can_migrate(taskc, llcx);
	if (topo_config.nr_llcs > 1 &&
	    (llcx->saturated || saturated || overloaded) &&
	    !migratable) {
		cpu = prev_cpu;
		goto found_cpu;
	}

	if (!valid_dsq(taskc->dsq_id))
		if (!(llcx = rand_llc_ctx()))
			goto found_cpu;

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		// Interactive tasks aren't worth migrating across LLCs.
		if (taskc->interactive ||
		    (topo_config.nr_llcs == 2 && topo_config.nr_nodes == 2)) {
			// Try an idle CPU in the LLC.
			if (llcx->cpumask &&
			    (cpu = __pick_idle_cpu(llcx->cpumask, 0)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		struct task_struct *waker = (void *)bpf_get_current_task_btf();
		task_ctx *waker_taskc = scx_task_data(waker);
		// Shouldn't happen, but makes code easier to follow
		if (!waker_taskc) {
			stat_inc(P2DQ_STAT_WAKE_PREV);
			goto found_cpu;
		}

		if (waker_taskc->llc_id == llcx->id ||
		    !lb_config.wakeup_llc_migrations) {
			// Try an idle smt core in the LLC.
			if (topo_config.smt_enabled &&
			    llcx->cpumask &&
			    (cpu = __pick_idle_cpu(llcx->cpumask,
						   SCX_PICK_IDLE_CORE)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Try an idle cpu in the LLC.
			if (llcx->cpumask &&
			    (cpu = __pick_idle_cpu(llcx->cpumask,
						   0)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		// If wakeup LLC are allowed then migrate to the waker llc.
		struct llc_ctx *waker_llcx = lookup_llc_ctx(waker_taskc->llc_id);
		if (!waker_llcx) {
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		if (waker_llcx->cpumask &&
		    (cpu = __pick_idle_cpu(waker_llcx->cpumask,
					   SCX_PICK_IDLE_CORE)
		     ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}

		// Couldn't find an idle core so just migrate to the CPU
		if (waker_llcx->cpumask &&
		    (cpu = __pick_idle_cpu(waker_llcx->cpumask,
					   0)
		     ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}

		// Nothing idle, move to waker CPU
		cpu = scx_bpf_task_cpu(waker);
		stat_inc(P2DQ_STAT_WAKE_MIG);
		goto found_cpu;
	}

	if (p2dq_config.sched_mode == MODE_PERF &&
	    topo_config.has_little_cores &&
	    llcx->big_cpumask) {
		cpu = __pick_idle_cpu(llcx->big_cpumask,
				      SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->big_cpumask) {
			cpu = __pick_idle_cpu(llcx->big_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}

	if (p2dq_config.sched_mode == MODE_EFFICIENCY &&
	    topo_config.has_little_cores &&
	    llcx->little_cpumask) {
		cpu = __pick_idle_cpu(llcx->little_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->little_cpumask) {
			cpu = __pick_idle_cpu(llcx->little_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}


	if (llcx->lb_llc_id < MAX_LLCS &&
	    taskc->llc_runs == 0) {
		u32 target_llc_id = llcx->lb_llc_id;
		llcx->lb_llc_id = MAX_LLCS;
		if (!(llcx = lookup_llc_ctx(target_llc_id)))
			goto found_cpu;
		stat_inc(P2DQ_STAT_SELECT_PICK2);
	}

	if (topo_config.has_little_cores &&
	    llcx->little_cpumask && llcx->big_cpumask) {
		if (taskc->interactive) {
			cpu = __pick_idle_cpu(llcx->little_cpumask,
					      0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		} else {
			cpu = __pick_idle_cpu(llcx->big_cpumask,
					      SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}

	if (p2dq_config.cpu_priority) {
		pref_cpu = pref_idle_cpu(llcx);
		if (llcx->cpumask && pref_cpu >= 0 &&
		    scx_bpf_test_and_clear_cpu_idle(pref_cpu)) {
			*is_idle = true;
			cpu = pref_cpu;
			trace("PREF idle %s->%d", p->comm, pref_cpu);
			goto found_cpu;
		}
	}

	// Next try in the local LLC
	if (llcx->cpumask &&
	    (cpu = __pick_idle_cpu(llcx->cpumask,
				   SCX_PICK_IDLE_CORE)
	     ) >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Try a idle CPU in the llc
	if (llcx->cpumask &&
	    (cpu = __pick_idle_cpu(llcx->cpumask, 0)) >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	if (topo_config.nr_llcs > 1 &&
	    llcx->saturated &&
	    migratable &&
	    llcx->node_cpumask) {
		cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->node_cpumask),
					    SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->node_cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(llcx->node_cpumask), 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
		if (saturated && migratable && all_cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(all_cpumask),
						    SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
			if (all_cpumask) {
				cpu = scx_bpf_pick_idle_cpu(cast_mask(all_cpumask), 0);
				if (cpu >= 0) {
					*is_idle = true;
					goto found_cpu;
				}
			}
		}
	}

	cpu = prev_cpu;

found_cpu:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	return cpu;
}


static s32 p2dq_select_cpu_impl(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	task_ctx *taskc;
	bool is_idle = false;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	if (!taskc->all_cpus)
		cpu = pick_idle_affinitized_cpu(p, taskc, prev_cpu, &is_idle);
	else
		cpu = pick_idle_cpu(p, taskc, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, taskc->slice_ns, 0);
	}
	trace("SELECT [%d][%s] %i->%i idle %i",
	      p->pid, p->comm, prev_cpu, cpu, is_idle);

	return cpu;
}


/*
 * Perform the enqueue logic for `p` but don't enqueue it where possible.  This
 * is primarily used so that scx_chaos can decide to enqueue a task either
 * immediately in `enqueue` or later in `dispatch`. This returns a tagged union
 * with three states:
 * - P2DQ_ENQUEUE_PROMISE_COMPLETE: The enqueue has been completed. Note that
 *     this case _must_ be determinstic, or else scx_chaos will stall. That is,
 *     if the same task and enq_flags arrive twice, it must have returned
 *     _COMPLETE the first time to return it again.
 * - P2DQ_ENQUEUE_PROMISE_FIFO: The completer should enqueue this task on a fifo dsq.
 * - P2DQ_ENQUEUE_PROMISE_VTIME: The completer should enqueue this task on a vtime dsq.
 * - P2DQ_ENQUEUE_PROMISE_FAILED: The enqueue failed.
 */
static void async_p2dq_enqueue(struct enqueue_promise *ret,
			       struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	task_ctx *taskc;
	s32 cpu = scx_bpf_task_cpu(p);

	// Default to 0 and set to failed.
	__builtin_memset(ret, 0, sizeof(*ret));
	ret->kind = P2DQ_ENQUEUE_PROMISE_FAILED;

	/*
	 * Per-cpu kthreads are considered interactive and dispatched directly
	 * into the local DSQ.
	 */
	if (p2dq_config.kthreads_local &&
	    (p->flags & PF_KTHREAD) &&
	    p->nr_cpus_allowed == 1) {
		stat_inc(P2DQ_STAT_DIRECT);
		u64 slice_ns = clamp_slice(scale_by_task_weight(p,
					   min_dsq_time_slice()));
		scx_bpf_dsq_insert(p,
				   SCX_DSQ_LOCAL,
				   slice_ns,
				   enq_flags);
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		return;
	}

	if(!(taskc = lookup_task_ctx(p))) {
		scx_bpf_error("invalid lookup");
		return;
	}

	// Handle affinitized tasks separately
	if (!taskc->all_cpus || !task_all_cpus(p)) {
		if (!__COMPAT_is_enq_cpu_selected(enq_flags) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			cpu = pick_idle_affinitized_cpu(p,
							taskc,
							cpu,
							&ret->has_cleared_idle);
		else
			ret->has_cleared_idle = scx_bpf_test_and_clear_cpu_idle(cpu);

		ret->cpu = cpu;
		if (!(cpuc = lookup_cpu_ctx(cpu)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
			scx_bpf_error("invalid lookup");
			return;
		}

		stat_inc(P2DQ_STAT_ENQ_CPU);
		taskc->dsq_id = cpuc->affn_dsq;
		update_vtime(p, cpuc, taskc, llcx);
		if (timeline_config.deadline)
			set_deadline_slice(p, taskc, llcx);

		if (cpuc->nice_task)
			enq_flags |= SCX_ENQ_PREEMPT;

		if (ret->has_cleared_idle || cpuc->nice_task) {
			ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
			ret->fifo.dsq_id = SCX_DSQ_LOCAL_ON|cpu;
			ret->fifo.slice_ns = taskc->slice_ns;
			ret->fifo.enq_flags = enq_flags;
			ret->kick_idle = ret->has_cleared_idle;
			return;
		}

		ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
		ret->vtime.dsq_id = taskc->dsq_id;
		ret->vtime.slice_ns = taskc->slice_ns;
		ret->vtime.enq_flags = enq_flags;
		ret->vtime.vtime = p->scx.dsq_vtime;

		trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
		      p->comm, p->scx.weight, taskc->slice_ns,
		      p->scx.dsq_vtime, llcx->vtime);

		return;
	}

	// If an idle CPU hasn't been found in select_cpu find one now
	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		cpu = pick_idle_cpu(p,
				    taskc,
				    cpu,
				    0,
				    &ret->has_cleared_idle);
		if (!(cpuc = lookup_cpu_ctx(cpu)) ||
		     !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
			scx_bpf_error("invalid lookup");
			return;
		}

		ret->cpu = cpu;
		update_vtime(p, cpuc, taskc, llcx);
		if (timeline_config.deadline)
			set_deadline_slice(p, taskc, llcx);

		if (cpuc->nice_task)
			enq_flags |= SCX_ENQ_PREEMPT;

		if (ret->has_cleared_idle || cpuc->nice_task) {
			ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
			ret->fifo.dsq_id = SCX_DSQ_LOCAL_ON|cpu;
			ret->fifo.slice_ns = taskc->slice_ns;
			ret->fifo.enq_flags = enq_flags;
			ret->kick_idle = ret->has_cleared_idle;
			return;
		}

		bool migrate = can_migrate(taskc, llcx);
		if (migrate) {
			taskc->dsq_id = llcx->mig_dsq;
			if (p2dq_config.atq_enabled) {
				taskc->enq_flags = enq_flags;
				ret->kind = P2DQ_ENQUEUE_PROMISE_ATQ_VTIME;
				ret->vtime.dsq_id = cpuc->llc_dsq;
				ret->vtime.atq = llcx->mig_atq;
				ret->vtime.slice_ns = taskc->slice_ns;
				ret->vtime.vtime = p->scx.dsq_vtime;
			} else {
				ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
				ret->vtime.dsq_id = taskc->dsq_id;
				ret->vtime.slice_ns = taskc->slice_ns;
				ret->vtime.enq_flags = enq_flags;
				ret->vtime.vtime = p->scx.dsq_vtime;
			}
			stat_inc(P2DQ_STAT_ENQ_MIG);
		} else {
			taskc->dsq_id = cpuc->llc_dsq;
			ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
			ret->vtime.dsq_id = taskc->dsq_id;
			ret->vtime.slice_ns = taskc->slice_ns;
			ret->vtime.enq_flags = enq_flags;
			ret->vtime.vtime = p->scx.dsq_vtime;
			stat_inc(P2DQ_STAT_ENQ_LLC);
		}

		trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
		      p->comm, p->scx.weight, taskc->slice_ns,
		      p->scx.dsq_vtime, llcx->vtime);

		return;
	}

	if (!(cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p))) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
		scx_bpf_error("invalid lookup");
		return;
	}
	ret->cpu = cpuc->id;

	if (cpuc->nice_task)
		enq_flags |= SCX_ENQ_PREEMPT;

	update_vtime(p, cpuc, taskc, llcx);
	if (timeline_config.deadline)
		set_deadline_slice(p, taskc, llcx);

	ret->has_cleared_idle = scx_bpf_test_and_clear_cpu_idle(cpu);
	if (ret->has_cleared_idle || cpuc->nice_task) {
		ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
		ret->fifo.dsq_id = SCX_DSQ_LOCAL_ON|cpu;
		ret->fifo.slice_ns = taskc->slice_ns;
		ret->fifo.enq_flags = enq_flags;
		ret->kick_idle = ret->has_cleared_idle;
		return;
	}

	bool migrate = can_migrate(taskc, llcx);
	if (migrate) {
		taskc->dsq_id = llcx->mig_dsq;
		stat_inc(P2DQ_STAT_ENQ_MIG);
		if (p2dq_config.atq_enabled) {
			taskc->enq_flags = enq_flags;
			ret->kind = P2DQ_ENQUEUE_PROMISE_ATQ_VTIME;
			ret->vtime.dsq_id = cpuc->llc_dsq;
			ret->vtime.atq = llcx->mig_atq;
			ret->vtime.slice_ns = taskc->slice_ns;
			ret->vtime.vtime = p->scx.dsq_vtime;

			return;
		}
	} else {
		taskc->dsq_id = cpuc->llc_dsq;
		stat_inc(P2DQ_STAT_ENQ_LLC);
	}

	trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
	      p->comm, p->scx.weight, taskc->slice_ns,
	      p->scx.dsq_vtime, llcx->vtime);

	ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
	ret->vtime.dsq_id = taskc->dsq_id;
	ret->vtime.enq_flags = enq_flags;
	ret->vtime.slice_ns = taskc->slice_ns;
	ret->vtime.vtime = p->scx.dsq_vtime;
}

static void complete_p2dq_enqueue(struct enqueue_promise *pro, struct task_struct *p)
{
	int ret;

	switch (pro->kind) {
	case P2DQ_ENQUEUE_PROMISE_COMPLETE:
		break;
	case P2DQ_ENQUEUE_PROMISE_FIFO:
		scx_bpf_dsq_insert(p,
				   task_enqueue_dsq(p, pro->fifo.dsq_id),
				   pro->fifo.slice_ns,
				   pro->fifo.enq_flags);
		break;
	case P2DQ_ENQUEUE_PROMISE_VTIME:
		scx_bpf_dsq_insert_vtime(p,
					 task_enqueue_dsq(p, pro->vtime.dsq_id),
					 pro->vtime.slice_ns,
				         pro->vtime.vtime,
					 pro->vtime.enq_flags);
		break;
	case P2DQ_ENQUEUE_PROMISE_ATQ_FIFO:
		if (!pro->fifo.atq) {
			scx_bpf_error("invalid ATQ");
			break;
		}
		ret = scx_atq_insert(pro->fifo.atq, (u64)p->pid);
		if (!ret) {
			// The ATQ was full, fallback to the DSQ.
			scx_bpf_dsq_insert(p,
					   task_enqueue_dsq(p, pro->vtime.dsq_id),
					   pro->vtime.slice_ns,
					   pro->vtime.enq_flags);
			stat_inc(P2DQ_STAT_ATQ_REENQ);
		} else {
			stat_inc(P2DQ_STAT_ATQ_ENQ);
		}
		break;
	case P2DQ_ENQUEUE_PROMISE_ATQ_VTIME:
		if (!pro->vtime.atq) {
			scx_bpf_error("invalid ATQ");
			break;
		}
		ret = scx_atq_insert_vtime(pro->vtime.atq,
					   (u64)p->pid,
					   pro->vtime.vtime);
		if (!ret) {
			// The ATQ was full, fallback to the DSQ.
			scx_bpf_dsq_insert_vtime(p,
						 task_enqueue_dsq(p, pro->vtime.dsq_id),
						 pro->vtime.slice_ns,
						 pro->vtime.vtime,
						 pro->vtime.enq_flags);
			stat_inc(P2DQ_STAT_ATQ_REENQ);
		} else {
			stat_inc(P2DQ_STAT_ATQ_ENQ);
		}
		break;
	case P2DQ_ENQUEUE_PROMISE_FAILED:
		// should have already errored with a more specific error, but
		// just for luck.
		scx_bpf_error("p2dq enqueue failed");
		break;
	}

	if (pro->kick_idle) {
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_kick_cpu(pro->cpu, SCX_KICK_IDLE);
	}

	pro->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
}

static int p2dq_running_impl(struct task_struct *p)
{
	task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(taskc = lookup_task_ctx(p)) ||
	    !(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return -EINVAL;

	if (taskc->llc_id != cpuc->llc_id) {
		task_refresh_llc_runs(taskc);
		stat_inc(P2DQ_STAT_LLC_MIGRATION);
		trace("RUNNING %d cpu %d->%d llc %d->%d",
		      p->pid, cpuc->id, task_cpu,
		      taskc->llc_id, llcx->id);
	} else {
		if (taskc->llc_runs == 0)
			task_refresh_llc_runs(taskc);
		else
			taskc->llc_runs -= 1;
	}
	if (taskc->node_id != cpuc->node_id) {
		stat_inc(P2DQ_STAT_NODE_MIGRATION);
	}

	taskc->llc_id = llcx->id;
	taskc->node_id = llcx->node_id;
	taskc->was_nice = p->scx.weight < 100;
	cpuc->interactive = taskc->interactive;
	cpuc->dsq_index = taskc->dsq_index;
	cpuc->nice_task = p->scx.weight < 100;
	cpuc->slice_ns = taskc->slice_ns;
	cpuc->ran_for = 0;
	// racy, but don't care
	if (p->scx.dsq_vtime > llcx->vtime &&
	    p->scx.dsq_vtime < llcx->vtime + max_dsq_time_slice()) {
		__sync_val_compare_and_swap(&llcx->vtime,
					    llcx->vtime, p->scx.dsq_vtime);
	}

	// If the task is running in the least interactive DSQ, bump the
	// frequency.
	if (p2dq_config.freq_control &&
	    taskc->dsq_index == p2dq_config.nr_dsqs_per_llc - 1) {
		scx_bpf_cpuperf_set(task_cpu, SCX_CPUPERF_ONE);
	}

	u64 now = bpf_ktime_get_ns();
	if (taskc->last_run_started == 0)
		taskc->last_run_started = now;

	taskc->last_run_at = now;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	task_ctx *taskc;
	struct llc_ctx *llcx;
	struct cpu_ctx *cpuc;
	u64 used, scaled_used, last_dsq_slice_ns;
	u64 now = bpf_ktime_get_ns();

	if (!(taskc = lookup_task_ctx(p)) ||
	    !(llcx = lookup_llc_ctx(taskc->llc_id)))
		return;

	// can't happen, appease the verifier
	int dsq_index = taskc->dsq_index;
	if (dsq_index < 0 || dsq_index >= p2dq_config.nr_dsqs_per_llc) {
		scx_bpf_error("taskc invalid dsq index");
		return;
	}

	// This is an optimization to not have to lookup the cpu_ctx every
	// time. When a nice task was run we need to update the cpu_ctx so that
	// tasks are no longer enqueued to the local DSQ.
	if (taskc->was_nice &&
	    (cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p)))) {
		cpuc->nice_task = false;
		taskc->was_nice = false;
	}

	taskc->last_dsq_id = taskc->dsq_id;
	taskc->last_dsq_index = taskc->dsq_index;
	taskc->used = 0;

	last_dsq_slice_ns = taskc->slice_ns;
	used = now - taskc->last_run_at;
	scaled_used = scale_by_task_weight_inverse(p, used);

	p->scx.dsq_vtime += scaled_used;
	__sync_fetch_and_add(&llcx->vtime, used);
	__sync_fetch_and_add(&llcx->load, used);
	if (taskc->dsq_index >= 0 && taskc->dsq_index < MAX_DSQS_PER_LLC)
		__sync_fetch_and_add(&llcx->dsq_load[taskc->dsq_index], used);

	if (taskc->interactive)
		__sync_fetch_and_add(&llcx->intr_load, used);

	if (!taskc->all_cpus)
		// Note that affinitized load is absolute load, not scaled.
		__sync_fetch_and_add(&llcx->affn_load, used);

	trace("STOPPING %s weight %d slice %llu used %llu scaled %llu",
	      p->comm, p->scx.weight, last_dsq_slice_ns, used, scaled_used);

	if (!runnable) {
		used = now - taskc->last_run_started;
		// On stopping determine if the task can move to a longer DSQ by
		// comparing the used time to the scaled DSQ slice.
		if (used >= ((9 * last_dsq_slice_ns) / 10)) {
			if (taskc->dsq_index < p2dq_config.nr_dsqs_per_llc - 1 &&
			    p->scx.weight >= 100) {
				taskc->dsq_index += 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ inc %llu -> %u", p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		// If under half the slice was consumed move the task back down.
		} else if (used < last_dsq_slice_ns / 2) {
			if (taskc->dsq_index > 0) {
				taskc->dsq_index -= 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ dec %llu -> %u",
				      p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		} else {
			stat_inc(P2DQ_STAT_DSQ_SAME);
		}

		// nice tasks can only get the minimal amount of non
		// interactive slice.
		if (p->scx.weight < 100 && taskc->dsq_index > 1)
			taskc->dsq_index = 1;

		if (p2dq_config.task_slice) {
			if (used >= ((7 * last_dsq_slice_ns) / 8)) {
				taskc->slice_ns = clamp_slice((5 * taskc->slice_ns) >> 2);
			} else if (used < last_dsq_slice_ns / 2) {
				taskc->slice_ns = clamp_slice((7 * taskc->slice_ns) >> 3);
			}
		} else {
			taskc->slice_ns = task_dsq_slice_ns(p, taskc->dsq_index);
		}
		taskc->last_run_started = 0;
		taskc->interactive = is_interactive(taskc);
	}
}

static bool consume_llc(struct llc_ctx *llcx)
{
	struct task_struct *p;
	task_ctx *taskc;
	u64 pid;

	if (!llcx)
		return false;

	if (p2dq_config.atq_enabled &&
	    scx_atq_nr_queued(llcx->mig_atq) > 0) {
		pid = scx_atq_pop(llcx->mig_atq);
		p = bpf_task_from_pid((s32)pid);
		if (!p) {
			trace("ATQ failed to get pid %llu", pid);
			return false;
		}

		if (!(taskc = lookup_task_ctx(p))) {
			bpf_task_release(p);
			return false;
		}

		trace("ATQ %llu insert %s->%d",
		      llcx->mig_atq, p->comm, p->pid);
		scx_bpf_dsq_insert(p,
				   SCX_DSQ_LOCAL,
				   taskc->slice_ns,
				   taskc->enq_flags);
		bpf_task_release(p);

		return false;
	}

	if (scx_bpf_dsq_move_to_local(llcx->mig_dsq)) {
		stat_inc(P2DQ_STAT_DISPATCH_PICK2);
		return true;
	}

	return false;
}

static __always_inline int dispatch_pick_two(s32 cpu, struct llc_ctx *cur_llcx, struct cpu_ctx *cpuc)
{
	struct llc_ctx *first, *second, *left, *right;
	int i;
	u64 cur_load;

	if (!cur_llcx || !cpuc)
		return -EINVAL;

	// If on a single LLC there isn't anything left to try.
	if (topo_config.nr_llcs == 1 ||
	    lb_config.dispatch_pick2_disable ||
	    topo_config.nr_llcs >= MAX_LLCS)
		return -EINVAL;


	if (lb_config.min_nr_queued_pick2 > 0) {
		u64 nr_queued = llc_nr_queued(cur_llcx);
		if (nr_queued < lb_config.min_nr_queued_pick2)
			return -EINVAL;
	}

	if (lb_config.backoff_ns > 0) {
		u64 now = scx_bpf_now();
		if (now - cur_llcx->last_period_ns < lb_config.backoff_ns)
			return -EINVAL;
	}

	/*
	 * For pick two load balancing we randomly choose two LLCs. We then
	 * first try to consume from the LLC with the largest load. If we are
	 * unable to consume from the first LLC then the second LLC is consumed
	 * from. This yields better work conservation on machines with a large
	 * number of LLCs.
	 */
	left = topo_config.nr_llcs == 2 ? lookup_llc_ctx(llc_ids[0]) : rand_llc_ctx();
	right = topo_config.nr_llcs == 2 ? lookup_llc_ctx(llc_ids[1]) : rand_llc_ctx();

	if (!left || !right)
		return -EINVAL;

	if (left->id == right->id) {
		i = cur_llcx->load % topo_config.nr_llcs;
		i &= 0x3; // verifier
		if (i >= 0 && i < topo_config.nr_llcs)
			right = lookup_llc_ctx(llc_ids[i]);
		if (!right)
			return -EINVAL;
	}


	if (right->load > left->load) {
		first = right;
		second = left;
	} else {
		first = left;
		second = right;
	}

	// Handle the edge case where there are two LLCs and the current has
	// more load. Since it's already been checked start with the other LLC.
	if (topo_config.nr_llcs == 2 && first->id == cur_llcx->id) {
		first = second;
		second = cur_llcx;
	}

	trace("PICK2 cpu[%d] first[%d] %llu second[%d] %llu",
	      cpu, first->id, first->load, second->id, second->load);

	cur_load = cur_llcx->load + ((cur_llcx->load * lb_config.slack_factor) / 100);

	if (first->load >= cur_load &&
	    consume_llc(first))
		return 0;

	if (second->load >= cur_load &&
	    consume_llc(second))
		return 0;

	if (saturated) {
		if (consume_llc(first))
			return 0;

		if (consume_llc(second))
			return 0;

		// If the system is saturated then be aggressive in trying to load balance.
		if (topo_config.nr_llcs > 2 &&
		    (first = rand_llc_ctx()) &&
		    consume_llc(first))
			return 0;
	}

	return 0;
}


static void p2dq_dispatch_impl(s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;
	task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 pid, peeked_pid, dsq_id = 0;
	scx_atq_t *min_atq = NULL;

	if (!(cpuc = lookup_cpu_ctx(cpu))) {
		scx_bpf_error("can't happen");
		return;
	}

	u64 min_vtime = 0;

	if (!saturated) {
		// First search affinitized DSQ
		bpf_for_each(scx_dsq, p, cpuc->affn_dsq, 0) {
			if (p->scx.dsq_vtime < min_vtime || min_vtime == 0) {
				min_vtime = p->scx.dsq_vtime;
				dsq_id = cpuc->affn_dsq;
			}
			break;
		}

		// LLC DSQ
		bpf_for_each(scx_dsq, p, cpuc->llc_dsq, 0) {
			if (p->scx.dsq_vtime < min_vtime || min_vtime == 0) {
				min_vtime = p->scx.dsq_vtime;
				dsq_id = cpuc->llc_dsq;
			}
			break;
		}

		// Migration eligible
		if (topo_config.nr_llcs > 1) {
			if (p2dq_config.atq_enabled) {
				pid = scx_atq_peek(cpuc->mig_atq);
				if ((p = bpf_task_from_pid((s32)pid))) {
					if (p->scx.dsq_vtime < min_vtime ||
					    min_vtime == 0) {
						min_vtime = p->scx.dsq_vtime;
						min_atq = cpuc->mig_atq;
						/*
						 * Normally doing these peeks would be
						 * racy with scx_bpf_dsq_move_to_local.
						 * However, with ATQs we can peek and
						 * pop so we can check that the popped
						 * task is the same as the peeked task.
						 * This gives slightly better
						 * prioritization with the potential
						 * cost of having to reenqueue popped
						 * tasks.
						 */
						peeked_pid = p->pid;
					}
					bpf_task_release(p);
				}
			} else {
				bpf_for_each(scx_dsq, p, cpuc->mig_dsq, 0) {
					if (p->scx.dsq_vtime < min_vtime ||
					    min_vtime == 0) {
						min_vtime = p->scx.dsq_vtime;
						dsq_id = cpuc->mig_dsq;
					}
					break;
				}
			}
		}
	}

	if (dsq_id != 0)
		trace("DISPATCH cpu[%d] min_vtime %llu dsq_id %llu atq %llu",
		      cpu, min_vtime, dsq_id, min_atq);

	// First try the DSQ with the lowest vtime for fairness.
	if (min_atq) {
		trace("ATQ dispatching %llu with min vtime %llu", min_atq, min_vtime);
		pid = scx_atq_pop(min_atq);
		if ((p = bpf_task_from_pid((s32)pid))) {
			/*
			 * Need to ensure the peeked_pid is the pid popped off
			 * the ATQ. Otherwise there may be priority inversions.
			 * This probably needs to be done for the DSQs as well.
			 */
			if (!(taskc = lookup_task_ctx(p))) {
				bpf_task_release(p);
				scx_bpf_error("failed to get task ctx");
				return;
			}
			if (p->pid == peeked_pid) {
				scx_bpf_dsq_insert(p,
						   SCX_DSQ_LOCAL,
						   taskc->slice_ns,
						   taskc->enq_flags);
				bpf_task_release(p);
				return;
			} else {
				/*
				 * The task that was popped was already
				 * consumed. The next task that was popped
				 * might have a higher vtime so reenqueue it
				 * back to the LLC DSQ.
				 */
				scx_bpf_dsq_insert_vtime(p,
						   cpuc->llc_dsq,
						   taskc->slice_ns,
						   p->scx.dsq_vtime,
						   taskc->enq_flags);
				bpf_task_release(p);
				stat_inc(P2DQ_STAT_ATQ_REENQ);
			}
		}
	} else {
		if (valid_dsq(dsq_id) && scx_bpf_dsq_move_to_local(dsq_id))
			return;
	}

	if (dsq_id != cpuc->affn_dsq &&
	    scx_bpf_dsq_move_to_local(cpuc->affn_dsq))
		return;

	// Handle sharded LLC DSQs, try to dispatch from all shards if sharding
	// is enabled
	if (p2dq_config.llc_shards > 1) {
		// First try the current CPU's assigned shard
		if (dsq_id != cpuc->llc_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->llc_dsq))
			return;

		if ((llcx = lookup_llc_ctx(cpuc->llc_id)) && llcx->nr_shards > 1) {
			// Then try other shards in the LLC for work stealing
			u32 shard_idx;
			bpf_for(shard_idx, 0, llcx->nr_shards) {
				u32 offset = cpuc->id % llcx->nr_shards;
				shard_idx = wrap_index(offset + shard_idx, 0, llcx->nr_shards);
				// TODO: should probably take min vtime to be fair
				if (shard_idx < MAX_LLC_SHARDS && shard_idx < llcx->nr_shards) {
					u64 shard_dsq = *MEMBER_VPTR(llcx->shard_dsqs, [shard_idx]);
					if (shard_dsq != cpuc->llc_dsq && shard_dsq != dsq_id &&
					    scx_bpf_dsq_move_to_local(shard_dsq))
						return;
				}
			}
		}
	} else {
		if (dsq_id != cpuc->llc_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->llc_dsq))
			return;
	}

	if (p2dq_config.atq_enabled) {
		pid = scx_atq_pop(cpuc->mig_atq);
		if ((p = bpf_task_from_pid((s32)pid))) {
			if (!(taskc = lookup_task_ctx(p))) {
				bpf_task_release(p);
				scx_bpf_error("failed to get task ctx");
				return;
			}
			scx_bpf_dsq_insert(p,
					   SCX_DSQ_LOCAL,
					   taskc->slice_ns,
					   taskc->enq_flags);
			bpf_task_release(p);
			return;
		}
	} else {
		if (cpuc && dsq_id != cpuc->mig_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->mig_dsq))
			return;
	}

	if (p2dq_config.llc_shards <= 1 &&
	    !(llcx = lookup_llc_ctx(cpuc->llc_id))) {
		scx_bpf_error("invalid llc id %u", cpuc->llc_id);
		return;
	}

	if (prev && keep_running(cpuc, llcx, prev))
		return;

	dispatch_pick_two(cpu, llcx, cpuc);
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->all_cpus = task_all_cpus(p);
}

void BPF_STRUCT_OPS(p2dq_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(p2dq_update_idle, s32 cpu, bool idle)
{
	const struct cpumask *idle_cpumask;
	struct llc_ctx *llcx;
	u64 idle_score;
	int ret, priority;
	u32 percent_idle;

	idle_cpumask = scx_bpf_get_idle_cpumask();

	percent_idle = idle_cpu_percent(idle_cpumask);
	saturated = percent_idle < p2dq_config.saturated_percent;

	if (saturated) {
		min_llc_runs_pick2 = min(2, lb_config.min_llc_runs_pick2);
	} else {
		u32 llc_scaler = log2_u32(topo_config.nr_llcs);
		min_llc_runs_pick2 = min(log2_u32(percent_idle) + llc_scaler, lb_config.min_llc_runs_pick2);
	}

	if (!(llcx = lookup_cpu_llc_ctx(cpu))) {
		scx_bpf_put_cpumask(idle_cpumask);
		return;
	}
	if (percent_idle == 0)
		overloaded = true;

	if (idle) {
		llcx->saturated = false;
		overloaded = false;
	} else if (!idle && llcx->cpumask && idle_cpumask && llcx->tmp_cpumask) {
		bpf_cpumask_and(llcx->tmp_cpumask,
				cast_mask(llcx->cpumask),
				idle_cpumask);
		if (llcx->tmp_cpumask &&
		    bpf_cpumask_weight(cast_mask(llcx->tmp_cpumask)) == 0)
			llcx->saturated = true;
	}

	scx_bpf_put_cpumask(idle_cpumask);

	if (!p2dq_config.cpu_priority)
		return;

	/*
	 * The idle_score factors relative CPU performance. It could also
	 * consider the last time the CPU went idle in the future.
	 */

	priority = cpu_priority(cpu);
	if (priority < 0)
		priority = 1;

	// Since we use a minheap convert the highest prio to lowest score.
	idle_score = scx_bpf_now() - ((1<<7) * (u64)priority);

	if ((ret = arena_spin_lock((void __arena *)&llcx->idle_lock)))
		return;

	scx_minheap_insert(llcx->idle_cpu_heap, (u64)cpu, idle_score);
	arena_spin_unlock((void __arena *)&llcx->idle_lock);

	return;
}

static s32 p2dq_init_task_impl(struct task_struct *p, struct scx_init_task_args *args)
{
	struct mask_wrapper *wrapper;
	struct bpf_cpumask *cpumask;
	task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 slice_ns;

	s32 task_cpu = scx_bpf_task_cpu(p);

	taskc = scx_task_alloc(p);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if (!(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return -EINVAL;

	if (!(cpumask = bpf_cpumask_create())) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	wrapper = bpf_task_storage_get(&task_masks, p, 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!wrapper) {
		bpf_cpumask_release(cpumask);
		scx_bpf_error("task mask allocation failure");
		return -ENOMEM;
	}

	if ((cpumask = bpf_kptr_xchg(&wrapper->mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		scx_bpf_error("task_ctx allocation failure");
		return -EINVAL;
	}

	slice_ns = scale_by_task_weight(p,
					dsq_time_slice(p2dq_config.init_dsq_index));

	taskc->enq_flags = 0;
	taskc->llc_id = cpuc->llc_id;
	taskc->node_id = cpuc->node_id;
	// Adjust starting index based on niceness
	if (p->scx.weight == 100) {
		taskc->dsq_index = p2dq_config.init_dsq_index;
	} else if (p->scx.weight < 100) {
		taskc->dsq_index = 0;
	} else if (p->scx.weight > 100) {
		taskc->dsq_index = p2dq_config.nr_dsqs_per_llc - 1;
	}
	taskc->last_dsq_index = taskc->dsq_index;
	taskc->slice_ns = slice_ns;
	taskc->all_cpus = task_all_cpus(p);
	taskc->interactive = is_interactive(taskc);
	p->scx.dsq_vtime = llcx->vtime;
	task_refresh_llc_runs(taskc);

	// When a task is initialized set the DSQ id to invalid. This causes
	// the task to be randomized on a LLC.
	if (taskc->all_cpus)
		taskc->dsq_id = SCX_DSQ_INVALID;
	else
		taskc->dsq_id = cpuc->llc_dsq;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	scx_task_free(p);
}

static int init_llc(u32 llc_index)
{
	struct llc_ctx *llcx;
	u32 llc_id = llc_ids[llc_index];
	int i, ret;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc_id);
	if (!llcx) {
		scx_bpf_error("No llc %u", llc_id);
		return -ENOENT;
	}

	llcx->vtime = 0;
	llcx->id = *MEMBER_VPTR(llc_ids, [llc_index]);
	llcx->index = llc_index;
	llcx->nr_cpus = 0;
	llcx->vtime = 0;

	ret = llc_create_atqs(llcx);
	if (ret) {
		return ret;
	}

	llcx->dsq = llcx->id | MAX_LLCS;
	ret = scx_bpf_create_dsq(llcx->dsq, llcx->node_id);
	if (ret) {
		scx_bpf_error("failed to create DSQ %llu", llcx->dsq);
		return -EINVAL;
	}

	llcx->mig_dsq = llcx->id | P2DQ_MIG_DSQ;
	ret = scx_bpf_create_dsq(llcx->mig_dsq, llcx->node_id);
	if (ret) {
		scx_bpf_error("failed to create DSQ %llu", llcx->mig_dsq);
		return -EINVAL;
	}

	ret = init_cpumask(&llcx->cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}

	ret = init_cpumask(&llcx->tmp_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC tmp_cpumask");
		return ret;
	}

	// big cpumask
	ret = init_cpumask(&llcx->big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC big cpumask");
		return ret;
	}

	ret = init_cpumask(&llcx->little_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC little cpumask");
		return ret;
	}

	ret = init_cpumask(&llcx->node_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC node cpumask");
		return ret;
	}

	// Initialize CPU sharding fields
	llcx->nr_shards = p2dq_config.llc_shards;

	if (p2dq_config.llc_shards > 1) {
		llcx->nr_shards = min(min(p2dq_config.llc_shards, llcx->nr_cpus), MAX_LLC_SHARDS);

		bpf_for(i, 0, llcx->nr_shards) {
			u64 shard_dsq = shard_dsq_id(llc_id, i);
			if (i < MAX_LLC_SHARDS) // verifier
				llcx->shard_dsqs[i] = shard_dsq;

			ret = scx_bpf_create_dsq(shard_dsq, llcx->node_id);
			if (ret) {
				scx_bpf_error("failed to create shard DSQ %llu for LLC %u shard %u",
					      shard_dsq, llc_id, i);
				return ret;
			}
		}
	}

	return 0;
}

static int init_node(u32 node_id)
{
	struct node_ctx *nodec;
	int ret;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node_id);
	if (!nodec) {
		scx_bpf_error("No node %u", node_id);
		return -ENOENT;
	}

	nodec->id = node_id;

	ret = init_cpumask(&nodec->cpumask);
	if (ret) {
		scx_bpf_error("failed to create node cpumask");
		return ret;
	}

	// big cpumask
	ret = init_cpumask(&nodec->big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create node cpumask");
		return ret;
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
	cpuc->slice_ns = 1;

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
	cpuc->mig_atq = llcx->mig_atq;

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
		bpf_rcu_read_lock();
		if (llcx->little_cpumask)
			bpf_cpumask_set_cpu(cpu, llcx->little_cpumask);
		bpf_rcu_read_unlock();
	}

	bpf_rcu_read_lock();
	if (all_cpumask)
		bpf_cpumask_set_cpu(cpu, all_cpumask);
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
	struct llc_ctx *llcx, *lb_llcx;
	int j;
	u64 ideal_sum, load_sum = 0, interactive_sum = 0;
	u32 llc_id, llc_index, lb_llc_index, lb_llc_id;

	bpf_for(llc_index, 0, topo_config.nr_llcs) {
		// verifier
		if (llc_index >= MAX_LLCS)
			break;

		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);
		if (!(llcx = lookup_llc_ctx(llc_id))) {
			scx_bpf_error("failed to lookup llc");
			return false;
		}

		lb_llc_index = (llc_index + llc_lb_offset) % topo_config.nr_llcs;
		if (lb_llc_index < 0 || lb_llc_index >= MAX_LLCS) {
			scx_bpf_error("failed to lookup lb_llc");
			return false;
		}

		lb_llc_id = *MEMBER_VPTR(llc_ids, [lb_llc_index]);
		if (!(lb_llcx = lookup_llc_ctx(lb_llc_id))) {
			scx_bpf_error("failed to lookup lb llc");
			return false;
		}

		load_sum += llcx->load;
		interactive_sum += llcx->intr_load;

		s64 load_imbalance = 0;
		if(llcx->load > lb_llcx->load)
			load_imbalance = (100 * (llcx->load - lb_llcx->load)) / llcx->load;

		u32 lb_slack = (lb_config.slack_factor > 0 ?
				lb_config.slack_factor : LOAD_BALANCE_SLACK);

		if (load_imbalance > lb_slack)
			llcx->lb_llc_id = lb_llc_id;
		else
			llcx->lb_llc_id = MAX_LLCS;

		dbg("LB llcx[%u] %llu lb_llcx[%u] %llu imbalance %lli",
		    llc_id, llcx->load, lb_llc_id, lb_llcx->load, load_imbalance);
	}

	dbg("LB Total load %llu, Total interactive %llu",
	    load_sum, interactive_sum);

	llc_lb_offset = (llc_lb_offset % (topo_config.nr_llcs - 1)) + 1;

	if (!timeline_config.autoslice || load_sum == 0 || load_sum < interactive_sum)
		goto reset_load;

	if (interactive_sum == 0) {
		dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;
		bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
			dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
		}
	} else {
		ideal_sum = (load_sum * p2dq_config.interactive_ratio) / 100;
		dbg("LB autoslice ideal/sum %llu/%llu", ideal_sum, interactive_sum);
		if (interactive_sum < ideal_sum) {
			dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;

			bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
			}
		} else {
			dsq_time_slices[0] = max((10 * dsq_time_slices[0]) / 11, min_slice_ns);
			bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
			}
		}
	}


reset_load:

	bpf_for(llc_index, 0, topo_config.nr_llcs) {
		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);
		if (!(llcx = lookup_llc_ctx(llc_id)))
			return false;

		llcx->load = 0;
		llcx->intr_load = 0;
		llcx->affn_load = 0;
		llcx->last_period_ns = scx_bpf_now();
		bpf_for(j, 0, p2dq_config.nr_dsqs_per_llc) {
			llcx->dsq_load[j] = 0;
			if (llc_id == 0 && timeline_config.autoslice) {
				if (j > 0 && dsq_time_slices[j] < dsq_time_slices[j-1]) {
					dsq_time_slices[j] = dsq_time_slices[j-1] << p2dq_config.dsq_shift;
				}
				dbg("LB autoslice interactive slice %llu", dsq_time_slices[j]);
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

static s32 p2dq_init_impl()
{
	struct llc_ctx *llcx;
	struct cpu_ctx *cpuc;
	int i, ret;
	u64 dsq_id;

	ret = init_cpumask(&all_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}
	ret = init_cpumask(&big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}

	if (p2dq_config.init_dsq_index >= p2dq_config.nr_dsqs_per_llc) {
		scx_bpf_error("invalid init_dsq_index");
		return -EINVAL;
	}

	// First we initialize LLCs because DSQs are created at the LLC level.
	bpf_for(i, 0, topo_config.nr_llcs) {
		ret = init_llc(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, topo_config.nr_nodes) {
		ret = init_node(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, topo_config.nr_cpus) {
		ret = init_cpu(i);
		if (ret)
			return ret;
	}

	// Create DSQs for the LLCs
	bpf_for(i, 0, topo_config.nr_cpus) {
		if (!(cpuc = lookup_cpu_ctx(i)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
			return -EINVAL;

		if (cpuc &&
		    llcx->node_cpumask &&
		    llcx->node_id == cpuc->node_id) {
			bpf_rcu_read_lock();
			if (llcx->node_cpumask)
				bpf_cpumask_set_cpu(cpuc->id, llcx->node_cpumask);
			bpf_rcu_read_unlock();
		}

		cpuc->llc_dsq = llcx->dsq;
		cpuc->mig_atq = llcx->mig_atq;

		if (p2dq_config.llc_shards > 1 && llcx->nr_shards > 1) {
			int shard_id = cpuc->core_id % llcx->nr_shards;
			if (shard_id >= 0 &&
			    shard_id < MAX_LLC_SHARDS &&
			    shard_id < llcx->nr_shards)
				cpuc->llc_dsq = *MEMBER_VPTR(llcx->shard_dsqs, [shard_id]);
		}

		dsq_id = cpu_dsq_id(i);
		dbg("CFG creating affn CPU[%d]DSQ[%llu]", i, dsq_id);
		ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
		if (ret < 0) {
			scx_bpf_error("failed to create DSQ %llu", dsq_id);
			return ret;
		}
		cpuc->affn_dsq = dsq_id;
		cpuc->mig_dsq = llcx->mig_dsq;
	}

	if (p2dq_config.cpu_priority) {
		bpf_for(i, 0, topo_config.nr_llcs) {
			if (!(llcx = lookup_llc_ctx(i)))
				return -EINVAL;
			llcx->idle_cpu_heap = scx_minheap_alloc(llcx->nr_cpus);
		}
	}

	min_slice_ns = 1000 * timeline_config.min_slice_us;

	if (start_timers() < 0)
		return -EINVAL;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

#if P2DQ_CREATE_STRUCT_OPS
s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init)
{
	return p2dq_init_impl();
}

void BPF_STRUCT_OPS(p2dq_running, struct task_struct *p)
{
	p2dq_running_impl(p);
}

void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct enqueue_promise pro;
	async_p2dq_enqueue(&pro, p, enq_flags);
	complete_p2dq_enqueue(&pro, p);
}

void BPF_STRUCT_OPS(p2dq_dispatch, s32 cpu, struct task_struct *prev)
{
	return p2dq_dispatch_impl(cpu, prev);
}

s32 BPF_STRUCT_OPS(p2dq_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return p2dq_select_cpu_impl(p, prev_cpu, wake_flags);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	return p2dq_init_task_impl(p, args);
}

SCX_OPS_DEFINE(p2dq,
	       .select_cpu		= (void *)p2dq_select_cpu,
	       .cpu_release		= (void *)p2dq_cpu_release,
	       .enqueue			= (void *)p2dq_enqueue,
	       .dispatch		= (void *)p2dq_dispatch,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
	       .update_idle		= (void *)p2dq_update_idle,
	       .init_task		= (void *)p2dq_init_task,
	       .exit_task		= (void *)p2dq_exit_task,
	       .init			= (void *)p2dq_init,
	       .exit			= (void *)p2dq_exit,
	       .timeout_ms		= 20000,
	       .name			= "p2dq");
#endif
