/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	4096

/*
 * Maximum amount of LLCs (Last Level Cache domains) supported by the scheduler.
 */
#define MAX_LLCS	1024

/*
 * Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
 * this value).
 */
#define MAX_WAKEUP_FREQ		1024ULL

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Sub-scheduler support.
 */
#define MAX_SUB_SCHEDS		8

/*
 * Sub-scheduler context.
 */
struct sub_sched_ctx {
	u64 cgroup_id;
	u32 weight;
	u64 cvtime;
};
static struct sub_sched_ctx sub_scheds[MAX_SUB_SCHEDS];

/*
 * Sub-scheduler vruntime (to implement sub-scheduler fair dispatch).
 */
static u64 sub_cvtime_now;

/*
 * Set from userspace (see main.rs): enable nested sub-scheduler dispatch in
 * maestro_dispatch(). False for leaf sub-scheduler instances; true for root-level
 * scheduler instances (const volatile rodata, no per-attach atomics).
 */
const volatile bool sub_sched_enabled = true;

/*
 * Default task time slice.
 */
const volatile u64 slice_ns = 700ULL * NSEC_PER_USEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile u64 slice_lag_ns = 20ULL * NSEC_PER_MSEC;

/*
 * SMT (Simultaneous Multi-Threading) is enabled on the system.
 */
const volatile bool smt_enabled = true;

/*
 * NUMA is enabled on the system.
 */
const volatile bool numa_enabled = true;

/*
 * Subset of CPUs to prioritize (primary scheduling domain).
 */
private(ECO) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * CPUs).
 */
const volatile bool primary_all = true;

/*
 * Try to minimize latency.
 */
const volatile bool lowlatency = false;

/*
 * Try to minimize the number of actively used CPUs.
 */
const volatile bool compaction = false;

/*
 * Runtime throttling.
 *
 * Throttle the CPUs by injecting @throttle_ns idle time every @slice_ns.
 */
const volatile u64 throttle_ns;
static volatile bool cpus_throttled;

static inline bool is_throttled(void)
{
	return READ_ONCE(cpus_throttled);
}

static inline void set_throttled(bool state)
{
	WRITE_ONCE(cpus_throttled, state);
}

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_shared_dispatches;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids;

/*
 * Number of LLC domains (set from userspace).
 */
const volatile u64 nr_llc_ids;

/*
 * Average CPU capacity per LLC (sum of all CPU capacities / nr_cpus),
 * filled from userspace.
 */
const volatile u64 llc_capacity[MAX_LLCS];

/*
 * Dense LLC id with the maximum capacity (set from userspace).
 */
const volatile u32 llc_id_max;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Timer used to inject idle cycles when CPU throttling is enabled.
 */
struct throttle_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct throttle_timer);
} throttle_timer SEC(".maps");

/*
 * Default cgroup weight (matches CGROUP_WEIGHT_DFL).
 */
#define CGROUP_WEIGHT_DFL	100

/*
 * Per-cgroup context: tracks the cgroup's cpu.weight.
 */
struct cgrp_ctx {
	u32 weight;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	u64 awake_vtime;
	u64 last_run_at;
	u64 wakeup_freq;
	u64 last_woke_at;
	u32 cgweight;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	struct bpf_cpumask __kptr *smt;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return the per-CPU context for @cpu.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Return the effective weight of a task, incorporating its cgroup weight.
 *
 * The effective weight is: task_nice_weight * cgroup_weight / CGROUP_WEIGHT_DFL
 *
 * This ensures tasks in a cgroup with weight 200 get twice the CPU time
 * of tasks in a cgroup with the default weight (100).
 */
static u64 task_weight(const struct task_struct *p)
{
	struct task_ctx *tctx;
	u32 cgw;

	tctx = try_lookup_task_ctx(p);
	cgw = tctx ? tctx->cgweight : CGROUP_WEIGHT_DFL;

	return (u64)p->scx.weight * cgw / CGROUP_WEIGHT_DFL;
}

static inline u64 scale_by_weight(const struct task_struct *p, u64 value)
{
	return value * task_weight(p) / CGROUP_WEIGHT_DFL;
}

static inline u64 scale_by_weight_inverse(const struct task_struct *p, u64 value)
{
	u64 w = task_weight(p);

	return w ? value * CGROUP_WEIGHT_DFL / w : value;
}

/*
 * LLC (Last Level Cache) domain context.
 */
struct llc_ctx {
	struct bpf_cpumask __kptr *cpumask;
	int node_id;
	u64 llc_capacity;	/* Average CPU capacity in this LLC (sum / nr_cpus) */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct llc_ctx);
	__uint(max_entries, MAX_LLCS);
} llc_ctx_stor SEC(".maps");

struct llc_ctx *try_lookup_llc_ctx(int llc)
{
	return bpf_map_lookup_elem(&llc_ctx_stor, &llc);
}

/*
 * Return NUMA node for @llc, or a negative value if invalid.
 */
static inline int llc_node(int llc)
{
	struct llc_ctx *lctx;

	if (!numa_enabled)
		return 0;

	lctx = try_lookup_llc_ctx(llc);

	return lctx ? lctx->node_id : -ENOENT;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);	/* cpu_id */
	__type(value, u32);	/* llc_id (dense index) */
} cpu_llc_map SEC(".maps");

static int cpu_llc(s32 cpu)
{
	u32 *id;

	id = bpf_map_lookup_elem(&cpu_llc_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if @this_cpu is in a faster LLC than @that_cpu, false
 * otherwise.
 */
static bool is_llc_faster(s32 this_cpu, s32 that_cpu)
{
	struct llc_ctx *lctx_this, *lctx_that;
	int this_llc, that_llc;

	if (this_cpu == that_cpu)
		return false;

	this_llc = cpu_llc(this_cpu);
	that_llc = cpu_llc(that_cpu);

	if (this_llc == that_llc)
		return false;

	lctx_this = try_lookup_llc_ctx(this_llc);
	lctx_that = try_lookup_llc_ctx(that_llc);

	if (!lctx_this || !lctx_that)
		return false;

	return lctx_this->llc_capacity > lctx_that->llc_capacity;
}

/*
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Return true if @cpu is in the primary domain, false otherwise.
 */
static inline bool is_primary_cpu(s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	if (primary_all)
		return true;

	return mask && bpf_cpumask_test_cpu(cpu, mask);
}

/*
 * Return a time slice scaled by the task's weight.
 */
static u64 task_slice(const struct task_struct *p)
{
	return scale_by_weight(p, slice_ns);
}

/*
 * Return task deadline in function of the vruntime and wakeup frequency.
 */
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx, u64 enq_flags)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 vsleep_max = scale_by_weight(p, slice_lag_ns * lag_scale);
	u64 vtime_min = vtime_now - vsleep_max;
	u64 dl = p->scx.dsq_vtime;

	if (enq_flags & SCX_ENQ_REENQ)
		return dl;

	if (time_before(dl, vtime_min))
		dl = vtime_min;

	return dl + scale_by_weight_inverse(p, tctx->awake_vtime);
}

/*
 * Return the preferred NUMA node of task @p, or NUMA_NO_NODE if not set.
 */
static inline s32 get_task_numa_node(const struct task_struct *p)
{
	if (numa_enabled && bpf_core_field_exists(p->numa_preferred_nid))
		return p->numa_preferred_nid;

	return NUMA_NO_NODE;
}

static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);
	s32 cpu;

	if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
	    (compaction ? is_llc_faster(prev_cpu, this_cpu) : is_llc_faster(this_cpu, prev_cpu)))
		prev_cpu = this_cpu;

	if (!primary_all && primary) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary, 0);
		if (cpu >= 0)
			return cpu;
	}

	if (numa_enabled) {
		s32 task_node = get_task_numa_node(p);
		int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);

		if (task_node != NUMA_NO_NODE && node != task_node) {
			cpu = scx_bpf_pick_idle_cpu_node(p->cpus_ptr, task_node, SCX_PICK_IDLE_IN_NODE);
			if (cpu >= 0)
				return cpu;
		}
	}

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
				     p->cpus_ptr, SCX_PICK_IDLE_IN_NODE);
	if (cpu >= 0)
		return cpu;

	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

s32 BPF_STRUCT_OPS(maestro_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	cpu = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags, false);
	if (cpu >= 0) {
		u64 flags = 0;

		/*
		 * Always preempt the waker in case of a sync wakeup.
		 */
		if ((wake_flags & SCX_WAKE_SYNC) &&
		    (this_cpu == prev_cpu))
			flags |= SCX_ENQ_PREEMPT;

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);

		return cpu;
	}

	return prev_cpu;
}

static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
}

/*
 * Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_cpumask();

	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return the SMT sibling of @cpu, or @cpu if SMT is disabled.
 */
static inline s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx *cctx;

	if (!smt_enabled)
		return cpu;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return cpu;

	smt = cast_mask(cctx->smt);
	if (!smt)
		return cpu;

	return bpf_cpumask_first(smt);
}

/*
 * Return true if @cpu is in  a partially-idle SMT core, false otherwise.
 */
static bool is_smt_contended(s32 cpu)
{
	const struct cpumask *idle_mask;
	bool is_contended;

	if (!smt_enabled)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask = get_idle_cpumask(cpu);
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

void BPF_STRUCT_OPS(maestro_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	bool do_migrate = task_should_migrate(p, enq_flags);
	bool is_reenq = enq_flags & SCX_ENQ_REENQ;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (lowlatency || do_migrate || is_reenq ||
	    (!compaction && (!is_cpu_idle(prev_cpu) ||
			  is_smt_contended(prev_cpu) ||
			  (!is_pcpu_task(p) && !is_primary_cpu(prev_cpu))))) {
		s32 cpu;

		if (is_pcpu_task(p))
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);

		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	scx_bpf_dsq_insert_vtime(p, cpu_llc(prev_cpu), task_slice(p),
				 task_dl(p, tctx, enq_flags), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	if (do_migrate)
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	/* Do not keep running if the task doesn't need to run */
	if (!is_task_queued(p))
		return false;

	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (is_pcpu_task(p))
		return true;

	/*
	 * If the CPU is not in the primary domain and the task can run
	 * on a primary CPU, give it a chance to migrate there.
	 */
	if (!is_primary_cpu(cpu) &&
	    mask && bpf_cpumask_intersects(p->cpus_ptr, mask))
		return false;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	return true;
}

void BPF_STRUCT_OPS(maestro_dispatch, s32 cpu, struct task_struct *prev)
{
	int llc, curr_llc = cpu_llc(cpu);
	int curr_node = llc_node(curr_llc);
	int i;

	/*
	 * Let the CPU go idle if the system is throttled.
	 */
	if (is_throttled())
		return;

	/*
	 * Check if other tasks in the same LLC needs to run.
	 */
	if (scx_bpf_dsq_move_to_local(curr_llc, 0))
		return;

	/*
	 * Then scan for tasks in LLCs within the same NUMA node.
	 */
	bpf_for(llc, 0, nr_llc_ids) {
		if (llc == curr_llc || llc_node(llc) != curr_node)
			continue;
		if (scx_bpf_dsq_move_to_local(llc, 0))
			return;
	}

	/*
	 * Then scan for tasks in LLCs in other NUMA nodes.
	 */
	bpf_for(llc, 0, nr_llc_ids) {
		if (llc == curr_llc || llc_node(llc) == curr_node)
			continue;
		if (scx_bpf_dsq_move_to_local(llc, 0))
			return;
	}

	/*
	 * Try to consume tasks from sub-scheduler instances, picking the
	 * one with the lowest cvtime first (weighted fair dispatch).
	 * Skip when userspace disables nested sub-dispatch (sub_sched_enabled).
	 */
	if (sub_sched_enabled && bpf_ksym_exists(scx_bpf_sub_dispatch)) {
		int tried = 0;

		bpf_for(i, 0, MAX_SUB_SCHEDS) {
			int best = -1, j;
			u64 min_cvt = (u64)-1;

			bpf_for(j, 0, MAX_SUB_SCHEDS) {
				if (!sub_scheds[j].cgroup_id ||
				    (tried & (1 << j)))
					continue;

				if (sub_scheds[j].cvtime < min_cvt) {
					min_cvt = sub_scheds[j].cvtime;
					best = j;
				}
			}

			if (best < 0)
				break;

			tried |= (1 << best);

			if (scx_bpf_sub_dispatch(sub_scheds[best].cgroup_id)) {
				u32 w = sub_scheds[best].weight ?: 1;

				if (time_before(sub_cvtime_now, sub_scheds[best].cvtime))
					sub_cvtime_now = sub_scheds[best].cvtime;

				sub_scheds[best].cvtime += slice_ns / w;
				return;
			}
		}
	}

	/*
	 * If no other task wants to run, let the same task run on the CPU.
	 */
	if (prev && keep_running(prev, cpu))
		scx_bpf_task_set_slice(prev, task_slice(prev));
}

void BPF_STRUCT_OPS(maestro_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Return the time slice normalized by the average capacity of @cpu's LLC.
 */
static u64 scale_by_llc_capacity(u64 slice, s32 cpu)
{
	int llc;

	llc = cpu_llc(cpu);
	if (llc < 0 || llc >= nr_llc_ids || llc >= MAX_LLCS)
		return slice;

	return slice * llc_capacity[llc] / SCX_CPUPERF_ONE;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(maestro_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice, vtime;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	slice = bpf_ktime_get_ns() - tctx->last_run_at;

	/*
	 * Scale used time slice by average LLC capacity: time spent in a
	 * slower LLC is charged less than in a faster LLC.
	 */
	slice = scale_by_llc_capacity(slice, cpu);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 *
	 * Cap the maximum accumulated time since last sleep to
	 * @slice_lag_ns, to prevent starving CPU-intensive tasks.
	 */
	vtime = p->scx.dsq_vtime + scale_by_weight_inverse(p, slice);
	scx_bpf_task_set_dsq_vtime(p, vtime);
	tctx->awake_vtime = MIN(tctx->awake_vtime + slice, slice_lag_ns);
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static inline u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update the average frequency of an event.
 *
 * The frequency is computed from the given interval since the last event
 * and combined with the previous frequency using an exponential weighted
 * moving average.
 */
static inline u64 update_freq(u64 freq, u64 interval)
{
        u64 new_freq;

        new_freq = (100 * NSEC_PER_MSEC) / interval;
        return calc_avg(freq, new_freq);
}

void BPF_STRUCT_OPS(maestro_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->awake_vtime = 0;

	delta_t = now - tctx->last_woke_at;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(maestro_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS(maestro_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct cgrp_ctx *cgc;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	if (args->cgroup) {
		cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, args->cgroup, 0, 0);
		tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
	} else {
		tctx->cgweight = CGROUP_WEIGHT_DFL;
	}

	return 0;
}

s32 BPF_STRUCT_OPS(maestro_sub_attach, struct scx_sub_attach_args *args)
{
	s32 i;

	for (i = 0; i < MAX_SUB_SCHEDS; i++) {
		if (!sub_scheds[i].cgroup_id) {
			struct cgroup *cgrp;
			struct cgrp_ctx *cgc;
			u32 weight = 100;

			cgrp = bpf_cgroup_from_id(args->ops->sub_cgroup_id);
			if (cgrp) {
				cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
				if (cgc)
					weight = cgc->weight;
				bpf_cgroup_release(cgrp);
			}

			sub_scheds[i].cgroup_id = args->ops->sub_cgroup_id;
			sub_scheds[i].weight = weight;
			sub_scheds[i].cvtime = sub_cvtime_now;
			bpf_printk("attach sub-sched[%d] on %s weight %u", i, args->cgroup_path, weight);
			return 0;
		}
	}

	return -ENOSPC;
}

void BPF_STRUCT_OPS(maestro_sub_detach, struct scx_sub_detach_args *args)
{
	s32 i;

	for (i = 0; i < MAX_SUB_SCHEDS; i++) {
		if (sub_scheds[i].cgroup_id == args->ops->sub_cgroup_id) {
			sub_scheds[i].cgroup_id = 0;
			sub_scheds[i].weight = 0;
			sub_scheds[i].cvtime = 0;
			bpf_printk("detach sub-sched[%d] on %s", i, args->cgroup_path);
			break;
		}
	}
}

s32 BPF_STRUCT_OPS(maestro_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;

	cgc->weight = args->weight;

	return 0;
}

void BPF_STRUCT_OPS(maestro_cgroup_exit, struct cgroup *cgrp)
{
}

void BPF_STRUCT_OPS(maestro_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;
	u64 cgid = cgrp->kn->id;
	s32 i;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (cgc)
		cgc->weight = weight;

	for (i = 0; i < MAX_SUB_SCHEDS; i++) {
		if (sub_scheds[i].cgroup_id == cgid) {
			sub_scheds[i].weight = weight;
			return;
		}
	}
}

void BPF_STRUCT_OPS(maestro_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx;
	struct cgrp_ctx *cgc;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, to, 0, 0);
	tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
}

static s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */
static int init_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *mask;

	mask = *p_cpumask;
	if (mask)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	mask = bpf_kptr_xchg(p_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return *p_cpumask ? 0 : -ENOMEM;
}

/*
 * Initialize an LLC domain context and create its DSQ. The LLC DSQ is
 * created using the NUMA node for of first CPU in the LLC.
 */
static int init_llc(int llc)
{
	struct bpf_cpumask *cpumask;
	struct llc_ctx *lctx;
	s32 cpu, first_cpu = -1;
	int ret;

	lctx = try_lookup_llc_ctx(llc);
	if (!lctx)
		return -ENOENT;

	ret = init_cpumask(&lctx->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = lctx->cpumask;
	if (!cpumask) {
		ret = -EINVAL;
		goto out_unlock;
	}
	bpf_for(cpu, 0, MAX_CPUS) {
		if (cpu_llc(cpu) != llc)
			continue;
		bpf_cpumask_set_cpu(cpu, cpumask);
		if (first_cpu < 0)
			first_cpu = cpu;
	}
out_unlock:
	bpf_rcu_read_unlock();

	/* Precomputed in userspace; bounds check for verifier. */
	lctx->llc_capacity = (llc < MAX_LLCS) ? llc_capacity[llc] : 0;

	if (ret)
		return ret;

	if (first_cpu < 0) {
		scx_bpf_error("LLC %d has no CPUs", llc);
		return -EINVAL;
	}

	lctx->node_id = __COMPAT_scx_bpf_cpu_node(first_cpu);
	ret = scx_bpf_create_dsq(llc, lctx->node_id);
	if (ret) {
		scx_bpf_error("failed to create LLC DSQ %d: %d", llc, ret);
		return ret;
	}

	return 0;
}

/*
 * Throttle timer used to inject idle time across all the CPUs.
 */
static int throttle_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bool throttled = is_throttled();
	u64 flags, duration;
	s32 cpu;
	int err;

	if (throttled) {
		flags = SCX_KICK_IDLE;
		duration = slice_ns;
	} else {
		flags = SCX_KICK_PREEMPT;
		duration = throttle_ns;
	}

	set_throttled(!throttled);

	bpf_for(cpu, 0, nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, flags);

	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(maestro_init)
{
	struct bpf_timer *timer;
	int err, llc;
	u32 key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Initialize each LLC (build cpumask and create per-LLC DSQ inside init_llc).
	 */
	bpf_for(llc, 0, nr_llc_ids) {
		err = init_llc(llc);
		if (err) {
			scx_bpf_error("failed to initialize LLC %d: %d", llc, err);
			return err;
		}
	}

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup throttle timer");
		return -ESRCH;
	}

	if (throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_ns, 0);
		if (err) {
			scx_bpf_error("Failed to arm throttle timer");
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(maestro_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	pmask = &cctx->smt;
	err = init_cpumask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

SCX_OPS_DEFINE(maestro_ops,
	       .select_cpu		= (void *)maestro_select_cpu,
	       .enqueue			= (void *)maestro_enqueue,
	       .dispatch		= (void *)maestro_dispatch,
	       .running			= (void *)maestro_running,
	       .stopping		= (void *)maestro_stopping,
	       .runnable		= (void *)maestro_runnable,
	       .enable			= (void *)maestro_enable,
	       .init_task		= (void *)maestro_init_task,
	       .cgroup_init		= (void *)maestro_cgroup_init,
	       .cgroup_exit		= (void *)maestro_cgroup_exit,
	       .cgroup_set_weight	= (void *)maestro_cgroup_set_weight,
	       .cgroup_move		= (void *)maestro_cgroup_move,
	       .sub_attach		= (void *)maestro_sub_attach,
	       .sub_detach		= (void *)maestro_sub_detach,
	       .init			= (void *)maestro_init,
	       .exit			= (void *)maestro_exit,
	       .timeout_ms		= 5000ULL,
	       .name			= "maestro");
