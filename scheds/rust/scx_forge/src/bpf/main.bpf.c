/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include <lib/pmu.h>
#include "intf.h"

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS			FORGE_MAX_CPUS

/*
 * User DSQs that are created at init time for generated policies.
 *
 * CPU DSQs use CPU IDs directly. LLC DSQs use dense LLC indices, matching
 * cpu_llc(). Node DSQs use kernel NUMA node IDs, matching cpu_node().
 */
#define GLOBAL_DSQ_ID			(1ULL << 34)
#define NODE_DSQ_ID(__node)		((1ULL << 33) + (u64)(__node))
#define LLC_DSQ_ID(__llc)		((1ULL << 32) + (u64)(__llc))
#define CPU_DSQ_ID(__cpu)		((u64)(__cpu))

/*
 * Policy abstraction layer for generated schedulers.
 *
 * Keep sched_ext callback semantics intact while changing these helpers:
 *   - select_cpu() is a wakeup placement hint and may use a terminal-DSQ direct
 *     dispatch fast path when useful. It must not own global queueing or
 *     selection policy.
 *   - enqueue() admits every task that did not get consumed by the core,
 *     including migration-disabled tasks, affinity-constrained tasks, and
 *     per-CPU kernel threads.
 *   - dispatch() is the primary selection point. CPUs pull from their per-CPU
 *     DSQ and can steal from other per-CPU DSQs as CPU demand changes.
 */

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Subset of CPUs to prioritize.
 */
private(FORGE) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPUs).
 */
const volatile bool primary_all = true;

/*
 * Default task time slice.
 */
const volatile u64 slice_ns = NSEC_PER_MSEC;

/*
 * SMT (Simultaneous Multi-Threading) is enabled on the system.
 */
const volatile bool smt_enabled = true;

/*
 * Define the topology level of the DSQs.
 *
 * Selected at load time from the Rust control plane (see the --dsq-topology
 * CLI flag). enum topology_dsq_type lives in intf.h so both sides share the
 * values; declared as u32 here so the generated skeleton exposes a plain
 * integer rodata field.
 */
const volatile u32 topo_dsq = TOPO_DSQ_CPU;

/*
 * Ordering algorithm for the queue key of vtime-ordered DSQs.
 *
 * Selected at load time from the Rust control plane (see the --ordering CLI
 * flag). enum ordering_type lives in intf.h so both sides share the values.
 */
const volatile u32 ordering = ORDER_VRUNTIME;

/*
 * Wakeup idle-CPU selection policy.
 *
 * Selected at load time from the Rust control plane (see the --idle-policy CLI
 * flag). enum idle_policy_type lives in intf.h so both sides share the values.
 */
const volatile u32 idle_policy = IDLE_WAKEE;

/*
 * Ignore synchronous wakeup hints (SCX_WAKE_SYNC) during idle CPU selection.
 *
 * When set, the wakee is not biased toward the waker's CPU/LLC on a sync
 * wakeup. This can spread load more uniformly across cores, at the cost of
 * tighter producer-consumer locality for pipe-intensive workloads. Selected at
 * load time from the Rust control plane (see the --no-wake-sync CLI flag).
 */
const volatile bool no_wake_sync;

/*
 * Preempt the currently running task on an eligible sleeper wakeup.
 *
 * When set, a task waking up can immediately preempt the task running on its
 * target CPU if the waker's queue key is eligible and earlier than the running
 * task's estimated current vruntime (see should_preempt_curr()). Selected at
 * load time from the Rust control plane (see the --preemption CLI flag).
 */
const volatile bool preemption;

/*
 * Hardware/software PMU event to monitor for the "event-heavy" migration hint
 * (0 = disabled). An opaque event id shared with the PMU library; the Rust
 * control plane installs the matching perf event per CPU (see --perf-config).
 */
const volatile u64 perf_config;

/*
 * Threshold (events accumulated over the last slice) above which a task is
 * classified as event-heavy and biased toward migrating to an idle CPU. The
 * behavior is gated on @perf_config (see --perf-threshold).
 */
const volatile u64 perf_threshold;

/*
 * PMU event to monitor for the "sticky" hint (0 = disabled). When a task's
 * count for this event exceeds @perf_sticky_threshold it is kept on its
 * previous CPU instead of migrating (see --perf-sticky).
 */
const volatile u64 perf_sticky;

/*
 * Threshold above which a task is classified as sticky and kept on its
 * previous CPU. The behavior is gated on @perf_sticky (see
 * --perf-sticky-threshold).
 */
const volatile u64 perf_sticky_threshold;

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_enqueues, nr_preempt_dispatches;
volatile u64 nr_local_dispatches, nr_remote_dispatches;
volatile u64 nr_llc_dispatches, nr_node_dispatches;
volatile u64 nr_global_dispatches;
volatile u64 nr_dequeues, nr_dispatch_dequeues, nr_sched_change_dequeues;
volatile u64 nr_task_state_errors;
volatile u64 nr_event_dispatches, nr_ev_sticky_dispatches;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids;

/*
 * True when all CPUs have the same capacity (no capacity asymmetry).
 */
const volatile bool all_cpus_same_capacity = false;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Current global vruntime.
 */
static u64 vtime_now;

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
enum task_state {
	TASK_NONE = 0,
	TASK_ENQUEUED,
	TASK_DISPATCHED,
};

struct task_ctx {
	u64 last_woke_at;
	/*
	 * Runtime accounting source of truth. p->scx.dsq_vtime is only the
	 * queue key while the task is stored in a vtime-ordered DSQ.
	 */
	u64 vruntime;
	u64 enqueue_seq;
	/*
	 * Accumulated execution time since the task last woke up (reset in
	 * ops.runnable(), charged in ops.stopping()). Used by the deadline
	 * ordering to favor tasks that have run little since waking.
	 */
	u64 burst_time;
	s64 sleep_vlag;
	bool has_sleep_vlag;
	enum task_state state;
	u32 cgweight;
	/*
	 * PMU event counts accumulated over the task's last time slice, refreshed
	 * in ops.stopping() via update_counters(). @perf_events feeds the
	 * event-heavy migration hint and @perf_sticky_events the sticky hint;
	 * both are 0 unless the matching event is configured.
	 */
	u64 perf_events;
	u64 perf_sticky_events;
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
	/*
	 * Timestamp when the task currently running on this CPU started. Kept
	 * per-CPU (rather than in task-local storage) so should_preempt_curr()
	 * can read it for the remote CPU's running task without an untrusted
	 * task-storage lookup.
	 */
	u64 last_run_at;
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
static struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Return a local task context from a generic task.
 */
static struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Return a local cgroup context from a generic cgroup.
 */
static struct cgrp_ctx *try_lookup_cgrp_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
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
 * Host topology populated from userspace from scx_utils::Topology.
 *
 * The ID maps preserve the BTreeMap iteration order from userspace and allow
 * BPF code to iterate dense indices while the object maps stay keyed by the
 * original topology IDs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct forge_topology);
} topo_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, u32);
} topo_cpu_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, u32);
} topo_core_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, u32);
} topo_llc_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, u32);
} topo_node_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, FORGE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct forge_topo_cpu);
} topo_cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, struct forge_topo_core);
} topo_core_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, struct forge_topo_llc);
} topo_llc_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, FORGE_MAX_TOPO_DOMAINS);
	__type(key, u32);
	__type(value, struct forge_topo_node);
} topo_node_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, FORGE_MAX_TOPO_DISTANCES);
	__type(key, struct forge_topo_distance_key);
	__type(value, u32);
} topo_distance_map SEC(".maps");

static __always_inline __maybe_unused struct forge_topology *lookup_topology(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&topo_info_map, &key);
}

static __always_inline __maybe_unused int topo_cpu_id_at(u32 idx)
{
	u32 *id;

	id = bpf_map_lookup_elem(&topo_cpu_ids, &idx);
	return id ? *id : -ENOENT;
}

static __always_inline __maybe_unused int topo_core_id_at(u32 idx)
{
	u32 *id;

	id = bpf_map_lookup_elem(&topo_core_ids, &idx);
	return id ? *id : -ENOENT;
}

static __always_inline __maybe_unused int topo_llc_id_at(u32 idx)
{
	u32 *id;

	id = bpf_map_lookup_elem(&topo_llc_ids, &idx);
	return id ? *id : -ENOENT;
}

static __always_inline __maybe_unused int topo_node_id_at(u32 idx)
{
	u32 *id;

	id = bpf_map_lookup_elem(&topo_node_ids, &idx);
	return id ? *id : -ENOENT;
}

static __always_inline __maybe_unused struct forge_topo_cpu *lookup_topo_cpu(s32 cpu)
{
	u32 key = cpu;

	if (cpu < 0)
		return NULL;
	return bpf_map_lookup_elem(&topo_cpu_map, &key);
}

static __always_inline __maybe_unused struct forge_topo_core *lookup_topo_core(u32 core_id)
{
	return bpf_map_lookup_elem(&topo_core_map, &core_id);
}

static __always_inline __maybe_unused struct forge_topo_llc *lookup_topo_llc(u32 llc_id)
{
	return bpf_map_lookup_elem(&topo_llc_map, &llc_id);
}

static __always_inline __maybe_unused struct forge_topo_node *lookup_topo_node(u32 node_id)
{
	return bpf_map_lookup_elem(&topo_node_map, &node_id);
}

static __always_inline __maybe_unused int topo_distance(u32 node_id, u32 distance_idx)
{
	struct forge_topo_distance_key key = {
		.node_id = node_id,
		.distance_idx = distance_idx,
	};
	u32 *distance;

	distance = bpf_map_lookup_elem(&topo_distance_map, &key);
	return distance ? *distance : -ENOENT;
}

static __always_inline __maybe_unused bool
topo_cpumask_test_cpu(const struct forge_topo_cpumask *mask, u32 cpu)
{
	u32 word = cpu / 64;
	u32 bit = cpu % 64;

	if (word >= FORGE_TOPO_CPUMASK_WORDS)
		return false;

	return mask->bits[word] & (1ULL << bit);
}

/*
 * Track whether a task is in BPF custody (queued on a user-created DSQ) or
 * has already been handed to a terminal DSQ for execution.
 */
static void task_mark_enqueued(struct task_struct *p, struct task_ctx *tctx)
{
	if (tctx->state == TASK_ENQUEUED) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		dbg_msg("%d (%s): enqueue while already enqueued seq=%llu",
			p->pid, p->comm, tctx->enqueue_seq);
	}

	tctx->state = TASK_ENQUEUED;
	tctx->enqueue_seq++;
}

static void task_mark_dispatched(struct task_struct *p, struct task_ctx *tctx)
{
	if (tctx->state == TASK_ENQUEUED) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		dbg_msg("%d (%s): terminal dispatch while enqueued seq=%llu",
			p->pid, p->comm, tctx->enqueue_seq);
	}

	tctx->state = TASK_DISPATCHED;
}

static void task_mark_none(struct task_ctx *tctx)
{
	tctx->state = TASK_NONE;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);	/* cpu_id */
	__type(value, u32);	/* llc_id (dense index) */
} cpu_llc_map SEC(".maps");

static __maybe_unused int cpu_llc(s32 cpu)
{
	u32 *id;

	id = bpf_map_lookup_elem(&cpu_llc_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

/*
 * CPU -> NUMA node mapping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);	/* cpu_id */
	__type(value, u32);	/* node_id */
} cpu_node_map SEC(".maps");

static int cpu_node(s32 cpu)
{
	u32 *id;

	id = bpf_map_lookup_elem(&cpu_node_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
	struct forge_topo_cpu *this_topo, *that_topo;

	if (all_cpus_same_capacity || this_cpu == that_cpu)
		return false;

	this_topo = lookup_topo_cpu(this_cpu);
	that_topo = lookup_topo_cpu(that_cpu);
	if (!this_topo || !that_topo)
		return false;

	return this_topo->cpu_capacity > that_topo->cpu_capacity;
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
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Return the time slice normalized by @cpu's capacity.
 */
static u64 scale_by_cpu_capacity(u64 slice, s32 cpu)
{
	struct forge_topo_cpu *topo_cpu;

	if (all_cpus_same_capacity)
		return slice;

	topo_cpu = lookup_topo_cpu(cpu);
	if (!topo_cpu || !topo_cpu->cpu_capacity)
		return slice;

	return slice * topo_cpu->cpu_capacity / SCX_CPUPERF_ONE;
}

/*
 * Clamp saved virtual lag so sleepers carry bounded credit or debt.
 */
static s64 selection_clamp_vlag(const struct task_struct *p, s64 vlag)
{
	s64 limit = (s64)slice_ns + NSEC_PER_MSEC;

	return CLAMP(vlag, -limit, limit);
}

/*
 * Save bounded virtual lag for voluntary sleepers.
 *
 * Positive lag means the task slept behind vtime_now (credit), negative lag
 * means it slept ahead of vtime_now (debt).
 */
static void selection_save_sleep_vlag(struct task_struct *p, struct task_ctx *tctx)
{
	s64 vlag = (s64)(vtime_now - tctx->vruntime);

	tctx->sleep_vlag = selection_clamp_vlag(p, vlag);
	tctx->has_sleep_vlag = true;
}

/*
 * Re-align task-local vruntime to the current vtime_now, applying its saved
 * bounded virtual lag. Positive lag gives credit, negative lag preserves debt.
 */
static u64 update_task_vruntime(struct task_struct *p, struct task_ctx *tctx)
{
	s64 vlag;

	if (tctx->has_sleep_vlag) {
		vlag = selection_clamp_vlag(p, tctx->sleep_vlag);
		tctx->vruntime = vtime_now - vlag;
		tctx->has_sleep_vlag = false;
	}

	return tctx->vruntime;
}

/*
 * Compute the queue key used to order @p inside its vtime-ordered DSQ,
 * according to the @ordering policy knob.
 *
 * This re-aligns the task's vruntime via update_task_vruntime() in all cases
 * (so sleeper credit/debt accounting stays consistent), then derives the key.
 */
static u64 task_dsq_key(struct task_struct *p, struct task_ctx *tctx)
{
	u64 vruntime = update_task_vruntime(p, tctx);

	switch (ordering) {
	case ORDER_DEADLINE:
		/*
		 * Earliest-deadline-first: offset the vruntime by the
		 * weight-scaled execution time accumulated since the task last
		 * woke up, so tasks that have run little (more latency- or
		 * I/O-bound) get earlier deadlines.
		 */
		return vruntime + scale_by_task_weight_inverse(p, tctx->burst_time);
	case ORDER_FIFO:
		/*
		 * Order strictly by enqueue order: vtime_now is monotonically
		 * non-decreasing, so tasks enqueued later get a key >= earlier
		 * ones and equal keys break by DSQ insertion order (also FIFO).
		 * Keeping the key in the vruntime domain avoids mixing a
		 * separate ktime magnitude with the other orderings.
		 */
		return vtime_now;
	case ORDER_VRUNTIME:
	default:
		return vruntime;
	}
}

/*
 * Return true if a task is waking up another task that share the same address
 * space, false otherwise.
 */
static bool is_wake_affine(const struct task_struct *p)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();

	return !(current->flags & PF_EXITING) &&
		current->mm && p->mm && (p->mm == current->mm);
}

/*
 * Return the optimal idle CPU for a task, in function of its previously used
 * CPU, the current CPU (in case of wakeup) and the wakeup flags.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
			 s32 this_cpu, u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	bool reuse_prev = false;
	s32 cpu;

	/*
	 * Clear the wake-sync hint if synchronous wakeups are disabled, so the
	 * kernel idle selection does not bias the wakee toward the waker.
	 */
	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	switch (idle_policy) {
	case IDLE_WAKEE:
		/*
		 * Strict previous-CPU cache affinity: never re-seed the search
		 * toward the waker CPU.
		 */
		break;
	case IDLE_WAKER:
		/*
		 * Wakeup locality: seed the search from the waker CPU on any
		 * wakeup when it is usable, regardless of relative capacity.
		 */
		if (this_cpu >= 0 && is_wakeup(wake_flags))
			prev_cpu = this_cpu;
		break;
	case IDLE_THREAD:
		/*
		 * Wakeup locality limited to threads of the same task: only
		 * seed from the waker CPU when the waker and wakee share an
		 * address space (e.g. threads of one process exchanging data).
		 */
		if (this_cpu >= 0 && is_wakeup(wake_flags) && is_wake_affine(p))
			prev_cpu = this_cpu;
		break;
	case IDLE_STICKY:
		/*
		 * Fall back to the previous CPU when no idle CPU is available,
		 * so the wakeup is always directly dispatched.
		 */
		reuse_prev = true;
		break;
	case IDLE_CAPACITY:
	default:
		/*
		 * For tail latency minimization, prefer immediate idle CPU
		 * availability over cache affinity. Only migrate to this_cpu if
		 * it's actually idle and faster, to avoid latency from waiting
		 * for preferred CPUs.
		 */
		if (this_cpu >= 0 && is_wakeup(wake_flags) &&
		    is_cpu_faster(this_cpu, prev_cpu))
			prev_cpu = this_cpu;
		break;
	}

	/*
	 * Compatibility with older kernels that don't support
	 * scx_bpf_select_cpu_and(). scx_bpf_select_cpu_dfl() is only valid from
	 * ops.select_cpu(), so enqueue-side direct dispatch falls back to the
	 * sticky previous-CPU policy when requested.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		bool is_idle = false;

		if (from_enqueue)
			return reuse_prev ? prev_cpu : -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		if (is_idle)
			return cpu;

		return reuse_prev ? prev_cpu : -EBUSY;
	}

	/*
	 * If a primary domain is defined, try to pick an idle CPU from there
	 * first.
	 */
	if (!primary_all && mask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask, 0);
		if (cpu >= 0)
			return cpu;
	}

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu;

	return reuse_prev ? prev_cpu : cpu;
}

/*
 * Called on task wake-up, this mirrors select_task_rq() in the kernel.
 *
 * NOTE: ops.select_cpu() is skipped for tasks that can only run on a single CPU
 * (migration-disabled tasks or tasks with p->nr_cpus_allowed == 1).
 */
s32 BPF_STRUCT_OPS(forge_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();

	if (!bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr))
		this_cpu = -ENOENT;

	/*
	 * On wakeup, @this_cpu is the CPU handling the wakeup, i.e., the
	 * "waker's" CPU. However, the current task running on @this_cpu is not
	 * necessarily the waker: interrupt-driven wakeups can happen while
	 * current has no direct relationship with the wakee (@p).
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = this_cpu >= 0 ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	cpu = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags, false);
	if (cpu >= 0) {
		/*
		 * Dispatch the task directly if we found an idle CPU. In this
		 * context SCX_DSQ_LOCAL represents the CPU returned by this
		 * function (no need to use SCX_DSQ_LOCAL_ON | cpu).
		 */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Return true if task is waking up (not running) and ops.select_cpu() was not
 * called (e.g., in case of a queued wakeups or per-CPU tasks), false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Return true if the target CPU is running the idle thread, false otherwise.
 */
static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
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
	idle_mask = __COMPAT_scx_bpf_get_idle_cpumask_node(cpu_node(cpu));
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if @p is triggering enough monitored PMU events to be treated as
 * event-heavy, biasing it toward migrating to an idle CPU. Gated on @perf_config
 * being configured.
 */
static inline bool is_event_heavy(const struct task_ctx *tctx)
{
	return perf_config &&
	       tctx->perf_events > perf_threshold;
}

/*
 * Return true if @p exceeds the sticky event threshold and should be kept on
 * its previous CPU. Gated on @perf_sticky being configured.
 */
static inline bool is_sticky_event_heavy(const struct task_ctx *tctx)
{
	return perf_sticky &&
	       tctx->perf_sticky_events > perf_sticky_threshold;
}

/*
 * Refresh @p's PMU event counts for the slice that just ended. Called from
 * ops.stopping() after scx_pmu_event_stop(); reads (and clears) the per-task
 * accumulators maintained by the PMU library.
 */
static void update_counters(struct task_struct *p, struct task_ctx *tctx)
{
	u64 delta = 0;

	if (perf_config) {
		scx_pmu_read(p, perf_config, &delta, true);
		tctx->perf_events = delta;
	}

	if (perf_sticky) {
		scx_pmu_read(p, perf_sticky, &delta, true);
		tctx->perf_sticky_events = delta;
	}
}

/*
 * Placement policy: opportunistically dispatch a task directly to an idle CPU.
 *
 * This is an optimization after enqueue() has seen the task. Returning false
 * intentionally lets the task wait in its per-CPU DSQ so dispatch() can make
 * the primary selection decision.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 enq_flags,
				bool do_migrate, bool is_reenq)
{
	bool cpu_selected = __COMPAT_is_enq_cpu_selected(enq_flags);
	bool waking_after_select = cpu_selected && !scx_bpf_task_running(p);
	bool event_heavy = is_event_heavy(tctx);
	s32 cpu;

	/*
	 * Sticky hint: keep an event-sticky task on its previous CPU when that
	 * CPU is idle and not SMT-contended, instead of letting it migrate.
	 * Skipped for per-CPU tasks, which are already bound to prev_cpu.
	 */
	if (is_sticky_event_heavy(tctx) && !is_pcpu_task(p) &&
	    is_primary_cpu(prev_cpu) &&
	    !is_smt_contended(prev_cpu) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns, enq_flags);
		task_mark_dispatched(p, tctx);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		__sync_fetch_and_add(&nr_ev_sticky_dispatches, 1);

		return true;
	}

	if (!(do_migrate || waking_after_select || is_reenq || event_heavy ||
	      !is_cpu_idle(prev_cpu) || is_smt_contended(prev_cpu) ||
	      (!is_pcpu_task(p) && !is_primary_cpu(prev_cpu))))
		return false;

	if (is_pcpu_task(p)) {
		if (!scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return false;

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns, enq_flags);
		task_mark_dispatched(p, tctx);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);

		return true;
	}

	cpu = pick_idle_cpu(p, prev_cpu, -ENOENT, 0, true);
	if (cpu < 0)
		return false;

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns, enq_flags);
	task_mark_dispatched(p, tctx);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

	/*
	 * Count migrations triggered for event-heavy tasks (those moved off
	 * their previous CPU to spread PMU-intensive work).
	 */
	if (event_heavy && cpu != prev_cpu)
		__sync_fetch_and_add(&nr_event_dispatches, 1);

	return true;
}

/*
 * Select the target DSQ for task @p, running on CPU @cpu.
 */
static u64 task_dsq(const struct task_struct *p, s32 cpu)
{
	int llc, node;

	switch (topo_dsq) {
	case TOPO_DSQ_LLC:
		llc = cpu_llc(cpu);
		if (llc >= 0)
			return LLC_DSQ_ID(llc);
		break;
	case TOPO_DSQ_NODE:
		node = cpu_node(cpu);
		if (node >= 0)
			return NODE_DSQ_ID(node);
		break;
	case TOPO_DSQ_GLOBAL:
		return GLOBAL_DSQ_ID;
	case TOPO_DSQ_CPU:
		return CPU_DSQ_ID(cpu);
	}

	/* Fallback: use built-in global DSQ */
	return SCX_DSQ_GLOBAL;
}

/*
 * Return true if @vtime is eligible to run at the current system vruntime.
 */
static bool vtime_eligible(u64 vtime)
{
	return time_before(vtime, vtime_now);
}

/*
 * Estimate @p's current vruntime, accounting for the time it has been running
 * since @last_run_at (its queue key plus the weight-scaled elapsed runtime).
 *
 * @last_run_at is sourced from the per-CPU context rather than @p's task-local
 * storage, so this can be called on an untrusted remote-CPU current task: only
 * plain field reads (dsq_vtime, weight) are performed on @p.
 */
static u64 task_current_vtime(const struct task_struct *p, u64 last_run_at)
{
	u64 now;

	if (!last_run_at)
		return p->scx.dsq_vtime;

	now = bpf_ktime_get_ns();
	if (now <= last_run_at)
		return p->scx.dsq_vtime;

	return p->scx.dsq_vtime +
	       scale_by_task_weight_inverse(p, now - last_run_at);
}

/*
 * Return true if an eligible sleeper with queue key @dl should preempt @curr,
 * the task currently running on @curr_cpu, on wakeup.
 */
static bool should_preempt_curr(const struct task_struct *curr, s32 curr_cpu, u64 dl)
{
	struct cpu_ctx *cctx;
	u64 curr_vtime, last_run_at = 0;

	/*
	 * Always allow to preempt the idle thread.
	 */
	if (curr->flags & PF_IDLE)
		return true;

	/*
	 * Do not preempt if the task is not eligible to run.
	 */
	if (!vtime_eligible(dl))
		return false;

	/*
	 * Only preempt tasks managed by sched_ext. A task that isn't (or is no
	 * longer) scheduled by sched_ext has a zero dsq_vtime: it is set to a
	 * non-zero system vruntime in ops.enable() and reset in ops.disable().
	 *
	 * Tasks in higher scheduling classes (stop, deadline, RT) can't be
	 * preempted by us anyway, and the idle task does not need SCX_ENQ_PREEMPT
	 * (a regular enqueue plus the idle kick is enough). This also avoids
	 * estimating @curr's vruntime from a stale per-CPU timestamp left behind
	 * by a previous sched_ext task.
	 */
	if (!curr->scx.dsq_vtime)
		return false;

	cctx = try_lookup_cpu_ctx(curr_cpu);
	if (cctx)
		last_run_at = cctx->last_run_at;

	curr_vtime = task_current_vtime(curr, last_run_at);

	return !vtime_eligible(curr_vtime) || time_before(dl, curr_vtime);
}

/*
 * Triggered when a task is ready to run: on wakeup if ops.select_cpu() was
 * skipped, or every time a task is re-enqueued (expired time slice, sched
 * property change, etc.).
 */
void BPF_STRUCT_OPS(forge_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	bool do_migrate = task_should_migrate(p, enq_flags);
	bool is_reenq = enq_flags & SCX_ENQ_REENQ;
	u64 dl;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags,
				do_migrate, is_reenq))
		return;

	dl = task_dsq_key(p, tctx);

	/*
	 * When preemption is enabled, let an eligible sleeper immediately
	 * preempt the task currently running on the target CPU instead of
	 * waiting in the vtime-ordered DSQ.
	 */
	if (preemption) {
		struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(prev_cpu);
		bool is_wakeup = (enq_flags & SCX_ENQ_WAKEUP) && tctx->has_sleep_vlag;

		if (curr && is_wakeup && should_preempt_curr(curr, prev_cpu, dl)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns,
					   enq_flags | SCX_ENQ_PREEMPT);
			task_mark_enqueued(p, tctx);
			__sync_fetch_and_add(&nr_preempt_dispatches, 1);
			return;
		}
	}

	/*
	 * Enqueue to the target DSQ if the task was not directly dispatched to
	 * an idle CPU. This path covers migration-disabled tasks, affinity
	 * constrained tasks, queued wakeups, and tasks that lost the direct
	 * placement race.
	 */
	scx_bpf_dsq_insert_vtime(p, task_dsq(p, prev_cpu), slice_ns, dl, enq_flags);
	task_mark_enqueued(p, tctx);
	__sync_fetch_and_add(&nr_enqueues, 1);

	/*
	 * Wake the target CPU if enqueue() is placing work without the wakeup
	 * side effect from select_cpu().
	 */
	if (do_migrate)
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Called when a task leaves BPF scheduler custody.
 *
 * scx_forge inserts non-direct tasks into user-created per-CPU DSQs. Those
 * tasks enter BPF custody and receive ops.dequeue() when moved to a terminal
 * DSQ, picked by core scheduling, or dequeued for a scheduling property change.
 */
void BPF_STRUCT_OPS(forge_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_dequeues, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (deq_flags & SCX_DEQ_SCHED_CHANGE) {
		__sync_fetch_and_add(&nr_sched_change_dequeues, 1);

		if (tctx->state != TASK_ENQUEUED &&
		    tctx->state != TASK_DISPATCHED) {
			__sync_fetch_and_add(&nr_task_state_errors, 1);
			dbg_msg("%d (%s): sched-change dequeue from state=%d seq=%llu",
				p->pid, p->comm, tctx->state, tctx->enqueue_seq);
		}

		task_mark_none(tctx);
		return;
	}

	__sync_fetch_and_add(&nr_dispatch_dequeues, 1);

	if (tctx->state != TASK_ENQUEUED && tctx->state != TASK_NONE) {
		__sync_fetch_and_add(&nr_task_state_errors, 1);
		dbg_msg("%d (%s): dispatch dequeue from state=%d seq=%llu",
			p->pid, p->comm, tctx->state, tctx->enqueue_seq);
	}

	if (tctx->state == TASK_ENQUEUED)
		tctx->state = TASK_DISPATCHED;
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool selection_keep_running(const struct task_struct *p, s32 cpu)
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
	 * If the idle selection policy keeps the task sticky on the same CPU we
	 * can keep the task running here.
	 */
	if (idle_policy == IDLE_STICKY)
		return true;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	/*
	 * If the task is not in the primary domain, give it a chance to
	 * migrate.
	 */
	if (!primary_all && !is_primary_cpu(cpu) &&
	    mask && bpf_cpumask_intersects(p->cpus_ptr, mask))
		return false;

	return true;
}

/*
 * Pick the per-CPU DSQ whose head has the earliest queue key and can run on
 * @dst_cpu. The scan starts from @dst_cpu so tie-breaking is naturally spread
 * across dispatching CPUs.
 */
static s32 pick_remote_cpu(s32 dst_cpu)
{
	u64 min_vtime = ULLONG_MAX;
	s32 min_cpu = -ENOENT;
	u64 i, cpu;

	bpf_for(i, 0, nr_cpu_ids) {
		struct task_struct *p;

		cpu = dst_cpu + i;
		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;

		if (!lookup_topo_cpu((s32)cpu))
			continue;

		p = __COMPAT_scx_bpf_dsq_peek(CPU_DSQ_ID(cpu));
		if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr))
			continue;

		if (p->scx.dsq_vtime < min_vtime) {
			min_vtime = p->scx.dsq_vtime;
			min_cpu = (s32)cpu;
		}
	}

	return min_cpu;
}

/*
 * Called when a CPU becomes available, trigger from the kernel sched balance().
 *
 * The CPU becomes available either when the previously running task releases
 * the CPU or because it expires its assigned time slice.
 */
void BPF_STRUCT_OPS(forge_dispatch, s32 cpu, struct task_struct *prev)
{
	int node, llc;
	s32 dst_cpu;

	switch (topo_dsq) {
	case TOPO_DSQ_CPU:
		/*
		 * First, try to consume a task from the local DSQ.
		 */
		if (scx_bpf_dsq_move_to_local(CPU_DSQ_ID(cpu), 0)) {
			__sync_fetch_and_add(&nr_local_dispatches, 1);
			return;
		}

		/*
		 * The local DSQ is empty, so steal a task from a remote CPU
		 * (load balancing).
		 */
		dst_cpu = pick_remote_cpu(cpu);
		if (dst_cpu >= 0 &&
		    scx_bpf_dsq_move_to_local(CPU_DSQ_ID(dst_cpu), 0)) {
			if (dst_cpu == cpu)
				__sync_fetch_and_add(&nr_local_dispatches, 1);
			else
				__sync_fetch_and_add(&nr_remote_dispatches, 1);
			return;
		}
		break;

	case TOPO_DSQ_LLC:
		llc = cpu_llc(cpu);
		if (llc >= 0 &&
		    scx_bpf_dsq_move_to_local(LLC_DSQ_ID(llc), 0)) {
			__sync_fetch_and_add(&nr_llc_dispatches, 1);
			return;
		}
		break;

	case TOPO_DSQ_NODE:
		node = cpu_node(cpu);
		if (node >= 0 &&
		    scx_bpf_dsq_move_to_local(NODE_DSQ_ID(node), 0)) {
			__sync_fetch_and_add(&nr_node_dispatches, 1);
			return;
		}
		break;

	case TOPO_DSQ_GLOBAL:
		if (scx_bpf_dsq_move_to_local(GLOBAL_DSQ_ID, 0)) {
			__sync_fetch_and_add(&nr_global_dispatches, 1);
			return;
		}
		break;
	}

	/*
	 * If no other task wants to run, let the same task run on the CPU,
	 * otherwise let the CPU go idle.
	 */
	if (prev && selection_keep_running(prev, cpu))
		scx_bpf_task_set_slice(prev, slice_ns);
}

/*
 * Called when a task starts running on a CPU.
 */
void BPF_STRUCT_OPS(forge_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate the
	 * used time slice in ops.stopping() and to estimate this task's current
	 * vruntime from a remote CPU in should_preempt_curr()).
	 *
	 * It is stored in the per-CPU context so should_preempt_curr() can read
	 * it without a task-local storage lookup on an untrusted remote-CPU
	 * current task.
	 */
	cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
	if (cctx)
		cctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Re-apply vlag here for those tasks that have been directly
	 * dispatched, bypassing the per-CPU DSQ.
	 */
	update_task_vruntime(p, tctx);

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, tctx->vruntime))
		vtime_now = tctx->vruntime;

	/*
	 * Capture the PMU baseline when the task starts running, so the counts
	 * read in ops.stopping() reflect just this slice.
	 */
	if (perf_config || perf_sticky)
		scx_pmu_event_start(p, false);
}

/*
 * Called on scheduler tick for the currently running task.
 *
 * The default policy does not need periodic tick work. Keep this callback in
 * place so generated policies can add tick-based accounting or preemption
 * logic without first wiring a new struct_ops callback.
 */
void BPF_STRUCT_OPS(forge_tick, struct task_struct *p)
{
	(void)p;
}

/*
 * Called when a task stops using a CPU.
 *
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(forge_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u64 slice, vtime;

	cctx = try_lookup_cpu_ctx(scx_bpf_task_cpu(p));
	if (!cctx)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	slice = bpf_ktime_get_ns() - cctx->last_run_at;
	slice = scale_by_cpu_capacity(slice, scx_bpf_task_cpu(p));

	/*
	 * Update task-local vruntime accounting. DSQ queue keys are assigned
	 * separately when tasks are inserted into vtime-ordered DSQs.
	 */
	vtime = tctx->vruntime + scale_by_task_weight_inverse(p, slice);
	tctx->vruntime = vtime;

	/*
	 * Accumulate execution time since the last wakeup, capped to bound the
	 * deadline offset and avoid starving long-running tasks.
	 */
	tctx->burst_time = MIN(tctx->burst_time + slice, slice_ns + NSEC_PER_MSEC);

	/*
	 * Stop the PMU counters and refresh the task's event counts for the
	 * slice that just ended.
	 */
	if (perf_config || perf_sticky)
		scx_pmu_event_stop(p);

	update_counters(p, tctx);
}

/*
 * Called when a task becomes runnable (on wake-up).
 */
void BPF_STRUCT_OPS(forge_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_woke_at = now;

	/* Reset execution time accumulated since the last wakeup. */
	tctx->burst_time = 0;
}

/*
 * Called when a task releases its assigned CPU and is no longer runnable.
 */
void BPF_STRUCT_OPS(forge_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * quiescent() is the reliable lifecycle hook for "no longer runnable",
	 * including direct-dispatched tasks. Preserve sleep lag only for actual
	 * sleep; CPU moves and sched property changes should not gain sleeper
	 * placement credit.
	 */
	if (!(deq_flags & SCX_DEQ_SLEEP)) {
		task_mark_none(tctx);
		return;
	}

	selection_save_sleep_vlag(p, tctx);
	task_mark_none(tctx);
}

/*
 * Called when a task enters the SCHED_EXT scheduler.
 */
void BPF_STRUCT_OPS(forge_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (tctx) {
		tctx->vruntime = vtime_now;
		tctx->has_sleep_vlag = false;
		task_mark_none(tctx);
	}

	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

/*
 * Called when a task leaves the SCHED_EXT scheduler.
 */
void BPF_STRUCT_OPS(forge_disable, struct task_struct *p)
{
	/*
	 * Reset the task's DSQ queue key when it leaves sched_ext, so that it
	 * is no longer mistaken for a sched_ext task by should_preempt_curr()
	 * while it runs under a different scheduling class.
	 */
	scx_bpf_task_set_dsq_vtime(p, 0);
}

/*
 * Called when a task is initialized in the SCHED_EXT scheduler (we can sleep
 * and allocate memory here).
 */
s32 BPF_STRUCT_OPS(forge_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct cgrp_ctx *cgc;
	s32 ret;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	task_mark_none(tctx);

	if (args->cgroup) {
		cgc = try_lookup_cgrp_ctx(args->cgroup);
		tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
	} else {
		tctx->cgweight = CGROUP_WEIGHT_DFL;
	}

	/* Allocate the task's PMU state when perf monitoring is enabled. */
	if (perf_config || perf_sticky) {
		ret = scx_pmu_task_init(p);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Called when a task leaves the SCHED_EXT scheduler for good (task exit).
 */
void BPF_STRUCT_OPS(forge_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (perf_config || perf_sticky)
		scx_pmu_task_fini(p);
}

/*
 * Initialize a cgroup with a local cgroup context.
 */
s32 BPF_STRUCT_OPS(forge_cgroup_init, struct cgroup *cgrp,
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

/*
 * Exit / unregister a cgroup.
 */
void BPF_STRUCT_OPS(forge_cgroup_exit, struct cgroup *cgrp)
{
}

/*
 * A cgroup weight is being changed.
 */
void BPF_STRUCT_OPS(forge_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;

	cgc = try_lookup_cgrp_ctx(cgrp);
	if (cgc)
		cgc->weight = weight;
}

/*
 * Commit a cgroup move: a task is moving from a cgroup to another.
 */
void BPF_STRUCT_OPS(forge_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx;
	struct cgrp_ctx *cgc;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	cgc = try_lookup_cgrp_ctx(to);
	tctx->cgweight = cgc ? cgc->weight : CGROUP_WEIGHT_DFL;
}

/*
 * Return the amount of online CPUs.
 *
 * NOTE: the scheduler is restarted on CPU hotplug events.
 */
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
 * Initialize a new cpumask, return 0 in case of success or a negative value
 * otherwise.
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
 * Create prepared-but-unused topology DSQs.
 *
 * These are placeholders for generated policies. The default enqueue() and
 * dispatch() paths never insert into or consume from them. This is the only
 * place that creates the global, per-LLC, and per-node DSQs; generated policies
 * should reuse the forge_*_dsq_id() helpers instead of calling
 * scx_bpf_create_dsq() again.
 */
static int init_dsqs(void)
{
	struct forge_topology *topo;
	u32 nr_llcs, nr_nodes;
	int i, err;

	topo = lookup_topology();
	if (!topo) {
		scx_bpf_error("missing topology info");
		return -ENOENT;
	}

	err = scx_bpf_create_dsq(GLOBAL_DSQ_ID, -1);
	if (err) {
		scx_bpf_error("failed to create global DSQ: %d", err);
		return err;
	}

	nr_nodes = MIN(topo->nr_nodes, (u32)FORGE_MAX_TOPO_DOMAINS);
	bpf_for(i, 0, nr_nodes) {
		struct forge_topo_node *node;
		s32 node_id;

		node_id = topo_node_id_at((u32)i);
		if (node_id < 0) {
			scx_bpf_error("missing NUMA node %d", i);
			return node_id;
		}

		node = lookup_topo_node((u32)node_id);
		if (!node || !node->nr_cpus)
			continue;

		err = scx_bpf_create_dsq(NODE_DSQ_ID(node_id), node_id);
		if (err) {
			scx_bpf_error("failed to create node DSQ %d: %d",
				      node_id, err);
			return err;
		}
	}

	nr_llcs = MIN(topo->nr_llcs, (u32)FORGE_MAX_TOPO_DOMAINS);
	bpf_for(i, 0, nr_llcs) {
		struct forge_topo_llc *llc;
		s32 llc_id, node_id;
		u32 dense_id = (u32)i;

		llc_id = topo_llc_id_at(dense_id);
		if (llc_id < 0) {
			scx_bpf_error("missing LLC topology id at index %u", dense_id);
			return llc_id;
		}

		llc = lookup_topo_llc((u32)llc_id);
		if (!llc || !llc->nr_cpus)
			continue;

		node_id = (int)llc->node_id;
		err = scx_bpf_create_dsq(LLC_DSQ_ID(dense_id), node_id);
		if (err) {
			scx_bpf_error("failed to create LLC DSQ %u: %d", dense_id, err);
			return err;
		}
	}

	bpf_for(i, 0, nr_cpu_ids) {
		s32 node_id = NUMA_NO_NODE;

		if (!lookup_topo_cpu(i))
			continue;

		node_id = cpu_node(i);
		if (node_id < 0) {
			scx_bpf_error("missing NUMA node for CPU DSQ %d", i);
			return node_id;
		}

		err = scx_bpf_create_dsq(CPU_DSQ_ID(i), node_id);
		if (err) {
			scx_bpf_error("failed to create CPU DSQ %d: %d", i, err);
			return err;
		}
	}

	return 0;
}

/*
 * Initialize the SCHED_EXT scheduler.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(forge_init)
{
	s32 err;

	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Install the configured PMU events before any task starts running. */
	if (perf_config) {
		err = scx_pmu_install(perf_config);
		if (err)
			return err;
	}
	if (perf_sticky) {
		err = scx_pmu_install(perf_sticky);
		if (err)
			return err;
	}

	return init_dsqs();
}

/*
 * Exit/unregister the SCHED_EXT scheduler.
 */
void BPF_STRUCT_OPS(forge_exit, struct scx_exit_info *ei)
{
	if (perf_config)
		scx_pmu_uninstall(perf_config);
	if (perf_sticky)
		scx_pmu_uninstall(perf_sticky);

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

/*
 * Called from user-space to add CPUs to the primary domain.
 */
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

SCX_OPS_DEFINE(forge_ops,
	       .select_cpu		= (void *)forge_select_cpu,
	       .enqueue			= (void *)forge_enqueue,
	       .dequeue			= (void *)forge_dequeue,
	       .dispatch		= (void *)forge_dispatch,
	       .running			= (void *)forge_running,
	       .tick			= (void *)forge_tick,
	       .stopping		= (void *)forge_stopping,
	       .runnable		= (void *)forge_runnable,
	       .quiescent		= (void *)forge_quiescent,
	       .enable			= (void *)forge_enable,
	       .disable			= (void *)forge_disable,
	       .init_task		= (void *)forge_init_task,
	       .exit_task		= (void *)forge_exit_task,
	       .cgroup_init		= (void *)forge_cgroup_init,
	       .cgroup_exit		= (void *)forge_cgroup_exit,
	       .cgroup_set_weight	= (void *)forge_cgroup_set_weight,
	       .cgroup_move		= (void *)forge_cgroup_move,
	       .init			= (void *)forge_init,
	       .exit			= (void *)forge_exit,
	       .timeout_ms		= 5000ULL,
	       .name			= "forge");
