/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/pmu.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Maximum amount of NUMA nodes supported by the scheduler.
 */
#define MAX_NODES	1024

/*
 * Maximum amount of GPUs supported by the scheduler.
 */
#define MAX_GPUS	32

/*
 * Shared DSQ used to schedule tasks in deadline mode when the system is
 * saturated.
 *
 * When system is not saturated tasks will be dispatched to the local DSQ
 * in round-robin mode.
 */

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Subset of CPUs to prioritize.
 */
private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Complement of @primary_cpumask (only initialized when a primary domain
 * is defined): CPUs that can be used only when the primary domain is
 * overloaded.
 */
private(COSMOS) struct bpf_cpumask __kptr *nonprimary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile bool primary_all = true;

/*
 * Enable flat iteration to find idle CPUs (fast but inaccurate).
 */
const volatile bool flat_idle_scan = false;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Enable preferred cores prioritization.
 */
const volatile bool preferred_idle_scan = false;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * True when all CPUs have the same capacity (no capacity asymmetry).
 */
const volatile bool all_cpus_same_capacity = false;

/*
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations.
 */
const volatile bool numa_enabled;

/*
 * Enable automatic GPU affinity.
 */
const volatile bool gpu_enabled = true;

/*
 * Enable address space affinity.
 */
const volatile bool mm_affinity;

/*
 * ID of perf-event being tracked. 0 for "no event".
 */
const volatile u64 perf_config;

/*
 * Performance counter threshold to classify a task as event heavy.
 */
volatile u64 perf_threshold;

/*
 * Sticky perf event (0x0 = disabled). When task's count for this event
 * exceeds perf_sticky_threshold, keep it on the same CPU.
 */
const volatile u64 perf_sticky;

/*
 * Threshold for sticky event; task is kept on same CPU when exceeded.
 */
volatile u64 perf_sticky_threshold;

/*
 * Disable high-resolution preemption enforcement.
 */
const volatile bool time_preemption;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Disable early clearing of idle CPU state.
 */
const volatile bool no_early_clear;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 1000000ULL;

/*
 * Maximum lag, in virtual time, that a task can carry across a sleep.
 */
const volatile u64 slice_lag = 20000000ULL;

/*
 * Per-CPU contention threshold, in the range [0 .. 1024], to determine
 * when a CPU is busy: a CPU is considered busy when it has had tasks
 * waiting to run for more than this fraction of time.
 *
 * 0 = contention tracking disabled: every CPU is always considered busy
 * (pure deadline mode) and no contention state is ever updated (the
 * branches are resolved at load time, since this is read-only data frozen
 * at that point).
 */
const volatile u64 busy_threshold;

/*
 * Maximum time (ns) that tasks are allowed to wait in a shared DSQ before
 * the primary domain is considered overloaded, allowing tasks to spill to
 * the non-primary CPUs (0 = tasks are always contained in the primary
 * domain).
 */
const volatile u64 overload_thresh_ns;

/*
 * Scheduler statistics.
 */
volatile u64 nr_event_dispatches;
volatile u64 nr_ev_sticky_dispatches;
volatile u64 nr_gpu_dispatches;
volatile u64 nr_steals;
volatile u64 nr_overload_events;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * Maximum possible NUMA node number.
 */
const volatile u32 nr_node_ids;

/*
 * Current system vruntime.
 */
static u64 vtime_now;

/*
 * Total weight of the runnable tasks, EEVDF's \Sum w_i (cfs_rq->sum_weight).
 *
 * Maintained across the ops.runnable() / ops.quiescent() pair, which the core
 * scheduler guarantees to be symmetric, so it converges even when a task is
 * dequeued without ever being consumed by the BPF side.
 */
static u64 sum_weight;

/*
 * Per-task context.
 */
struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	u64 last_run_at;
	u64 last_stop_at;
	u64 last_utime;
	u64 vruntime;
	s64 vlag;
	u64 perf_events;
	u64 perf_sticky_events;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * NUMA node context.
 */
struct node_ctx {
        struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NODES);
} node_ctx_stor SEC(".maps");

struct node_ctx *try_lookup_node_ctx(int node)
{
	return bpf_map_lookup_elem(&node_ctx_stor, &node);
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

	if (!numa_enabled)
		return 0;

	id = bpf_map_lookup_elem(&cpu_node_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

/*
 * GPU -> node mapping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GPUS);
	__type(key, u32);	/* nvml_id */
	__type(value, u32);	/* node_id */
} gpu_node_map SEC(".maps");

/*
 * Process TGID -> NUMA node mapping for GPU workload tasks. NVML identifies
 * GPU processes, and userspace may include peer processes from the same
 * workload cgroup.
 */
#define MAX_GPU_PIDS	8192

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GPU_PIDS);
	__type(key, u32);	/* process tgid */
	__type(value, u32);	/* node_id */
} gpu_pid_map SEC(".maps");

/*
 * Look up the preferred NUMA node for a process TGID from the userspace-
 * provided GPU workload list. Returns a node id or a negative
 * error.
 */
static int gpu_node_by_tgid(u32 tgid)
{
	u32 *node;

	if (!gpu_enabled || !numa_enabled)
		return -ENOENT;

	node = bpf_map_lookup_elem(&gpu_pid_map, &tgid);
	if (!node)
		return -ENOENT;

	return *node;
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
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_update;
	u64 perf_lvl;
	u64 perf_events;
	u64 busy_avg;
	u64 busy_eval_at;
	u64 acc_utime;
	u64 vtime_rem;
	u32 steal_cursor;
	bool busy;
	struct bpf_cpumask __kptr *smt;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

static void update_counters(struct task_struct *p, struct task_ctx *tctx, s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 delta = 0;
	u64 sticky_delta = 0;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->perf_events += delta;

	if (perf_config) {
		scx_pmu_read(p, perf_config, &delta, true);
		tctx->perf_events = delta;
	}

	if (perf_sticky) {
		scx_pmu_read(p, perf_sticky, &sticky_delta, true);
		tctx->perf_sticky_events = sticky_delta;
	}
}

/*
 * Return true if the task is triggering too many PMU events (migration event).
 */
static inline bool is_event_heavy(const struct task_ctx *tctx)
{
	return perf_config && tctx->perf_events > perf_threshold;
}

/*
 * Return true if the task exceeds the sticky event threshold and should
 * stay on the same CPU.
 */
static inline bool is_sticky_event_heavy(const struct task_ctx *tctx)
{
	return perf_sticky && tctx->perf_sticky_events > perf_sticky_threshold;
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, u64 slice)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_t;
	struct cpu_ctx *cctx;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_update;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);
	cctx->last_update = now;
}

/*
 * Apply target cpufreq performance level to @cpu.
 */
static void update_cpufreq(s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 perf_lvl;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Apply target performance level to the cpufreq governor.
	 */
	if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 2;
	else
		perf_lvl = cctx->perf_lvl;

	scx_bpf_cpuperf_set(cpu, perf_lvl);
}

/*
 * Return the DSQ of @cpu.
 *
 * Every CPU owns a deadline ordered DSQ where the tasks that last ran on
 * it are queued, and every dispatch scans the heads of the DSQs of the
 * node for the earliest deadline (see try_steal_task()). All the keys are
 * built on the same system-wide vruntime reference, so the queues behave
 * as a single node-wide deadline queue, without the single lock that a
 * single queue puts in the path of every wakeup.
 */
static inline u64 cpu_dsq(s32 cpu)
{
	return cpu;
}

/*
 * Primary domain overload detection.
 *
 * When a primary domain is defined, tasks are contained in it and are not
 * allowed to spill to the non-primary CPUs, unless the primary domain is
 * overloaded.
 *
 * Instantaneous saturation (no idle primary CPU at a given moment) is not
 * a reliable overload signal: bursty workloads can saturate the domain for
 * microseconds at a time (e.g., barrier wakeups) and spilling in response
 * to such transients just moves work to worse CPUs (typically the SMT
 * siblings of the primary CPUs).
 *
 * Overload is instead defined in terms of sustained queueing delay, per
 * NUMA node: @node_empty_ts tracks the last time the node's shared DSQ was
 * observed empty from ops.dispatch(), so a shared DSQ that has been
 * continuously backlogged for longer than @overload_thresh_ns means the
 * primary domain can't keep up and waiting is costing more than running on
 * a non-primary CPU.
 *
 * When that happens the node is marked overloaded for a short decay window
 * (@overload_until): spilling is allowed while the window keeps being
 * renewed by backlogged enqueues and stops automatically once the backlog
 * drains, without the ping-pong that an instantaneous threshold would
 * cause.
 */
#define OVERLOAD_WINDOW_NS	(25ULL * NSEC_PER_MSEC)

static u64 node_empty_ts[MAX_NODES];
static u64 overload_until[MAX_NODES];

/*
 * Return true if the primary domain is overloaded on @node, false
 * otherwise.
 */
static bool is_primary_overloaded(int node)
{
	if (primary_all || !overload_thresh_ns)
		return false;

	if (node < 0 || node >= MAX_NODES)
		return false;

	return time_before(bpf_ktime_get_ns(), overload_until[node]);
}

/*
 * Wake up an idle non-primary CPU (close to @from_cpu) to start draining
 * the shared DSQ.
 */
static void kick_idle_nonprimary(s32 from_cpu)
{
	const struct cpumask *nonpri = cast_mask(nonprimary_cpumask);
	s32 cpu;

	if (!nonpri)
		return;

	if (numa_enabled)
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(nonpri,
					__COMPAT_scx_bpf_cpu_node(from_cpu), 0);
	else
		cpu = scx_bpf_pick_idle_cpu(nonpri, 0);

	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Update the overload state of @node after inserting a task into its
 * shared DSQ from @cpu.
 */
static void update_primary_overload(s32 cpu, int node)
{
	u64 now;

	if (primary_all || !overload_thresh_ns)
		return;

	if (node < 0 || node >= MAX_NODES)
		return;

	/*
	 * The shared DSQ has been empty recently: the primary domain is
	 * keeping up with the load.
	 */
	now = bpf_ktime_get_ns();
	if (time_delta(now, node_empty_ts[node]) < overload_thresh_ns)
		return;

	if (!is_primary_overloaded(node))
		__sync_fetch_and_add(&nr_overload_events, 1);
	overload_until[node] = now + OVERLOAD_WINDOW_NS;

	/*
	 * Idle non-primary CPUs are never picked and never kicked during
	 * normal operation, so nothing would drain the backlog without an
	 * explicit wakeup.
	 */
	kick_idle_nonprimary(cpu);
}

/*
 * Return true if task @p can run on NUMA node @node, false otherwise.
 */
static bool can_use_node(const struct task_struct *p, int node)
{
	struct node_ctx *nctx;

	if (!numa_enabled)
		return true;

	if (p->nr_cpus_allowed == nr_cpu_ids)
		return true;

	nctx = try_lookup_node_ctx(node);
	if (!nctx || !nctx->cpumask ||
	    !bpf_cpumask_intersects(cast_mask(nctx->cpumask), p->cpus_ptr))
		return false;

	return true;
}

/*
 * If the task's thread group is in gpu_pid_map and should run on a different
 * node, pick a CPU on the preferred GPU node. Returns the CPU id (>= 0) on
 * success, or a negative value if the task is not GPU-bound, is already on
 * the right node, or no suitable CPU was found.
 */
static s32 pick_cpu_on_gpu_node(const struct task_struct *p, int node,
				struct task_ctx *tctx)
{
	struct node_ctx *nctx;
	struct bpf_cpumask *mask;
	int target_node;

	target_node = gpu_node_by_tgid(p->tgid);
	if (target_node < 0 || target_node == node || !can_use_node(p, target_node))
		return -ENOENT;

	nctx = try_lookup_node_ctx(target_node);
	if (!nctx || !nctx->cpumask)
		return -ENOENT;

	mask = tctx->cpumask;
	if (!mask || !bpf_cpumask_and(mask, cast_mask(nctx->cpumask), p->cpus_ptr))
		return -ENOENT;

	return __COMPAT_scx_bpf_pick_idle_cpu_node(cast_mask(mask), target_node, 0);
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
 * Per-CPU user utilization tracking.
 *
 * This determines, per CPU, when the scheduler needs to switch to
 * deadline-mode (using a shared DSQ) vs round-robin mode (using per-CPU
 * local DSQs).
 *
 * The signal is the fraction of wall time the CPU spends executing user
 * code, deliberately excluding system time: sleep-intensive workloads
 * (frequent short sleeps and wakeups) burn most of their CPU time in the
 * kernel, and for them tasks should stay on their CPU / local DSQ to
 * reduce the scheduling overhead and the balancing pressure in
 * ops.dispatch(). Only CPUs running sustained user work are worth the
 * extra migrations that deadline mode brings.
 *
 * The user time of the running task (p->utime deltas, charged in
 * ops.tick() and ops.stopping()) is accumulated per CPU and periodically
 * folded into an EWMA (@busy_avg) of the user utilization, normalized in
 * the range [0 .. 1024] of wall time. The busy state is derived from the
 * EWMA with hysteresis (enter at @busy_threshold, exit at 3/4 of it) to
 * avoid flapping between the two modes around the threshold. Idle CPUs
 * don't tick, so a CPU with no recent evaluations is considered not
 * busy.
 */
#define BUSY_EVAL_NS	(10ULL * NSEC_PER_MSEC)
#define BUSY_STALE_NS	(50ULL * NSEC_PER_MSEC)

/*
 * Charge the user time accumulated by @p (running on @cpu) since the
 * last update and periodically refresh the CPU's busy state.
 */
static void update_cpu_busy(struct task_struct *p, s32 cpu)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	u64 now, delta_t, util;

	if (!busy_threshold)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	tctx = try_lookup_task_ctx(p);
	if (!cctx || !tctx)
		return;

	cctx->acc_utime += p->utime - tctx->last_utime;
	tctx->last_utime = p->utime;

	now = bpf_ktime_get_ns();
	delta_t = time_delta(now, cctx->busy_eval_at);
	if (delta_t < BUSY_EVAL_NS)
		return;

	util = MIN(cctx->acc_utime * 1024 / delta_t, 1024);
	cctx->busy_avg = calc_avg(cctx->busy_avg, util);
	cctx->acc_utime = 0;
	cctx->busy_eval_at = now;

	if (!cctx->busy && cctx->busy_avg >= busy_threshold)
		cctx->busy = true;
	else if (cctx->busy && cctx->busy_avg < busy_threshold - busy_threshold / 4)
		cctx->busy = false;
}

/*
 * Return true if the given CPU is busy (running sustained user work),
 * false otherwise.
 *
 * @cpu should be the CPU of interest: prev_cpu in select_cpu/enqueue, or
 * scx_bpf_task_cpu(p) in tick.
 */
static inline bool is_cpu_busy(s32 cpu)
{
	struct cpu_ctx *cctx;

	/*
	 * Utilization tracking disabled: always use deadline mode.
	 */
	if (!busy_threshold)
		return true;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return true;

	/*
	 * No recent evaluations: the CPU has been (mostly) idle, hence
	 * not busy.
	 */
	if (time_delta(bpf_ktime_get_ns(), cctx->busy_eval_at) > BUSY_STALE_NS)
		return false;

	return cctx->busy;
}

/*
 * Return the SMT sibling CPU of a @cpu.
 */
static s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx *cctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return cpu;

	smt = cast_mask(cctx->smt);
	if (!smt)
		return cpu;

	return bpf_cpumask_first(smt);
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
 * Return the cpumask of idle SMT cores within the NUMA node that contains
 * @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_smtmask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_smtmask();

	return __COMPAT_scx_bpf_get_idle_smtmask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return true if the CPU is part of a fully busy SMT core, false
 * otherwise.
 *
 * If SMT is disabled or SMT contention avoidance is disabled, always
 * return false (since there's no SMT contention or it's ignored).
 */
static bool is_smt_contended(s32 cpu)
{
	const struct cpumask *idle_mask;
	bool is_contended;
	s32 sibling;

	if (!smt_enabled)
		return false;

	/*
	 * A CPU without an SMT sibling (e.g. an E-core on a hybrid part)
	 * has nothing to be contended by. Its sibling mask is empty, so
	 * smt_sibling() returns an out-of-range CPU that never tests idle,
	 * which would otherwise report the CPU as contended whenever any
	 * other CPU in the system is idle.
	 */
	sibling = smt_sibling(cpu);
	if (sibling == cpu || sibling < 0 || sibling >= nr_cpu_ids)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask = get_idle_cpumask(cpu);
	is_contended = !bpf_cpumask_test_cpu(sibling, idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if @cpu is valid, otherwise trigger an error and return
 * false.
 */
static inline bool is_cpu_valid(s32 cpu)
{
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);

	if (cpu < 0 || cpu >= max_cpu) {
		scx_bpf_error("invalid CPU id: %d", cpu);
		return false;
	}
	return true;
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
	if (this_cpu == that_cpu)
		return true;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}
/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
	if (all_cpus_same_capacity || this_cpu == that_cpu)
		return false;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_capacity[this_cpu] > cpu_capacity[that_cpu];
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

static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
}

/*
 * Test if a CPU is idle.
 *
 * If no_early_clear is true, leave the idle state intact so that concurrent
 * wakeups can stack tasks on the same cache. Otherwise, atomically test and
 * clear the idle state.
 */
static inline bool test_cpu_idle(s32 cpu)
{
	return no_early_clear ? is_cpu_idle(cpu) : scx_bpf_test_and_clear_cpu_idle(cpu);
}

/*
 * Try to pick the best idle CPU based on the @preferred_cpus ranking.
 * Return a full-idle SMT core if @do_idle_smt is true, or any idle CPU if
 * @do_idle_smt is false.
 */
static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
				  const struct cpumask *primary, const struct cpumask *smt)
{
	static u32 last_cpu;
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i, start;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    test_cpu_idle(prev_cpu))
		return prev_cpu;

	start = last_cpu;
	bpf_for(i, 0, max_cpus) {
		/*
		 * If @preferred_idle_scan is true, always scan the CPUs in
		 * the preferred order, otherwise rotate the CPUs to
		 * distribute the load more evenly.
		 */
		s32 cpu = preferred_idle_scan ?
				preferred_cpus[i] : (start + i) % max_cpus;

		if ((cpu == prev_cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		if ((!primary || bpf_cpumask_test_cpu(cpu, primary)) &&
		    (!smt || bpf_cpumask_test_cpu(cpu, smt)) &&
		    test_cpu_idle(cpu)) {
			if (!preferred_idle_scan)
				last_cpu = cpu + 1;
			return cpu;
		}
	}

	return -EBUSY;
}

/*
 * Return the optimal idle CPU for task @p or -EBUSY if no idle CPU is
 * found.
 */
static s32 pick_idle_cpu_flat(struct task_struct *p, s32 prev_cpu)
{
	const struct cpumask *smt, *primary;
	bool is_prev_allowed = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	s32 cpu;

	primary = !primary_all ? cast_mask(primary_cpumask) : NULL;
	smt = smt_enabled ? get_idle_smtmask(prev_cpu) : NULL;

	/*
	 * If the task can't migrate, there's no point looking for other
	 * CPUs.
	 */
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		if (test_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out;
		}
	}

	if (!primary_all) {
		if (smt_enabled) {
			/*
			 * Try to pick a full-idle core in the primary
			 * domain.
			 */
			cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);
			if (cpu >= 0)
				goto out;
		}

		/*
		 * Try to pick any idle CPU in the primary domain.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, NULL);
		if (cpu >= 0)
			goto out;

		/*
		 * Contain the task in the primary domain, unless the
		 * domain is overloaded.
		 */
		if (primary && bpf_cpumask_intersects(p->cpus_ptr, primary) &&
		    !is_primary_overloaded(cpu_node(prev_cpu))) {
			cpu = -EBUSY;
			goto out;
		}
	}

	if (smt_enabled) {
		/*
		 * Try to pick any full-idle core in the system.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, smt);
		if (cpu >= 0)
			goto out;
	}

	/*
	 * Try to pick any idle CPU in the system.
	 */
	cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, NULL);

out:
	if (smt)
		scx_bpf_put_cpumask(smt);

	return cpu;
}

/*
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Use lightweight idle CPU scanning when flat or preferred idle
	 * scan is enabled, unless the system is busy, in which case the
	 * cpumask-based scanning is more efficient.
	 */
	if ((flat_idle_scan || preferred_idle_scan) && !is_cpu_busy(prev_cpu))
		return pick_idle_cpu_flat(p, prev_cpu);

	/*
	 * Clear the wake sync bit if synchronous wakeups are disabled.
	 */
	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 *
	 * In presence of hybrid cores this helps to naturally migrate
	 * tasks over to the faster cores.
	 */
	if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
	    is_cpu_faster(this_cpu, prev_cpu)) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    !is_smt_contended(prev_cpu) &&
		    test_cpu_idle(prev_cpu))
			return prev_cpu;

		prev_cpu = this_cpu;
	}

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		bool is_idle = false;

		if (from_enqueue)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * If a primary domain is defined, try to pick an idle CPU from there
	 * first.
	 */
	if (!primary_all && mask && bpf_cpumask_intersects(p->cpus_ptr, mask)) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask, 0);
		if (cpu >= 0)
			return cpu;

		/*
		 * Contain the task in the primary domain, unless the
		 * domain is overloaded.
		 */
		if (!is_primary_overloaded(cpu_node(prev_cpu)))
			return -EBUSY;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Floor on the weight used to stretch the request and the lag bound.
 *
 * The scx weight of a nice 19 task is 1, so its request would be a hundred
 * times the base slice and the lag it can carry two hundred times: under
 * a deep backlog V takes many seconds to cover that, well past the
 * watchdog. The vruntime is still charged with the real weight, so the
 * share is what nice asks for; only how far ahead the deadline and the lag
 * can stretch is capped, which update_deadline() itself notes is "probably
 * good enough".
 */
#define MIN_DL_WEIGHT	25

static u64 scale_by_dl_weight(const struct task_struct *p, u64 value)
{
	u64 weight = p->scx.weight;

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * 100 / weight;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * This is EEVDF's virtual deadline, see update_deadline():
 *
 *	vd_i = ve_i + r_i / w_i
 *
 * The request size r_i is the same @slice_ns for everybody, exactly like
 * sysctl_sched_base_slice: the weight does not buy a task a longer time
 * slice, it buys it an earlier deadline, so it runs more often instead of
 * running longer.
 *
 * The deadline is the DSQ key and nothing else. The kernel stores what is
 * passed to scx_bpf_dsq_insert_vtime() in p->scx.dsq_vtime, so the
 * vruntime has to live somewhere the key cannot overwrite it, see
 * task_ctx.vruntime.
 *
 * pick_eevdf() considers only the eligible tasks, v_i <= V, and picks the
 * earliest deadline among them. A DSQ cannot skip a task and its key is
 * fixed at insertion, so the filter is not applied here. It is mostly not
 * needed: a task that is over-served carries the excess in its key and
 * sorts after the under-served tasks of the same weight, and stays there
 * until V has moved past it, which is the wait pick_eevdf() would impose
 * anyway. What is lost is the case of a heavier over-served task, whose
 * r_i / w_i is smaller, sorting ahead of a lighter under-served one: it
 * wins by at most the difference between the two requests, a bounded
 * latency skew, not a fairness leak, since the vruntime is charged all
 * the same.
 *
 * Pushing the ineligible tasks further back with an offset, to apply the
 * filter exactly, would starve them instead. V advances by the service
 * delivered divided by the total weight, so under load it barely moves,
 * and a task waiting for V to cover a fixed offset waits for seconds
 * while every newly woken task keeps being queued ahead of it.
 */
static u64 task_dl(const struct task_struct *p, const struct task_ctx *tctx)
{
	return tctx->vruntime + scale_by_dl_weight(p, slice_ns);
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
 * Called from user-space to add CPUs to the the primary domain.
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

/*
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * Attempt a migration on wakeup (task was not running) and only if
	 * ops.select_cpu() has not been called already.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Return true if a task that only @cpu can run is waiting in @cpu's DSQ.
 *
 * The kernel skips ops.dispatch() entirely while a CPU's local DSQ is not
 * empty (see dispatch_one()), so tasks stacked on a local DSQ silently
 * outrank the deadline-ordered DSQs. A task pinned to @cpu can therefore
 * wait in @cpu's DSQ forever: remote CPUs skip it in try_steal_task() and
 * @cpu never gets to ops.dispatch().
 *
 * The DSQ is ordered by deadline and the deadline of a task that is
 * not running is fixed at insertion time, so a starving task climbs to the
 * head as the queue drains: peeking at the head is enough to notice it.
 */
static bool dsq_has_pinned_waiter(s32 cpu)
{
	const struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));

	return p && is_pcpu_task(p) && scx_bpf_task_cpu(p) == cpu;
}

/*
 * Direct dispatch @p to the local DSQ of @cpu from ops.select_cpu().
 *
 * Insert with SCX_ENQ_IMMED so that the kernel bounces @p back through
 * ops.enqueue() (and from there into a per-CPU DSQ, where the deadline
 * ordering applies) whenever @p can't run on @cpu right away. This keeps
 * the local DSQ a pure "run now" fast path instead of an unbounded queue
 * that outranks the deadline-ordered DSQs.
 *
 * On kernels without SCX_ENQ_IMMED the flag reads as 0, so fall back to
 * skipping the direct dispatch when a task only @cpu can run is already
 * waiting: @p then falls through to ops.enqueue() on its own.
 */
static void direct_dispatch_local(struct task_struct *p, s32 cpu)
{
	if (!SCX_ENQ_IMMED && dsq_has_pinned_waiter(cpu))
		return;

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, SCX_ENQ_IMMED);
}

/*
 * Return true if a task is waking up another task that share the same
 * address space, false otherwise.
 */
static inline bool
is_wake_affine(const struct task_struct *waker, const struct task_struct *wakee)
{
	return mm_affinity &&
		!(waker->flags & PF_EXITING) && wakee->mm && (wakee->mm == waker->mm);
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;
	bool is_busy = is_cpu_busy(prev_cpu);
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * When the waker and wakee share the same address space and were previously
	 * running on the same CPU, there's a high chance of finding hot cache data
	 * on that CPU. In such cases, prefer keeping the wakee on the same CPU.
	 *
	 * This optimization is applied only when the system is not saturated,
	 * to avoid introducing too much unfairness.
	 */
	if (is_wake_affine(current, p) && !is_busy) {
		if (this_cpu == prev_cpu) {
			direct_dispatch_local(p, this_cpu);
			return this_cpu;
		}
	}

	/*
	 * If GPU affinity is enabled and the task's TGID is in gpu_pid_map
	 * but not on the GPU's node, try to pick a CPU on the GPU node.
	 */
	if (gpu_enabled && numa_enabled) {
		cpu = pick_cpu_on_gpu_node(p, cpu_node(prev_cpu), tctx);
		if (cpu >= 0) {
			__sync_fetch_and_add(&nr_gpu_dispatches, 1);
			direct_dispatch_local(p, cpu);
			return cpu;
		}
	}

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false);
	if (cpu >= 0 || !is_busy)
		direct_dispatch_local(p, cpu >= 0 ? cpu : prev_cpu);

	return cpu >= 0 ? cpu : prev_cpu;
}

void BPF_STRUCT_OPS(cosmos_tick, struct task_struct *p)
{
	struct task_ctx *tctx;

	/*
	 * Refresh the CPU user utilization state (resolved to a no-op at
	 * load time when utilization tracking is disabled).
	 */
	if (busy_threshold)
		update_cpu_busy(p, scx_bpf_task_cpu(p));

	if (!time_preemption)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Force preemption if the task has exceeded its time slice and
	 * either:
	 * - SMT contention has changed since we started running
	 *   (sibling went busy or idle), triggering rescheduling so
	 *   select_cpu can make a better placement decision, or
	 * - the system is busy and there are tasks waiting in the
	 *   local or shared DSQ.
	 */
	if (time_delta(bpf_ktime_get_ns(), tctx->last_run_at) > slice_ns) {
		s32 cpu = scx_bpf_task_cpu(p);
		bool cpu_busy = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) ||
				scx_bpf_dsq_nr_queued(cpu_dsq(cpu));

		if (is_smt_contended(cpu) || (is_cpu_busy(cpu) && cpu_busy))
			scx_bpf_task_set_slice(p, 0);
	}
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	int node = cpu_node(prev_cpu);
	struct task_ctx *tctx;

	/*
	 * Dispatch the task to the shared DSQ, using the deadline-based
	 * scheduling.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * If the task's TGID is in gpu_pid_map (GPU workload process), prefer the
	 * GPU NUMA node. If we're on a different node, migrate to the GPU
	 * node.
	 */
	if (gpu_enabled && numa_enabled && !is_pcpu_task(p) &&
	    task_should_migrate(p, enq_flags)) {
		cpu = pick_cpu_on_gpu_node(p, node, tctx);
		if (cpu >= 0) {
			__sync_fetch_and_add(&nr_gpu_dispatches, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   slice_ns, enq_flags);
			return;
		}
	}

	/*
	 * Attempt to immediately dispatch sticky event-heavy tasks to the
	 * same CPU.
	 */
	if (is_sticky_event_heavy(tctx) &&
	    (is_primary_cpu(prev_cpu) || is_pcpu_task(p)) &&
	    !is_smt_contended(prev_cpu)) {
		const struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(prev_cpu));

		/*
		 * If a per-CPU task is waiting to acquire the CPU, skip
		 * direct dispatch to prevent starvation.
		 */
		if (!q || q->nr_cpus_allowed > 1) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
			__sync_fetch_and_add(&nr_ev_sticky_dispatches, 1);
			return;
		}
	}

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 *
	 * A busy @prev_cpu is a reason to leave only when it is busy with
	 * someone else. A task that is re-enqueued from its own CPU at the
	 * end of its slice is what @prev_cpu is busy with, and it is giving
	 * the CPU up to whoever was waiting for it, typically a per-CPU
	 * kworker that is done a few microseconds later. Pushing it away at
	 * that point turns every such handover into a migration. Leave it
	 * queued instead, the way a task stays on its runqueue: its own CPU
	 * takes it back as soon as it is free again.
	 *
	 * A task re-enqueued from its own CPU with slice left, on the other
	 * hand, was preempted by a higher scheduling class (the kernel
	 * bounces an IMMED task back through ops.enqueue() in that case)
	 * and @prev_cpu is taken for an unknown amount of time, so an idle
	 * CPU is the better option.
	 */
	if (task_should_migrate(p, enq_flags) ||
	    (!is_cpu_idle(prev_cpu) && (!scx_bpf_task_running(p) || p->scx.slice)) ||
	    (!is_pcpu_task(p) && is_smt_contended(prev_cpu)) ||
	    (!is_pcpu_task(p) && (is_event_heavy(tctx) || !is_primary_cpu(prev_cpu)))) {
		if (is_pcpu_task(p))
			cpu = test_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   slice_ns, enq_flags | SCX_ENQ_IMMED);
			if (is_event_heavy(tctx) && cpu != prev_cpu)
				__sync_fetch_and_add(&nr_event_dispatches, 1);
			return;
		}
	}

	/*
	 * Keep using the same CPU if that CPU is not busy.
	 */
	if (!is_cpu_busy(prev_cpu) &&
	    (is_primary_cpu(prev_cpu) || is_pcpu_task(p))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_ns, enq_flags);
		return;
	}

	/*
	 * Queue the task on @prev_cpu's DSQ, ordered by deadline.
	 *
	 * Any CPU of the node can take it from there, but only while
	 * dispatching: if @prev_cpu went idle in the meantime and the rest
	 * of the node is idle too, nothing would ever look at it. Kick
	 * @prev_cpu, which is a no-op unless it is idle.
	 */
	scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
				 slice_ns, task_dl(p, tctx), enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);

	/*
	 * Detect a sustained backlog on the node and, in that case, allow
	 * tasks to spill to the non-primary CPUs.
	 */
	update_primary_overload(prev_cpu, node);
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	/*
	 * Do not keep running if the task doesn't need to run.
	 */
	if (!is_task_queued(p))
		return false;

	/*
	* If the task can only run on this CPU, keep it running.
	*/
	if (is_pcpu_task(p))
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
	if (!is_primary_cpu(cpu) &&
	    mask && bpf_cpumask_intersects(p->cpus_ptr, mask))
		return false;

	return true;
}

/*
 * Number of other CPUs' DSQs sampled at each dispatch while this CPU has
 * work of its own. 0 = a busy CPU never steals, only an idle one pulls.
 */
const volatile u64 steal_sample;

/*
 * A task that ran within this long on its CPU is still cache hot there and
 * is not stolen, like task_hot() with sysctl_sched_migration_cost.
 */
#define MIGRATION_COST_NS	500000ULL

static bool task_hot(struct task_struct *p, u64 now)
{
	const struct task_ctx *tctx = try_lookup_task_ctx(p);

	return tctx && time_before(now, tctx->last_stop_at + MIGRATION_COST_NS);
}

/*
 * Dispatch on @dst_cpu the task with the earliest deadline among the head
 * of its own DSQ and the heads of the DSQs of other CPUs on the node.
 *
 * With the per-CPU keys all built on the same system-wide vruntime
 * reference, the earliest head across the queues is the task a single
 * node-wide queue would hand out. Peeking every queue at every dispatch
 * costs as much as the single queue's lock did, though, so the scan is
 * bounded: a CPU with work of its own samples @steal_sample other queues,
 * rotating through them across dispatches, and takes a remote head only
 * when it is at least a full request ahead of its own; a task with real
 * lag to spend is found within a few dispatches, while under a balanced
 * load nothing clears the bar and every CPU drains its own queue, as its
 * own runqueue would be drained by EEVDF. A CPU with nothing of its own
 * takes the first task it finds instead of the earliest, the way the idle
 * balancer pulls whatever is available.
 *
 * A task that ran on its CPU a moment ago is left there in both cases:
 * its home CPU takes it back within a slice, while moving it costs its
 * cache, see task_hot(). This is what keeps a wakeup-heavy load from
 * migrating on every idle transition.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cpu
 * (or is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cpu)
{
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(dst_cpu);
	struct task_struct *own = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(dst_cpu));
	int node = cpu_node(dst_cpu);
	u64 min_dl = 0, now = bpf_ktime_get_ns();
	u32 limit, start, cpu, i;
	s32 min_cpu = -1;

	/*
	 * One extra slot covers @dst_cpu itself falling in the sample.
	 */
	limit = own ? (steal_sample ? steal_sample + 1 : 0) : nr_cpu_ids;
	start = cctx ? cctx->steal_cursor : dst_cpu;
	if (start >= nr_cpu_ids)
		start = 0;

	bpf_for(i, 0, limit) {
		struct task_struct *p;

		cpu = start + 1 + i;
		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;
		if (cpu >= nr_cpu_ids || cpu == dst_cpu)
			continue;
		if (numa_enabled && cpu_node(cpu) != node)
			continue;

		p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
		if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr) ||
		    task_hot(p, now))
			continue;

		if (min_cpu < 0 || time_before(p->scx.dsq_vtime, min_dl)) {
			min_dl = p->scx.dsq_vtime;
			min_cpu = cpu;
		}

		/*
		 * Nothing to compare against: take the first task found.
		 */
		if (!own)
			break;
	}
	if (cctx && limit) {
		start += limit;
		if (start >= nr_cpu_ids)
			start -= nr_cpu_ids;
		cctx->steal_cursor = start;
	}

	if (own && (min_cpu < 0 ||
		    !time_before(min_dl + slice_ns, own->scx.dsq_vtime)))
		min_cpu = dst_cpu;

	if (min_cpu < 0)
		return false;

	if (!scx_bpf_dsq_move_to_local(cpu_dsq(min_cpu), 0))
		return false;

	if (min_cpu != dst_cpu)
		__sync_fetch_and_add(&nr_steals, 1);

	return true;
}

void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Take the earliest deadline waiting on this node, then fall back
	 * to this CPU's own DSQ in case the pick raced with another CPU.
	 */
	if (try_steal_task(cpu) || scx_bpf_dsq_move_to_local(cpu_dsq(cpu), 0))
		return;

	/*
	 * Nothing is waiting on this node (or nothing that can run here):
	 * refresh the timestamp used to detect a sustained backlog on this
	 * node.
	 */
	if (!primary_all && overload_thresh_ns) {
		int node = cpu_node(cpu);

		if (node >= 0 && node < MAX_NODES)
			node_empty_ts[node] = bpf_ktime_get_ns();
	}

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, give it another time slot if the CPU
	 * is on the primary domain.
	 */
	if (prev && keep_running(prev, cpu))
		scx_bpf_task_set_slice(prev, slice_ns);
}

void BPF_STRUCT_OPS(cosmos_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;
	s64 limit, lag;

	__sync_fetch_and_sub(&sum_weight, p->scx.weight);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Remember how far the task is from the reference as it stops being
	 * runnable, clamped both ways, like update_entity_lag():
	 *
	 *	vlag = avg_vruntime(cfs_rq) - se->vruntime;
	 *	se->vlag = clamp(vlag, -limit, limit);
	 *
	 * What is preserved across a sleep is the position relative to the
	 * reference, not the absolute vruntime. Restoring the vruntime
	 * against the reference alone would hand every task that sleeps long
	 * enough the full credit, no matter whether it had earned it.
	 */
	limit = scale_by_dl_weight(p, slice_lag);
	lag = (s64)(vtime_now - tctx->vruntime);
	if (lag > limit)
		lag = limit;
	else if (lag < -limit)
		lag = -limit;
	tctx->vlag = lag;
}

void BPF_STRUCT_OPS(cosmos_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&sum_weight, p->scx.weight);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Place the task back at the lag it had when it went to sleep, the
	 * way place_entity() does:
	 *
	 *	se->vruntime = vruntime - lag;
	 *
	 * A task that had consumed its share before sleeping comes back with
	 * no credit, while one that was still owed service keeps it.
	 */
	tctx->vruntime = vtime_now - tctx->vlag;
}

void BPF_STRUCT_OPS(cosmos_running, struct task_struct *p)
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
	 * Snapshot the task's user time, so that only the user time
	 * accumulated on this CPU is charged to it.
	 */
	if (busy_threshold)
		tctx->last_utime = p->utime;

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(scx_bpf_task_cpu(p));

	/*
	 * Capture performance counter baseline when task starts running.
	 */
	if (perf_config || perf_sticky)
		scx_pmu_event_start(p, false);
}

/*
 * Return the time slice normalized by @cpu's capacity.
 */
static u64 scale_by_cpu_capacity(u64 slice, s32 cpu)
{
	if (all_cpus_same_capacity || !is_cpu_valid(cpu))
		return slice;

	return slice * cpu_capacity[cpu] / SCX_CPUPERF_ONE;
}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice, weight;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Update task's performance counters */
	if (perf_config || perf_sticky) {
		scx_pmu_event_stop(p);
		update_counters(p, tctx, cpu);
	}

	/*
	 * Charge the user time accumulated on this CPU before the task
	 * releases it.
	 */
	if (busy_threshold) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);

		if (cctx) {
			cctx->acc_utime += p->utime - tctx->last_utime;
			tctx->last_utime = p->utime;
		}
	}

	/*
	 * Evaluate the used time slice.
	 */
	tctx->last_stop_at = bpf_ktime_get_ns();
	slice = tctx->last_stop_at - tctx->last_run_at;

	/*
	 * Scale used time slice by CPU capacity: time spent on slower CPU
	 * is charged less time than running on faster CPU.
	 */
	slice = scale_by_cpu_capacity(slice, cpu);

	/*
	 * Charge the service just consumed to the task's vruntime, the way
	 * update_curr() does:
	 *
	 *	se->vruntime += calc_delta_fair(delta_exec, se);
	 */
	tctx->vruntime += scale_by_task_weight_inverse(p, slice);

	/*
	 * Advance the system virtual time by the service just delivered.
	 *
	 * EEVDF's reference is the weighted average of the runnable set,
	 *
	 *	V = \Sum (w_i * v_i) / \Sum w_i
	 *
	 * so serving @p for @slice moves it by
	 *
	 *	dV = w_p * dv_p / \Sum w_i = slice * NICE_0 / \Sum w_i
	 *
	 * since dv_p is the slice scaled by the inverse of @p's weight. That
	 * is an identity, not an approximation: what matters is that V rises
	 * with the service handed out no matter who receives it. Deriving it
	 * from the running task's own vruntime instead (the previous
	 * max-of-running rule) stalls the clock exactly when it is needed,
	 * because the tasks that are behind never run and the tasks that do
	 * run barely advance their own vruntime.
	 *
	 * The division truncates, and once the total weight exceeds a
	 * hundred times the length of a burst every burst contributes
	 * nothing: with a few thousand runnable tasks V would stop entirely
	 * and everything queued behind it would starve. Carry the remainder
	 * per CPU so that the service is accounted in full.
	 */
	weight = sum_weight;
	if (weight) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
		u64 acc = slice * 100 + (cctx ? cctx->vtime_rem : 0);
		u64 delta = acc / weight;

		if (cctx)
			cctx->vtime_rem = acc - delta * weight;
		if (delta)
			__sync_fetch_and_add(&vtime_now, delta);
	}

	/*
	 * Update per-CPU statistics.
	 */
	update_cpu_load(p, slice);
}

void BPF_STRUCT_OPS(cosmos_enable, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (tctx)
		tctx->vruntime = vtime_now;
}

s32 BPF_STRUCT_OPS(cosmos_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	int ret;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	if ((ret = scx_pmu_task_init(p)))
		return ret;

	ret = init_cpumask(&tctx->cpumask);
	if (ret)
		return ret;

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	scx_pmu_task_fini(p);
}

/*
 * Initialize a NUMA node context.
 *
 * Return 0 if @node contains at least one CPU, -ENODEV if it is CPU-less, or
 * another negative errno on failure.
 */
static int init_node(int node)
{
	struct bpf_cpumask *cpumask;
	struct node_ctx *nctx;
	bool has_cpus = false;
	u32 cpu;
	int ret;

	nctx = try_lookup_node_ctx(node);
	if (!nctx)
		return -ENOENT;

	ret = init_cpumask(&nctx->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = nctx->cpumask;
	if (!cpumask) {
		ret = -EINVAL;
		goto out_unlock;
	}
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu_node(cpu) == node) {
			bpf_cpumask_set_cpu(cpu, cpumask);
			has_cpus = true;
		}
	}
out_unlock:
	bpf_rcu_read_unlock();

	if (ret)
		return ret;
	return has_cpus ? 0 : -ENODEV;
}

/*
 * Initialize @nonprimary_cpumask as the complement of the primary domain.
 */
static int init_nonprimary_cpumask(void)
{
	const struct cpumask *primary;
	struct bpf_cpumask *mask;
	int err = 0, cpu;

	err = init_cpumask(&nonprimary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = nonprimary_cpumask;
	primary = cast_mask(primary_cpumask);
	if (!mask || !primary) {
		err = -EINVAL;
		goto out_unlock;
	}
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, primary))
			bpf_cpumask_set_cpu(cpu, mask);
	}
out_unlock:
	bpf_rcu_read_unlock();

	return err;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	u64 now = bpf_ktime_get_ns();
	int err;
	int cpu;
	struct cpu_ctx *cctx;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	if (!primary_all) {
		err = init_nonprimary_cpumask();
		if (err) {
			scx_bpf_error("failed to init non-primary cpumask: %d", err);
			return err;
		}
	}

	/*
	 * Consider all the shared DSQs as just drained, so that the
	 * overload detection starts from a clean state.
	 */
	bpf_for(cpu, 0, MAX_NODES)
		node_empty_ts[cpu] = now;

	if (numa_enabled) {
		int node;

		/*
		 * Nodes that fail to initialize, including CPU-less NUMA
		 * nodes (e.g., GPU-memory or CXL-memory nodes), are simply
		 * skipped.
		 */
		bpf_for(node, 0, nr_node_ids)
			init_node(node);
	}

	/*
	 * Create the per-CPU DSQs.
	 */
	bpf_for(cpu, 0, nr_cpu_ids) {
		int node = numa_enabled ? cpu_node(cpu) : -1;

		err = scx_bpf_create_dsq(cpu_dsq(cpu), node < 0 ? -1 : node);
		if (err) {
			scx_bpf_error("failed to create DSQ for CPU %d: %d", cpu, err);
			return err;
		}
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;
		cctx->perf_events = 0;
	}

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

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	if (perf_config)
		scx_pmu_uninstall(perf_config);

	if (perf_sticky)
		scx_pmu_uninstall(perf_sticky);

	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .tick                    = (void *)cosmos_tick,
	       .runnable		= (void *)cosmos_runnable,
	       .quiescent		= (void *)cosmos_quiescent,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .enable			= (void *)cosmos_enable,
	       .init_task		= (void *)cosmos_init_task,
	       .exit_task		= (void *)cosmos_exit_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
