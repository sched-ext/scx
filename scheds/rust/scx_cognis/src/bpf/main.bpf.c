/* Copyright (c) Andrea Righi <andrea.righi@linux.dev> */
/*
 * Cognis v2 — BPF-owned sched_ext policy with a minimal Rust companion.
 *
 * Scheduling decisions are made in BPF. The Rust process remains responsible
 * for loading the scheduler, exporting stats, handling restart/reporting, and
 * keeping a dormant compatibility path for legacy user-space dispatch.
 *
 * The hot policy is intentionally simple and research-driven:
 *   - per-CPU local DSQs for locality
 *   - per-LLC overflow DSQs before the global shared fallback
 *   - per-NUMA node DSQs before the global shared fallback
 *   - EEVDF-like virtual deadlines
 *   - bounded wakeup credit for frequently sleeping tasks
 *   - desktop/server profiles that tune slice, lag, and spill behavior
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifdef LSP
#define __bpf__
#include "../../../../scheds/include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include <scx/percpu.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC 1000ULL
#endif

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC 1000000ULL
#endif

/*
 * Introduce a custom DSQ shared across all the CPUs, where we can dispatch
 * tasks that will be executed on the first CPU available.
 *
 * Per-CPU DSQs are also provided, to allow the scheduler to run a task on a
 * specific CPU (see dsq_init()).
 */
#define SHARED_DSQ MAX_CPUS

/*
 * Per-LLC overflow DSQs sit between the CPU-local queues and the wider
 * node-wide spill queue. This keeps saturation mostly inside the closest
 * cache domain before broadening out to a NUMA domain or the global shared
 * fallback.
 */
#define MAX_LLCS 64
#define LLC_DSQ_BASE (MAX_CPUS + 2)

/*
 * Per-node overflow DSQs sit between the LLC queues and the global shared
 * fallback. On single-node systems this layer is skipped entirely.
 */
#define MAX_NODES 64
#define NODE_DSQ_BASE (LLC_DSQ_BASE + MAX_LLCS)

/*
 * The user-space scheduler itself is dispatched using a separate DSQ, that
 * is consumed after all other DSQs.
 *
 * This ensures to work in bursts: tasks are queued, then the user-space
 * scheduler runs and dispatches them. Once all these tasks exhaust their
 * time slices, the scheduler is invoked again, repeating the cycle.
 */
#define SCHED_DSQ (MAX_CPUS + 1)

/*
 * Number of compact LLC domains exported by the Rust loader.
 *
 * When topology probing fails, this stays at the safe single-domain default.
 */
const volatile u32 nr_llcs = 1;

/*
 * Number of compact NUMA domains exported by the Rust loader.
 *
 * When topology probing fails, this stays at the safe single-domain default.
 */
const volatile u32 nr_nodes = 1;

/*
 * Compact LLC index for each CPU, exported by the Rust loader.
 */
const volatile u16 cpu_llc_idx_map[MAX_CPUS] = {};

/*
 * Compact node index for each CPU, exported by the Rust loader.
 */
const volatile u16 cpu_node_idx_map[MAX_CPUS] = {};

/*
 * Compact node index for each LLC domain, exported by the Rust loader.
 */
const volatile u16 llc_node_idx_map[MAX_LLCS] = {};

/*
 * Scheduler attributes and statistics.
 */
const volatile u32 usersched_pid; /* User-space scheduler PID */
u64 usersched_last_run_at; /* Timestamp of the last user-space scheduler execution */
static u64 nr_cpu_ids; /* Maximum possible CPU number */

/*
 * Maximum task slice for the active profile.
 */
const volatile u64 slice_ns;

/*
 * Minimum task slice for the active profile.
 */
const volatile u64 slice_min_ns;

/*
 * Maximum bounded wakeup credit for the active profile.
 */
const volatile u64 slice_lag_ns;

/*
 * Number of tasks that are queued for scheduling.
 *
 * This number is incremented by the BPF component when a task is queued to the
 * user-space scheduler and it must be decremented by the user-space scheduler
 * when a task is consumed.
 */
volatile u64 nr_queued;

/*
 * Number of tasks that are waiting for scheduling.
 *
 * This number must be updated by the user-space scheduler to keep track if
 * there is still some scheduling work to do.
 */
volatile u64 nr_scheduled;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running, nr_online_cpus;

/* Dispatch statistics */
volatile u64 nr_user_dispatches, nr_kernel_dispatches,
	     nr_cancel_dispatches, nr_bounce_dispatches;

/* BPF hierarchy routing statistics */
volatile u64 nr_local_dispatches, nr_llc_dispatches,
	     nr_node_dispatches, nr_shared_dispatches,
	     nr_xllc_steals, nr_xnode_steals;

/* Failure statistics */
volatile u64 nr_failed_dispatches, nr_sched_congested;

/* Report additional debugging information */
const volatile bool debug;

/* Rely on the in-kernel idle CPU selection policy */
const volatile bool builtin_idle;

/* Reduce wake-sync affinity and favor broader balancing. */
const volatile bool no_wake_sync;

/* Keep very short-burst tasks on the same CPU to reduce queue churn. */
const volatile bool sticky_tasks;

/* Server profile spills through the hierarchy sooner, but still keeps the same tiers. */
const volatile bool server_mode;

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {						\
	if (debug)							\
		bpf_printk(_fmt, ##__VA_ARGS__);			\
} while(0)

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Legacy compatibility buffers between kernel and the dormant user-space
 * fallback path. In Cognis v2 the default desktop/server profiles do not
 * normally enqueue tasks here.
 */
#define MAX_ENQUEUED_TASKS 4096

/*
 * Maximum amount of slots reserved to the tasks dispatched via shared queue.
 */
#define MAX_DISPATCH_SLOT (MAX_ENQUEUED_TASKS / 8)

/*
 * The map containing tasks that are queued to user space from the kernel.
 *
 * This map is drained by the user-space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENQUEUED_TASKS *
				sizeof(struct queued_task_ctx));
} queued SEC(".maps");

/*
 * The user ring buffer containing pids that are dispatched from user space to
 * the kernel.
 *
 * Drained by the kernel in .dispatch().
 */
struct {
        __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, MAX_ENQUEUED_TASKS *
				sizeof(struct dispatched_task_ctx));
} dispatched SEC(".maps");

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Timestamp since last time the task ran on a CPU.
	 */
	u64 start_ts;

	/*
	 * Timestamp since last time the task released a CPU.
	 */
	u64 stop_ts;

	/*
	 * Execution time (in nanoseconds) since the last sleep event.
	 */
	u64 exec_runtime;

	/*
	 * Task generation counter to detect duplicate enqueues.
	 */
	u64 enq_cnt;

	/*
	 * Virtual service accumulated since the last sleep event.
	 */
	u64 awake_vtime;

	/*
	 * Timestamp when the task most recently started executing.
	 */
	u64 last_run_at;

	/*
	 * Smoothed wakeup frequency used to bound wakeup credit.
	 */
	u64 wakeup_freq;

	/*
	 * Timestamp of the last wakeup.
	 */
	u64 last_woke_at;

	/*
	 * Smoothed runtime per scheduling cycle used for sticky-task detection.
	 */
	u64 avg_runtime;
};

/*
 * PIDs of tasks leaving sched_ext (exiting or migrating to a different
 * scheduling class). Written by ops.disable, consumed by user-space to
 * trigger immediate Bayesian reputation updates instead of the 2-second
 * staleness heuristic. Inspired by scx_layered's layered_disable pattern.
 *
 * max_entries must be a power-of-2 multiple of the page size (4 KiB):
 *   4096 × sizeof(__u32) = 16 KiB = 4 pages  →  capacity: 4096 PIDs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 * sizeof(__u32));
} task_exits SEC(".maps");

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Current global virtual-time front.
 */
static u64 vtime_now;

/*
 * Wakeup-frequency cap evaluated over 100ms windows.
 */
#define MAX_WAKEUP_FREQ 64ULL

/*
 * Return a local task context from a generic task or NULL if the context
 * doesn't exist.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor,
						(struct task_struct *)p, 0, 0);
	if (!tctx)
		dbg_msg("warning: failed to get task context for pid=%d (%s)",
			p->pid, p->comm);
	return tctx;
}

/*
 * Heartbeat timer used to periodically trigger the check to run the user-space
 * scheduler.
 *
 * Without this timer we may starve the scheduler if the system is completely
 * idle and hit the watchdog that would auto-kill this scheduler.
 */
struct usersched_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct usersched_timer);
} usersched_timer SEC(".maps");

/*
 * Time period of the scheduler heartbeat, used to periodically kick the
 * user-space scheduler and check if there is any pending activity.
 */
#define USERSCHED_TIMER_NS	NSEC_PER_SEC

/*
 * Return true if the target task @p is the user-space scheduler.
 */
static inline bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

static inline bool is_deadline_min(const struct task_struct *p1,
				       const struct task_struct *p2)
{
	if (!p1)
		return false;
	if (!p2)
		return true;

	return p1->scx.dsq_vtime < p2->scx.dsq_vtime;
}

/*
 * Flag used to wake-up the user-space scheduler.
 */
static volatile u32 usersched_needed;

/*
 * Set user-space scheduler wake-up flag (equivalent to an atomic release
 * operation).
 */
static void set_usersched_needed(void)
{
	__sync_fetch_and_or(&usersched_needed, 1);
}

/*
 * Check and clear user-space scheduler wake-up flag (equivalent to an atomic
 * acquire operation).
 */
static bool test_and_clear_usersched_needed(void)
{
	return __sync_fetch_and_and(&usersched_needed, 0) == 1;
}

/*
 * Return true if there's any pending activity to do for the scheduler, false
 * otherwise.
 *
 * NOTE: a task is sent to the user-space scheduler using the "queued"
 * ringbuffer, then the scheduler drains the queued tasks and adds them to
 * its internal data structures / state; at this point tasks become
 * "scheduled" and the user-space scheduler will take care of updating
 * nr_scheduled accordingly; lastly tasks will be dispatched and the
 * user-space scheduler will update nr_scheduled again.
 *
 * Checking nr_scheduled and the available data in the ringbuffer allows to
 * determine if there is still some pending work to do for the scheduler:
 * new tasks have been queued since last check, or there are still tasks
 * "queued" or "scheduled" since the previous user-space scheduler run.
 *
 * If there's no pending action, it is pointless to wake-up the scheduler
 * (even if a CPU becomes idle), because there is nothing to do.
 *
 * Also keep in mind that we don't need any protection here since this code
 * doesn't run concurrently with the user-space scheduler (that is single
 * threaded), therefore this check is also safe from a concurrency perspective.
 */
static bool usersched_has_pending_tasks(void)
{
	if (test_and_clear_usersched_needed())
		return true;

	if (nr_scheduled)
		return true;

	return bpf_ringbuf_query(&queued, BPF_RB_AVAIL_DATA) > 0;
}

/*
 * Return true if @cpu is valid, otherwise trigger an error and return false.
 */
static inline bool is_cpu_valid(s32 cpu)
{
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);

	if (cpu < 0 || cpu >= max_cpu) {
		scx_bpf_error("Invalid cpu: %d", cpu);
		return false;
	}
	return true;
}

/*
 * Return the DSQ ID associated to a CPU, or SHARED_DSQ if the CPU is not
 * valid.
 */
static u64 cpu_to_dsq(s32 cpu)
{
	if (!is_cpu_valid(cpu))
		return SHARED_DSQ;

	return (u64)cpu;
}

/*
 * Return the DSQ ID associated to a compact LLC domain.
 */
static inline u64 llc_to_dsq(u32 llc_idx)
{
	return LLC_DSQ_BASE + llc_idx;
}

/*
 * Return the DSQ ID associated to a compact NUMA node domain.
 */
static inline u64 node_to_dsq(u32 node_idx)
{
	return NODE_DSQ_BASE + node_idx;
}

/*
 * Return the compact LLC index associated to @cpu.
 */
static inline u32 cpu_llc_idx_for(s32 cpu)
{
	if (!is_cpu_valid(cpu))
		return 0;

	return cpu_llc_idx_map[cpu];
}

/*
 * Return the compact node index associated to @cpu.
 */
static inline u32 cpu_node_idx_for(s32 cpu)
{
	if (!is_cpu_valid(cpu))
		return 0;

	return cpu_node_idx_map[cpu];
}

/*
 * Return the compact node index associated to an LLC domain.
 */
static inline u32 llc_node_idx_for(u32 llc_idx)
{
	if (llc_idx >= MAX_LLCS)
		return 0;

	return llc_node_idx_map[llc_idx];
}

/*
 * Return the DSQ ID associated to the LLC domain that contains @cpu.
 */
static inline u64 cpu_llc_dsq(s32 cpu)
{
	return llc_to_dsq(cpu_llc_idx_for(cpu));
}

/*
 * Return the DSQ ID associated to the node domain that contains @cpu.
 */
static inline u64 cpu_node_dsq(s32 cpu)
{
	return node_to_dsq(cpu_node_idx_for(cpu));
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
        if (this_cpu == that_cpu)
                return false;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_priority(this_cpu) > cpu_priority(that_cpu);
}

/*
 * Return true if @cpu is a fully-idle SMT core, false otherwise.
 */
static inline bool is_smt_idle(s32 cpu)
{
	const struct cpumask *idle_smtmask;
        bool is_idle;

	if (!smt_enabled)
		return true;

	idle_smtmask = scx_bpf_get_idle_smtmask();
        is_idle = bpf_cpumask_test_cpu(cpu, idle_smtmask);
        scx_bpf_put_cpumask(idle_smtmask);

	return is_idle;
}

/*
 * Return true on a wake-up event, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq;

	new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

static bool is_task_sticky(const struct task_ctx *tctx)
{
	return sticky_tasks && tctx->avg_runtime < 10 * NSEC_PER_USEC;
}

static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	       (!sticky_tasks || !scx_bpf_task_running(p));
}

static void count_kernel_route(u64 dsq_id)
{
	if (dsq_id == SHARED_DSQ) {
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
	} else if (dsq_id >= NODE_DSQ_BASE &&
		   dsq_id < NODE_DSQ_BASE + MAX_NODES) {
		__sync_fetch_and_add(&nr_node_dispatches, 1);
	} else if (dsq_id >= LLC_DSQ_BASE &&
		   dsq_id < LLC_DSQ_BASE + MAX_LLCS) {
		__sync_fetch_and_add(&nr_llc_dispatches, 1);
	} else {
		__sync_fetch_and_add(&nr_local_dispatches, 1);
	}

	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
}

static u64 queue_pressure(s32 cpu)
{
	u64 pressure = scx_bpf_dsq_nr_queued(SHARED_DSQ);

	if (!is_cpu_valid(cpu))
		return pressure;

	pressure += scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu));
	pressure += scx_bpf_dsq_nr_queued(cpu_llc_dsq(cpu));
	if (nr_nodes > 1)
		pressure += scx_bpf_dsq_nr_queued(cpu_node_dsq(cpu));

	return pressure;
}

static u64 llc_spill_threshold(void)
{
	u64 llcs = MAX((u64)nr_llcs, 1);
	u64 cpus_per_llc = MAX((nr_online_cpus + llcs - 1) / llcs, 1);

	if (server_mode)
		return MAX(cpus_per_llc / 2, 1);

	return cpus_per_llc;
}

static u64 node_spill_threshold(void)
{
	u64 nodes = MAX((u64)nr_nodes, 1);
	u64 cpus_per_node = MAX((nr_online_cpus + nodes - 1) / nodes, 1);

	if (server_mode)
		return MAX(cpus_per_node / 2, 1);

	return cpus_per_node;
}

/*
 * Pick the fallback DSQ to use once no idle CPU was available.
 *
 * Both profiles keep the first spill local when the previous CPU queue is
 * still empty. Once that CPU already carries backlog, Cognis prefers the
 * closest LLC DSQ and then the wider node DSQ. It only spills to the global
 * shared DSQ once the nearer domains are already saturated too.
 *
 * Server mode uses the same hierarchy but reaches broader spill tiers sooner
 * to keep throughput-oriented balancing broad under pressure.
 */
static u64 overflow_dsq(s32 prev_cpu)
{
	u64 local_dsq, llc_dsq, node_dsq;
	u64 local_depth, llc_depth, node_depth;

	if (!is_cpu_valid(prev_cpu))
		return SHARED_DSQ;

	local_dsq = cpu_to_dsq(prev_cpu);
	llc_dsq = cpu_llc_dsq(prev_cpu);
	local_depth = scx_bpf_dsq_nr_queued(local_dsq);
	if (!local_depth)
		return local_dsq;

	llc_depth = scx_bpf_dsq_nr_queued(llc_dsq);
	if (llc_depth < llc_spill_threshold())
		return llc_dsq;

	if (nr_nodes > 1) {
		node_dsq = cpu_node_dsq(prev_cpu);
		node_depth = scx_bpf_dsq_nr_queued(node_dsq);
		if (node_depth < node_spill_threshold())
			return node_dsq;
	}

	return SHARED_DSQ;
}

static u64 task_slice(const struct task_struct *p, s32 cpu)
{
	u64 nr_wait = queue_pressure(cpu);
	u64 slice = scale_by_task_weight(p, slice_ns) / MAX(nr_wait, 1);

	return MAX(slice, slice_min_ns);
}

static u64 task_dl(struct task_struct *p, s32 cpu, struct task_ctx *tctx)
{
	const u64 STARVATION_NS = 500ULL * NSEC_PER_MSEC;
	const u64 q_thresh = MAX(STARVATION_NS / MAX(slice_ns, 1), 1);
	u64 nr_wait = queue_pressure(cpu);
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 awake_max = scale_by_task_weight_inverse(p, slice_lag_ns);
	u64 vtime_min;

	if (nr_wait * slice_ns >= STARVATION_NS)
		lag_scale = 1;
	else
		lag_scale = MAX(lag_scale * q_thresh / (q_thresh + nr_wait), 1);

	vtime_min = vtime_now - scale_by_task_weight(p, slice_lag_ns * lag_scale);
	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	if (time_after(tctx->awake_vtime, awake_max))
		tctx->awake_vtime = awake_max;

	return p->scx.dsq_vtime + tctx->awake_vtime;
}

/*
 * Find an idle CPU in the system for the task.
 *
 * NOTE: the idle CPU selection doesn't need to be formally perfect, it is
 * totally fine to accept racy conditions and potentially make mistakes, by
 * picking CPUs that are not idle or even offline, the logic has been designed
 * to handle these mistakes in favor of a more efficient response and a reduced
 * scheduling overhead.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is still idle.
	 */
	if (p->nr_cpus_allowed == 1) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		return -EBUSY;
	}

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 *
	 * In presence of hybrid cores this helps to naturally migrate
	 * tasks over to the faster cores.
	 */
	if (is_wakeup(wake_flags) &&
	    is_cpu_faster(this_cpu, prev_cpu) && is_this_cpu_allowed) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    is_smt_idle(prev_cpu) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
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

		if (!wake_flags)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Wake-up a target @cpu for the dispatched task @p. If @cpu can't be used
 * wakeup another valid CPU.
 */
static void kick_task_cpu(const struct task_struct *p, s32 cpu)
{
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		/*
		 * Kick the target CPU anyway, since it may be locked and
		 * needs to go back to idle to reset its state.
		 */
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		/*
		 * Pick any other idle CPU that the task can use.
		 */
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (cpu < 0)
			return;
	}
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Dispatch a task to a target per-CPU DSQ, waking up the corresponding CPU, if
 * needed.
 */
static void dispatch_task(const struct dispatched_task_ctx *task)
{
	struct task_ctx *tctx;
	struct task_struct *p;
	s32 prev_cpu, cpu = task->cpu;

	/* Ignore entry if the task doesn't exist anymore */
	p = bpf_task_from_pid(task->pid);
	if (!p)
		return;
	prev_cpu = scx_bpf_task_cpu(p);

	/*
	 * Dispatch task to the shared DSQ if the user-space scheduler
	 * didn't select any specific target CPU.
	 *
	 * Count these as user dispatches: every cognis-dispatched user task
	 * uses RL_CPU_ANY, so omitting the counter here caused d→u to
	 * always read 0 in --monitor output even when the scheduler was
	 * working correctly.
	 */
	if (task->cpu == RL_CPU_ANY) {
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
					 task->slice_ns, task->vtime, task->flags);
		__sync_fetch_and_add(&nr_user_dispatches, 1);
		kick_task_cpu(p, prev_cpu);
		goto out_release;
	}

	/*
	 * Dispatch the task to the target CPU selected by the
	 * user-space scheduler.
	 *
	 * However, if the target CPU is not valid (due to affinity
	 * constraints), keep the task on the previously used CPU,
	 * overriding the user-space scheduler decision.
	 */
	if (!bpf_cpumask_test_cpu(task->cpu, p->cpus_ptr)) {
		cpu = prev_cpu;
		__sync_fetch_and_add(&nr_bounce_dispatches, 1);
	} else {
		__sync_fetch_and_add(&nr_user_dispatches, 1);
	}
	scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
				 task->slice_ns, task->vtime, task->flags);

	/*
	 * If the task was dequeued while still in the user-space
	 * scheduler, this dispatch can be ignored.
	 *
	 * Another enqueue event for the same task will be received later.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx || tctx->enq_cnt > task->enq_cnt) {
		scx_bpf_dispatch_cancel();
		__sync_fetch_and_add(&nr_cancel_dispatches, 1);
		goto out_release;
	}

	/*
	 * CPU selected by the user-space scheduler is valid, kick it.
	 */
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

out_release:
	bpf_task_release(p);
}

static inline bool is_remote_head_better(const struct task_struct *candidate,
					 u64 candidate_depth,
					 const struct task_struct *best,
					 u64 best_depth)
{
	if (!candidate)
		return false;
	if (!best)
		return true;
	if (candidate->scx.dsq_vtime != best->scx.dsq_vtime)
		return candidate->scx.dsq_vtime < best->scx.dsq_vtime;

	return candidate_depth > best_depth;
}

static bool steal_remote_llc(s32 cpu, bool same_node_only)
{
	struct task_struct *candidate, *best = NULL;
	u64 best_depth = 0, candidate_depth, best_dsq = 0;
	u32 my_llc, my_node, victim, i;

	if (!is_cpu_valid(cpu) || nr_llcs <= 1)
		return false;

	my_llc = cpu_llc_idx_for(cpu);
	my_node = cpu_node_idx_for(cpu);

	bpf_for(i, 1, MAX_LLCS) {
		if (i >= nr_llcs)
			break;

		victim = my_llc + i;
		if (victim >= nr_llcs)
			victim -= nr_llcs;

		if (same_node_only && llc_node_idx_for(victim) != my_node)
			continue;

		candidate_depth = scx_bpf_dsq_nr_queued(llc_to_dsq(victim));
		if (!candidate_depth)
			continue;

		candidate = __COMPAT_scx_bpf_dsq_peek(llc_to_dsq(victim));
		if (is_remote_head_better(candidate, candidate_depth, best, best_depth)) {
			best = candidate;
			best_depth = candidate_depth;
			best_dsq = llc_to_dsq(victim);
		}
	}

	if (best && scx_bpf_dsq_move_to_local(best_dsq)) {
		__sync_fetch_and_add(&nr_xllc_steals, 1);
		return true;
	}

	return false;
}

static bool steal_remote_node(s32 cpu)
{
	struct task_struct *candidate, *best = NULL;
	u64 best_depth = 0, candidate_depth, best_dsq = 0;
	u32 my_node, victim, i;

	if (!is_cpu_valid(cpu) || nr_nodes <= 1)
		return false;

	my_node = cpu_node_idx_for(cpu);

	bpf_for(i, 1, MAX_NODES) {
		if (i >= nr_nodes)
			break;

		victim = my_node + i;
		if (victim >= nr_nodes)
			victim -= nr_nodes;

		candidate_depth = scx_bpf_dsq_nr_queued(node_to_dsq(victim));
		if (!candidate_depth)
			continue;

		candidate = __COMPAT_scx_bpf_dsq_peek(node_to_dsq(victim));
		if (is_remote_head_better(candidate, candidate_depth, best, best_depth)) {
			best = candidate;
			best_depth = candidate_depth;
			best_dsq = node_to_dsq(victim);
		}
	}

	if (best && scx_bpf_dsq_move_to_local(best_dsq)) {
		__sync_fetch_and_add(&nr_xnode_steals, 1);
		return true;
	}

	return false;
}

s32 BPF_STRUCT_OPS(cognis_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);
	struct task_ctx *tctx;

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here.
	 */
	if (is_usersched_task(p))
		return prev_cpu;

	/*
	 * If built-in idle CPU policy is disabled, keep reusing the same CPU.
	 */
	if (!builtin_idle)
		return prev_cpu;

	/*
	 * Pick the idle CPU closest to @prev_cpu usable by the task and
	 * dispatch directly with a BPF-owned virtual deadline.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		tctx = try_lookup_task_ctx(p);
		if (tctx) {
			scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), 0);
			count_kernel_route(cpu_to_dsq(cpu));
		}
		return cpu;
	}

	/*
	 * If we couldn't find an idle CPU, in case of a sync wakeup
	 * prioritize the waker's CPU.
	 */
	return prev_cpu;
}

/*
 * Select and wake-up an idle CPU for a specific task from the user-space
 * scheduler.
 */
SEC("syscall")
int rs_select_cpu(struct task_cpu_arg *input)
{
	struct task_struct *p;
	int cpu = input->cpu;

	p = bpf_task_from_pid(input->pid);
	if (!p)
		return -EINVAL;

	bpf_rcu_read_lock();
	/*
	 * Kernels that don't provide scx_bpf_select_cpu_and() only allow
	 * to use the built-in idle CPU selection policy only from
	 * ops.select_cpu() and opt.enqueue(), return any idle CPU usable
	 * by the task in this case.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		if (!scx_bpf_test_and_clear_cpu_idle(cpu))
			cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	} else {
		/*
		 * Set SCX_WAKE_TTWU, pretending to be a wakeup, to prioritize
		 * faster CPU selection (we probably want to add an option to allow
		 * the user-space scheduler to use this logic or not).
		 */
		cpu = pick_idle_cpu(p, cpu, SCX_WAKE_TTWU);
	}
	bpf_rcu_read_unlock();

	bpf_task_release(p);

	return cpu;
}

/*
 * Return true if a task has been enqueued as a remote wakeup, false
 * otherwise.
 */
static bool is_queued_wakeup(const struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Task @p becomes ready to run. We can dispatch the task directly here if the
 * user-space scheduler is not required, or enqueue it to be processed by the
 * scheduler.
 */
void BPF_STRUCT_OPS(cognis_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	bool should_kick = is_queued_wakeup(p, enq_flags);
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Insert the user-space scheduler to its dedicated DSQ, it will be
	 * consumed from ops.dispatch() only when there's any pending
	 * scheduling action to do.
	 */
	if (is_usersched_task(p)) {
		scx_bpf_dsq_insert(p, SCHED_DSQ, slice_ns, enq_flags);
		goto out;
	}

	/*
	 * Dispatch ALL kthreads directly, bypassing the user-space scheduling
	 * round-trip entirely.
	 *
	 * Linux >= 6.13 reworked workqueue CPU affinity so that nominally
	 * per-CPU workers (kworker/N:M) now carry nr_cpus_allowed > 1.
	 * The old check `is_kthread(p) && nr_cpus_allowed == 1` let those
	 * workers fall through to user-space, where round-trip latency could
	 * exceed the 5-second sched_ext watchdog and crash the scheduler with
	 * a "runnable task stall" event.
	 *
	 * Dispatching ALL kthreads in BPF eliminates this stall class without
	 * correctness loss: kthreads must never be trust-throttled or
	 * burst-predicted by user-space. kswapd/khugepaged are kthreads;
	 * redundant checks removed.
	 */
	if (is_kthread(p)) {
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(prev_cpu),
					 task_slice(p, prev_cpu), p->scx.dsq_vtime, enq_flags);
		count_kernel_route(cpu_to_dsq(prev_cpu));
		goto out;
	}

	/*
	 * Keep very short-burst tasks on the same CPU to reduce queue churn and
	 * preserve cache locality.
	 */
	if (is_task_sticky(tctx)) {
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(prev_cpu),
					 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
		count_kernel_route(cpu_to_dsq(prev_cpu));
		goto out;
	}

	/*
	 * Attempt to move the task directly to an idle CPU when migration is
	 * still worth the cost.
	 */
	if (task_should_migrate(p, enq_flags)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), enq_flags);
			count_kernel_route(cpu_to_dsq(cpu));
			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * No idle CPU was available. Route through the hierarchy:
	 *
	 *   local CPU DSQ -> LLC DSQ -> node DSQ -> shared DSQ
	 *
	 * This keeps saturation mostly inside the closest cache domain before
	 * widening to a node domain and finally paying the contention cost of the
	 * global shared queue.
	 */
	u64 target_dsq = overflow_dsq(prev_cpu);
	scx_bpf_dsq_insert_vtime(p, target_dsq,
				 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
	count_kernel_route(target_dsq);

out:
	/*
	 * Wakeup the task's CPU if needed.
	 */
	if (should_kick)
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Handle a task dispatched from user-space, performing the actual low-level
 * BPF dispatch.
 */
static long handle_dispatched_task(struct bpf_dynptr *dynptr, void *context)
{
	const struct dispatched_task_ctx *task;

	task = bpf_dynptr_data(dynptr, 0, sizeof(*task));
	if (!task)
		return 0;

	dispatch_task(task);

	return !!scx_bpf_dispatch_nr_slots();
}

/*
 * Dispatch tasks that are ready to run.
 *
 * This function is called when a CPU's local DSQ is empty and ready to accept
 * new dispatched tasks.
 *
 * We may dispatch tasks also on other CPUs from here, if the scheduler decided
 * so (usually if other CPUs are idle we may want to send more tasks to their
 * local DSQ to optimize the scheduling pipeline).
 */
void BPF_STRUCT_OPS(cognis_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *local, *llc, *node = NULL, *shared, *best = NULL;
	u64 local_dsq = cpu_to_dsq(cpu);
	u64 llc_dsq = cpu_llc_dsq(cpu);
	u64 node_dsq = cpu_node_dsq(cpu);
	u64 best_dsq = 0;

	/*
	 * Consume all tasks from the @dispatched list and immediately
	 * dispatch them on the target CPU decided by the user-space
	 * scheduler.
	 */
	s32 ret = bpf_user_ringbuf_drain(&dispatched,
					 handle_dispatched_task, NULL, BPF_RB_NO_WAKEUP);
	if (ret)
		dbg_msg("User ringbuf drain error: %d", ret);

	/*
	 * Dispatch the user-space scheduler if there's any pending action
	 * to do.
	 */
	if (usersched_has_pending_tasks() &&
	    scx_bpf_dsq_move_to_local(SCHED_DSQ))
		return;

	/*
	 * Pick the earliest deadline between the local CPU DSQ, the local LLC
	 * overflow DSQ, the wider node DSQ, and the global shared spill DSQ.
	 */
	local = __COMPAT_scx_bpf_dsq_peek(local_dsq);
	llc = __COMPAT_scx_bpf_dsq_peek(llc_dsq);
	if (nr_nodes > 1)
		node = __COMPAT_scx_bpf_dsq_peek(node_dsq);
	shared = __COMPAT_scx_bpf_dsq_peek(SHARED_DSQ);
	best = local;
	best_dsq = local_dsq;
	if (is_deadline_min(llc, best)) {
		best = llc;
		best_dsq = llc_dsq;
	}
	if (is_deadline_min(node, best)) {
		best = node;
		best_dsq = node_dsq;
	}
	if (is_deadline_min(shared, best)) {
		best = shared;
		best_dsq = SHARED_DSQ;
	}
	if (best && scx_bpf_dsq_move_to_local(best_dsq))
		return;
	if (local && best_dsq != local_dsq && scx_bpf_dsq_move_to_local(local_dsq))
		return;
	if (llc && best_dsq != llc_dsq && scx_bpf_dsq_move_to_local(llc_dsq))
		return;
	if (node && best_dsq != node_dsq && scx_bpf_dsq_move_to_local(node_dsq))
		return;
	if (shared && best_dsq != SHARED_DSQ && scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;
	if (steal_remote_llc(cpu, true))
		return;
	if (steal_remote_node(cpu))
		return;
	if (steal_remote_llc(cpu, false))
		return;

	/*
	 * If the current task expired its time slice and no other task
	 * wants to run, simply replenish its time slice and let it run for
	 * another round on the same CPU.
	 *
	 * In case of the user-space scheduler task, replenish its time
	 * slice only if there're still pending scheduling actions to do.
	 */
	if (prev && is_queued(prev) &&
	    (!is_usersched_task(prev) || usersched_has_pending_tasks()))
		prev->scx.slice = task_slice(prev, cpu);
}

void BPF_STRUCT_OPS(cognis_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	if (is_usersched_task(p))
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
	tctx->awake_vtime = 0;
	delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

/*
 * Task @p starts on its selected CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(cognis_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);

	if (is_usersched_task(p)) {
		usersched_last_run_at = scx_bpf_now();
		return;
	}

	dbg_msg("start: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);

	/*
	 * Mark the CPU as busy by setting the pid as owner (ignoring the
	 * user-space scheduler).
	 */
	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->start_ts = scx_bpf_now();
	tctx->last_run_at = bpf_ktime_get_ns();

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Task @p stops running on its associated CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(cognis_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now();
	u64 slice, delta_vtime;
	struct task_ctx *tctx;

	if (is_usersched_task(p))
		return;

	dbg_msg("stop: pid=%d (%s) cpu=%ld", p->pid, p->comm, scx_bpf_task_cpu(p));

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->stop_ts = now;

	/*
	 * Update the partial execution time since last sleep.
	 */
	slice = now - tctx->last_run_at;
	tctx->exec_runtime += now - tctx->start_ts;
	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);

	delta_vtime = scale_by_task_weight_inverse(p, slice);
	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;

	/* Production path: keep ops.stopping minimal. */
}

/*
 * A task joins the sched_ext scheduler.
 */
void BPF_STRUCT_OPS(cognis_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
	p->scx.slice = MAX(slice_ns, slice_min_ns);
}

/*
 * A task leaves sched_ext — it is exiting or being moved to a different
 * scheduling class. Publish its PID to the task_exits ring buffer so
 * user-space can immediately finalise its Bayesian reputation record
 * instead of waiting for the 2-second staleness heuristic.
 *
 * Pattern from scx_layered's layered_disable / scx_bpfland's ops.disable.
 */
void BPF_STRUCT_OPS(cognis_disable, struct task_struct *p)
{
	__u32 *pid_slot;

	/* Skip the user-space scheduler process and kernel threads. */
	if (is_usersched_task(p) || is_kthread(p))
		return;

	pid_slot = bpf_ringbuf_reserve(&task_exits, sizeof(__u32), 0);
	if (!pid_slot)
		return;

	*pid_slot = (__u32)p->pid;
	bpf_ringbuf_submit(pid_slot, 0);
}

/*
 * Heartbeat scheduler timer callback.
 *
 * If the system is completely idle the sched-ext watchdog may incorrectly
 * detect that as a stall and automatically disable the scheduler. So, use this
 * timer to periodically wake-up the scheduler and avoid long inactivity.
 *
 * This can also help to prevent real "stalling" conditions in the scheduler.
 */
static int usersched_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	struct task_struct *p;
	int err = 0;

	/*
	 * Trigger the user-space scheduler if it has been inactive for
	 * more than USERSCHED_TIMER_NS.
	 */
	if (time_delta(scx_bpf_now(), usersched_last_run_at) >= USERSCHED_TIMER_NS) {
		bpf_rcu_read_lock();
		p = bpf_task_from_pid(usersched_pid);
		if (p) {
			set_usersched_needed();
			scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_IDLE);
			bpf_task_release(p);
		}
		bpf_rcu_read_unlock();
	}

	/* Re-arm the timer */
	err = bpf_timer_start(timer, USERSCHED_TIMER_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm stats timer");

	return 0;
}

/*
 * Initialize the heartbeat scheduler timer.
 */
static int usersched_timer_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	timer = bpf_map_lookup_elem(&usersched_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup scheduler timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &usersched_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, usersched_timer_fn);
	err = bpf_timer_start(timer, USERSCHED_TIMER_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm scheduler timer");

	return err;
}

/*
 * Evaluate the amount of online CPUs.
 */
static s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int i, cpus = 0;

	online_cpumask = scx_bpf_get_online_cpumask();

	bpf_for(i, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(i, online_cpumask))
			continue;
		cpus++;
	}

	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

/*
 * Create a DSQ hierarchy for each CPU available in the system:
 *
 *   per-CPU DSQs -> per-LLC DSQs -> per-node DSQs -> global shared DSQ
 *
 * The compatibility user-space scheduler still keeps its own dedicated DSQ.
 */
static int dsq_init(void)
{
	int err;
	s32 cpu, llc;

	/* Initialize amount of online CPUs */
	nr_online_cpus = get_nr_online_cpus();

	/* Create per-CPU DSQs */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu_to_dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create pcpu DSQ %d: %d",
				      cpu, err);
			return err;
		}
	}

	/* Create per-LLC DSQs */
	bpf_for(llc, 0, MAX_LLCS) {
		if (llc >= nr_llcs)
			break;

		err = scx_bpf_create_dsq(llc_to_dsq(llc), -1);
		if (err) {
			scx_bpf_error("failed to create llc DSQ %d: %d",
				      llc, err);
			return err;
		}
	}

	/* Create per-node DSQs */
	bpf_for(llc, 0, MAX_NODES) {
		if (llc >= nr_nodes)
			break;

		err = scx_bpf_create_dsq(node_to_dsq(llc), -1);
		if (err) {
			scx_bpf_error("failed to create node DSQ %d: %d",
				      llc, err);
			return err;
		}
	}

	/* Create the global shared DSQ */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	/* Create the scheduler's DSQ */
	err = scx_bpf_create_dsq(SCHED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create scheduler DSQ: %d", err);
		return err;
	}

	return 0;
}

/*
 * A new task @p is being created.
 *
 * Allocate and initialize all the internal structures for the task (this
 * function is allowed to block, so it can be used to preallocate memory).
 */
s32 BPF_STRUCT_OPS(cognis_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

/*
 * Initialize the scheduling class.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cognis_init)
{
	int err;

	/* Compile-time checks */
	BUILD_BUG_ON((MAX_CPUS % 2));
	BUILD_BUG_ON(MAX_LLCS > MAX_CPUS);
	BUILD_BUG_ON(MAX_NODES > MAX_CPUS);

	/* Initialize maximum possible CPU number */
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize the Cognis BPF scheduler core. */
	err = dsq_init();
	if (err)
		return err;
	err = usersched_timer_init();
	if (err)
		return err;

	return 0;
}

/*
 * Unregister the scheduling class.
 */
void BPF_STRUCT_OPS(cognis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduling class declaration.
 */
SCX_OPS_DEFINE(cognis,
	       .select_cpu		= (void *)cognis_select_cpu,
	       .enqueue			= (void *)cognis_enqueue,
	       .dispatch		= (void *)cognis_dispatch,
	       .runnable		= (void *)cognis_runnable,
	       .running			= (void *)cognis_running,
	       .stopping		= (void *)cognis_stopping,
	       .enable			= (void *)cognis_enable,
	       .disable			= (void *)cognis_disable,
	       .init_task		= (void *)cognis_init_task,
	       .init			= (void *)cognis_init,
	       .exit			= (void *)cognis_exit,
	       .timeout_ms		= 5000,
	       .dispatch_max_batch	= MAX_DISPATCH_SLOT,
	       .name			= "cognis");
