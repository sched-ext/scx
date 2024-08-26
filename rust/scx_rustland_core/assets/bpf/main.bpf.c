/* Copyright (c) Andrea Righi <andrea.righi@linux.dev> */
/*
 * scx_rustland_core: BPF backend for schedulers running in user-space.
 *
 * This BPF backend implements the low level sched-ext functionalities for a
 * user-space counterpart, that implements the actual scheduling policy.
 *
 * The BPF part collects total cputime and weight from the tasks that need to
 * run, then it sends all details to the user-space scheduler that decides the
 * best order of execution of the tasks (based on the collected metrics).
 *
 * The user-space scheduler then returns to the BPF component the list of tasks
 * to be dispatched in the proper order.
 *
 * Messages between the BPF component and the user-space scheduler are passed
 * using two BPF_MAP_TYPE_QUEUE maps: @queued for the messages sent by the BPF
 * dispatcher to the user-space scheduler and @dispatched for the messages sent
 * by the user-space scheduler to the BPF dispatcher.
 *
 * The BPF dispatcher is completely agnostic of the particular scheduling
 * policy implemented in user-space. For this reason developers that are
 * willing to use this scheduler to experiment scheduling policies should be
 * able to simply modify the Rust component, without having to deal with any
 * internal kernel / BPF details.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Introduce a custom DSQ shared across all the CPUs, where we can dispatch
 * tasks that will be executed on the first CPU available.
 *
 * Per-CPU DSQs are also provided, to allow the scheduler to run a task on a
 * specific CPU (see dsq_init()).
 */
#define SHARED_DSQ MAX_CPUS

/*
 * Scheduler attributes and statistics.
 */
u32 usersched_pid; /* User-space scheduler PID */
const volatile bool switch_partial; /* Switch all tasks or SCHED_EXT tasks */

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

/* Failure statistics */
volatile u64 nr_failed_dispatches, nr_sched_congested;

 /* Report additional debugging information */
const volatile bool debug;

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
 * Mask of offline CPUs, used to properly support CPU hotplugging.
 */
private(BPFLAND) struct bpf_cpumask __kptr *offline_cpumask;

/*
 * Set the state of a CPU in a cpumask.
 */
static bool set_cpu_state(struct bpf_cpumask *cpumask, s32 cpu, bool state)
{
	if (!cpumask)
		return false;
	if (state)
		return bpf_cpumask_test_and_set_cpu(cpu, cpumask);
	else
		return bpf_cpumask_test_and_clear_cpu(cpu, cpumask);
}

/*
 * Access a cpumask in read-only mode (typically to check bits).
 */
static const struct cpumask *cast_mask(struct bpf_cpumask *mask)
{
	return (const struct cpumask *)mask;
}

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Determine when we need to drain tasks dispatched to CPUs that went offline.
 */
static int offline_needed;

/*
 * Notify the scheduler that we need to drain and re-enqueue the tasks
 * dispatched to the offline CPU DSQs.
 */
static void set_offline_needed(void)
{
	__sync_fetch_and_or(&offline_needed, 1);
}

/*
 * Check and clear the state of the offline CPUs re-enqueuing.
 */
static bool test_and_clear_offline_needed(void)
{
	return __sync_fetch_and_and(&offline_needed, 0) == 1;
}

/*
 * Maximum amount of tasks queued between kernel and user-space at a certain
 * time.
 *
 * The @queued and @dispatched lists are used in a producer/consumer fashion
 * between the BPF part and the user-space part.
 */
#define MAX_ENQUEUED_TASKS 4096

/*
 * Maximum amount of slots reserved to the tasks dispatched via shared queue.
 */
#define MAX_DISPATCH_SLOT (MAX_ENQUEUED_TASKS / 8)

/*
 * The map containing tasks that are queued to user space from the kernel.
 *
 * This map is drained by the user space scheduler.
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
	 * Time slice assigned to the task.
	 */
	u64 slice_ns;

	/*
	 * cpumask generation counter: used to verify the validity of the
	 * current task's cpumask.
	 */
	u64 cpumask_cnt;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* Return a local task context from a generic task */
struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
		return NULL;
	}
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
#define USERSCHED_TIMER_NS (NSEC_PER_SEC / 10)

/*
 * Return true if the target task @p is the user-space scheduler.
 */
static inline bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
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
 * NOTE: nr_queued is incremented by the BPF component, more exactly in
 * enqueue(), when a task is sent to the user-space scheduler, then the
 * scheduler drains the queued tasks (updating nr_queued) and adds them to its
 * internal data structures / state; at this point tasks become "scheduled" and
 * the user-space scheduler will take care of updating nr_scheduled
 * accordingly; lastly tasks will be dispatched and the user-space scheduler
 * will update nr_scheduled again.
 *
 * Checking both counters allows to determine if there is still some pending
 * work to do for the scheduler: new tasks have been queued since last check,
 * or there are still tasks "queued" or "scheduled" since the previous
 * user-space scheduler run. If the counters are both zero it is pointless to
 * wake-up the scheduler (even if a CPU becomes idle), because there is nothing
 * to do.
 *
 * Also keep in mind that we don't need any protection here since this code
 * doesn't run concurrently with the user-space scheduler (that is single
 * threaded), therefore this check is also safe from a concurrency perspective.
 */
static bool usersched_has_pending_tasks(void)
{
	return nr_queued || nr_scheduled;
}

/*
 * Return the corresponding CPU associated to a DSQ.
 */
static s32 dsq_to_cpu(u64 dsq_id)
{
	if (dsq_id >= MAX_CPUS) {
		scx_bpf_error("Invalid dsq_id: %llu", dsq_id);
		return -EINVAL;
	}
	return (s32)dsq_id;
}

/*
 * Return the DSQ ID associated to a CPU, or SHARED_DSQ if the CPU is not
 * valid.
 */
static u64 cpu_to_dsq(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS) {
		scx_bpf_error("Invalid cpu: %d", cpu);
		return SHARED_DSQ;
	}
	return (u64)cpu;
}

/*
 * Return the time slice assigned to the task.
 */
static inline u64 task_slice(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return SCX_SLICE_DFL;
	return tctx->slice_ns;
}

/*
 * Dispatch a task to a target DSQ, waking up the corresponding CPU, if needed.
 */
static void dispatch_task(struct task_struct *p, u64 dsq_id,
			  u64 cpumask_cnt, u64 slice, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 curr_cpumask_cnt;
	bool force_shared = false;
	s32 cpu = scx_bpf_task_cpu(p);

	/*
	 * Update task's time slice in its context.
	 */
	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->slice_ns = slice;

	/*
	 * Dispatch task to the target DSQ.
	 */
	switch (dsq_id) {
	case SHARED_DSQ:
		scx_bpf_dispatch(p, dsq_id, SCX_SLICE_DFL, enq_flags);
		dbg_msg("dispatch: pid=%d (%s) dsq=%llu enq_flags=%llx slice=%llu",
			p->pid, p->comm, dsq_id, enq_flags, slice);
		break;
	default:
		/*
		 * Dispatch a task to a specific per-CPU DSQ if the target CPU
		 * can be used (according to the cpumask), otherwise redirect
		 * the task to the first CPU available, using the shared DSQ
		 * logic.
		 *
		 * This can happen if the user-space scheduler dispatches the
		 * task to an invalid CPU, the redirection to the shared DSQ
		 * allows to prevent potential stalls in the scheduler.
		 *
		 * If the cpumask is not valid anymore (determined by the
		 * cpumask_cnt generation counter) we can simply cancel the
		 * dispatch event, since the task will be re-enqueued by the
		 * core sched-ext code, potentially selecting a different cpu
		 * and a different cpumask.
		 */
		scx_bpf_dispatch(p, dsq_id, SCX_SLICE_DFL, enq_flags);

		/* Read current cpumask generation counter */
		curr_cpumask_cnt = tctx->cpumask_cnt;

		/* Check if the CPU is valid, according to the cpumask */
		cpu = dsq_to_cpu(dsq_id);
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			force_shared = true;

		/* If the cpumask is not valid anymore, ignore the dispatch event */
		if (curr_cpumask_cnt != cpumask_cnt) {
			scx_bpf_dispatch_cancel();
			__sync_fetch_and_add(&nr_cancel_dispatches, 1);

			dbg_msg("dispatch: pid=%d (%s) dsq=%llu cancel",
				p->pid, p->comm, dsq_id);
			return;
		}

		/*
		 * If the cpumask is valid, but the CPU is invalid, redirect
		 * the task to the shared DSQ.
		 */
		if (force_shared) {
			scx_bpf_dispatch_cancel();
			__sync_fetch_and_add(&nr_bounce_dispatches, 1);

			scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
			dbg_msg("dispatch: pid=%d (%s) dsq=%llu enq_flags=%llx slice=%llu bounce",
				p->pid, p->comm, dsq_id, enq_flags, slice);
			return;
		}

		/* Requested dispatch was valid */
		dbg_msg("dispatch: pid=%d (%s) dsq=%llu enq_flags=%llx slice=%llu",
			p->pid, p->comm, dsq_id, enq_flags, slice);

		break;
	}

	/*
	 * Wake up the target CPU (only if idle and if we are bouncing
	 * to a different CPU).
	 */
	if (cpu != bpf_get_smp_processor_id())
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Dispatch the user-space scheduler.
 */
static bool dispatch_user_scheduler(void)
{
	struct task_struct *p;

	if (!test_and_clear_usersched_needed())
		return false;

	p = bpf_task_from_pid(usersched_pid);
	if (!p) {
		scx_bpf_error("Failed to find usersched task %d", usersched_pid);
		return false;
	}
	/*
	 * Dispatch the scheduler on the first CPU available, likely the
	 * current one.
	 */
	dispatch_task(p, SHARED_DSQ, 0, SCX_SLICE_DFL, 0);
	bpf_task_release(p);

	return true;
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
	const struct cpumask *online_cpumask, *idle_smtmask, *idle_cpumask;
	s32 cpu;

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is idle.
	 */
	if (p->nr_cpus_allowed == 1) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		return -ENOENT;
	}

	/*
	 * Acquire the CPU masks to determine the online and idle CPUs in the
	 * system.
	 */
	online_cpumask = scx_bpf_get_online_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();

	/*
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * Otherwise, search for another usable full-idle core.
		 */
		cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_smtmask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * If a full-idle core can't be found (or if this is not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	/*
	 * If all the previous attempts have failed, try to use any idle CPU in
	 * the system.
	 */
	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_cpumask);
	if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * If all the previous attempts have failed, dispatch the task to the
	 * first CPU that will become available.
	 */
	cpu = -ENOENT;

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpu;
}

s32 BPF_STRUCT_OPS(rustland_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/*
	 * Completely delegate the CPU selection logic to the user-space
	 * scheduler.
	 */
	return prev_cpu;
}

/*
 * Select an idle CPU for a specific task from the user-space scheduler.
 */
SEC("syscall")
int rs_select_cpu(struct task_cpu_arg *input)
{
	struct task_struct *p;
	int cpu;

	p = bpf_task_from_pid(input->pid);
	if (!p)
		return -EINVAL;
	bpf_rcu_read_lock();
	cpu = pick_idle_cpu(p, input->cpu, input->flags);
	bpf_rcu_read_unlock();

	bpf_task_release(p);

	return cpu;
}

/*
 * Fill @task with all the information that need to be sent to the user-space
 * scheduler.
 */
static void
get_task_info(struct queued_task_ctx *task, const struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	task->pid = p->pid;
	task->cpumask_cnt = tctx->cpumask_cnt;
	task->sum_exec_runtime = p->se.sum_exec_runtime;
	task->weight = p->scx.weight;
	task->cpu = scx_bpf_task_cpu(p);
}

/*
 * User-space scheduler is congested: log that and increment congested counter.
 */
static void sched_congested(struct task_struct *p)
{
	dbg_msg("congested: pid=%d (%s)", p->pid, p->comm);
	__sync_fetch_and_add(&nr_sched_congested, 1);
}

/*
 * Task @p becomes ready to run. We can dispatch the task directly here if the
 * user-space scheduler is not required, or enqueue it to be processed by the
 * scheduler.
 */
void BPF_STRUCT_OPS(rustland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct queued_task_ctx *task;

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here.
	 */
	if (is_usersched_task(p))
		return;

	/*
	 * Add tasks to the @queued list, they will be processed by the
	 * user-space scheduler.
	 *
	 * If @queued list is full (user-space scheduler is congested) tasks
	 * will be dispatched directly from the kernel (using the first CPU
	 * available in this case).
	 */
	task = bpf_ringbuf_reserve(&queued, sizeof(*task), 0);
	if (!task) {
		sched_congested(p);
		dispatch_task(p, SHARED_DSQ, 0, SCX_SLICE_DFL, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}
	get_task_info(task, p);
	dbg_msg("enqueue: pid=%d (%s)", p->pid, p->comm);
	bpf_ringbuf_submit(task, 0);

	__sync_fetch_and_add(&nr_queued, 1);
}

/*
 * Handle a task dispatched from user-space, performing the actual low-level
 * BPF dispatch.
 */
static long handle_dispatched_task(struct bpf_dynptr *dynptr, void *context)
{
	const struct dispatched_task_ctx *task;
	struct task_struct *p;
	u64 enq_flags = 0, dsq_id;

	/* Get a pointer to the dispatched task */
	task = bpf_dynptr_data(dynptr, 0, sizeof(*task));
	if (!task)
		return 0;

	/* Ignore entry if the task doesn't exist anymore */
	p = bpf_task_from_pid(task->pid);
	if (!p)
		return 0;

	dbg_msg("usersched: pid=%d cpu=%d cpumask_cnt=%llu slice_ns=%llu flags=%llx",
		task->pid, task->cpu, task->cpumask_cnt, task->slice_ns, task->flags);

	/*
	 * Check whether the user-space scheduler assigned a different
	 * CPU to the task and migrate (if possible).
	 *
	 * If the task has been submitted with RL_CPU_ANY, then
	 * dispatch it to the shared DSQ and run it on the first CPU
	 * available.
	 */
	if (task->flags & RL_CPU_ANY)
		dsq_id = SHARED_DSQ;
	else
		dsq_id = cpu_to_dsq(task->cpu);
	dispatch_task(p, dsq_id, task->cpumask_cnt, task->slice_ns, enq_flags);
	bpf_task_release(p);

	__sync_fetch_and_add(&nr_user_dispatches, 1);

	return !scx_bpf_dispatch_nr_slots();
}

/*
 * Consume tasks dispatched to CPUs that have gone offline.
 *
 * These tasks will be consumed on other active CPUs to prevent indefinite
 * stalling.
 *
 * Return true if one task is consumed, false otherwise.
 */
static bool consume_offline_cpus(s32 cpu)
{
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	struct bpf_cpumask *offline;
	bool ret = false;

	if (!test_and_clear_offline_needed())
		return false;

	offline = offline_cpumask;
	if (!offline)
		return false;

	/*
	 * Cycle through all the CPUs and evenly consume tasks from the DSQs of
	 * those that are offline.
	 */
	bpf_repeat(nr_cpu_ids - 1) {
		cpu = (cpu + 1) % nr_cpu_ids;

		if (!bpf_cpumask_test_cpu(cpu, cast_mask(offline)))
			continue;
		/*
		 * This CPU is offline, if a task has been dispatched there
		 * consume it immediately on the current CPU.
		 */
		if (scx_bpf_consume(cpu_to_dsq(cpu))) {
			set_offline_needed();
			ret = true;
			break;
		}
	}

	return ret;
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
void BPF_STRUCT_OPS(rustland_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Try also to steal tasks directly dispatched to CPUs that have gone
	 * offline (this allows to prevent indefinite task stalls).
	 */
	if (consume_offline_cpus(cpu))
		return;

	/*
	 * First check if the user-space scheduler needs to run, and in that
	 * case try to dispatch it immediately.
	 */
	if (dispatch_user_scheduler())
		return;

	/*
	 * Consume a task from the per-CPU DSQ.
	 */
	if (scx_bpf_consume(cpu_to_dsq(cpu)))
		return;

	/*
	 * Consume all tasks from the @dispatched list and immediately try to
	 * dispatch them on their target CPU selected by the user-space
	 * scheduler (at this point the proper ordering has been already
	 * determined so we can simply dispatch them preserving the same
	 * order).
	 */
	bpf_user_ringbuf_drain(&dispatched, handle_dispatched_task, NULL, 0);

	/*
	 * Consume the first task from the shared DSQ.
	 */
	scx_bpf_consume(SHARED_DSQ);
}

/*
 * Task @p starts on its selected CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(rustland_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);

	dbg_msg("start: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);

	/*
	 * Ensure time slice never exceeds slice_ns when a task is started on a
	 * CPU.
	 */
	p->scx.slice = task_slice(p);

	/*
	 * Mark the CPU as busy by setting the pid as owner (ignoring the
	 * user-space scheduler).
	 */
	if (!is_usersched_task(p))
		__sync_fetch_and_add(&nr_running, 1);
}

/*
 * Task @p stops running on its associated CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(rustland_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);

	dbg_msg("stop: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);
	/*
	 * Mark the CPU as idle by setting the owner to 0.
	 */
	if (!is_usersched_task(p)) {
		__sync_fetch_and_sub(&nr_running, 1);
		/*
		 * Kick the user-space scheduler immediately when a task
		 * releases a CPU and speculate on the fact that most of the
		 * time there is another task ready to run.
		 */
		set_usersched_needed();
	}
}

/*
 * A CPU is about to change its idle state.
 */
void BPF_STRUCT_OPS(rustland_update_idle, s32 cpu, bool idle)
{
	/*
	 * Don't do anything if we exit from and idle state, a CPU owner will
	 * be assigned in .running().
	 */
	if (!idle)
		return;
	/*
	 * A CPU is now available, notify the user-space scheduler that tasks
	 * can be dispatched.
	 */
	if (usersched_has_pending_tasks()) {
		set_usersched_needed();
		/*
		 * Wake up the idle CPU and trigger a resched, so that it can
		 * immediately accept dispatched tasks.
		 */
		scx_bpf_kick_cpu(cpu, 0);
	}
}

/*
 * Task @p changes cpumask: update its local cpumask generation counter.
 */
void BPF_STRUCT_OPS(rustland_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->cpumask_cnt++;
}

/*
 * A CPU is taken away from the scheduler, preempting the current task by
 * another one running in a higher priority sched_class.
 */
void BPF_STRUCT_OPS(rustland_cpu_release, s32 cpu,
				struct scx_cpu_release_args *args)
{
	struct task_struct *p = args->task;
	/*
	 * If the interrupted task is the user-space scheduler make sure to
	 * re-schedule it immediately.
	 */
	dbg_msg("cpu preemption: pid=%d (%s)", p->pid, p->comm);
	if (is_usersched_task(p))
		set_usersched_needed();
}

void BPF_STRUCT_OPS(rustland_cpu_online, s32 cpu)
{
	/* Set the CPU state to online */
	set_cpu_state(offline_cpumask, cpu, false);

	__sync_fetch_and_add(&nr_online_cpus, 1);
}

void BPF_STRUCT_OPS(rustland_cpu_offline, s32 cpu)
{
	/* Set the CPU state to offline */
	set_cpu_state(offline_cpumask, cpu, true);

	__sync_fetch_and_sub(&nr_online_cpus, 1);
	set_offline_needed();
}

/*
 * A new task @p is being created.
 *
 * Allocate and initialize all the internal structures for the task (this
 * function is allowed to block, so it can be used to preallocate memory).
 */
s32 BPF_STRUCT_OPS(rustland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;;

	/* Allocate task's local storage */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	tctx->slice_ns = SCX_SLICE_DFL;

	return 0;
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
	int err = 0;

	/* Kick the scheduler */
	set_usersched_needed();

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
s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
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
 * Create a DSQ for each CPU available in the system and a global shared DSQ.
 *
 * All the tasks processed by the user-space scheduler can be dispatched either
 * to a specific CPU/DSQ or to the first CPU available (SHARED_DSQ).
 *
 * Custom DSQs are then consumed from the .dispatch() callback, that will
 * transfer all the enqueued tasks to the consuming CPU's local DSQ.
 */
static int dsq_init(void)
{
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	int err;
	s32 cpu;

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

	/* Create the global shared DSQ */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	return 0;
}

/*
 * Initialize the scheduling class.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(rustland_init)
{
	struct bpf_cpumask *mask;
	int err;

	/* Compile-time checks */
	BUILD_BUG_ON((MAX_CPUS % 2));

	/* Initialize the offline CPU mask */
	err = calloc_cpumask(&offline_cpumask);
	mask = offline_cpumask;
	if (!mask)
		err = -ENOMEM;
	if (err)
		return err;

	/* Initialize rustland core */
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
void BPF_STRUCT_OPS(rustland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduling class declaration.
 */
SCX_OPS_DEFINE(rustland,
	       .select_cpu		= (void *)rustland_select_cpu,
	       .enqueue			= (void *)rustland_enqueue,
	       .dispatch		= (void *)rustland_dispatch,
	       .running			= (void *)rustland_running,
	       .stopping		= (void *)rustland_stopping,
	       .update_idle		= (void *)rustland_update_idle,
	       .set_cpumask		= (void *)rustland_set_cpumask,
	       .cpu_release		= (void *)rustland_cpu_release,
	       .cpu_online		= (void *)rustland_cpu_online,
	       .cpu_offline		= (void *)rustland_cpu_offline,
	       .init_task		= (void *)rustland_init_task,
	       .init			= (void *)rustland_init,
	       .exit			= (void *)rustland_exit,
	       .flags			= SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms		= 5000,
	       .dispatch_max_batch	= MAX_DISPATCH_SLOT,
	       .name			= "rustland");
