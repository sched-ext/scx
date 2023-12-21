/* Copyright (c) Andrea Righi <andrea.righi@canonical.com> */
/*
 * scx_rustland: simple user-space scheduler written in Rust
 *
 * The main goal of this scheduler is be an "easy to read" template that can be
 * used to quickly test more complex scheduling policies. For this reason this
 * scheduler is mostly focused on simplicity and code readability.
 *
 * The scheduler is made of a BPF component (dispatcher) that implements the
 * low level sched-ext functionalities and a user-space counterpart
 * (scheduler), written in Rust, that implements the actual scheduling policy.
 *
 * The BPF dispatcher collects total cputime and weight from the tasks that
 * need to run, then it sends all details to the user-space scheduler that
 * decides the best order of execution of the tasks (based on the collected
 * metrics).
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

/*
 * Exit info (passed to the user-space counterpart).
 */
int exit_kind = SCX_EXIT_NONE;
char exit_msg[SCX_EXIT_MSG_LEN];

/*
 * Scheduler attributes and statistics.
 */
u32 usersched_pid; /* User-space scheduler PID */
static volatile bool usersched_needed; /* Used to wake-up the user-space scheduler */
const volatile bool switch_partial; /* Switch all tasks or SCHED_EXT tasks */
const volatile u64 slice_ns = SCX_SLICE_DFL; /* Base time slice duration */

/* Statistics */
u64 nr_enqueues, nr_user_dispatches, nr_kernel_dispatches;
u64 nr_sched_congested, nr_tasks_running;

 /* Report additional debugging information */
const volatile bool debug;

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);        \
} while(0)

/*
 * Maximum amount of tasks queued between kernel and user-space at a certain
 * time.
 *
 * The @queued and @dispatched lists are used in a producer/consumer fashion
 * between the BPF part and the user-space part.
 */
#define MAX_ENQUEUED_TASKS 1024

/*
 * The map containing tasks that are queued to user space from the kernel.
 *
 * This map is drained by the user space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct queued_task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} queued SEC(".maps");

/*
 * The map containing pids that are dispatched from user space to the kernel.
 *
 * Drained by the kernel in .dispatch().
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct dispatched_task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} dispatched SEC(".maps");

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Set this flag to dispatch directly from .enqueueu() to the local DSQ
	 * of the cpu where the task is going to run (bypassing the scheduler).
	 *
	 * This can be used for example when the selected cpu is idle; in this
	 * case we can simply dispatch the task on the same target cpu and
	 * avoid unnecessary calls to the user-space scheduler.
	 */
	bool force_local;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

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
	return !!(p->flags & PF_KTHREAD);
}

/*
 * Dispatch a task on the local per-CPU FIFO.
 */
static void
dispatch_task_local(struct task_struct *p, u64 enq_flags)
{
	dbg_msg("dispatch (local): pid=%d", p->pid);
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags | SCX_ENQ_LOCAL);
	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
}

/*
 * Dispatch a task on the global FIFO.
 */
static void
dispatch_task_global(struct task_struct *p, u64 payload, u64 enq_flags)
{
	/*
	 * Tasks without a payload are dispatched directly by the kernel, tasks
	 * with payload are dispatched by the user-space scheduler.
	 */
	if (!payload)
		dbg_msg("dispatch (global): pid=%d", p->pid);
	else
		dbg_msg("dispatch (user): pid=%d payload=%llu", p->pid, payload);

	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
	__sync_fetch_and_add(&nr_user_dispatches, 1);
}

/*
 * Select the target CPU where a task can be directly dispatched to from
 * .enqueue().
 *
 * The idea here is to try to find an idle CPU in the system, and preferably
 * maintain the task on the same CPU.
 *
 * If the CPU where the task was running is still idle, then the task can be
 * dispatched immediately on the same CPU from .enqueue(), without having to
 * call the scheduler.
 *
 * In the future we may want to improve this part and figure out a way to move
 * this logic into the user-space scheduler as well.
 */
s32 BPF_STRUCT_OPS(rustland_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 cpu;
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to look up task-local storage for %s", p->comm);
		return -ESRCH;
	}

	/*
	 * Check if the previously used CPU is still idle, in this case we can
	 * dispatch directly in .enqueue() bypassing the scheduler.
	 */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		tctx->force_local = true;
		return prev_cpu;
	}

	/*
	 * Otherwise try to find another idle CPU in the system, but in this
	 * case do not bypass the user-space scheduler (to prevent having too
	 * much migration overhead).
	 */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu;

	/*
	* If we cannot find an idle CPU keep using the same one and pass
	* through the user-space scheduler.
	*/
	return prev_cpu;
}

/*
 * Return true if the selected CPU for the task is immediately avaliable
 * (user-space scheduler not required), false otherwise (user-space scheduler
 * required).
 *
 * To determine if the CPU is available we rely on tctx->force_idle (set in
 * .select_cpu()), since this function may be called on a different CPU (so we
 * cannot check the current CPU directly).
 */
static bool is_task_cpu_available(struct task_struct *p)
{
	struct task_ctx *tctx;

	/*
	 * Always dispatch per-CPU kthread on the same CPU, bypassing the
	 * user-space scheduler (in this way we can to prioritize critical
	 * kernel threads that may potentially slow down the entire system if
	 * they are blocked for too long).
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1)
		return true;

	/*
	 * For regular tasks always rely on force_local to determine if we can
	 * bypass the scheduler.
	 */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
		return false;
	}
	if (tctx->force_local) {
		tctx->force_local = false;
		return true;
	}

	return false;
}

/*
 * Fill @task with all the information that need to be sent to the user-space
 * scheduler.
 */
static void
get_task_info(struct queued_task_ctx *task, const struct task_struct *p)
{
        task->pid = p->pid;
        task->sum_exec_runtime = p->se.sum_exec_runtime;
        task->weight = p->scx.weight;
}

/*
 * Task @p becomes ready to run.
 */
void BPF_STRUCT_OPS(rustland_enqueue, struct task_struct *p, u64 enq_flags)
{
        struct queued_task_ctx task;

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here.
	 */
	if (is_usersched_task(p))
		return;

	/*
	 * Dispatch the task on the local FIFO directly if the selected task's
	 * CPU is available (no scheduling decision required).
	 */
	if (is_task_cpu_available(p)) {
		dispatch_task_local(p, enq_flags);
		return;
	}

	/*
	 * Other tasks can be added to the @queued list and they will be
	 * processed by the user-space scheduler.
	 *
	 * If @queued list is full (user-space scheduler is congested) tasks
	 * will be dispatched directly from the kernel to the global FIFO.
	 */
	get_task_info(&task, p);
	dbg_msg("enqueue: pid=%d", task.pid);
	if (bpf_map_push_elem(&queued, &task, 0)) {
		dbg_msg("scheduler congested: pid=%d", task.pid);
		__sync_fetch_and_add(&nr_sched_congested, 1);
		dispatch_task_global(p, 0, enq_flags);
		return;
	}
	__sync_fetch_and_add(&nr_enqueues, 1);

	/*
	 * Task was sent to user-space correctly, now we can wake-up the
	 * user-space scheduler.
	 */
	usersched_needed = true;
}

/*
 * Dispatch the user-space scheduler.
 */
static void dispatch_user_scheduler(void)
{
	struct task_struct *p;

	if (!usersched_needed)
		return;
	usersched_needed = false;

	p = bpf_task_from_pid(usersched_pid);
	if (!p) {
		scx_bpf_error("Failed to find usersched task %d", usersched_pid);
		return;
	}
	dispatch_task_global(p, 0, 0);
	bpf_task_release(p);
}

/*
 * Dispatch tasks that are ready to run.
 */
void BPF_STRUCT_OPS(rustland_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Check if the user-space scheduler needs to run */
	dispatch_user_scheduler();

	/*
	 * Consume all tasks from the @dispatched list and immediately dispatch
	 * them to the global FIFO (the proper ordering has been already
	 * determined by the user-space scheduler).
	 */
	bpf_repeat(MAX_ENQUEUED_TASKS) {
		struct task_struct *p;
		struct dispatched_task_ctx task;

		if (!scx_bpf_dispatch_nr_slots())
			break;
		if (bpf_map_pop_elem(&dispatched, &task))
			break;
		p = bpf_task_from_pid(task.pid);
		if (!p)
			continue;
		dispatch_task_global(p, task.payload, 0);
		bpf_task_release(p);
	}
}

/* Task @p starts on a CPU */
void BPF_STRUCT_OPS(rustland_running, struct task_struct *p)
{
	dbg_msg("start: pid=%d (%s)", p->pid, p->comm);
	__sync_fetch_and_add(&nr_tasks_running, 1);
}

/* Task @p releases a CPU */
void BPF_STRUCT_OPS(rustland_stopping, struct task_struct *p, bool runnable)
{
	dbg_msg("stop: pid=%d (%s)", p->pid, p->comm);
	__sync_fetch_and_sub(&nr_tasks_running, 1);
}

/* Task @p is created */
s32 BPF_STRUCT_OPS(rustland_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	/* Allocate task's local storage */
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

/*
 * Heartbeat scheduler timer callback.
 */
static int usersched_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	int err = 0;

	/* Kick the scheduler */
	usersched_needed = true;

	/* Re-arm the timer */
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
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
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err)
		scx_bpf_error("Failed to arm scheduler timer");

	return err;
}

/*
 * Initialize the scheduling class.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(rustland_init)
{
	int err;

	err = usersched_timer_init();
	if (err)
		return err;
        if (!switch_partial)
		scx_bpf_switch_all();
	return 0;
}

/*
 * Unregister the scheduling class.
 */
void BPF_STRUCT_OPS(rustland_exit, struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_kind = ei->kind;
}

/*
 * Scheduling class declaration.
 */
SEC(".struct_ops.link")
struct sched_ext_ops rustland = {
	.select_cpu		= (void *)rustland_select_cpu,
	.enqueue		= (void *)rustland_enqueue,
	.dispatch		= (void *)rustland_dispatch,
	.running		= (void *)rustland_running,
	.stopping		= (void *)rustland_stopping,
	.prep_enable		= (void *)rustland_prep_enable,
	.init			= (void *)rustland_init,
	.exit			= (void *)rustland_exit,
	.timeout_ms		= 5000,
	.name			= "rustland",
};
