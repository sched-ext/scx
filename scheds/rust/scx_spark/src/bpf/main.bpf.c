/* SPDX-License-Identifier: GPL-2.0 */
/* 
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_min = 1ULL * NSEC_PER_MSEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile s64 slice_lag = 20ULL * NSEC_PER_MSEC;

/*
 * If enabled, never allow tasks to be directly dispatched.
 */
const volatile bool no_preempt;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * When enabled always dispatch per-CPU kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads;

/*
 * Prioritize per-CPU tasks (tasks that can only run on a single CPU).
 *
 * This allows to prioritize per-CPU tasks that usually tend to be
 * de-prioritized (since they can't be migrated when their only usable CPU
 * is busy). Enabling this option can introduce unfairness and potentially
 * trigger stalls, but it can improve performance of server-type workloads
 * (such as large parallel builds).
 */
const volatile bool local_pcpu;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

/*
 * Enable GPU support for task detection and prioritization.
 */
const volatile bool enable_gpu_support = false;

/*
 * Aggressive GPU task mode: only GPU tasks can use big/performance cores.
 */
const volatile bool aggressive_gpu_tasks = false;

/*
 * Stay with kthread: tasks stay on CPUs where kthreads are running. TODO: Make this more fine-grained. We don't want to stick with all kthreads. C
 */
const volatile bool stay_with_kthread = false;

/*
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;

/*
 * Amount of tasks using GPU that were dispatched.
 */
volatile u64 nr_gpu_task_dispatches;

/*
 * Workload type dispatch statistics.
 */
volatile u64 nr_inference_dispatches;
volatile u64 nr_training_dispatches;
volatile u64 nr_validation_dispatches;
volatile u64 nr_preprocessing_dispatches;
volatile u64 nr_data_loading_dispatches;
volatile u64 nr_model_loading_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids = 1;

/*
 * Runtime throttling.
 *
 * Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
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
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * GPU task detection maps.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_GPU_TASK_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} gpu_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_GPU_TASK_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} gpu_tid SEC(".maps");

/*
 * Workload type detection maps.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct workload_info);
	__uint(max_entries, MAX_WORKLOAD_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} workload_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct workload_info);
	__uint(max_entries, MAX_WORKLOAD_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} workload_tid SEC(".maps");

/*
 * Mask of CPUs that the scheduler can use until the system becomes saturated,
 * at which point tasks may overflow to other available CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Mask of Big (performance) CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *big_cpumask;

/*
 * Mask of Little (energy-efficient) CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *little_cpumask;

/*
 * Mask of Turbo (performance) CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *turbo_cpumask;

/*
 * DSQ dispatch mode.
 */
const volatile u32 dsq_mode = 0;

/*
 * Shared DSQ ID (used when dsq_mode == DSQ_MODE_SHARED).
 */
#define SHARED_DSQ_ID 0

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
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	u64 perf_lvl;
	struct bpf_cpumask __kptr *l3_cpumask;
	bool has_active_kthread;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");


/*
 * Detect workload type based on process name and behavior patterns.
 */
static void detect_workload_type(const struct task_struct *p, u32 pid, u32 tid) {
	if (!enable_gpu_support)
		return;
		
	struct workload_info info = {0};
	u64 now = bpf_ktime_get_ns();
	
	if (!p)
		return;
	
	info.detection_time = now;
	info.workload_type = WORKLOAD_TYPE_UNKNOWN;
	
	/* Use the comm field from the task_struct instead of bpf_get_current_comm */
	char *comm = p->comm;
	
	/* Inference workload detection */
	if (bpf_strncmp(comm, sizeof(p->comm), "inference") == 0 ||
	    bpf_strncmp(comm, sizeof(p->comm), "predict") == 0 ||
	    bpf_strncmp(comm, sizeof(p->comm), "serve") == 0 ||
	    bpf_strncmp(comm, sizeof(p->comm), "model") == 0 ||
	    bpf_strncmp(comm, sizeof(p->comm), "onnx") == 0 ||
	    bpf_strncmp(comm, sizeof(p->comm), "tensorrt") == 0) {
		info.workload_type = WORKLOAD_TYPE_INFERENCE;
		// bpf_printk("Workload detected: PID %u -> INFERENCE\n", pid);
	}
	/* Training workload detection */
	else if (bpf_strncmp(comm, sizeof(p->comm), "train") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "training") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "fit") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "learn") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "optimize") == 0) {
		info.workload_type = WORKLOAD_TYPE_TRAINING;
		// bpf_printk("Workload detected: PID %u -> TRAINING\n", pid);
	}
	/* Validation workload detection */
	else if (bpf_strncmp(comm, sizeof(p->comm), "validate") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "eval") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "test") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "accuracy") == 0) {
		info.workload_type = WORKLOAD_TYPE_VALIDATION;
		// bpf_printk("Workload detected: PID %u -> VALIDATION\n", pid);
	}
	/* Preprocessing workload detection */
	else if (bpf_strncmp(comm, sizeof(p->comm), "preprocess") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "augment") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "transform") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "normalize") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "resize") == 0) {
		info.workload_type = WORKLOAD_TYPE_PREPROCESSING;
		// bpf_printk("Workload detected: PID %u -> PREPROCESSING\n", pid);
	}
	/* Data loading workload detection */
	else if (bpf_strncmp(comm, sizeof(p->comm), "dataloader") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "dataset") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "loader") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "batch") == 0) {
		info.workload_type = WORKLOAD_TYPE_DATA_LOADING;
		// bpf_printk("Workload detected: PID %u -> DATA_LOADING\n", pid);
	}
	/* Model loading workload detection */
	else if (bpf_strncmp(comm, sizeof(p->comm), "load_model") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "checkpoint") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "restore") == 0 ||
	         bpf_strncmp(comm, sizeof(p->comm), "import") == 0) {
		info.workload_type = WORKLOAD_TYPE_MODEL_LOADING;
		// bpf_printk("Workload detected: PID %u -> MODEL_LOADING\n", pid);
	}
	
	if (tid)
		bpf_map_update_elem(&workload_tid, &tid, &info, BPF_ANY);
	bpf_map_update_elem(&workload_tgid, &pid, &info, BPF_ANY);
}

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Save current task's PID/TID to GPU maps when GPU operations are detected.
 * Both entire processes using the GPU and single threads using the GPU will be tracked.
 */
int save_gpu_tgid_pid() {
	if (!enable_gpu_support)
		return 0;
	u32 pid, tid, zero;
	struct task_struct *current;
	zero = 0;

	current = (void *)bpf_get_current_task_btf();
	if (!current)
		return -ENOENT;
	
	pid = current->tgid;
	tid = current->pid;
	
	bpf_map_update_elem(&gpu_tid, &tid, &zero, BPF_ANY);
	bpf_map_update_elem(&gpu_tgid, &pid, &zero, BPF_ANY);
	
	detect_workload_type(current, pid, tid);
	
	return 0;
}



/*
 * Get workload type for a task.
 */
static u32 get_workload_type(const struct task_struct *p) {
	if (!enable_gpu_support)
		return WORKLOAD_TYPE_UNKNOWN;
		
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct workload_info *info;
	
	/* Check thread-specific workload info first */
	info = bpf_map_lookup_elem(&workload_tid, &tid);
	if (info && info->workload_type != WORKLOAD_TYPE_UNKNOWN)
		return info->workload_type;
	
	/* Check process-level workload info */
	info = bpf_map_lookup_elem(&workload_tgid, &tgid);
	if (info && info->workload_type != WORKLOAD_TYPE_UNKNOWN)
		return info->workload_type;
	
	return WORKLOAD_TYPE_UNKNOWN;
}

/*
 * Check if a task is using GPU.
 */
static bool is_gpu_task(const struct task_struct *p)
{
	if (!enable_gpu_support)
		return false;
	
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	
	bool is_gpu = bpf_map_lookup_elem(&gpu_tid, &tid) != NULL ||
	       bpf_map_lookup_elem(&gpu_tgid, &tgid) != NULL;
	
	if (is_gpu) {
		bpf_printk("GPU task detected: %s (PID: %u, TID: %u)\n", p->comm, tgid, tid);
	}
	
	return is_gpu;
}

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Temporary cpumask for calculating scheduling domains.
	 */
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;

	/*
	 * Task's average used time slice.
	 */
	u64 exec_runtime;
	u64 last_run_at;

	/*
	 * Task's deadline, defined as:
	 *
	 *   deadline = vruntime + exec_vruntime
	 *
	 * Here, vruntime represents the task's total runtime, scaled inversely by
	 * its weight, while exec_vruntime accounts for the vruntime accumulated
	 * from the moment the task becomes runnable until it voluntarily releases
	 * the CPU.
	 *
	 * Fairness is ensured through vruntime, whereas exec_vruntime helps in
	 * prioritizing latency-sensitive tasks: tasks that are frequently blocked
	 * waiting for an event (typically latency sensitive) will accumulate a
	 * smaller exec_vruntime, compared to tasks that continuously consume CPU
	 * without interruption.
	 *
	 * As a result, tasks with a smaller exec_vruntime will have a shorter
	 * deadline and will be dispatched earlier, ensuring better responsiveness
	 * for latency-sensitive tasks.
	 */
	u64 deadline;

	/*
	 * Task's recently used CPU: used to determine whether we need to
	 * refresh the task's cpumasks.
	 */
	s32 recent_used_cpu;

	/*
	 * GPU-related fields.
	 */
	bool is_gpu_task;

	/*
	 * Workload classification fields.
	 */
	u32 workload_type;
	u64 gpu_usage_count;
	u64 cpu_usage_time;
	u64 io_operations;
	u64 memory_allocations;
	u64 last_gpu_access;
	u64 last_cpu_access;
};

/*
 * GPU detection kprobes.
 */

SEC("kprobe/nvidia_poll")
int kprobe_nvidia_poll() {
	// bpf_printk("nvidia_poll detected, saving pid/tid\n");
	return save_gpu_tgid_pid();
}

SEC("kprobe/nvidia_open")
int kprobe_nvidia_open() {
	// bpf_printk("nvidia_open detected, saving pid/tid\n");
	return save_gpu_tgid_pid();
}

SEC("kprobe/nvidia_mmap")
int kprobe_nvidia_mmap() {
	// bpf_printk("nvidia_mmap detected, saving pid/tid\n");
	return save_gpu_tgid_pid();
}

/*
 * ML Framework detection kprobes.
 */
// SEC("kprobe/cudaLaunchKernel")
// int kprobe_cuda_launch_kernel() {
// 	u64 pid_tgid = bpf_get_current_pid_tgid();
// 	u32 pid = pid_tgid >> 32;
// 	u32 tid = pid_tgid;
	
// 	/* Mark as GPU task and detect workload type */
// 	save_gpu_tgid_pid();
	
// 	/* Update workload info to indicate training/inference */
// 	struct workload_info *info = bpf_map_lookup_elem(&workload_tid, &tid);
// 	if (info) {
// 		info->gpu_usage_count++;
// 		info->detection_time = bpf_ktime_get_ns();
// 		/* If not already classified, assume inference (most common) */
// 		if (info->workload_type == WORKLOAD_TYPE_UNKNOWN)
// 			info->workload_type = WORKLOAD_TYPE_INFERENCE;
// 	}
	
// 	return 0;
// }

// SEC("kprobe/cudaMemcpy")
// int kprobe_cuda_memcpy() {
// 	u64 pid_tgid = bpf_get_current_pid_tgid();
// 	u32 pid = pid_tgid >> 32;
// 	u32 tid = pid_tgid;
	
// 	/* Mark as GPU task */
// 	save_gpu_tgid_pid();
	
// 	/* Update workload info */
// 	struct workload_info *info = bpf_map_lookup_elem(&workload_tid, &tid);
// 	if (info) {
// 		info->gpu_usage_count++;
// 		info->detection_time = bpf_ktime_get_ns();
// 	}
	
// 	return 0;
// }

// /*
//  * System call kprobes for workload pattern detection.
//  */
// SEC("kprobe/do_readv_writev")
// int kprobe_io_operations() {
// 	u64 pid_tgid = bpf_get_current_pid_tgid();
// 	u32 tid = pid_tgid;
	
// 	/* Update workload info for I/O operations */
// 	struct workload_info *info = bpf_map_lookup_elem(&workload_tid, &tid);
// 	if (info) {
// 		info->io_operations++;
// 		/* High I/O might indicate data loading or preprocessing */
// 		if (info->workload_type == WORKLOAD_TYPE_UNKNOWN && info->io_operations > 10)
// 			info->workload_type = WORKLOAD_TYPE_DATA_LOADING;
// 	}
	
// 	return 0;
// }

// SEC("kprobe/do_mmap")
// int kprobe_memory_allocations() {
// 	u64 pid_tgid = bpf_get_current_pid_tgid();
// 	u32 tid = pid_tgid;
	
// 	/* Update workload info for memory operations */
// 	struct workload_info *info = bpf_map_lookup_elem(&workload_tid, &tid);
// 	if (info) {
// 		info->memory_allocations++;
// 		/* Large memory allocations might indicate model loading */
// 		if (info->workload_type == WORKLOAD_TYPE_UNKNOWN && info->memory_allocations > 5)
// 			info->workload_type = WORKLOAD_TYPE_MODEL_LOADING;
// 	}
	
// 	return 0;
// }

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
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
 * Return the DSQ ID for dispatching tasks.
 */
static u64 get_dsq_id(s32 cpu)
{
	switch (dsq_mode) {
	case DSQ_MODE_CPU:
		return (u64) cpu;
	case DSQ_MODE_SHARED:
	default:
		return SHARED_DSQ_ID;
	}
}

/*
 * Return the total amount of tasks that are currently waiting to be scheduled.
 */
static u64 nr_tasks_waiting(s32 cpu)
{
	u64 dsq_id = get_dsq_id(cpu);
	return scx_bpf_dsq_nr_queued(dsq_id) + 1;
}

/*
 * Scale a value inversely proportional to the task's normalized weight.
 */
static inline u64 scale_by_task_normalized_weight_inverse(const struct task_struct *p, u64 value)
{
	/*
	 * Original weight range:   [1, 10000], default = 100
	 * Normalized weight range: [1, 128], default = 64
	 *
	 * This normalization reduces the impact of extreme weight differences,
	 * preventing highly prioritized tasks from starving lower-priority ones.
	 *
	 * The goal is to ensure a more balanced scheduling that is
	 * influenced more by the task's behavior rather than its priority
	 * difference and prevent potential stalls due to large priority
	 * gaps.
	*/
	u64 weight = 1 + (127 * log2_u64(p->scx.weight) / log2_u64(10000));

	return value * 64 / weight;
}

/*
 * Update and return the task's deadline.
 */
static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min;

	/*
	 * Cap the vruntime budget that an idle task can accumulate to
	 * slice_lag, preventing sleeping tasks from gaining excessive
	 * priority.
	 *
	 * A larger slice_lag favors tasks that sleep longer by allowing
	 * them to accumulate more credit, leading to shorter deadlines and
	 * earlier execution. A smaller slice_lag reduces the advantage of
	 * long sleeps, treating short and long sleeps equally once they
	 * exceed the threshold.
	 *
	 * If slice_lag is negative, it can be used to de-emphasize the
	 * deadline-based scheduling altogether by charging all tasks a
	 * fixed vruntime penalty (equal to the absolute value of
	 * slice_lag), effectively approximating FIFO behavior as the
	 * penalty increases.
	 */
	vtime_min = vtime_now - slice_lag;
	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	tctx->deadline += scale_by_task_normalized_weight_inverse(p, tctx->exec_runtime);

	return tctx->deadline;
}

/*
 * Return true if the task can keep running on its current CPU, false if
 * the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);
	const struct cpumask  *idle_cpumask;
	struct cpu_ctx *cctx;
	bool ret;

	/* Do not keep running if the task doesn't need to run */
	if (!is_queued(p))
		return false;


	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (p->nr_cpus_allowed == 1)
		return true;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	return true;
}


static void task_update_domain(struct task_struct *p, struct task_ctx *tctx,
			       s32 cpu, const struct cpumask *cpumask)
{
	struct bpf_cpumask *primary, *l3_domain;
	struct bpf_cpumask *p_mask, *l3_mask;
	struct cpu_ctx *cctx;

	/*
	 * Refresh task's recently used CPU every time the task's domain
	 * is updated.
	 */
	tctx->recent_used_cpu = cpu;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	primary = primary_cpumask;
	if (!primary)
		return;

	l3_domain = cctx->l3_cpumask;

	p_mask = tctx->cpumask;
	if (!p_mask) {
		scx_bpf_error("cpumask not initialized");
		return;
	}

	l3_mask = tctx->l3_cpumask;
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		return;
	}

	/*
	 * Determine the task's scheduling domain.
	 * idle CPU, re-try again with the primary scheduling domain.
	 */
	bpf_cpumask_and(p_mask, cpumask, cast_mask(primary));

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	if (l3_domain)
		bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));
}

/*
 * Return true if all the CPUs in the LLC of @cpu are busy, false
 * otherwise.
 */
static bool is_llc_busy(const struct cpumask *idle_cpumask, s32 cpu)
{
	const struct cpumask *primary, *l3_mask;
	struct cpu_ctx *cctx;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return false;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	l3_mask = cast_mask(cctx->l3_cpumask);
	if (!l3_mask)
		l3_mask = primary;

	/* If we still don't have a valid mask, assume not busy */
	if (!l3_mask)
		return false;

	return !bpf_cpumask_intersects(l3_mask, idle_cpumask);
}

/*
 * Return true if the waker commits to release the CPU after waking up @p,
 * false otherwise.
 */
static bool is_wake_sync(s32 prev_cpu, s32 this_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();

	if (no_wake_sync)
		return false;

	if ((wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING))
		return true;

	/*
	 * If the current task is a per-CPU kthread running on the wakee's
	 * previous CPU, treat it as a synchronous wakeup.
	 *
	 * The assumption is that the wakee had queued work for the per-CPU
	 * kthread, which has now finished, making the wakeup effectively
	 * synchronous. An example of this behavior is seen in IO
	 * completions.
	 */
	if (is_kthread(current) && (current->nr_cpus_allowed == 1) &&
	    (prev_cpu == this_cpu))
		return true;

	return false;
}

/*
 * Return the target CPU for @p in case of a sync wakeup.
 *
 * During a sync wakeup, the waker commits to releasing the CPU immediately
 * after the wakeup event, so we should consider a sync wakeup almost like
 * a direct function call between a waker and a wakee.
 */
static s32 try_sync_wakeup(const struct task_struct *p, s32 prev_cpu, s32 this_cpu)
{
	/*
	 * If @prev_cpu is idle, keep using it, since there is no guarantee
	 * that the cache hot data from the waker's CPU is more important
	 * than cache hot data in the wakee's CPU.
	 */
	if ((this_cpu != prev_cpu) && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	/*
	 * If waker and wakee are on the same CPU and no other tasks are
	 * queued, consider the waker's CPU as idle.
	 */
	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | this_cpu))
		return this_cpu;

	return -EBUSY;
}

/*
 * Helper function to find idle CPU with specific constraints.
 */
static s32 find_idle_cpu_in_mask(const struct cpumask *mask, u64 flags)
{
	if (!mask)
		return -1;
	return scx_bpf_pick_idle_cpu(mask, flags);
}

static s32 pick_idle_cpu_gpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *big_mask;
	const struct cpumask *turbo_mask;
	s32 cpu = -1; //If no idle CPU is found, go down the regular path for finding an idle CPU

	big_mask = cast_mask(big_cpumask);
	turbo_mask = cast_mask(turbo_cpumask);
	if (big_mask && bpf_cpumask_empty(big_mask)){
		big_mask = NULL;
		turbo_mask = NULL;
		return cpu;
	}

	if(turbo_mask && bpf_cpumask_empty(turbo_mask)){
		turbo_mask = NULL;
	}


/*Try looking for idle turbo CPUs, even if it's not a cache sibling. NOTE: This will probably happen dynamically based on cache sensitivity when workload detection improves.*/
if(turbo_mask){
    //Check if the previous CPU is idle and in the turbo mask
	if (bpf_cpumask_test_cpu(prev_cpu, turbo_mask) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		*is_idle = true;
		return prev_cpu;
	}
//Select any turbo CPU :
	cpu = find_idle_cpu_in_mask(turbo_mask, 0);
	if(cpu >= 0){
		*is_idle = true;
		return cpu;
	}
}
	/*
	 * Try to re-use the same CPU if it's a big CPU.
	 */
	if (big_mask && bpf_cpumask_test_cpu(prev_cpu, big_mask) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		*is_idle = true;
		return prev_cpu;
	}

	//All big CPUs are L3 cache siblings
	if (big_mask) {
		cpu = find_idle_cpu_in_mask(big_mask, 0);
		if(cpu >= 0){
			*is_idle = true;
			return cpu;
		}
	}

	return cpu;
}

static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *primary, *p_mask, *l3_mask, *idle_cpumask, *little_mask;
	struct task_ctx *tctx;
	s32 this_cpu = bpf_get_smp_processor_id(), cpu;
	bool share_llc;
	bool is_gpu_task = false;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	is_gpu_task = tctx->is_gpu_task;

	if(aggressive_gpu_tasks){
		
		if(is_gpu_task){
			bpf_printk("Aggressive gpu task: %s", p->comm);
			cpu = pick_idle_cpu_gpu(p, prev_cpu, wake_flags, is_idle);
			if(cpu >= 0){
				return cpu;
			}
		}
		else{
			bpf_printk("Not a gpu task: %s", p->comm);
			little_mask = cast_mask(little_cpumask);
			if (little_mask && bpf_cpumask_empty(little_mask)){
				little_mask = NULL;
			}

			/*
	 * Try to re-use the same CPU if it's a little CPU.
	 */
	if (little_mask && bpf_cpumask_test_cpu(prev_cpu, little_mask) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

			//All little CPUs are L3 cache siblings
			if(little_mask){
				cpu = find_idle_cpu_in_mask(little_mask, 0);
				if(cpu >= 0){
					*is_idle = true;
					goto out_put_cpumask;
				}
			}
		}
	}
		

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;


	/*
	 * If prev_cpu is not in the primary domain, pick an arbitrary CPU
	 * in the primary domain.
	 */

	if (!bpf_cpumask_test_cpu(prev_cpu, primary)) {
	  	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, primary);
	  	if (cpu >= nr_cpu_ids)
	  		return prev_cpu;
	  	prev_cpu = cpu;
	}
	/*
	 * Refresh task domain based on the previously used cpu. If we keep
	 * selecting the same CPU, the task's domain doesn't need to be
	 * updated and we can save some cpumask ops.
	 */
	if (tctx->recent_used_cpu != prev_cpu)
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);

	p_mask = cast_mask(tctx->cpumask);
	if (p_mask && bpf_cpumask_empty(p_mask))
		p_mask = NULL;
	l3_mask = cast_mask(tctx->l3_cpumask);
	if (l3_mask && bpf_cpumask_empty(l3_mask))
		l3_mask = NULL;

	idle_cpumask = scx_bpf_get_idle_cpumask();

	/*
	 * In case of a sync wakeup, attempt to run the wakee on the
	 * waker's CPU if possible, as it's going to release the CPU right
	 * after the wakeup, so it can be considered as idle and, possibly,
	 * cache hot.
	 *
	 * However, ignore this optimization if the LLC is completely
	 * saturated, since it's just more efficient to dispatch the task
	 * on the first CPU available.
	 */
	share_llc = l3_mask && bpf_cpumask_test_cpu(this_cpu, l3_mask);
	if (is_wake_sync(prev_cpu, this_cpu, wake_flags) &&
	    share_llc && !is_llc_busy(idle_cpumask, this_cpu)) {
		cpu = try_sync_wakeup(p, prev_cpu, this_cpu);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Try to re-use the same CPU.
	 */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU that shares the same L3 cache.
	 */
	if (l3_mask) {
		cpu = find_idle_cpu_in_mask(l3_mask, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU in the scheduling domain.
	 */
	if (p_mask) {
		cpu = find_idle_cpu_in_mask(p_mask, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU usable by the task.
	 */
	cpu = find_idle_cpu_in_mask(p->cpus_ptr, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	/*
	 * If we couldn't find any CPU, or in case of error, return the
	 * previously used CPU.
	 */
	if (cpu < 0)
		cpu = prev_cpu;

	return cpu;
}

/*
 * Return true if we can perform a direct dispatch for @cpu, false
 * otherwise.
 */
static bool can_direct_dispatch(s32 cpu)
{
	u64 dsq_id = get_dsq_id(cpu);

	/*
	 * Never allow direct dispatch if preemption is disabled.
	 */
	if (no_preempt)
		return false;

	/*
	 * Allow direct dispatch when @local_pcpu is enabled, or when there
	 * are no tasks queued in the DSQ.
	 */
	return local_pcpu || !scx_bpf_dsq_nr_queued(dsq_id);
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p,
		s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	if (is_throttled())
		return prev_cpu;

	/* If stay_with_kthread is enabled, check if prev_cpu has an active kthread */
	if (stay_with_kthread) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(prev_cpu);
		if (cctx && cctx->has_active_kthread) {
			return prev_cpu;
		}
	}

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		if (can_direct_dispatch(cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
	}

	return cpu;
}

/*
 * Try to wake up an idle CPU that can immediately process the task.
 *
 * Return true if a CPU has been kicked, false otherwise.
 */
static bool kick_idle_cpu(const struct task_struct *p, const struct task_ctx *tctx,
			  s32 prev_cpu)
{
	const struct cpumask *mask;

	s32 cpu = scx_bpf_task_cpu(p);

	if (is_throttled())
		return false;
	/*
	 * Try to reuse the same CPU if idle.
	 */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
			return true;
	}

	/*
	 * Look for any idle CPU usable by the task that can immediately
	 * execute the task.
	 */
	mask = cast_mask(tctx->l3_cpumask);
	if (mask) {
		cpu = find_idle_cpu_in_mask(mask, 0);
		if (cpu >= 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return true;
		}
	}

	return false;
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 slice, u64 enq_flags)
{

	/*
	 * If a task has been re-enqueued because its assigned CPU has been
	 * taken by a higher priority scheduling class, force it to follow
	 * the regular scheduling path and give it a chance to run on a
	 * different CPU.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
		return false;

	/*
	 * If local_kthread is specified dispatch per-CPU kthreads
	 * directly on their assigned CPU.
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);

		return true;
	}

	/*
	 * Skip direct dispatch if the CPUs are forced to stay idle.
	 */
	if (is_throttled())
		return false;

	/*
	 * If ops.select_cpu() has been skipped, try direct dispatch.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		/*
		 * Stop here if direct dispatch is not allowed for this CPU.
		 */
		if (!can_direct_dispatch(prev_cpu))
			return false;

		/*
		 * If local_pcpu is enabled always dispatch tasks that can
		 * only run on one CPU directly.
		 *
		 * This can help to improve I/O workloads (like large
		 * parallel builds).
		 */
		if (local_pcpu && p->nr_cpus_allowed == 1) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			return true;
		}

		/*
		 * If the task can only run on a single CPU and that CPU is
		 * idle, perform a direct dispatch.
		 */
		if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
						   slice_max, enq_flags);
				__sync_fetch_and_add(&nr_direct_dispatches, 1);

				return true;
			}

			/*
			 * No need to check for other CPUs if the task can
			 * only run on a singe one.
			 */
			return false;
		}


		/*
		 * In case of a remote wakeup (ttwu_queue), attempt a task
		 * migration.
		 */
		if (!scx_bpf_task_running(p)) {
			bool is_idle = false;
			s32 cpu;

			cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
			if (is_idle) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_max, 0);
				__sync_fetch_and_add(&nr_direct_dispatches, 1);

				return true;
			}
		}
	}

	/*
	 * Direct dispatch not possible, follow the regular scheduling
	 * path.
	 */
	return false;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 slice, deadline, dsq_id;
	s32 prev_cpu = scx_bpf_task_cpu(p);

	/*
	 * Dispatch regular tasks to the appropriate DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	deadline = task_deadline(p, tctx);
	slice = CLAMP(slice_max / nr_tasks_waiting(prev_cpu), slice_min, slice_max);

	/*
	 * Try to dispatch the task directly, if possible.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, slice, enq_flags))
		return;

	dsq_id = get_dsq_id(prev_cpu);
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, deadline, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * Track workload type dispatches.
	 */
	if (enable_gpu_support) {
		if (tctx->is_gpu_task) {
			__sync_fetch_and_add(&nr_gpu_task_dispatches, 1);
		}
		
		switch (tctx->workload_type) {
		case WORKLOAD_TYPE_INFERENCE:
			__sync_fetch_and_add(&nr_inference_dispatches, 1);
			break;
		case WORKLOAD_TYPE_TRAINING:
			__sync_fetch_and_add(&nr_training_dispatches, 1);
			break;
		case WORKLOAD_TYPE_VALIDATION:
			__sync_fetch_and_add(&nr_validation_dispatches, 1);
			break;
		case WORKLOAD_TYPE_PREPROCESSING:
			__sync_fetch_and_add(&nr_preprocessing_dispatches, 1);
			break;
		case WORKLOAD_TYPE_DATA_LOADING:
			__sync_fetch_and_add(&nr_data_loading_dispatches, 1);
			break;
		case WORKLOAD_TYPE_MODEL_LOADING:
			__sync_fetch_and_add(&nr_model_loading_dispatches, 1);
			break;
		}
	}

	/*
	 * If there are idle CPUs in the system try to proactively wake up
	 * one, so that it can immediately execute the task in case its
	 * current CPU is busy.
	 */
	if (!kick_idle_cpu(p, tctx, prev_cpu))
		kick_idle_cpu(p, tctx, prev_cpu);
}


void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 dsq_id = get_dsq_id(cpu);

	/*
	 * Let the CPU go idle if the system is throttled.
	 */
	if (is_throttled())
		return;

	/*
	 * Consume regular tasks from the appropriate DSQ, transferring them to the
	 * local CPU DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(dsq_id))
		return;

	if (prev && keep_running(prev, cpu))
		prev->scx.slice = slice_max;

	return;
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	/*
	 * For non-interactive tasks determine their cpufreq scaling factor as
	 * a function of their CPU utilization.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_running;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level, if utilization is above 75%
	 * bump up the performance level to the max.
	 */
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	if (perf_lvl >= SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)
		perf_lvl = SCX_CPUPERF_ONE;
	cctx->perf_lvl = perf_lvl;

	/*
	 * Refresh the dynamic cpuperf scaling factor if needed.
	 */
	if (cpufreq_perf_lvl < 0)
		scx_bpf_cpuperf_set(cpu, cctx->perf_lvl);

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

/*
 * Update workload statistics for a task.
 */
static void update_workload_stats(struct task_struct *p, struct task_ctx *tctx, u64 now)
{
	if (!enable_gpu_support)
		return;
		
	/* Update CPU usage time */
	if (tctx->last_cpu_access > 0) {
		tctx->cpu_usage_time += now - tctx->last_cpu_access;
	}
	tctx->last_cpu_access = now;
	
	/* Update workload type based on behavior patterns */
	if (tctx->workload_type == WORKLOAD_TYPE_UNKNOWN) {
		/* High GPU usage might indicate training */
		if (tctx->gpu_usage_count > 100) {
			tctx->workload_type = WORKLOAD_TYPE_TRAINING;
		}
		/* High I/O operations might indicate data loading */
		else if (tctx->io_operations > 50) {
			tctx->workload_type = WORKLOAD_TYPE_DATA_LOADING;
		}
		/* High memory allocations might indicate model loading */
		else if (tctx->memory_allocations > 20) {
			tctx->workload_type = WORKLOAD_TYPE_MODEL_LOADING;
		}
	}
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);

	__sync_fetch_and_add(&nr_running, 1);

	/* If stay_with_kthread is enabled, track kthread activity */
	if (stay_with_kthread && is_kthread(p)) {
		struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
		if (cctx) {
			cctx->has_active_kthread = true;
		}
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = now;

	/*
	 * Update workload statistics.
	 */
	if (enable_gpu_support) {
		update_workload_stats(p, tctx, now);
	}

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpu_load(p, tctx);

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (time_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now(), slice, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	/* If stay_with_kthread is enabled, reset kthread activity flag */
	if (stay_with_kthread && is_kthread(p)) {
		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx) {
			cctx->has_active_kthread = false; //Maayybee racey? 
		}
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the time slice used by the task.
	 */
	slice = now - tctx->last_run_at;

	/*
	 * Update task's execution time (exec_runtime), but never account
	 * more than 10 slices of runtime to prevent excessive
	 * de-prioritization of CPU-intensive tasks (which could lead to
	 * starvation).
	 */
	if (tctx->exec_runtime < 10 * slice_max)
		tctx->exec_runtime += slice;

	/*
	 * Update task's vruntime.
	 */
	tctx->deadline += scale_by_task_normalized_weight_inverse(p, slice);

	/*
	 * Update CPU runtime.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;
	delta_runtime = now - cctx->last_running;
	cctx->tot_runtime += delta_runtime;
}

void BPF_STRUCT_OPS(bpfland_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
}

void BPF_STRUCT_OPS(bpfland_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * When a CPU is taken by a higher priority scheduler class,
	 * re-enqueue all the tasks that are waiting in the local DSQ, so
	 * that we can give them a chance to run on another CPU.
	 */
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(bpfland_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	task_update_domain(p, tctx, cpu, cpumask);
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* Initialize voluntary context switch timestamp */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	tctx->deadline = vtime_now;
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/*
	 * Detect if this task is using GPU.
	 */
	if (enable_gpu_support) {
		tctx->is_gpu_task = is_gpu_task(p);

		/*
		 * Initialize workload classification fields.
		 */
		detect_workload_type(p, p->pid, 0);
		tctx->workload_type = get_workload_type(p);
		tctx->gpu_usage_count = 0;
		tctx->cpu_usage_time = 0;
		tctx->io_operations = 0;
		tctx->memory_allocations = 0;
		tctx->last_gpu_access = 0;
		tctx->last_cpu_access = 0;
	}

	/*
	 * Create task's primary cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	/*
	 * Create task's L3 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	task_update_domain(p, tctx, cpu, p->cpus_ptr);

	return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 */
	mask = *cpumask;
	if (mask)
		return 0;
	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
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

	/* Make sure the target CPU mask is initialized */
	switch (input->lvl_id) {
	case 3:
		pmask = &cctx->l3_cpumask;
		break;
	default:
		return -EINVAL;
	}
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
int enable_cpu(struct enable_cpu_arg *input)
{
	struct bpf_cpumask *mask;
	struct bpf_cpumask **target_mask;
	int err = 0;

	/* Select the target mask based on mask_type */
	switch (input->mask_type) {
	case 0: /* primary */
		target_mask = &primary_cpumask;
		break;
	case 1: /* big */
		target_mask = &big_cpumask;
		break;
	case 2: /* little */
		target_mask = &little_cpumask;
		break;
	case 3: /* turbo */
		target_mask = &turbo_cpumask;
		break;
	default:
		return -EINVAL;
	}

	/* Make sure the target CPU mask is initialized */
	err = init_cpumask(target_mask);
	if (err)
		return err;

	/*
	 * Enable the target CPU in the specified domain. If the
	 * target CPU is a negative value, clear the whole mask (this can be
	 * used to reset the domain).
	 */
	bpf_rcu_read_lock();
	mask = *target_mask;
	if (mask) {
		s32 cpu = input->cpu_id;

		if (cpu < 0)
			bpf_cpumask_clear(mask);
		else
			bpf_cpumask_set_cpu(cpu, mask);
	}
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Initialize cpufreq performance level on all the online CPUs.
 */
static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for (cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		/* Set the initial cpufreq performance level  */
		if (cpufreq_perf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
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

	/*
	 * Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we
	 * need to interrupt the running tasks and inject the idle sleep.
	 *
	 * Otherwise, send a wakeup IPI to resume from the injected idle
	 * sleep.
	 */
	if (throttled) {
		flags = SCX_KICK_IDLE;
		duration = slice_max;
	} else {
		flags = SCX_KICK_PREEMPT;
		duration = throttle_ns;
	}

	/*
	 * Flip the throttled state.
	 */
	set_throttled(!throttled);

	bpf_for(cpu, 0, nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, flags);

	/*
	 * Re-arm the duty-cycle timer setting the runtime or the idle time
	 * duration.
	 */
	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	struct bpf_timer *timer;
	int err;
	u32 key = 0;
	s32 cpu;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs */
	init_cpuperf_target();

	/*
	 * Create DSQs based on the selected mode.
	 */
	switch (dsq_mode) {
	case DSQ_MODE_CPU:
		/* Create per-CPU DSQs */
		bpf_for(cpu, 0, nr_cpu_ids) {
			err = scx_bpf_create_dsq((u64) cpu, -1);
			if (err) {
				scx_bpf_error("failed to create per-CPU DSQ %llu for CPU %d: %d", 
					     cpu, cpu, err);
				return err;
			}
		}
		break;
	case DSQ_MODE_SHARED:
		/* Create a single shared DSQ */
		err = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
		if (err) {
			scx_bpf_error("failed to create shared DSQ %d: %d", SHARED_DSQ_ID, err);
			return err;
		}
		break;
	default:
		/* Default to shared DSQ mode */
		err = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
		if (err) {
			scx_bpf_error("failed to create shared DSQ %d: %d", SHARED_DSQ_ID, err);
			return err;
		}
		break;
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	/* Initialize the big CPU domain */
	err = init_cpumask(&big_cpumask);
	if (err)
		return err;

	/* Initialize the little CPU domain */
	err = init_cpumask(&little_cpumask);
	if (err)
		return err;

	/* Initialize the turbo CPU domain */
	err = init_cpumask(&turbo_cpumask);
	if (err)
		return err;

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup throttle timer");
		return -ESRCH;
	}

	/*
	 * Fire the throttle timer if CPU throttling is enabled.
	 */
	if (throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_max, 0);
		if (err) {
			scx_bpf_error("Failed to arm throttle timer");
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(bpfland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bpfland_ops,
	       .select_cpu		= (void *)bpfland_select_cpu,
	       .enqueue			= (void *)bpfland_enqueue,
	       .dispatch		= (void *)bpfland_dispatch,
	       .running			= (void *)bpfland_running,
	       .stopping		= (void *)bpfland_stopping,
	       .runnable		= (void *)bpfland_runnable,
	       .cpu_release		= (void *)bpfland_cpu_release,
	       .set_cpumask		= (void *)bpfland_set_cpumask,
	       .enable			= (void *)bpfland_enable,
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= 5000,
	       .name			= "spark");
