// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define NSEC_PER_SEC	1000000000L
#define CLOCK_BOOTTIME	7

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;
#endif

/* Check a condition at build time */
#define BUILD_BUG_ON(expr) \
	do { \
		extern char __build_assert__[(expr) ? -1 : 1] \
			__attribute__((unused)); \
	} while(0)

/*
 * Maximum amount of CPUs supported by this scheduler (this defines the size of
 * cpu_map that is used to store the idle state and CPU ownership).
 */
#define MAX_CPUS 1024

/* Special dispatch flags */
enum {
	/*
	 * Do not assign any specific CPU to the task.
	 *
	 * The task will be dispatched to the global shared DSQ and it will run
	 * on the first CPU available.
	 */
	RL_CPU_ANY = 1 << 0,

	/*
	 * Allow to preempt the target CPU when dispatching the task.
	 */
	RL_PREEMPT_CPU = 1 << 1,
};

/*
 * Task sent to the user-space scheduler by the BPF dispatcher.
 *
 * All attributes are collected from the kernel by the the BPF component.
 */
struct queued_task_ctx {
	s32 pid;
	s32 cpu; /* CPU where the task is running (-1 = exiting) */
	u64 cpumask_cnt; /* cpumask generation counter */
	u64 sum_exec_runtime; /* Total cpu time */
	u64 weight; /* Task static priority */
};

/*
 * Task sent to the BPF dispatcher by the user-space scheduler.
 *
 * This struct can be easily extended to send more information to the
 * dispatcher (i.e., a target CPU, a variable time slice, etc.).
 */
struct dispatched_task_ctx {
	s32 pid;
	s32 cpu; /* CPU where the task should be dispatched */
	u64 flags; /* special dispatch flags */
	u64 cpumask_cnt; /* cpumask generation counter */
	u64 slice_ns; /* time slice assigned to the task (0=default) */
};

#endif /* __INTF_H */
