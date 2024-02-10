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
	u64 nvcsw; /* Voluntary context switches */
	u64 weight; /* Task static priority */
};

/*
 * Task sent to the BPF dispatcher by the user-space scheduler.
 *
 * This structure has a payload that can be used by the user-space scheduler to
 * send debugging information to the BPF dispatcher (i.e., vruntime, etc.),
 * depending on the particular scheduler implementation.
 *
 * This struct can be easily extended to send more information to the
 * dispatcher (i.e., a target CPU, a variable time slice, etc.).
 */
struct dispatched_task_ctx {
	s32 pid;
	s32 cpu; /* CPU where the task should be dispatched */
	u64 cpumask_cnt; /* cpumask generation counter */
	u64 payload; /* Task payload */
};

#endif /* __INTF_H */
