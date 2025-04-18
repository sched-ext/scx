/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;

#define U64_MAX ((u64)~0ULL)

enum {
	TASK_COMM_LEN = 16,
	SCX_SLICE_INF = U64_MAX,
};

#define __kptr
#endif

#ifdef __VMLINUX_H__
#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)
#define MAX_RT_PRIO	100

struct bpf_iter_task;
extern int bpf_iter_task_new(struct bpf_iter_task *it,
		struct task_struct *task, unsigned int flags) __weak __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __weak __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __weak __ksym;
#endif /* __KERNEL__ */

/*
 * common constants
 */
enum {
	LAVD_CPU_ID_MAX			= 512,

	LAVD_CPDOM_MAX_NR		= 16, /* maximum number of compute domain */
	LAVD_CPDOM_MAX_DIST		= 4,  /* maximum distance from one compute domain to another */

	LAVD_STATUS_STR_LEN		= 4, /* {LR: Latency-critical, Regular}
						{HI: performance-Hungry, performance-Insensitive}
						{BT: Big, liTtle}
						{EG: Eligible, Greedy} */
};

/*
 * System-wide stats
 */
struct sys_stat {
	u64	last_update_clk;
	u64	avg_util;	/* average of the CPU utilization */
	u64	avg_sc_util;	/* average of the scaled CPU utilization,
				   which is capacity and frequency invariant */

	u64	avg_svc_time;	/* average service time per task */
	u64	nr_queued_task;
	u64	slice;		/* base time slice */

	u32	avg_lat_cri;	/* average latency criticality (LC) */
	u32	max_lat_cri;	/* maximum latency criticality (LC) */
	u32	thr_lat_cri;	/* latency criticality threshold for kicking */

	u32	min_perf_cri;	/* minimum performance criticality */
	u32	avg_perf_cri;	/* average performance criticality */
	u32	max_perf_cri;	/* maximum performance criticality */
	u32	thr_perf_cri;	/* performance criticality threshold */

	u32	nr_stealee;	/* number of compute domains to be migrated */
	u32	nr_active;	/* number of active cores */

	u64	nr_sched;	/* total scheduling so far */
	u64	nr_perf_cri;	/* number of performance-critical tasks scheduled */
	u64	nr_lat_cri;	/* number of latency-critical tasks scheduled */
	u64	nr_x_migration; /* number of cross domain migration */
	u64	nr_big;		/* scheduled on big core */
	u64	nr_pc_on_big;	/* performance-critical tasks scheduled on big core */
	u64	nr_lc_on_big;	/* latency-critical tasks scheduled on big core */
};

/*
 * Task context
 */
struct task_ctx {
	/*
	 * Clocks when a task state transition happens for task statistics calculation
	 */
	u64	last_runnable_clk;	/* last time when a task wakes up others */
	u64	last_running_clk;	/* last time when scheduled in */
	u64	last_stopping_clk;	/* last time when scheduled out */
	u64	last_quiescent_clk;	/* last time when a task waits for an event */

	/*
	 * Task running statistics for latency criticality calculation
	 */
	u64	acc_runtime;		/* accmulated runtime from runnable to quiescent state */
	u64	avg_runtime;		/* average runtime per schedule */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	wait_freq;		/* waiting frequency in a second */
	u64	wake_freq;		/* waking-up frequency in a second */
	u64	svc_time;		/* total CPU time consumed for this task scaled by task's weight */
	u64	dsq_id;			/* DSQ id where a task run for statistics */

	/*
	 * Task deadline and time slice
	 */
	u32	lat_cri;		/* final context-aware latency criticality */
	u32	lat_cri_waker;		/* waker's latency criticality */
	u32	perf_cri;		/* performance criticality of a task */
	u32	slice_ns;		/* time slice */
	s8	futex_boost;		/* futex acquired or not */
	u8	is_greedy;		/* task's overscheduling ratio compared to its nice priority */
	u8	need_lock_boost;	/* need to boost lock for deadline calculation */
	u8	lock_holder_xted;	/* slice is already extended for a lock holder task */
	u8	wakeup_ft;		/* regular wakeup = 1, sync wakeup = 2 */
	u8	slice_boost_prio;	/* how many times a task fully consumed the slice */
	u8	on_big;			/* executable on a big core */
	u8	on_little;		/* executable on a little core */
	u8	is_affinitized;		/* is this task pinned to a subset of all CPUs? */
};

/*
 * Task's extra context for report
 */
struct task_ctx_x {
	pid_t	pid;
	char	comm[TASK_COMM_LEN + 1];
	char	stat[LAVD_STATUS_STR_LEN + 1];
	u16	static_prio;	/* nice priority */
	u32	cpu_id;		/* where a task ran */
	u64	cpu_util;	/* cpu utilization in [0..100] */
	u64	cpu_sutil;	/* scaled cpu utilization in [0..100] */
	u32	thr_perf_cri;	/* performance criticality threshold */
	u32	avg_lat_cri;	/* average latency criticality */
	u32	nr_active;	/* number of active cores */
	u32	cpuperf_cur;	/* CPU's current performance target */
};


/*
 * introspection
 */
enum {
       LAVD_CMD_NOP		= 0x0,
       LAVD_CMD_SCHED_N		= 0x1,
};

enum {
       LAVD_MSG_TASKC		= 0x1
};

struct introspec {
	volatile u64	arg;
	volatile u32	cmd;
};

struct msg_hdr {
	u32		kind;
};

struct msg_task_ctx {
	struct msg_hdr		hdr;
	struct task_ctx		taskc;
	struct task_ctx_x	taskc_x;
};


/*
 * BPF syscall
 */
enum {
	LAVD_PM_PERFORMANCE	= 0,
	LAVD_PM_BALANCED	= 1,
	LAVD_PM_POWERSAVE	= 2,

	LAVD_PM_MAX		= 3
};

struct power_arg {
	s32	power_mode;
};

#endif /* __INTF_H */
