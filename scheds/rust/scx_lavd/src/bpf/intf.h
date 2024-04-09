/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Changwoo Min <changwoo@igalia.com>
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

enum {
	TASK_COMM_LEN = 16,
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
enum consts {
	CLOCK_BOOTTIME			= 7,
	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),
	LAVD_TIME_ONE_SEC		= (1000ULL * NSEC_PER_MSEC),
	LAVD_MAX_CAS_RETRY		= 8,

	LAVD_TARGETED_LATENCY_NS	= (15 * NSEC_PER_MSEC),
	LAVD_SLICE_MIN_NS		= (300 * NSEC_PER_USEC),/* min time slice */
	LAVD_SLICE_MAX_NS		= (3 * NSEC_PER_MSEC),	/* max time slice */
	LAVD_SLICE_GREEDY_FT		= 3,
	LAVD_LOAD_FACTOR_ADJ		= 6,
	LAVD_LOAD_FACTOR_MAX		= (10 * 1000),
	LAVD_TIME_INFINITY_NS		= 0xFFFFFFFFFFFFFFFFULL,

	LAVD_LC_FREQ_MAX		= 1000000,
	LAVD_LC_RUNTIME_MAX		= LAVD_TARGETED_LATENCY_NS,
	LAVD_LC_RUNTIME_SHIFT		= 10,

	LAVD_BOOST_RANGE		= 14, /* 35% of nice range */
	LAVD_BOOST_WAKEUP_LAT		= 1,
	LAVD_SLICE_BOOST_MAX_STEP	= 3,
	LAVD_GREEDY_RATIO_MAX		= USHRT_MAX,
	LAVD_LAT_PRIO_IDLE		= USHRT_MAX,

	LAVD_ELIGIBLE_TIME_LAT_FT	= 2,
	LAVD_ELIGIBLE_TIME_MAX		= LAVD_TARGETED_LATENCY_NS,

	LAVD_CPU_UTIL_MAX		= 1000, /* 100.0% */
	LAVD_CPU_UTIL_INTERVAL_NS	= (100 * NSEC_PER_MSEC), /* 100 msec */
	LAVD_CPU_ID_HERE		= ((u16)-2),
	LAVD_CPU_ID_NONE		= ((u16)-1),

	LAVD_PREEMPT_KICK_LAT_PRIO	= 18,
	LAVD_PREEMPT_KICK_MARGIN	= (LAVD_SLICE_MIN_NS >> 1),

	LAVD_GLOBAL_DSQ			= 0,
};

/*
 * System-wide CPU utilization
 */
struct sys_cpu_util {
	volatile u64	last_update_clk;
	volatile u64	util;		/* average of the CPU utilization */
	volatile u64	load_factor;	/* system load in % (1000 = 100%) for running all runnables within a LAVD_TARGETED_LATENCY_NS */

	volatile u64	load_ideal;	/* average ideal load of runnable tasks */
	volatile u64	load_actual;	/* average actual load of runnable tasks */

	volatile u64	avg_lat_cri;	/* average latency criticality (LC) */
	volatile u64	max_lat_cri;	/* maximum latency criticality (LC) */
	volatile u64	min_lat_cri;	/* minimum latency criticality (LC) */
	volatile u64	thr_lat_cri;	/* latency criticality threshold for kicking */

	volatile s64	inc1k_low;	/* increment from low LC to priority mapping */
	volatile s64	inc1k_high;	/* increment from high LC to priority mapping */
};

/*
 * Per-CPU context
 */
struct cpu_ctx {
	/* 
	 * Information used to keep track of CPU utilization
	 */
	volatile u64	idle_total;	/* total idle time so far */
	volatile u64	idle_start_clk;	/* when the CPU becomes idle */

	/*
	 * Information used to keep track of load
	 */
	volatile u64	load_ideal;	/* ideal loaf of runnable tasks */
	volatile u64	load_actual;	/* actual load of runnable tasks */
	volatile u64	load_run_time_ns; /* total runtime of runnable tasks */
	volatile u64	last_kick_clk;	/* when the CPU was kicked */

	/*
	 * Information used to keep track of latency criticality
	 */
	volatile u64	max_lat_cri;	/* maximum latency criticality */
	volatile u64	min_lat_cri;	/* minimum latency criticality */
	volatile u64	sum_lat_cri;	/* sum of latency criticality */
	volatile u64	sched_nr;	/* number of schedules */

	/*
	 * Information of a current running task for preemption
	 */
	volatile u64	stopping_tm_est_ns; /* estimated stopping time */
	volatile u16	lat_prio;	/* latency priority */
	volatile u8	is_online;	/* is this CPU online? */
	s32		cpu_id;		/* cpu id */
};

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
	u64	acc_run_time_ns;	/* accmulated runtime from runnable to quiescent state */
	u64	run_time_ns;		/* average runtime per schedule */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	wait_freq;		/* waiting frequency in a second */
	u64	wake_freq;		/* waking-up frequency in a second */
	u64	load_actual;		/* task load derived from run_time and run_freq */

	/*
	 * Task deadline and time slice
	 */
	u64	vdeadline_delta_ns;	/* time delta until task's virtual deadline */
	u64	eligible_delta_ns;	/* time delta until task becomes eligible */
	u64	slice_ns;		/* time slice */
	u64	greedy_ratio;		/* task's overscheduling ratio compared to its nice priority */
	u64	lat_cri;		/* calculated latency criticality */
	u16	slice_boost_prio;	/* how many times a task fully consumed the slice */
	u16	lat_prio;		/* latency priority */
	s16	lat_boost_prio;		/* DEBUG */
	s16	victim_cpu;		/* DEBUG */
};

struct task_ctx_x {
	pid_t	pid;
	char	comm[TASK_COMM_LEN + 1];
	u16	static_prio;	/* nice priority */
	u16	cpu_id;		/* where a task ran */
	u64	cpu_util;	/* cpu utilization in [0..100] */
	u64	sys_load_factor; /* system load factor in [0..100..] */
	u64	max_lat_cri;	/* maximum latency criticality */
	u64	min_lat_cri;	/* minimum latency criticality */
	u64	avg_lat_cri;	/* average latency criticality */
};


/*
 * introspection
 */
enum {
       LAVD_CMD_NOP		= 0x0,
       LAVD_CMD_SCHED_N		= 0x1,
       LAVD_CMD_PID		= 0x2,
       LAVD_CMD_DUMP		= 0x3,
};

enum {
       LAVD_MSG_TASKC		= 0x1,
};

struct introspec {
	volatile u64	arg;
	volatile u32	cmd;
	u8		requested;
};

struct msg_hdr {
	u32		kind;
};

struct msg_task_ctx {
	struct msg_hdr		hdr;
	struct task_ctx		taskc;
	struct task_ctx_x	taskc_x;
};

#endif /* __INTF_H */
