// SPDX-License-Identifier: GPL-2.0
/*
 * Global state of the mlfq scheduler.
 *
 * Userspace fills in the topology tables before the program is loaded, so
 * the hot paths look up the LLC, NUMA node and core group of a CPU with a
 * plain array access. The tables also carry the L3 size of each LLC. Each
 * CPU publishes what it is running in its own cache line for the
 * preemption and statistics code to read.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __MLFQ_MAPS_BPF_H
#define __MLFQ_MAPS_BPF_H

#include "intf.h"

enum mlfq_tunables {
	MLFQ_NSEC_PER_SEC		= 1000000000,
	MLFQ_NSEC_PER_MSEC		= 1000000,
	MLFQ_SLICE_MIN_NS		= 500000,	/* 0.5 ms */
	MLFQ_SLICE_MAX_NS		= 5000000,	/* 5 ms */
	MLFQ_SLICE_BOOST_MAX_NS		= 20000000,	/* 20 ms */
	MLFQ_TARGETED_LATENCY_NS	= 10000000,	/* 10 ms */

	/*
	 * Runtime the top level allows. A burst that fits in it can get a
	 * boosted slice, and each level below allows twice the runtime of the
	 * one above it. The bottom level holds every longer burst.
	 */
	MLFQ_LEVEL_QUANTUM_NS		= MLFQ_SLICE_BOOST_MAX_NS,
	MLFQ_NR_LEVELS			= 8,

	/*
	 * A waking task takes the CPU of a task of another process on
	 * MLFQ_PREEMPT_LEVEL or below right away, once that task has run for
	 * MLFQ_PREEMPT_MIN_RUN_NS, and only while fewer than
	 * MLFQ_PREEMPT_MAX_AHEAD queued tasks are due before it. Each limit
	 * keeps a busy queue from turning every wakeup into a preemption.
	 */
	MLFQ_PREEMPT_LEVEL		= 3,
	MLFQ_PREEMPT_MIN_RUN_NS		= 100000,	/* 0.1 ms */
	MLFQ_PREEMPT_MAX_AHEAD		= 2,

	/* How far the virtual time of a task may trail or lead the clock. */
	MLFQ_VTIME_LAG_NS		= MLFQ_SLICE_MAX_NS,

	/* Burst length beyond which the deadline offset stops growing. */
	MLFQ_BURST_MAX_NS		= 500000000,	/* 500 ms */

	/* Burst length from which a task no longer counts as running briefly. */
	MLFQ_RUNTIME_MAX_NS		= 100 * MLFQ_TARGETED_LATENCY_NS,

	/* Highest event rate counted in lat_cri, one per 10 us. */
	MLFQ_FREQ_MAX			= 100000,

	MLFQ_STAT_INTERVAL_NS		= 10000000,	/* 10 ms */
	MLFQ_CPUPERF_REFRESH_NS		= 1000000,	/* 1 ms */
	MLFQ_PREEMPT_SHIFT		= 6,
	MLFQ_VICTIM_PROBES		= 4,
	MLFQ_CLOCK_RETRIES		= 8,
	MLFQ_WEIGHT_DFLT		= 100,
	MLFQ_WEIGHT_MAX			= 10000,
	MLFQ_OPS_TIMEOUT_MS		= 20000,
};

enum mlfq_dsq_ids {
	MLFQ_CPU_DSQ_BASE		= 0x1000,
	MLFQ_LLC_DSQ_BASE		= 0x2000,
	MLFQ_FALLBACK_DSQ		= 0x6100,
};

enum mlfq_task_flags {
	MLFQ_FLAG_SYNC_WAKEUP		= 1 << 0,
	MLFQ_FLAG_HARDIRQ_WAKEUP	= 1 << 1,
	MLFQ_FLAG_SOFTIRQ_WAKEUP	= 1 << 2,
};

#define MLFQ_CPUPERF_IDLE	(SCX_CPUPERF_ONE / 2)

struct mlfq_task_ctx {
	u64	vtime;			/* virtual time, see mlfq_charge() */
	u64	acc_runtime_ns;		/* runtime since the task last woke up */
	u64	avg_runtime_ns;		/* average runtime between wakeup and sleep */
	u64	last_running_clk;	/* when the task last started running */
	u64	last_wake_clk;		/* when the task last woke up another task */
	u64	last_quiescent_clk;	/* when the task last went to sleep */
	u64	wake_freq;		/* how often the task wakes others, in Hz */
	u64	wait_freq;		/* how often the task sleeps, in Hz */
	u32	lat_cri;		/* latency criticality */
	u32	lat_cri_waker;		/* lat_cri of the last waker, until scored */
	u32	lat_cri_wakee;		/* lat_cri of the last wakee, until scored */
	u32	flags;			/* MLFQ_FLAG_* */
	s32	pinned_cpu;		/* CPU whose nr_pinned counts this task */
};

struct mlfq_cpu_state {
	u64	est_stopping_clk;	/* expected stop of curr, 0 if not a victim */
	u64	run_start_clk;		/* when curr started or was kept, 0 if idle or claimed */
	u64	idle_start_clk;		/* when the CPU ran out of work, 0 if busy */
	u64	cpuperf_commit_clk;	/* when the perf target was last sent */
	u64	sum_lat_cri;		/* lat_cri of tasks started this period */
	u32	nr_sched;		/* tasks started this period */
	u32	max_lat_cri;		/* highest lat_cri started this period */
	u32	lat_cri;		/* lat_cri of curr */
	u32	nr_pinned;		/* pinned tasks waiting for this CPU */
	u32	cpuperf_cur;		/* last perf target sent */
	u32	run_acc_ms;		/* burst of curr at run_start_clk, in ms */
} __attribute__((aligned(64)));

/*
 * The system virtual time changes whenever a task that runs in short
 * bursts starts, so it gets a cache line of its own instead of sharing one
 * with the statistics every enqueue reads.
 */
struct mlfq_clock {
	u64	vtime_now;		/* never moves backward */
} __attribute__((aligned(64)));

struct mlfq_sys_stat {
	u64	nr_queued;		/* tasks waiting in mlfq DSQs */
	u64	slice_ns;		/* base slice for the current period */
	u64	avg_lat_cri;		/* average lat_cri of running tasks */
	u64	max_lat_cri;		/* average of the highest lat_cri per period */
	u64	thr_lat_cri;		/* lat_cri needed to preempt another task */
} __attribute__((aligned(64)));

const volatile u32 mlfq_nr_cpus = 1;
const volatile u32 mlfq_nr_llcs = 1;
const volatile u32 mlfq_nr_groups;
const volatile u32 mlfq_cpu_llc[MLFQ_MAX_CPUS];
const volatile u32 mlfq_cpu_group[MLFQ_MAX_CPUS];
const volatile u32 mlfq_llc_node[MLFQ_MAX_LLCS];
const volatile u32 mlfq_llc_kb[MLFQ_MAX_LLCS];

private(MLFQ) struct bpf_cpumask mlfq_llc_cpumask[MLFQ_MAX_LLCS];
private(MLFQ) struct bpf_cpumask mlfq_group_cpumask[MLFQ_MAX_GROUPS];

/* CPUs of the LLCs with the largest L3, set when the LLC sizes differ. */
private(MLFQ) struct bpf_cpumask mlfq_big_cache_cpumask;
bool mlfq_has_big_cache;

struct mlfq_cpu_state mlfq_cpu_states[MLFQ_MAX_CPUS];
struct mlfq_clock mlfq_clock;
struct mlfq_sys_stat mlfq_sys_stat;
u64 mlfq_llc_nr_queued[MLFQ_MAX_LLCS];

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mlfq_task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_cpu_stats);
} cpu_stats SEC(".maps");

struct mlfq_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_timer);
} stat_timer SEC(".maps");

static __always_inline u64 mlfq_min(u64 a, u64 b)
{
	return a < b ? a : b;
}

static __always_inline u64 mlfq_max(u64 a, u64 b)
{
	return a > b ? a : b;
}

static __always_inline bool mlfq_cpu_valid(s32 cpu)
{
	return cpu >= 0 && (u32)cpu < mlfq_nr_cpus && (u32)cpu < MLFQ_MAX_CPUS;
}

/* @cpu must have passed mlfq_cpu_valid(). */
static __always_inline u32 mlfq_llc_of(s32 cpu)
{
	u32 llc = mlfq_cpu_llc[cpu];

	return llc < mlfq_nr_llcs && llc < MLFQ_MAX_LLCS ? llc : 0;
}

static __always_inline struct mlfq_task_ctx *mlfq_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

static __always_inline void mlfq_stat_inc(enum mlfq_stat_idx idx)
{
	struct mlfq_cpu_stats *st;
	u32 zero = 0;

	st = bpf_map_lookup_elem(&cpu_stats, &zero);
	if (st)
		st->cnt[idx]++;
}

#endif /* __MLFQ_MAPS_BPF_H */
