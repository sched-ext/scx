// SPDX-License-Identifier: GPL-2.0
/*
 * Global state of the flow scheduler.
 *
 * Userspace fills in the topology tables before the program is loaded, so
 * the hot paths look up the LLC, NUMA node and core group of a CPU with a
 * plain array access. The tables also carry the online CPUs and the L3
 * size of each LLC. Each
 * CPU publishes what it is running in its own cache line for the
 * preemption and statistics code to read. With --helicoprion, each cgroup
 * also keeps its weight and busy task counts here, and the system keeps
 * the totals and whether the cgroups compete for the CPUs. With
 * --performance, each CPU also counts the time it had no task to run, and
 * the LLCs of a node are paired up for the double helix queues of
 * helix.bpf.h.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H

#include "intf.h"

enum flow_tunables {
	FLOW_NSEC_PER_SEC		= 1000000000,
	FLOW_SLICE_MIN_NS		= 500000,	/* 0.5 ms */
	FLOW_SLICE_MAX_NS		= 5000000,	/* 5 ms */
	FLOW_SLICE_BOOST_MAX_NS		= 20000000,	/* 20 ms */
	FLOW_TARGETED_LATENCY_NS	= 10000000,	/* 10 ms */

	/* How far the virtual time of a task may trail or lead the clock. */
	FLOW_VTIME_LAG_NS		= FLOW_SLICE_MAX_NS,

	/*
	 * How far it may lead while cgroups compete, see flow_cgrp_stat. A
	 * task of a cgroup that is over its share is charged for several
	 * times its CPU time, and needs room for that.
	 */
	FLOW_VTIME_LEAD_NS		= FLOW_SLICE_BOOST_MAX_NS,

	/* Burst length beyond which the deadline offset stops growing. */
	FLOW_BURST_MAX_NS		= 500000000,	/* 500 ms */

	/* Burst length from which a task no longer counts as running briefly. */
	FLOW_RUNTIME_MAX_NS		= 100 * FLOW_TARGETED_LATENCY_NS,

	/* Highest event rate counted in lat_cri, one per 10 us. */
	FLOW_FREQ_MAX			= 100000,

	FLOW_STAT_INTERVAL_NS		= 10000000,	/* 10 ms */

	/* --performance: how busy a CPU must be to wake up quickly, see flow_track_busy(). */
	FLOW_UTIL_ONE			= 1024,
	FLOW_UTIL_BUSY			= FLOW_UTIL_ONE / 4,
	FLOW_UTIL_IDLE			= FLOW_UTIL_ONE / 8,

	FLOW_CPUPERF_REFRESH_NS		= 1000000,	/* 1 ms */
	FLOW_PREEMPT_SHIFT		= 6,
	FLOW_PERF_PREEMPT_SHIFT		= 1,	/* --performance */
	FLOW_VICTIM_PROBES		= 4,
	FLOW_CLOCK_RETRIES		= 8,
	FLOW_WEIGHT_DFLT		= 100,
	FLOW_WEIGHT_MAX			= 10000,
	FLOW_OPS_TIMEOUT_MS		= 20000,

	/*
	 * Tasks of a DSQ looked at for one that is due before a running task
	 * and may run on its CPU.
	 */
	FLOW_AHEAD_DEPTH		= 4,

	/*
	 * --performance, see helix.bpf.h: how many more tasks one strand of
	 * a double helix queue may hold than the other, how many entries
	 * each queue has per CPU of its two LLCs, how many entries a CPU
	 * takes off a strand before it leaves the rest to its next dispatch,
	 * and the arena pages the queues are carved from at a time.
	 */
	FLOW_HELIX_IMBALANCE		= 10,
	FLOW_HELIX_SLOTS		= 4,
	FLOW_HELIX_POPS			= 8,
	FLOW_HELIX_PAGES		= 16,

	/* Priorities below this one belong to realtime and deadline tasks. */
	FLOW_MAX_RT_PRIO		= 100,

	/*
	 * A task that wakes up another one and goes to sleep before it has
	 * run for FLOW_SYNC_WAKE_NS gains FLOW_SYNC_SCORE_STEP points, up to
	 * FLOW_SYNC_SCORE_MAX, and loses half of its points when it runs for
	 * longer. New tasks start with none. Once a task has
	 * FLOW_SYNC_SCORE_MIN points, the task it keeps waking up takes over
	 * its CPU. Only tasks whose bursts average under FLOW_SYNC_WAKE_NS
	 * hand over a CPU. A task that takes over a CPU, and the partner it
	 * preempted, get FLOW_SYNC_SLICE_NS, so a wrong guess costs no more
	 * than that.
	 */
	FLOW_SYNC_WAKE_NS		= 50000,	/* 50 us */
	FLOW_SYNC_SLICE_NS		= 100000,	/* 100 us */
	FLOW_SYNC_SCORE_STEP		= 2,
	FLOW_SYNC_SCORE_MIN		= 6,
	FLOW_SYNC_SCORE_MAX		= 8,

	/* How often a task that keeps taking over CPUs is scored again. */
	FLOW_RESCORE_NS			= 1000000,	/* 1 ms */

	/* How far a task must run ahead before it moves the system virtual time. */
	FLOW_VTIME_GRAIN_NS		= 50000,	/* 50 us */

	/*
	 * A cgroup period is this many runs of the statistics timer. The
	 * charge of a task is scaled by a factor in fixed point, where
	 * FLOW_FACTOR_ONE is 1.
	 */
	FLOW_CGRP_PERIOD_RUNS		= 10,
	FLOW_FACTOR_SHIFT		= 10,
	FLOW_FACTOR_ONE			= 1 << FLOW_FACTOR_SHIFT,
	FLOW_FACTOR_MIN			= FLOW_FACTOR_ONE / 16,
	FLOW_FACTOR_MAX			= FLOW_FACTOR_ONE * 16,
};

enum flow_dsq_ids {
	FLOW_CPU_DSQ_BASE		= 0x1000,
	FLOW_LLC_DSQ_BASE		= 0x2000,
	FLOW_FALLBACK_DSQ		= 0x6100,
};

enum flow_task_flags {
	FLOW_FLAG_SYNC_WAKEUP		= 1 << 0,
	FLOW_FLAG_HARDIRQ_WAKEUP	= 1 << 1,
	FLOW_FLAG_SOFTIRQ_WAKEUP	= 1 << 2,
	FLOW_FLAG_YIELDED		= 1 << 3,	/* preempted by its own wakee */
	FLOW_FLAG_WOKE			= 1 << 4,	/* woke up a task since it woke up */
	FLOW_FLAG_NEW			= 1 << 5,	/* not queued since it joined */
	FLOW_FLAG_NOTED			= 1 << 6,	/* waker noted when it was placed */
};

#define FLOW_CPUPERF_IDLE	(SCX_CPUPERF_ONE / 2)

struct flow_task_ctx {
	u64	vtime;			/* virtual time, see flow_charge() */
	u64	acc_runtime_ns;		/* runtime since the task last woke up */
	u64	avg_runtime_ns;		/* average runtime between wakeup and sleep */
	u64	last_running_clk;	/* when the task last started running */
	u64	last_wake_clk;		/* when the task last woke up another task */
	u64	last_quiescent_clk;	/* when the task last went to sleep */
	u64	score_clk;		/* when last scored at a CPU hand-off */
	u64	sum_exec_ns;		/* sum_exec_runtime already charged */
	u64	wake_freq;		/* how often the task wakes others, in Hz */
	u64	wait_freq;		/* how often the task sleeps, in Hz */
	u64	busy_ns;		/* CPU time charged since the last busy count */
	u32	cgrp_factor;		/* share of its cgroup, see flow_refresh_cgrp() */
	u32	cgrp_period;		/* cgroup period of the last refresh */
	u32	lat_cri;		/* latency criticality */
	u32	lat_cri_waker;		/* lat_cri of the last waker, until scored */
	u32	lat_cri_wakee;		/* lat_cri of the last wakee, until scored */
	u32	flags;			/* FLOW_FLAG_* */
	s32	pinned_cpu;		/* CPU whose nr_pinned counts this task */
	u32	sync_score;		/* how reliably it sleeps after waking others */
	s32	last_waker;		/* pid of the task that last woke it up */
};

struct flow_cpu_state {
	u64	est_stopping_clk;	/* expected stop of curr, 0 if not a victim */
	u64	idle_start_clk;		/* when the CPU ran out of work, 0 if busy */
	u64	cpuperf_commit_clk;	/* when the perf target was last sent */
	u64	sum_lat_cri;		/* lat_cri of tasks started this period */
	u64	burst_start_clk;	/* when curr would have woken up, had it run throughout */
	u32	nr_sched;		/* tasks started this period */
	u32	max_lat_cri;		/* highest lat_cri started this period */
	u32	lat_cri;		/* lat_cri of curr */
	u32	nr_pinned;		/* pinned tasks waiting for this CPU */
	u32	cpuperf_cur;		/* last perf target sent */
	u32	idled;			/* went idle this period */
	u32	busy;			/* never went idle in the last period */
	u64	handoff_clk;		/* when a wakee last took this CPU over */
	u64	idle_ns;		/* --performance: time without a task to run */
	u64	idle_seen;		/* --performance: idle_ns at the last timer run */
	u32	util;			/* --performance: how busy, see flow_track_busy() */
	u32	shallow;		/* --performance: busy enough to wake up quickly */
} __attribute__((aligned(64)));

/*
 * The system virtual time changes whenever a task that runs in short
 * bursts starts, so it gets a cache line of its own instead of sharing one
 * with the statistics every enqueue reads.
 */
struct flow_clock {
	u64	vtime_now;		/* never moves backward */
} __attribute__((aligned(64)));

/* Weight and busy task counts of a cgroup, kept in its cgroup storage. */
struct flow_cgrp_ctx {
	struct bpf_spin_lock	lock;
	u32	weight;			/* cpu.weight */
	u32	period;			/* cgroup period that nr_busy counts */
	u32	nr_busy;		/* busy tasks counted in that period */
	u32	nr_busy_prev;		/* busy tasks counted in the period before */
};

/*
 * Busy tasks of all cgroups. The timer starts a new period every
 * FLOW_CGRP_PERIOD_RUNS runs, and the tasks count themselves into it.
 * The cgroups compete for the CPUs when the last finished period had busy
 * tasks in at least two cgroups, and more of them than CPUs.
 */
struct flow_cgrp_stat {
	u64	weight_sum;		/* weight of the cgroups with a busy task */
	u64	weight_sum_prev;	/* the same for the period before */
	u32	nr_busy;		/* busy tasks in this period */
	u32	nr_busy_prev;		/* busy tasks in the period before */
	u32	nr_groups;		/* cgroups with a busy task in this period */
	u32	active;			/* the cgroups compete in this period */
	u32	period;			/* number of the period being counted */
} __attribute__((aligned(64)));

struct flow_sys_stat {
	u64	nr_queued;		/* tasks waiting in flow DSQs and strands */
	u64	slice_ns;		/* base slice for the current period */
	u64	avg_lat_cri;		/* average lat_cri of running tasks */
	u64	max_lat_cri;		/* average of the highest lat_cri per period */
	u64	thr_lat_cri;		/* lat_cri needed to preempt another task */
	u64	saturated;		/* no CPU was idle while tasks waited */
} __attribute__((aligned(64)));

/* Wakeup latency tuning and cgroup weights, enabled by --helicoprion. */
const volatile bool flow_helicoprion;

/* Higher frame rates and lower input latency, enabled by --performance. */
const volatile bool flow_performance;

/*
 * --performance on a kernel that may queue a wakeup to the CPU of the
 * wakee, see flow_runnable().
 */
const volatile bool flow_queued_wakeup;

const volatile u32 flow_nr_cpus = 1;
const volatile u32 flow_nr_usable = 1;	/* online CPUs, see the loader */
const volatile u32 flow_nr_llcs = 1;
const volatile u32 flow_nr_groups;
const volatile u32 flow_cpu_ids[FLOW_MAX_CPUS];	/* online CPUs, see flow_nr_usable */
const volatile u32 flow_cpu_llc[FLOW_MAX_CPUS];
const volatile u32 flow_cpu_group[FLOW_MAX_CPUS];
const volatile u32 flow_cpu_sibling[FLOW_MAX_CPUS];	/* the CPU itself without SMT */
const volatile u32 flow_llc_node[FLOW_MAX_LLCS];
const volatile u32 flow_llc_kb[FLOW_MAX_LLCS];

/*
 * The LLC that each LLC shares a double helix queue with, or the LLC
 * itself if it has no partner in its node, see helix.bpf.h.
 */
const volatile u32 flow_llc_mate[FLOW_MAX_LLCS];

private(FLOW) struct bpf_cpumask flow_llc_cpumask[FLOW_MAX_LLCS];
private(FLOW) struct bpf_cpumask flow_group_cpumask[FLOW_MAX_GROUPS];

/* CPUs of the LLCs with the largest L3, set when the LLC sizes differ. */
private(FLOW) struct bpf_cpumask flow_big_cache_cpumask;
bool flow_has_big_cache;

struct flow_cpu_state flow_cpu_states[FLOW_MAX_CPUS];
struct flow_clock flow_clock;
struct flow_sys_stat flow_sys_stat;
struct flow_cgrp_stat flow_cgrp_stat;
u64 flow_llc_nr_queued[FLOW_MAX_LLCS];

/*
 * Set once a task went to the fallback DSQ. Until then, ops.dispatch()
 * skips that DSQ, which would always be empty.
 */
bool flow_fallback_used;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_cpu_stats);
} cpu_stats SEC(".maps");

struct flow_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_timer);
} stat_timer SEC(".maps");

static __always_inline u64 flow_min(u64 a, u64 b)
{
	return a < b ? a : b;
}

static __always_inline u64 flow_max(u64 a, u64 b)
{
	return a > b ? a : b;
}

/*
 * The clock of every time stamp. Stamps are compared between CPUs, and
 * scx_bpf_now() returns the runqueue clock of the calling CPU, which can be
 * a hundred milliseconds behind on a CPU whose clock was not updated for a
 * while.
 */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}

static __always_inline bool flow_cpu_valid(s32 cpu)
{
	return cpu >= 0 && (u32)cpu < flow_nr_cpus && (u32)cpu < FLOW_MAX_CPUS;
}

/* The cgroups compete for the CPUs, so their weights are followed. */
static __always_inline bool flow_cgrp_active(void)
{
	return flow_helicoprion && READ_ONCE(flow_cgrp_stat.active);
}

/* @cpu must have passed flow_cpu_valid(). */
static __always_inline u32 flow_llc_of(s32 cpu)
{
	u32 llc = flow_cpu_llc[cpu];

	return llc < flow_nr_llcs && llc < FLOW_MAX_LLCS ? llc : 0;
}

/*
 * The LLC @i places after @llc, for stealing from the other LLCs in turn.
 * Only an LLC in the node of @llc counts if @same_node is set, and only one
 * outside of it if not. Returns -1 for any other LLC.
 */
static __always_inline s32 flow_peer_llc(u32 llc, u32 i, bool same_node)
{
	u32 other = (llc + i) % flow_nr_llcs;

	if (llc >= FLOW_MAX_LLCS || other >= FLOW_MAX_LLCS ||
	    (flow_llc_node[other] == flow_llc_node[llc]) != same_node)
		return -1;
	return other;
}

static __always_inline struct flow_task_ctx *flow_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

static __always_inline void flow_stat_inc(enum flow_stat_idx idx)
{
	struct flow_cpu_stats *st;
	u32 zero = 0;

	st = bpf_map_lookup_elem(&cpu_stats, &zero);
	if (st)
		st->cnt[idx]++;
}

#endif /* __FLOW_MAPS_BPF_H */
