/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/*
 * This file defines the BPF maps, volatiles, and ops dispatch table.
 * The scheduling logic is organized into separate modules included below,
 * in dependency order:
 *   vtime.bpf.c      - EEVDF virtual-time substrate (virtual clock, placement)
 *   classify.bpf.c   - EMA gauge, queue mapping, hysteresis
 *   lifecycle.bpf.c  - task state, init_task/enable/running/stopping/exit_task/cpu_release
 *   select_cpu.bpf.c - CPU selection
 *   enqueue.bpf.c    - enqueue routing, aging, wakeup preemption
 *   dispatch.bpf.c   - queue service with quotas, cross-CPU stealing, keep path
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per-task state, allocated in init_task()/enable() and freed in
 * exit_task() (BPF task storage is reclaimed on task exit regardless).
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-queue virtual-clock state, keyed by queue id 1..3 (slot 0 unused).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_NR_QUEUES + 1);
	__type(key, u32);
	__type(value, struct queue_ctx);
} queue_ctx_stor SEC(".maps");

/*
 * Per-CPU state, keyed by cpu id. Bounds are validated against
 * nr_cpu_ids (<= MLFQ_MAX_CPUS, checked in init()).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_cpu_state);
} cpu_state_stor SEC(".maps");

/*
 * Scheduler-wide state in .bss. The stats counters are shared across
 * CPUs and updated with atomic RMWs; volatile stops the compiler from
 * caching a value in a register across the atomic operations.
 * nr_cpu_ids is written once in init() before any other callback runs.
 */
volatile u64 nr_cpu_ids;
volatile u32 mlfq_steal_scan;
volatile struct mlfq_stats mlfq_stats;

/*
 * Placement bitmaps (see select_cpu.bpf.c).
 *
 * mlfq_primary_bitmap[0] holds the primary (big-core) CPU set;
 * mlfq_llc_bitmaps[llc_id] holds the CPU membership of one LLC domain.
 * Both are plain u64 bitmaps in ARRAY map values: the Rust front-end
 * writes them after load, and the CPU-selection path reads them directly
 * as map values, without any kernel cpumask kptr machinery or RCU
 * protection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_primary_bitmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_LLCS);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_llc_bitmaps SEC(".maps");

/*
 * Constants: rodata. The declared defaults match the constants in
 * intf.h and are written by the Rust front-end before load; the section
 * is read-only afterwards, and the compiler must not fold them as
 * compile-time constants. The veristat configs supply the same values
 * as verification inputs.
 */
const volatile u64 mlfq_q1_slice_ns = MLFQ_Q1_SLICE_NS;
const volatile u64 mlfq_q2_slice_ns = MLFQ_Q2_SLICE_NS;
const volatile u64 mlfq_q3_slice_ns = MLFQ_Q3_SLICE_NS;
const volatile u64 mlfq_budget_max_ns = MLFQ_BUDGET_MAX_NS;
const volatile u64 mlfq_alpha = MLFQ_ALPHA;
const volatile u64 mlfq_t_l_ns = MLFQ_T_L_NS;
const volatile u64 mlfq_t_h_ns = MLFQ_T_H_NS;
const volatile u64 mlfq_ema_half_life_ns = MLFQ_EMA_HALF_LIFE_NS;
const volatile u64 mlfq_aging_period_ns = MLFQ_AGING_PERIOD_NS;
const volatile u64 mlfq_short_sleep_ns = MLFQ_SHORT_SLEEP_NS;
const volatile u64 mlfq_short_sleep_rate_limit_ns = MLFQ_SHORT_SLEEP_RATE_LIMIT_NS;
const volatile u64 mlfq_hysteresis_sleep_ns = MLFQ_HYSTERESIS_SLEEP_NS;
const volatile u64 mlfq_long_sleep_ns = MLFQ_LONG_SLEEP_NS;
const volatile u32 mlfq_q1_quota = MLFQ_Q1_QUOTA;
const volatile u32 mlfq_q2_quota = MLFQ_Q2_QUOTA;
const volatile u32 mlfq_dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH;

/*
 * True when every CPU has the same capacity (uniform-capacity system): the
 * CPU-selection fast path skips all hybrid logic in that case. Written by
 * the Rust front-end from the discovered topology.
 */
const volatile bool mlfq_primary_all = true;

/*
 * Cache-domain data written by the Rust front-end before load. mlfq_nr_llcs
 * is the number of LLC domains with usable masks (0 disables the LLC step
 * entirely); mlfq_llc_has_primary marks LLCs that contain at least one
 * primary (big) core; mlfq_cpu_llc maps a CPU to its LLC domain (0 when
 * unknown).
 */
const volatile u32 mlfq_nr_llcs;
const volatile u8 mlfq_llc_has_primary[MLFQ_MAX_LLCS];
const volatile u32 mlfq_cpu_llc[MLFQ_MAX_CPUS];

static struct task_ctx *mlfq_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static struct task_ctx *mlfq_alloc_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct mlfq_cpu_state *mlfq_lookup_cpu_state(s32 cpu)
{
	u32 key;

	if (cpu < 0)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}

#include "vtime.bpf.c"
#include "classify.bpf.c"
#include "lifecycle.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	struct queue_ctx *q;
	u32 key, qid, nr_cpus;
	s32 cpu;
	s32 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > MLFQ_MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids (%llu) exceeds max supported (%llu)",
			      nr_cpu_ids, (u64)MLFQ_MAX_CPUS);
		return -E2BIG;
	}

	/*
	 * Snapshot the CPU count once; the DSQ creation loop and the
	 * id-space invariant below are keyed on it.
	 */
	nr_cpus = (u32)nr_cpu_ids;
	if (nr_cpus == 0) {
		scx_bpf_error("no possible CPUs");
		return -EINVAL;
	}

	/*
	 * Clamp the Q2/Q3 steal-scan window to the CPU count: on a machine
	 * with fewer CPUs than the cap, an unscaled window would re-peek
	 * the same remote DSQs multiple times per slot.
	 */
	mlfq_steal_scan = nr_cpus < MLFQ_STEAL_SCAN_MAX ?
			  nr_cpus : (u32)MLFQ_STEAL_SCAN_MAX;

	/*
	 * Create the per-CPU vtime-ordered queue DSQs. bpf_for() is an
	 * iterator-backed loop: the bound is a runtime value (the checked
	 * CPU count) and the iterator contract lets the verifier bound the
	 * iteration without unrolling it.
	 */
	bpf_for(cpu, 0, nr_cpus) {
		for (qid = 1; qid <= MLFQ_NR_QUEUES; qid++) {
			ret = scx_bpf_create_dsq(mlfq_dsq_id(qid, cpu), -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("failed to create q%u cpu%d DSQ: %d",
					      qid, cpu, ret);
				return ret;
			}
		}
	}

	/*
	 * The dispatch batch is served as q1 + q2 + q3, with the Q3 share
	 * computed as the unsigned remainder of dispatch_max_batch (see
	 * dispatch.bpf.c). Quotas that cover the whole batch would wrap
	 * that remainder and unbind the Q3 service loop, so the
	 * configuration is rejected outright.
	 */
	if (mlfq_q1_quota + mlfq_q2_quota >= mlfq_dispatch_max_batch) {
		scx_bpf_error("Q1+Q2 quotas (%u+%u) must leave a Q3 share of "
			      "max batch %u",
			      mlfq_q1_quota, mlfq_q2_quota,
			      mlfq_dispatch_max_batch);
		return -EINVAL;
	}

	/*
	 * The queue DSQ id space must stay below the top bits the kernel
	 * reserves for the SCX_DSQ_LOCAL / SCX_DSQ_LOCAL_ON flags, so the
	 * mlfq_dsq_id() arithmetic never collides with the local DSQ
	 * range. With the per-CPU layout the highest id is owned by the
	 * last queue on the last CPU.
	 */
	if (mlfq_dsq_id(MLFQ_NR_QUEUES, (s32)(nr_cpus - 1)) >= SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("queue DSQ id space overflows SCX_DSQ_LOCAL_ON");
		return -EINVAL;
	}

	/* Initialize the per-queue request slices. */
	for (key = 1; key <= MLFQ_NR_QUEUES; key++) {
		q = mlfq_lookup_queue(key);
		if (!q) {
			scx_bpf_error("queue %u map lookup failed", key);
			return -EINVAL;
		}
		q->max_slice_ns = mlfq_queue_slice(key);
	}

	return 0;
}

void BPF_STRUCT_OPS(mlfq_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(mlfq_ops,
	       .select_cpu		= (void *)mlfq_select_cpu,
	       .enqueue			= (void *)mlfq_enqueue,
	       .dispatch		= (void *)mlfq_dispatch,
	       .cpu_release		= (void *)mlfq_cpu_release,
	       .running			= (void *)mlfq_running,
	       .stopping		= (void *)mlfq_stopping,
	       .enable			= (void *)mlfq_enable,
	       .init			= (void *)mlfq_init,
	       .exit			= (void *)mlfq_exit,
	       .init_task		= (void *)mlfq_init_task,
	       .exit_task		= (void *)mlfq_exit_task,
	       .dispatch_max_batch	= MLFQ_DISPATCH_MAX_BATCH,
	       /*
		* The kernel's own default watchdog timeout. A shorter one
		* would trip on machines where real-time tasks saturate the
		* CPUs: the RT class is not throttled below its budget, so
		* the watchdog work can be starved for the whole burst, and
		* the scheduler would exit even though nothing in its own
		* queues stalled. The watchdog still fires on a genuinely
		* stalled queue within the kernel's maximum detection
		* latency.
		*/
	       .timeout_ms		= 30000,
	       .name			= "mlfq");
