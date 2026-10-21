/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>
 *
 * scx_intent: Exploidus 5-Class Intent-Based Preemptive CPU Scheduler.
 * Implemented natively in in-kernel BPF using 5 dedicated BPF Dispatch Queues (DSQs).
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Tunables configurable from userspace / rodata */
const volatile bool debug = false;
const volatile u32 starvation_threshold = STARVATION_THRESHOLD;

/* Global statistics shared with userspace */
struct intent_stats stats = {};

/* Multi-tier starvation counters per intent queue (updated atomically) */
static u32 starvation_counters[INTENT_COUNT] = {};

/*
 * Dynamic classification map populated by userspace presets / rules.
 * Maps task command name (char[16]) -> intent class (u32).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INTENT_RULES);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, u32);
} intent_map SEC(".maps");

/*
 * Classify task into one of the 5 Exploidus intent tiers:
 * 1. Checks dynamic intent_map populated by userspace presets (--preset desktop/gaming/server).
 * 2. Falls back to behavioral heuristics:
 *    - Real-time policies (SCHED_FIFO, SCHED_RR) -> INTENT_AUDIT
 *    - Batch and idle policies (SCHED_BATCH, SCHED_IDLE) -> INTENT_COMPUTE
 *    - Interactive / low latency (nice < 0) -> INTENT_INTERACTIVE
 *    - Standard default (nice 0..5) -> INTENT_IO
 *    - Background compute (nice > 5) -> INTENT_COMPUTE
 */
static inline enum intent_type classify_task(struct task_struct *p)
{
	char comm[TASK_COMM_LEN] = {};
	bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);

	u32 *val = bpf_map_lookup_elem(&intent_map, comm);
	if (val && *val < INTENT_COUNT)
		return (enum intent_type)*val;

	/* Real-time scheduling policies */
	if (p->policy == 1 /* SCHED_FIFO */ || p->policy == 2 /* SCHED_RR */)
		return INTENT_AUDIT;

	/* Batch and idle scheduling policies */
	if (p->policy == 3 /* SCHED_BATCH */ || p->policy == 5 /* SCHED_IDLE */)
		return INTENT_COMPUTE;

	/* Fallback based on static priority (120 is nice 0) */
	if (p->static_prio < 115)
		return INTENT_INTERACTIVE;
	else if (p->static_prio <= 125)
		return INTENT_IO;
	else
		return INTENT_COMPUTE;
}

static inline u64 slice_for_intent(enum intent_type intent)
{
	switch (intent) {
	case INTENT_AUDIT:
		return SLICE_AUDIT_NS;
	case INTENT_INTERACTIVE:
		return SLICE_INTERACTIVE_NS;
	case INTENT_IO:
		return SLICE_IO_NS;
	case INTENT_NETWORK:
		return SLICE_NETWORK_NS;
	case INTENT_COMPUTE:
	default:
		return SLICE_COMPUTE_NS;
	}
}

s32 BPF_STRUCT_OPS(intent_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	return cpu;
}

void BPF_STRUCT_OPS(intent_enqueue, struct task_struct *p, u64 enq_flags)
{
	enum intent_type intent = classify_task(p);
	u64 slice = slice_for_intent(intent);
	u64 dsq_id = (u64)intent;

	scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
	__sync_fetch_and_add(&stats.enqueued[intent], 1);
}

void BPF_STRUCT_OPS(intent_dispatch, s32 cpu, struct task_struct *prev)
{
	int i, j;

	/*
	 * 1. Multi-Tier Anti-Starvation Pass:
	 * Examine lower queues in reverse priority order (Compute -> Network -> IO -> Interactive).
	 * If any lower-priority tier has been starved past starvation_threshold due to sustained
	 * higher-tier saturation, grant it an immediate guaranteed dispatch slot.
	 */
	bpf_for(i, 0, INTENT_COUNT - 1) {
		int q = (INTENT_COUNT - 1) - i;
		if (starvation_counters[q] >= starvation_threshold) {
			if (scx_bpf_dsq_move_to_local((u64)q, 0)) {
				__sync_lock_test_and_set(&starvation_counters[q], 0);
				__sync_fetch_and_add(&stats.starved_dispatches[q], 1);
				__sync_fetch_and_add(&stats.dispatched[q], 1);
				return;
			}
		}
	}

	/*
	 * 2. Normal Priority Drain:
	 * Audit -> Interactive -> IO -> Network -> Compute
	 */
	bpf_for(i, 0, INTENT_COUNT) {
		if (scx_bpf_dsq_move_to_local((u64)i, 0)) {
			__sync_lock_test_and_set(&starvation_counters[i], 0);
			__sync_fetch_and_add(&stats.dispatched[i], 1);

			/* Advance starvation counters for all waiting lower queues */
			bpf_for(j, 0, INTENT_COUNT) {
				if (j > i)
					__sync_fetch_and_add(&starvation_counters[j], 1);
			}
			return;
		}
	}

	/*
	 * 3. Keep running previous task if runnable and no new work queued
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		scx_bpf_task_set_slice(prev, SLICE_INTERACTIVE_NS);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(intent_init)
{
	int ret, i;

	/* Create the 5 dedicated intent DSQs */
	bpf_for(i, 0, INTENT_COUNT) {
		ret = scx_bpf_create_dsq((u64)i, -1);
		if (ret < 0) {
			scx_bpf_error("failed to create intent DSQ %d: %d", i, ret);
			return ret;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(intent_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(intent_ops,
	       .select_cpu	= (void *)intent_select_cpu,
	       .enqueue		= (void *)intent_enqueue,
	       .dispatch	= (void *)intent_dispatch,
	       .init		= (void *)intent_init,
	       .exit		= (void *)intent_exit,
	       .timeout_ms	= 10000,
	       .name		= "intent");
