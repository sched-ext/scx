// SPDX-License-Identifier: GPL-2.0
/*
 * Idle kick for the enqueue pass.
 *
 * Holds the one idle allowed kick for shared and overflow parks with
 * no preempt. Each park sends one idle kick at most with no storm, so
 * the cost stays bounded by parks and only an idle CPU wakes. Outlined
 * to keep enqueue small with no duplicate walk. Runs under the caller
 * with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Kick one idle allowed CPU for shared or overflow parks with one kick at most, */
/* so the cost stays bounded by parks with no storm. */
/* Tries the selected CPU first, then the kernel idle pick, then */
/* the first allowed live CPU. Kicks only when the target runs */
/* nothing, with the idle flag cleared first so the kick sticks. */
/* Never sends a preempt kick, so shared parks stay idle only. A kick */
/* miss stays fail closed with mask wins on drain and the next pass */
/* still meets the park with no wait. */
static __noinline void flow_kick_idle_allowed(
	const struct task_struct *p, s32 sel)
{
	s32 idle;
	s32 first;
	struct flow_cpu_state *st;
	if (flow_cpu_ok(p, sel)) {
		st = flow_cpu((u32)sel);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(sel);
			scx_bpf_kick_cpu(sel, SCX_KICK_IDLE);
			__sync_fetch_and_add(
			    &flow_stats.kicks, 1);
			return;
		}
	}
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0 && flow_cpu_ok(p, idle)) {
		st = flow_cpu((u32)idle);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(
			    (s32)idle);
			scx_bpf_kick_cpu((s32)idle,
			    SCX_KICK_IDLE);
			__sync_fetch_and_add(
			    &flow_stats.kicks, 1);
			return;
		}
	}
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (first >= 0 && flow_cpu_ok(p, first)) {
		st = flow_cpu((u32)first);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(first);
			scx_bpf_kick_cpu(first, SCX_KICK_IDLE);
			__sync_fetch_and_add(
			    &flow_stats.kicks, 1);
		}
	}
}
