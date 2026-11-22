// SPDX-License-Identifier: GPL-2.0
/*
 * Wakeup placement for the flow scheduler.
 *
 * The kernel's idle CPU picker already walks the topology in the order
 * flow wants: the previous CPU if its core is fully idle, a fully idle
 * core in the same LLC, then in the same node, then anywhere, and only
 * then partially idle cores. Flow adds two steps in front of it.
 *
 * On a CPU whose LLCs differ in size, a latency critical task that last
 * ran outside of the largest LLC first tries a fully idle core in it, so
 * that the tasks that matter most for responsiveness keep their working
 * set in the biggest cache. Then, when the LLCs are split into smaller
 * core groups, a fully idle core in the group of the previous CPU is
 * tried.
 *
 * A wakeup that wins an idle CPU goes straight to its local DSQ, and the
 * kernel then skips ops.enqueue() for that wakeup.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SELECT_BPF_H
#define __FLOW_SELECT_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

static __always_inline void flow_tag_wakeup(struct flow_task_ctx *t, u64 wake_flags)
{
	u32 flags = t->flags & ~(FLOW_FLAG_SYNC_WAKEUP | FLOW_FLAG_HARDIRQ_WAKEUP |
				 FLOW_FLAG_SOFTIRQ_WAKEUP);

	if (wake_flags & SCX_WAKE_SYNC)
		flags |= FLOW_FLAG_SYNC_WAKEUP;
	if (bpf_in_hardirq() || bpf_in_nmi())
		flags |= FLOW_FLAG_HARDIRQ_WAKEUP;
	else if (bpf_in_serving_softirq())
		flags |= FLOW_FLAG_SOFTIRQ_WAKEUP;
	t->flags = flags;
}

static bool flow_wants_big_cache(const struct flow_task_ctx *t, s32 prev_cpu)
{
	return flow_has_big_cache &&
	       t->lat_cri >= READ_ONCE(flow_sys_stat.avg_lat_cri) &&
	       !bpf_cpumask_test_cpu(prev_cpu, cast_mask(&flow_big_cache_cpumask));
}

/* Claim an idle CPU for @p, or return a negative value if there is none. */
static s32 flow_pick_idle_cpu(struct task_struct *p, const struct flow_task_ctx *t,
			      s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (flow_wants_big_cache(t, prev_cpu)) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
					     cast_mask(&flow_big_cache_cpumask),
					     SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
	}
	if (flow_nr_groups > flow_nr_llcs && flow_cpu_valid(prev_cpu)) {
		struct bpf_cpumask *group;

		group = MEMBER_VPTR(flow_group_cpumask, [flow_cpu_group[prev_cpu]]);
		if (group) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
						     cast_mask(group), SCX_PICK_IDLE_CORE);
			if (cpu >= 0)
				return cpu;
		}
	}
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu;

	if (!t)
		return prev_cpu;

	flow_tag_wakeup(t, wake_flags);
	cpu = flow_pick_idle_cpu(p, t, prev_cpu, wake_flags);
	if (cpu < 0)
		return prev_cpu;

	/* The task starts a new activation, so it has not run yet. */
	t->acc_runtime_ns = 0;
	scx_bpf_task_set_dsq_vtime(p, flow_score_task(p, t));
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, flow_calc_slice(t, cpu), 0);
	flow_stat_inc(FLOW_STAT_DIRECT);
	return cpu;
}

#endif /* __FLOW_SELECT_BPF_H */
