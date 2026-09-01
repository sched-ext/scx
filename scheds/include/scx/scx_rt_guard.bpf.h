// SPDX-License-Identifier: GPL-2.0
/*
 * scx_rt_guard.bpf.h — reusable sched_switch RT preemption interceptor.
 * Layer 3 of RT monopolization fix (sched-ext/scx#1202).
 *
 * Include from BPF schedulers after scx/common.bpf.h.
 * Requires kernel >= 6.19 (scx_bpf_reenqueue_local from any context).
 */
#ifndef __SCX_RT_GUARD_BPF_H
#define __SCX_RT_GUARD_BPF_H

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>

#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR 2
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

/*
 * Call from a sched_switch tracepoint program when @next takes the CPU
 * with a higher-priority scheduling class than SCHED_EXT.
 */
static __always_inline void scx_rt_guard_on_sched_switch(struct task_struct *next)
{
	if (!__COMPAT_scx_bpf_reenqueue_local_from_anywhere())
		return;

	switch (next->policy) {
	case SCHED_FIFO:
	case SCHED_RR:
	case SCHED_DEADLINE:
		scx_bpf_reenqueue_local();
		break;
	default:
		break;
	}
}

#define SCX_RT_GUARD_SCHED_SWITCH_PROG(name)                                   \
	SEC("tp_btf/sched_switch")                                               \
	int BPF_PROG(name, bool preempt, struct task_struct *prev,               \
		     struct task_struct *next)                                   \
	{                                                                      \
		scx_rt_guard_on_sched_switch(next);                                \
		return 0;                                                      \
	}

#endif /* __SCX_RT_GUARD_BPF_H */
