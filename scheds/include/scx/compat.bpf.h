/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_BPF_H
#define __SCX_COMPAT_BPF_H

#define __COMPAT_ENUM_OR_ZERO(__type, __ent)					\
({										\
	__type __ret = 0;							\
	if (bpf_core_enum_value_exists(__type, __ent))				\
		__ret = __ent;							\
	__ret;									\
})

/*
 * scx_bpf_dump() is a new addition. Ignore if unavailable. Users can use
 * scx_bpf_dump() directly in the future.
 */
#define __COMPAT_scx_bpf_dump(fmt, args...)					\
({										\
	if (bpf_ksym_exists(scx_bpf_dump_bstr))					\
		scx_bpf_dump(fmt, ##args);					\
})

/*
 * scx_bpf_nr_cpu_ids(), scx_bpf_get_possible/online_cpumask() are new. No good
 * way to noop these kfuncs. Provide a test macro. Users can assume existence in
 * the future.
 */
#define __COMPAT_HAS_CPUMASKS							\
	bpf_ksym_exists(scx_bpf_nr_cpu_ids)

/*
 * cpuperf is new. The followings become noop on older kernels. Callers can be
 * updated to call cpuperf kfuncs directly in the future.
 */
static inline u32 __COMPAT_scx_bpf_cpuperf_cap(s32 cpu)
{
	if (bpf_ksym_exists(scx_bpf_cpuperf_cap))
		return scx_bpf_cpuperf_cap(cpu);
	else
		return 1024;
}

static inline u32 __COMPAT_scx_bpf_cpuperf_cur(s32 cpu)
{
	if (bpf_ksym_exists(scx_bpf_cpuperf_cur))
		return scx_bpf_cpuperf_cur(cpu);
	else
		return 1024;
}

static inline void __COMPAT_scx_bpf_cpuperf_set(s32 cpu, u32 perf)
{
	if (bpf_ksym_exists(scx_bpf_cpuperf_set))
		return scx_bpf_cpuperf_set(cpu, perf);
}

/*
 * Iteration and scx_bpf_consume_task() are new. The following become noop on
 * older kernels. The users can switch to bpf_for_each(scx_dsq) and directly
 * call scx_bpf_consume_task() in the future.
 */
#define __COMPAT_DSQ_FOR_EACH(p, dsq_id, flags)					\
	if (bpf_ksym_exists(bpf_iter_scx_dsq_new))				\
		bpf_for_each(scx_dsq, (p), (dsq_id), (flags))

static inline bool __COMPAT_scx_bpf_consume_task(struct bpf_iter_scx_dsq *it,
						 struct task_struct *p)
{
	return false;
}

/*
 * Define sched_ext_ops. This may be expanded to define multiple variants for
 * backward compatibility. See compat.h::SCX_OPS_LOAD/ATTACH().
 */
#define SCX_OPS_DEFINE(__name, ...)						\
	SEC(".struct_ops.link")							\
	struct sched_ext_ops __name = {						\
		__VA_ARGS__,							\
	};

#endif	/* __SCX_COMPAT_BPF_H */
