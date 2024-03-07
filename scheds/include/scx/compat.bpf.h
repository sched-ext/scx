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
 * %SCX_KICK_IDLE is a later addition. To support both before and after, use
 * %__COMPAT_SCX_KICK_IDLE which becomes 0 on kernels which don't support it.
 */
#define __COMPAT_SCX_KICK_IDLE							\
	__COMPAT_ENUM_OR_ZERO(enum scx_kick_flags, SCX_KICK_IDLE)

/*
 * scx_switch_all() was replaced by %SCX_OPS_SWITCH_PARTIAL. See
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL in compat.h.
 */
void scx_bpf_switch_all(void) __ksym __weak;

static inline void __COMPAT_scx_bpf_switch_all(void)
{
	if (!bpf_core_enum_value_exists(enum scx_ops_flags, SCX_OPS_SWITCH_PARTIAL))
		scx_bpf_switch_all();
}

#endif

/*
 * sched_ext_ops.exit_dump_len is a recent addition. Use the following
 * definition to support older kernels. See scx_qmap for usage example.
 */
struct sched_ext_ops___no_exit_dump_len {
	s32 (*select_cpu)(struct task_struct *, s32, u64);
	void (*enqueue)(struct task_struct *, u64);
	void (*dequeue)(struct task_struct *, u64);
	void (*dispatch)(s32, struct task_struct *);
	void (*runnable)(struct task_struct *, u64);
	void (*running)(struct task_struct *);
	void (*stopping)(struct task_struct *, bool);
	void (*quiescent)(struct task_struct *, u64);
	bool (*yield)(struct task_struct *, struct task_struct *);
	bool (*core_sched_before)(struct task_struct *, struct task_struct *);
	void (*set_weight)(struct task_struct *, u32);
	void (*set_cpumask)(struct task_struct *, const struct cpumask *);
	void (*update_idle)(s32, bool);
	void (*cpu_acquire)(s32, struct scx_cpu_acquire_args *);
	void (*cpu_release)(s32, struct scx_cpu_release_args *);
	s32 (*init_task)(struct task_struct *, struct scx_init_task_args *);
	void (*exit_task)(struct task_struct *, struct scx_exit_task_args *);
	void (*enable)(struct task_struct *);
	void (*disable)(struct task_struct *);
	s32 (*cgroup_init)(struct cgroup *, struct scx_cgroup_init_args *);
	void (*cgroup_exit)(struct cgroup *);
	s32 (*cgroup_prep_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_cancel_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_set_weight)(struct cgroup *, u32);
	void (*cpu_online)(s32);
	void (*cpu_offline)(s32);
	s32 (*init)();
	void (*exit)(struct scx_exit_info *);
	u32 dispatch_max_batch;
	u64 flags;
	u32 timeout_ms;
	char name[128];
};

/* define sched_ext_ops, see compat.h::SCX_OPS_LOAD/ATTACH() */
#define SCX_OPS_DEFINE(__name, ...)						\
	SEC(".struct_ops.link")							\
	struct sched_ext_ops __name = {						\
		__VA_ARGS__,							\
	};									\
	SEC(".struct_ops.link")							\
	struct sched_ext_ops___no_exit_dump_len __name##___no_exit_dump_len = {	\
		__VA_ARGS__							\
	};									\
