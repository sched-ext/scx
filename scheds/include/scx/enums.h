/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Define struct scx_enums that stores the load-time values of enums
 * used by the BPF program.
 *
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 */

#ifndef __SCX_ENUMS_H
#define __SCX_ENUMS_H

#define SCX_ENUM(name) __##name

#ifndef __bpf__

static inline void __ENUM_set(u64 *val, char *type, char *name)
{
	bool res;

	res = __COMPAT_read_enum(type, name, val);
	SCX_BUG_ON(!res, "enum not found(%s)", name);
}

#define SCX_ENUM_SET(skel, type, name) do {				\
	__ENUM_set(&skel->rodata->SCX_ENUM(name), #type, #name);	\
	} while (0)

#define SCX_ENUM_INIT(skel)						\
	SCX_ENUM_SET(skel, scx_public_consts, SCX_OPS_NAME_LEN);	\
	SCX_ENUM_SET(skel, scx_public_consts, SCX_SLICE_DFL);		\
	SCX_ENUM_SET(skel, scx_public_consts, SCX_SLICE_INF);		\
									\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_FLAG_BUILTIN);	\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_FLAG_LOCAL_ON);	\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_INVALID);		\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_GLOBAL);		\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_LOCAL);		\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_LOCAL_ON);		\
	SCX_ENUM_SET(skel, scx_dsq_id_flags, SCX_DSQ_LOCAL_CPU_MASK);	\
									\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_QUEUED);		\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_RESET_RUNNABLE_AT);	\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_DEQD_FOR_SLEEP);	\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_STATE_SHIFT);	\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_STATE_BITS);		\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_STATE_MASK);		\
	SCX_ENUM_SET(skel, scx_ent_flags, SCX_TASK_CURSOR);		\
									\
	SCX_ENUM_SET(skel, scx_task_state, SCX_TASK_NONE);		\
	SCX_ENUM_SET(skel, scx_task_state, SCX_TASK_INIT);		\
	SCX_ENUM_SET(skel, scx_task_state, SCX_TASK_READY);		\
	SCX_ENUM_SET(skel, scx_task_state, SCX_TASK_ENABLED);		\
	SCX_ENUM_SET(skel, scx_task_state, SCX_TASK_NR_STATES);		\
									\
	SCX_ENUM_SET(skel, scx_ent_dsq_flags, SCX_TASK_DSQ_ON_PRIQ);	\
									\
	SCX_ENUM_SET(skel, scx_kick_flags, SCX_KICK_IDLE);		\
	SCX_ENUM_SET(skel, scx_kick_flags, SCX_KICK_PREEMPT);		\
	SCX_ENUM_SET(skel, scx_kick_flags, SCX_KICK_WAIT);		\
									\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_WAKEUP);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_HEAD);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_PREEMPT);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_REENQ);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_LAST);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_CLEAR_OPSS);		\
	SCX_ENUM_SET(skel, scx_enq_flags, SCX_ENQ_DSQ_PRIQ);

#endif /* !__bpf__ */

#endif /* __SCX_ENUMS_H */
