/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_BPF_H
#define __SCX_COMPAT_BPF_H

static inline void __COMPAT_scx_bpf_kick_cpu_IDLE(s32 cpu)
{
	if (bpf_core_enum_value_exists(enum scx_kick_flags, SCX_KICK_IDLE))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	else
		scx_bpf_kick_cpu(cpu, 0);
}

#endif
