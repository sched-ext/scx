/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once

#ifdef __BPF__

#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>

void __arena *scx_task_data(struct task_struct *p);
int scx_task_init(__u64 data_size);
void __arena *scx_task_alloc(struct task_struct *p);
void scx_task_free(struct task_struct *p);
void scx_arena_subprog_init(void);


#endif /* __BPF__ */
