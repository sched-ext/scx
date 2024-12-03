/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 */
#ifndef __SCHED_EXT_NAMESPACE_BPF_H
#define __SCHED_EXT_NAMESPACE_BPF_H

#ifdef LSP
#define __bpf__
#include "../vmlinux.h"
#else
#include "vmlinux.h"
#endif

struct pid_namespace* get_task_pid_ns(const struct task_struct* task, enum pid_type);
struct pid* get_task_pid_ptr(const struct task_struct* task, enum pid_type type);
pid_t get_task_ns_pid(const struct task_struct* task);

pid_t get_pid_nr_ns(struct pid* pid, struct pid_namespace* ns);
pid_t get_ns_pid(void);

#endif /* __SCHED_EXT_NAMESPACE_BPF_H */
