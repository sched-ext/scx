/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#pragma once

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <lib/alloc/bpf_helpers_local.h>

void bpf_preempt_disable(void) __weak __ksym;
void bpf_preempt_enable(void) __weak __ksym;
void bpf_local_irq_save(unsigned long *flags__irq_flag) __weak __ksym;
void bpf_local_irq_restore(unsigned long *flags__irq_flag) __weak __ksym;
