/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Define struct user_exit_info which is shared between BPF and userspace parts
 * to communicate exit status and other information.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef __USER_EXIT_INFO_H
#define __USER_EXIT_INFO_H

enum uei_sizes {
	UEI_REASON_SIZE	= 128,
	UEI_MSG_SIZE	= 1024,
	UEI_DUMP_SIZE	= 32768,
};

struct user_exit_info {
	int		kind;
	char		reason[UEI_REASON_SIZE];
	char		msg[UEI_MSG_SIZE];
	char		dump[UEI_DUMP_SIZE];
};

#ifdef __bpf__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

static inline void uei_record(struct user_exit_info *uei,
			      const struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(uei->reason, sizeof(uei->reason), ei->reason);
	bpf_probe_read_kernel_str(uei->msg, sizeof(uei->msg), ei->msg);
	bpf_probe_read_kernel_str(uei->dump, sizeof(uei->dump), ei->dump);
	/* use __sync to force memory barrier */
	__sync_val_compare_and_swap(&uei->kind, uei->kind, ei->kind);
}

#else	/* !__bpf__ */

#include <stdio.h>
#include <stdbool.h>

static inline bool uei_exited(struct user_exit_info *uei)
{
	/* use __sync to force memory barrier */
	return __sync_val_compare_and_swap(&uei->kind, -1, -1);
}

static inline void uei_print(const struct user_exit_info *uei)
{
	if (uei->dump[0] != '\0') {
		fputs("\nDEBUG DUMP\n", stderr);
		fputs("================================================================================\n\n", stderr);
		fputs(uei->dump, stderr);
		fputs("\n================================================================================\n\n", stderr);
	}
	fprintf(stderr, "EXIT: %s", uei->reason);
	if (uei->msg[0] != '\0')
		fprintf(stderr, " (%s)", uei->msg);
	fputs("\n", stderr);
}

#endif	/* __bpf__ */
#endif	/* __USER_EXIT_INFO_H */
