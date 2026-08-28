/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * Decode helper for the serialized cpu bitmaps userspace places in cell_config.
 * The masks themselves live in the arena as cid-space cmasks, see
 * apply_cell_cmasks() and struct cell_cmasks.
 */

#pragma once

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"

/* Return whether @cpu is set in serialized cell_cpumask_data. */
static inline int cell_cpumask_data_test_cpu(const struct cell_cpumask_data *data, u32 cpu,
					     bool *setp)
{
	u32 byte_idx = cpu / 8;
	u32 bit_idx = cpu % 8;
	const unsigned char *bytep;

	bytep = MEMBER_VPTR(data->mask, [byte_idx]);
	if (!bytep)
		return -EINVAL;

	*setp = *bytep & (1 << bit_idx);
	return 0;
}
