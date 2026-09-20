/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

/*
 * Return the offset from the destination reference used to place @p: the lag
 * carried out of its old pack, with a minimum of the configured virtual-time
 * credit.
 *
 * The credit is a fixed placement scale rather than a computed minimum needed
 * to cross the current deadline frontier. It is scaled by the task's deadline
 * weight.
 */
static s64 task_place_offset(const struct task_struct *p, task_ctx_t *tctx)
{
	s64 credit;

	if (!latency_credit)
		return tctx->se.vlag;

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	return MAX(tctx->se.vlag, credit);
}
