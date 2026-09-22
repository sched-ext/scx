/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees: pressure admission,
 * placement credit, and asymmetric-capacity packing.
 */
#pragma once

#include "eevdf.bpf.h"

static void update_cid_user(struct task_struct *p, s32 cid,
			    task_ctx_t *tctx, u64 now);
static s64 task_place_offset(s32 cid, pack_t *pk, const struct task_struct *p,
			     task_ctx_t *tctx, u64 now, u64 tnow);
static void credit_charge(pack_t *pk, task_ctx_t *tctx, u64 delta);
static void credit_stats_fold(s32 cid);
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now);
