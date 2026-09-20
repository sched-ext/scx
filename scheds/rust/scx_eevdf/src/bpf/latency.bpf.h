/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees.
 */
#pragma once

#include "eevdf.bpf.h"

static s64 task_place_offset(const struct task_struct *p, task_ctx_t *tctx);
