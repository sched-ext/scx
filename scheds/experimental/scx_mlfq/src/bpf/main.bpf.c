// SPDX-License-Identifier: GPL-2.0
/*
 * scx_mlfq: a multilevel feedback queue scheduler for gaming and desktop use.
 *
 * Tasks drop through feedback levels while they run without sleeping and
 * are scored by how much they behave like part of an interactive pipeline.
 * They wait in per-LLC queues ordered by a virtual deadline derived from
 * both. Pinned tasks wait in per-CPU queues. Wakeups that find an idle CPU
 * are dispatched to it directly.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <bpf_experimental.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "stats.bpf.h"
#include "select.bpf.h"
#include "enqueue.bpf.h"
#include "dispatch.bpf.h"

SCX_OPS_DEFINE(mlfq_ops,
	       .select_cpu		= (void *)mlfq_select_cpu,
	       .enqueue			= (void *)mlfq_enqueue,
	       .dispatch		= (void *)mlfq_dispatch,
	       .runnable		= (void *)mlfq_runnable,
	       .running			= (void *)mlfq_running,
	       .tick			= (void *)mlfq_tick,
	       .stopping		= (void *)mlfq_stopping,
	       .quiescent		= (void *)mlfq_quiescent,
	       .init_task		= (void *)mlfq_init_task,
	       .init			= (void *)mlfq_init,
	       .exit			= (void *)mlfq_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED,
	       .timeout_ms		= MLFQ_OPS_TIMEOUT_MS,
	       .name			= "mlfq");
