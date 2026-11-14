// SPDX-License-Identifier: GPL-2.0
/*
 * scx_flow: a latency criticality scheduler for gaming and desktop use.
 *
 * Tasks are scored by how much they behave like part of an interactive
 * pipeline and wait in per-LLC queues ordered by a virtual deadline derived
 * from that score. Pinned tasks wait in per-CPU queues. Wakeups that find
 * an idle CPU are dispatched to it directly.
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

SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dispatch		= (void *)flow_dispatch,
	       .runnable		= (void *)flow_runnable,
	       .running			= (void *)flow_running,
	       .tick			= (void *)flow_tick,
	       .stopping		= (void *)flow_stopping,
	       .quiescent		= (void *)flow_quiescent,
	       .init_task		= (void *)flow_init_task,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED,
	       .timeout_ms		= FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
