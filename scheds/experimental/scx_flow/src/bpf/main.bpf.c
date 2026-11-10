// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler entry.
 *
 * Thin glue that pulls in area headers in order and declares
 * the ops table. Each CPU owns one upstream queue in deadline order
 * and there is one fallback
 * queue in FIFO order. Queues hold bounded at 64 total.
 * Ties leave in insertion order. Deadline order sets the queue with
 * preempts for shared tasks with an earlier deadline. Queues come from
 * the upstream deadline library and placement follows the
 * upstream topology library. Tables are written once, so a CPU that
 * arrives late needs a restart to be seen. Settings live in the
 * shared header.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/edq.h>
#include <lib/topology.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"
#include "enqueue.bpf.h"
#include "dispatch.bpf.h"
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .tick			= (void *)flow_tick,
	       .set_cpumask		= (void *)flow_set_cpumask,
	       .enable			= (void *)flow_enable,
	       .init_task		= (void *)flow_init_task,
	       .exit_task		= (void *)flow_exit_task,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
