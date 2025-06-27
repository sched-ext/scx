/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifndef __LAYERED_TIMER_H
#define __LAYERED_TIMER_H

#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum timer_consts {
	// kernel definitions
	CLOCK_BOOTTIME		= 7,
};

struct layered_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

enum layer_timer_callbacks {
	ANTISTALL_TIMER,
	MAX_TIMERS,
};

u64 run_timer_cb(int key);
int start_layered_timers(void);

extern struct layered_timer layered_timers[MAX_TIMERS];

#endif /* __LAYERED_TIMER_H */
