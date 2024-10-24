/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifdef LSP
#define __bpf__
#ifndef LSP_INC
#include "../../../../include/scx/common.bpf.h"
#include "timer.bpf.h"
#endif
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "timer.bpf.h"


struct timer_wrapper {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} layered_timer_data SEC(".maps");


static int layered_timer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	struct layered_timer *cb_timer = MEMBER_VPTR(layered_timers, [key]);
	bool resched = run_timer_cb(key);

	if (!resched || cb_timer->interval_ns == 0) {
		return 0;
	}

	return bpf_timer_start(&timerw->timer,
			       cb_timer->interval_ns,
			       cb_timer->start_flags);
}

static int start_layered_timers(void)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&layered_timer_data, &timer_id);
		if (!timerw) {
			scx_bpf_error("Failed to lookup layered timer");
			return -ENOENT;
		}

		struct layered_timer *new_timer = MEMBER_VPTR(layered_timers, [timer_id]);
		if (!new_timer) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_init(&timerw->timer,
				     &layered_timer_data, new_timer->init_flags);
		if (err) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_set_callback(&timerw->timer, &layered_timer_cb);
		if (err) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_start(&timerw->timer,
				      new_timer->interval_ns,
				      new_timer->start_flags);
		if (err) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
	}

	return 0;
}
