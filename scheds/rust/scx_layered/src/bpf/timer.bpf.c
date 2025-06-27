/* Copyright (c) Meta Platforms, Inc. and affiliates. */

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

#include "intf.h"
#include "timer.bpf.h"
#include "util.bpf.h"

struct timer_wrapper {
	struct bpf_timer timer;
	int	key;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} layered_timer_data SEC(".maps");


static int layered_timer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	u64 intvl_ns;

	if (timerw->key < 0 || timerw->key > MAX_TIMERS) {
		return 0;
	}

	struct layered_timer *cb_timer = &layered_timers[timerw->key];
	intvl_ns = run_timer_cb(timerw->key);

	if (intvl_ns == 0 || !cb_timer) {
		trace("TIMER %d stopped %llu", timerw->key, intvl_ns);
		return 0;
	}

	trace("TIMER %d scheduled in %llu", timerw->key, intvl_ns);

	bpf_timer_start(&timerw->timer,
			intvl_ns,
			cb_timer->start_flags);

	return 0;
}

int start_layered_timers(void)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&layered_timer_data, &timer_id);
		if (!timerw) {
			scx_bpf_error("Failed to lookup layered timer");
			return -ENOENT;
		}
		if (timer_id < 0 || timer_id > MAX_TIMERS) {
			scx_bpf_error("Failed to lookup layered timer");
			return -ENOENT;
		}

		struct layered_timer *new_timer = &layered_timers[timer_id];
		if (!new_timer) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
		timerw->key = timer_id;

		err = bpf_timer_init(&timerw->timer,
				     &layered_timer_data,
				     new_timer->init_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_set_callback(&timerw->timer, &layered_timer_cb);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_start(&timerw->timer,
				      new_timer->interval_ns,
				      new_timer->start_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
	}

	return 0;
}
