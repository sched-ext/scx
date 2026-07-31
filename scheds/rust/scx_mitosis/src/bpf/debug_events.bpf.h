/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#pragma once

#define DEBUG_EVENTS_BUF_SIZE 4096

enum debug_event_type {
	DEBUG_EVENT_CGROUP_INIT,
	DEBUG_EVENT_INIT_TASK,
	DEBUG_EVENT_CGROUP_EXIT,
};

struct debug_event {
	u64 timestamp;
	u32 event_type;
	union {
		struct {
			u64 cgid;
		} cgroup_init;
		struct {
			u64 cgid;
			u32 pid;
		} init_task;
		struct {
			u64 cgid;
		} cgroup_exit;
	};
};

const volatile bool debug_events_enabled = false;

u32 debug_event_pos;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DEBUG_EVENTS_BUF_SIZE);
	__type(key, u32);
	__type(value, struct debug_event);
} debug_events SEC(".maps");

static inline void record_cgroup_init(u64 cgid)
{
	struct debug_event *event;
	u32 pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos = __sync_fetch_and_add(&debug_event_pos, 1);
	idx = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp = scx_bpf_now();
	event->event_type = DEBUG_EVENT_CGROUP_INIT;
	event->cgroup_init.cgid = cgid;
}

static inline void record_init_task(u64 cgid, u32 pid)
{
	struct debug_event *event;
	u32 pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos = __sync_fetch_and_add(&debug_event_pos, 1);
	idx = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp = scx_bpf_now();
	event->event_type = DEBUG_EVENT_INIT_TASK;
	event->init_task.cgid = cgid;
	event->init_task.pid = pid;
}

static inline void record_cgroup_exit(u64 cgid)
{
	struct debug_event *event;
	u32 pos, idx;

	if (likely(!debug_events_enabled))
		return;

	pos = __sync_fetch_and_add(&debug_event_pos, 1);
	idx = pos % DEBUG_EVENTS_BUF_SIZE;

	event = bpf_map_lookup_elem(&debug_events, &idx);
	if (unlikely(!event))
		return;

	event->timestamp = scx_bpf_now();
	event->event_type = DEBUG_EVENT_CGROUP_EXIT;
	event->cgroup_exit.cgid = cgid;
}

static void dump_debug_events(void)
{
	struct debug_event *event;
	u32 total_events, start_idx, i;
	u32 event_num, idx;

	if (!debug_events_enabled)
		return;

	scx_bpf_dump("\n");
	scx_bpf_dump("DEBUG EVENTS (last %d):\n", DEBUG_EVENTS_BUF_SIZE);

	total_events = READ_ONCE(debug_event_pos);
	start_idx = total_events > DEBUG_EVENTS_BUF_SIZE ? total_events - DEBUG_EVENTS_BUF_SIZE : 0;

	bpf_for(i, 0, DEBUG_EVENTS_BUF_SIZE)
	{
		event_num = start_idx + i;
		if (event_num >= total_events)
			break;

		idx = event_num % DEBUG_EVENTS_BUF_SIZE;
		event = bpf_map_lookup_elem(&debug_events, &idx);
		if (!event)
			continue;

		switch (event->event_type) {
		case DEBUG_EVENT_CGROUP_INIT:
			scx_bpf_dump("[%3d] CGROUP_INIT cgid=%llu ts=%llu\n", event_num,
				     event->cgroup_init.cgid, event->timestamp);
			break;
		case DEBUG_EVENT_INIT_TASK:
			scx_bpf_dump("[%3d] INIT_TASK   cgid=%llu pid=%u ts=%llu\n", event_num,
				     event->init_task.cgid, event->init_task.pid, event->timestamp);
			break;
		case DEBUG_EVENT_CGROUP_EXIT:
			scx_bpf_dump("[%3d] CGROUP_EXIT cgid=%llu ts=%llu\n", event_num,
				     event->cgroup_exit.cgid, event->timestamp);
			break;
		default:
			scx_bpf_dump("[%3d] UNKNOWN     type=%u ts=%llu\n", event_num,
				     event->event_type, event->timestamp);
			break;
		}
	}
}
