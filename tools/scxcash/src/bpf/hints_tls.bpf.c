/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

struct task_hint {
    __u64 hint;
    __u64 __reserved[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_hint);
} scx_layered_task_hint_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} hints_events SEC(".maps");

/* Trace on kfunc map_update path; use fentry to see updates before copy. */
SEC("fentry/bpf_pid_task_storage_update_elem")
int BPF_PROG(handle_map_update, struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct hints_event *e;
	u64 hint_value = 0;

	if (map != (void *)&scx_layered_task_hint_map)
		return 0;
	bpf_probe_read_kernel(&hint_value, sizeof(hint_value), value);

	e = bpf_ringbuf_reserve(&hints_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->timestamp = bpf_ktime_get_ns();
	e->pid = current->tgid;
	e->tid = current->pid;
	e->cpu = bpf_get_smp_processor_id();
	e->hint_value = hint_value;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
