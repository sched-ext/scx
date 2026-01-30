// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

SEC("fentry/bpf_map_update_elem")
int BPF_PROG(trace_map_update, struct bpf_map *map, void *key, void *value, u64 flags)
{
    struct hints_event *ev;

    if (map->map_type != BPF_MAP_TYPE_TASK_STORAGE)
        return 0;

    ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    ev->pid = task->pid;
    ev->tgid = task->tgid;
    ev->hints = *(unsigned long long *)value;
    ev->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
