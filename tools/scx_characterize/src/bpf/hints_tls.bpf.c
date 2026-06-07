// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Cannot include vmlinux.h */
enum bpf_map_type {
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
};

struct file;

struct bpf_map {
    enum bpf_map_type map_type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned long long map_extra;
    unsigned int map_flags;
    unsigned int id;
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));
/* Cannot include vmlinux.h */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

struct hints_bss hints_bss SEC(".bss");

SEC("fentry/bpf_map_update_value")
int BPF_PROG(trace_map_update, struct bpf_map *map, struct file *file, void *key, void *value)
{
    struct hints_event *ev;
    unsigned long hints;
    enum bpf_map_type map_type;
    unsigned int map_id;
    struct task_struct *task;

    map_type = BPF_CORE_READ(map, map_type);
    if (map_type != BPF_MAP_TYPE_TASK_STORAGE)
        return 0;

    map_id = BPF_CORE_READ(map, id);
    if (map_id != hints_bss.target_map_id)
        return 0;

    if (bpf_probe_read_kernel(&hints, sizeof(hints), value))
	return 0;

    ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        __sync_fetch_and_add(&hints_bss.dropped_events, 1);
        return 0;
    }

    task = bpf_get_current_task_btf();
    ev->pid = BPF_CORE_READ(task, pid);
    ev->tgid = BPF_CORE_READ(task, tgid);
    ev->hints = hints;
    ev->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
