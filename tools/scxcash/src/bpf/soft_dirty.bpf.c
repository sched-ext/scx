/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

const volatile pid_t filter_tgid = 0;

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); /* 4 MiB default */
} soft_dirty_events SEC(".maps");

SEC("fentry/do_fault")
int BPF_PROG(handle_do_fault, struct vm_fault *vmf)
{
	struct soft_dirty_fault_event *e;
	struct task_struct *current;

	/* TODO(kkd): Add x86-specific SOFT_DIRT bit and minor fault filtering. */

	current = bpf_get_current_task_btf();
	if (filter_tgid && current->tgid != filter_tgid)
		return 0;

	e = bpf_ringbuf_reserve(&soft_dirty_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->timestamp = bpf_ktime_get_ns();
	e->pid = current->tgid;
	e->tid = current->pid;
	e->cpu = bpf_get_smp_processor_id();
	e->address = (unsigned long)vmf->address;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
