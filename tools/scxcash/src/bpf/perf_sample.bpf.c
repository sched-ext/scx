/* Prototype perf sampling BPF program for scxcash. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 0);
} perf_sample_events SEC(".maps");

SEC("perf_event")
int handle_perf(struct bpf_perf_event_data *ctx)
{
	struct perf_sample_event ev = {};
	struct task_struct *current;

	current = bpf_get_current_task_btf();
	if (!current->pid || !ctx->addr)
		return 0;

	ev.timestamp = bpf_ktime_get_ns();
	ev.pid = current->tgid;
	ev.tid = current->pid;
	ev.cpu = bpf_get_smp_processor_id();
	ev.address = (unsigned long)ctx->addr;
	bpf_perf_event_output(ctx, &perf_sample_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}
