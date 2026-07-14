#ifdef LSP
#define LSP_INC
#include "../../../scheds/include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif
#include "intf.h"

char _license[] SEC("license") = "GPL";
const volatile u32 nr_cpu_ids = 1;

#define SAMPLE_INTERVAL_NS (10ULL * 1000 * 1000)
/* A 12-byte sample consumes 24 bytes including ring-buffer framing/alignment.
 * 8 KiB is the smallest valid power-of-two capacity that holds >= 200 samples. */
#define SAMPLE_RING_BYTES 8192

struct timer_wrapper {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct timer_wrapper);
} sample_timer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, SAMPLE_RING_BYTES);
} samples SEC(".maps");

static int collect_sample(struct cpu_snapshot *out)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	const struct cpumask *idle = scx_bpf_get_idle_cpumask();
	u32 cpu;

	out->online_cpus = bpf_cpumask_weight(online);
	out->busy_cpus = out->online_cpus - bpf_cpumask_weight(idle);
	out->runnable_tasks = 0;
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct rq *rq;

		if (!bpf_cpumask_test_cpu(cpu, online))
			continue;
		rq = bpf_per_cpu_ptr(&runqueues, cpu);
		if (rq)
			out->runnable_tasks += BPF_CORE_READ(rq, nr_running);
	}

	scx_bpf_put_cpumask(online);
	scx_bpf_put_idle_cpumask(idle);
	return 0;
}

static int sample_timer_cb(void *map, int *key, struct timer_wrapper *timerw)
{
	struct cpu_snapshot sample = {};

	collect_sample(&sample);
	bpf_ringbuf_output(&samples, &sample, sizeof(sample), 0);
	bpf_timer_start(&timerw->timer, SAMPLE_INTERVAL_NS, 0);
	return 0;
}

SEC("syscall")
int start_sampling(void *ctx)
{
	struct timer_wrapper *timerw;
	u32 key = 0;
	int ret;

	timerw = bpf_map_lookup_elem(&sample_timer, &key);
	if (!timerw)
		return -ENOENT;
	ret = bpf_timer_init(&timerw->timer, &sample_timer, CLOCK_MONOTONIC);
	if (ret)
		return ret;
	ret = bpf_timer_set_callback(&timerw->timer, sample_timer_cb);
	if (ret)
		return ret;
	return bpf_timer_start(&timerw->timer, SAMPLE_INTERVAL_NS, 0);
}
