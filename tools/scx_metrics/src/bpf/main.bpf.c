#ifdef LSP
#define LSP_INC
#include "../../../scheds/include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif
#include "intf.h"

char		   _license[] SEC("license") = "GPL";
const volatile u32 nr_cpu_ids		     = 1;

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

struct queued_affinity {
	cpumask_t allowed;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);
	__type(value, struct queued_affinity);
} queued_affinities SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct queued_affinity);
} affinity_scratch SEC(".maps");

#define CPU_WORD_BITS (sizeof(unsigned long) * 8)
#define CPU_WORDS (sizeof(claimed_cpus.bits) / sizeof(claimed_cpus.bits[0]))

static cpumask_t	    claimed_cpus;

static __always_inline bool cpu_is_claimed(u32 cpu)
{
	if (cpu >= CPU_WORDS * CPU_WORD_BITS)
		return true;
	return claimed_cpus.bits[cpu / CPU_WORD_BITS] &
	       (1UL << (cpu % CPU_WORD_BITS));
}

static __always_inline void claim_cpu(u32 cpu)
{
	if (cpu < CPU_WORDS * CPU_WORD_BITS)
		claimed_cpus.bits[cpu / CPU_WORD_BITS] |=
			1UL << (cpu % CPU_WORD_BITS);
}

static __always_inline void release_cpu(u32 cpu)
{
	if (cpu < CPU_WORDS * CPU_WORD_BITS)
		claimed_cpus.bits[cpu / CPU_WORD_BITS] &=
			~(1UL << (cpu % CPU_WORD_BITS));
}

struct queued_task_state {
	bool queued;
	bool constrained;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct queued_task_state);
} queued_task_states SEC(".maps");

static u32	     queued_unrestricted;

struct assign_ctx {
	u32 assigned;
	u32 capacity;
	u32 unrestricted;
};

static long assign_constrained_task(struct bpf_map *map, const u32 *pid,
				    struct queued_affinity *task,
				    struct assign_ctx	   *ctx)
{
	u32 cpu;

	if (ctx->unrestricted >= ctx->capacity - ctx->assigned)
		return 1;
	bpf_for(cpu, 0, nr_cpu_ids)
	{
		if (!bpf_cpumask_test_cpu(cpu, &task->allowed) ||
		    cpu_is_claimed(cpu))
			continue;
		claim_cpu(cpu);
		ctx->assigned++;
		break;
	}
	return 0;
}

static __always_inline bool task_is_constrained(struct task_struct *p)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	bool constrained	     = !bpf_cpumask_subset(online, p->cpus_ptr);

	scx_bpf_put_cpumask(online);
	return constrained;
}

static __always_inline void store_task_affinity(struct task_struct *p, u32 pid)
{
	struct queued_affinity *entry;
	u32			zero = 0;

	entry = bpf_map_lookup_elem(&affinity_scratch, &zero);
	if (!entry)
		return;
	bpf_probe_read_kernel(&entry->allowed, sizeof(entry->allowed),
			      p->cpus_ptr);
	bpf_map_update_elem(&queued_affinities, &pid, entry, BPF_ANY);
}

static __always_inline void remove_queued_task(struct queued_task_state *state,
					       u32			 pid)
{
	if (!state || !state->queued)
		return;
	if (state->constrained)
		bpf_map_delete_elem(&queued_affinities, &pid);
	else
		__sync_fetch_and_sub(&queued_unrestricted, 1);
	state->queued = false;
}

static void queue_task(struct task_struct *p)
{
	struct queued_task_state *state;
	bool			  constrained;
	u32			  pid;

	if (!p || !(pid = BPF_CORE_READ(p, pid)))
		return;
	state = bpf_task_storage_get(&queued_task_states, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!state)
		return;
	constrained = task_is_constrained(p);
	if (state->queued && state->constrained == constrained) {
		if (constrained)
			store_task_affinity(p, pid);
		return;
	}
	remove_queued_task(state, pid);
	state->queued	   = true;
	state->constrained = constrained;
	if (constrained)
		store_task_affinity(p, pid);
	else
		__sync_fetch_and_add(&queued_unrestricted, 1);
}

static void dequeue_task(struct task_struct *p)
{
	struct queued_task_state *state;
	u32			  pid;

	if (!p || !(pid = BPF_CORE_READ(p, pid)))
		return;
	state = bpf_task_storage_get(&queued_task_states, p, 0, 0);
	remove_queued_task(state, pid);
}

static int collect_sample(struct cpu_snapshot *out)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	struct assign_ctx     assign = {};
	u32		      cpu;

	out->online_cpus = bpf_cpumask_weight(online);
	out->busy_cpus	 = 0;
	bpf_for(cpu, 0, nr_cpu_ids)
	{
		struct rq *rq;

		claim_cpu(cpu);
		if (!bpf_cpumask_test_cpu(cpu, online))
			continue;
		rq = bpf_per_cpu_ptr(&runqueues, cpu);
		if (!rq)
			continue;
		if (BPF_CORE_READ(rq, curr, pid) != 0)
			out->busy_cpus++;
		else
			release_cpu(cpu);
	}

	assign.capacity	    = out->online_cpus - out->busy_cpus;
	assign.unrestricted = __sync_fetch_and_add(&queued_unrestricted, 0);
	bpf_for_each_map_elem(&queued_affinities, assign_constrained_task,
			      &assign, 0);

	out->runnable_tasks = out->busy_cpus + assign.assigned;
	if (out->runnable_tasks < out->online_cpus) {
		u32 remaining = out->online_cpus - out->runnable_tasks;

		out->runnable_tasks += assign.unrestricted < remaining ?
					       assign.unrestricted :
					       remaining;
	}

	scx_bpf_put_cpumask(online);
	return 0;
}

static __always_inline int on_wakeup(struct task_struct *p)
{
	queue_task(p);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(metrics_sched_wakeup, struct task_struct *p)
{
	return on_wakeup(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(metrics_sched_wakeup_new, struct task_struct *p)
{
	return on_wakeup(p);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(metrics_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	dequeue_task(next);
	if (preempt || prev_state == 0)
		queue_task(prev);
	else
		dequeue_task(prev);
	return 0;
}

SEC("tp_btf/sched_process_free")
int BPF_PROG(metrics_process_free, struct task_struct *p)
{
	dequeue_task(p);
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
	u32		      key = 0;
	int		      ret;

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
