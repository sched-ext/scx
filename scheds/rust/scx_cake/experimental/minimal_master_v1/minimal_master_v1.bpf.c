/* SPDX-License-Identifier: GPL-2.0 */
/* Source-only minimal master-law candidate. See README.md. */
#include <scx/common.bpf.h>
#include "../../src/bpf/intf.h"

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

enum {
	MASTER_CACHELINE_SIZE = 64,
	MASTER_DSQ = MAX_CPUS + 2,
};

const volatile u64 slice_ns = 1000ULL * NSEC_PER_USEC;
static u64 vtime_now __attribute__((aligned(MASTER_CACHELINE_SIZE)));

struct run_stamp {
	u64 ns;
} __attribute__((aligned(MASTER_CACHELINE_SIZE)));
static struct run_stamp run_start[MAX_CPUS];

/* (1024 << 20) / sched_prio_to_weight[nice + 20]. */
static const u64 recip_weight[64] = {
	12097, 14964, 19009, 23204, 29587, 36830, 46174, 57404,
	71827, 90109, 112457, 140911, 176023, 218952, 274895, 344037,
	429324, 539297, 677012, 840831, 1048576, 1309441, 1639300, 2041334,
	2538396, 3205199, 3947580, 4994148, 6242685, 7837531, 9761289, 12341860,
	15339168, 19173961, 23860929, 29826161, 37025580, 46684427, 59652323, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
};

static __always_inline u64 later_vtime(u64 a, u64 b)
{
	return time_before(a, b) ? b : a;
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
	if (idle)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
	return cpu;
}

void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 key = later_vtime(p->scx.dsq_vtime, vtime_now - slice_ns);
	s32 cpu;
	scx_bpf_dsq_insert_vtime(p, MASTER_DSQ, slice_ns, key, enq_flags);
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!scx_bpf_dsq_move_to_local(MASTER_DSQ, 0) && prev &&
	    (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = slice_ns;
}

void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
	run_start[cpu].ns = bpf_ktime_get_ns();
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
	u32 idx = (u32)(p->static_prio - 100) & 63;
	u64 used = bpf_ktime_get_ns() - run_start[cpu].ns;
	p->scx.dsq_vtime += (used * recip_weight[idx]) >> 20;
}

void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	return scx_bpf_create_dsq(MASTER_DSQ, -1);
}

void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cake_ops,
	.select_cpu = (void *)cake_select_cpu,
	.enqueue = (void *)cake_enqueue,
	.dispatch = (void *)cake_dispatch,
	.running = (void *)cake_running,
	.stopping = (void *)cake_stopping,
	.enable = (void *)cake_enable,
	.init = (void *)cake_init,
	.exit = (void *)cake_exit);
