/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include <scx/sdt_task_impl.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct sdt_task_ctx {
	int seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(sdt_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(sdt_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(sdt_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	/*struct sdt_task_data __arena *data;

	data = sdt_task_alloc(p);
	if (!data)
	return -ENOMEM;*/
	return 0;
}

void BPF_STRUCT_OPS_SLEEPABLE(sdt_exit_task, struct task_struct *p,
			      struct scx_exit_task_args *args)
{
	sdt_task_free(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init)
{
	int ret;

	ret = sdt_task_init(sizeof(struct sdt_task_ctx));
	if (ret < 0)
		return ret;
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(sdt_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(sdt_ops,
	       .select_cpu		= (void *)sdt_select_cpu,
	       .enqueue			= (void *)sdt_enqueue,
	       .dispatch		= (void *)sdt_dispatch,
	       .init_task		= (void *)sdt_init_task,
	       .exit_task		= (void *)sdt_exit_task,
	       .init			= (void *)sdt_init,
	       .exit			= (void *)sdt_exit,
	       .name			= "sdt");
