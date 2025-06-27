#include "scx_test.h"
#include "kern_types.h"

#include <stdbool.h>
#include <stddef.h>

__weak unsigned long CONFIG_NR_CPUS = 1024;

struct cpumask;
struct task_struct;

__weak
void scx_bpf_error_bstr(char *fmt, long long unsigned int *data, u32 data__sz)
{
}

__weak
struct bpf_cpumask *bpf_cpumask_create(void)
{
	return NULL;
}

__weak
void bpf_cpumask_release(struct bpf_cpumask *cpumask)
{
}

__weak
void bpf_task_release(struct task_struct *p)
{
}

__weak
s32 scx_bpf_task_cpu(const struct task_struct *p)
{
	return -1;
}

__weak
struct task_struct *bpf_task_from_pid(s32 pid)
{
	return NULL;
}

__weak
s32 scx_bpf_dsq_nr_queued(u64 dsq_id)
{
	return -1;
}

__weak
void scx_bpf_kick_cpu(s32 cpu, u64 flags)
{
}

__weak
s32 scx_bpf_create_dsq(u64 dsq_id, s32 node)
{
	return -1;
}

__weak
void bpf_rcu_read_lock(void)
{
}

__weak
void bpf_rcu_read_unlock(void)
{
}

__weak
void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
}

__weak
u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask)
{
	return 0;
}

__weak
bool bpf_cpumask_and(struct bpf_cpumask *dst, const struct cpumask *src1, const struct cpumask *src2)
{
	return false;
}

__weak
u32 bpf_cpumask_weight(const struct cpumask *cpumask)
{
	return 0;
}

__weak
void scx_bpf_put_cpumask(const struct cpumask *cpumask)
{
}
