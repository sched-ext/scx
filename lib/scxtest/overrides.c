#include "scx_test.h"
#include "kern_types.h"

#include <stdbool.h>
#include <stddef.h>

__weak unsigned long CONFIG_NR_CPUS = 1024;

struct cpumask;
struct task_struct;
struct scx_minheap_elem;

__weak
void scx_bpf_error_bstr(char *fmt __attribute__((unused)),
		        long long unsigned int *data __attribute__((unused)),
			u32 data__sz __attribute__((unused)))
{
}

__weak
struct bpf_cpumask *bpf_cpumask_create(void)
{
	return NULL;
}

__weak
void bpf_cpumask_release(struct bpf_cpumask *cpumask __attribute__((unused)))
{
}

__weak
void bpf_task_release(struct task_struct *p __attribute__((unused)))
{
}

__weak
s32 scx_bpf_task_cpu(const struct task_struct *p __attribute__((unused)))
{
	return -1;
}

__weak
struct task_struct *bpf_task_from_pid(s32 pid __attribute__((unused)))
{
	return NULL;
}

__weak
s32 scx_bpf_dsq_nr_queued(u64 dsq_id __attribute__((unused)))
{
	return -1;
}

__weak
void scx_bpf_kick_cpu(s32 cpu __attribute__((unused)),
		      u64 flags __attribute__((unused)))
{
}

__weak
s32 scx_bpf_create_dsq(u64 dsq_id __attribute__((unused)),
		       s32 node __attribute__((unused)))
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
void bpf_cpumask_set_cpu(u32 cpu __attribute__((unused)),
		         struct bpf_cpumask *cpumask __attribute__((unused)))
{
}

__weak
u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask __attribute__((unused)))
{
	return 0;
}

__weak
bool bpf_cpumask_and(struct bpf_cpumask *dst __attribute__((unused)),
		     const struct cpumask *src1 __attribute__((unused)),
		     const struct cpumask *src2 __attribute__((unused)))
{
	return false;
}

__weak
u32 bpf_cpumask_weight(const struct cpumask *cpumask __attribute__((unused)))
{
	return 0;
}

__weak
void scx_bpf_put_cpumask(const struct cpumask *cpumask __attribute__((unused)))
{
}

__weak
void *scx_task_data(struct task_struct *p __attribute__((unused)))
{
	// No arena support in scxtest yet, we can drop this when it's available.
	return NULL;
}

__weak
int scx_minheap_pop(void *heap_ptr __attribute__((unused)),
		    struct scx_minheap_elem *helem __attribute__((unused)))
{
	return 0;
}
