#include "scx_test.h"
#include "kern_types.h"

#include <stdbool.h>
#include <stddef.h>

__weak unsigned long CONFIG_NR_CPUS = 1024;

struct task_struct;
struct scx_minheap_elem;

/* Forward declarations for libc functions to avoid header conflicts */
extern void *calloc(unsigned long nmemb, unsigned long size);
extern void free(void *ptr);
extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memset(void *s, int c, unsigned long n);

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#endif

#ifndef NR_CPUS
#define NR_CPUS 128
#endif

/*
 * Local struct definitions matching vmlinux.h layout.
 * overrides.c is compiled separately from vmlinux.h, so we define
 * these locally (same pattern as scx_test_cpumask.c).
 */
struct cpumask {
	unsigned long bits[NR_CPUS / BITS_PER_LONG];
};

struct bpf_cpumask {
	struct cpumask cpumask;
	int usage; /* refcount_t — not used in simulator */
};

__weak
void scx_bpf_error_bstr(char *fmt __attribute__((unused)),
		        long long unsigned int *data __attribute__((unused)),
			u32 data__sz __attribute__((unused)))
{
}

/*
 * =================================================================
 * BPF cpumask operations — real implementations
 *
 * These replace the no-op stubs so that schedulers using BPF cpumask
 * allocation (e.g. LAVD's active_cpumask, ovrflw_cpumask) get working
 * bit manipulation. struct bpf_cpumask starts with cpumask_t followed
 * by refcount_t, so casting to struct cpumask * is safe.
 * =================================================================
 */

__weak
struct bpf_cpumask *bpf_cpumask_create(void)
{
	struct bpf_cpumask *m = calloc(1, sizeof(struct bpf_cpumask));
	return m;
}

__weak
void bpf_cpumask_release(struct bpf_cpumask *cpumask)
{
	if (cpumask)
		free(cpumask);
}

__weak
void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	if (!cpumask || cpu >= NR_CPUS)
		return;
	unsigned long *bits = (unsigned long *)cpumask;
	bits[cpu / BITS_PER_LONG] |= (1UL << (cpu % BITS_PER_LONG));
}

__weak
void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	if (!cpumask || cpu >= NR_CPUS)
		return;
	unsigned long *bits = (unsigned long *)cpumask;
	bits[cpu / BITS_PER_LONG] &= ~(1UL << (cpu % BITS_PER_LONG));
}

__weak
bool bpf_cpumask_test_and_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	if (!cpumask || cpu >= NR_CPUS)
		return false;
	unsigned long *bits = (unsigned long *)cpumask;
	unsigned long mask = 1UL << (cpu % BITS_PER_LONG);
	unsigned long word = cpu / BITS_PER_LONG;
	bool was_set = (bits[word] & mask) != 0;
	bits[word] |= mask;
	return was_set;
}

__weak
void bpf_cpumask_copy(struct bpf_cpumask *dst,
		      const struct cpumask *src)
{
	if (!dst || !src)
		return;
	memcpy(dst, src, sizeof(struct cpumask));
}

__weak
u32 bpf_cpumask_weight(const struct cpumask *cpumask)
{
	if (!cpumask)
		return 0;
	u32 count = 0;
	for (int i = 0; i < NR_CPUS / BITS_PER_LONG; i++) {
		unsigned long w = cpumask->bits[i];
		while (w) {
			count += w & 1;
			w >>= 1;
		}
	}
	return count;
}

__weak
bool bpf_cpumask_intersects(const struct cpumask *src1,
			    const struct cpumask *src2)
{
	if (!src1 || !src2)
		return false;
	for (int i = 0; i < NR_CPUS / BITS_PER_LONG; i++) {
		if (src1->bits[i] & src2->bits[i])
			return true;
	}
	return false;
}

__weak
bool bpf_cpumask_and(struct bpf_cpumask *dst,
		     const struct cpumask *src1,
		     const struct cpumask *src2)
{
	if (!dst || !src1 || !src2)
		return false;
	unsigned long *d = (unsigned long *)dst;
	bool any = false;
	for (int i = 0; i < NR_CPUS / BITS_PER_LONG; i++) {
		d[i] = src1->bits[i] & src2->bits[i];
		if (d[i])
			any = true;
	}
	return any;
}

__weak
u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask)
{
	if (!cpumask)
		return NR_CPUS;
	for (int i = 0; i < NR_CPUS; i++) {
		if ((cpumask->bits[i / BITS_PER_LONG] >>
		     (i % BITS_PER_LONG)) & 1)
			return i;
	}
	return NR_CPUS;
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

__weak
void *scx_minheap_alloc(u32 nr_elems __attribute__((unused)))
{
	return NULL;
}

__weak
int scx_minheap_insert(void *heap_ptr __attribute__((unused)),
		       u64 key __attribute__((unused)),
		       u64 value __attribute__((unused)))
{
	return 0;
}

__weak
u64 scx_atq_create_internal(int fifo __attribute__((unused)),
			    unsigned long capacity __attribute__((unused)))
{
	return 0;
}

__weak
int scx_atq_insert(void *atq_ptr __attribute__((unused)),
		   u64 taskc_ptr __attribute__((unused)))
{
	return 0;
}

__weak
int scx_atq_insert_vtime(void *atq __attribute__((unused)),
			 u64 taskc_ptr __attribute__((unused)),
			 u64 vtime __attribute__((unused)))
{
	return 0;
}

__weak
int scx_atq_nr_queued(void *atq __attribute__((unused)))
{
	return 0;
}

__weak
u64 scx_atq_pop(void *atq __attribute__((unused)))
{
	return 0;
}

__weak
u64 scx_atq_peek(void *atq __attribute__((unused)))
{
	return 0;
}

__weak
void *scx_task_alloc(struct task_struct *p __attribute__((unused)))
{
	return NULL;
}

__weak
void scx_task_free(struct task_struct *p __attribute__((unused)))
{
}
