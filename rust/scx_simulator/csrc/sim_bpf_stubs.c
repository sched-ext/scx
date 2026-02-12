/*
 * sim_bpf_stubs.c - Strong stub implementations for BPF helpers
 *
 * These override the __weak stubs in overrides.c with implementations
 * that actually work for the simulator. Used by schedulers that need
 * cpumask manipulation and kptr exchange.
 *
 * This file does NOT include sim_wrapper.h or any BPF headers to avoid
 * conflicts with bpf_helper_defs.h (which defines bpf_timer_* as static
 * function pointers). We only need basic types and the cpumask struct.
 */

/* Use kern_types.h for basic types (u32, s32, etc.) */
#include "kern_types.h"
#include <stdbool.h>
#include <stddef.h>

/* Reproduce the cpumask struct definition from scx_test_cpumask.c */
#ifndef BITS_PER_LONG
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#endif

#ifndef NR_CPUS
#define NR_CPUS 128
#endif

struct cpumask {
	unsigned long bits[128];
};

/* bpf_cpumask is just a cpumask in the test infrastructure */
struct bpf_cpumask {
	unsigned long bits[128];
};

/* Forward declarations for libc functions */
extern void *calloc(unsigned long nmemb, unsigned long size);
extern void free(void *ptr);
extern void *memset(void *s, int c, unsigned long n);

/* --- cpumask helpers --- */

struct bpf_cpumask *bpf_cpumask_create(void)
{
	return (struct bpf_cpumask *)calloc(1, sizeof(struct bpf_cpumask));
}

void bpf_cpumask_release(struct bpf_cpumask *cpumask)
{
	free(cpumask);
}

void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	if (cpu < NR_CPUS)
		cpumask->bits[cpu / BITS_PER_LONG] |= (1UL << (cpu % BITS_PER_LONG));
}

void bpf_cpumask_clear(struct bpf_cpumask *cpumask)
{
	memset(cpumask, 0, sizeof(struct bpf_cpumask));
}

u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask)
{
	unsigned int i;
	for (i = 0; i < NR_CPUS; i++) {
		if (cpumask->bits[i / BITS_PER_LONG] & (1UL << (i % BITS_PER_LONG)))
			return i;
	}
	return NR_CPUS;
}

/* --- kptr exchange --- */

void *bpf_kptr_xchg_impl(void **kptr, void *new_val)
{
	void *old = *kptr;
	*kptr = new_val;
	return old;
}
