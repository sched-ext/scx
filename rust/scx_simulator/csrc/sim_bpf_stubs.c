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

void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	if (cpu < NR_CPUS)
		cpumask->bits[cpu / BITS_PER_LONG] &= ~(1UL << (cpu % BITS_PER_LONG));
}

void bpf_cpumask_clear(struct bpf_cpumask *cpumask)
{
	memset(cpumask, 0, sizeof(struct bpf_cpumask));
}

void bpf_cpumask_setall(struct bpf_cpumask *cpumask)
{
	memset(cpumask, 0xff, sizeof(struct bpf_cpumask));
}

bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask)
{
	if (cpu >= NR_CPUS)
		return false;
	return !!(cpumask->bits[cpu / BITS_PER_LONG] & (1UL << (cpu % BITS_PER_LONG)));
}

bool bpf_cpumask_empty(const struct cpumask *cpumask)
{
	unsigned int i;
	for (i = 0; i < 128; i++) {
		if (cpumask->bits[i])
			return false;
	}
	return true;
}

u32 bpf_cpumask_first(const struct cpumask *cpumask)
{
	unsigned int i;
	for (i = 0; i < 128; i++) {
		if (cpumask->bits[i]) {
			unsigned long v = cpumask->bits[i];
			u32 bit = 0;
			while (!(v & 1)) {
				v >>= 1;
				bit++;
			}
			return i * (sizeof(unsigned long) * 8) + bit;
		}
	}
	/* No bits set — return >= nr_cpu_ids to signal "none found". */
	return 128 * sizeof(unsigned long) * 8;
}

u32 bpf_cpumask_weight(const struct cpumask *cpumask)
{
	u32 count = 0;
	unsigned int i;
	for (i = 0; i < 128; i++) {
		unsigned long v = cpumask->bits[i];
		while (v) {
			count += v & 1;
			v >>= 1;
		}
	}
	return count;
}

bool bpf_cpumask_and(struct bpf_cpumask *dst, const struct cpumask *src1,
		     const struct cpumask *src2)
{
	bool result = false;
	unsigned int i;
	for (i = 0; i < 128; i++) {
		dst->bits[i] = src1->bits[i] & src2->bits[i];
		if (dst->bits[i])
			result = true;
	}
	return result;
}

void bpf_cpumask_or(struct bpf_cpumask *dst, const struct cpumask *src1,
		    const struct cpumask *src2)
{
	unsigned int i;
	for (i = 0; i < 128; i++)
		dst->bits[i] = src1->bits[i] | src2->bits[i];
}

void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src)
{
	__builtin_memcpy(dst, src, sizeof(struct cpumask));
}

bool bpf_cpumask_subset(const struct cpumask *src1, const struct cpumask *src2)
{
	unsigned int i;
	for (i = 0; i < 128; i++) {
		if (src1->bits[i] & ~src2->bits[i])
			return false;
	}
	return true;
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

u32 bpf_cpumask_any_and_distribute(const struct cpumask *src1,
				   const struct cpumask *src2)
{
	unsigned int i;
	for (i = 0; i < NR_CPUS; i++) {
		unsigned long bit = 1UL << (i % BITS_PER_LONG);
		unsigned long word = i / BITS_PER_LONG;
		if ((src1->bits[word] & bit) && (src2->bits[word] & bit))
			return i;
	}
	return NR_CPUS;
}

bool bpf_cpumask_intersects(const struct cpumask *src1,
			    const struct cpumask *src2)
{
	unsigned int i;
	for (i = 0; i < 128; i++) {
		if (src1->bits[i] & src2->bits[i])
			return true;
	}
	return false;
}

bool bpf_cpumask_test_and_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
{
	bool was_set;
	if (cpu >= NR_CPUS)
		return false;
	was_set = !!(cpumask->bits[cpu / BITS_PER_LONG] &
		     (1UL << (cpu % BITS_PER_LONG)));
	cpumask->bits[cpu / BITS_PER_LONG] |= (1UL << (cpu % BITS_PER_LONG));
	return was_set;
}

/* --- kptr exchange --- */

void *bpf_kptr_xchg_impl(void **kptr, void *new_val)
{
	void *old = *kptr;
	*kptr = new_val;
	return old;
}


