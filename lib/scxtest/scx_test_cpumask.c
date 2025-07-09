#include <stdbool.h>

#include "kern_types.h"

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#endif

#ifndef NR_CPUS
#define NR_CPUS 128
#endif

struct cpumask {
	unsigned long bits[128];
};

static __thread struct cpumask all_cpus = { 0 };
static __thread struct cpumask idle_smtmask = { 0 };
static __thread struct cpumask idle_cpumask = { 0 };

static void cpumask_set_cpu(int cpu, struct cpumask *mask)
{
	if (cpu < 0 || cpu >= NR_CPUS) {
		return;
	}
	mask->bits[cpu / BITS_PER_LONG] |= (1UL << (cpu % BITS_PER_LONG));
}

static void cpumask_clear_cpu(int cpu, struct cpumask *mask)
{
	if (cpu < 0 || cpu >= NR_CPUS) {
		return;
	}
	mask->bits[cpu / BITS_PER_LONG] &= ~(1UL << (cpu % BITS_PER_LONG));
}

static bool cpumask_test_cpu(int cpu, const struct cpumask *mask)
{
	if (cpu < 0 || cpu >= NR_CPUS) {
		return false;
	}
	return (mask->bits[cpu / BITS_PER_LONG] & (1UL << (cpu % BITS_PER_LONG))) != 0;
}

void scx_test_set_all_cpumask(int cpu)
{
	cpumask_set_cpu(cpu, &all_cpus);
}

void scx_test_set_idle_smtmask(int cpu)
{
	cpumask_set_cpu(cpu, &idle_smtmask);
}

void scx_test_set_idle_cpumask(int cpu)
{
	cpumask_set_cpu(cpu, &idle_cpumask);
}

void scx_test_cpumask_set(int cpu, struct cpumask *cpumask)
{
	cpumask_set_cpu(cpu, cpumask);
}

const struct cpumask *scx_bpf_get_idle_smtmask_node(int node __attribute__((unused)))
{
	return &idle_smtmask;
}

const struct cpumask *scx_bpf_get_idle_smtmask(void)
{
	return &idle_smtmask;
}

const struct cpumask *scx_bpf_get_idle_cpumask(void)
{
	return &idle_cpumask;
}

bool scx_bpf_test_and_clear_cpu_idle(s32 cpu)
{
	if (cpumask_test_cpu(cpu, &idle_cpumask)) {
		cpumask_clear_cpu(cpu, &idle_cpumask);
		return true;
	}
	return false;
}

bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask)
{
	return cpumask_test_cpu(cpu, cpumask);
}

s32 scx_bpf_pick_idle_cpu_node(const struct cpumask *cpus_allowed,
			       int node __attribute__((unused)),
			       u64 flags __attribute__((unused)))
{
	for (int i = 0; i < NR_CPUS; i++) {
		if (cpumask_test_cpu(i, cpus_allowed) && cpumask_test_cpu(i, &idle_cpumask)) {
			return i;
		}
	}
	return -1;
}

s32 scx_bpf_pick_idle_cpu(const struct cpumask *cpus_allowed, u64 flags __attribute__((unused)))
{
	for (int i = 0; i < NR_CPUS; i++) {
		if (cpumask_test_cpu(i, cpus_allowed) && cpumask_test_cpu(i, &idle_cpumask)) {
			return i;
		}
	}
	return -1;
}
