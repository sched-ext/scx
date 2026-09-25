#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

/*
 * Arguments to eevdf_arena_init(), which sizes everything indexed by cid:
 * the width of the cid space, num_possible_cpus(), the number of packing and
 * capacity tiers, and the active asymmetric placement policies.
 */
struct eevdf_arena_args {
	unsigned long long	nr_cpus;
	unsigned long long	nr_place_tiers;
	unsigned long long	nr_capacity_tiers;
	unsigned long long	asym_capacity;
	unsigned long long	sched_asym_capacity;
	unsigned long long	force_asym_capacity;
	unsigned long long	asym_packing;
};

/*
 * Arguments to eevdf_set_cpu(): the capacity, its independent capacity and
 * packing tiers, and the SMT-domain asymmetric-packing state of one CPU, in
 * cpu space.
 */
struct eevdf_cpu_args {
	unsigned long long	cpu;
	unsigned long long	capacity;
	unsigned long long	place_tier;
	unsigned long long	capacity_tier;
	unsigned long long	smt_asym_packing;
	unsigned long long	fork_span;
	unsigned long long	wake_affine_span;
	unsigned long long	asym_capacity_span;
};

/*
 * Arguments to eevdf_get_cpu_priority(). There is no portable userspace ABI
 * for SD_ASYM_PACKING or arch_asym_cpu_priority(), so keep this narrow query
 * until sched_ext provides one.
 */
struct eevdf_cpu_priority_args {
	unsigned long long	cpu;
	long long		priority;
	unsigned long long	asym_packing;
	unsigned long long	smt_asym_packing;
};

#endif /* __INTF_H */
