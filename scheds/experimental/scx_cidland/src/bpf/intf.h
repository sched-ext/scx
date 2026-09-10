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
 * Arguments to cidland_arena_init(), which sizes everything indexed by cid:
 * the width of the cid space, num_possible_cpus(), the number of packing and
 * capacity tiers, and the active asymmetric placement policies.
 */
struct cidland_arena_args {
	unsigned long long	nr_cpus;
	unsigned long long	nr_place_tiers;
	unsigned long long	nr_capacity_tiers;
	unsigned long long	asym_capacity;
	unsigned long long	asym_packing;
};

/*
 * Arguments to cidland_set_cpu(): the capacity, its independent capacity and
 * packing tiers, and the SMT-domain asymmetric-packing state of one CPU, in
 * cpu space.
 */
struct cidland_cpu_args {
	unsigned long long	cpu;
	unsigned long long	capacity;
	unsigned long long	place_tier;
	unsigned long long	capacity_tier;
	unsigned long long	smt_asym_packing;
};

/*
 * Arguments to cidland_get_cpu_priority(). The program returns the live
 * arch_asym_cpu_priority() value, whether SD_ASYM_PACKING is active in a
 * scheduling domain containing the CPU, and whether the SMT domain itself has
 * both SD_SHARE_CPUCAPACITY and SD_ASYM_PACKING.
 */
struct cidland_cpu_priority_args {
	unsigned long long	cpu;
	long long		priority;
	unsigned long long	asym_packing;
	unsigned long long	smt_asym_packing;
};

#endif /* __INTF_H */
