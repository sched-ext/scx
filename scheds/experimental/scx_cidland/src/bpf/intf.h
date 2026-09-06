/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#define MAX(x, y)	((x) > (y) ? (x) : (y))
#define MIN(x, y)	((x) < (y) ? (x) : (y))

enum {
	NSEC_PER_USEC	= 1000ULL,
	NSEC_PER_MSEC	= (1000ULL * NSEC_PER_USEC),
};

/*
 * Arguments to cidland_arena_init(), which sizes everything that is indexed by
 * cid: the width of the cid space, num_possible_cpus(), and the number of
 * capacity tiers. Userspace knows both before the scheduler is attached.
 */
struct cidland_arena_args {
	unsigned long long	nr_cpus;
	unsigned long long	nr_tiers;
};

/*
 * Arguments to cidland_set_cpu(): the capacity and the tier of one CPU, in cpu
 * space.
 */
struct cidland_cpu_args {
	unsigned long long	cpu;
	unsigned long long	capacity;
	unsigned long long	tier;
};

#endif /* __INTF_H */
