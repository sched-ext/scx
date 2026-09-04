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
 * cid. The cid space is always num_possible_cpus() entries wide, so userspace
 * knows how wide it is before the scheduler is attached.
 */
struct cidland_arena_args {
	unsigned long long	nr_cpus;
};

/*
 * Arguments to cidland_set_primary_word(): one word of the primary domain, in
 * cpu space. Userspace feeds the mask a word at a time, so nothing here caps
 * the number of CPUs.
 */
struct cidland_primary_args {
	unsigned long long	idx;
	unsigned long long	word;
};

#endif /* __INTF_H */
