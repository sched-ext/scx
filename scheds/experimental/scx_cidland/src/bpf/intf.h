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
 * Maximum size of the cid space handled by this scheduler.
 *
 * The cid space is always num_possible_cpus() entries wide, so this is simply
 * the maximum number of CPUs supported.
 */
#define MAX_CIDS	1024

/* Number of u64 words needed to hold one bit per cid. */
#define MAX_CID_WORDS	(MAX_CIDS / 64)

#endif /* __INTF_H */
