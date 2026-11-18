/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC  = (1000ULL * NSEC_PER_MSEC),
};

/* cpu_domain has one entry per possible CPU, at most LERTICK_MAX_CPUS. */
#define LERTICK_MAX_CPUS 512U
#define LERTICK_MAX_DOMAINS 64U

/* Statistics, one counter per CPU each, summed by user space. */
enum lertick_stat {
	LERTICK_STAT_LOCAL_DISPATCHES,
	LERTICK_STAT_SHARED_DISPATCHES,
	LERTICK_STAT_CONTINUATIONS,
	LERTICK_STAT_ADAPTIVE_SLICES,
	LERTICK_STAT_TRAINING_UPDATES,
	LERTICK_NR_STATS,
};

enum lertick_mode {
	LERTICK_MODE_FIXED  = 0,
	LERTICK_MODE_ONLINE = 1,
};

#ifndef __VMLINUX_H__
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

typedef signed char    s8;
typedef signed short   s16;
typedef signed int     s32;
typedef signed long    s64;

typedef int	       pid_t;
#endif /* __VMLINUX_H__ */

#endif /* __INTF_H */
