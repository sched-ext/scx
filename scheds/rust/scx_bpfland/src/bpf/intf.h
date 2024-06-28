/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <righi.andrea@gmail.com>
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
	NSEC_PER_SEC = 1000000000ULL,
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

#endif /* __INTF_H */
