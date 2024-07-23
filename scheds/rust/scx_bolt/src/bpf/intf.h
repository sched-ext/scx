// Copyright (c) David Vernet <void@manifault.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
#endif

#include <scx/ravg.bpf.h>

enum consts {
	CACHELINE_SIZE		= 64,
};

#endif /* __INTF_H */
