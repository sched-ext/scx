/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Jake Hillion <jake@hillion.co.uk>
 */
#ifndef __SCX_ARENA_USERSPACE_INTERROP_H
#define __SCX_ARENA_USERSPACE_INTERROP_H

#ifndef __arena
#define __arena
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif

struct scx_userspace_arena_alloc_pages_args
{
	u32		sz;
	void __arena	*ret;
};

struct scx_userspace_arena_free_pages_args
{
	void __arena	*addr;
	u32		sz;
};

#endif /* __SCX_ARENA_USERSPACE_INTERROP_H */
