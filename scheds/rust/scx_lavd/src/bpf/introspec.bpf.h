/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026
 */
#ifndef __LAVD_INTROSPEC_BPF_H
#define __LAVD_INTROSPEC_BPF_H

enum {
	LAVD_INTROSPEC_STREAM_RINGBUF_SIZE = 128 * 1024,
};

struct lavd_stream_sample {
	u64	timestamp_ns;
	u32	cpu_id;
	s32	pid;
	u32	lat_cri;
	u32	perf_cri;
	u64	slice_ns;
	u64	dsq_id;
};

#endif /* __LAVD_INTROSPEC_BPF_H */
