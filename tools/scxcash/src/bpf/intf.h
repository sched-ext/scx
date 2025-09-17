// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned int u32;
typedef unsigned long long u64;
#endif

struct soft_dirty_fault_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 cpu;
    u64 address; /* faulting address */
};

struct perf_sample_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 cpu;
    u64 address; /* placeholder */
};

/* Emitted on task local storage map update; reports first 8 bytes of value. */
struct hints_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 cpu;
    u64 hint_value;
};

#endif /* __INTF_H */
