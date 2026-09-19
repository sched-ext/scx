// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DATATYPES_H
#define DATATYPES_H
#include "defines.h"

const volatile u32 nr_llcs = 1;
const volatile u32 cpu_to_llc[MAX_CPUS] = {};

extern const int CONFIG_HZ __kconfig;

struct task_ctx
{
  u64 current_dsq_type;
  u64 blocked_at;
  u64 runnable_at;
  s64 duty;
  u64 run_acc;
  u64 sleep_acc;
  u64 started_at;
  u64 duty_samples;
  u64 last_run_granted_slice;
};

struct dispatch_ctx
{
  u64 current_task_dsq_type;
  u64 last_kick_timestamp;
};

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dispatch_ctx);
} dispatch_state SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_ctx);
} task_ctx_store SEC(".maps");

#endif  // DATATYPES_H
