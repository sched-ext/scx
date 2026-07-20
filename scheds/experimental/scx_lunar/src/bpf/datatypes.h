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
const volatile u32 schedulerMode = SCHED_MODE_DSQ_PER_CPU;

struct task_ctx
{
  u64 current_dsq_type;
  u64 runtime_avg;
  u64 current_runtime;
  u64 last_yield_timestamp;
  s64 vlag;
  u64 last_run_granted_slice;
  bool first_runtime_avg_sample_taken;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4200000);
  __type(key, u32);  // pid
  __type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

#endif  // DATATYPES_H
