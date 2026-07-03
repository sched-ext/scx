#ifndef DATATYPES_H
#define DATATYPES_H
#include "defines.h"

const volatile u32 nr_llcs = 1;
const volatile u32 cpu_to_llc[MAX_CPUS] = {};
const volatile u32 schedulerMode = 0;

struct task_ctx
{
  // s64 vlag;
  u64 current_dsq_type;
  u64 dsq_type_before_boost;
  u64 runtime_avg;
  u64 current_runtime;
  u64 last_yield_timestamp;
  bool first_runtime_avg_sample_taken;
  bool boostUntilYield;
  s64 vlag;
  u64 last_spawn_timestamp;
  u64 task_spawn_interval_avg;
};

struct dispatch_ctx
{
  u64 runtime_avg;
  u64 runtime_per_queue[DSQ_PRIO_QUEUE_AMOUNT];
  u64 skipFallbackRemainingTime;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4200000);
  __type(key, u32);  // pid
  __type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dispatch_ctx);
} dispatch_state SEC(".maps");

#endif  // DATATYPES_H
