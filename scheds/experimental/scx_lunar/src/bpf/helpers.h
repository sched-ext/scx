// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef HELPERS_H
#define HELPERS_H
#include "datatypes.h"
#include "defines.h"

static __always_inline u64 get_dsq_task_slice(u64 dsqType)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return SLICE_LC;
    case DSQ_TYPE_INTERACTIVE:
      return SLICE_INTERACTIVE;
    case DSQ_TYPE_NORMAL:
      return SLICE_NORMAL;
    case DSQ_TYPE_BATCH:
      return SLICE_BATCH;
    case DSQ_TYPE_GREEDY:
      return SLICE_GREEDY;
  }
  return SLICE_GREEDY;
}

static __always_inline u64 get_cpu_dsq_from_type(u64 dsqType, u32 cpu)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return DSQ_CPU_QUEUE_BASE_LC + cpu;
    case DSQ_TYPE_INTERACTIVE:
      return DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu;
    case DSQ_TYPE_NORMAL:
      return DSQ_CPU_QUEUE_BASE_NORMAL + cpu;
    case DSQ_TYPE_BATCH:
      return DSQ_CPU_QUEUE_BASE_BATCH + cpu;
    case DSQ_TYPE_GREEDY:
      return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
  }
  return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
}

static __always_inline u64 get_llc_dsq_from_type(u64 dsqType, u32 llc)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return DSQ_LLC_QUEUE_BASE_LC + llc;
    case DSQ_TYPE_INTERACTIVE:
      return DSQ_LLC_QUEUE_BASE_INTERACTIVE + llc;
    case DSQ_TYPE_NORMAL:
      return DSQ_LLC_QUEUE_BASE_NORMAL + llc;
    case DSQ_TYPE_BATCH:
      return DSQ_LLC_QUEUE_BASE_BATCH + llc;
    case DSQ_TYPE_GREEDY:
      return DSQ_LLC_QUEUE_BASE_GREEDY + llc;
  }
  return DSQ_LLC_QUEUE_BASE_GREEDY + llc;
}

static __always_inline bool is_kthread(const struct task_struct* p)
{
  return p->flags & PF_KTHREAD;
}

static __always_inline bool is_high_prio_kthread_task(struct task_struct* p)
{
  return p->prio == MAX_RT_PRIO && is_kthread(p);
}

static __always_inline struct task_ctx* get_task_ctx(struct task_struct* task)
{
  return bpf_task_storage_get(&task_ctx_store, task, NULL, 0);
}

static __always_inline u32 cpu_llc_id(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_to_llc[cpu];
}

static __always_inline u32 task_duty(const struct task_ctx* tctx)
{
  return (tctx->run_acc << 10) / (tctx->run_acc + tctx->sleep_acc + 1);
}

static __always_inline void duty_account(struct task_ctx* tctx, u64 run, u64 slept)
{
  if (run > DUTY_WINDOW_NS)
    run = DUTY_WINDOW_NS;
  if (slept > DUTY_WINDOW_NS)
    slept = DUTY_WINDOW_NS;

  tctx->run_acc += run;

  if (tctx->run_acc > DUTY_WINDOW_NS)
    tctx->run_acc = DUTY_WINDOW_NS;

  tctx->sleep_acc += slept;

  if (tctx->run_acc + tctx->sleep_acc > 2 * DUTY_WINDOW_NS)
  {
    tctx->run_acc >>= 1;
    tctx->sleep_acc >>= 1;
  }
}

static __always_inline u64 getTickInterval_ns(void)
{
  return 1000000000ULL / CONFIG_HZ;
}

static __always_inline u64* get_or_create_greedy_counter(struct greedy_group_key* key)
{
  u64* count = bpf_map_lookup_elem(&greedy_group_store, key);
  if (count)
    return count;

  u64 countNew = 0;
  bpf_map_update_elem(&greedy_group_store, key, &countNew, BPF_NOEXIST);
  return bpf_map_lookup_elem(&greedy_group_store, key);
}

static __always_inline void greedy_group_join(struct task_ctx* tctx, u64 dsq_id, u32 tgid)
{
  barrier_var(tgid);
  barrier_var(dsq_id);

  if (tctx->counted_in_greedy_group)
  {
    if (tctx->counted_greedy_dsq == dsq_id)
      return;

    struct greedy_group_key old_key;
    __builtin_memset(&old_key, 0, sizeof(old_key));
    old_key.dsq_id = tctx->counted_greedy_dsq;
    old_key.tgid = tgid;

    u64* old_count = bpf_map_lookup_elem(&greedy_group_store, &old_key);
    if (old_count && *old_count > 0)
      __sync_fetch_and_sub(old_count, 1);
    tctx->counted_in_greedy_group = false;
  }

  struct greedy_group_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.dsq_id = dsq_id;
  key.tgid = tgid;

  u64* count = get_or_create_greedy_counter(&key);
  if (!count)
    return;

  __sync_fetch_and_add(count, 1);
  tctx->counted_in_greedy_group = true;
  tctx->counted_greedy_dsq = dsq_id;
}

static __always_inline void decrement_greedy_group_count(struct greedy_group_key* key)
{
  u64* count = bpf_map_lookup_elem(&greedy_group_store, key);
  if (!count)
    return;

  if (*count == 0)
  {
    bpf_map_delete_elem(&greedy_group_store, key);
  }

  u64 old = __sync_fetch_and_sub(count, 1);
  if (old == 1)  // this decrement was the one that brought it to zero
    bpf_map_delete_elem(&greedy_group_store, key);
}

static __always_inline void greedy_group_leave(struct task_ctx* tctx, u32 tgid)
{
  barrier_var(tgid);

  if (!tctx->counted_in_greedy_group)
    return;

  struct greedy_group_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.dsq_id = tctx->counted_greedy_dsq;  // release against the queue it was actually joined on
  key.tgid = tgid;

  decrement_greedy_group_count(&key);
  tctx->counted_in_greedy_group = false;
}

static __always_inline u64 greedy_group_slice(u64 dsq_id, u32 tgid)
{
  barrier_var(tgid);
  barrier_var(dsq_id);

  struct greedy_group_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.dsq_id = dsq_id;
  key.tgid = tgid;

  u64* count = bpf_map_lookup_elem(&greedy_group_store, &key);
  u64 slice = SLICE_GREEDY;
  if (count && *count > 1)
  {
    u64 n = *count;
    if (n > GREEDY_GROUP_CAP)
      n = GREEDY_GROUP_CAP;
    slice = SLICE_GREEDY / n;
    if (slice < GREEDY_MIN_SLICE)
      slice = GREEDY_MIN_SLICE;
  }
  return slice;
}

static __always_inline u64 get_greedy_dsq_for_cpu(u32 cpu)
{
  if(schedulerMode == SCHED_MODE_DSQ_PER_CPU){

    return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
  }
  return DSQ_LLC_QUEUE_BASE_GREEDY + cpu_llc_id(cpu);
}

#endif  // HELPERS_H
