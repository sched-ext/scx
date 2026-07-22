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
  u32 pid = task->pid;
  return bpf_map_lookup_elem(&task_ctx_map, &pid);
}

static __always_inline u32 cpu_llc_id(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_to_llc[cpu];
}

static __always_inline void creditVlag(struct task_ctx* context)
{
  if (!context)
  {
    return;
  }
  u64 now = bpf_ktime_get_ns();
  u64 slept = now - context->last_yield_timestamp;

  s64 credit = (s64)(slept / SLEEP_CREDIT_DIVISOR);
  if (credit > MAX_CREDITABLE_SLEEP)
    credit = MAX_CREDITABLE_SLEEP;

  context->vlag += credit;

  if (context->vlag > VLAG_MAX)
    context->vlag = VLAG_MAX;
}

#endif  // HELPERS_H
