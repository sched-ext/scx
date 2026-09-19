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
    case DSQ_TYPE_GREEDY:
      return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
  }
  return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
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
#endif  // HELPERS_H
