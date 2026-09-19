// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <include/scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "defines.h"
#include "helpers.h"
#include "datatypes.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static __always_inline u64 dispatch_with_fallback(u32 cpu)
{
  return dispatch_dsq_per_cpu(cpu);
}

static __always_inline u64 tier_from_duty(s64 duty)
{
  if (duty < DUTY_EDGE_LC)
    return DSQ_TYPE_LC;
  if (duty < DUTY_EDGE_INTERACTIVE)
    return DSQ_TYPE_INTERACTIVE;
  if (duty < DUTY_EDGE_NORMAL)
    return DSQ_TYPE_NORMAL;
  return DSQ_TYPE_GREEDY;
}

static __always_inline void update_task_dsq_type(struct task_struct* task, struct task_ctx* task_ctx)
{
  if (task_ctx->duty_samples < DUTY_SAMPLES_NEEDED)
  {
    task_ctx->current_dsq_type = DSQ_TYPE_GREEDY;
    return;
  }

  u64 cur = task_ctx->current_dsq_type;
  u64 pessimistic = tier_from_duty(task_ctx->duty + DUTY_HYST);
  u64 optimistic = tier_from_duty(task_ctx->duty - DUTY_HYST);

  if (pessimistic < cur)
    task_ctx->current_dsq_type = pessimistic;
  else if (optimistic > cur)
    task_ctx->current_dsq_type = optimistic;
}

static __always_inline void update_task_prio(struct task_struct* task, struct task_ctx* task_ctx, u64 used_ns, bool runnable)
{
  if (!task_ctx)
  {
    return;
  }

  update_task_dsq_type(task, task_ctx);
}

// callbacks

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init)
{
  s32 ret;

  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 cpu;
  bpf_for(cpu, 0, nr_cpu_ids)
  {
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_LC + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_NORMAL + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_GREEDY + cpu, -1);
    if (ret)
      return ret;
  }

  bpf_for(cpu, 0, nr_cpu_ids)
  {
    u32 key = 0;
    struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
    if (!dispatch_ctx)
      return -ENOMEM;

    dispatch_ctx->current_task_dsq_type = DSQ_TYPE_GREEDY;
  }

  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init_task, struct task_struct* p, struct scx_init_task_args* args)
{  
  struct task_ctx* tctx;
  u64 now = bpf_ktime_get_ns();

  tctx = bpf_task_storage_get(&task_ctx_store, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!tctx)
    return -ENOMEM;

  tctx->current_dsq_type = DSQ_TYPE_GREEDY;
  tctx->started_at = now;
  tctx->run_acc = DUTY_INIT_RUN_NS;
  tctx->sleep_acc = 0;
  tctx->duty_samples = 0;

  if (args->fork)
  {
    struct task_struct* cur = bpf_get_current_task_btf();
    struct task_struct* parent = p->real_parent;

    bool from_creator = cur && ((parent && cur->pid == parent->pid) || cur->tgid == p->tgid);
    if (from_creator)
    {
      struct task_ctx* pctx = bpf_task_storage_get(&task_ctx_store, cur, NULL, 0);
      if (pctx && pctx->duty_samples >= DUTY_SAMPLES_NEEDED)
      {
        tctx->run_acc = pctx->run_acc >> 1;
        tctx->sleep_acc = pctx->sleep_acc >> 1;
        tctx->current_dsq_type = pctx->current_dsq_type;
        tctx->duty_samples = DUTY_SAMPLES_NEEDED;
      }
    }
  }
  return 0;
}

void BPF_STRUCT_OPS(lunar_exit_task, struct task_struct* p, struct scx_exit_task_args* args)
{
}

s32 BPF_STRUCT_OPS(
  lunar_select_cpu,
  struct task_struct* p,
  s32 prev_cpu,
  u64 wake_flags)
{
  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return prev_cpu;

  bool isIdle;
  return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &isIdle);
}

void BPF_STRUCT_OPS(lunar_enqueue, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* context = get_task_ctx(p);

  u64 dsqType = context ? context->current_dsq_type : QUEUE_START;
  u32 cpu = scx_bpf_task_cpu(p);

  u64 dsq = get_cpu_dsq_from_type(dsqType, cpu);

  u64 slice = get_dsq_task_slice(dsqType);

  if (context)
    context->last_run_granted_slice = slice;

  scx_bpf_dsq_insert(p, dsq, slice, enq_flags);

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dispatch_ctx)
    return;

  if (enq_flags & SCX_ENQ_WAKEUP && dispatch_ctx->current_task_dsq_type > dsqType)
  {
    u64 now = bpf_ktime_get_ns();
    dispatch_ctx->last_kick_timestamp = now;
    scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
  }
}

void BPF_STRUCT_OPS(
  lunar_dispatch,
  s32 cpu,
  struct task_struct* prev)
{
  dispatch_with_fallback(cpu);
}

void BPF_STRUCT_OPS(
  lunar_stopping,
  struct task_struct* task,
  bool runnable)
{
  u64 now = bpf_ktime_get_ns();
  if (!task)
  {
    return;
  }
  struct task_ctx* tctx = get_task_ctx(task);
  if (!tctx)
    return;

  u64 used_ns = now - tctx->started_at;

  duty_account(tctx, used_ns, 0);

  tctx->duty = task_duty(tctx);
  update_task_prio(task, tctx, used_ns, runnable);

  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_elem(&dispatch_state, &key);
  if (dctx)
    dctx->current_task_dsq_type = DSQ_TYPE_EMPTY;
}

void BPF_STRUCT_OPS(
  lunar_exit,
  struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(lunar_running, struct task_struct* p)
{
  if (!p)
    return;

  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return;

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_elem(&dispatch_state, &key);
  if (!dispatch_ctx)
    return;

  u64 dsqType = context->current_dsq_type;
  if (dsqType > DSQ_TYPE_GREEDY)
    dsqType = DSQ_TYPE_GREEDY;

  dispatch_ctx->current_task_dsq_type = dsqType;

  u64 now = bpf_ktime_get_ns();
  context->started_at = now;

  // bpf_printk("lunar_run cpu=%d pid=%d tgid=%d comm=%s dsqType=%llu greedy=%d dsq_id=%llu slice=%llu duty=%llu", bpf_get_smp_processor_id(), p->pid, p->tgid, p->comm,
  //            context->current_dsq_type, context->counted_in_greedy_group, context->counted_greedy_dsq, context->last_run_granted_slice, context->duty);
}

void BPF_STRUCT_OPS(lunar_quiescent, struct task_struct* p, u64 deq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  if (!tctx)
    return;

  tctx->blocked_at = (deq_flags & SCX_DEQ_SLEEP) ? bpf_ktime_get_ns() : 0;
}

void BPF_STRUCT_OPS(lunar_runnable, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 now = bpf_ktime_get_ns();

  if (!tctx)
    return;

  if (tctx->blocked_at)
  {
    duty_account(tctx, 0, now - tctx->blocked_at);
    tctx->duty_samples++;
    if (tctx->duty_samples > DUTY_SAMPLES_MAX)
    {
      tctx->duty_samples = DUTY_SAMPLES_MAX;
    }
    tctx->blocked_at = 0;
    tctx->duty = task_duty(tctx);
    update_task_dsq_type(p, tctx);
  }
  tctx->runnable_at = now;
}

SCX_OPS_DEFINE(lunar_ops,
               .init = (void*)lunar_init,
               .init_task = (void*)lunar_init_task,
               .exit_task = (void*)lunar_exit_task,
               .select_cpu = (void*)lunar_select_cpu,
               .runnable = (void*)lunar_runnable,
               .quiescent = (void*)lunar_quiescent,
               .running = (void*)lunar_running,
               .enqueue = (void*)lunar_enqueue,
               .dispatch = (void*)lunar_dispatch,
               .stopping = (void*)lunar_stopping,
               .exit = (void*)lunar_exit,
               .name = "scx_lunar");
