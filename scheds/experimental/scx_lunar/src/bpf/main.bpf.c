// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include "defines.h"
#include "helpers.h"
#include "datatypes.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static __always_inline u64 dispatch_with_fallback(u32 cpu)
{
  switch (schedulerMode)
  {
    case SCHED_MODE_DSQ_PER_LLC:
    {
      u32 llc = cpu_llc_id(cpu);
      return dispatch_dsq_per_llc(llc);
      break;
    }

    case SCHED_MODE_DSQ_PER_CPU:
      return dispatch_dsq_per_cpu(cpu);
      break;
  }

  return DSQ_TYPE_EMPTY;
}

static __always_inline void update_task_dsq_type(struct task_struct* task, struct task_ctx* task_ctx)
{
  if (task_ctx->duty_samples < DUTY_SAMPLES_NEEDED)
  {
    task_ctx->current_dsq_type = DSQ_TYPE_GREEDY;
  }

  switch (task_ctx->current_dsq_type)
  {
    case DSQ_TYPE_LC:
      if (task_ctx->duty > DUTY_EDGE_LC + DUTY_HYST)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      break;
    case DSQ_TYPE_INTERACTIVE:
      if (task_ctx->duty < DUTY_EDGE_LC)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_LC;
      }
      else if (task_ctx->duty > DUTY_EDGE_INTERACTIVE + DUTY_HYST)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_NORMAL;
      }
      break;
    case DSQ_TYPE_NORMAL:
      if (task_ctx->duty < DUTY_EDGE_INTERACTIVE)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      else if (task_ctx->duty > DUTY_EDGE_NORMAL + DUTY_HYST)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_BATCH;
      }
      break;
    case DSQ_TYPE_BATCH:
      if (task_ctx->duty < DUTY_EDGE_NORMAL)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_NORMAL;
      }
      break;
    case DSQ_TYPE_GREEDY:
      if (task_ctx->duty < DUTY_EDGE_BATCH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_BATCH;
      }
      break;
  }
  if (task_ctx->current_dsq_type != DSQ_TYPE_GREEDY)
  {
    if (task_ctx->duty > DUTY_EDGE_BATCH + DUTY_HYST_HIGH)
    {
      task_ctx->current_dsq_type = DSQ_TYPE_GREEDY;
    }
  }
}

static __always_inline void update_task_prio(struct task_struct* task, struct task_ctx* task_ctx, u64 used_ns, bool runnable)
{
  if (!task_ctx)
  {
    return;
  }

  task_ctx->current_runtime += used_ns;
  if (task_ctx->current_runtime > MAX_RUNTIME_PER_TASK)
  {
    task_ctx->current_runtime = MAX_RUNTIME_PER_TASK;
  }

  if ((task_ctx->current_runtime / task_ctx->runtime_avg) > AVG_RUNTIME_OVERRIDE_FACTOR)
  {
    task_ctx->runtime_avg = task_ctx->current_runtime;
  }

  if (!runnable)
  {
    if (!task_ctx->first_runtime_avg_sample_taken)
    {
      task_ctx->runtime_avg = task_ctx->current_runtime;
      task_ctx->first_runtime_avg_sample_taken = true;
    }
    else
    {
      task_ctx->runtime_avg = (task_ctx->runtime_avg * (HISTORIC_TASK_SAMPLES - 1) + task_ctx->current_runtime) / HISTORIC_TASK_SAMPLES;
    }
    task_ctx->current_runtime = 0;
  }
  if (task_ctx->runtime_avg < MIN_AVG_RUNTIME)
  {
    task_ctx->runtime_avg = MIN_AVG_RUNTIME;
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
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_BATCH + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_GREEDY + cpu, -1);
    if (ret)
      return ret;
  }
  u32 llc;
  bpf_for(llc, 0, nr_llcs)
  {
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_LC + llc, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_NORMAL + llc, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_BATCH + llc, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_INTERACTIVE + llc, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_GREEDY + llc, -1);
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

  tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!tctx)
    return -ENOMEM;

  tctx->runtime_avg = AVG_RUNTIME_START;
  tctx->current_runtime = 0;
  tctx->current_dsq_type = DSQ_TYPE_GREEDY;
  tctx->started_at = now;
  tctx->first_runtime_avg_sample_taken = false;
  tctx->run_acc = DUTY_WINDOW_NS;
  tctx->sleep_acc = 0;

  return 0;
}

void BPF_STRUCT_OPS(lunar_exit_task, struct task_struct* p, struct scx_exit_task_args* args) { }

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
  if (!context)
    return;

  u64 dsqType = context ? context->current_dsq_type : QUEUE_START;
  u32 cpu = scx_bpf_task_cpu(p);

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dispatch_ctx)
    return;

  u64 dsq;
  if (schedulerMode == SCHED_MODE_DSQ_PER_LLC)
  {
    u32 llc = cpu_llc_id(cpu);
    dsq = get_llc_dsq_from_type(dsqType, llc);
  }
  else
  {
    dsq = get_cpu_dsq_from_type(dsqType, cpu);
  }
  u64 slice = get_dsq_task_slice(dsqType);
  context->last_run_granted_slice = slice;
  scx_bpf_dsq_insert(p, dsq, slice, enq_flags);

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

  u32 cpu = scx_bpf_task_cpu(task);
  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dispatch_ctx)
    return;

  if (!runnable)
  {
    dispatch_ctx->current_task_dsq_type = DSQ_TYPE_EMPTY;
  }
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

  u32 cpu = scx_bpf_task_cpu(p);

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dispatch_ctx)
    return;

  u64 dsqType = context->current_dsq_type;
  if (dsqType > DSQ_TYPE_GREEDY)
    dsqType = DSQ_TYPE_GREEDY;

  dispatch_ctx->current_task_dsq_type = dsqType;

  u64 now = bpf_ktime_get_ns();
  dispatch_ctx->current_task_deadline = now + context->last_run_granted_slice;
  context->started_at = now;
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
