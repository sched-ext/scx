// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>
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
  switch (task_ctx->current_dsq_type)
  {
    case DSQ_TYPE_LC:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg >= ((RUNTIME_PRIO_BOUNDARY_LC + (RUNTIME_PRIO_BOUNDARY_LC * RUNTIME_THRESH_PERCENT) / 100))) ||
          task_ctx->vlag < VLAG_DEMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      break;
    case DSQ_TYPE_INTERACTIVE:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= (RUNTIME_PRIO_BOUNDARY_LC)) && task_ctx->vlag > VLAG_PROMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_LC;
      }
      else if ((task_ctx->first_runtime_avg_sample_taken &&
                task_ctx->runtime_avg >= (RUNTIME_PRIO_BOUNDARY_INTERACTIVE + ((RUNTIME_PRIO_BOUNDARY_INTERACTIVE * RUNTIME_THRESH_PERCENT) / 100))) ||
               task_ctx->vlag < VLAG_DEMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_NORMAL;
      }
      break;
    case DSQ_TYPE_NORMAL:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= (RUNTIME_PRIO_BOUNDARY_INTERACTIVE)) && task_ctx->vlag > VLAG_PROMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      else if ((task_ctx->first_runtime_avg_sample_taken &&
                task_ctx->runtime_avg >= (RUNTIME_PRIO_BOUNDARY_NORMAL + ((RUNTIME_PRIO_BOUNDARY_NORMAL * RUNTIME_THRESH_PERCENT) / 100))) ||
               task_ctx->vlag < VLAG_DEMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_BATCH;
      }
      break;
    case DSQ_TYPE_BATCH:
      if (task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= (RUNTIME_PRIO_BOUNDARY_NORMAL) && task_ctx->vlag > VLAG_PROMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_NORMAL;
      }
      break;
    case DSQ_TYPE_GREEDY:
      if (((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= RUNTIME_PRIO_BOUNDARY_BATCH) ||
           (!task_ctx->first_runtime_avg_sample_taken && task_ctx->current_runtime <= RUNTIME_PRIO_BOUNDARY_BATCH)) &&
          task_ctx->vlag > VLAG_PROMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_BATCH;
      }
      break;
  }
  if (task_ctx->current_dsq_type != DSQ_TYPE_GREEDY)
  {
    if (((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg >= RUNTIME_PRIO_BOUNDARY_BATCH + ((RUNTIME_PRIO_BOUNDARY_BATCH * RUNTIME_THRESH_PERCENT) / 100)) ||
         (!task_ctx->first_runtime_avg_sample_taken &&
          task_ctx->current_runtime >= RUNTIME_PRIO_BOUNDARY_BATCH + ((RUNTIME_PRIO_BOUNDARY_BATCH * RUNTIME_THRESH_PERCENT) / 100))) &&
        task_ctx->vlag < VLAG_DEMOTE_THRESH)
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

  return 0;
}

s32 BPF_STRUCT_OPS(lunar_init_task, struct task_struct* p, struct scx_init_task_args* args)
{
  u64 now = bpf_ktime_get_ns();
  struct task_ctx context_temp = {.runtime_avg = AVG_RUNTIME_START,
                                  .current_runtime = 0,
                                  .current_dsq_type = DSQ_TYPE_GREEDY,
                                  .vlag = 200 * NS_PER_US,
                                  .last_yield_timestamp = now,
                                  .first_runtime_avg_sample_taken = false};

  u32 pid = p->pid;
  long ret = bpf_map_update_elem(&task_ctx_map, &pid, &context_temp, BPF_ANY);
  if (ret)
  {
    return ret;
  }

  return ret;
}

void BPF_STRUCT_OPS(
  lunar_exit_task,
  struct task_struct* p,
  struct scx_exit_task_args* args)
{
  u32 pid = p->pid;
  bpf_map_delete_elem(&task_ctx_map, &pid);
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

void BPF_STRUCT_OPS(
  lunar_enqueue,
  struct task_struct* p,
  u64 enq_flags)
{
  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return;

  if (enq_flags & SCX_ENQ_WAKEUP)
  {
    creditVlag(context);
  }

  u64 dsqType = context ? context->current_dsq_type : QUEUE_START;
  u32 cpu = scx_bpf_task_cpu(p);
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

  u64 task_slice = tctx->last_run_granted_slice;
  u64 remaining = task->scx.slice;

  u64 used_ns = (remaining >= task_slice) ? 0 : (task_slice - remaining);

  tctx->vlag -= (s64)used_ns;
  if (tctx->vlag < VLAG_MIN)
    tctx->vlag = VLAG_MIN;

  if (!runnable)
  {
    tctx->last_yield_timestamp = now;
  }

  update_task_prio(task, tctx, used_ns, runnable);
}

void BPF_STRUCT_OPS(
  lunar_exit,
  struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(lunar_ops,
               .init = (void*)lunar_init,
               .init_task = (void*)lunar_init_task,
               .exit_task = (void*)lunar_exit_task,
               .select_cpu = (void*)lunar_select_cpu,
               .enqueue = (void*)lunar_enqueue,
               .dispatch = (void*)lunar_dispatch,
               .stopping = (void*)lunar_stopping,
               .exit = (void*)lunar_exit,
               .name = "scx_lunar");
