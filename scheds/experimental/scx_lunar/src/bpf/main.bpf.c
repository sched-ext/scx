// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>
#include <bpf_experimental.h>
#include <bpf/bpf_helpers.h>
#include "defines.h"
#include "helpers.h"
#include "datatypes.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static __always_inline u64 tier_from_crit(s64 crit)
{
  if (crit >= CRIT_EDGE_LC)
    return DSQ_TYPE_LC;
  if (crit >= CRIT_EDGE_INTERACTIVE)
    return DSQ_TYPE_INTERACTIVE;
  if (crit >= CRIT_EDGE_NORMAL)
    return DSQ_TYPE_NORMAL;
  return DSQ_TYPE_GREEDY;
}

static __always_inline u64 tier_cap_from_duty(s64 duty)
{
  if (duty < DUTY_CAP_LC)
    return DSQ_TYPE_LC;
  if (duty < DUTY_CAP_INTERACTIVE)
    return DSQ_TYPE_INTERACTIVE;
  if (duty < DUTY_CAP_NORMAL)
    return DSQ_TYPE_NORMAL;
  return DSQ_TYPE_GREEDY;
}

static __always_inline u64 target_tier(s64 crit, s64 duty)
{
  u64 wanted = tier_from_crit(crit);
  u64 allowed = tier_cap_from_duty(duty);
  return wanted > allowed ? wanted : allowed;
}

static __always_inline u64 sanitize_tier(u64 tier)
{
  if (tier < DSQ_TYPE_LC || tier > DSQ_TYPE_GREEDY)
    return DSQ_TYPE_GREEDY;
  return tier;
}

static __always_inline void update_task_dsq_type(struct task_struct* task, struct task_ctx* tctx, u64 now)
{
  u64 old = tctx->current_dsq_type;

  tctx->crit = calc_crit(tctx, now);

  if (tctx->duty_samples < DUTY_SAMPLES_NEEDED)
  {
    tctx->current_dsq_type = DSQ_TYPE_GREEDY;
  }
  else
  {
    // No hysteresis on crit, only on duty.
    s64 crit = tctx->crit;
    u64 pessimistic = target_tier(crit, tctx->duty + DUTY_HYST);
    u64 optimistic = target_tier(crit, tctx->duty - DUTY_HYST);

    if (pessimistic < old)
      tctx->current_dsq_type = pessimistic;
    else if (optimistic > old)
      tctx->current_dsq_type = optimistic;
  }
}

static __always_inline void record_waker(struct task_struct* p, u64 now)
{
  if (bpf_in_interrupt())
    return;

  struct task_struct* waker = bpf_get_current_task_btf();
  if (waker->pid == p->pid)
    return;

  struct task_ctx* wctx = get_task_ctx(waker);
  if (!wctx)
    return;

  wctx->wake_interval = exponentially_weighted_moving_avg(wctx->wake_interval, clamp_interval(elapsed(now, wctx->last_wake_at)));
  wctx->last_wake_at = now;
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
    struct dispatch_ctx* dispatch_ctx = get_dispatch_ctx(cpu);
    if (!dispatch_ctx)
      return -ENOMEM;

    dispatch_ctx->current_task_dsq_type = DSQ_TYPE_EMPTY;

    u64 now = bpf_ktime_get_ns();
    dispatch_ctx->tier_head_ts[DSQ_TYPE_INTERACTIVE] = now;
    dispatch_ctx->tier_head_ts[DSQ_TYPE_NORMAL] = now;
    dispatch_ctx->tier_head_ts[DSQ_TYPE_GREEDY] = now;
    dispatch_ctx->last_override_ts = now;
    dispatch_ctx->preempt_pending = false;
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
  tctx->granted_slice = 0;
  tctx->resume_slice = 0;
  tctx->last_migrated_at = 0;

  tctx->wait_interval = CRIT_INTERVAL_REF;
  tctx->wake_interval = CRIT_INTERVAL_REF;
  tctx->last_woken_at = now;
  tctx->last_wake_at = now;
  tctx->crit = 0;
  tctx->duty = DUTY_RANGE / 2;

  return 0;
}

void BPF_STRUCT_OPS(lunar_exit_task, struct task_struct* p, struct scx_exit_task_args* args) { }

s32 BPF_STRUCT_OPS(lunar_select_cpu, struct task_struct* p, s32 prev_cpu, u64 wake_flags)
{
  bool is_idle = false;
  s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

  if (is_idle)
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_NS, 0);

  return cpu;
}

void BPF_STRUCT_OPS(lunar_enqueue, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 tier = tctx ? sanitize_tier(tctx->current_dsq_type) : DSQ_TYPE_GREEDY;
  u32 cpu = scx_bpf_task_cpu(p);
  u64 now = bpf_ktime_get_ns();

  if (tctx && tctx->resume_slice)
  {
    u64 slice = tctx->resume_slice;
    u64 own_dsq = get_cpu_dsq_from_type(tier, cpu);
    struct dispatch_ctx* own = get_dispatch_ctx(cpu);
    tctx->resume_slice = 0;
    if (own && tier != DSQ_TYPE_LC && dsq_queued(own_dsq) == 0)
      stamp_tier_head_ts(own, tier, now);
    scx_bpf_dsq_insert(p, own_dsq, slice, enq_flags | SCX_ENQ_HEAD);
    return;
  }

  u32 target = tctx ? (u32)pick_enqueue_cpu(p, tctx, tier, cpu, now) : cpu;
  u64 dsq = get_cpu_dsq_from_type(tier, target);
  struct dispatch_ctx* dctx = get_dispatch_ctx(target);

  if (dctx && tier != DSQ_TYPE_LC && dsq_queued(dsq) == 0)
    stamp_tier_head_ts(dctx, tier, now);

  scx_bpf_dsq_insert(p, dsq, SLICE_NS, enq_flags);

  if (!dctx)
  {
    scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
    return;
  }

  u64 running = dctx->current_task_dsq_type;
  if (running == DSQ_TYPE_EMPTY)
  {
    scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
  }
  else if (tier == DSQ_TYPE_LC && (enq_flags & SCX_ENQ_WAKEUP) && running > tier)
  {
    dctx->preempt_pending = true;
    scx_bpf_kick_cpu(target, SCX_KICK_PREEMPT);
  }
}

void BPF_STRUCT_OPS(lunar_dispatch, s32 cpu, struct task_struct* prev)
{
  dispatch_dsq_per_cpu(cpu);
}

void BPF_STRUCT_OPS(lunar_running, struct task_struct* p)
{
  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return;

  u32 cpu = bpf_get_smp_processor_id();
  struct dispatch_ctx* dispatch_ctx = get_dispatch_ctx(cpu);
  if (!dispatch_ctx)
    return;

  dispatch_ctx->current_task_dsq_type = sanitize_tier(context->current_dsq_type);
  dispatch_ctx->preempt_pending = false;

  context->started_at = bpf_ktime_get_ns();
  context->granted_slice = p->scx.slice;

  // bpf_printk("lunar_run cpu=%d pid=%d tgid=%d comm=%s dsqType=%llu duty=%lld crit=%d ", bpf_get_smp_processor_id(), p->pid, p->tgid, p->comm, context->current_dsq_type,
  //            context->duty, context->crit);
}

void BPF_STRUCT_OPS(lunar_stopping, struct task_struct* task, bool runnable)
{
  u64 now = bpf_ktime_get_ns();

  struct task_ctx* tctx = get_task_ctx(task);
  if (!tctx)
    return;

  u64 used_ns = elapsed(now, tctx->started_at);

  duty_account(tctx, used_ns, 0);
  tctx->duty = task_duty(tctx);

  update_task_dsq_type(task, tctx, now);

  struct dispatch_ctx* dctx = get_dispatch_ctx(bpf_get_smp_processor_id());
  if (!dctx)
    return;

  if (dctx->preempt_pending && runnable && tctx->granted_slice > used_ns + RESUME_SLICE_MIN_NS)
    tctx->resume_slice = tctx->granted_slice - used_ns;

  dctx->preempt_pending = false;
  dctx->current_task_dsq_type = DSQ_TYPE_EMPTY;
}

void BPF_STRUCT_OPS(lunar_exit, struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(lunar_quiescent, struct task_struct* p, u64 deq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  if (!tctx)
    return;

  tctx->resume_slice = 0;
  tctx->blocked_at = (deq_flags & SCX_DEQ_SLEEP) ? bpf_ktime_get_ns() : 0;
}

void BPF_STRUCT_OPS(lunar_runnable, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 now = bpf_ktime_get_ns();

  if (!tctx)
    return;

  if (enq_flags & SCX_ENQ_WAKEUP)
  {
    tctx->wait_interval = exponentially_weighted_moving_avg(tctx->wait_interval, clamp_interval(elapsed(now, tctx->last_woken_at)));
    tctx->last_woken_at = now;
    record_waker(p, now);
  }

  if (tctx->blocked_at)
  {
    duty_account(tctx, 0, elapsed(now, tctx->blocked_at));
    tctx->duty_samples++;
    if (tctx->duty_samples > DUTY_SAMPLES_MAX)
    {
      tctx->duty_samples = DUTY_SAMPLES_MAX;
    }
    tctx->blocked_at = 0;
    tctx->duty = task_duty(tctx);
    update_task_dsq_type(p, tctx, now);
  }
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
