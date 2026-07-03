#include <scx/common.bpf.h>
//#include <bpf_experimental.h>
#include "defines.h"
#include "helpers.h"
#include "datatypes.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static __always_inline u64 dispatch_with_fallback(
  u32 cpu,
  struct dispatch_ctx* ctx)
{
  switch (schedulerMode)
  {
    case SCHED_MODE_DSQ_PER_LLC:
    {
      u32 llc = cpu_llc_id(cpu);
      return dispatch_dsq_per_llc(llc, ctx);
      break;
    }

    case SCHED_MODE_DSQ_PER_CPU:
      return dispatch_dsq_per_cpu(cpu, ctx);
      break;
  }

  return DSQ_TYPE_EMPTY;
}

static __always_inline void update_task_dsq_type(
  struct task_struct* task,
  struct task_ctx* task_ctx,
  struct dispatch_ctx* dispatch_ctx)
{
  if (!is_kthread(task) && isSpammer(task_ctx))
  {
    task_ctx->current_dsq_type = DSQ_TYPE_GREEDY;
    return;
  }

  switch (task_ctx->current_dsq_type)
  {
    case DSQ_TYPE_LC:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg >= (RUNTIME_PRIO_BOUNDARY_LC + RUNTIME_THRESH)) ||
          task_ctx->vlag < VLAG_DEMOTE_THRESH /* && !task_ctx->boostUntilYield*/)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      break;
    case DSQ_TYPE_INTERACTIVE:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= (RUNTIME_PRIO_BOUNDARY_LC)) &&
          task_ctx->vlag > VLAG_PROMOTE_THRESH /* && task_ctx->vlag > VLAG_PROMOTE_THRESH && !task_ctx->boostUntilYield*/)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_LC;
      }
      else if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg >= (RUNTIME_PRIO_BOUNDARY_INTERACTIVE + RUNTIME_THRESH)) ||
               task_ctx->vlag < VLAG_DEMOTE_THRESH /* && !task_ctx->boostUntilYield*/)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_NORMAL;
      }
      break;
    case DSQ_TYPE_NORMAL:
      if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg <= (RUNTIME_PRIO_BOUNDARY_INTERACTIVE)) &&
          task_ctx->vlag > VLAG_PROMOTE_THRESH /*&& !task_ctx->boostUntilYield*/)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
      }
      else if ((task_ctx->first_runtime_avg_sample_taken && task_ctx->runtime_avg >= (RUNTIME_PRIO_BOUNDARY_NORMAL + RUNTIME_THRESH)) ||
               task_ctx->vlag < VLAG_DEMOTE_THRESH /* && !task_ctx->boostUntilYield*/)
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
      if (((task_ctx->first_runtime_avg_sample_taken && (task_ctx->runtime_avg / dispatch_ctx->runtime_avg) <= ACCEPTABLE_MULTIPLICATOR) ||
           (!task_ctx->first_runtime_avg_sample_taken && (task_ctx->current_runtime / dispatch_ctx->runtime_avg) <= ACCEPTABLE_MULTIPLICATOR)) &&
          task_ctx->vlag > VLAG_PROMOTE_THRESH)
      {
        task_ctx->current_dsq_type = DSQ_TYPE_BATCH;
      }
      break;
  }
  if (task_ctx->current_dsq_type != DSQ_TYPE_SOFT && task_ctx->current_dsq_type != DSQ_TYPE_GREEDY)
  {
    if (((task_ctx->first_runtime_avg_sample_taken && (task_ctx->runtime_avg / dispatch_ctx->runtime_avg) > GREEDY_MULTIPLICATOR) ||
         (!task_ctx->first_runtime_avg_sample_taken && (task_ctx->current_runtime / dispatch_ctx->runtime_avg) > GREEDY_MULTIPLICATOR)) &&
        task_ctx->vlag < VLAG_DEMOTE_THRESH)
    {
      task_ctx->current_dsq_type = DSQ_TYPE_GREEDY;
    }
  }
}

static __always_inline void update_task_prio(struct task_struct* task, struct task_ctx* task_ctx, struct dispatch_ctx* dispatch_ctx, u64 used_ns, bool runnable)
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
    }
    else
    {
      task_ctx->runtime_avg = (task_ctx->runtime_avg * (HISTORIC_TASK_SAMPLES - 1) + task_ctx->current_runtime) / HISTORIC_TASK_SAMPLES;
    }
    // if (task_ctx->runtime_avg > AVG_RUNTIME_MAX)
    // {
    //   task_ctx->runtime_avg = AVG_RUNTIME_MAX;
    // }
    task_ctx->current_runtime = 0;
    // task_ctx->boostUntilYield = false;
    //  task_ctx->current_dsq_type = task_ctx->dsq_type_before_boost;
    task_ctx->first_runtime_avg_sample_taken = true;
  }
  if (task_ctx->runtime_avg < MIN_AVG_RUNTIME)
  {
    task_ctx->runtime_avg = MIN_AVG_RUNTIME;
  }

  update_task_dsq_type(task, task_ctx, dispatch_ctx);
}

// callbacks

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init)
{
  s32 ret;

  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 cpu;
  bpf_for(cpu, 0, nr_cpu_ids)
  {
    u32 key = 0;
    struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
    if (!dispatch_ctx)
      return -EINVAL;

    // ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_HARD + cpu, -1);
    // if (ret)
    //   return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_SOFT + cpu, -1);
    if (ret)
      return ret;
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

    dispatch_ctx->runtime_avg = AVG_RUNTIME_START;
  }
  u32 llc;
  bpf_for(llc, 0, nr_llcs)
  {
    // ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_HARD + llc, -1);
    // if (ret)
    //   return ret;
    ret = scx_bpf_create_dsq(DSQ_LLC_QUEUE_BASE_SOFT + llc, -1);
    if (ret)
      return ret;
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
                                  .current_dsq_type = DSQ_TYPE_BATCH,
                                  .vlag = 0,
                                  .last_yield_timestamp = now,
                                  .first_runtime_avg_sample_taken = false,
                                  .last_spawn_timestamp = now,
                                  .task_spawn_interval_avg = 0};

  u32 pid = p->pid;
  long ret = bpf_map_update_elem(&task_ctx_map, &pid, &context_temp, BPF_ANY);
  if (ret)
  {
    return ret;
  }

  struct task_ctx* context = get_task_ctx(p);
  if (!context)
  {
    return 0;
  }
  if (args && args->fork)
  {
    struct task_struct* spawner;
    if (p->pid != p->tgid)
      spawner = p->group_leader; /* pthread_create & friends */
    else
      spawner = p->real_parent; /* fork/exec of a new process */

    if (spawner)
    {
      struct task_ctx* pctx = get_task_ctx(spawner);
      if (pctx)
      {
        u64 now = bpf_ktime_get_ns();
        u64 last = __sync_lock_test_and_set(&pctx->last_spawn_timestamp, now);

        if (last)
        {  // skip the very first spawn
          u64 interval = now - last;
          if (!pctx->task_spawn_interval_avg)
            pctx->task_spawn_interval_avg = interval;
          else
            pctx->task_spawn_interval_avg = (pctx->task_spawn_interval_avg * (HISTORIC_SPAWN_SAMPLES - 1) + interval) / HISTORIC_SPAWN_SAMPLES;
        }
      }
      if (/*!is_kthread(p) &&*/ !is_kthread(p) && isSpammer(pctx))
      {
        context->current_dsq_type = DSQ_TYPE_GREEDY;
        /* inherit the lineage's spawn stats so the flag survives generations */
        context->task_spawn_interval_avg = pctx->task_spawn_interval_avg;
        context->last_spawn_timestamp = pctx->last_spawn_timestamp;
      }
    }
  }

  return ret;
}

void BPF_STRUCT_OPS(lunar_exit_task, struct task_struct* p, struct scx_exit_task_args* args)
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
  u32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &isIdle);

  if (isIdle && (context->current_dsq_type != DSQ_TYPE_GREEDY || !context->first_runtime_avg_sample_taken) && !isSpammer(context))
  {
    creditVlag(context);
    scx_bpf_dsq_insert(p, DEFAULT_DSQ_LOCAL_ON | cpu, get_dsq_task_slice(context->current_dsq_type), 0);
  }
  return cpu;
}

void BPF_STRUCT_OPS(lunar_enqueue, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return;

  // struct task_struct* waker = bpf_get_current_task_btf();
  // if (!waker)
  //   return;

  // struct task_ctx* waker_ctx = get_task_ctx(waker);

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, bpf_get_smp_processor_id());
  if (!dispatch_ctx)
    return;

  if (enq_flags & SCX_ENQ_WAKEUP)
  {
    // if ((bpf_in_hardirq() || bpf_in_nmi()) && !bpf_in_serving_softirq())
    // {
    //   context->dsq_type_before_boost = context->current_dsq_type;
    //   context->current_dsq_type = DSQ_TYPE_HARD;
    //   context->boostUntilYield = true;
    // }
    // else if (bpf_in_serving_softirq() || is_ksoftirqd(waker) || is_RT_task(waker) || is_RT_task(p))
    // {
    //   context->dsq_type_before_boost = context->current_dsq_type;
    //   context->current_dsq_type = DSQ_TYPE_SOFT;
    //   context->boostUntilYield = true;
    // }
    // else if (context->current_dsq_type >= DSQ_TYPE_LC && (is_high_prio_task(p) || is_high_prio_task(waker)))
    // {
    //   context->dsq_type_before_boost = context->current_dsq_type;
    //   context->current_dsq_type = DSQ_TYPE_LC;
    //   context->boostUntilYield = true;
    // }

    // else if (context->current_dsq_type >= DSQ_TYPE_INTERACTIVE)
    // {
    //   context->dsq_type_before_boost = context->current_dsq_type;
    //   context->current_dsq_type = DSQ_TYPE_INTERACTIVE;
    //   context->boostUntilYield = true;
    // }

    if (is_high_prio_kthread_task(p))
    {
      // context->dsq_type_before_boost = context->current_dsq_type;
      context->current_dsq_type = DSQ_TYPE_SOFT;
      // context->boostUntilYield = true;
    }

    creditVlag(context);
    //  if (waker_ctx->current_dsq_type == DSQ_TYPE_GREEDY && (context->current_dsq_type != DSQ_TYPE_HARD && context->current_dsq_type != DSQ_TYPE_GREEDY))
    //  {
    //    context->current_dsq_type = DSQ_TYPE_GREEDY;
    //    context->boostUntilYield = true;
    //  }
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

  scx_bpf_dsq_insert(p, dsq, get_dsq_task_slice(dsqType), enq_flags);
}

void BPF_STRUCT_OPS(
  lunar_dispatch,
  s32 cpu,
  struct task_struct* prev)
{
  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dispatch_ctx)
    return;

  u64 dispatched_to = dispatch_with_fallback(cpu, dispatch_ctx);
}

void BPF_STRUCT_OPS(
  lunar_stopping,
  struct task_struct* task,
  bool runnable)
{
  if (!task)
  {
    return;
  }
  struct task_ctx* tctx = get_task_ctx(task);
  if (!tctx)
    return;

  u32 key = 0;
  struct dispatch_ctx* dispatch_ctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, bpf_get_smp_processor_id());
  if (!dispatch_ctx)
    return;

  u64 task_slice = get_dsq_task_slice(tctx->current_dsq_type);
  u64 remaining = task->scx.slice;

  u64 used_ns = (remaining >= task_slice) ? 0 : (task_slice - remaining);

  tctx->vlag -= (s64)used_ns;
  if (tctx->vlag < VLAG_MIN)
    tctx->vlag = VLAG_MIN;

  if (!runnable)
  {
    tctx->last_yield_timestamp = bpf_ktime_get_ns();
  }

  update_task_prio(task, tctx, dispatch_ctx, used_ns, runnable);
  dispatch_ctx->runtime_avg = (dispatch_ctx->runtime_avg * (HISTORIC_CPU_SAMPLES - 1) + tctx->runtime_avg) / HISTORIC_CPU_SAMPLES;
  if (dispatch_ctx->runtime_avg > MAX_AVG_RUNTIME_PER_CPU)
  {
    dispatch_ctx->runtime_avg = MAX_AVG_RUNTIME_PER_CPU;
  }
}

// void BPF_STRUCT_OPS(
//   lunar_running,
//   struct task_struct* p)
// {
//   // struct task_ctx* task = get_task_ctx(p);
//   // if (!task)
//   //   return;

//   // char comm[16];
//   // bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);

//   // // bool boosted = task->boostUntilYield;

//   // // char comm[16];
//   // bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);

//   // bpf_printk("TCTX comm=%s dsq=%llu ravg=%llu", comm, task->current_dsq_type, task->runtime_avg);

//   // bpf_printk("TCTX cur_rt=%llu last_yield=%llu vlag=%lld", task->current_runtime, task->last_yield_timestamp, task->vlag);

//   // bpf_printk("TCTX first_sample=%d boost=%d spawn_avg=%llu", (int)task->first_runtime_avg_sample_taken, (int)task->boostUntilYield, task->task_spawn_interval_avg);

//   // bpf_printk("TCTX last_spawn=%llu \n", task->last_spawn_timestamp);
// }

void BPF_STRUCT_OPS(
  lunar_exit,
  struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(lunar_ops,
               .init = (void*)lunar_init,
               .init_task = (void*)lunar_init_task,
               //.running = (void*)lunar_running,
               .exit_task = (void*)lunar_exit_task,
               .select_cpu = (void*)lunar_select_cpu,
               .enqueue = (void*)lunar_enqueue,
               .dispatch = (void*)lunar_dispatch,
               .stopping = (void*)lunar_stopping,
                .exit = (void*)lunar_exit,
               .name = "scx_lunar");
