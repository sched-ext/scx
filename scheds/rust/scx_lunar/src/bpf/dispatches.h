#ifndef DISPATCHES_H
#define DISPATCHES_H
#include "defines.h"
#include "datatypes.h"
#include "helpers.h"

static __always_inline u64 try_acquire_task_from_other_cpu(u64 dsqType, u32 cpu, bool sameLLC)
{
  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu)
      continue;
    if (sameLLC && cpu_llc_id(other) != my_llc)
      continue;
    if (!sameLLC && cpu_llc_id(other) == my_llc)
      continue;

    if (scx_bpf_dsq_move_to_local(get_cpu_dsq_from_type(dsqType, other), 0))
      return dsqType;
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline u64 dispatch_dsq_per_cpu(u32 cpu, struct dispatch_ctx* ctx)
{
  // if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_HARD + cpu))
  // {
  //   return DSQ_TYPE_HARD;
  // }

  // if (try_acquire_task_from_other_cpu(DSQ_TYPE_HARD, cpu, true) != DSQ_TYPE_EMPTY)
  // {
  //   return DSQ_TYPE_HARD;
  // }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_SOFT + cpu, 0))
  {
    return DSQ_TYPE_SOFT;
  }

  if (try_acquire_task_from_other_cpu(DSQ_TYPE_SOFT, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_SOFT;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_LC + cpu, 0))
  {
    return DSQ_TYPE_LC;
  }

  if (try_acquire_task_from_other_cpu(DSQ_TYPE_LC, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_LC;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu, 0))
  {
    return DSQ_TYPE_INTERACTIVE;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_INTERACTIVE, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_INTERACTIVE;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_NORMAL + cpu, 0))
  {
    return DSQ_TYPE_NORMAL;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_NORMAL, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_NORMAL;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_BATCH + cpu, 0))
  {
    return DSQ_TYPE_BATCH;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_BATCH, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_BATCH;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_GREEDY + cpu, 0))
  {
    return DSQ_TYPE_GREEDY;
  }

  if (try_acquire_task_from_other_cpu(DSQ_TYPE_GREEDY, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_GREEDY;
  }

  if (nr_llcs > 1)
  {
    // if (try_acquire_task_from_other_cpu(DSQ_TYPE_HARD, cpu, false) != DSQ_TYPE_EMPTY)
    // {
    //   return DSQ_TYPE_HARD;
    // }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_SOFT, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_SOFT;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_LC, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_LC;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_INTERACTIVE, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_INTERACTIVE;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_NORMAL, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_NORMAL;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_BATCH, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_BATCH;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_GREEDY, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_GREEDY;
    }
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline u64 try_acquire_task_from_other_llc(u64 dsqType, u32 currentLLc)
{
  u32 llcs = nr_llcs;
  u32 start = bpf_get_prandom_u32() % llcs;
  u32 i;

  bpf_for(i, 0, llcs)
  {
    u32 other = (start + i) % llcs;
    if (other == currentLLc)
      continue;

    if (scx_bpf_dsq_move_to_local(get_llc_dsq_from_type(dsqType, other), 0))
      return dsqType;
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline u64 dispatch_dsq_per_llc(u32 llc, struct dispatch_ctx* ctx)
{
  // if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_HARD + llc))
  // {
  //   return DSQ_TYPE_HARD;
  // }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_SOFT + llc, 0))
  {
    return DSQ_TYPE_SOFT;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_LC + llc, 0))
  {
    return DSQ_TYPE_LC;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_INTERACTIVE + llc, 0))
  {
    return DSQ_TYPE_INTERACTIVE;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_NORMAL + llc, 0))
  {
    return DSQ_TYPE_NORMAL;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_BATCH + llc, 0))
  {
    return DSQ_TYPE_BATCH;
  }

  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE_GREEDY + llc, 0))
  {
    return DSQ_TYPE_GREEDY;
  }

  if (nr_llcs > 1)
  {
    // if (try_acquire_task_from_other_llc(DSQ_TYPE_HARD, llc) != DSQ_TYPE_EMPTY)
    // {
    //   return DSQ_TYPE_HARD;
    // }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_SOFT, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_SOFT;
    }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_LC, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_LC;
    }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_INTERACTIVE, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_INTERACTIVE;
    }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_NORMAL, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_NORMAL;
    }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_BATCH, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_BATCH;
    }

    if (try_acquire_task_from_other_llc(DSQ_TYPE_GREEDY, llc) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_GREEDY;
    }
  }

  return DSQ_TYPE_EMPTY;
}

#endif  // DISPATCHES_H
