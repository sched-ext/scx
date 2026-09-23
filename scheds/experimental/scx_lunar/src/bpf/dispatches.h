// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

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

    u64 dsq = get_cpu_dsq_from_type(dsqType, other);

    if (scx_bpf_dsq_nr_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0))
      return dsqType;
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline u64 most_starved_tier(
  struct dispatch_ctx* dctx,
  u32 cpu,
  u64 now)
{
  if (now - dctx->last_override_ts < STARVE_OVERRIDE_COOLDOWN_NS)
    return DSQ_TYPE_EMPTY;

  u64 worst_type = DSQ_TYPE_EMPTY;
  s64 worst_overrun = 0;
  u64 dsq;
  s64 overrun;

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_INTERACTIVE, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_INTERACTIVE]) - (s64)STARVE_BUDGET_INTERACTIVE_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_INTERACTIVE;
    }
  }

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_NORMAL, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_NORMAL]) - (s64)STARVE_BUDGET_NORMAL_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_NORMAL;
    }
  }

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_GREEDY, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_GREEDY]) - (s64)STARVE_BUDGET_GREEDY_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_GREEDY;
    }
  }

  return worst_type;
}

static __always_inline bool take_from_local_tier(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now)
{
  u64 dsq = get_cpu_dsq_from_type(dsqType, cpu);
  if (dctx)
    stamp_tier_head_ts(dctx, dsqType, now);

  return scx_bpf_dsq_nr_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0);
}

static __always_inline bool take_from_other_tier(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now, bool thisLLC)
{
  if (dctx)
    stamp_tier_head_ts(dctx, dsqType, now);

  return try_acquire_task_from_other_cpu(dsqType, cpu, thisLLC) != DSQ_TYPE_EMPTY;
}

static __always_inline u64 dispatch_dsq_per_cpu(u32 cpu)
{
  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  u64 now = bpf_ktime_get_ns();
  if (dctx)
  {
    u64 starved = most_starved_tier(dctx, cpu, now);
    if (starved != DSQ_TYPE_EMPTY)
    {
      u64 dsq = get_cpu_dsq_from_type(starved, cpu);
      dctx->tier_head_ts[starved] = now;
      if (scx_bpf_dsq_nr_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0))
      {
        dctx->last_override_ts = now;
        dctx->pending_override = true;
        return starved;
      }
    }
  }

  if (take_from_local_tier(dctx, DSQ_TYPE_LC, cpu, now))
  {
    return DSQ_TYPE_LC;
  }
  if (take_from_local_tier(dctx, DSQ_TYPE_INTERACTIVE, cpu, now))
  {
    return DSQ_TYPE_INTERACTIVE;
  }
  if (take_from_local_tier(dctx, DSQ_TYPE_NORMAL, cpu, now))
  {
    return DSQ_TYPE_NORMAL;
  }
  if (take_from_local_tier(dctx, DSQ_TYPE_GREEDY, cpu, now))
  {
    return DSQ_TYPE_GREEDY;
  }

  if (take_from_other_tier(dctx, DSQ_TYPE_LC, cpu, now, true))
  {
    return DSQ_TYPE_LC;
  }
  if (take_from_other_tier(dctx, DSQ_TYPE_INTERACTIVE, cpu, now, true))
  {
    return DSQ_TYPE_INTERACTIVE;
  }
  if (take_from_other_tier(dctx, DSQ_TYPE_NORMAL, cpu, now, true))
  {
    return DSQ_TYPE_NORMAL;
  }
  if (take_from_other_tier(dctx, DSQ_TYPE_GREEDY, cpu, now, true))
  {
    return DSQ_TYPE_GREEDY;
  }

  if (nr_llcs > 1)
  {
    if (take_from_other_tier(dctx, DSQ_TYPE_LC, cpu, now, false))
    {
      return DSQ_TYPE_LC;
    }

    if (take_from_other_tier(dctx, DSQ_TYPE_INTERACTIVE, cpu, now, false))
    {
      return DSQ_TYPE_INTERACTIVE;
    }

    if (take_from_other_tier(dctx, DSQ_TYPE_NORMAL, cpu, now, false))
    {
      return DSQ_TYPE_NORMAL;
    }

    if (take_from_other_tier(dctx, DSQ_TYPE_GREEDY, cpu, now, false))
    {
      return DSQ_TYPE_GREEDY;
    }
  }

  return DSQ_TYPE_EMPTY;
}

#endif  // DISPATCHES_H
