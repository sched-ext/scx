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

// ---------------------------------------------------------------------------
// Placement (enqueue side)
// ---------------------------------------------------------------------------

static __always_inline u64 cpu_load_ahead(u32 cpu, u64 tier)
{
  u64 load = 0;

  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);
  if (dctx && dctx->current_task_dsq_type <= tier)
    load++;

  load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_LC, cpu));
  if (tier >= DSQ_TYPE_INTERACTIVE)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_INTERACTIVE, cpu));
  if (tier >= DSQ_TYPE_NORMAL)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_NORMAL, cpu));
  if (tier >= DSQ_TYPE_GREEDY)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_GREEDY, cpu));

  return load;
}

static __always_inline s32 pick_enqueue_cpu(struct task_struct* p, struct task_ctx* tctx, u64 tier, u32 cpu, u64 now)
{
  u64 best_load = cpu_load_ahead(cpu, tier);
  if (best_load == 0)
    return cpu;

  if (p->nr_cpus_allowed == 1)
    return cpu;

  s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
  if (idle >= 0)
  {
    if ((u32)idle != cpu)
      tctx->last_migrated_at = now;
    return idle;
  }

  bool latency_tier = tier <= DSQ_TYPE_INTERACTIVE;
  if (!latency_tier && now - tctx->last_migrated_at < BALANCE_INTERVAL_NS)
    return cpu;

  u32 key = 0;
  struct pick_scratch* sc = bpf_map_lookup_elem(&pick_scratch_map, &key);
  if (!sc)
    return cpu;

  sc->best_load = best_load;
  sc->best = cpu;
  sc->sampled = 0;

  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 budget = latency_tier ? nr_cpu_ids : BALANCE_SAMPLES;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu || cpu_llc_id(other) != my_llc)
      continue;
    if (!bpf_cpumask_test_cpu(other, p->cpus_ptr))
      continue;

    u64 load = cpu_load_ahead(other, tier);
    if (load < sc->best_load)
    {
      sc->best_load = load;
      sc->best = other;
      if (load == 0)
        break;
    }
    sc->sampled++;
    if (sc->sampled >= budget)
      break;
  }

  if ((u32)sc->best != cpu)
    tctx->last_migrated_at = now;
  return sc->best;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

static __always_inline u64 try_acquire_task_from_other_cpu(u64 dsqType, u32 cpu, bool sameLLC, u64 now)
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

    if (dsq_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0))
    {
      struct dispatch_ctx* victim = get_dispatch_ctx(other);
      if (victim)
        stamp_tier_head_ts(victim, dsqType, now);
      return dsqType;
    }
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline s64 tier_overrun(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now, u64 budget)
{
  if (!dsq_queued(get_cpu_dsq_from_type(dsqType, cpu)))
    return 0;
  return (s64)(now - dctx->tier_head_ts[dsqType]) - (s64)budget;
}

static __always_inline u64 most_starved_tier(struct dispatch_ctx* dctx, u32 cpu, u64 now)
{
  if (now - dctx->last_override_ts < STARVE_OVERRIDE_COOLDOWN_NS)
    return DSQ_TYPE_EMPTY;

  u64 worst_type = DSQ_TYPE_EMPTY;
  s64 worst_overrun = 0;
  s64 overrun;

  overrun = tier_overrun(dctx, DSQ_TYPE_INTERACTIVE, cpu, now, STARVE_BUDGET_INTERACTIVE_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_INTERACTIVE;
  }

  overrun = tier_overrun(dctx, DSQ_TYPE_NORMAL, cpu, now, STARVE_BUDGET_NORMAL_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_NORMAL;
  }

  overrun = tier_overrun(dctx, DSQ_TYPE_GREEDY, cpu, now, STARVE_BUDGET_GREEDY_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_GREEDY;
  }

  return worst_type;
}

static __always_inline bool take_from_local_tier(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now)
{
  u64 dsq = get_cpu_dsq_from_type(dsqType, cpu);
  if (!dsq_queued(dsq) || !scx_bpf_dsq_move_to_local(dsq, 0))
    return false;

  if (dctx)
    stamp_tier_head_ts(dctx, dsqType, now);
  return true;
}

static __always_inline bool take_from_other_tier(u64 dsqType, u32 cpu, u64 now, bool thisLLC)
{
  return try_acquire_task_from_other_cpu(dsqType, cpu, thisLLC, now) != DSQ_TYPE_EMPTY;
}

static __always_inline u64 dispatch_dsq_per_cpu(u32 cpu)
{
  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);
  u64 now = bpf_ktime_get_ns();

  if (take_from_local_tier(dctx, DSQ_TYPE_LC, cpu, now))
    return DSQ_TYPE_LC;

  if (dctx)
  {
    u64 starved = most_starved_tier(dctx, cpu, now);
    if (starved != DSQ_TYPE_EMPTY && take_from_local_tier(dctx, starved, cpu, now))
    {
      dctx->last_override_ts = now;
      return starved;
    }
  }

  if (take_from_local_tier(dctx, DSQ_TYPE_INTERACTIVE, cpu, now))
    return DSQ_TYPE_INTERACTIVE;
  if (take_from_local_tier(dctx, DSQ_TYPE_NORMAL, cpu, now))
    return DSQ_TYPE_NORMAL;
  if (take_from_local_tier(dctx, DSQ_TYPE_GREEDY, cpu, now))
    return DSQ_TYPE_GREEDY;

  if (take_from_other_tier(DSQ_TYPE_LC, cpu, now, true))
    return DSQ_TYPE_LC;
  if (take_from_other_tier(DSQ_TYPE_INTERACTIVE, cpu, now, true))
    return DSQ_TYPE_INTERACTIVE;
  if (take_from_other_tier(DSQ_TYPE_NORMAL, cpu, now, true))
    return DSQ_TYPE_NORMAL;
  if (take_from_other_tier(DSQ_TYPE_GREEDY, cpu, now, true))
    return DSQ_TYPE_GREEDY;

  if (nr_llcs > 1)
  {
    if (take_from_other_tier(DSQ_TYPE_LC, cpu, now, false))
      return DSQ_TYPE_LC;
    if (take_from_other_tier(DSQ_TYPE_INTERACTIVE, cpu, now, false))
      return DSQ_TYPE_INTERACTIVE;
    if (take_from_other_tier(DSQ_TYPE_NORMAL, cpu, now, false))
      return DSQ_TYPE_NORMAL;
    if (take_from_other_tier(DSQ_TYPE_GREEDY, cpu, now, false))
      return DSQ_TYPE_GREEDY;
  }

  return DSQ_TYPE_EMPTY;
}

#endif  // DISPATCHES_H
