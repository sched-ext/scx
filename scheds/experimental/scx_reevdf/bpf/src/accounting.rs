// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The policy's arithmetic, as plain functions of numbers: nothing here
//! reads a task, the arena or the clock. The callbacks load the operands
//! and store the results, and `cargo test` runs this very file on the
//! host, from tests/accounting.rs.
//!
//! - Virtual time: a request and its deadline, update_deadline(); a task's
//!   lag and its bound, entity_lag(); what joining, leaving and charging do
//!   to a pack's reference, the weighted average vruntime of its members;
//!   the reference projected over the running task's uncharged service;
//!   the vruntime that places a task with a given lag, place_entity(); and
//!   the debt a task that blocked over-served still owes, DELAY_DEQUEUE.
//! - Load: the utilization and runnable estimates of a task and the load
//!   they give it, util_est_update() and task_h_load().
//! - Wakeups and forks: wake_wide() and wake_affine_weight(), and the
//!   order find_idlest_group() puts the groups of a fork domain in.
//! - The idle pull: the average idle period, the cost record of a pull and
//!   NI_RANDOM's sampling.
//! - Group scheduling: a cgroup's weight, its shares on a CID and the
//!   weight they leave a task with, __calc_prop_weight().
//!
//! BPF v3 has no signed division, so quotients of signed virtual-time
//! products divide magnitudes, vdiv(), and every divisor is checked, which
//! keeps panic paths out of the object.

/// The weight of a nice 0 task, NICE_0_LOAD after scale_load_down(): what
/// virtual time is measured in.
pub use crate::task::NICE_0_WEIGHT;

/// The lowest weight deadlines and lags are scaled by, a quarter of nice 0.
///
/// A task at the lowest weights would otherwise be issued deadlines and
/// carry lags thousands of requests away. Its vruntime is still charged at
/// its real weight, so its share is what nice asks for; only how far ahead
/// its deadline and lag can stretch is capped, as in scx_eevdf.
pub const MIN_DL_WEIGHT: u64 = NICE_0_WEIGHT / 4;

/// `request` ns of service in virtual time at `weight`, floored as above.
#[inline(always)]
pub fn scale_by_dl_weight(request: u64, weight: u64) -> u64 {
    request * NICE_0_WEIGHT / weight.max(MIN_DL_WEIGHT)
}

#[derive(Clone, Copy, Default)]
pub struct Request {
    pub deadline: u64,
    pub slice: u64,
    pub weight: u64,
}

impl Request {
    /// Issue a deadline for a request of `slice` ns at `weight` unless the
    /// current one is unfinished, update_deadline(). An `initial` request,
    /// the first of a forked task, asks for half, PLACE_DEADLINE_INITIAL:
    /// the tasks it joins are halfway through theirs on average. Returns
    /// whether a deadline was issued.
    #[inline(always)]
    pub fn prepare(&mut self, vtime: u64, slice: u64, weight: u64, initial: bool) -> bool {
        let weight = weight.max(MIN_DL_WEIGHT);
        let pending = self.slice != 0 && (vtime.wrapping_sub(self.deadline) as i64) < 0;
        let issued = self.slice != slice || !pending;
        if issued {
            let request = if initial { slice / 2 } else { slice };
            self.deadline = vtime.wrapping_add(scale_by_dl_weight(request, weight));
        } else if self.weight != weight {
            self.deadline =
                vtime.wrapping_add(self.deadline.wrapping_sub(vtime) * self.weight / weight);
        }
        self.slice = slice;
        self.weight = weight;
        issued
    }

    #[inline(always)]
    pub fn rebase(&mut self, old: u64, new: u64) {
        if self.slice != 0 && (old.wrapping_sub(self.deadline) as i64) < 0 {
            self.deadline = new.wrapping_add(self.deadline.wrapping_sub(old));
        } else {
            self.slice = 0;
        }
    }

    #[inline(always)]
    pub fn sleep(&mut self) {
        self.slice = 0;
    }
}

/// Divide a signed virtual-time product, truncating toward zero. A zero
/// divisor yields zero, which keeps panic paths out of the BPF object.
#[inline(always)]
pub fn vdiv(value: i64, divisor: u64) -> i64 {
    if divisor == 0 {
        0
    } else if value < 0 {
        -((value.unsigned_abs() / divisor) as i64)
    } else {
        (value as u64 / divisor) as i64
    }
}

/// The lag bound of fair.c's entity_lag(), for a task whose `request` is
/// already the larger of its own and the default, plus a tick.
#[inline(always)]
pub fn lag_limit(request: u64, weight: u64) -> i64 {
    scale_by_dl_weight(request, weight) as i64
}

/// The lag of a task at `vtime` against `reference`, clamped to `limit`.
#[inline(always)]
pub fn lag(reference: u64, vtime: u64, limit: i64) -> i64 {
    (reference.wrapping_sub(vtime) as i64).clamp(-limit, limit)
}

/// The reference change when weight `weight` at `vtime` joins weight `sum`.
///
/// V' = V + w * (v - V) / (W + w). The first member becomes the reference.
#[inline(always)]
pub fn join_delta(reference: u64, sum: u64, vtime: u64, weight: u64) -> u64 {
    let distance = vtime.wrapping_sub(reference) as i64;
    vdiv(weight as i64 * distance, sum + weight) as u64
}

/// The reference change when weight `weight` last folded in at `vtime` leaves
/// weight `sum`, which still includes it.
///
/// V' = V + w * (V - v) / (W - w). The last member leaves the reference
/// where it is.
#[inline(always)]
pub fn leave_delta(reference: u64, sum: u64, vtime: u64, weight: u64) -> u64 {
    if sum <= weight {
        return 0;
    }
    let distance = reference.wrapping_sub(vtime) as i64;
    vdiv(weight as i64 * distance, sum - weight) as u64
}

/// The vruntime that leaves a task of `weight` with `lag` once it joins.
///
/// Joining moves the reference toward the task, so the lag is inflated by
/// (W + w) / W beforehand, as place_entity() does.
#[inline(always)]
pub fn place(reference: u64, sum: u64, lag: i64, weight: u64) -> u64 {
    let lag = if sum == 0 {
        lag
    } else {
        vdiv(lag * (sum + weight) as i64, sum)
    };
    reference.wrapping_sub(lag as u64)
}

/// Fold `distance` of service at `weight` into a pack of weight `sum`.
///
/// dV = w * dv / W. Returns the reference advance and the new remainder,
/// which carries what truncation would drop on a heavy pack.
#[inline(always)]
pub fn charge(weight: u64, distance: u64, sum: u64, remainder: u64) -> (u64, u64) {
    if sum == 0 {
        return (0, remainder);
    }
    let accumulated = weight * distance + remainder;
    let advance = accumulated / sum;
    (advance, accumulated - advance * sum)
}

/// The vruntime a task of `weight` reaches after running `delta` ns.
#[inline(always)]
pub fn advance(vtime: u64, delta: u64, weight: u64) -> u64 {
    vtime.wrapping_add(delta * NICE_0_WEIGHT / weight.max(1))
}

/// The reference of a pack of weight `sum` whose running task of `weight`
/// has run `delta` ns since it was last charged, as if it had just been
/// charged: dV = w * dv / W. Past a whole `request` the task is due to be
/// rescheduled and charged for real, so nothing more is projected.
#[inline(always)]
pub fn reference_at(reference: u64, sum: u64, weight: u64, delta: u64, request: u64) -> u64 {
    if weight == 0 || sum == 0 || delta >= request {
        return reference;
    }
    let distance = delta * NICE_0_WEIGHT / weight;
    reference.wrapping_add(distance * weight / sum)
}

/// Is `first` before `second`, allowing for wraparound?
#[inline(always)]
pub fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}

/// What is left of a debt `lag` < 0 a task carried when it blocked, once the
/// pack it left has advanced by `advance` since, DELAY_DEQUEUE and
/// DELAY_ZERO. fair.c keeps such a task queued, still weighing `weight` in a
/// pack of `sum` without it, so it sees the pack move at
/// `sum / (sum + weight)` of what the pack now moves. The debt is paid off
/// by that much and never turns into credit.
#[inline(always)]
pub fn delay_debt(lag: i64, advance: i64, sum: u64, weight: u64) -> i64 {
    if lag >= 0 {
        return 0;
    }
    if advance <= 0 {
        return lag;
    }
    let paid = vdiv(advance * sum as i64, sum + weight);
    (lag + paid).min(0)
}

/// The reference to place a task of `join` weight against as it joins a
/// pack of weight `sum`, whose running task of `weight` has run `delta` ns
/// uncharged, pack_vref_before_join().
///
/// The running task's service is projected over `sum` before the join and
/// over `sum + join` after it. Placing at the pre-join projection can leave
/// a zero-lag task one unit above the post-join reference through
/// truncation, and so ineligible. With `q` the projection after the join,
/// placing against `V + q * (W + w) / W` makes the join contribute
/// `w * (V' - V) / (W + w)`, and adding `q` back gives `V'` exactly.
#[inline(always)]
pub fn reference_before_join(
    reference: u64,
    sum: u64,
    weight: u64,
    delta: u64,
    request: u64,
    join: u64,
) -> u64 {
    let total = sum.wrapping_add(join);
    if weight == 0 || sum == 0 || total == 0 || delta >= request {
        return reference;
    }
    let distance = delta * NICE_0_WEIGHT / weight;
    let projection = distance * weight / total;
    reference.wrapping_add(projection * total / sum)
}

/// Half-life of the utilization and load averages, as fair.c's PELT roughly
/// has it.
pub const UTIL_HALF_LIFE_NS: u32 = 32_000_000;

/// Fold what a task used over the activation that just ended into its
/// estimate, util_est_update(): a new demand is taken at once, a smaller one
/// only over several activations.
#[inline(always)]
pub fn util_est_update(estimate: u64, dequeued: u64) -> u64 {
    if estimate <= dequeued {
        dequeued
    } else {
        estimate - ((estimate - dequeued) >> 2)
    }
}

/// Fold the fraction of the last sleep-to-sleep `cycle` that the task spent
/// runnable, `runnable`, into its estimate with the weight of eight cycles:
/// what fair.c's runnable PELT measures for task_h_load(). A task kept
/// waiting behind a CPU-bound one counts what it asks for, not what it got.
#[inline(always)]
pub fn runnable_update(estimate: u64, cycle: u64, runnable: u64) -> u64 {
    if cycle == 0 {
        return estimate;
    }
    let fraction = if runnable >= cycle {
        1024
    } else {
        runnable * 1024 / cycle
    };
    (estimate * 7 + fraction) / 8
}

/// A task's load, an approximation of task_h_load(): its weight times the
/// larger of its utilization estimate and its runnable fraction, decayed
/// over `asleep` ns the way PELT would while it receives no callbacks.
#[inline(always)]
pub fn task_load(weight: u64, util_est: u64, runnable_est: u64, asleep: u64) -> u64 {
    let shift = (asleep / u64::from(UTIL_HALF_LIFE_NS)).min(63);
    let util = util_est.max(runnable_est) >> shift;
    weight * util.min(1024) / 1024
}

/// wake_wide(): do the waker and the wakee each wake many different tasks,
/// with `factor` (the LLC size) as the bar? Then there is no pair whose
/// affinity is worth keeping, and the wakee stays where it was.
#[inline(always)]
pub fn wake_wide(waker_flips: u64, wakee_flips: u64, factor: u64) -> bool {
    let (master, slave) = if waker_flips >= wakee_flips {
        (waker_flips, wakee_flips)
    } else {
        (wakee_flips, waker_flips)
    };
    slave >= factor && master >= slave * factor
}

/// wake_affine_weight() between CIDs of equal capacity: does the waking CID
/// stay better balanced than the previous one by taking a wakee of
/// `task_load`? `this_load` and `prev_load` are the two CIDs' loads,
/// `waker_load` the waker's own on a sync wakeup, about to leave its CID,
/// and `same_core` whether the two are SMT siblings. WA_BIAS weighs the
/// previous CID's load up by half of the domain's imbalance margin, 110% for
/// SMT siblings and 117% otherwise, so a tie goes to the waking CID.
#[inline(always)]
pub fn wake_affine_weight(
    this_load: u64,
    prev_load: u64,
    waker_load: Option<u64>,
    task_load: u64,
    same_core: bool,
) -> bool {
    let mut this_eff = this_load as i64;
    if let Some(current) = waker_load {
        if current > this_load {
            return true;
        }
        this_eff -= current as i64;
    }
    this_eff = (this_eff + task_load as i64) * 100;
    let pct = if same_core {
        100 + (110 - 100) / 2
    } else {
        100 + (117 - 100) / 2
    };
    let mut prev_eff = (prev_load as i64 - task_load as i64) * pct;
    if waker_load.is_some() {
        prev_eff += 1;
    }
    this_eff < prev_eff
}

/// A child group of a fork domain as find_idlest_group() sees it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ForkGroup {
    pub base: u32,
    pub nr: u32,
    /// CIDs idle with nothing queued.
    pub idle: u32,
    /// Summed load, and utilization for a restricted task.
    pub load: u64,
    pub util: u64,
    /// Summed capacity.
    pub cap: u64,
    /// When a fork was last placed in the group, 0 if not recently.
    pub recent: u64,
    /// For a restricted task: tasks runnable on, and CIDs allowed in, the
    /// group, whose difference is its spare capacity.
    pub runnable: u32,
    pub allowed: u32,
    /// Whether the group holds the fork's anchor, the local group.
    pub local: bool,
}

/// fair.c's imbalance_pct for a group of cores, and for wider domains.
const FORK_MC_IMBALANCE_PCT: u64 = 117;
const FORK_WIDE_IMBALANCE_PCT: u64 = 125;

/// Does `group` beat `best`, the idlest group so far if any,
/// as find_idlest_group() orders them? Idle CPUs first, then spare
/// capacity ordered by utilization, then load per capacity, with the local
/// group kept on ties and, for a restricted task, unless beaten by the
/// domain's imbalance margin. `core_level` says the groups are cores, where
/// the time of the last fork placed breaks ties: a fork that has already
/// blocked leaves no load behind.
pub fn fork_group_wins(
    group: &ForkGroup,
    best: Option<&ForkGroup>,
    restricted: bool,
    core_level: bool,
) -> bool {
    // fair.c skips a group with no CPU allowed to the task.
    if group.nr == 0 || group.allowed == 0 {
        return false;
    }
    let Some(best) = best else {
        return true;
    };
    // A disallowed SMT sibling is not spare capacity for this task.
    let spare = restricted && group.runnable < group.allowed;
    let best_spare = restricted && best.runnable < best.allowed;
    if spare != best_spare {
        return spare;
    }
    if group.idle != best.idle {
        return group.idle > best.idle;
    }
    if spare {
        if best.local {
            return false;
        }
        if group.local {
            return true;
        }
        if group.util != best.util {
            return group.util < best.util;
        }
    } else {
        let load = group.load * best.cap;
        let best_load = best.load * group.cap;
        if restricted && best.local != group.local {
            let pct = if core_level {
                FORK_MC_IMBALANCE_PCT
            } else {
                FORK_WIDE_IMBALANCE_PCT
            };
            return if best.local {
                best_load * 100 > load * pct
            } else {
                load * 100 <= best_load * pct
            };
        }
        if load != best_load {
            return load < best_load;
        }
        if !restricted && core_level && group.recent != best.recent {
            return group.recent < best.recent;
        }
        if best.local {
            return false;
        }
        if group.local {
            return true;
        }
    }
    core_level && group.recent < best.recent
}

/// A newidle cost record is halved, near enough, over 1% a second.
pub const NEWIDLE_DECAY_NS: u64 = 1_000_000_000;

/// update_rq_avg_idle(): move the average idle period an eighth of the way
/// to the period that just ended, capped at twice the CPU's worst pull.
#[inline(always)]
pub fn avg_idle_update(average: u64, idle: u64, max_cost: u64) -> u64 {
    let average = if idle > average {
        average + (idle - average) / 8
    } else {
        average - (average - idle) / 8
    };
    average.min(2 * max_cost)
}

/// update_newidle_cost(): a pull that cost more than the level's record
/// raises it at once; otherwise the record decays 1% every second. Returns
/// the record and when it last decayed or rose.
#[inline(always)]
pub fn newidle_cost_update(record: u64, stamp: u64, cost: u64, now: u64) -> (u64, u64) {
    if cost > record {
        (cost, now)
    } else if time_before(stamp.wrapping_add(NEWIDLE_DECAY_NS), now) {
        (record * 253 / 256, now)
    } else {
        (record, stamp)
    }
}

/// NI_RANDOM's success estimate for a level after `calls` scans with
/// `successes` among them, the last fold at `stamp`: every 1024 calls it
/// becomes the successes plus a point for each 4.194 ms between folds, and
/// the counts are halved. Returns (calls, successes, stamp, ratio).
#[inline(always)]
pub fn newidle_stats_fold(
    calls: u64,
    successes: u64,
    stamp: u64,
    ratio: u64,
    now: u64,
) -> (u64, u64, u64, u64) {
    if calls < 1024 {
        return (calls, successes, stamp, ratio);
    }
    let delta = if time_before(now, stamp) {
        0
    } else {
        now - stamp
    };
    let ratio = ((delta >> 22) + successes).min(1024);
    (calls / 2, successes / 2, now, ratio)
}

/// Whether NI_RANDOM admits a scan at `ratio` of 1024 with the random draw
/// `random`, and the weight a success then counts with: the inverse of the
/// sampling probability, which keeps the estimate unbiased.
#[inline(always)]
pub fn newidle_sample(ratio: u64, random: u32) -> Option<u64> {
    if ratio >= 1024 {
        return Some(1);
    }
    let sample = 1 + ratio;
    if u64::from(random & 1023) > sample {
        None
    } else {
        Some((1024 + sample / 2) / sample)
    }
}

/// Fractional bits the effective weight of a task in a cgroup is carried
/// with down the hierarchy, the precision scale_load() gives fair.c's
/// weights on 64-bit.
pub const GROUP_WEIGHT_SHIFT: u32 = 10;

/// The smallest weight a group can have on a CID, MIN_SHARES.
pub const GROUP_MIN_SHARES: u64 = 2;

/// The load weight of a cgroup written `weight` in cpu.weight,
/// sched_weight_from_cgroup(): 100 is nice 0.
#[inline(always)]
pub fn cgroup_load_weight(weight: u64) -> u64 {
    ((weight * NICE_0_WEIGHT + 50) / 100).max(1)
}

/// One level of __calc_prop_weight(): a fixed-point weight `fixed` of a
/// member of a group whose `load` gives it `shares` in its parent.
#[inline(always)]
pub fn prop_weight(fixed: u64, shares: u64, load: u64) -> u64 {
    (fixed * shares).checked_div(load.max(1)).unwrap_or(0)
}

/// The fixed-point product of the levels rounded once to a whole weight.
/// Packs multiply weights by vruntime distances, so the floor is 1 where
/// fair.c's is MIN_SHARES of a scaled weight.
#[inline(always)]
pub fn round_weight(fixed: u64) -> u64 {
    ((fixed + (1 << (GROUP_WEIGHT_SHIFT - 1))) >> GROUP_WEIGHT_SHIFT).max(1)
}

/// The shares of a group queue whose load on its CID is `load` now and
/// `load_avg` averaged, update_cfs_group() with fair.c's default "concur"
/// cgroup_mode, calc_concur_shares():
///
/// ```text
/// nr = min(tg_tasks(tg), tg_cpus(tg));
/// return __calc_smp_shares(cfs_rq, nr * tg_shares, nr * tg_shares);
/// ```
///
/// `weight` is the group's cpu.weight as a load weight, `tasks` its
/// averaged task count summed over CIDs, `cpus` the CPUs of its cpuset,
/// `tg_load_avg` the sum of its queues' averaged loads and `contrib` what
/// this queue last added to it.
#[inline(always)]
pub fn group_shares(
    weight: u64,
    tasks: u64,
    cpus: u64,
    load: u64,
    load_avg: u64,
    tg_load_avg: u64,
    contrib: u64,
) -> u64 {
    let total = tasks.max(1).min(cpus.max(1)) * weight;
    let load = load.max(load_avg);
    let tg_load = tg_load_avg.saturating_sub(contrib) + load;
    let shares = (total * load).checked_div(tg_load).unwrap_or(total);
    shares.max(GROUP_MIN_SHARES).min(total)
}
