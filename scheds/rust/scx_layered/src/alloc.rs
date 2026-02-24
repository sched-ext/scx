//! Unified per-node CPU allocation for scx_layered.
//!
//! All quantities in this module are in **alloc units** — typically full
//! cores, but can be individual CPUs. The caller converts between CPU counts
//! and alloc units before/after calling into this module.
//!
//! # Problem
//!
//! scx_layered assigns CPUs to layers based on utilization and weight. On a
//! single NUMA node this is straightforward: compute each layer's target CPU
//! count, then grow or shrink to match. On multi-node systems, some tasks
//! are pinned to a specific node (their cpumask covers exactly one node)
//! while others can run anywhere. A naive global allocation ignores this
//! distinction — a layer's CPUs may land on the wrong node, forcing pinned
//! tasks to migrate or stall.
//!
//! Each layer's CPU demand decomposes into:
//! - **Pinned**: must be on the task's node (node-constrained)
//! - **Unpinned**: can go wherever there's capacity (flexible)
//!
//! # Approach
//!
//! ## Water-fill: the core mechanism
//!
//! The algorithm is built on a single primitive: **water-fill**. Given a
//! pool of resources, a set of consumers with weights and demand caps,
//! water-fill distributes the pool proportionally by weight, but never
//! gives a consumer more than its demand. When a consumer hits its cap,
//! it is "locked" at that amount and the excess returns to the pool for
//! the remaining consumers to share. This repeats until every consumer
//! either uses its full proportional share or is locked at its demand.
//!
//! Water-fill has two useful properties: it respects weights (higher
//! weight means a larger share) and it wastes nothing (unclaimed budget
//! always flows to someone who can use it).
//!
//! ## Applying water-fill to per-node allocation
//!
//! The outer allocation loop is itself a water-fill over layers — the
//! pool is total CPUs, weights are layer weights, and the "demand cap"
//! for each layer is determined by trying to spend its budget on pinned
//! and unpinned work. The complication is that a layer's effective demand
//! isn't a single number; it depends on per-node pinned allocation
//! (which may be constrained by node capacity) and unpinned demand.
//!
//! Each iteration of the outer loop does three things for every
//! competing layer:
//!
//! **1. Scale and allocate pinned demand.** Each layer gets a
//! weight-proportional share of the pool (its "global target"). Its
//! per-node pinned demands are scaled down proportionally if the total
//! raw demand exceeds this budget. Then, on each node, the scaled pinned
//! demands from all layers are distributed via water-fill against the
//! node's available capacity. This places constrained work on the right
//! node while respecting both per-layer budgets and physical node limits.
//!
//! Pinned demand is allocated before unpinned because it is inflexible —
//! it can only be satisfied on a specific node. Unpinned demand is
//! flexible and can absorb whatever capacity remains.
//!
//! **2. Budget remainder for unpinned.** Pinned and unpinned demand
//! share a single budget (the global target). After pinned allocation,
//! the leftover becomes available for unpinned work:
//!
//! ```text
//! budget_left = global_target - actual_pinned_total
//! unpinned_alloc = min(raw_unpinned, budget_left)
//! ```
//!
//! If pinned allocation got everything it asked for, budget_left is
//! whatever portion of the global target wasn't claimed by pinned
//! demand. If a node was too full to satisfy all pinned demand, the
//! unspent pinned budget flows automatically to the unpinned side,
//! giving the layer more flexibility to place work elsewhere.
//!
//! **3. Lock or continue.** After both phases, the layer either used its
//! entire global target (it stays in competition for the next round) or
//! it used less. Using less means one of two things:
//!
//! - **Demand-capped**: the layer got all its pinned and unpinned demand
//!   with budget to spare. It simply doesn't need more CPUs.
//! - **Supply-constrained**: pinned allocation fell short (node full) and
//!   the layer's unpinned demand is too small to absorb the slack.
//!
//! Either way, the layer is locked at its actual allocation. This is
//! exactly what water-fill does when a consumer hits its cap — lock it
//! and redistribute the excess. The remaining layers get larger global
//! targets in the next iteration, and the loop repeats until no new
//! layers are locked.
//!
//! The result is that pinned tasks get CPUs on the right node, unpinned
//! tasks absorb whatever is left, and no budget is wasted on layers that
//! can't use it.
//!
//! # Terminology
//!
//! - **raw_pinned\[N\]**: layer's raw pinned CPU demand on node N (from
//!   pinned utilization / util_range)
//! - **raw_unpinned**: layer's raw unpinned CPU demand
//! - **raw_total**: sum(raw_pinned) + raw_unpinned
//! - **pool**: remaining CPUs after locking layers (starts at total_cpus)
//! - **global_target**: pool * weight / total_weight (proportional share)
//! - **scale**: min(1, global_target / raw_total) — proportionally reduces
//!   pinned targets when total demand exceeds the layer's budget
//! - **pinned_target\[N\]**: raw_pinned\[N\] * scale
//! - **unpinned_target**: min(raw_unpinned, global_target - actual_pinned)
//! - **demand-capped**: layer got everything it wants (total == raw_total)
//! - **supply-constrained**: layer can't use budget (node full, unpinned
//!   satisfied, but budget remains)
//!
//! # Algorithm
//!
//! ```text
//! locked = {}
//! pool = total_cpus
//!
//! loop:
//!     competing = all layers - locked
//!     total_weight = sum(weight[L] for L in competing)
//!
//!     for L in competing:
//!         global_target[L] = pool * weight[L] / total_weight
//!         scale = min(1, global_target[L] / raw_total[L])
//!         pinned_target[L][N] = raw_pinned[L][N] * scale
//!
//!     // Pinned water-fill per node (available excludes locked layers)
//!     for each node N:
//!         water_fill(node_available[N], pinned_target[*][N], weight)
//!         -> actual_pinned[L][N]
//!
//!     // Budget remainder -> unpinned
//!     for L in competing:
//!         actual_pinned_total[L] = sum(actual_pinned[L][N])
//!         unpinned_target[L] = min(raw_unpinned[L],
//!                                  global_target[L] - actual_pinned_total[L])
//!
//!     total_alloc[L] = actual_pinned_total[L] + unpinned_alloc[L]
//!
//!     // Lock layers not using full budget and redistribute.
//!     // Demand-capped: total == raw_total < global_target.
//!     // Supply-constrained: total < raw_total < global_target.
//!     newly_locked = { L | total_alloc[L] < global_target[L] }
//!     if newly_locked is empty: break
//!
//!     for L in newly_locked:
//!         lock L, pool -= total_alloc[L]
//!     restart
//! ```
//!
//! ## Water-fill
//!
//! Distributes a pool among entries by weight, capped at demand. When an
//! entry hits its demand cap, excess is redistributed to remaining entries.
//!
//! ```text
//! water_fill(pool, demands, weights):
//!     competing = all entries
//!     loop:
//!         total_weight = sum(weight for competing)
//!         for each entry:
//!             share = pool * weight / total_weight
//!             if share > demand: capped
//!         if no caps: allocate shares, done
//!         lock capped at demand, pool -= their demands, restart
//! ```
//!
//! # Properties
//!
//! - **Conservation**: total allocated == min(total_units, sum of demands).
//!   No alloc units are stranded.
//! - **Exact rounding**: `water_fill()` uses largest-remainder (Hamilton's
//!   method) so integer allocations sum exactly to the pool.
//! - **Budget enforcement**: pinned is deducted from global_target first,
//!   unpinned gets the remainder. Scaling prevents pinned from starving
//!   unpinned.
//! - **Unified locking**: `total_alloc < global_target` catches both
//!   demand-capped and supply-constrained layers, freeing stranded budget.
//! - **Floor-capping never happens**: after scaling, pinned <= global_target.
//!   Water-fill with proportional weights can't produce negative allocations.
//! - **Single-node equivalence**: when pinned utils are zero for all layers
//!   (single-node or no pinned tasks), pinned allocations are all zero and
//!   the result degenerates to pure weight-proportional distribution.

use crate::largest_remainder;

/// Per-layer allocation result from unified_alloc().
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LayerAlloc {
    /// Per-node pinned allocation (in alloc units).
    pub pinned: Vec<usize>,
    /// Global unpinned budget from unified_alloc (alloc units).
    pub unpinned_budget: usize,
    /// Per-node unpinned distribution (alloc units). Filled by post-step.
    pub unpinned: Vec<usize>,
}

impl LayerAlloc {
    pub fn total(&self) -> usize {
        self.pinned.iter().sum::<usize>() + self.unpinned_budget
    }

    pub fn node_target(&self, n: usize) -> usize {
        self.pinned[n] + self.unpinned[n]
    }
}

/// Entry for water_fill: a layer competing for a share of a pool.
#[derive(Clone, Debug)]
pub struct WaterFillEntry {
    pub weight: usize,
    pub demand: usize,
}

/// Distribute `pool` among entries by weight, capped at demand.
///
/// Each entry gets `pool * weight / total_weight`, but if that exceeds its
/// demand, the entry is locked at its demand and the excess is redistributed
/// to remaining entries. Iterates until no new caps. Uses largest-remainder
/// (Hamilton's method) for exact integer rounding — allocations always sum
/// to exactly min(pool, sum(demands)).
pub fn water_fill(pool: usize, entries: &[WaterFillEntry]) -> Vec<usize> {
    let n = entries.len();
    if n == 0 {
        return vec![];
    }

    let mut result = vec![0usize; n];
    let mut locked = vec![false; n];
    let mut remaining_pool = pool;

    loop {
        let total_weight: usize = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !locked[*i])
            .map(|(_, e)| e.weight)
            .sum();

        if total_weight == 0 {
            break;
        }

        // Compute proportional shares for competing entries.
        let quotas: Vec<f64> = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !locked[*i])
            .map(|(_, e)| e.weight as f64)
            .collect();
        let competing_indices: Vec<usize> = (0..n).filter(|i| !locked[*i]).collect();
        let shares = largest_remainder(remaining_pool, &quotas);

        // Check for newly capped entries.
        let mut newly_capped = false;
        for (pos, &idx) in competing_indices.iter().enumerate() {
            if shares[pos] > entries[idx].demand {
                // Capped: lock at demand, return excess to pool.
                result[idx] = entries[idx].demand;
                locked[idx] = true;
                remaining_pool -= entries[idx].demand;
                newly_capped = true;
            }
        }

        if !newly_capped {
            // No caps — assign shares and done.
            for (pos, &idx) in competing_indices.iter().enumerate() {
                result[idx] = shares[pos];
            }
            break;
        }
        // Restart with reduced pool and fewer competitors.
    }

    result
}

/// Per-layer demand input for unified_alloc().
#[derive(Clone, Debug)]
pub struct LayerDemand {
    /// Per-node raw pinned demand (in alloc units).
    pub raw_pinned: Vec<usize>,
    /// Raw unpinned demand (in alloc units).
    pub raw_unpinned: usize,
    /// Layer weight.
    pub weight: usize,
}

impl LayerDemand {
    pub fn raw_total(&self) -> usize {
        self.raw_pinned.iter().sum::<usize>() + self.raw_unpinned
    }
}

/// Unified per-node allocation in two phases:
///
/// 1. **Budget allocation** (`allocate_budgets`): water-fill distributes
///    `total_units` across layers by weight, resolving pinned demand
///    per-node and budgeting the remainder as unpinned.  See module-level
///    docs for the full algorithm.
///
/// 2. **Unpinned placement** (`place_unpinned`): places each layer's
///    unpinned budget on specific nodes, preserving current placement
///    and using preference/weight logic for the marginal delta.
///
/// `cur_node_cpus[layer][node]` is each layer's current total CPU count
/// on each node (in alloc units).  `norders[layer]` is the node
/// preference order.
///
/// Returns a `LayerAlloc` per layer with per-node pinned counts, an
/// unpinned budget, and per-node unpinned distribution, all in alloc
/// units.
pub fn unified_alloc(
    total_units: usize,
    node_caps: &[usize],
    demands: &[LayerDemand],
    cur_node_cpus: &[Vec<usize>],
    norders: &[Vec<usize>],
) -> Vec<LayerAlloc> {
    let mut allocs = allocate_budgets(total_units, node_caps, demands);
    place_unpinned(&mut allocs, demands, node_caps, cur_node_cpus, norders);
    allocs
}

/// Phase 1: Allocate per-layer budgets via iterative water-fill.
///
/// Distributes `total_units` across layers by weight.  Each iteration:
///
/// 1. Compute each competing layer's weight-proportional global target.
/// 2. Scale per-node pinned demands to fit within the global target,
///    then water-fill pinned demand against per-node capacity.
/// 3. Budget the remainder (global_target - actual_pinned) as unpinned.
/// 4. Lock layers that used less than their global target (demand-capped
///    or supply-constrained) and redistribute the excess.
///
/// Repeats until no new layers are locked.  Returns a `LayerAlloc` per
/// layer with per-node `pinned` counts and `unpinned_budget` set.
/// Per-node `unpinned` distribution is NOT resolved here — that's done
/// by `place_unpinned`.
fn allocate_budgets(
    total_units: usize,
    node_caps: &[usize],
    demands: &[LayerDemand],
) -> Vec<LayerAlloc> {
    let nr_layers = demands.len();
    let nr_nodes = node_caps.len();

    if nr_layers == 0 {
        return vec![];
    }

    let mut allocs: Vec<LayerAlloc> = demands
        .iter()
        .map(|_| LayerAlloc {
            pinned: vec![0; nr_nodes],
            unpinned_budget: 0,
            unpinned: vec![0; nr_nodes],
        })
        .collect();
    let mut locked = vec![false; nr_layers];
    let mut pool = total_units;

    // Per-node capacity consumed by locked layers' pinned allocs.
    let mut node_used: Vec<usize> = vec![0; nr_nodes];

    for _iteration in 0..nr_layers + 1 {
        let total_weight: usize = demands
            .iter()
            .enumerate()
            .filter(|(i, _)| !locked[*i])
            .map(|(_, d)| d.weight)
            .sum();

        if total_weight == 0 {
            break;
        }

        // Step 1: Weight-proportional global targets.
        let mut global_targets = vec![0usize; nr_layers];
        let competing: Vec<usize> = (0..nr_layers).filter(|i| !locked[*i]).collect();
        {
            let quotas: Vec<f64> = demands
                .iter()
                .enumerate()
                .filter(|(i, _)| !locked[*i])
                .map(|(_, d)| d.weight as f64)
                .collect();
            let shares = largest_remainder(pool, &quotas);
            for (pos, &idx) in competing.iter().enumerate() {
                global_targets[idx] = shares[pos];
            }
        }

        // Floor guarantee: any competing layer with demand > 0 gets at
        // least 1 unit.  Steal from the layer with the highest target.
        for &idx in &competing {
            if demands[idx].raw_total() > 0 && global_targets[idx] == 0 {
                if let Some(&donor) = competing
                    .iter()
                    .filter(|&&j| global_targets[j] > 1)
                    .max_by_key(|&&j| global_targets[j])
                {
                    global_targets[donor] -= 1;
                    global_targets[idx] = 1;
                }
            }
        }

        // Step 2: Scale pinned targets proportionally to fit budget.
        let mut pinned_targets: Vec<Vec<f64>> = vec![vec![0.0; nr_nodes]; nr_layers];
        for i in 0..nr_layers {
            if locked[i] {
                continue;
            }
            let raw_total = demands[i].raw_total();
            let scale = if raw_total > 0 {
                (global_targets[i] as f64 / raw_total as f64).min(1.0)
            } else {
                0.0
            };
            for n in 0..nr_nodes {
                pinned_targets[i][n] = demands[i].raw_pinned[n] as f64 * scale;
            }
        }

        // Step 3: Water-fill pinned per node against available capacity.
        let mut actual_pinned: Vec<Vec<usize>> = vec![vec![0; nr_nodes]; nr_layers];
        for n in 0..nr_nodes {
            let node_avail = node_caps[n].saturating_sub(node_used[n]);
            let mut wf_entries: Vec<WaterFillEntry> = Vec::new();
            let mut wf_indices: Vec<usize> = Vec::new();

            for i in 0..nr_layers {
                if locked[i] || pinned_targets[i][n] == 0.0 {
                    continue;
                }
                wf_entries.push(WaterFillEntry {
                    weight: demands[i].weight,
                    demand: pinned_targets[i][n].ceil() as usize,
                });
                wf_indices.push(i);
            }

            let wf_allocs = water_fill(node_avail, &wf_entries);
            for (pos, &idx) in wf_indices.iter().enumerate() {
                actual_pinned[idx][n] = wf_allocs[pos];
            }
        }

        // Step 4: Budget remainder goes to unpinned.
        let mut unpinned_alloc = vec![0usize; nr_layers];
        for i in 0..nr_layers {
            if locked[i] {
                continue;
            }
            let pinned_total: usize = actual_pinned[i].iter().sum();
            let budget_left = global_targets[i].saturating_sub(pinned_total);
            unpinned_alloc[i] = demands[i].raw_unpinned.min(budget_left);
        }

        // Step 5: Lock layers not using full budget, redistribute excess.
        let mut newly_locked = false;
        for i in 0..nr_layers {
            if locked[i] {
                continue;
            }
            let pinned_total: usize = actual_pinned[i].iter().sum();
            let total_alloc = pinned_total + unpinned_alloc[i];

            if total_alloc < global_targets[i] {
                allocs[i].pinned = actual_pinned[i].clone();
                allocs[i].unpinned_budget = unpinned_alloc[i];
                locked[i] = true;
                pool -= total_alloc;
                for n in 0..nr_nodes {
                    node_used[n] += actual_pinned[i][n];
                }
                newly_locked = true;
            }
        }

        if !newly_locked {
            for i in 0..nr_layers {
                if locked[i] {
                    continue;
                }
                allocs[i].pinned = actual_pinned[i].clone();
                allocs[i].unpinned_budget = unpinned_alloc[i];
            }
            break;
        }
    }

    allocs
}

/// Phase 2: Place each layer's unpinned budget on specific nodes.
///
/// Uses `cur_node_cpus` as the starting point so that pinned shifts
/// between nodes are compensated and the per-node total stays stable.
/// Only the marginal delta uses preference/weight logic:
///
/// - **Shrink**: trims from least-preferred nodes (reverse norder).
/// - **Grow**: distributes rank-interleaved, weight-proportional via
///   `water_fill` across nodes in preference order.
///
/// No-op when `cur_node_cpus` is empty (first cycle or tests without
/// per-node state).
fn place_unpinned(
    allocs: &mut [LayerAlloc],
    demands: &[LayerDemand],
    node_caps: &[usize],
    cur_node_cpus: &[Vec<usize>],
    norders: &[Vec<usize>],
) {
    if cur_node_cpus.is_empty() {
        return;
    }

    let nr_layers = allocs.len();
    let nr_nodes = node_caps.len();

    // Initialize unpinned from current minus pinned.
    for (idx, alloc) in allocs.iter_mut().enumerate() {
        for n in 0..nr_nodes {
            alloc.unpinned[n] = cur_node_cpus[idx][n].saturating_sub(alloc.pinned[n]);
        }
    }

    // Shrink: trim from least-preferred nodes first.
    for (idx, alloc) in allocs.iter_mut().enumerate() {
        let cur_total: usize = alloc.unpinned.iter().sum();
        if cur_total > alloc.unpinned_budget {
            let mut excess = cur_total - alloc.unpinned_budget;
            for &n in norders[idx].iter().rev() {
                let trim = excess.min(alloc.unpinned[n]);
                alloc.unpinned[n] -= trim;
                excess -= trim;
                if excess == 0 {
                    break;
                }
            }
        }
    }

    // Remaining capacity per node after all pinned + current unpinned.
    let mut node_remaining = node_caps.to_vec();
    for alloc in allocs.iter() {
        for n in 0..nr_nodes {
            node_remaining[n] =
                node_remaining[n].saturating_sub(alloc.pinned[n] + alloc.unpinned[n]);
        }
    }

    // Per-layer growth needed.
    let mut growth: Vec<usize> = allocs
        .iter()
        .map(|a| {
            a.unpinned_budget
                .saturating_sub(a.unpinned.iter().sum::<usize>())
        })
        .collect();

    // Grow: rank-interleaved, weight-proportional across preferred nodes.
    for rank in 0..nr_nodes {
        let mut node_to_layers: Vec<Vec<usize>> = vec![vec![]; nr_nodes];
        for idx in 0..nr_layers {
            if growth[idx] == 0 || rank >= norders[idx].len() {
                continue;
            }
            node_to_layers[norders[idx][rank]].push(idx);
        }

        for n in 0..nr_nodes {
            let contestants = &node_to_layers[n];
            if contestants.is_empty() || node_remaining[n] == 0 {
                continue;
            }

            let entries: Vec<WaterFillEntry> = contestants
                .iter()
                .map(|&idx| WaterFillEntry {
                    weight: demands[idx].weight,
                    demand: growth[idx],
                })
                .collect();
            let shares = water_fill(node_remaining[n], &entries);

            for (pos, &idx) in contestants.iter().enumerate() {
                allocs[idx].unpinned[n] += shares[pos];
                growth[idx] -= shares[pos];
                node_remaining[n] -= shares[pos];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // water_fill tests
    // =====================================================================

    #[test]
    fn test_wf_no_contention() {
        // Pool exactly matches total demand. Each gets its full demand.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 10,
            },
            WaterFillEntry {
                weight: 1,
                demand: 10,
            },
        ];
        let result = water_fill(20, &entries);
        assert_eq!(result, vec![10, 10]);
    }

    #[test]
    fn test_wf_equal_split() {
        // Pool < total demand, equal weights. Split evenly.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 100,
            },
            WaterFillEntry {
                weight: 1,
                demand: 100,
            },
        ];
        let result = water_fill(10, &entries);
        assert_eq!(result, vec![5, 5]);
    }

    #[test]
    fn test_wf_one_capped() {
        // A(w=1,d=3), B(w=1,d=100). Pool=10.
        // Iter 1: share=5 each. A: 5>3, capped at 3. Pool=7.
        // Iter 2: B gets 7.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 3,
            },
            WaterFillEntry {
                weight: 1,
                demand: 100,
            },
        ];
        let result = water_fill(10, &entries);
        assert_eq!(result[0], 3);
        assert_eq!(result[1], 7);
    }

    #[test]
    fn test_wf_all_capped() {
        // Both demands < pool. Each gets exactly its demand, pool not exhausted.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 3,
            },
            WaterFillEntry {
                weight: 1,
                demand: 4,
            },
        ];
        let result = water_fill(20, &entries);
        assert_eq!(result, vec![3, 4]);
    }

    #[test]
    fn test_wf_unequal_weights() {
        // A(w=3,d=100), B(w=1,d=100). Pool=20. 3:1 split -> 15:5.
        let entries = vec![
            WaterFillEntry {
                weight: 3,
                demand: 100,
            },
            WaterFillEntry {
                weight: 1,
                demand: 100,
            },
        ];
        let result = water_fill(20, &entries);
        assert_eq!(result[0], 15);
        assert_eq!(result[1], 5);
    }

    #[test]
    fn test_wf_cascading_caps() {
        // Three entries: A(w=1,d=2), B(w=1,d=3), C(w=1,d=100). Pool=12.
        // Iter 1: share=4 each. A capped(2), B capped(3). Pool=7.
        // Iter 2: C gets 7.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 2,
            },
            WaterFillEntry {
                weight: 1,
                demand: 3,
            },
            WaterFillEntry {
                weight: 1,
                demand: 100,
            },
        ];
        let result = water_fill(12, &entries);
        assert_eq!(result, vec![2, 3, 7]);
    }

    #[test]
    fn test_wf_zero_demand() {
        // A has zero demand -> locked immediately. B gets entire pool.
        let entries = vec![
            WaterFillEntry {
                weight: 1,
                demand: 0,
            },
            WaterFillEntry {
                weight: 1,
                demand: 10,
            },
        ];
        let result = water_fill(10, &entries);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 10);
    }

    #[test]
    fn test_wf_single_entry() {
        // Single entry gets min(pool, demand).
        let entries = vec![WaterFillEntry {
            weight: 1,
            demand: 5,
        }];
        let result = water_fill(10, &entries);
        assert_eq!(result, vec![5]);
    }

    #[test]
    fn test_wf_conservation() {
        // When no entries are capped, allocations must sum exactly to pool.
        // Verifies largest-remainder rounding doesn't lose units.
        let entries = vec![
            WaterFillEntry {
                weight: 2,
                demand: 100,
            },
            WaterFillEntry {
                weight: 3,
                demand: 100,
            },
            WaterFillEntry {
                weight: 5,
                demand: 100,
            },
        ];
        let result = water_fill(50, &entries);
        assert_eq!(result.iter().sum::<usize>(), 50);
    }

    #[test]
    fn test_wf_empty() {
        let result = water_fill(10, &[]);
        assert!(result.is_empty());
    }

    // =====================================================================
    // unified_alloc scenario tests
    //
    // All scenarios: 2 NUMA nodes, 48 units/node, 96 total, 4 layers.
    // Layer notation: L(weight, pinned_N0, pinned_N1, unpinned).
    // Result notation: L=(N0_pin, N1_pin, unpin)=total.
    // =====================================================================

    fn caps_2n() -> Vec<usize> {
        vec![48, 48]
    }

    fn demand(w: usize, p0: usize, p1: usize, u: usize) -> LayerDemand {
        LayerDemand {
            raw_pinned: vec![p0, p1],
            raw_unpinned: u,
            weight: w,
        }
    }

    fn total_alloc(allocs: &[LayerAlloc]) -> usize {
        allocs.iter().map(|a| a.total()).sum()
    }

    // S1: No contention, no demand-cap
    //
    // A(1,18,0,18) B(1,0,18,18) C(1,12,0,24) D(1,0,12,24). All raw=36.
    //
    // Iter 1: global_target=24 each. scale=24/36=2/3.
    //   Pinned: A[N0]=12, B[N1]=12, C[N0]=8, D[N1]=8.
    //   N0: 12+8=20<=48, N1: 12+8=20<=48. No contention.
    //   Unpinned: A=min(18,24-12)=12, B=12, C=min(24,24-8)=16, D=16.
    //   Total: all=24=global_target. No locking. Done.
    //
    // Result: A=(12,0,12)=24, B=(0,12,12)=24, C=(8,0,16)=24, D=(0,8,16)=24.
    // 0 unused.
    #[test]
    fn test_ua_s1_no_contention() {
        let demands = vec![
            demand(1, 18, 0, 18),
            demand(1, 0, 18, 18),
            demand(1, 12, 0, 24),
            demand(1, 0, 12, 24),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        for a in &allocs {
            assert_eq!(a.total(), 24);
        }
        assert_eq!(total_alloc(&allocs), 96);
    }

    // S2: Demand-cap, one outer restart
    //
    // A(1,18,0,18) B(1,0,18,18) C(1,4,0,2) D(1,0,4,2).
    // A,B raw=36; C,D raw=6.
    //
    // Iter 1: global_target=24. A,B: scale=2/3. C,D: no scale.
    //   Pinned: A[N0]=12, B[N1]=12, C[N0]=4, D[N1]=4. No contention.
    //   Unpinned: A=12, B=12, C=min(2,20)=2, D=2.
    //   Total: A=24, B=24, C=6, D=6. C,D: 6<24 -> lock (demand-capped).
    //   Pool=96-6-6=84.
    //
    // Iter 2: A,B competing. global_target=42. raw=36<42, no scale.
    //   Pinned: A[N0]=18, B[N1]=18. No contention.
    //   Unpinned: A=min(18,42-18)=18, B=18. Total=36<42 -> lock. 12 unused.
    //
    // Result: A=(18,0,18)=36, B=(0,18,18)=36, C=(4,0,2)=6, D=(0,4,2)=6.
    // 12 unused.
    #[test]
    fn test_ua_s2_demand_cap_one_restart() {
        let demands = vec![
            demand(1, 18, 0, 18),
            demand(1, 0, 18, 18),
            demand(1, 4, 0, 2),
            demand(1, 0, 4, 2),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[2].total(), 6);
        assert_eq!(allocs[3].total(), 6);
        assert_eq!(allocs[0].total(), 36);
        assert_eq!(allocs[1].total(), 36);
        assert_eq!(total_alloc(&allocs), 84);
    }

    // S3: Cascading demand-caps, three restarts
    //
    // A(1,18,0,18) B(1,12,0,12) C(1,6,0,2) D(1,0,2,2). Raw: 36,24,8,4.
    //
    // Iter 1: global_target=24. C=8<24, D=4<24 -> lock. Pool=84.
    // Iter 2: global_target=42. B=24<42 -> lock. Pool=60.
    // Iter 3: global_target=60. A=36<60 -> lock. 24 unused.
    //
    // Result: A=(18,0,18)=36, B=(12,0,12)=24, C=(6,0,2)=8, D=(0,2,2)=4.
    // 24 unused.
    #[test]
    fn test_ua_s3_cascading_demand_caps() {
        let demands = vec![
            demand(1, 18, 0, 18),
            demand(1, 12, 0, 12),
            demand(1, 6, 0, 2),
            demand(1, 0, 2, 2),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 36);
        assert_eq!(allocs[1].total(), 24);
        assert_eq!(allocs[2].total(), 8);
        assert_eq!(allocs[3].total(), 4);
        assert_eq!(total_alloc(&allocs), 72);
    }

    // S4: Pinned contention on single node, unpinned absorbs freed budget
    //
    // All: (1,36,0,12). raw=48. global_target=24. scale=0.5.
    // pinned_target[N0]=18 each. N0: 4*18=72>48.
    //
    // Water-fill N0: equal weight, share=12 each. All<=18 -> done.
    // actual_pinned=12. Unpinned=min(12,24-12)=12.
    // Total=24=global_target. No locking. Done.
    //
    // Pinned contention reduced each layer's pinned from 18 to 12. The
    // freed budget (24-12=12) goes to unpinned, which absorbs it fully.
    //
    // Result: all=(12,0,12)=24. 0 unused.
    #[test]
    fn test_ua_s4_pinned_contention() {
        let demands = vec![
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        for a in &allocs {
            assert_eq!(a.total(), 24);
            assert_eq!(a.pinned[0], 12);
            assert_eq!(a.unpinned_budget, 12);
        }
        assert_eq!(total_alloc(&allocs), 96);
    }

    // S5: Pinned contention + demand-cap + supply-constrained
    //
    // A(1,40,0,8) B(1,40,0,8) C(1,40,0,8) D(1,3,0,3). Raw: 48,48,48,6.
    //
    // Iter 1: global_target=24. A,B,C: scale=0.5, pinned_target=20. D: pinned=3.
    //   N0: 20+20+20+3=63>48. Water-fill: D capped(3), pool=45. A,B,C: 15 each.
    //   Unpinned: A,B,C=min(8,24-15)=8, D=min(3,24-3)=3.
    //   Total: A,B,C=23<24, D=6<24. All lock.
    //   D: demand-capped (6=raw_total). A,B,C: supply-constrained (N0 full,
    //   unpinned satisfied but budget remains).
    //
    // Result: A,B,C=(15,0,8)=23, D=(3,0,3)=6. 21 unused (N1 has no pinned
    // demand from anyone).
    #[test]
    fn test_ua_s5_pinned_contention_demand_cap() {
        let demands = vec![
            demand(1, 40, 0, 8),
            demand(1, 40, 0, 8),
            demand(1, 40, 0, 8),
            demand(1, 3, 0, 3),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[3].total(), 6);
        for i in 0..3 {
            assert_eq!(allocs[i].unpinned_budget, 8);
            assert!(allocs[i].total() >= 22 && allocs[i].total() <= 24);
        }
    }

    // S6: Per-node cascading water-fill + outer restart
    //
    // A(1,6,0,6) B(1,6,0,6) C(1,40,0,8) D(1,40,0,8). Raw: 12,12,48,48.
    //
    // Iter 1: global_target=24. A,B: no scale. C,D: scale=0.5, pinned_target=20.
    //   N0: 6+6+20+20=52>48. Water-fill: A,B capped(6). Pool=36. C,D: 18 each.
    //   Unpinned: A=6, B=6, C=min(8,24-18)=6, D=6.
    //   Total: A=12, B=12 (demand-capped), C=24, D=24. Lock A,B. Pool=72.
    //
    // Iter 2: C,D competing. global_target=36. scale=36/48=3/4. pinned_target=30.
    //   N0 available=48-6-6=36. 30+30=60>36. Equal: 18 each.
    //   Unpinned=min(8,36-18)=8. Total=26<36. Lock (supply-constrained: N0 full).
    //   20 unused on N1.
    //
    // Result: A=(6,0,6)=12, B=(6,0,6)=12, C=(18,0,8)=26, D=(18,0,8)=26.
    // 20 unused.
    #[test]
    fn test_ua_s6_per_node_cascading() {
        let demands = vec![
            demand(1, 6, 0, 6),
            demand(1, 6, 0, 6),
            demand(1, 40, 0, 8),
            demand(1, 40, 0, 8),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 12);
        assert_eq!(allocs[1].total(), 12);
        assert_eq!(allocs[2].unpinned_budget, 8);
        assert_eq!(allocs[3].unpinned_budget, 8);
        assert_eq!(allocs[2].total(), 26);
        assert_eq!(allocs[3].total(), 26);
        assert_eq!(total_alloc(&allocs), 76);
    }

    // S7: Large weight disparity
    //
    // A(5,18,0,18) B(1,18,0,18) C(1,18,0,18) D(1,6,0,6). total_weight=8.
    // Raw: 36,36,36,12.
    //
    // Iter 1: global_target: A=60, B=C=D=12.
    //   A: no scale (36<60), pinned[N0]=18. B,C: scale=1/3, pinned[N0]=6.
    //   D: no scale, pinned[N0]=6.
    //   N0: 18+6+6+6=36<=48. No contention.
    //   Total: A=36<60 -> lock. B,C,D=12=global_target, not locked. Pool=60.
    //
    // Iter 2: B,C,D competing. total_weight=3. global_target=20.
    //   B,C: scale=20/36, pinned[N0]=10. D: no scale, pinned[N0]=6.
    //   N0 available=48-18=30. 10+10+6=26<=30. No contention.
    //   Total: B=20, C=20, D=12<20 -> lock. Pool=48.
    //
    // Iter 3: B,C competing. global_target=24. scale=2/3. pinned[N0]=12.
    //   N0 available=48-18-6=24. 24=24. Unpinned=12. Total=24. Done.
    //
    // Result: A=(18,0,18)=36, B=(12,0,12)=24, C=(12,0,12)=24, D=(6,0,6)=12.
    // 0 unused.
    #[test]
    fn test_ua_s7_weight_disparity() {
        let demands = vec![
            demand(5, 18, 0, 18),
            demand(1, 18, 0, 18),
            demand(1, 18, 0, 18),
            demand(1, 6, 0, 6),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 36);
        assert_eq!(allocs[3].total(), 12);
        assert_eq!(allocs[1].total(), 24);
        assert_eq!(allocs[2].total(), 24);
        assert_eq!(total_alloc(&allocs), 96);
    }

    // S8: Mixed pinned-only + unpinned-only layers
    //
    // A(1,24,0,0) B(1,0,24,0) C(1,0,0,24) D(1,0,0,24). All raw=24.
    //
    // global_target=24=raw_total. No scaling. A pins N0, B pins N1.
    // C,D get 24 unpinned. No contention, no locking.
    //
    // Result: A=(24,0,0)=24, B=(0,24,0)=24, C=(0,0,24)=24, D=(0,0,24)=24.
    // 0 unused.
    #[test]
    fn test_ua_s8_mixed_pinned_unpinned() {
        let demands = vec![
            demand(1, 24, 0, 0),
            demand(1, 0, 24, 0),
            demand(1, 0, 0, 24),
            demand(1, 0, 0, 24),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        for a in &allocs {
            assert_eq!(a.total(), 24);
        }
        assert_eq!(allocs[0].pinned[0], 24);
        assert_eq!(allocs[1].pinned[1], 24);
        assert_eq!(allocs[2].unpinned_budget, 24);
        assert_eq!(allocs[3].unpinned_budget, 24);
    }

    // S8b: Mixed pinned/unpinned with demand-cap
    //
    // A(1,24,0,0) B(1,0,24,0) C(1,0,0,6) D(1,0,0,6). Raw: 24,24,6,6.
    //
    // Iter 1: global_target=24. C,D: 6<24 -> lock. Pool=84.
    // Iter 2: global_target=42. A,B: 24<42 -> lock. 36 unused.
    //
    // Result: A=(24,0,0)=24, B=(0,24,0)=24, C=(0,0,6)=6, D=(0,0,6)=6.
    // 36 unused.
    #[test]
    fn test_ua_s8b_mixed_with_demand_cap() {
        let demands = vec![
            demand(1, 24, 0, 0),
            demand(1, 0, 24, 0),
            demand(1, 0, 0, 6),
            demand(1, 0, 0, 6),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 24);
        assert_eq!(allocs[1].total(), 24);
        assert_eq!(allocs[2].total(), 6);
        assert_eq!(allocs[3].total(), 6);
        assert_eq!(total_alloc(&allocs), 60);
    }

    // S9: All pinned to same node (same setup as S4)
    //
    // All: (1,36,0,12). N0: 4*18=72>48 (after scale=0.5).
    // Water-fill: 12 each. Unpinned: 12 each. Total=24. Done.
    //
    // Result: all=(12,0,12)=24. 0 unused.
    #[test]
    fn test_ua_s9_all_pinned_same_node() {
        let demands = vec![
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        for a in &allocs {
            assert_eq!(a.total(), 24);
            assert_eq!(a.pinned[0], 12);
            assert_eq!(a.unpinned_budget, 12);
        }
    }

    // S9b: All pinned same node, unequal weights
    //
    // A(3,36,0,12) B(1,36,0,12) C(1,36,0,12) D(1,36,0,12). total_weight=6.
    // Raw=48 for all. global_target: A=48, B=C=D=16.
    //
    // A: scale=1, pinned_target=36. B,C,D: scale=1/3, pinned_target=12.
    // N0: 36+12+12+12=72>48. Water-fill weights 3:1:1:1:
    //   A=24, B=C=D=8. All<=targets.
    // Unpinned: A=min(12,48-24)=12. B,C,D=min(12,16-8)=8.
    // Total: A=36<48 -> lock (supply-constrained). B,C,D=16. Pool=60.
    //
    // Iter 2: B,C,D. global_target=20. scale=20/48. pinned_target=15.
    //   N0 available=48-24=24. 15*3=45>24. Equal: 8 each.
    //   Unpinned=min(12,20-8)=12. Total=20. Done.
    //
    // Result: A=(24,0,12)=36, B,C,D=(8,0,12)=20. 0 unused.
    #[test]
    fn test_ua_s9b_unequal_weights() {
        let demands = vec![
            demand(3, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
            demand(1, 36, 0, 12),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 36);
        assert_eq!(allocs[0].unpinned_budget, 12);
        for i in 1..4 {
            assert_eq!(allocs[i].unpinned_budget, 12);
            assert_eq!(allocs[i].total(), 20);
        }
        assert_eq!(total_alloc(&allocs), 96);
    }

    // S10: Pinned spread across nodes + demand-cap
    //
    // A(2,18,0,18) B(2,0,18,18) C(1,3,0,3) D(1,0,3,3). total_weight=6.
    // Raw: A,B=36; C,D=6. global_target: A,B=32, C,D=16.
    //
    // Iter 1: A: scale=32/36=8/9, pinned[N0]=16. B: pinned[N1]=16.
    //   C: pinned[N0]=3, D: pinned[N1]=3. No node contention.
    //   Unpinned: A=min(18,32-16)=16, B=16, C=min(3,13)=3, D=3.
    //   Total: A=32, B=32, C=6<16, D=6<16. Lock C,D. Pool=84.
    //
    // Iter 2: global_target=42. A,B: raw=36<42, no scale. Full pinned, full
    //   unpinned. Total=36<42 -> lock. 12 unused.
    //
    // Result: A=(18,0,18)=36, B=(0,18,18)=36, C=(3,0,3)=6, D=(0,3,3)=6.
    // 12 unused.
    #[test]
    fn test_ua_s10_pinned_spread() {
        let demands = vec![
            demand(2, 18, 0, 18),
            demand(2, 0, 18, 18),
            demand(1, 3, 0, 3),
            demand(1, 0, 3, 3),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 36);
        assert_eq!(allocs[1].total(), 36);
        assert_eq!(allocs[2].total(), 6);
        assert_eq!(allocs[3].total(), 6);
        assert_eq!(total_alloc(&allocs), 84);
    }

    // S11: Supply-constrained — unused budget, no demand-cap
    //
    // A(1,48,0,0) B(1,48,0,0) C(1,48,0,0) D(1,0,0,24). Raw: 48,48,48,24.
    //
    // Iter 1: global_target=24. A,B,C: scale=0.5, pinned_target[N0]=24.
    //   N0: 72>48. Equal: 16 each. No unpinned demand for A,B,C.
    //   D: unpinned=24.
    //   Total: A,B,C=16<24 -> lock (supply-constrained: N0 full, no unpinned
    //   to absorb remainder). D=24. Pool=48.
    //
    // Iter 2: D alone. global_target=48. D: raw=24<48 -> lock. 24 unused.
    //
    // A,B,C are pinned-only. N0 full. D satisfied. 24 unused on N1 —
    // nobody has pinned demand there.
    //
    // Result: A,B,C=(16,0,0)=16, D=(0,0,24)=24. 24 unused.
    #[test]
    fn test_ua_s11_supply_constrained() {
        let demands = vec![
            demand(1, 48, 0, 0),
            demand(1, 48, 0, 0),
            demand(1, 48, 0, 0),
            demand(1, 0, 0, 24),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[3].total(), 24);
        for i in 0..3 {
            assert_eq!(allocs[i].pinned[0], 16);
            assert_eq!(allocs[i].total(), 16);
        }
        assert_eq!(total_alloc(&allocs), 72);
    }

    // S12: Pinned contention + cascading demand-caps + supply-constrained
    //
    // A(1,40,0,8) B(1,40,0,8) C(1,40,0,8) D(1,2,0,2). Raw: 48,48,48,4.
    //
    // Iter 1: global_target=24. A,B,C: scale=0.5, pinned_target=20. D: pinned=2.
    //   N0: 62>48. Water-fill: D capped(2), pool=46. A,B,C: 46/3~15 each.
    //   Unpinned: A,B,C=min(8,24-15)=8. D=min(2,22)=2.
    //   Total: D=4<24 -> lock (demand-capped). A,B,C~23<24 -> lock
    //   (supply-constrained: N0 full, unpinned satisfied).
    //
    // All unpinned satisfied (8,8,8,2). Unused on N1 — pinned can't go there.
    //
    // Result: A,B,C=(~15,0,8)=~23, D=(2,0,2)=4. ~22 unused.
    #[test]
    fn test_ua_s12_pinned_contention_cascading() {
        let demands = vec![
            demand(1, 40, 0, 8),
            demand(1, 40, 0, 8),
            demand(1, 40, 0, 8),
            demand(1, 2, 0, 2),
        ];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[3].total(), 4);
        for i in 0..3 {
            assert_eq!(allocs[i].unpinned_budget, 8);
        }

        let n0_pinned: usize = allocs.iter().map(|a| a.pinned[0]).sum();
        assert!(n0_pinned <= 48);
    }

    // =====================================================================
    // Single-node equivalence and edge cases
    // =====================================================================

    // Single-node degenerate: all pinned=0 -> pure weight-proportional.
    // On single-node systems there are no node-pinned tasks, so all pinned
    // demands are zero and unified_alloc degenerates to weight-proportional.
    #[test]
    fn test_ua_single_node_degenerate() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 20,
                weight: 1,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 20,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(16, &[16], &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 8);
        assert_eq!(allocs[1].total(), 8);
        assert_eq!(allocs[0].unpinned_budget, 8);
        assert_eq!(allocs[1].unpinned_budget, 8);
    }

    // Single layer gets all of its demand (pool > demand).
    #[test]
    fn test_ua_single_layer() {
        let demands = vec![demand(1, 10, 5, 20)];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 35);
        assert_eq!(allocs[0].pinned[0], 10);
        assert_eq!(allocs[0].pinned[1], 5);
        assert_eq!(allocs[0].unpinned_budget, 20);
    }

    // Conservation: when total demand exceeds supply, all units allocated.
    // Two layers with raw=80 each, total=96. Each gets 48, sum=96.
    #[test]
    fn test_ua_conservation_no_stranded() {
        let demands = vec![demand(1, 40, 0, 40), demand(1, 0, 40, 40)];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        assert_eq!(total_alloc(&allocs), 96);
    }

    #[test]
    fn test_ua_empty() {
        let allocs = unified_alloc(96, &caps_2n(), &[], &[], &[]);
        assert!(allocs.is_empty());
    }

    // All-zero demand: nothing allocated even with large pool.
    #[test]
    fn test_ua_all_zero_demand() {
        let demands = vec![demand(1, 0, 0, 0), demand(1, 0, 0, 0)];
        let allocs = unified_alloc(96, &caps_2n(), &demands, &[], &[]);
        for a in &allocs {
            assert_eq!(a.total(), 0);
        }
    }

    // Single-node weight-proportional: weights 2:1:1, all unpinned, total=32.
    // A gets 16, B gets 8, C gets 8. Verifies weight-proportional split
    // when there's no pinned demand.
    #[test]
    fn test_ua_single_node_weight_proportional() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 100,
                weight: 2,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 100,
                weight: 1,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 100,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(32, &[32], &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 16);
        assert_eq!(allocs[1].total(), 8);
        assert_eq!(allocs[2].total(), 8);
        assert_eq!(total_alloc(&allocs), 32);
    }

    // Single-node demand-capped: A wants 5, B wants 100. Pool=32, w=1:1.
    // Iter 1: share=16 each. A: 5<16 -> lock. Pool=27.
    // Iter 2: B alone, gets min(100,27)=27.
    #[test]
    fn test_ua_single_node_demand_capped() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 5,
                weight: 1,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 100,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(32, &[32], &demands, &[], &[]);
        assert_eq!(allocs[0].total(), 5);
        assert_eq!(allocs[1].total(), 27);
    }

    // =====================================================================
    // Floor guarantee tests
    // =====================================================================

    // Low-weight layer with demand gets at least 1 unit, stolen from highest.
    // A(w=100,d=50), B(w=1,d=10). Pool=4. Without floor, B rounds to 0.
    // Floor steals 1 from A: A=3, B=1.
    #[test]
    fn test_ua_floor_low_weight_gets_one() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 50,
                weight: 100,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 10,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(4, &[4], &demands, &[], &[]);
        assert!(
            allocs[1].total() >= 1,
            "low-weight layer must get >= 1, got {}",
            allocs[1].total()
        );
        assert_eq!(total_alloc(&allocs), 4);
    }

    // Zero-demand layer should still get 0 even with floor guarantee.
    #[test]
    fn test_ua_floor_zero_demand_stays_zero() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 50,
                weight: 100,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 0,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(4, &[4], &demands, &[], &[]);
        assert_eq!(allocs[1].total(), 0);
    }

    // Multiple low-weight layers competing: all with demand get >= 1.
    // A(w=100,d=50), B(w=1,d=5), C(w=1,d=5). Pool=6.
    #[test]
    fn test_ua_floor_multiple_low_weight() {
        let demands = vec![
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 50,
                weight: 100,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 5,
                weight: 1,
            },
            LayerDemand {
                raw_pinned: vec![0],
                raw_unpinned: 5,
                weight: 1,
            },
        ];
        let allocs = unified_alloc(6, &[6], &demands, &[], &[]);
        assert!(allocs[1].total() >= 1);
        assert!(allocs[2].total() >= 1);
        assert_eq!(total_alloc(&allocs), 6);
    }
}
