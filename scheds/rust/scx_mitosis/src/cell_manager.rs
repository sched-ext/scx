// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Cell manager for userspace-driven cell creation.
//!
//! This module implements the `--cell-parent-cgroup` mode where cells are created
//! for direct child cgroups of a specified parent. Uses inotify to watch for
//! cgroup creation/destruction and manages cell ID allocation.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use inotify::{Inotify, WatchMask};
use scx_utils::Cpumask;
use tracing::{debug, info};

/// Information about a cell created for a cgroup
#[derive(Debug)]
pub struct CellInfo {
    pub cell_id: u32,
    pub cgroup_path: Option<PathBuf>,
    pub cgid: Option<u64>,
    /// Optional cpuset mask if the cgroup has cpuset.cpus configured
    pub cpuset: Option<Cpumask>,
}

/// Compute the global target CPU count for each cell.
///
/// Each cell gets a floor of 1 CPU, with the remainder distributed proportionally
/// by weight. Returns only counts, not actual CPU assignments.
fn compute_targets(total_cpus: usize, cells: &[(u32, f64)]) -> Result<HashMap<u32, usize>> {
    if cells.is_empty() {
        bail!("compute_targets called with no cells");
    }
    if total_cpus < cells.len() {
        bail!(
            "Not enough CPUs ({}) for {} cells (need at least 1 each)",
            total_cpus,
            cells.len()
        );
    }

    let total_weight: f64 = cells.iter().map(|(_, w)| w).sum();
    let num_cells = cells.len();

    if total_weight <= 0.0 {
        // Equal division fallback
        let per = total_cpus / num_cells;
        let remainder = total_cpus % num_cells;
        return Ok(cells
            .iter()
            .enumerate()
            .map(|(i, (cell_id, _))| {
                let extra = if i < remainder { 1 } else { 0 };
                (*cell_id, per + extra)
            })
            .collect());
    }

    let distributable = total_cpus - num_cells;
    let mut assigned = num_cells;
    let mut raw: Vec<(u32, f64, usize)> = cells
        .iter()
        .map(|(cell_id, w)| {
            let frac = w / total_weight * distributable as f64;
            let floored = frac.floor() as usize;
            assigned += floored;
            (*cell_id, frac - frac.floor(), 1 + floored)
        })
        .collect();

    let mut remainder = total_cpus - assigned;
    raw.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for entry in raw.iter_mut() {
        if remainder == 0 {
            break;
        }
        entry.2 += 1;
        remainder -= 1;
    }

    Ok(raw
        .iter()
        .map(|(cell_id, _, count)| (*cell_id, *count))
        .collect())
}

/// Distribute CPUs among recipients proportionally by weight, without a floor guarantee.
///
/// Unlike `distribute_cpus_by_weight`, recipients with weight 0 (or very low weight)
/// may receive 0 CPUs. If all weights are 0, falls back to equal division.
fn distribute_cpus_proportional(
    cpus: &[usize],
    recipients: &[(u32, f64)],
) -> Result<HashMap<u32, Vec<usize>>> {
    if cpus.is_empty() {
        bail!("distribute_cpus_proportional called with no CPUs");
    }
    if recipients.is_empty() {
        bail!("distribute_cpus_proportional called with no recipients");
    }

    let total_weight: f64 = recipients.iter().map(|(_, w)| w).sum();
    let n = cpus.len();

    let mut allocs: Vec<(u32, usize)> = if total_weight <= 0.0 {
        // Equal division fallback
        let per = n / recipients.len();
        let remainder = n % recipients.len();
        recipients
            .iter()
            .enumerate()
            .map(|(i, (cell_id, _))| {
                let extra = if i < remainder { 1 } else { 0 };
                (*cell_id, per + extra)
            })
            .collect()
    } else {
        let mut assigned = 0usize;
        let mut raw: Vec<(u32, f64, usize)> = recipients
            .iter()
            .map(|(cell_id, w)| {
                let frac = w / total_weight * n as f64;
                let floored = frac.floor() as usize;
                assigned += floored;
                (*cell_id, frac - frac.floor(), floored)
            })
            .collect();

        let mut remainder = n - assigned;
        raw.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for entry in raw.iter_mut() {
            if remainder == 0 {
                break;
            }
            entry.2 += 1;
            remainder -= 1;
        }

        raw.iter()
            .map(|(cell_id, _, count)| (*cell_id, *count))
            .collect()
    };

    // Assign actual CPU numbers
    let mut cpu_iter = cpus.iter().copied();
    allocs.sort_by_key(|(cell_id, _)| *cell_id);
    let mut result: HashMap<u32, Vec<usize>> = HashMap::new();
    for (cell_id, count) in allocs {
        let cpus_for_cell: Vec<usize> = cpu_iter.by_ref().take(count).collect();
        if cpus_for_cell.len() != count {
            bail!(
                "BUG: distribute_cpus_proportional: cell {} expected {} CPUs but got {}",
                cell_id,
                count,
                cpus_for_cell.len()
            );
        }
        if !cpus_for_cell.is_empty() {
            result.insert(cell_id, cpus_for_cell);
        }
    }

    Ok(result)
}

/// Result of CPU assignment computation, containing both primary and optional borrowable masks.
#[derive(Debug)]
pub struct CpuAssignment {
    pub cell_id: u32,
    pub primary: Cpumask,
    pub borrowable: Option<Cpumask>,
}

/// Manages cells for direct child cgroups of a specified parent
pub struct CellManager {
    cell_parent_path: PathBuf,
    inotify: Inotify,
    /// Maps cgroup ID to cell info
    cells: HashMap<u64, CellInfo>,
    /// Maps cell ID to cgroup ID (for reverse lookup)
    cell_id_to_cgid: HashMap<u32, u64>,
    /// Freed cell IDs available for reuse
    free_cell_ids: Vec<u32>,
    next_cell_id: u32,
    max_cells: u32,
    /// Cpumask of all CPUs in the system (from topology)
    all_cpus: Cpumask,
    /// Cgroup directory names to exclude from cell creation
    exclude_names: HashSet<String>,
}

impl CellManager {
    pub fn new(
        cell_parent_path: &str,
        max_cells: u32,
        all_cpus: Cpumask,
        exclude: HashSet<String>,
    ) -> Result<Self> {
        let path = PathBuf::from(format!("/sys/fs/cgroup{}", cell_parent_path));
        if !path.exists() {
            bail!("Cell parent cgroup path does not exist: {}", path.display());
        }
        Self::new_with_path(path, max_cells, all_cpus, exclude)
    }

    fn new_with_path(
        path: PathBuf,
        max_cells: u32,
        all_cpus: Cpumask,
        exclude: HashSet<String>,
    ) -> Result<Self> {
        let inotify = Inotify::init().context("Failed to initialize inotify")?;
        inotify
            .watches()
            .add(&path, WatchMask::CREATE | WatchMask::DELETE)
            .context("Failed to add inotify watch")?;

        let mut mgr = Self {
            cell_parent_path: path.clone(),
            inotify,
            cells: HashMap::new(),
            cell_id_to_cgid: HashMap::new(),
            free_cell_ids: Vec::new(),
            next_cell_id: 1, // Cell 0 is reserved for root
            max_cells,
            all_cpus,
            exclude_names: exclude,
        };

        // Insert cell 0 as a permanent entry. cgid 0 is a safe sentinel —
        // real cgroup inode numbers are always > 0.
        mgr.cells.insert(
            0,
            CellInfo {
                cell_id: 0,
                cgroup_path: None,
                cgid: None,
                cpuset: None,
            },
        );
        mgr.cell_id_to_cgid.insert(0, 0);

        // Scan for existing children at startup
        mgr.scan_existing_children()
            .context("Failed to scan existing child cgroups at startup")?;
        Ok(mgr)
    }

    fn should_exclude(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| self.exclude_names.contains(name))
            .unwrap_or(false)
    }

    fn scan_existing_children(&mut self) -> Result<Vec<(u64, u32)>> {
        let mut assignments = Vec::new();
        let entries = std::fs::read_dir(&self.cell_parent_path).with_context(|| {
            format!(
                "Failed to read cell parent directory: {}",
                self.cell_parent_path.display()
            )
        })?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read directory entry in: {}",
                    self.cell_parent_path.display()
                )
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!("Failed to get file type for: {}", entry.path().display())
            })?;
            if file_type.is_dir() {
                let path = entry.path();
                if self.should_exclude(&path) {
                    continue;
                }
                let cgid = path.metadata()?.ino();
                let (cgid, cell_id) =
                    self.create_cell_for_cgroup(&path, cgid).with_context(|| {
                        format!("Failed to create cell for cgroup: {}", path.display())
                    })?;
                assignments.push((cgid, cell_id));
            }
        }
        Ok(assignments)
    }

    /// Process pending inotify events. Returns list of (cgid, cell_id) for new cells
    /// and list of cell_ids that were destroyed.
    ///
    /// Rather than processing individual events, we simply check if any events occurred
    /// and then rescan the directory to reconcile state. This is simpler and handles
    /// edge cases like inotify queue overflow gracefully.
    pub fn process_events(&mut self) -> Result<(Vec<(u64, u32)>, Vec<u32>)> {
        let mut buffer = [0; 1024];
        let mut has_events = false;

        // Drain all pending events
        loop {
            match self.inotify.read_events(&mut buffer) {
                Ok(events) => {
                    if events.into_iter().next().is_some() {
                        has_events = true;
                    } else {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(e).context("Failed to read inotify events");
                }
            }
        }

        if !has_events {
            return Ok((Vec::new(), Vec::new()));
        }

        // Rescan directory and reconcile with our tracked state
        self.reconcile_cells()
    }

    /// Reconcile our tracked cells with the actual cgroup directory contents.
    /// Returns (new_cells, destroyed_cells).
    fn reconcile_cells(&mut self) -> Result<(Vec<(u64, u32)>, Vec<u32>)> {
        let mut new_cells = Vec::new();

        // Find current cgroups on disk
        let mut current_paths: HashSet<PathBuf> = HashSet::new();
        let entries = std::fs::read_dir(&self.cell_parent_path).with_context(|| {
            format!(
                "Failed to read cell parent directory: {}",
                self.cell_parent_path.display()
            )
        })?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read directory entry in: {}",
                    self.cell_parent_path.display()
                )
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!("Failed to get file type for: {}", entry.path().display())
            })?;
            if file_type.is_dir() {
                let path = entry.path();
                if !self.should_exclude(&path) {
                    current_paths.insert(path);
                }
            }
        }

        // Remove cells for cgroups that no longer exist
        let mut destroyed_cells: HashSet<u32> = HashSet::new();
        self.cells.retain(|&cgid, info| {
            if info.cell_id == 0 {
                return true; // Cell 0 is permanent
            }
            // Non-zero cells always have a cgroup_path
            let cgroup_path = info
                .cgroup_path
                .as_ref()
                .expect("BUG: non-zero cell missing cgroup_path");
            if current_paths.contains(cgroup_path) {
                true
            } else {
                info!(
                    "Destroyed cell {} for cgroup {} (cgid={})",
                    info.cell_id,
                    cgroup_path.display(),
                    cgid
                );
                destroyed_cells.insert(info.cell_id);
                false
            }
        });

        // Update tracking structures for destroyed cells
        self.cell_id_to_cgid
            .retain(|cell_id, _| !destroyed_cells.contains(cell_id));
        self.free_cell_ids.extend(destroyed_cells.iter().copied());

        // Find new cgroups that we don't have cells for
        for path in current_paths {
            let cgid = path.metadata()?.ino();
            if self.cells.contains_key(&cgid) {
                continue; // Already have a cell for this cgroup
            }
            let (cgid, cell_id) = self
                .create_cell_for_cgroup(&path, cgid)
                .with_context(|| format!("Failed to create cell for cgroup: {}", path.display()))?;
            new_cells.push((cgid, cell_id));
        }

        Ok((new_cells, destroyed_cells.into_iter().collect()))
    }

    fn create_cell_for_cgroup(&mut self, path: &Path, cgid: u64) -> Result<(u64, u32)> {
        let cell_id = self.allocate_cell_id()?;

        // Try to read cpuset.cpus for this cgroup
        let cpuset_path = path.join("cpuset.cpus");
        let cpuset = match std::fs::read_to_string(&cpuset_path) {
            Ok(content) => {
                let content = content.trim();
                if content.is_empty() {
                    None
                } else {
                    let mask = Cpumask::from_cpulist(content).with_context(|| {
                        format!(
                            "Failed to parse cpuset '{}' from {}",
                            content,
                            cpuset_path.display()
                        )
                    })?;
                    debug!(
                        "Cell {} has cpuset: {} (from {})",
                        cell_id,
                        content,
                        cpuset_path.display()
                    );
                    Some(mask)
                }
            }
            // File doesn't exist - cpuset controller is not enabled for this cgroup
            Err(_) => None,
        };

        self.cells.insert(
            cgid,
            CellInfo {
                cell_id,
                cgroup_path: Some(path.to_path_buf()),
                cgid: Some(cgid),
                cpuset,
            },
        );
        self.cell_id_to_cgid.insert(cell_id, cgid);

        info!(
            "Created cell {} for cgroup {} (cgid={})",
            cell_id,
            path.display(),
            cgid
        );

        Ok((cgid, cell_id))
    }

    fn allocate_cell_id(&mut self) -> Result<u32> {
        // Prefer reusing freed IDs to keep cell ID space compact
        if let Some(id) = self.free_cell_ids.pop() {
            return Ok(id);
        }

        if self.next_cell_id >= self.max_cells {
            bail!("Cell ID space exhausted (max_cells={})", self.max_cells);
        }

        let id = self.next_cell_id;
        self.next_cell_id += 1;
        Ok(id)
    }

    /// Compute CPU assignments for all cells.
    ///
    /// When cpusets overlap, contested CPUs are divided proportionally among claimants.
    /// Unclaimed CPUs go to cell 0 and any unpinned cells (cells without cpusets).
    ///
    /// If `compute_borrowable` is true, each assignment includes a borrowable cpumask
    /// (all system CPUs minus the cell's own, intersected with cpuset if present).
    /// Without demand data, borrowable masks are uncapped.
    ///
    /// Returns a Vec of CpuAssignment, or an error if any cell would
    /// receive zero CPUs (which indicates too many cells for available CPUs).
    pub fn compute_cpu_assignments(&self, compute_borrowable: bool) -> Result<Vec<CpuAssignment>> {
        // Use equal weights for all cells (no demand data)
        self.compute_cpu_assignments_inner(None, compute_borrowable)
    }

    /// Compute CPU assignments weighted by per-cell demand.
    ///
    /// `cell_demands` maps cell_id -> smoothed_util_pct. All active cells must be
    /// present in the map; missing entries or negative weights are errors.
    ///
    /// If `compute_borrowable` is true, each assignment includes a borrowable cpumask
    /// (all system CPUs minus the cell's own, intersected with cpuset if present).
    pub fn compute_demand_cpu_assignments(
        &self,
        cell_demands: &HashMap<u32, f64>,
        compute_borrowable: bool,
    ) -> Result<Vec<CpuAssignment>> {
        self.compute_cpu_assignments_inner(Some(cell_demands), compute_borrowable)
    }

    /// Internal implementation shared by equal-weight and demand-weighted assignment.
    fn compute_cpu_assignments_inner(
        &self,
        cell_demands: Option<&HashMap<u32, f64>>,
        compute_borrowable: bool,
    ) -> Result<Vec<CpuAssignment>> {
        // Validate that all demand weights are non-negative
        if let Some(demands) = cell_demands {
            for (&cell_id, &weight) in demands {
                if weight < 0.0 {
                    bail!("Cell {} has negative demand weight {}", cell_id, weight);
                }
            }
        }

        // Phase 1: Build contention map - for each CPU, track which cells claim it
        let mut contention: HashMap<usize, Vec<u32>> = HashMap::new();
        for cell_info in self.cells.values() {
            if let Some(ref cpuset) = cell_info.cpuset {
                for cpu in cpuset.iter() {
                    contention.entry(cpu).or_default().push(cell_info.cell_id);
                }
            }
        }

        // Phase 2: Categorize CPUs and build initial assignments
        // - Exclusive: claimed by exactly 1 cell -> assigned directly
        // - Contested: claimed by 2+ cells -> distributed by weight
        // - Unclaimed: no cpuset claims it -> shared among cell 0 + unpinned cells
        let mut cell_cpus: HashMap<u32, Cpumask> = HashMap::new();
        let mut contested_cpus: Vec<usize> = Vec::new();
        let mut unclaimed_cpus: Vec<usize> = Vec::new();

        for cpu in self.all_cpus.iter() {
            match contention.get(&cpu) {
                None => unclaimed_cpus.push(cpu),
                Some(claimants) if claimants.len() == 1 => {
                    let cell_id = claimants[0];
                    cell_cpus
                        .entry(cell_id)
                        .or_insert_with(Cpumask::new)
                        .set_cpu(cpu)
                        .ok();
                }
                Some(_) => contested_cpus.push(cpu),
            }
        }

        // Compute global targets and initialize running count of CPUs assigned per cell
        let total_cpu_count = self.all_cpus.weight();
        let mut all_cells_with_weights: Vec<(u32, f64)> = self
            .cells
            .values()
            .map(|info| {
                let weight = match cell_demands {
                    Some(demands) => *demands.get(&info.cell_id).ok_or_else(|| {
                        anyhow::anyhow!("Cell {} is missing from demands map", info.cell_id)
                    })?,
                    None => 1.0,
                };
                Ok((info.cell_id, weight))
            })
            .collect::<Result<Vec<_>>>()?;
        all_cells_with_weights.sort_by_key(|(cell_id, _)| *cell_id);

        let targets = compute_targets(total_cpu_count, &all_cells_with_weights)?;

        // Seed assigned_count from exclusive assignments
        let mut assigned_count: HashMap<u32, usize> = HashMap::new();
        for (cell_id, mask) in &cell_cpus {
            assigned_count.insert(*cell_id, mask.weight());
        }

        // Phase 3: Distribute contested CPUs among claimants using deficit weights
        let mut contested_groups: HashMap<Vec<u32>, Vec<usize>> = HashMap::new();
        for cpu in contested_cpus {
            if let Some(claimants) = contention.get(&cpu) {
                let mut sorted_claimants = claimants.clone();
                sorted_claimants.sort();
                contested_groups
                    .entry(sorted_claimants)
                    .or_default()
                    .push(cpu);
            }
        }

        for (claimants, cpus) in contested_groups {
            let mut recipients: Vec<(u32, f64)> = Vec::new();
            let mut all_zero = true;
            for &cell_id in &claimants {
                let target = *targets.get(&cell_id).ok_or_else(|| {
                    anyhow::anyhow!(
                        "BUG: cell {} in contention map but missing from targets",
                        cell_id
                    )
                })?;
                let already = assigned_count.get(&cell_id).copied().unwrap_or(0);
                let deficit = if target > already {
                    (target - already) as f64
                } else {
                    0.0
                };
                if deficit > 0.0 {
                    all_zero = false;
                }
                recipients.push((cell_id, deficit));
            }

            // If all claimants already meet/exceed their target, fall back to equal weights
            if all_zero {
                recipients = claimants.iter().map(|&cell_id| (cell_id, 1.0)).collect();
            }

            let distribution = distribute_cpus_proportional(&cpus, &recipients)?;
            for (cell_id, assigned_cpus) in distribution {
                let count = assigned_cpus.len();
                for cpu in assigned_cpus {
                    cell_cpus
                        .entry(cell_id)
                        .or_insert_with(Cpumask::new)
                        .set_cpu(cpu)
                        .ok();
                }
                *assigned_count.entry(cell_id).or_insert(0) += count;
            }
        }

        // Phase 4: Distribute unclaimed CPUs among unpinned cells (including cell 0) using deficit weights
        if !unclaimed_cpus.is_empty() {
            let mut recipients: Vec<(u32, f64)> = Vec::new();
            let mut all_zero = true;

            for info in self.cells.values() {
                if info.cpuset.is_some() {
                    continue; // pinned cells don't receive unclaimed CPUs
                }
                let target = *targets.get(&info.cell_id).ok_or_else(|| {
                    anyhow::anyhow!(
                        "BUG: cell {} is unpinned but missing from targets",
                        info.cell_id
                    )
                })?;
                // Cells with no exclusive CPUs have no entry yet; 0 is correct.
                let already = assigned_count.get(&info.cell_id).copied().unwrap_or(0);
                let deficit = if target > already {
                    (target - already) as f64
                } else {
                    0.0
                };
                if deficit > 0.0 {
                    all_zero = false;
                }
                recipients.push((info.cell_id, deficit));
            }
            recipients.sort_by_key(|(cell_id, _)| *cell_id);

            // If all recipients already meet/exceed their target, fall back to equal weights
            if all_zero {
                recipients = recipients
                    .iter()
                    .map(|(cell_id, _)| (*cell_id, 1.0))
                    .collect();
            }

            let distribution = distribute_cpus_proportional(&unclaimed_cpus, &recipients)?;
            for (cell_id, assigned_cpus) in distribution {
                let count = assigned_cpus.len();
                for cpu in assigned_cpus {
                    cell_cpus
                        .entry(cell_id)
                        .or_insert_with(Cpumask::new)
                        .set_cpu(cpu)
                        .ok();
                }
                *assigned_count.entry(cell_id).or_insert(0) += count;
            }
        }

        // Phase 5: Verify all cells have at least one CPU assigned
        for info in self.cells.values() {
            if !cell_cpus.contains_key(&info.cell_id)
                || cell_cpus
                    .get(&info.cell_id)
                    .map_or(true, |m| m.weight() == 0)
            {
                bail!(
                    "Cell {} has no CPUs assigned (nr_cpus={}, num_cells={})",
                    info.cell_id,
                    self.all_cpus.weight(),
                    self.cells.len()
                );
            }
        }

        // Phase 6: Build CpuAssignment results, optionally computing borrowable masks
        let assignments: Vec<CpuAssignment> = cell_cpus
            .into_iter()
            .map(|(cell_id, primary)| {
                let borrowable = if compute_borrowable {
                    let mut borrow_mask = self.all_cpus.and(&primary.not());

                    // If this cell has a cpuset, restrict borrowable to it
                    if let Some(cell_info) = self.cells.values().find(|c| c.cell_id == cell_id) {
                        if let Some(ref cpuset) = cell_info.cpuset {
                            borrow_mask = borrow_mask.and(cpuset);
                        }
                    }

                    Some(borrow_mask)
                } else {
                    None
                };
                CpuAssignment {
                    cell_id,
                    primary,
                    borrowable,
                }
            })
            .collect();

        Ok(assignments)
    }

    /// Returns all cell assignments as (cgid, cell_id) pairs.
    /// Used to configure BPF with cgroup-to-cell mappings.
    pub fn get_cell_assignments(&self) -> Vec<(u64, u32)> {
        self.cells
            .values()
            .filter(|info| info.cell_id != 0)
            .map(|info| {
                (
                    info.cgid.expect("BUG: non-zero cell missing cgid"),
                    info.cell_id,
                )
            })
            .collect()
    }

    /// Format the cell configuration as a compact string for logging.
    /// Example output: "[0: 0-7] [1(container-a): 8-15] [2(container-b): 16-23]"
    pub fn format_cell_config(&self, cpu_assignments: &[CpuAssignment]) -> String {
        let mut sorted: Vec<_> = cpu_assignments.iter().collect();
        sorted.sort_by_key(|a| a.cell_id);

        let mut parts = Vec::new();
        for assignment in sorted {
            let cpulist = assignment.primary.to_cpulist();
            if assignment.cell_id == 0 {
                parts.push(format!("[0: {}]", cpulist));
            } else {
                // Find cgroup name for this cell
                let name = self
                    .cells
                    .values()
                    .find(|info| info.cell_id == assignment.cell_id)
                    .and_then(|info| {
                        info.cgroup_path
                            .as_ref()
                            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    })
                    .unwrap_or_else(|| "?".to_string());
                parts.push(format!("[{}({}): {}]", assignment.cell_id, name, cpulist));
            }
        }
        parts.join(" ")
    }
}

impl AsFd for CellManager {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inotify.as_fd()
    }
}

#[cfg(test)]
impl CellManager {
    /// Returns the number of cells created for cgroups.
    /// Does not include cell 0 (the implicit root cell).
    fn cell_count(&self) -> usize {
        self.cells.values().filter(|c| c.cell_id != 0).count()
    }

    /// Get all cell IDs for cells created for cgroups.
    /// Does not include cell 0 (the implicit root cell).
    fn get_cell_ids(&self) -> Vec<u32> {
        self.cells
            .values()
            .filter(|c| c.cell_id != 0)
            .map(|c| c.cell_id)
            .collect()
    }

    /// Find a cell by cgroup directory name.
    /// Only searches cells created for cgroups, not cell 0.
    fn find_cell_by_name(&self, name: &str) -> Option<&CellInfo> {
        self.cells.values().filter(|c| c.cell_id != 0).find(|c| {
            c.cgroup_path
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_str() == Some(name))
                .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cpumask_for_range(nr_cpus: usize) -> Cpumask {
        let mut mask = Cpumask::new();
        for cpu in 0..nr_cpus {
            mask.set_cpu(cpu).unwrap();
        }
        mask
    }

    // ==================== Cell scanning and creation tests ====================

    #[test]
    fn test_scan_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        assert_eq!(mgr.cell_count(), 0);
    }

    #[test]
    fn test_scan_existing_subdirectories() {
        let tmp = TempDir::new().unwrap();

        // Create some "cgroup" directories
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        assert_eq!(mgr.cell_count(), 2);

        // Verify cells were assigned IDs 1 and 2
        let cell_ids = mgr.get_cell_ids();
        assert!(cell_ids.contains(&1));
        assert!(cell_ids.contains(&2));
    }

    #[test]
    fn test_reconcile_detects_new_directories() {
        let tmp = TempDir::new().unwrap();

        // Start with one directory
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();
        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        assert_eq!(mgr.cell_count(), 1);

        // Add another directory
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();

        // Reconcile should detect it
        let (new_cells, destroyed_cells) = mgr.reconcile_cells().unwrap();
        assert_eq!(new_cells.len(), 1);
        assert_eq!(destroyed_cells.len(), 0);
        assert_eq!(mgr.cell_count(), 2);
    }

    #[test]
    fn test_reconcile_detects_removed_directories() {
        let tmp = TempDir::new().unwrap();

        // Start with two directories
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();
        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        assert_eq!(mgr.cell_count(), 2);

        // Remove one directory
        std::fs::remove_dir(tmp.path().join("container-b")).unwrap();

        // Reconcile should detect it
        let (new_cells, destroyed_cells) = mgr.reconcile_cells().unwrap();
        assert_eq!(new_cells.len(), 0);
        assert_eq!(destroyed_cells.len(), 1);
        assert_eq!(mgr.cell_count(), 1);
    }

    #[test]
    fn test_cell_id_reuse_after_destruction() {
        let tmp = TempDir::new().unwrap();

        // Create directories
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();
        std::fs::create_dir(tmp.path().join("cell3")).unwrap();

        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        // Find cell2's ID
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();
        let cell2_id = cell2_info.cell_id;

        // Remove cell2
        std::fs::remove_dir(tmp.path().join("cell2")).unwrap();
        mgr.reconcile_cells().unwrap();

        // Add a new directory - should reuse cell2's ID
        std::fs::create_dir(tmp.path().join("cell4")).unwrap();
        mgr.reconcile_cells().unwrap();

        let cell4_info = mgr.find_cell_by_name("cell4").unwrap();
        assert_eq!(cell4_info.cell_id, cell2_id);
    }

    // ==================== compute_cpu_assignments tests ====================

    #[test]
    fn test_cpu_assignments_no_cells() {
        let tmp = TempDir::new().unwrap();
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        // Only cell 0 with all CPUs
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].cell_id, 0);
        assert_eq!(assignments[0].primary.weight(), 16);
    }

    #[test]
    fn test_cpu_assignments_proportional() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("container")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        // 16 CPUs / 2 cells = 8 each
        assert_eq!(assignments.len(), 2);

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let cell1 = assignments.iter().find(|a| a.cell_id == 1).unwrap();

        assert_eq!(cell0.primary.weight(), 8);
        assert_eq!(cell1.primary.weight(), 8);
    }

    #[test]
    fn test_cpu_assignments_remainder_to_cell0() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(10),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        // 10 CPUs / 3 cells = 3 each + 1 remainder to cell 0
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        assert_eq!(cell0.primary.weight(), 4); // 3 + 1 remainder
    }

    #[test]
    fn test_cpu_assignments_too_many_cells() {
        let tmp = TempDir::new().unwrap();

        // Create more cells than CPUs
        for i in 1..=5 {
            std::fs::create_dir(tmp.path().join(format!("cell{}", i))).unwrap();
        }

        // Only 4 CPUs but 6 cells (cell 0 + 5 user cells)
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(4),
            HashSet::new(),
        )
        .unwrap();
        let result = mgr.compute_cpu_assignments(false);

        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("Not enough CPUs"),
            "Expected 'Not enough CPUs' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_cpu_assignments_with_cpusets() {
        let tmp = TempDir::new().unwrap();

        // Create cgroup directories with cpuset files
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-3\n").unwrap();

        let cell2_path = tmp.path().join("cell2");
        std::fs::create_dir(&cell2_path).unwrap();
        std::fs::write(cell2_path.join("cpuset.cpus"), "8-11\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        // Should have 3 assignments: cell1, cell2, and cell0
        assert_eq!(assignments.len(), 3);

        // Find each cell's assignment using find_cell_by_name
        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let cell1 = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let cell2 = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();

        // cell1 gets CPUs 0-3
        assert_eq!(cell1.primary.weight(), 4);
        for cpu in 0..4 {
            assert!(cell1.primary.test_cpu(cpu));
        }

        // cell2 gets CPUs 8-11
        assert_eq!(cell2.primary.weight(), 4);
        for cpu in 8..12 {
            assert!(cell2.primary.test_cpu(cpu));
        }

        // cell0 gets remaining CPUs: 4-7, 12-15
        assert_eq!(cell0.primary.weight(), 8);
        for cpu in 4..8 {
            assert!(cell0.primary.test_cpu(cpu));
        }
        for cpu in 12..16 {
            assert!(cell0.primary.test_cpu(cpu));
        }
    }

    #[test]
    fn test_cpu_assignments_cpusets_cover_all_cpus() {
        let tmp = TempDir::new().unwrap();

        // Create cgroups that cover all CPUs - cell 0 gets nothing, which is an error
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let cell2_path = tmp.path().join("cell2");
        std::fs::create_dir(&cell2_path).unwrap();
        std::fs::write(cell2_path.join("cpuset.cpus"), "8-15\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let result = mgr.compute_cpu_assignments(false);

        // Should error because cell 0 has no CPUs
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = format!("{:#}", err);
        assert!(
            err_msg.contains("Cell 0 has no CPUs assigned"),
            "Expected 'Cell 0 has no CPUs assigned' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_cpu_assignments_single_cpuset() {
        let tmp = TempDir::new().unwrap();

        // Only one cell with a cpuset
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0,2,4,6\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(8),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        assert_eq!(assignments.len(), 2);

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let cell1 = assignments.iter().find(|a| a.cell_id != 0).unwrap();

        // cell1 gets even CPUs
        assert_eq!(cell1.primary.weight(), 4);
        for cpu in [0, 2, 4, 6] {
            assert!(cell1.primary.test_cpu(cpu));
        }

        // cell0 gets odd CPUs
        assert_eq!(cell0.primary.weight(), 4);
        for cpu in [1, 3, 5, 7] {
            assert!(cell0.primary.test_cpu(cpu));
        }
    }

    #[test]
    fn test_cpuset_parsing_from_file() {
        let tmp = TempDir::new().unwrap();

        // Test various cpuset formats
        let cell_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell_path).unwrap();
        std::fs::write(cell_path.join("cpuset.cpus"), "0-3,8-11,16\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(32),
            HashSet::new(),
        )
        .unwrap();

        // Find the cell and verify its cpuset was parsed correctly
        let cell_info = mgr.find_cell_by_name("cell1").unwrap();
        let cpuset = cell_info.cpuset.as_ref().unwrap();

        assert_eq!(cpuset.weight(), 9); // 4 + 4 + 1
        for cpu in 0..4 {
            assert!(cpuset.test_cpu(cpu));
        }
        for cpu in 8..12 {
            assert!(cpuset.test_cpu(cpu));
        }
        assert!(cpuset.test_cpu(16));
    }

    #[test]
    fn test_cpu_assignments_mixed_cpuset_and_no_cpuset() {
        let tmp = TempDir::new().unwrap();

        // cell1 has a cpuset
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-3\n").unwrap();

        // cell2 has NO cpuset (no cpuset.cpus file)
        let cell2_path = tmp.path().join("cell2");
        std::fs::create_dir(&cell2_path).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        // Verify cell1 has cpuset, cell2 doesn't
        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();
        assert!(cell1_info.cpuset.is_some());
        assert!(cell2_info.cpuset.is_none());

        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        // cell1 (pinned) gets its cpuset: 0-3 (4 CPUs)
        // Targets (equal weight, 3 cells, 16 CPUs): cell0=6, cell1=5, cell2=5
        // cell1 has 4 exclusive. Deficit = 1 (but can't participate in unclaimed)
        // 12 unclaimed CPUs split by deficit: cell0 deficit=6, cell2 deficit=5
        // Result: cell0=7, cell1=4, cell2=5
        assert_eq!(assignments.len(), 3);

        // cell1 gets its cpuset (0-3)
        let cell1_assignment = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        assert_eq!(cell1_assignment.primary.weight(), 4);

        // cell0 gets 7 CPUs (deficit-proportional share of unclaimed)
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        assert_eq!(cell0.primary.weight(), 7);

        // cell2 (unpinned) gets 5 CPUs
        let cell2_assignment = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();
        assert_eq!(cell2_assignment.primary.weight(), 5);
    }

    // ==================== Overlapping cpuset tests ====================

    #[test]
    fn test_cpu_assignments_partial_overlap() {
        let tmp = TempDir::new().unwrap();

        // Cell A (cpuset 0-7) and Cell B (cpuset 4-11) - overlap on 4-7
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "4-11\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // Cell A gets exclusive 0-3 (4 CPUs) + half of contested 4-7 (2 CPUs) = 6 CPUs
        // Cell B gets half of contested 4-7 (2 CPUs) + exclusive 8-11 (4 CPUs) = 6 CPUs
        // Cell 0 gets unclaimed 12-15 (4 CPUs)
        assert_eq!(cell_a.primary.weight(), 6);
        assert_eq!(cell_b.primary.weight(), 6);
        assert_eq!(cell0.primary.weight(), 4);

        // Verify exclusive CPUs went to correct cells
        for cpu in 0..4 {
            assert!(
                cell_a.primary.test_cpu(cpu),
                "CPU {} should be in cell_a",
                cpu
            );
        }
        for cpu in 8..12 {
            assert!(
                cell_b.primary.test_cpu(cpu),
                "CPU {} should be in cell_b",
                cpu
            );
        }
        for cpu in 12..16 {
            assert!(
                cell0.primary.test_cpu(cpu),
                "CPU {} should be in cell0",
                cpu
            );
        }

        // Verify contested CPUs 4-7 are split - each cell gets exactly 2
        let cell_a_contested: Vec<_> = (4..8).filter(|&cpu| cell_a.primary.test_cpu(cpu)).collect();
        let cell_b_contested: Vec<_> = (4..8).filter(|&cpu| cell_b.primary.test_cpu(cpu)).collect();
        assert_eq!(cell_a_contested.len(), 2);
        assert_eq!(cell_b_contested.len(), 2);

        // No CPU should be assigned to multiple cells
        for cpu in 0..16 {
            let mut count = 0;
            if cell_a.primary.test_cpu(cpu) {
                count += 1;
            }
            if cell_b.primary.test_cpu(cpu) {
                count += 1;
            }
            if cell0.primary.test_cpu(cpu) {
                count += 1;
            }
            assert!(count <= 1, "CPU {} is assigned to {} cells", cpu, count);
        }
    }

    #[test]
    fn test_cpu_assignments_three_way_overlap() {
        let tmp = TempDir::new().unwrap();

        // All three cells claim CPUs 0-5
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-5\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "0-5\n").unwrap();

        let cell_c_path = tmp.path().join("cell_c");
        std::fs::create_dir(&cell_c_path).unwrap();
        std::fs::write(cell_c_path.join("cpuset.cpus"), "0-5\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(12),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();
        let cell_c_info = mgr.find_cell_by_name("cell_c").unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell_c = assignments
            .iter()
            .find(|a| a.cell_id == cell_c_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // 6 contested CPUs / 3 cells = 2 each
        assert_eq!(cell_a.primary.weight(), 2);
        assert_eq!(cell_b.primary.weight(), 2);
        assert_eq!(cell_c.primary.weight(), 2);

        // Cell 0 gets unclaimed 6-11 (6 CPUs)
        assert_eq!(cell0.primary.weight(), 6);
        for cpu in 6..12 {
            assert!(cell0.primary.test_cpu(cpu));
        }

        // Verify total contested CPUs assigned = 6 (no duplicates)
        let total_contested: usize = (0..6)
            .filter(|&cpu| {
                cell_a.primary.test_cpu(cpu)
                    || cell_b.primary.test_cpu(cpu)
                    || cell_c.primary.test_cpu(cpu)
            })
            .count();
        assert_eq!(total_contested, 6);
    }

    #[test]
    fn test_cpu_assignments_odd_contested_count() {
        let tmp = TempDir::new().unwrap();

        // Two cells contesting 3 CPUs (odd number - can't split evenly)
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-2\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "0-2\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(8),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();

        // 3 CPUs / 2 cells = 1 each + 1 remainder
        // One cell gets 2, the other gets 1
        let total = cell_a.primary.weight() + cell_b.primary.weight();
        assert_eq!(total, 3);
        assert!(cell_a.primary.weight() >= 1 && cell_a.primary.weight() <= 2);
        assert!(cell_b.primary.weight() >= 1 && cell_b.primary.weight() <= 2);

        // No overlap in assignments
        for cpu in 0..3 {
            let a_has = cell_a.primary.test_cpu(cpu);
            let b_has = cell_b.primary.test_cpu(cpu);
            assert!(!(a_has && b_has), "CPU {} assigned to both cells", cpu);
        }
    }

    #[test]
    fn test_cpu_assignments_complete_overlap() {
        let tmp = TempDir::new().unwrap();

        // Two cells with identical cpusets
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // 8 contested CPUs / 2 cells = 4 each
        assert_eq!(cell_a.primary.weight(), 4);
        assert_eq!(cell_b.primary.weight(), 4);

        // Cell 0 gets unclaimed 8-15 (8 CPUs)
        assert_eq!(cell0.primary.weight(), 8);
        for cpu in 8..16 {
            assert!(cell0.primary.test_cpu(cpu));
        }

        // Verify no overlap between cell_a and cell_b
        for cpu in 0..8 {
            let a_has = cell_a.primary.test_cpu(cpu);
            let b_has = cell_b.primary.test_cpu(cpu);
            assert!(!(a_has && b_has), "CPU {} assigned to both cells", cpu);
        }
    }

    #[test]
    fn test_cpu_assignments_no_overlap() {
        // This verifies existing non-overlapping behavior still works
        let tmp = TempDir::new().unwrap();

        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-3\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "4-7\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // No overlap - each cell gets its exact cpuset
        assert_eq!(cell_a.primary.weight(), 4);
        for cpu in 0..4 {
            assert!(cell_a.primary.test_cpu(cpu));
        }

        assert_eq!(cell_b.primary.weight(), 4);
        for cpu in 4..8 {
            assert!(cell_b.primary.test_cpu(cpu));
        }

        // Cell 0 gets remaining 8-15
        assert_eq!(cell0.primary.weight(), 8);
        for cpu in 8..16 {
            assert!(cell0.primary.test_cpu(cpu));
        }
    }

    // ==================== format_cell_config tests ====================

    #[test]
    fn test_format_cell_config_only_cell0() {
        let tmp = TempDir::new().unwrap();
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(8),
            HashSet::new(),
        )
        .unwrap();

        let mut mask = Cpumask::new();
        for cpu in 0..8 {
            mask.set_cpu(cpu).unwrap();
        }

        let assignments = vec![CpuAssignment {
            cell_id: 0,
            primary: mask,
            borrowable: None,
        }];
        let result = mgr.format_cell_config(&assignments);

        assert_eq!(result, "[0: 0-7]");
    }

    #[test]
    fn test_format_cell_config_with_cells() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        let mut mask0 = Cpumask::new();
        for cpu in 0..8 {
            mask0.set_cpu(cpu).unwrap();
        }

        let mut mask1 = Cpumask::new();
        for cpu in 8..16 {
            mask1.set_cpu(cpu).unwrap();
        }

        let assignments = vec![
            CpuAssignment {
                cell_id: 0,
                primary: mask0,
                borrowable: None,
            },
            CpuAssignment {
                cell_id: 1,
                primary: mask1,
                borrowable: None,
            },
        ];
        let result = mgr.format_cell_config(&assignments);

        assert_eq!(result, "[0: 0-7] [1(container-a): 8-15]");
    }

    // ==================== Cell ID exhaustion tests ====================

    #[test]
    fn test_cell_id_exhaustion() {
        let tmp = TempDir::new().unwrap();

        // Create a manager with max_cells=3 (can allocate cell IDs 1 and 2)
        // Cell 0 is reserved, so we can create 2 cells before exhaustion
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            3,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        assert_eq!(mgr.cell_count(), 2); // cell1 + cell2

        // Adding a third cell should fail due to exhaustion
        std::fs::create_dir(tmp.path().join("cell3")).unwrap();
        let result = mgr.reconcile_cells();

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_chain = format!("{:#}", err);
        assert!(
            err_chain.contains("Cell ID space exhausted"),
            "Expected exhaustion error, got: {}",
            err_chain
        );
    }

    #[test]
    fn test_cell_id_reuse_prevents_exhaustion() {
        let tmp = TempDir::new().unwrap();

        // Create a manager with max_cells=3
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            3,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        assert_eq!(mgr.cell_count(), 2);

        // Remove cell1 to free up its ID
        std::fs::remove_dir(tmp.path().join("cell1")).unwrap();
        mgr.reconcile_cells().unwrap();
        assert_eq!(mgr.cell_count(), 1);

        // Now adding cell3 should succeed by reusing the freed ID
        std::fs::create_dir(tmp.path().join("cell3")).unwrap();
        let result = mgr.reconcile_cells();
        assert!(result.is_ok());
        assert_eq!(mgr.cell_count(), 2);
    }

    // ==================== Exclusion tests ====================

    #[test]
    fn test_scan_excludes_named_cgroups() {
        let tmp = TempDir::new().unwrap();

        std::fs::create_dir(tmp.path().join("container-a")).unwrap();
        std::fs::create_dir(tmp.path().join("systemd-workaround.service")).unwrap();
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();

        let exclude = HashSet::from(["systemd-workaround.service".to_string()]);
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            exclude,
        )
        .unwrap();

        // Only 2 cells — the excluded cgroup is not a cell
        assert_eq!(mgr.cell_count(), 2);
        assert!(mgr.find_cell_by_name("container-a").is_some());
        assert!(mgr.find_cell_by_name("container-b").is_some());
        assert!(mgr
            .find_cell_by_name("systemd-workaround.service")
            .is_none());
    }

    #[test]
    fn test_reconcile_excludes_named_cgroups() {
        let tmp = TempDir::new().unwrap();

        std::fs::create_dir(tmp.path().join("container-a")).unwrap();

        let exclude = HashSet::from(["ignored-service".to_string()]);
        let mut mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            exclude,
        )
        .unwrap();
        assert_eq!(mgr.cell_count(), 1);

        // Add an excluded cgroup — should not become a cell
        std::fs::create_dir(tmp.path().join("ignored-service")).unwrap();
        let (new_cells, destroyed_cells) = mgr.reconcile_cells().unwrap();
        assert_eq!(new_cells.len(), 0);
        assert_eq!(destroyed_cells.len(), 0);
        assert_eq!(mgr.cell_count(), 1);

        // Add a non-excluded cgroup — should become a cell
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();
        let (new_cells, destroyed_cells) = mgr.reconcile_cells().unwrap();
        assert_eq!(new_cells.len(), 1);
        assert_eq!(destroyed_cells.len(), 0);
        assert_eq!(mgr.cell_count(), 2);
    }

    // ==================== Borrowable cpumask tests ====================

    #[test]
    fn test_borrowable_cpumasks_basic() {
        let tmp = TempDir::new().unwrap();

        // Create 2 cells without cpusets
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(true).unwrap();

        // Each cell should be able to borrow CPUs from other cells
        for assignment in &assignments {
            let borrow_mask = assignment.borrowable.as_ref().unwrap();
            // borrowable should have no overlap with primary
            let overlap = borrow_mask.and(&assignment.primary);
            assert_eq!(
                overlap.weight(),
                0,
                "Cell {} borrowable overlaps with primary",
                assignment.cell_id
            );
            // borrowable + primary should cover all CPUs
            let union = borrow_mask.or(&assignment.primary);
            assert_eq!(
                union.weight(),
                16,
                "Cell {} union doesn't cover all CPUs",
                assignment.cell_id
            );
        }
    }

    #[test]
    fn test_borrowable_cpumasks_no_overlap() {
        let tmp = TempDir::new().unwrap();

        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-3\n").unwrap();

        let cell2_path = tmp.path().join("cell2");
        std::fs::create_dir(&cell2_path).unwrap();
        std::fs::write(cell2_path.join("cpuset.cpus"), "8-11\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(true).unwrap();

        // Verify no cell's borrowable mask overlaps with its own primary
        for assignment in &assignments {
            let borrow_mask = assignment.borrowable.as_ref().unwrap();
            let overlap = borrow_mask.and(&assignment.primary);
            assert_eq!(
                overlap.weight(),
                0,
                "Cell {} borrowable overlaps with primary",
                assignment.cell_id
            );
        }
    }

    #[test]
    fn test_borrowable_cpumasks_respects_cpuset() {
        let tmp = TempDir::new().unwrap();

        // Cell 1 has cpuset 0-7, Cell 2 has cpuset 8-15
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let cell2_path = tmp.path().join("cell2");
        std::fs::create_dir(&cell2_path).unwrap();
        std::fs::write(cell2_path.join("cpuset.cpus"), "8-15\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(32),
            HashSet::new(),
        )
        .unwrap();
        let assignments = mgr.compute_cpu_assignments(true).unwrap();

        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();

        // Cell 1's borrowable should be restricted to its cpuset (0-7),
        // minus its own CPUs. Since cell1 gets some of 0-7 as primary,
        // the borrowable within 0-7 is whatever it doesn't own.
        let cell1_assignment = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let cell1_borrow = cell1_assignment.borrowable.as_ref().unwrap();
        // Cell 1's borrowable should NOT include CPUs outside its cpuset (0-7)
        for cpu in 8..32 {
            assert!(
                !cell1_borrow.test_cpu(cpu),
                "Cell 1 borrowable should not include CPU {} (outside cpuset)",
                cpu
            );
        }

        // Cell 2's borrowable should be restricted to its cpuset (8-15)
        let cell2_assignment = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();
        let cell2_borrow = cell2_assignment.borrowable.as_ref().unwrap();
        for cpu in 0..8 {
            assert!(
                !cell2_borrow.test_cpu(cpu),
                "Cell 2 borrowable should not include CPU {} (outside cpuset)",
                cpu
            );
        }
        for cpu in 16..32 {
            assert!(
                !cell2_borrow.test_cpu(cpu),
                "Cell 2 borrowable should not include CPU {} (outside cpuset)",
                cpu
            );
        }
    }

    // ==================== compute_demand_cpu_assignments tests ====================

    #[test]
    fn test_demand_cpu_assignments_all_idle() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(12),
            HashSet::new(),
        )
        .unwrap();

        // All cells idle (0 demand) -> falls back to equal division
        let demands: HashMap<u32, f64> = [(0, 0.0), (1, 0.0), (2, 0.0)].into();
        let assignments = mgr.compute_demand_cpu_assignments(&demands, false).unwrap();

        // 12 / 3 = 4 each
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();
        let c1 = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let c2 = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();

        assert_eq!(cell0.primary.weight(), 4);
        assert_eq!(c1.primary.weight(), 4);
        assert_eq!(c2.primary.weight(), 4);
    }

    #[test]
    fn test_demand_cpu_assignments_uneven_demand() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(12),
            HashSet::new(),
        )
        .unwrap();

        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();

        // cell1 is very busy (100%), cell2 is idle (1%), cell0 is moderate (50%)
        let demands: HashMap<u32, f64> = [
            (0, 50.0),
            (cell1_info.cell_id, 100.0),
            (cell2_info.cell_id, 1.0),
        ]
        .into();
        let assignments = mgr.compute_demand_cpu_assignments(&demands, false).unwrap();

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let c1 = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let c2 = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();

        // Busy cell should get more CPUs than idle cell
        assert!(
            c1.primary.weight() > c2.primary.weight(),
            "Busy cell ({}) should have more CPUs than idle cell ({})",
            c1.primary.weight(),
            c2.primary.weight()
        );
        // Each cell should have at least 1 CPU (floor guarantee)
        assert!(c2.primary.weight() >= 1);
        assert!(cell0.primary.weight() >= 1);
        // Total should be 12
        assert_eq!(
            cell0.primary.weight() + c1.primary.weight() + c2.primary.weight(),
            12
        );
    }

    #[test]
    fn test_demand_cpu_assignments_with_cpusets() {
        let tmp = TempDir::new().unwrap();

        // Two cells with overlapping cpusets
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-7\n").unwrap();

        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "4-11\n").unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        // Cell A is much busier than Cell B
        let demands: HashMap<u32, f64> = [
            (0, 10.0),
            (cell_a_info.cell_id, 90.0),
            (cell_b_info.cell_id, 10.0),
        ]
        .into();
        let assignments = mgr.compute_demand_cpu_assignments(&demands, false).unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();

        // Cell A should get more of the contested CPUs 4-7
        // Exclusive: A gets 0-3, B gets 8-11
        // Contested 4-7: A should get more due to higher demand
        assert!(
            cell_a.primary.weight() > cell_b.primary.weight(),
            "Cell A ({}) should have more CPUs than Cell B ({})",
            cell_a.primary.weight(),
            cell_b.primary.weight()
        );

        // Both should have at least their exclusive CPUs
        assert!(cell_a.primary.weight() >= 4);
        assert!(cell_b.primary.weight() >= 4);
    }

    #[test]
    fn test_demand_cpu_assignments_idle_cell_gets_floor() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(12),
            HashSet::new(),
        )
        .unwrap();

        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();

        // cell1 is very busy, cell2 is completely idle (weight 0)
        let demands: HashMap<u32, f64> = [
            (0, 50.0),
            (cell1_info.cell_id, 100.0),
            (cell2_info.cell_id, 0.0),
        ]
        .into();
        let assignments = mgr.compute_demand_cpu_assignments(&demands, false).unwrap();

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let c1 = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let c2 = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();

        // Idle cell gets its minimum target (1 CPU) via deficit-based distribution:
        // compute_targets assigns a target of 1, giving it a deficit of 1.
        assert_eq!(
            c2.primary.weight(),
            1,
            "Idle cell should get minimum target of 1 CPU"
        );
        // Busy cell should get the most CPUs
        assert!(c1.primary.weight() > cell0.primary.weight());
        assert!(c1.primary.weight() > c2.primary.weight());
        // Total should be 12
        assert_eq!(
            cell0.primary.weight() + c1.primary.weight() + c2.primary.weight(),
            12
        );
    }

    #[test]
    fn test_demand_cpu_assignments_negative_weight_errors() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();

        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(8),
            HashSet::new(),
        )
        .unwrap();

        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();

        let demands: HashMap<u32, f64> = [(0, 50.0), (cell1_info.cell_id, -10.0)].into();
        let result = mgr.compute_demand_cpu_assignments(&demands, false);
        assert!(result.is_err(), "Negative weight should be rejected");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("negative demand weight"),
            "Error message should mention negative weight"
        );
    }

    // ==================== Deficit distribution tests ====================

    #[test]
    fn test_deficit_distribution_with_cpusets() {
        // Two pinned cells with overlapping cpusets + cell0.
        // One cell has high demand weight -> gets more contested CPUs.
        // Cell that exceeds target from exclusive gets 0 contested.
        let tmp = TempDir::new().unwrap();

        // cell_a: cpuset 0-9 (10 CPUs)
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-9\n").unwrap();

        // cell_b: cpuset 6-11 (6 CPUs), overlaps with cell_a on 6-9
        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "6-11\n").unwrap();

        // 16 CPUs total
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        // cell_a has high demand (90), cell_b has low demand (10), cell0 moderate (10)
        let demands: HashMap<u32, f64> = [
            (0, 10.0),
            (cell_a_info.cell_id, 90.0),
            (cell_b_info.cell_id, 10.0),
        ]
        .into();
        let assignments = mgr.compute_demand_cpu_assignments(&demands, false).unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // Verify total = 16
        assert_eq!(
            cell_a.primary.weight() + cell_b.primary.weight() + cell0.primary.weight(),
            16,
        );

        // cell_a should get the most CPUs (high demand)
        assert!(
            cell_a.primary.weight() > cell_b.primary.weight(),
            "cell_a ({}) should have more CPUs than cell_b ({})",
            cell_a.primary.weight(),
            cell_b.primary.weight()
        );

        // Every cell should have at least 1 CPU
        assert!(cell_a.primary.weight() >= 1);
        assert!(cell_b.primary.weight() >= 1);
        assert!(cell0.primary.weight() >= 1);
    }

    #[test]
    fn test_deficit_distribution_equal_weight_with_exclusive() {
        // Equal weights, one cell has cpuset covering half the CPUs.
        // The deficit adjustment should give the other cell(s) more unclaimed CPUs.
        let tmp = TempDir::new().unwrap();

        // cell1 has cpuset 0-7 (8 CPUs exclusive, no overlap)
        let cell1_path = tmp.path().join("cell1");
        std::fs::create_dir(&cell1_path).unwrap();
        std::fs::write(cell1_path.join("cpuset.cpus"), "0-7\n").unwrap();

        // cell2 has no cpuset (unpinned)
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        // 16 CPUs total, 3 cells (cell0, cell1, cell2), equal weight
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(16),
            HashSet::new(),
        )
        .unwrap();

        let cell1_info = mgr.find_cell_by_name("cell1").unwrap();
        let cell2_info = mgr.find_cell_by_name("cell2").unwrap();

        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();
        let cell1 = assignments
            .iter()
            .find(|a| a.cell_id == cell1_info.cell_id)
            .unwrap();
        let cell2 = assignments
            .iter()
            .find(|a| a.cell_id == cell2_info.cell_id)
            .unwrap();

        // Targets (equal weight, 3 cells, 16 CPUs): cell0=6, cell1=5, cell2=5
        // cell1 has 8 exclusive (exceeds target of 5), deficit = 0
        // 8 unclaimed CPUs split by deficit: cell0 deficit=6, cell2 deficit=5
        // cell0 gets ceil(6/11*8) ~= 4, cell2 gets floor(5/11*8) ~= 4
        // But exact split: 6/11*8 = 4.36, 5/11*8 = 3.63
        // floor: cell0=4, cell2=3 -> assigned=7, remainder=1 -> cell0 gets it
        // Result: cell0=5, cell1=8, cell2=3

        assert_eq!(cell1.primary.weight(), 8); // Gets all its exclusive CPUs
        assert_eq!(
            cell0.primary.weight() + cell1.primary.weight() + cell2.primary.weight(),
            16,
        );

        // cell0 should get more unclaimed CPUs than cell2 (higher deficit)
        assert!(
            cell0.primary.weight() >= cell2.primary.weight(),
            "cell0 ({}) should have >= CPUs than cell2 ({})",
            cell0.primary.weight(),
            cell2.primary.weight()
        );
    }

    #[test]
    fn test_deficit_all_cells_exceed_target() {
        // Scenario where all claimants in a contested group already exceed their
        // global target from exclusive CPUs alone. Verify fallback to equal distribution.
        let tmp = TempDir::new().unwrap();

        // cell_a: cpuset 0-9 (10 CPUs, overlaps with cell_b on 8-9)
        let cell_a_path = tmp.path().join("cell_a");
        std::fs::create_dir(&cell_a_path).unwrap();
        std::fs::write(cell_a_path.join("cpuset.cpus"), "0-9\n").unwrap();

        // cell_b: cpuset 8-13 (6 CPUs, overlaps with cell_a on 8-9)
        let cell_b_path = tmp.path().join("cell_b");
        std::fs::create_dir(&cell_b_path).unwrap();
        std::fs::write(cell_b_path.join("cpuset.cpus"), "8-13\n").unwrap();

        // 20 CPUs total, 3 cells, equal weight
        // Targets: cell0=7, cell_a=7, cell_b=6 (or similar)
        // cell_a exclusive: 0-7 (8 CPUs) -> exceeds target of 7
        // cell_b exclusive: 10-13 (4 CPUs) -> below target of 6
        // Contested: 8-9 (2 CPUs) -> cell_a deficit=0, cell_b deficit=2
        // cell_b should get both contested CPUs
        let mgr = CellManager::new_with_path(
            tmp.path().to_path_buf(),
            256,
            cpumask_for_range(20),
            HashSet::new(),
        )
        .unwrap();

        let cell_a_info = mgr.find_cell_by_name("cell_a").unwrap();
        let cell_b_info = mgr.find_cell_by_name("cell_b").unwrap();

        let assignments = mgr.compute_cpu_assignments(false).unwrap();

        let cell_a = assignments
            .iter()
            .find(|a| a.cell_id == cell_a_info.cell_id)
            .unwrap();
        let cell_b = assignments
            .iter()
            .find(|a| a.cell_id == cell_b_info.cell_id)
            .unwrap();
        let cell0 = assignments.iter().find(|a| a.cell_id == 0).unwrap();

        // cell_a exceeded its target from exclusive alone, so it gets 0 contested CPUs.
        // cell_b has deficit, so it gets all 2 contested CPUs.
        let cell_a_contested: Vec<_> = (8..10)
            .filter(|&cpu| cell_a.primary.test_cpu(cpu))
            .collect();
        let cell_b_contested: Vec<_> = (8..10)
            .filter(|&cpu| cell_b.primary.test_cpu(cpu))
            .collect();
        assert_eq!(
            cell_a_contested.len(),
            0,
            "cell_a should get 0 contested CPUs (exceeded target)"
        );
        assert_eq!(
            cell_b_contested.len(),
            2,
            "cell_b should get all 2 contested CPUs (has deficit)"
        );

        // Total should be 20
        assert_eq!(
            cell_a.primary.weight() + cell_b.primary.weight() + cell0.primary.weight(),
            20,
        );

        // Every cell should have at least 1 CPU
        assert!(cell0.primary.weight() >= 1);
        assert!(cell_a.primary.weight() >= 1);
        assert!(cell_b.primary.weight() >= 1);
    }

    // ==================== distribute_cpus_proportional tests ====================

    #[test]
    fn test_distribute_proportional_basic() {
        let cpus: Vec<usize> = (0..8).collect();
        let recipients = vec![(0, 3.0), (1, 1.0)];
        let result = distribute_cpus_proportional(&cpus, &recipients).unwrap();

        // 3/4 * 8 = 6 for cell 0, 1/4 * 8 = 2 for cell 1
        assert_eq!(result.get(&0).unwrap().len(), 6);
        assert_eq!(result.get(&1).unwrap().len(), 2);
    }

    #[test]
    fn test_distribute_proportional_zero_weight_gets_nothing() {
        let cpus: Vec<usize> = (0..6).collect();
        let recipients = vec![(0, 1.0), (1, 0.0)];
        let result = distribute_cpus_proportional(&cpus, &recipients).unwrap();

        // Cell 0 gets all, cell 1 gets nothing
        assert_eq!(result.get(&0).unwrap().len(), 6);
        assert!(result.get(&1).is_none() || result.get(&1).unwrap().is_empty());
    }

    #[test]
    fn test_distribute_proportional_all_zero_fallback() {
        let cpus: Vec<usize> = (0..6).collect();
        let recipients = vec![(0, 0.0), (1, 0.0)];
        let result = distribute_cpus_proportional(&cpus, &recipients).unwrap();

        // Falls back to equal division
        assert_eq!(result.get(&0).unwrap().len(), 3);
        assert_eq!(result.get(&1).unwrap().len(), 3);
    }

    // ==================== compute_targets tests ====================

    #[test]
    fn test_compute_targets_equal_weight() {
        let targets = compute_targets(12, &[(0, 1.0), (1, 1.0), (2, 1.0)]).unwrap();
        assert_eq!(*targets.get(&0).unwrap(), 4);
        assert_eq!(*targets.get(&1).unwrap(), 4);
        assert_eq!(*targets.get(&2).unwrap(), 4);
    }

    #[test]
    fn test_compute_targets_with_remainder() {
        let targets = compute_targets(10, &[(0, 1.0), (1, 1.0), (2, 1.0)]).unwrap();
        // 10 / 3 = 3 each + 1 remainder
        let total: usize = targets.values().sum();
        assert_eq!(total, 10);
        for (_, &count) in &targets {
            assert!(count >= 3 && count <= 4);
        }
    }
}
