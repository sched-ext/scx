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
use tracing::info;

/// Information about a cell created for a cgroup
#[derive(Debug)]
pub struct CellInfo {
    pub cell_id: u32,
    pub cgroup_path: Option<PathBuf>,
    pub cgid: Option<u64>,
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
    nr_cpus: u32,
}

impl CellManager {
    pub fn new(cell_parent_path: &str, max_cells: u32, nr_cpus: u32) -> Result<Self> {
        let path = PathBuf::from(format!("/sys/fs/cgroup{}", cell_parent_path));
        if !path.exists() {
            bail!("Cell parent cgroup path does not exist: {}", path.display());
        }
        Self::new_with_path(path, max_cells, nr_cpus)
    }

    fn new_with_path(path: PathBuf, max_cells: u32, nr_cpus: u32) -> Result<Self> {
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
            nr_cpus,
        };

        // Insert cell 0 as a permanent entry. cgid 0 is a safe sentinel —
        // real cgroup inode numbers are always > 0.
        mgr.cells.insert(
            0,
            CellInfo {
                cell_id: 0,
                cgroup_path: None,
                cgid: None,
            },
        );
        mgr.cell_id_to_cgid.insert(0, 0);

        // Scan for existing children at startup
        mgr.scan_existing_children()
            .context("Failed to scan existing child cgroups at startup")?;
        Ok(mgr)
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
                current_paths.insert(entry.path());
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

        self.cells.insert(
            cgid,
            CellInfo {
                cell_id,
                cgroup_path: Some(path.to_path_buf()),
                cgid: Some(cgid),
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
    /// CPUs are divided equally among cell 0 and all user cells.
    /// Any remainder CPUs go to cell 0.
    ///
    /// Returns a Vec of (cell_id, Cpumask), or an error if any cell would
    /// receive zero CPUs (which indicates too many cells for available CPUs).
    pub fn compute_cpu_assignments(&self) -> Result<Vec<(u32, Cpumask)>> {
        let mut cell_cpus: HashMap<u32, Cpumask> = HashMap::new();

        // All CPUs are distributed equally among all cells (including cell 0)
        let mut sorted_cells: Vec<u32> = self.cells.values().map(|c| c.cell_id).collect();
        sorted_cells.sort();
        let num_recipients = sorted_cells.len();
        let cpus_per_recipient = self.nr_cpus as usize / num_recipients;
        let remainder = self.nr_cpus as usize % num_recipients;

        let mut cpu_iter = 0..self.nr_cpus as usize;

        for (i, &cell_id) in sorted_cells.iter().enumerate() {
            // Earlier cells (lower cell_id) get one extra CPU if there's remainder
            let extra = if i < remainder { 1 } else { 0 };
            let count = cpus_per_recipient + extra;

            for _ in 0..count {
                if let Some(cpu) = cpu_iter.next() {
                    cell_cpus
                        .entry(cell_id)
                        .or_insert_with(Cpumask::new)
                        .set_cpu(cpu)
                        .ok();
                }
            }
        }

        // Verify all cells have at least one CPU assigned
        for info in self.cells.values() {
            if !cell_cpus.contains_key(&info.cell_id)
                || cell_cpus
                    .get(&info.cell_id)
                    .map_or(true, |m| m.weight() == 0)
            {
                bail!(
                    "Cell {} has no CPUs assigned (nr_cpus={}, num_cells={})",
                    info.cell_id,
                    self.nr_cpus,
                    self.cells.len()
                );
            }
        }

        Ok(cell_cpus.into_iter().collect())
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
    pub fn format_cell_config(&self, cpu_assignments: &[(u32, Cpumask)]) -> String {
        let mut parts = Vec::new();
        for (cell_id, cpumask) in cpu_assignments {
            let cpulist = cpumask.to_cpulist();
            if *cell_id == 0 {
                parts.push(format!("[0: {}]", cpulist));
            } else {
                // Find cgroup name for this cell
                let name = self
                    .cells
                    .values()
                    .find(|info| info.cell_id == *cell_id)
                    .and_then(|info| {
                        info.cgroup_path
                            .as_ref()
                            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    })
                    .unwrap_or_else(|| "?".to_string());
                parts.push(format!("[{}({}): {}]", cell_id, name, cpulist));
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

    // ==================== Cell scanning and creation tests ====================

    #[test]
    fn test_scan_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();

        assert_eq!(mgr.cell_count(), 0);
    }

    #[test]
    fn test_scan_existing_subdirectories() {
        let tmp = TempDir::new().unwrap();

        // Create some "cgroup" directories
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();
        std::fs::create_dir(tmp.path().join("container-b")).unwrap();

        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();

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
        let mut mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();
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
        let mut mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();
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

        let mut mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();

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
        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();

        let assignments = mgr.compute_cpu_assignments().unwrap();

        // Only cell 0 with all CPUs
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0, 0);
        assert_eq!(assignments[0].1.weight(), 16);
    }

    #[test]
    fn test_cpu_assignments_proportional() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("container")).unwrap();

        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();
        let assignments = mgr.compute_cpu_assignments().unwrap();

        // 16 CPUs / 2 cells = 8 each
        assert_eq!(assignments.len(), 2);

        let cell0 = assignments.iter().find(|(id, _)| *id == 0).unwrap();
        let cell1 = assignments.iter().find(|(id, _)| *id == 1).unwrap();

        assert_eq!(cell0.1.weight(), 8);
        assert_eq!(cell1.1.weight(), 8);
    }

    #[test]
    fn test_cpu_assignments_remainder_to_cell0() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cell1")).unwrap();
        std::fs::create_dir(tmp.path().join("cell2")).unwrap();

        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 10).unwrap();
        let assignments = mgr.compute_cpu_assignments().unwrap();

        // 10 CPUs / 3 cells = 3 each + 1 remainder to cell 0
        let cell0 = assignments.iter().find(|(id, _)| *id == 0).unwrap();
        assert_eq!(cell0.1.weight(), 4); // 3 + 1 remainder
    }

    #[test]
    fn test_cpu_assignments_too_many_cells() {
        let tmp = TempDir::new().unwrap();

        // Create more cells than CPUs
        for i in 1..=5 {
            std::fs::create_dir(tmp.path().join(format!("cell{}", i))).unwrap();
        }

        // Only 4 CPUs but 6 cells (cell 0 + 5 user cells)
        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 4).unwrap();
        let result = mgr.compute_cpu_assignments();

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = format!("{:#}", err);
        assert!(
            err_msg.contains("has no CPUs assigned"),
            "Expected 'has no CPUs assigned' error, got: {}",
            err_msg
        );
    }

    // ==================== format_cell_config tests ====================

    #[test]
    fn test_format_cell_config_only_cell0() {
        let tmp = TempDir::new().unwrap();
        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 8).unwrap();

        let mut mask = Cpumask::new();
        for cpu in 0..8 {
            mask.set_cpu(cpu).unwrap();
        }

        let assignments = vec![(0u32, mask)];
        let result = mgr.format_cell_config(&assignments);

        assert_eq!(result, "[0: 0-7]");
    }

    #[test]
    fn test_format_cell_config_with_cells() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("container-a")).unwrap();

        let mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 256, 16).unwrap();

        let mut mask0 = Cpumask::new();
        for cpu in 0..8 {
            mask0.set_cpu(cpu).unwrap();
        }

        let mut mask1 = Cpumask::new();
        for cpu in 8..16 {
            mask1.set_cpu(cpu).unwrap();
        }

        let assignments = vec![(0u32, mask0), (1u32, mask1)];
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

        let mut mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 3, 16).unwrap();
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

        let mut mgr = CellManager::new_with_path(tmp.path().to_path_buf(), 3, 16).unwrap();
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
}
