//! Cgroup modeling for the simulator.
//!
//! This module provides a cgroup registry that tracks a hierarchy of cgroups,
//! each with an ID, level, parent, and optional cpuset. It interfaces with
//! C code to allocate `struct cgroup` structures that match the kernel's layout.

use std::collections::HashMap;
use std::ffi::c_void;

use crate::types::CpuId;

/// Unique cgroup identifier (kernel's cgroup->kn->id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CgroupId(pub u64);

impl CgroupId {
    /// The root cgroup's ID (always 1).
    pub const ROOT: CgroupId = CgroupId(1);
}

/// Information about a cgroup in the hierarchy.
#[derive(Debug, Clone)]
pub struct CgroupInfo {
    /// Unique cgroup ID.
    pub cgid: CgroupId,
    /// Depth in the hierarchy (root = 0).
    pub level: u32,
    /// Parent cgroup's ID (0 for root which has no parent).
    pub parent_cgid: CgroupId,
    /// Optional cpuset.cpus configuration (None = all CPUs allowed).
    pub cpuset: Option<Vec<CpuId>>,
    /// Name of the cgroup (for debugging/scenario API).
    pub name: String,
    /// Raw pointer to the C `struct cgroup` allocation.
    raw: *mut c_void,
}

// Safety: CgroupInfo holds a raw pointer to a heap-allocated C struct.
// The pointer is only accessed within the simulator (single-threaded).
unsafe impl Send for CgroupInfo {}
unsafe impl Sync for CgroupInfo {}

impl CgroupInfo {
    /// Get the raw C `struct cgroup` pointer.
    pub fn raw(&self) -> *mut c_void {
        self.raw
    }
}

/// Registry managing the cgroup hierarchy.
///
/// The registry always contains the root cgroup (cgid=1, level=0).
/// Additional cgroups can be created as children of existing cgroups.
pub struct CgroupRegistry {
    /// Map from cgroup ID to cgroup info.
    cgroups: HashMap<CgroupId, CgroupInfo>,
    /// Map from cgroup name to cgroup ID (for scenario API lookups).
    name_to_id: HashMap<String, CgroupId>,
    /// Next available cgroup ID for auto-assignment.
    next_cgid: u64,
    /// Number of CPUs in the system (for cpuset validation in Phase 5).
    #[allow(dead_code)]
    nr_cpus: u32,
}

// FFI declarations for C cgroup allocation functions.
extern "C" {
    fn sim_cgroup_alloc(cgid: u64, level: u32, parent: *mut c_void) -> *mut c_void;
    fn sim_cgroup_free(cgrp: *mut c_void);
    fn sim_get_root_cgroup() -> *mut c_void;
    fn sim_cgroup_set_cpuset(cgrp: *mut c_void, cpus: *const u32, nr_cpus: u32);
}

impl CgroupRegistry {
    /// Create a new cgroup registry with only the root cgroup.
    pub fn new(nr_cpus: u32) -> Self {
        let root_raw = unsafe { sim_get_root_cgroup() };
        let root = CgroupInfo {
            cgid: CgroupId::ROOT,
            level: 0,
            parent_cgid: CgroupId(0), // No parent
            cpuset: None,             // All CPUs
            name: String::new(),      // Root has no name
            raw: root_raw,
        };

        let mut cgroups = HashMap::new();
        cgroups.insert(CgroupId::ROOT, root);

        CgroupRegistry {
            cgroups,
            name_to_id: HashMap::new(),
            next_cgid: 2, // Start after root (1)
            nr_cpus,
        }
    }

    /// Look up a cgroup by ID.
    pub fn get(&self, cgid: CgroupId) -> Option<&CgroupInfo> {
        self.cgroups.get(&cgid)
    }

    /// Look up a cgroup by name.
    pub fn get_by_name(&self, name: &str) -> Option<&CgroupInfo> {
        self.name_to_id
            .get(name)
            .and_then(|cgid| self.cgroups.get(cgid))
    }

    /// Get the raw C `struct cgroup` pointer for a cgroup ID.
    pub fn get_raw(&self, cgid: CgroupId) -> Option<*mut c_void> {
        self.cgroups.get(&cgid).map(|info| info.raw)
    }

    /// Get the root cgroup's raw pointer.
    pub fn root_raw(&self) -> *mut c_void {
        self.cgroups[&CgroupId::ROOT].raw
    }

    /// Create a new cgroup as a child of the given parent.
    ///
    /// Returns the new cgroup's ID.
    pub fn create(
        &mut self,
        name: &str,
        parent_cgid: CgroupId,
        cpuset: Option<Vec<CpuId>>,
    ) -> CgroupId {
        let parent = self.cgroups.get(&parent_cgid).unwrap_or_else(|| {
            panic!("parent cgroup {:?} not found", parent_cgid);
        });

        let cgid = CgroupId(self.next_cgid);
        self.next_cgid += 1;

        let level = parent.level + 1;
        let parent_raw = parent.raw;

        // Allocate the C struct cgroup
        let raw = unsafe { sim_cgroup_alloc(cgid.0, level, parent_raw) };
        assert!(!raw.is_null(), "sim_cgroup_alloc returned null");

        // Set cpuset if specified
        if let Some(ref cpus) = cpuset {
            let cpu_ids: Vec<u32> = cpus.iter().map(|c| c.0).collect();
            unsafe {
                sim_cgroup_set_cpuset(raw, cpu_ids.as_ptr(), cpu_ids.len() as u32);
            }
        }

        let info = CgroupInfo {
            cgid,
            level,
            parent_cgid,
            cpuset,
            name: name.to_string(),
            raw,
        };

        self.cgroups.insert(cgid, info);
        if !name.is_empty() {
            self.name_to_id.insert(name.to_string(), cgid);
        }

        cgid
    }

    /// Create a cgroup with an auto-generated name under the root.
    pub fn create_under_root(&mut self, cpuset: Option<Vec<CpuId>>) -> CgroupId {
        let name = format!("cgroup_{}", self.next_cgid);
        self.create(&name, CgroupId::ROOT, cpuset)
    }

    /// Get the ancestor of a cgroup at a given level.
    ///
    /// Returns `None` if the level is invalid (> cgroup's level).
    pub fn ancestor(&self, cgid: CgroupId, level: u32) -> Option<&CgroupInfo> {
        let cgrp = self.cgroups.get(&cgid)?;
        if level > cgrp.level {
            return None;
        }
        if level == cgrp.level {
            return Some(cgrp);
        }
        // Walk up the tree
        let mut current = cgrp;
        while current.level > level {
            current = self.cgroups.get(&current.parent_cgid)?;
        }
        Some(current)
    }

    /// Iterate all cgroups in pre-order (depth-first, parent before children).
    ///
    /// Starts from the given root and yields descendant cgroups.
    pub fn iter_descendants(&self, root_cgid: CgroupId) -> impl Iterator<Item = &CgroupInfo> {
        // Collect descendants in pre-order
        let mut result = Vec::new();
        let mut stack = vec![root_cgid];

        while let Some(cgid) = stack.pop() {
            if let Some(info) = self.cgroups.get(&cgid) {
                result.push(info);
                // Add children in reverse order so they come out in order
                let children: Vec<CgroupId> = self
                    .cgroups
                    .values()
                    .filter(|c| c.parent_cgid == cgid && c.cgid != cgid)
                    .map(|c| c.cgid)
                    .collect();
                for child_cgid in children.into_iter().rev() {
                    stack.push(child_cgid);
                }
            }
        }

        result.into_iter()
    }

    /// Get all cgroup IDs in pre-order starting from the root.
    pub fn all_cgids_preorder(&self) -> Vec<CgroupId> {
        self.iter_descendants(CgroupId::ROOT)
            .map(|info| info.cgid)
            .collect()
    }

    /// Number of cgroups in the registry.
    pub fn len(&self) -> usize {
        self.cgroups.len()
    }

    /// Check if the registry is empty (should never be true due to root).
    pub fn is_empty(&self) -> bool {
        self.cgroups.is_empty()
    }
}

impl Drop for CgroupRegistry {
    fn drop(&mut self) {
        // Free all non-root cgroups (root is statically allocated in sim_task.c)
        for (cgid, info) in self.cgroups.iter() {
            if *cgid != CgroupId::ROOT && !info.raw.is_null() {
                unsafe { sim_cgroup_free(info.raw) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Global registry pointer for C callback access
// ---------------------------------------------------------------------------

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Global pointer to the active cgroup registry.
///
/// Set by the engine before simulation starts; cleared afterwards.
/// C code calls `sim_cgroup_lookup_by_id` and `sim_cgroup_lookup_ancestor`
/// which read this pointer.
static CGROUP_REGISTRY: AtomicPtr<CgroupRegistry> = AtomicPtr::new(ptr::null_mut());

/// Install a cgroup registry as the active registry for C callbacks.
///
/// # Safety
/// The registry must outlive any C callbacks that may access it.
/// Only one simulation can be active at a time (SIM_LOCK).
pub unsafe fn install_cgroup_registry(registry: &mut CgroupRegistry) {
    CGROUP_REGISTRY.store(registry as *mut CgroupRegistry, Ordering::SeqCst);
}

/// Clear the active cgroup registry.
pub fn clear_cgroup_registry() {
    CGROUP_REGISTRY.store(ptr::null_mut(), Ordering::SeqCst);
}

/// Look up a cgroup by ID (called from C).
///
/// Returns the raw cgroup pointer, or null if not found.
#[no_mangle]
pub extern "C" fn sim_cgroup_lookup_by_id(cgid: u64) -> *mut c_void {
    let registry = CGROUP_REGISTRY.load(Ordering::SeqCst);
    if registry.is_null() {
        // No registry installed - fall back to root
        return unsafe { sim_get_root_cgroup() };
    }
    let registry = unsafe { &*registry };
    registry
        .get(CgroupId(cgid))
        .map(|info| info.raw)
        .unwrap_or_else(ptr::null_mut)
}

/// Look up a cgroup's ancestor at a given level (called from C).
///
/// Returns the ancestor's raw cgroup pointer, or null if invalid.
#[no_mangle]
pub extern "C" fn sim_cgroup_lookup_ancestor(cgrp: *mut c_void, level: u32) -> *mut c_void {
    let registry = CGROUP_REGISTRY.load(Ordering::SeqCst);
    if registry.is_null() || cgrp.is_null() {
        // No registry - fall back to root for level 0
        if level == 0 {
            return unsafe { sim_get_root_cgroup() };
        }
        return ptr::null_mut();
    }
    let registry = unsafe { &*registry };

    // Find the cgroup by its raw pointer
    let cgid = registry
        .cgroups
        .values()
        .find(|info| info.raw == cgrp)
        .map(|info| info.cgid);

    match cgid {
        Some(id) => registry
            .ancestor(id, level)
            .map(|info| info.raw)
            .unwrap_or_else(ptr::null_mut),
        None => ptr::null_mut(),
    }
}

// FFI declarations for CSS iterator
extern "C" {
    fn sim_css_iter_reset();
    fn sim_css_iter_add(cgrp: *mut c_void);
    fn sim_css_iter_set_root(root: *mut c_void);
}

impl CgroupRegistry {
    /// Prepare the CSS iterator for iteration from the given root.
    ///
    /// This populates the C-side iteration list with all descendants
    /// in pre-order. Call this before entering a `bpf_for_each(css, ...)`
    /// loop in scheduler code.
    ///
    /// # Safety
    /// Must be called from the simulator's single-threaded context.
    pub unsafe fn prepare_css_iter(&self, root_cgid: CgroupId) {
        sim_css_iter_reset();

        if let Some(root) = self.cgroups.get(&root_cgid) {
            sim_css_iter_set_root(root.raw);

            // Add all descendants in pre-order
            for info in self.iter_descendants(root_cgid) {
                sim_css_iter_add(info.raw);
            }
        }
    }

    /// Prepare the CSS iterator for iteration from the root cgroup.
    ///
    /// Convenience wrapper for `prepare_css_iter(CgroupId::ROOT)`.
    ///
    /// # Safety
    /// Must be called from the simulator's single-threaded context.
    pub unsafe fn prepare_css_iter_from_root(&self) {
        self.prepare_css_iter(CgroupId::ROOT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_root() {
        let registry = CgroupRegistry::new(4);
        assert!(registry.get(CgroupId::ROOT).is_some());
        assert_eq!(registry.get(CgroupId::ROOT).unwrap().level, 0);
    }
}
