//! Platform-independent cgroup tree types for testing and simulation.
//!
//! This crate provides:
//! - `CGroupTreeNode`: recursive tree structure for cgroup hierarchies
//! - `Resources`: simplified resource limits (CPU, memory, etc.)
//! - `SystemConstraints`: bounds for random generation
//! - `NodeStats`: fairness oracle statistics
//! - Fairness oracle computation functions

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Resource Types
// ---------------------------------------------------------------------------

/// CPU resource configuration.
#[derive(Debug, Clone, Default)]
pub struct CpuResources {
    /// CPU shares (weight) - typically 1-1024, default 100
    pub shares: Option<u64>,
    /// CPU quota in microseconds per period
    pub quota: Option<i64>,
    /// CPU period in microseconds (typically 100000)
    pub period: Option<u64>,
    /// CPU set string (e.g., "0", "0-2", "0,2,4")
    pub cpus: Option<String>,
}

/// Memory resource configuration.
#[derive(Debug, Clone, Default)]
pub struct MemoryResources {
    /// Hard memory limit in bytes
    pub memory_hard_limit: Option<i64>,
    /// Soft memory limit in bytes
    pub memory_soft_limit: Option<i64>,
    /// Swap limit in bytes
    pub memory_swap_limit: Option<i64>,
    /// Swappiness (0-100)
    pub swappiness: Option<u64>,
}

/// Block I/O resource configuration.
#[derive(Debug, Clone, Default)]
pub struct BlkioResources {
    /// I/O weight (typically 10-1000, default 100)
    pub weight: Option<u16>,
    /// Leaf weight for hierarchical I/O
    pub leaf_weight: Option<u16>,
}

/// Network resource configuration.
#[derive(Debug, Clone, Default)]
pub struct NetworkResources {
    /// Network class ID
    pub class_id: Option<u64>,
}

/// PID resource configuration.
#[derive(Debug, Clone, Default)]
pub struct PidResources {
    /// Maximum number of processes
    pub maximum_number_of_processes: Option<i64>,
}

/// Combined resource configuration for a cgroup.
///
/// This is a simplified, platform-independent representation that mirrors
/// the cgroups v2 interface but doesn't depend on any specific cgroup library.
#[derive(Debug, Clone, Default)]
pub struct Resources {
    /// CPU resources
    pub cpu: CpuResources,
    /// Memory resources
    pub memory: MemoryResources,
    /// Block I/O resources
    pub blkio: BlkioResources,
    /// Network resources
    pub network: NetworkResources,
    /// PID resources
    pub pid: PidResources,
}

// ---------------------------------------------------------------------------
// System Constraints
// ---------------------------------------------------------------------------

/// System resource constraints used for generating realistic cgroup configurations.
#[derive(Debug, Clone, Copy)]
pub struct SystemConstraints {
    /// Number of CPUs available on the system
    pub num_cpus: usize,
    /// Total memory in bytes
    pub total_memory_bytes: u64,
}

impl SystemConstraints {
    /// Detect system constraints from the current machine.
    pub fn detect() -> Self {
        let num_cpus = Self::read_num_cpus().unwrap_or(1);
        let total_memory_bytes = Self::read_total_memory().unwrap_or(16 * 1024 * 1024 * 1024);

        Self {
            num_cpus,
            total_memory_bytes,
        }
    }

    /// Read number of CPUs from /proc/cpuinfo.
    fn read_num_cpus() -> Option<usize> {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let count = cpuinfo.matches("processor").count();
        if count > 0 {
            Some(count)
        } else {
            None
        }
    }

    /// Read total memory from /proc/meminfo.
    fn read_total_memory() -> Option<u64> {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let kb = parts[1].parse::<u64>().ok()?;
                    return Some(kb * 1024); // Convert KB to bytes
                }
            }
        }
        None
    }
}

impl Default for SystemConstraints {
    fn default() -> Self {
        Self::detect()
    }
}

// ---------------------------------------------------------------------------
// Node Statistics (Fairness Oracle)
// ---------------------------------------------------------------------------

/// Statistics collected for each node in the tree (both leaf and interior nodes).
#[derive(Debug, Clone)]
pub struct NodeStats {
    /// Node ID
    pub node_id: usize,
    /// Actual scheduled time in nanoseconds for this node.
    /// For leaf nodes: directly measured.
    /// For interior nodes: sum of all descendant leaves.
    pub total_time_ns: u64,
    /// Fraction of total work across ALL leaves (informational)
    pub total_time_fraction: f64,
    /// This node's cpu.weight value (defaults to 100 if not set)
    pub cpu_weight: u64,
    /// Effective cpu.max bandwidth limit (as fraction of one core, e.g., 0.5 = 50%).
    /// This is the minimum of this node's limit and all ancestor limits.
    pub effective_cpu_max: Option<f64>,
    /// Fraction of sibling work this node performed (only if has siblings)
    pub sibling_fraction: Option<f64>,
    /// Expected fair share among siblings based on cpu.weight and cpu.max interaction
    pub expected_sibling_share: Option<f64>,
    /// Deviation from expected share: (actual - expected) / expected.
    /// Positive means got more than fair share, negative means less.
    pub share_deviation: Option<f64>,
    /// Actual utilization vs cpu.max limit (only if cpu.max applies).
    /// > 1.0 indicates a violation.
    pub cpu_max_utilization: Option<f64>,
    /// Whether this is a leaf node
    pub is_leaf: bool,
}

// ---------------------------------------------------------------------------
// CGroup Tree Node
// ---------------------------------------------------------------------------

/// Default maximum depth for randomly generated cgroup trees.
pub const DEFAULT_MAX_TREE_DEPTH: usize = 7;

/// Default maximum number of children per node in randomly generated cgroup trees.
pub const DEFAULT_MAX_CHILDREN: usize = 4;

/// Newtype wrapper around Resources for random generation.
#[derive(Debug, Clone)]
pub struct RandResources(pub Resources);

/// A node in a cgroup tree hierarchy.
#[derive(Debug, Clone)]
pub struct CGroupTreeNode {
    /// Unique node ID for tracking
    pub node_id: usize,
    /// The resource limits for this cgroup
    pub resources: RandResources,
    /// Child cgroups under this node
    pub children: Vec<CGroupTreeNode>,
}

impl CGroupTreeNode {
    /// Create a new leaf node with the given resources.
    pub fn new_leaf(resources: Resources) -> Self {
        Self {
            node_id: 0,
            resources: RandResources(resources),
            children: Vec::new(),
        }
    }

    /// Create a new interior node with the given resources and children.
    pub fn new(resources: Resources, children: Vec<CGroupTreeNode>) -> Self {
        let mut node = Self {
            node_id: 0,
            resources: RandResources(resources),
            children,
        };
        Self::assign_ids(&mut node, &mut 0);
        node
    }

    /// Assign node IDs in preorder traversal.
    pub fn assign_ids(node: &mut CGroupTreeNode, next_id: &mut usize) {
        node.node_id = *next_id;
        *next_id += 1;
        for child in &mut node.children {
            Self::assign_ids(child, next_id);
        }
    }

    /// Create a simple deterministic tree for testing with 2 leaves:
    /// - Root (no limits)
    ///   - Leaf 1: cpu.max = 25%
    ///   - Leaf 2: cpu.max = 50%
    pub fn simple_test_tree() -> Self {
        let root_resources = Resources::default();

        let mut leaf1_resources = Resources::default();
        leaf1_resources.cpu.quota = Some(25000);
        leaf1_resources.cpu.period = Some(100000);

        let mut leaf2_resources = Resources::default();
        leaf2_resources.cpu.quota = Some(50000);
        leaf2_resources.cpu.period = Some(100000);

        let mut tree = Self {
            node_id: 0,
            resources: RandResources(root_resources),
            children: vec![
                Self {
                    node_id: 0,
                    resources: RandResources(leaf1_resources),
                    children: vec![],
                },
                Self {
                    node_id: 0,
                    resources: RandResources(leaf2_resources),
                    children: vec![],
                },
            ],
        };

        Self::assign_ids(&mut tree, &mut 0);
        tree
    }

    /// Count the total number of nodes in this tree.
    pub fn node_count(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(|child| child.node_count())
            .sum::<usize>()
    }

    /// Get the maximum depth of this tree.
    pub fn max_depth(&self) -> usize {
        if self.children.is_empty() {
            0
        } else {
            1 + self
                .children
                .iter()
                .map(|child| child.max_depth())
                .max()
                .unwrap_or(0)
        }
    }

    /// Count the number of leaf nodes in the tree.
    pub fn count_leaves(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            self.children.iter().map(|c| c.count_leaves()).sum()
        }
    }

    /// Pretty-print the tree structure to stderr.
    pub fn print_tree(&self) {
        Self::print_tree_recursive(self, "", true);
    }

    fn print_tree_recursive(node: &CGroupTreeNode, prefix: &str, is_last: bool) {
        let connector = if is_last { "`-" } else { "|-" };
        eprint!("{}{} Node #{} [", prefix, connector, node.node_id);

        let mut info = Vec::new();

        if let Some(ref cpus) = node.resources.0.cpu.cpus {
            info.push(format!("cpus:{}", cpus));
        }
        if let Some(shares) = node.resources.0.cpu.shares {
            info.push(format!("shares:{}", shares));
        }
        if let Some(quota) = node.resources.0.cpu.quota {
            if let Some(period) = node.resources.0.cpu.period {
                let percent = (quota as f64 / period as f64) * 100.0;
                info.push(format!("cpu.max:{:.1}%", percent));
            }
        }
        if let Some(mem) = node.resources.0.memory.memory_hard_limit {
            let mb = mem / (1024 * 1024);
            info.push(format!("mem:{}MB", mb));
        }
        if let Some(mem) = node.resources.0.memory.memory_soft_limit {
            let mb = mem / (1024 * 1024);
            info.push(format!("soft:{}MB", mb));
        }
        if let Some(swappiness) = node.resources.0.memory.swappiness {
            info.push(format!("swappiness:{}", swappiness));
        }
        if let Some(weight) = node.resources.0.blkio.weight {
            info.push(format!("blkio:{}", weight));
        }
        if let Some(class_id) = node.resources.0.network.class_id {
            info.push(format!("netclass:{}", class_id));
        }

        if info.is_empty() {
            eprintln!("no limits]");
        } else {
            eprintln!("{}]", info.join(", "));
        }

        let child_prefix = format!("{}{}", prefix, if is_last { "   " } else { "|  " });
        for (i, child) in node.children.iter().enumerate() {
            let is_last_child = i == node.children.len() - 1;
            Self::print_tree_recursive(child, &child_prefix, is_last_child);
        }
    }
}

// ---------------------------------------------------------------------------
// Fairness Oracle Functions
// ---------------------------------------------------------------------------

/// Compute oracle statistics for all nodes given leaf scheduled times.
pub fn compute_oracle_stats(tree: &CGroupTreeNode, leaf_times: &[(usize, u64)]) -> Vec<NodeStats> {
    let total_ns: u64 = leaf_times.iter().map(|(_, ns)| ns).sum();

    let mut leaf_time_map = HashMap::new();
    for &(node_id, ns) in leaf_times {
        leaf_time_map.insert(node_id, ns);
    }

    let mut all_stats = Vec::new();
    compute_node_stats_recursive(tree, None, total_ns, &leaf_time_map, &mut all_stats);

    // Second pass: compute sibling fractions
    compute_sibling_fractions(tree, &mut all_stats);

    all_stats
}

fn compute_node_stats_recursive(
    node: &CGroupTreeNode,
    parent_cpu_max: Option<f64>,
    total_ns: u64,
    leaf_time_map: &HashMap<usize, u64>,
    all_stats: &mut Vec<NodeStats>,
) -> u64 {
    let is_leaf = node.children.is_empty();

    let this_cpu_max = if let (Some(quota), Some(period)) =
        (node.resources.0.cpu.quota, node.resources.0.cpu.period)
    {
        Some(quota as f64 / period as f64)
    } else {
        None
    };

    let effective_cpu_max = match (this_cpu_max, parent_cpu_max) {
        (Some(this), Some(parent)) => Some(this.min(parent)),
        (Some(this), None) => Some(this),
        (None, Some(parent)) => Some(parent),
        (None, None) => None,
    };

    let cpu_weight = node.resources.0.cpu.shares.unwrap_or(100);

    let total_time_ns = if is_leaf {
        *leaf_time_map.get(&node.node_id).unwrap_or(&0)
    } else {
        let mut sum = 0u64;
        for child in &node.children {
            sum += compute_node_stats_recursive(
                child,
                effective_cpu_max,
                total_ns,
                leaf_time_map,
                all_stats,
            );
        }
        sum
    };

    let total_time_fraction = if total_ns > 0 {
        total_time_ns as f64 / total_ns as f64
    } else {
        0.0
    };

    let stats = NodeStats {
        node_id: node.node_id,
        total_time_ns,
        total_time_fraction,
        cpu_weight,
        effective_cpu_max,
        sibling_fraction: None,
        expected_sibling_share: None,
        share_deviation: None,
        cpu_max_utilization: None,
        is_leaf,
    };

    all_stats.push(stats);

    total_time_ns
}

fn compute_sibling_fractions(tree: &CGroupTreeNode, all_stats: &mut [NodeStats]) {
    let mut parent_map: HashMap<Option<usize>, Vec<usize>> = HashMap::new();
    build_parent_map(tree, None, &mut parent_map);

    let mut node_to_parent_max = HashMap::new();
    build_parent_max_map(tree, None, &mut node_to_parent_max);

    let mut node_to_index = HashMap::new();
    for (idx, stat) in all_stats.iter().enumerate() {
        node_to_index.insert(stat.node_id, idx);
    }

    for (_parent_id, child_ids) in parent_map.iter() {
        if child_ids.len() <= 1 {
            continue;
        }

        let parent_effective_cpu_max = child_ids
            .first()
            .and_then(|&child_id| node_to_parent_max.get(&child_id))
            .copied()
            .flatten();

        let mut sibling_info: Vec<(usize, u64, u64, Option<f64>)> = Vec::new();
        for &child_id in child_ids {
            if let Some(&idx) = node_to_index.get(&child_id) {
                let stat = &all_stats[idx];
                sibling_info.push((
                    stat.node_id,
                    stat.total_time_ns,
                    stat.cpu_weight,
                    stat.effective_cpu_max,
                ));
            }
        }

        let sibling_total_time: u64 = sibling_info.iter().map(|(_, time, _, _)| time).sum();
        let expected_shares = compute_expected_shares(&sibling_info, parent_effective_cpu_max);

        for ((node_id, total_time_ns, _, _), expected_share) in
            sibling_info.iter().zip(expected_shares.iter())
        {
            if let Some(&idx) = node_to_index.get(node_id) {
                let stat = &mut all_stats[idx];

                let sibling_fraction = if sibling_total_time > 0 {
                    *total_time_ns as f64 / sibling_total_time as f64
                } else {
                    0.0
                };

                let share_deviation = if *expected_share > 0.0 {
                    Some((sibling_fraction - expected_share) / expected_share)
                } else {
                    None
                };

                stat.sibling_fraction = Some(sibling_fraction);
                stat.expected_sibling_share = Some(*expected_share);
                stat.share_deviation = share_deviation;
            }
        }
    }
}

fn build_parent_map(
    node: &CGroupTreeNode,
    parent_id: Option<usize>,
    map: &mut HashMap<Option<usize>, Vec<usize>>,
) {
    map.entry(parent_id).or_default().push(node.node_id);
    for child in &node.children {
        build_parent_map(child, Some(node.node_id), map);
    }
}

fn build_parent_max_map(
    node: &CGroupTreeNode,
    parent_max: Option<f64>,
    map: &mut HashMap<usize, Option<f64>>,
) {
    let this_max = if let (Some(quota), Some(period)) =
        (node.resources.0.cpu.quota, node.resources.0.cpu.period)
    {
        Some(quota as f64 / period as f64)
    } else {
        None
    };

    let node_effective_max = match (this_max, parent_max) {
        (Some(this), Some(parent)) => Some(this.min(parent)),
        (Some(this), None) => Some(this),
        (None, Some(parent)) => Some(parent),
        (None, None) => None,
    };

    for child in &node.children {
        map.insert(child.node_id, node_effective_max);
        build_parent_max_map(child, node_effective_max, map);
    }
}

/// Compute expected shares among siblings accounting for cpu.weight and cpu.max interaction.
pub fn compute_expected_shares(
    siblings: &[(usize, u64, u64, Option<f64>)],
    parent_max: Option<f64>,
) -> Vec<f64> {
    let n = siblings.len();
    let mut allocated = vec![0.0; n];
    let mut is_capped = vec![false; n];
    let mut remaining_capacity = 1.0;
    let mut remaining_weight: u64 = siblings.iter().map(|(_, _, w, _)| w).sum();

    let normalized_caps: Vec<Option<f64>> = siblings
        .iter()
        .map(|(_, _, _, child_max)| match (*child_max, parent_max) {
            (Some(child), Some(parent)) if parent > 0.0 => Some((child / parent).min(1.0)),
            _ => None,
        })
        .collect();

    loop {
        let mut any_newly_capped = false;

        for i in 0..n {
            if is_capped[i] {
                continue;
            }

            let (_, _, weight, _) = siblings[i];
            let fair_share = (weight as f64 / remaining_weight as f64) * remaining_capacity;

            if let Some(cap) = normalized_caps[i] {
                if fair_share > cap {
                    allocated[i] = cap;
                    is_capped[i] = true;
                    remaining_capacity -= cap;
                    remaining_weight -= weight;
                    any_newly_capped = true;
                }
            }
        }

        if !any_newly_capped {
            for i in 0..n {
                if !is_capped[i] {
                    let (_, _, weight, _) = siblings[i];
                    allocated[i] = (weight as f64 / remaining_weight as f64) * remaining_capacity;
                }
            }
            break;
        }
    }

    let total_allocated: f64 = allocated.iter().sum();
    if total_allocated > 0.0 {
        allocated.iter().map(|a| a / total_allocated).collect()
    } else {
        vec![0.0; n]
    }
}

/// Print oracle statistics for all nodes.
pub fn print_oracle_stats(stats: &[NodeStats]) {
    let mut leaves: Vec<&NodeStats> = stats.iter().filter(|s| s.is_leaf).collect();
    let mut interior: Vec<&NodeStats> = stats.iter().filter(|s| !s.is_leaf).collect();

    leaves.sort_by_key(|s| s.node_id);
    interior.sort_by_key(|s| s.node_id);

    if !leaves.is_empty() {
        eprintln!("\n=== Leaf Node Statistics ===");
        for stat in leaves {
            print_node_stat(stat);
        }
    }

    if !interior.is_empty() {
        eprintln!("\n=== Interior Node Statistics ===");
        for stat in interior {
            print_node_stat(stat);
        }
    }
}

fn print_node_stat(stat: &NodeStats) {
    eprintln!("\nNode {}", stat.node_id);
    eprintln!("  total_time_ns:       {}", stat.total_time_ns);
    eprintln!(
        "  total_time_fraction: {:.4} ({:.2}%)",
        stat.total_time_fraction,
        stat.total_time_fraction * 100.0
    );
    eprintln!("  cpu_weight:          {}", stat.cpu_weight);

    if let Some(cpu_max) = stat.effective_cpu_max {
        eprintln!("  effective_cpu_max:   {:.2}%", cpu_max * 100.0);
    } else {
        eprintln!("  effective_cpu_max:   none");
    }

    if let Some(sibling_frac) = stat.sibling_fraction {
        eprintln!(
            "  sibling_fraction:    {:.4} ({:.2}%)",
            sibling_frac,
            sibling_frac * 100.0
        );
    }

    if let Some(expected_share) = stat.expected_sibling_share {
        eprintln!(
            "  expected_share:      {:.4} ({:.2}%)",
            expected_share,
            expected_share * 100.0
        );
    }

    if let Some(deviation) = stat.share_deviation {
        let sign = if deviation >= 0.0 { "+" } else { "" };
        eprintln!(
            "  share_deviation:     {}{:.4} ({}{:.2}%)",
            sign,
            deviation,
            sign,
            deviation * 100.0
        );

        if deviation.abs() > 0.10 {
            eprintln!("    WARNING: Deviation exceeds 10%!");
        }
    }

    if let Some(utilization) = stat.cpu_max_utilization {
        eprintln!(
            "  cpu_max_utilization: {:.4} ({:.2}%)",
            utilization,
            utilization * 100.0
        );

        if utilization > 1.0 {
            eprintln!("    VIOLATION: Exceeded cpu.max limit!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_constraints_detection() {
        let constraints = SystemConstraints::detect();
        assert!(constraints.num_cpus > 0);
        assert!(constraints.total_memory_bytes > 0);
    }

    #[test]
    fn test_simple_test_tree() {
        let tree = CGroupTreeNode::simple_test_tree();
        assert_eq!(tree.node_count(), 3);
        assert_eq!(tree.count_leaves(), 2);
        assert_eq!(tree.max_depth(), 1);
    }

    #[test]
    fn test_oracle_stats() {
        let tree = CGroupTreeNode::simple_test_tree();
        // Simulate leaf times
        let leaf_times = vec![(1, 25_000_000u64), (2, 50_000_000u64)];
        let stats = compute_oracle_stats(&tree, &leaf_times);

        // Should have stats for all 3 nodes
        assert_eq!(stats.len(), 3);

        // Leaf nodes should have sibling fractions
        let leaf_stats: Vec<_> = stats.iter().filter(|s| s.is_leaf).collect();
        assert_eq!(leaf_stats.len(), 2);
        for stat in leaf_stats {
            assert!(stat.sibling_fraction.is_some());
        }
    }

    #[test]
    fn test_new_leaf() {
        let resources = Resources::default();
        let node = CGroupTreeNode::new_leaf(resources);
        assert_eq!(node.children.len(), 0);
        assert_eq!(node.count_leaves(), 1);
    }

    #[test]
    fn test_new_interior() {
        let parent_resources = Resources::default();
        let child1 = CGroupTreeNode::new_leaf(Resources::default());
        let child2 = CGroupTreeNode::new_leaf(Resources::default());
        let tree = CGroupTreeNode::new(parent_resources, vec![child1, child2]);

        assert_eq!(tree.node_count(), 3);
        assert_eq!(tree.count_leaves(), 2);
        // Check IDs were assigned
        assert_eq!(tree.node_id, 0);
        assert_eq!(tree.children[0].node_id, 1);
        assert_eq!(tree.children[1].node_id, 2);
    }
}
