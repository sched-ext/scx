// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # Rusty load balancer
//!
//! The module that includes logic for performing load balancing in the
//! scx_rusty scheduler.
//!
//! Load Balancing
//! --------------
//!
//! scx_rusty performs load balancing using the following general workflow:
//!
//! 1. Determine domain load averages from the duty cycle buckets in the
//!    dom_ctx_map_elem map, aggregate the load using
//!    scx_utils::LoadCalculator, and then determine load distribution
//!    (accounting for infeasible weights) the scx_utils::LoadLedger object.
//!
//! 2. Create a hierarchy representing load using NumaNode and Domain objects
//!    as follows:
//!
//!                                                              o--------------------------------o
//!                                                              |             LB Root            |
//!                                                              |                                |
//!                                                              | PushNodes: <Load, NumaNode>    |
//!                                                              | PullNodes: <Load, NumaNode>    |
//!                                                              | BalancedNodes: <Load, NumaNode>|
//!                                                              o----------------o---------------o
//!                                                                               |
//!                                                         o---------------------o---------------------o
//!                                                         |                     |                     |
//!                                                         |                     |                     |
//!                                         o---------------o----------------o   ...   o----------------o---------------o
//!                                         |           NumaNode             |         |            NumaNode            |
//!                                         | ID    0                        |         | ID    1                        |
//!                                         | PushDomains <Load, Domain>     |         | PushDomains <Load, Domain>     |
//!                                         | PullDomains <Load, Domain>     |         | PullDomains <Load, Domain>     |
//!                                         | BalancedDomains <Domain>       |         | BalancedDomains <Domain>       |
//!                                         | LoadSum f64                    |         | LoadSum f64                    |
//!                                         | LoadAvg f64                    |         | LoadAvg f64                    |
//!                                         | LoadImbal f64                  |         | LoadImbal f64                  |
//!                                         | BalanceCost f64                |         | BalanceCost f64                |
//!                                         | ...                            |         | ...                            |
//!                                         o---------------o----------------o         o--------------------------------o
//!                                                         |
//!                                                         |
//!                   o--------------------------------o   ...   o--------------------------------o
//!                   |            Domain              |         |            Domain              |
//!                   | ID    0                        |         | ID    1                        |
//!                   | Tasks   <Load, Task>           |         | Tasks  <Load, Task>            |
//!                   | LoadSum f64                    |         | LoadSum f64                    |
//!                   | LoadAvg f64                    |         | LoadAvg f64                    |
//!                   | LoadImbal f64                  |         | LoadImbal f64                  |
//!                   | BalanceCost f64                |         | BalanceCost f64                |
//!                   | ...                            |         | ...                            |
//!                   o--------------------------------o         o----------------o---------------o
//!                                                                               |
//!                                                                               |
//!                                         o--------------------------------o   ...   o--------------------------------o
//!                                         |              Task              |         |              Task              |
//!                                         | PID   0                        |         | PID   1                        |
//!                                         | Load  f64                      |         | Load  f64                      |
//!                                         | Migrated bool                  |         | Migrated bool                  |
//!                                         | IsKworker bool                 |         | IsKworker bool                 |
//!                                         o--------------------------------o         o--------------------------------o
//!
//! As mentioned above, the hierarchy is created by querying BPF for each
//! domain's duty cycle, and using the infeasible.rs crate to determine load
//! averages and load sums for each domain.
//!
//! 3. From the LB Root, we begin by iterating over all NUMA nodes, and
//!    migrating load from any nodes with an excess of load (push nodes) to
//!    nodes with a lack of load (pull domains). The cost of migrations here are
//!    higher than when migrating load between domains within a node.
//!    Ultimately, migrations are performed by moving tasks between domains. The
//!    difference in this step is that imbalances are first addressed by moving
//!    tasks between NUMA nodes, and that such migrations only take place when
//!    imbalances are sufficiently high to warrant it.
//!
//! 4. Once load has been migrated between NUMA nodes, we iterate over each NUMA
//!    node and migrate load between the domains inside of each. The cost of
//!    migrations here are lower than between NUMA nodes. Like with load
//!    balancing between NUMA nodes, migrations here are just moving tasks
//!    between domains.
//!
//! The load hierarchy is always created when load_balance() is called on a
//! LoadBalancer object, but actual load balancing is only performed if the
//! balance_load option is specified.
//!
//! Statistics
//! ----------
//!
//! After load balancing has occurred, statistics may be queried by invoking
//! the get_stats() function on the LoadBalancer object:
//!
//! ```
//! let lb = LoadBalancer::new(...)?;
//! lb.load_balance()?;
//!
//! let stats = lb.get_stats();
//! ...
//! ```
//!
//! Statistics are exported as a vector of NumaStat objects, which each
//! contains load balancing statistics for that NUMA node, as well as
//! statistics for any Domains contained therein as DomainStat objects.
//!
//! Future Improvements
//! -------------------
//!
//! There are a few ways that we could further improve the implementation here:
//!
//! - The logic for load balancing between NUMA nodes, and load balancing within
//!   a specific NUMA node (i.e. between domains in that NUMA node), could
//!   probably be improved to avoid code duplication using traits and/or
//!   generics.
//!
//! - When deciding whether to migrate a task, we're only looking at its impact
//!   on addressing load imbalances. In reality, this is a very complex,
//!   multivariate cost function. For example, a domain with sufficiently low
//!   load to warrant having an imbalance / requiring more load maybe should not
//!   pull load if it's running tasks that are much better suited to isolation.
//!   Or, a domain may not want to push a task to another domain if the task is
//!   co-located with other tasks that benefit from shared L3 cache locality.
//!
//!   Coming up with an extensible and clean way to model and implement this is
//!   likely itself a large project.
//!
//! - We're not accounting for cgroups when performing load balancing.

use core::cmp::Ordering;

use crate::bpf_skel::*;
use crate::bpf_intf;
use crate::DomainGroup;

use std::cell::Cell;
use std::fmt;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::warn;
use ordered_float::OrderedFloat;
use scx_utils::ravg::ravg_read;
use scx_utils::LoadLedger;
use scx_utils::LoadAggregator;
use sorted_vec::SortedVec;
use std::collections::VecDeque;

const RAVG_FRAC_BITS: u32 = bpf_intf::ravg_consts_RAVG_FRAC_BITS;

fn now_monotonic() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    assert!(ret == 0);
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn clear_map(map: &libbpf_rs::Map) {
    for key in map.keys() {
        let _ = map.delete(&key);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum BalanceState {
    Balanced,
    NeedsPush,
    NeedsPull,
}

impl fmt::Display for BalanceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BalanceState::Balanced => write!(f, "BALANCED"),
            BalanceState::NeedsPush => write!(f, "OVER-LOADED"),
            BalanceState::NeedsPull => write!(f, "UNDER-LOADED"),
        }
    }
}

macro_rules! impl_ord_for_type {
    ($($t:ty),*) => {
        $(
            impl PartialEq for $t {
                fn eq(&self, other: &Self) -> bool {
                    <dyn LoadOrdered>::eq(self, other)
                }
            }

            impl Eq for $t {}

            impl PartialOrd for $t {
                fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                    <dyn LoadOrdered>::partial_cmp(self, other)
                }
            }

            impl Ord for $t {
                fn cmp(&self, other: &Self) -> Ordering {
                    <dyn LoadOrdered>::cmp(self, other)
                }
            }
        )*
    };
}

trait LoadOrdered {
    fn get_load(&self) -> OrderedFloat<f64>;
}

impl dyn LoadOrdered {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.get_load().eq(&other.get_load())
    }

    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.get_load().partial_cmp(&other.get_load())
    }

    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_load().cmp(&other.get_load())
    }
}

#[derive(Debug, Clone)]
pub struct LoadEntity {
    cost_ratio: f64,
    push_max_ratio: f64,
    xfer_ratio: f64,
    load_sum: OrderedFloat<f64>,
    load_avg: f64,
    load_delta: f64,
    bal_state: BalanceState,
}

impl LoadEntity {
    fn new(cost_ratio: f64,
           push_max_ratio: f64,
           xfer_ratio: f64,
           load_sum: f64,
           load_avg: f64) -> Self {
        let mut entity = Self {
            cost_ratio,
            push_max_ratio,
            xfer_ratio,
            load_sum: OrderedFloat(load_sum),
            load_avg,
            load_delta: 0.0f64,
            bal_state: BalanceState::Balanced,
        };
        entity.add_load(0.0f64);
        entity
    }

    pub fn load_sum(&self) -> f64 {
        *self.load_sum
    }

    pub fn load_avg(&self) -> f64 {
        self.load_avg
    }

    pub fn imbal(&self) -> f64 {
        self.load_sum() - self.load_avg
    }

    pub fn delta(&self) -> f64 {
        self.load_delta
    }

    fn state(&self) -> BalanceState {
        self.bal_state
    }

    fn rebalance(&mut self, new_load: f64) {
        self.load_sum = OrderedFloat(new_load);

        let imbal = self.imbal();
        let needs_balance = imbal.abs() > self.load_avg * self.cost_ratio;

        self.bal_state = if needs_balance {
            if imbal > 0f64 {
                BalanceState::NeedsPush
            } else {
                BalanceState::NeedsPull
            }
        } else {
            BalanceState::Balanced
        };
    }

    fn add_load(&mut self, delta: f64) {
        self.rebalance(self.load_sum() + delta);
        self.load_delta += delta;
    }

    fn push_cutoff(&self) -> f64 {
        self.imbal().abs() * self.push_max_ratio
    }

    fn xfer_between(&self, other: &LoadEntity) -> f64 {
        self.imbal().abs().min(other.imbal().abs()) * self.xfer_ratio
    }
}

#[derive(Debug)]
struct TaskInfo {
    pid: i32,
    load: OrderedFloat<f64>,
    dom_mask: u64,
    migrated: Cell<bool>,
    is_kworker: bool,
}

impl LoadOrdered for TaskInfo {
    fn get_load(&self) -> OrderedFloat<f64> {
        self.load
    }
}
impl_ord_for_type!(TaskInfo);

struct Domain {
    id: usize,
    queried_tasks: bool,
    load: LoadEntity,
    tasks: SortedVec<TaskInfo>,
}

impl Domain {
    const LOAD_IMBAL_HIGH_RATIO: f64 = 0.05;
    const LOAD_IMBAL_XFER_TARGET_RATIO: f64 = 0.50;
    const LOAD_IMBAL_PUSH_MAX_RATIO: f64 = 0.50;

    fn new(id: usize,
           load_sum: f64,
           load_avg: f64) -> Self {
        Self {
            id,
            queried_tasks: false,
            load: LoadEntity::new(Domain::LOAD_IMBAL_HIGH_RATIO,
                                  Domain::LOAD_IMBAL_PUSH_MAX_RATIO,
                                  Domain::LOAD_IMBAL_XFER_TARGET_RATIO,
                                  load_sum,
                                  load_avg),
            tasks: SortedVec::new(),
        }
    }

    fn transfer_load(&mut self,
                     load: f64,
                     pid: i32,
                     other: &mut Domain,
                     skel: &mut BpfSkel) {
        let cpid = (pid as libc::pid_t).to_ne_bytes();
        let dom_id: u32 = other.id.try_into().unwrap();

        // Ask BPF code to execute the migration.
        if let Err(e) = skel.maps_mut().lb_data().update(
            &cpid,
            &dom_id.to_ne_bytes(),
            libbpf_rs::MapFlags::NO_EXIST,
        ) {
            warn!(
                "Failed to update lb_data map for pid={} error={:?}",
                pid, &e
            );
        }

        self.load.add_load(-load);
        other.load.add_load(load);

        debug!("  DOM {} sending [pid: {:05}](load: {:.06}) --> DOM {} ",
               self.id, pid, load, other.id);
    }

    fn xfer_between(&self, other: &Domain) -> f64 {
        self.load.xfer_between(&other.load)
    }
}

impl LoadOrdered for Domain {
    fn get_load(&self) -> OrderedFloat<f64> {
        self.load.load_sum
    }
}
impl_ord_for_type!(Domain);

struct NumaNode {
    id: usize,
    load: LoadEntity,
    domains: SortedVec<Domain>,
}

impl NumaNode {
    const LOAD_IMBAL_HIGH_RATIO: f64 = 0.17;
    const LOAD_IMBAL_XFER_TARGET_RATIO: f64 = 0.50;
    const LOAD_IMBAL_PUSH_MAX_RATIO: f64 = 0.50;

    fn new(id: usize, numa_load_avg: f64) -> Self {
        Self {
            id,
            load: LoadEntity::new(NumaNode::LOAD_IMBAL_HIGH_RATIO,
                                  NumaNode::LOAD_IMBAL_PUSH_MAX_RATIO,
                                  NumaNode::LOAD_IMBAL_XFER_TARGET_RATIO,
                                  0.0f64, numa_load_avg),
            domains: SortedVec::new(),
        }
    }

    fn allocate_domain(&mut self, id: usize, load: f64, dom_load_avg: f64) {
        let domain = Domain::new(id, load, dom_load_avg);

        self.insert_domain(domain);
        self.load.rebalance(self.load.load_sum() + load);
    }

    fn xfer_between(&self, other: &NumaNode) -> f64 {
        self.load.xfer_between(&other.load)
    }

    fn insert_domain(&mut self, domain: Domain) {
        self.domains.insert(domain);
    }

    fn update_load(&mut self, delta: f64) {
        self.load.add_load(delta);
    }

    fn numa_stat(&self) -> NumaStat {
        let mut n_stat = NumaStat {
            id: self.id,
            load: self.load.clone(),
            domains: Vec::new(),
        };

        for dom in self.domains.iter(){
            n_stat.domains.push(DomainStat {
                id: dom.id,
                load: dom.load.clone(),
            });
        }
        n_stat.domains.sort_by(|x, y| x.id.partial_cmp(&y.id).unwrap());

        n_stat
    }
}

impl LoadOrdered for NumaNode {
    fn get_load(&self) -> OrderedFloat<f64> {
        self.load.load_sum
    }
}
impl_ord_for_type!(NumaNode);

pub struct DomainStat {
    pub id: usize,
    pub load: LoadEntity,
}

fn fmt_balance_stat(f: &mut fmt::Formatter<'_>,
                    load: &LoadEntity, preamble: String) -> fmt::Result {
    let imbal = load.imbal();
    let load_sum = load.load_sum();
    let load_delta = load.delta();
    let get_fmt = |num: f64| if num >= 0.0f64 { format!("{:+4.2}", num) } else { format!("{:4.2}", num) };

    write!(f, "{} load={:4.2} imbal={} load_delta={}",
           preamble, load_sum, get_fmt(imbal), get_fmt(load_delta))
}

impl fmt::Display for DomainStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_balance_stat(f, &self.load, format!("  DOMAIN[{:02}]", self.id))
    }
}

pub struct NumaStat {
    pub id: usize,
    pub load: LoadEntity,
    pub domains: Vec<DomainStat>,
}

impl fmt::Display for NumaStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_balance_stat(f, &self.load, format!("NODE[{:02}]", self.id))
    }
}

pub struct LoadBalancer<'a, 'b> {
    skel: &'a mut BpfSkel<'b>,
    dom_group: Arc<DomainGroup>,
    skip_kworkers: bool,

    infeas_threshold: f64,

    nodes: SortedVec<NumaNode>,

    lb_apply_weight: bool,
    balance_load: bool,
}

// Verify that the number of buckets is a factor of the maximum weight to
// ensure that the range of weight can be split evenly amongst every bucket.
const_assert_eq!(bpf_intf::consts_LB_MAX_WEIGHT % bpf_intf::consts_LB_LOAD_BUCKETS, 0);

impl<'a, 'b> LoadBalancer<'a, 'b> {
    pub fn new(
        skel: &'a mut BpfSkel<'b>,
        dom_group: Arc<DomainGroup>,
        skip_kworkers: bool,
        lb_apply_weight: bool,
        balance_load: bool,
    ) -> Self {
        Self {
            skel,
            skip_kworkers,

            infeas_threshold: bpf_intf::consts_LB_MAX_WEIGHT as f64,

            nodes: SortedVec::new(),

            lb_apply_weight: lb_apply_weight.clone(),
            balance_load,

            dom_group,
        }
    }

    /// Perform load balancing calculations. When load balancing is enabled,
    /// also perform rebalances between NUMA nodes (when running on a
    /// multi-socket host) and domains.
    pub fn load_balance(&mut self) -> Result<()> {
        self.create_domain_hierarchy()?;

        if self.balance_load {
            self.perform_balancing()?
        }

        Ok(())
    }

    pub fn get_stats(&self) -> Vec<NumaStat> {
        let mut numa_stats = Vec::with_capacity(self.dom_group.nr_nodes());
        for node in self.nodes.iter() {
            numa_stats.push(node.numa_stat());
        }

        numa_stats.sort_by(|x, y| x.id.partial_cmp(&y.id).unwrap());

        numa_stats
    }

    fn create_domain_hierarchy(&mut self) -> Result<()> {
        let ledger = self.calculate_load_avgs()?;

        let (dom_loads, total_load) = if !self.lb_apply_weight {
            (ledger.dom_dcycle_sums().to_vec(), ledger.global_dcycle_sum())
        } else {
            self.infeas_threshold = ledger.effective_max_weight();
            (ledger.dom_load_sums().to_vec(), ledger.global_load_sum())
        };

        let num_numa_nodes = self.dom_group.nr_nodes();
        let numa_load_avg = total_load / num_numa_nodes as f64;

        let mut nodes : Vec<NumaNode> = Vec::with_capacity(num_numa_nodes);
        for id in 0..num_numa_nodes {
            nodes.push(NumaNode::new(id, numa_load_avg));
        }

        let dom_load_avg = total_load / dom_loads.len() as f64;
        for (dom_id, load) in dom_loads.iter().enumerate() {
            let numa_id = self.dom_group.dom_numa_id(&dom_id).unwrap();

            if numa_id >= num_numa_nodes {
                bail!("NUMA ID {} exceeds maximum {}", numa_id, num_numa_nodes);
            }

            let node = &mut nodes[numa_id];
            node.allocate_domain(dom_id, *load, dom_load_avg);
        }

        for _ in 0..num_numa_nodes {
            self.nodes.insert(nodes.pop().unwrap());
        }

        Ok(())
    }

    fn calculate_load_avgs(&mut self) -> Result<LoadLedger> {
        const NUM_BUCKETS: u64 = bpf_intf::consts_LB_LOAD_BUCKETS as u64;
        let now_mono = now_monotonic();
        let load_half_life = self.skel.rodata().load_half_life;
        let maps = self.skel.maps();
        let dom_data = maps.dom_data();

        let mut aggregator = LoadAggregator::new(self.dom_group.weight(), !self.lb_apply_weight.clone());

        for dom_id in self.dom_group.doms().keys() {
            let dom = *dom_id;
            let dom_key = unsafe { std::mem::transmute::<u32, [u8; 4]>(dom as u32) };

            if let Some(dom_ctx_map_elem) = dom_data
                .lookup(&dom_key, libbpf_rs::MapFlags::ANY)
                .context("Failed to lookup dom_ctx")?
            {
                let dom_ctx =
                    unsafe { &*(dom_ctx_map_elem.as_slice().as_ptr() as *const bpf_intf::dom_ctx) };

                for bucket in 0..NUM_BUCKETS {
                    let bucket_ctx = dom_ctx.buckets[bucket as usize];
                    let rd = &bucket_ctx.rd;
                    let duty_cycle = ravg_read(
                        rd.val,
                        rd.val_at,
                        rd.old,
                        rd.cur,
                        now_mono,
                        load_half_life,
                        RAVG_FRAC_BITS,
                    );

                    if duty_cycle == 0.0f64 {
                        continue;
                    }

                    let weight = self.bucket_weight(bucket);
                    aggregator.record_dom_load(dom, weight, duty_cycle)?;
                }
            }
        }

        Ok(aggregator.calculate())
    }

    fn bucket_range(&self, bucket: u64) -> (f64, f64) {
        const MAX_WEIGHT: u64 = bpf_intf::consts_LB_MAX_WEIGHT as u64;
        const NUM_BUCKETS: u64 = bpf_intf::consts_LB_LOAD_BUCKETS as u64;
        const WEIGHT_PER_BUCKET: u64 = MAX_WEIGHT / NUM_BUCKETS;

        if bucket >= NUM_BUCKETS {
            panic!("Invalid bucket {}, max {}", bucket, NUM_BUCKETS);
        }

        // w_x = [1 + (10000 * x) / N, 10000 * (x + 1) / N]
        let min_w = 1 + (MAX_WEIGHT * bucket) / NUM_BUCKETS;
        let max_w = min_w + WEIGHT_PER_BUCKET - 1;

        (min_w as f64, max_w as f64)
    }

    fn bucket_weight(&self, bucket: u64) -> usize {
        const WEIGHT_PER_BUCKET: f64 = bpf_intf::consts_LB_WEIGHT_PER_BUCKET as f64;
        let (min_weight, _) = self.bucket_range(bucket);

        // Use the mid-point of the bucket when determining weight
        (min_weight + (WEIGHT_PER_BUCKET / 2.0f64)).ceil() as usize
    }

    /// @dom needs to push out tasks to balance loads. Make sure its
    /// tasks_by_load is populated so that the victim tasks can be picked.
    fn populate_tasks_by_load(&mut self, dom: &mut Domain) -> Result<()> {
        if dom.queried_tasks {
            return Ok(());
        }
        dom.queried_tasks = true;

        // Read active_pids and update write_idx and gen.
        //
        // XXX - We can't read task_ctx inline because self.skel.bss()
        // borrows mutably and thus conflicts with self.skel.maps().
        const MAX_PIDS: u64 = bpf_intf::consts_MAX_DOM_ACTIVE_PIDS as u64;
        let active_pids = &mut self.skel.bss_mut().dom_active_pids[dom.id];
        let mut pids = vec![];

        let (mut ridx, widx) = (active_pids.read_idx, active_pids.write_idx);
        ridx = ridx.max(widx - MAX_PIDS);

        for idx in ridx..widx {
            let pid = active_pids.pids[(idx % MAX_PIDS) as usize];
            pids.push(pid);
        }

        active_pids.read_idx = active_pids.write_idx;
        active_pids.gen += 1;

        // Read task_ctx and load.
        let load_half_life = self.skel.rodata().load_half_life;
        let maps = self.skel.maps();
        let task_data = maps.task_data();
        let now_mono = now_monotonic();

        for pid in pids.iter() {
            let key = unsafe { std::mem::transmute::<i32, [u8; 4]>(*pid) };

            if let Some(task_data_elem) = task_data.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                let task_ctx =
                    unsafe { &*(task_data_elem.as_slice().as_ptr() as *const bpf_intf::task_ctx) };
                if task_ctx.dom_id as usize != dom.id {
                    continue;
                }

                let rd = &task_ctx.dcyc_rd;
                let mut load = ravg_read(
                        rd.val,
                        rd.val_at,
                        rd.old,
                        rd.cur,
                        now_mono,
                        load_half_life,
                        RAVG_FRAC_BITS,
                    );

                if self.lb_apply_weight {
                    let weight = (task_ctx.weight as f64).min(self.infeas_threshold);
                    load *= weight;
                }

                dom.tasks.insert(
                    TaskInfo {
                        pid: *pid,
                        load: OrderedFloat(load),
                        dom_mask: task_ctx.dom_mask,
                        migrated: Cell::new(false),
                        is_kworker: task_ctx.is_kworker,
                    },
                );
            }
        }

        Ok(())
    }

    // Find the first candidate pid which hasn't already been migrated and
    // can run in @pull_dom.
    fn find_first_candidate<'d, I>(
        tasks_by_load: I,
        pull_dom: u32,
        skip_kworkers: bool,
    ) -> Option<&'d TaskInfo>
    where
        I: IntoIterator<Item = &'d TaskInfo>,
    {
        match tasks_by_load
            .into_iter()
            .skip_while(|task| {
                task.migrated.get()
                    || (task.dom_mask & (1 << pull_dom) == 0)
                    || (skip_kworkers && task.is_kworker)
            })
            .next()
        {
            Some(task) => Some(task),
            None => None,
        }
    }

    /// Try to find a task in @push_dom to be moved into @pull_dom. If a task is
    /// found, move the task between the domains, and return the amount of load
    /// transferred between the two.
    fn try_find_move_task(
        &mut self,
        (push_dom, to_push): (&mut Domain, f64),
        (pull_dom, to_pull): (&mut Domain, f64),
        to_xfer: f64,
    ) -> Result<Option<f64>> {
        let to_pull = to_pull.abs();
        let calc_new_imbal = |xfer: f64| (to_push - xfer).abs() + (to_pull - xfer).abs();

        self.populate_tasks_by_load(push_dom)?;

        // We want to pick a task to transfer from push_dom to pull_dom to
        // reduce the load imbalance between the two closest to $to_xfer.
        // IOW, pick a task which has the closest load value to $to_xfer
        // that can be migrated. Find such task by locating the first
        // migratable task while scanning left from $to_xfer and the
        // counterpart while scanning right and picking the better of the
        // two.
        let tasks = std::mem::take(&mut push_dom.tasks).into_vec();
        let (task, new_imbal) = match (
            Self::find_first_candidate(
                tasks
                    .as_slice()
                    .iter()
                    .filter(|x| x.load <= OrderedFloat(to_xfer))
                    .rev(),
                pull_dom.id.try_into().unwrap(),
                self.skip_kworkers,
            ),
            Self::find_first_candidate(
                tasks
                    .as_slice()
                    .iter()
                    .filter(|x| x.load >= OrderedFloat(to_xfer)),
                pull_dom.id.try_into().unwrap(),
                self.skip_kworkers,
            ),
        ) {
            (None, None) => return Ok(None),
            (Some(task), None) | (None, Some(task)) => {
                (task, calc_new_imbal(*task.load))
            }
            (Some(task0), Some(task1)) => {
                let (new_imbal0, new_imbal1) = (calc_new_imbal(*task0.load), calc_new_imbal(*task1.load));
                if new_imbal0 <= new_imbal1 {
                    (task0, new_imbal0)
                } else {
                    (task1, new_imbal1)
                }
            }
        };

        // If the best candidate can't reduce the imbalance, there's nothing
        // to do for this pair.
        let old_imbal = to_push + to_pull;
        if old_imbal < new_imbal {
            std::mem::swap(&mut push_dom.tasks, &mut SortedVec::from_unsorted(tasks));
            return Ok(None);
        }

        let load = *(task.load);
        let pid = task.pid;
        task.migrated.set(true);
        std::mem::swap(&mut push_dom.tasks, &mut SortedVec::from_unsorted(tasks));

        push_dom.transfer_load(load, pid, pull_dom, &mut self.skel);
        Ok(Some(load))
    }

    fn transfer_between_nodes(&mut self,
                              push_node: &mut NumaNode,
                              pull_node: &mut NumaNode) -> Result<f64> {
        debug!("Inter node {} -> {} started",
               push_node.id, pull_node.id);

        let push_imbal = push_node.load.imbal();
        let pull_imbal = pull_node.load.imbal();
        let xfer = push_node.xfer_between(&pull_node);

        if push_imbal <= 0.0f64 || pull_imbal >= 0.0f64 {
            bail!("push node {}:{}, pull node {}:{}",
                  push_node.id, push_imbal, pull_node.id, pull_imbal);
        }
        let mut pushers = VecDeque::with_capacity(push_node.domains.len());
        let mut pullers = Vec::with_capacity(pull_node.domains.len());
        let mut pushed = 0f64;

        while push_node.domains.len() > 0 {
            // Push from the busiest node
            let mut push_dom = push_node.domains.pop().unwrap();
            if push_dom.load.state() != BalanceState::NeedsPush {
                push_node.domains.insert(push_dom);
                break;
            }

            while pull_node.domains.len() > 0 {
                let mut pull_dom = pull_node.domains.remove_index(0);
                if pull_dom.load.state() != BalanceState::NeedsPull {
                    pull_node.domains.insert(pull_dom);
                    break;
                }
                let transferred = self.try_find_move_task((&mut push_dom, push_imbal),
                                                          (&mut pull_dom, pull_imbal),
                                                          xfer)?;
                pullers.push(pull_dom);
                if let Some(transferred) = transferred {
                    pushed = transferred;
                    push_node.update_load(-transferred);
                    pull_node.update_load(transferred);
                    break;
                }
            }
            while pullers.len() > 0 {
                pull_node.domains.insert(pullers.pop().unwrap());
            }
            pushers.push_back(push_dom);
            if pushed > 0.0f64 {
                break;
            }
        }
        while pushers.len() > 0 {
            push_node.domains.insert(pushers.pop_front().unwrap());
        }

        Ok(pushed)
    }

    fn balance_between_nodes(&mut self) -> Result<()> {
        if self.nodes.len() < 2 {
            return Ok(());
        }

        debug!("Node <-> Node LB started");

        // Keep track of the nodes we're pushing load from, and pulling load to,
        // respectively. We use separate vectors like this to allow us to
        // mutably iterate over the same list, and pull nodes from the front and
        // back in a nested fashion. The load algorithm looks roughly like this:
        //
        // In sorted order from most -> least loaded:
        //
        // For each "push node" (i.e. node with a positive load imbalance):
        // restart_push:
        //      For each "pull node" (i.e. node with a negative load imbalance):
        //              For each "push domain" (i.e. each domain in "push node"
        //              with a positive load imbalance):
        //                      For each "pull domain" (i.e. each domain in
        //                      "pull node" with a negative load imbalance):
        //                              load = try_move_load(push_dom -> pull-dom)
        //                              if load > 0
        //                                      goto restart_pushext_pull
        //
        // There are four levels of nesting here, but in practice these are very
        // shallow loops, as a system doesn't usually have many nodes or domains
        // per node, only a subset of them will be imbalanced, and the
        // imbalanced nodes and domains will only ever be in push imbalance, or
        // pull imbalance at any given time.
        //
        // Because we're iterating mutably over these lists, we pop nodes and
        // domains off of their lists, and then re-insert them after we're done
        // doing migrations. The lists below are how we keep track of
        // already-visited nodes while we're still iterating over the lists.
        // Note that we immediately go back to iterating over every pull node
        // any time we successfully transfer load, so that we ensure that we're
        // always sending load to the least-loaded node.
        //
        // Note that we use a VecDeque for the pushers because we're iterating
        // over self.nodes in descending-load order. Thus, when we're done
        // iterating and we're adding the popped nodes back into self.nodes, we
        // want to add them back in _ascending_ order so that we don't have to
        // unnecessarily shift any already-re-added nodes to the right in the
        // backing vector. In other words, this lets us do a true append in the
        // SortedVec, rather than doing an insert(list.len() - 2, node). This
        // applies both to iterating over push-imbalanced nodes, and iterating
        // over push-imbalanced domains in the inner loops.
        let mut pushers = VecDeque::with_capacity(self.nodes.len());
        let mut pullers = Vec::with_capacity(self.nodes.len());

        while self.nodes.len() >= 2 {
            // Push from the busiest node
            let mut push_node = self.nodes.pop().unwrap();
            if push_node.load.state() != BalanceState::NeedsPush {
                self.nodes.insert(push_node);
                break;
            }

            let push_cutoff = push_node.load.push_cutoff();
            let mut pushed = 0f64;
            while self.nodes.len() > 0 && pushed < push_cutoff {
                // To the least busy node
                let mut pull_node = self.nodes.remove_index(0);
                let pull_id = pull_node.id;
                if pull_node.load.state() != BalanceState::NeedsPull {
                    self.nodes.insert(pull_node);
                    break;
                }
                let migrated = self.transfer_between_nodes(&mut push_node, &mut pull_node)?;
                pullers.push(pull_node);
                if migrated > 0.0f64 {
                    // Break after a successful migration so that we can
                    // rebalance the pulling domains before the next
                    // transfer attempt, and ensure that we're trying to
                    // pull from domains in descending-imbalance order.
                    pushed += migrated;
                    debug!("NODE {} sending {:.06} --> NODE {}", push_node.id, migrated, pull_id);
                }
            }
            while pullers.len() > 0 {
                self.nodes.insert(pullers.pop().unwrap());
            }

            if pushed > 0.0f64 {
                debug!("NODE {} pushed {:.06} total load", push_node.id, pushed);
            }
            pushers.push_back(push_node);
        }

        while pushers.len() > 0 {
            self.nodes.insert(pushers.pop_front().unwrap());
        }

        Ok(())
    }

    fn balance_within_node(&mut self, node: &mut NumaNode) -> Result<()> {
        if node.domains.len() < 2 {
            return Ok(())
        }

        debug!("Intra node {} LB started", node.id);

        // See the comment in balance_between_nodes() for the purpose of these
        // lists. Everything is roughly the same here as in that comment block,
        // with the notable exception that we're only iterating over domains
        // inside of a single node.
        let mut pushers = VecDeque::with_capacity(node.domains.len());
        let mut pullers = Vec::new();

        while node.domains.len() >= 2 {
            let mut push_dom = node.domains.pop().unwrap();
            if node.domains.len() == 0 || push_dom.load.state() != BalanceState::NeedsPush {
                node.domains.insert(push_dom);
                break;
            }

            let mut pushed = 0.0f64;
            let push_cutoff = push_dom.load.push_cutoff();
            let push_imbal = push_dom.load.imbal();
            if push_imbal < 0.0f64 {
                bail!("Node {} push dom {} had imbal {}", node.id, push_dom.id, push_imbal);
            }

            while node.domains.len() > 0 && pushed < push_cutoff {
                let mut pull_dom = node.domains.remove_index(0);
                if pull_dom.load.state() != BalanceState::NeedsPull {
                    node.domains.push(pull_dom);
                    break;
                }
                let pull_imbal = pull_dom.load.imbal();
                if pull_imbal >= 0.0f64 {
                    bail!("Node {} pull dom {} had imbal {}", node.id, pull_dom.id, pull_imbal);
                }
                let xfer = push_dom.xfer_between(&pull_dom);
                let transferred = self.try_find_move_task((&mut push_dom, push_imbal),
                                                          (&mut pull_dom, pull_imbal),
                                                          xfer)?;
                if let Some(transferred) = transferred {
                    if transferred <= 0.0f64 {
                        bail!("Expected nonzero load transfer")
                    }
                    pushed += transferred;
                    // We've pushed load to pull_dom, and have already updated
                    // its load (in try_find_move_task()). Re-insert it into the
                    // sorted list (thus ensuring we're still iterating from
                    // least load -> most load in the loop above), and try to
                    // push more load.
                    node.domains.insert(pull_dom);
                    continue;
                }

                // Couldn't push any load to this domain, try the next one.
                pullers.push(pull_dom);
            }
            while pullers.len() > 0 {
                node.domains.insert(pullers.pop().unwrap());
            }

            if pushed > 0.0f64 {
                debug!("DOM {} pushed {:.06} total load", push_dom.id, pushed);
            }
            pushers.push_back(push_dom);
        }
        while pushers.len() > 0 {
            node.domains.insert(pushers.pop_front().unwrap());
        }

        Ok(())
    }

    fn perform_balancing(&mut self) -> Result<()> {
        clear_map(self.skel.maps().lb_data());

        // First balance load between the NUMA nodes. Balancing here has a
        // higher cost function than balancing between domains inside of NUMA
        // nodes, but the mechanics are the same. Adjustments made here are
        // reflected in intra-node balancing decisions made next.
        if self.dom_group.nr_nodes() > 1 {
            self.balance_between_nodes()?;
        }

        // Now that the NUMA nodes have been balanced, do another balance round
        // amongst the domains in each node.

        debug!("Intra node LBs started");

        // Assume all nodes are now balanced.

        let mut nodes = std::mem::take(&mut self.nodes).into_vec();
        for node in nodes.iter_mut() {
            self.balance_within_node(node)?;
        }
        std::mem::swap(&mut self.nodes, &mut SortedVec::from_unsorted(nodes));

        Ok(())
    }
}
