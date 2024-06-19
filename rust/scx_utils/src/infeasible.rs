// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Load Calculator
//!
//! A crate providing abstractions for calculating load between scheduling
//! domains.
//!
//! Load Balancing Primer
//! ---------------------
//!
//! Let's begin by doing a brief overview of load balancing. In order to
//! understand load balancing, we'll introduce the relevant terms, and explain
//! what load balancing is from there:
//!
//! *Weight*
//!
//! A positive integer value representing a task's priority in the system. The
//! meaning of weight is ultimately up to the caller to determine and apply, but
//! conceptually speaking weight is a linear scaling factor of a task's
//! perceived load (defined below) in the system.
//!
//! *Duty Cycle*
//!
//! A task's duty cycle is the proportion of time that it could have used a CPU
//! in some time window. For example, say that a task does nothing but spin in a
//! tight loop for 10ms, and then sleep for 10ms. Then in a 20ms time window,
//! its duty cycle would be 0.5.
//!
//! Note that this is not the same thing as the proportion of time it's
//! _runnable_. For example, if you had two such tasks sharing a CPU, one of
//! them may wait for 10ms to use the core while the other one runs, and then it
//! would run for its 10ms duty cycle. It was runnable for 20ms, but could only
//! actually use the CPU for 10ms, so its duty cycle was 10ms / 20ms = 0.5.
//!
//! *Load*
//!
//! A scheduling entity's load l_x is simply the product of its weight and duty
//! cycle:
//!
//! l_x = w_x * d_x
//!
//! *Infeasible Weights*
//!
//! At a conceptual level, the goal of a load balancer is of course to balance
//! load across the system. If a scheduling entity has load l_x, and the total
//! sum of all entities' loads on the system is L, then entity x should receive
//! l_x / L proportion of the available CPU capacity on the system.
//!
//! This formulation works fine in many cases, but can break down when an
//! entity's proportion of load (and thus allotted CPU capacity) exceeds the
//! amount of CPU it can consume.
//!
//! For example, say you were on a system with 2 sets of 2-core groups (for a
//! total of 4 cores on the system), eight tasks with the following duty cycle
//! and weight:
//!
//! ID          Weight          Duty Cycle              Load
//!
//! 0           1               1.0                     1
//! 1           1               1.0                     1
//! 2           1               1.0                     1
//! 3           1               1.0                     1
//! 4           1               1.0                     1
//! 5           1               1.0                     1
//! 6           1               1.0                     1
//! 7           10000           1.0                     10000
//!
//!
//! The load sum L of the system is 1 * 7 + 1 * 10000 = 10007. This means that
//! tasks 0-6 have a load proportion of 1 / 10007 ~= 0.0001, and task 7 has a
//! load proportion of 0.9993. In other words, tasks 0-6 are entitled to
//! 0.0001 * 4 = 0.0004 CPUs worth of capacity, and task 7 is entitled to
//! 0.9993 * 4 = 3.9972 CPUs worth of capacity.
//!
//! Task 7 can only consume at most 1.0 CPU due to its duty cycle being 1.0, so
//! its weight is "infeasible" as the amount of CPU capacity it would be
//! afforded exceeds what it can actually use.
//!
//! What we instead want is to find an adjusted weight w' that we can assign to
//! Task 7 such that it gets its full duty cycle of 1.0, but allows the
//! remaining 3 cores worth of compute to be equally spread amongst the
//! remaining tasks. The task of finding this weight w' is known as the
//! "infeasible weights problem", and is solved by this crate.
//!
//! More details on load balancing and the infeasible weights problem are
//! provided in the following Google Drive document:
//!
//! https://drive.google.com/file/d/1fAoWUlmW-HTp6akuATVpMxpUpvWcGSAv
//!
//! Using the Crate
//! ---------------
//!
//! This crate has two primary sets of APIs:
//!
//! (1) APIs for aggregating domain loads specified by the caller
//! (2) APIs for querying those loads, after being adjusted for infeasibility
//!
//! LoadAggregator
//! --------------
//!
//! The object that addresses (1) is the LoadAggregator. This object receives
//! load passed by the user, and once all load has been received, runs the
//! numbers to create load sums and weights that are adjusted for infeasibility
//! as described above. LoadAggregator objects can be created and used as
//! follows:
//!
//! Assume we're on a 16-core (32-CPU) host with two core complexes:
//!
//!```
//!     // Create a LoadAggregator object, specifying the number of CPUs on the
//!     // system, and whether it should only aggregate duty cycle.
//!     let mut aggregator = LoadAggregator::new(32, false);
//!
//!     // Domain 0, weight 1, has duty cycle 1.0.
//!     aggregator.record_dom_load(0, 1, 1.0);
//!
//!     // Domain 1, weight 1, has duty cycle 1.0.
//!     aggregator.record_dom_load(1, 1, 1.0);
//!     // ...
//!     aggregator.record_dom_load(31, 1, 1.0);
//!     // ...
//!     aggregator.record_dom_load(63, 1, 1.0);
//!
//!     // Domain 64, weight 10000, has duty cycle 1.0.
//!     aggregator.record_dom_load(64, 10000, 1.0);
//!
//!     // Note that it is allowed to record load for a domain more than once.
//!     // For a given domain you may only record load for a specific weight
//!     // once, but you may record loads for multiple different weights for a
//!     // single domain.
//!
//!     // Create the LoadLedger object
//!     let ledger = aggregator.calculate();
//!
//!     // Outputs: 66.06451612903226
//!     info!("{}", ledger.global_load_sum());
//!```
//!
//! In the above example, we have 65 domains, all with duty cycle 1.0. 64 of
//! them have weight 1, and one of them has weight 10000. If there were multiple
//! tasks per domain, we would record different or additional values. For
//! example, if we had two tasks with weight 1 in domain 0, and an additional
//! task with weight 100 in domain 1, we would record their loads as follows:
//!
//!```
//!     // Assume the same aggregator as above.
//!
//!     // In this version, domain 0 has 2 tasks with weight 1.0 and duty cycle
//!     // 1.0.
//!     aggregator.record_dom_load(0, 1, 2.0);
//!
//!     // In this version, domain 1 also has a task with weight 100 and duty
//!     // cycle 1.0.
//!     aggregator.record_dom_load(1, 100, 1.0);
//!```
//!
//! Note that the abstractions here are meant to be generic across schedulers.
//! LoadAggregator assumes nothing about the scheduling domains being passed to
//! it. For example, they may span layers defined in a scheduler, domains
//! specified by the user via cpumask strings, or domains that span L3 caches.
//!
//! LoadLedger
//! ----------
//!
//! Once you have fed all load values to the LoadAggregator, you can use it to
//! calculate load sums (including adjusting for weight infeasibility), and
//! create a read-only LoadLedger object that can be used to query the values as
//! described in (2).
//!
//! There are various values of interest that can be queried from a LoadLedger
//! object. For example, you may ask for the sum of load (adjusted for
//! infeasibility) for the whole system, or the sum of duty cycle for the whole
//! system, or the sum of load for each domain (adjusted for infeasibility):
//!
//! ```
//!     let mut aggregator = LoadAggregator::new(32, false);
//!     aggregator.record_dom_load(0, 1, 1.0);
//!     // ...
//!     aggregator.record_dom_load(63, 1, 1.0);
//!     aggregator.record_dom_load(64, 10000, 1.0);
//!
//!     let ledger = aggregator.calculate();
//!
//!     info!("Global load sum: {}", ledger.global_load_sum());
//!     info!("Global duty cycle sum: {}", ledger.global_dcycle_sum());
//!
//!     let dom_dcycles = ledger.dom_dcycle_sums();
//!     let dom_loads = ledger.dom_dcycle_sums();
//!     let effective_max_weight = ledger.effective_max_weight();
//!
//!     // ...
//! ```

use anyhow::bail;
use anyhow::Result;
use std::collections::BTreeMap;

const MIN_WEIGHT: usize = 1;

#[derive(Debug)]
pub struct LoadLedger {
    dom_load_sums: Vec<f64>,
    dom_dcycle_sums: Vec<f64>,
    global_dcycle_sum: f64,
    global_load_sum: f64,
    effective_max_weight: f64,
}

impl LoadLedger {
    /// Return the global, host-wide sum of duty cycles.
    pub fn global_dcycle_sum(&self) -> f64 {
        self.global_dcycle_sum
    }

    /// Return the global, host-wide load sum; adjusted for infeasibility.
    pub fn global_load_sum(&self) -> f64 {
        self.global_load_sum
    }

    /// Return an array of domain duty cycle sums, indexed by ID.
    pub fn dom_dcycle_sums(&self) -> &[f64] {
        &self.dom_dcycle_sums
    }

    /// Return an array of domain load sums, indexed by ID, and adjusted for
    /// infeasibility.
    pub fn dom_load_sums(&self) -> &[f64] {
        &self.dom_load_sums
    }

    /// If applicable, return the adjusted weight for all infeasible scheduling
    /// entities.
    pub fn effective_max_weight(&self) -> f64 {
        self.effective_max_weight
    }
}

#[derive(Debug)]
struct Domain {
    loads: BTreeMap<usize, f64>,
    dcycle_sum: f64,
    load_sum: f64,
}

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() <= 0.0001f64
}

fn approx_ge(a: f64, b: f64) -> bool {
    a > b || approx_eq(a, b)
}

#[derive(Debug)]
pub struct LoadAggregator {
    doms: BTreeMap<usize, Domain>,
    global_loads: BTreeMap<usize, f64>,
    nr_cpus: usize,
    max_weight: usize,
    global_dcycle_sum: f64,
    global_load_sum: f64,
    effective_max_weight: f64,
    dcycle_only: bool,
}

impl LoadAggregator {
    /// Create a LoadAggregator object that can be given domains and loads by
    /// the caller, and then used to create a LoadLedger object.
    pub fn new(nr_cpus: usize, dcycle_only: bool) -> LoadAggregator {
        LoadAggregator {
            doms: BTreeMap::new(),
            global_loads: BTreeMap::new(),
            nr_cpus,
            max_weight: 0,
            global_dcycle_sum: 0.0f64,
            global_load_sum: 0.0f64,
            effective_max_weight: 10000.0f64,
            dcycle_only,
        }
    }

    /// Given a LoadAggregator with recorded domain loads, compute the
    /// system-wide load, adjusting for infeasible weights when necessary.
    pub fn calculate(&mut self) -> LoadLedger {
        if !self.dcycle_only && approx_ge(self.max_weight as f64, self.infeasible_threshold()) {
            self.adjust_infeas_weights();
        }
        
        let mut dom_load_sums = Vec::new();
        let mut dom_dcycle_sums = Vec::new();

        for (_, dom) in self.doms.iter() {
            dom_load_sums.push(dom.load_sum);
            dom_dcycle_sums.push(dom.dcycle_sum);
        }

        LoadLedger {
            dom_load_sums,
            dom_dcycle_sums,
            global_dcycle_sum: self.global_dcycle_sum,
            global_load_sum: self.global_load_sum,
            effective_max_weight: self.effective_max_weight,
        }
    }

    /// Record an instance of some domain's load (by specifying its weight and
    /// dcycle). Returns an error if duty cycle is specified more than once
    /// for a given (Domain, weight) tuple.
    pub fn record_dom_load(&mut self, dom_id: usize, weight: usize, dcycle: f64) -> Result<()> {
        if weight < MIN_WEIGHT {
            bail!("weight {} is less than minimum weight {}", weight, MIN_WEIGHT);
        }

        let domain = self.doms.entry(dom_id).or_insert(Domain{
            loads: BTreeMap::new(),
            dcycle_sum: 0.0f64,
            load_sum: 0.0f64,
        });

        if let Some(_) = domain.loads.insert(weight, dcycle) {
            bail!("Domain {} already had load for weight {}", dom_id, weight);
        }

        let weight_dcycle = self.global_loads.entry(weight).or_insert(0.0f64);
        *weight_dcycle += dcycle;

        let load = weight as f64 * dcycle;

        domain.dcycle_sum += dcycle;
        domain.load_sum += load;

        self.global_dcycle_sum += dcycle;
        self.global_load_sum += load;

        if weight > self.max_weight {
            self.max_weight = weight;
        }

        Ok(())
    }

    fn infeasible_threshold(&self) -> f64 {
        // If the sum of duty cycle on the system is >= P, any weight w_x of a
        // task that exceeds L / P is guaranteed to be infeasible. Furthermore,
        // if any weight w_x == L / P then we know that task t_x can get its
        // full duty cycle, as:
        //
        // c_x = P * (w_x * d_x) / L
        //     = P * (L/P * d_x) / L
        //     = d_x / L / L
        //     = d_x
        //
        // If there is no scheduling entity whose weight exceeds L / P that has
        // a nonzero duty cycle, then all weights are feasible and we can use
        // the data we collected above without having to adjust for
        // infeasibility. Otherwise, we have at least one infeasible weight.
        //
        // See the comment in adjust_infeas_weights() for a more comprehensive
        // description of the algorithm for adjusting for infeasible weights.
        self.global_load_sum / self.nr_cpus as f64
    }

    fn apply_infeasible_threshold(&mut self, lambda_x: f64) {
        self.effective_max_weight = lambda_x;
        self.global_load_sum = 0.0f64;
        for (_, dom) in self.doms.iter_mut() {
            dom.load_sum = 0.0f64;
            for (weight, dcycle) in dom.loads.iter() {
                let adjusted = (*weight as f64).min(lambda_x);
                let load = adjusted * dcycle;

                dom.load_sum += load;
            }
            self.global_load_sum += dom.load_sum;
        }
    }

    fn adjust_infeas_weights(&mut self) {
        // At this point we have the following data points:
        //
        // P : The number of cores on the system
        // L : The total load sum of the system before any adjustments for
        //     infeasibility
        // Lf: The load sum of all feasible scheduling entities
        // D : The total sum of duty cycles across all domains in the system
        // Di: The duty cycle sum of all infeasible tasks
        //
        // We need to find a weight lambda_x such that every infeasible
        // scheduling entity in the system will be granted a CPU allocation
        // equal to their duty cycle, and all the remaining compute capacity in
        // the system will be divided fairly amongst the feasible tasks
        // according to their load. Our goal is to find a value lambda_x such
        // that every infeasible entity is allocated its duty cycle, and the
        // remaining compute capacity is shared fairly amongst the feasible
        // entities on the system.
        //
        // If L' is the load sum on the system after clamping all weights
        // w_x > lambda_x to lambda_x, then lambda_x can be defined as follows:
        //
        // lambda_x = L' / P
        //
        // => L'                  = lambda_x * Di + Lf
        // => lambda_x * P'       = lambda_x * Di + Lf
        // => lambda_x (P' - D_I) = Lf
        // => lambda_x            = Lf / (P' - Di)
        //
        // Thus, need to iterate over different values of x until we find a
        // lambda_x such that:
        //
        //      w_x >= lambda_x >= w_x+1
        //
        // Once we find a lambda_x, we need to:
        //
        // 1. Adjust the maximum weights of any w_x > lambda_x -> lambda_x
        // 2. Subtract (w_i - lambda_x) from the load sums that the infeasible
        //    entities were contributing to.
        // 3. Re-calculate the per-domain load, and the global load average.
        //
        // Note that we should always find a lambda_x at this point, as we
        // verified in the caller that there is at least one infeasible entity
        // in the system.
        //
        // All of this is described and proven in detail in the following pdf:
        //
        // https://drive.google.com/file/d/1fAoWUlmW-HTp6akuATVpMxpUpvWcGSAv
        let p = self.nr_cpus as f64;
        let mut curr_dcycle_sum = 0.0f64;
        let mut curr_load_sum = self.global_load_sum;
        let mut lambda_x = curr_load_sum / p;

        for (weight, dcycles) in self.global_loads.iter().rev() {
            if approx_ge(lambda_x, *weight as f64) {
                self.apply_infeasible_threshold(lambda_x);
                return;
            }

            curr_dcycle_sum += dcycles;
            curr_load_sum -= *weight as f64 * dcycles;
            lambda_x = curr_load_sum / (p - curr_dcycle_sum);
        }

        // We can fail to find an infeasible weight if the host is
        // under-utilized. In this case, just fall back to using weights. If
        // this is happening due to a stale system-wide util value due to the
        // tuner not having run recently enough, it is a condition that should
        // self-correct soon. If it is the result of the user configuring us to
        // use weights even when the system is under-utilized, they were warned
        // when the scheduler was launched.
    }
}
