// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Default)]
pub struct OpenMetricsStats {
    pub registry: Registry,
    pub total: Gauge<i64, AtomicI64>,
    pub local: Gauge<f64, AtomicU64>,
    pub open_idle: Gauge<f64, AtomicU64>,
    pub affn_viol: Gauge<f64, AtomicU64>,
    pub excl_idle: Gauge<f64, AtomicU64>,
    pub excl_wakeup: Gauge<f64, AtomicU64>,
    pub proc_ms: Gauge<i64, AtomicI64>,
    pub busy: Gauge<f64, AtomicU64>,
    pub util: Gauge<f64, AtomicU64>,
    pub load: Gauge<f64, AtomicU64>,
    pub l_util: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_util_frac: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_load: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_load_frac: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_tasks: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_total: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_sel_local: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_enq_wakeup: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_enq_expire: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_enq_last: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_enq_reenq: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_min_exec: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_min_exec_us: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_open_idle: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_preempt: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_preempt_first: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_preempt_idle: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_preempt_fail: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_affn_viol: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_keep: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_keep_fail_max_exec: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_keep_fail_busy: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_excl_collision: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_excl_preempt: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_kick: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_yield: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_yield_ignore: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_migration: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    pub l_cur_nr_cpus: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_min_nr_cpus: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub l_max_nr_cpus: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
}

impl OpenMetricsStats {
    pub fn new() -> OpenMetricsStats {
        let mut metrics = OpenMetricsStats {
            registry: <Registry>::default(),
            ..Default::default()
        };
        // Helper macro to reduce on some of the boilerplate:
        // $i: The identifier of the metric to register
        // $help: The Help text associated with the metric
        macro_rules! register {
            ($i:ident, $help:expr) => {
                metrics
                    .registry
                    .register(stringify!($i), $help, metrics.$i.clone())
            };
        }
        register!(total, "Total scheduling events in the period");
        register!(local, "% that got scheduled directly into an idle CPU");
        register!(
            open_idle,
            "% of open layer tasks scheduled into occupied idle CPUs"
        );
        register!(
            affn_viol,
            "% which violated configured policies due to CPU affinity restrictions"
        );
        register!(
            excl_idle,
            "Number of times a CPU skipped dispatching due to sibling running an exclusive task"
        );
        register!(
            excl_wakeup,
            "Number of times an idle sibling CPU was woken up after an exclusive task is finished"
        );
        register!(
            proc_ms,
            "CPU time this binary has consumed during the period"
        );
        register!(busy, "CPU busy % (100% means all CPUs were fully occupied)");
        register!(
            util,
            "CPU utilization % (100% means one CPU was fully occupied)"
        );
        register!(load, "Sum of weight * duty_cycle for all tasks");
        register!(
            l_util,
            "CPU utilization of the layer (100% means one CPU was fully occupied)"
        );
        register!(
            l_util_frac,
            "Fraction of total CPU utilization consumed by the layer"
        );
        register!(l_load, "Sum of weight * duty_cycle for tasks in the layer");
        register!(l_load_frac, "Fraction of total load consumed by the layer");
        register!(l_tasks, "Number of tasks in the layer");
        register!(l_total, "Number of scheduling events in the layer");
        register!(
            l_sel_local,
            "% of scheduling events directly into an idle CPU"
        );
        register!(
            l_enq_wakeup,
            "% of scheduling events enqueued to layer after wakeup"
        );
        register!(
            l_enq_expire,
            "% of scheduling events enqueued to layer after slice expiration"
        );
        register!(
            l_enq_last,
            "% of scheduling events enqueued as last runnable task on CPU"
        );
        register!(
            l_enq_reenq,
            "% of scheduling events re-enqueued due to RT preemption"
        );
        register!(
            l_min_exec,
            "Number of times execution duration was shorter than min_exec_us"
        );
        register!(
            l_min_exec_us,
            "Total execution duration extended due to min_exec_us"
        );
        register!(
            l_open_idle,
            "% of scheduling events into idle CPUs occupied by other layers"
        );
        register!(
            l_preempt,
            "% of scheduling events that preempted other tasks"
        );
        register!(
            l_preempt_first,
            "% of scheduling events that first-preempted other tasks"
        );
        register!(
            l_preempt_idle,
            "% of scheduling events that idle-preempted other tasks"
        );
        register!(
            l_preempt_fail,
            "% of scheduling events that attempted to preempt other tasks but failed"
        );
        register!(
            l_affn_viol,
            "% of scheduling events that violated configured policies due to CPU affinity restrictions"
        );
        register!(
            l_keep,
            "% of scheduling events that continued executing after slice expiration"
        );
        register!(
            l_keep_fail_max_exec,
            "% of scheduling events that weren't allowed to continue executing after slice expiration due to overrunning max_exec duration limit"
        );
        register!(
            l_keep_fail_busy,
            "% of scheduling events that weren't allowed to continue executing after slice expiration to accommodate other tasks"
        );
        register!(
            l_excl_collision,
            "Number of times an exclusive task skipped a CPU as the sibling was also exclusive"
        );
        register!(
            l_excl_preempt,
            "Number of times a sibling CPU was preempted for an exclusive task"
        );
        register!(
            l_kick,
            "% of schduling events that kicked a CPU from enqueue path"
        );
        register!(l_yield, "% of scheduling events that yielded");
        register!(l_yield_ignore, "Number of times yield was ignored");
	register!(l_migration, "% of scheduling events that migrated across CPUs");
        register!(l_cur_nr_cpus, "Current # of CPUs assigned to the layer");
        register!(l_min_nr_cpus, "Minimum # of CPUs assigned to the layer");
        register!(l_max_nr_cpus, "Maximum # of CPUs assigned to the layer");
        metrics
    }
}
