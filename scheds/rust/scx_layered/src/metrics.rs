use metrics::{describe_gauge, gauge, Gauge};

pub struct Metrics {
    // Metrics for the entire system
    pub total: Gauge,
    pub local: Gauge,
    pub open_idle: Gauge,
    pub affn_viol: Gauge,
    pub excl_coll: Gauge,
    pub excl_preempt: Gauge,
    pub excl_idle: Gauge,
    pub excl_wakeup: Gauge,
    pub proc_ms: Gauge,
    pub busy: Gauge,
    pub util: Gauge,
    pub load: Gauge,
    pub fallback_cpu: Gauge,

    // Metric names for gauges that will be created dynamically for each layer
    pub l_util: String,
    pub l_util_frac: String,
    pub l_load: String,
    pub l_load_frac: String,
    pub l_tasks: String,
    pub l_total: String,
    pub l_sel_local: String,
    pub l_enq_wakeup: String,
    pub l_enq_expire: String,
    pub l_enq_last: String,
    pub l_enq_reenq: String,
    pub l_min_exec: String,
    pub l_min_exec_us: String,
    pub l_open_idle: String,
    pub l_preempt: String,
    pub l_preempt_first: String,
    pub l_preempt_idle: String,
    pub l_preempt_fail: String,
    pub l_affn_viol: String,
    pub l_keep: String,
    pub l_keep_fail_max_exec: String,
    pub l_keep_fail_busy: String,
    pub l_excl_collision: String,
    pub l_excl_preempt: String,
    pub l_kick: String,
    pub l_yield: String,
    pub l_yield_ignore: String,
    pub l_migration: String,
    pub l_cur_nr_cpus: String,
    pub l_min_nr_cpus: String,
    pub l_max_nr_cpus: String,
}

macro_rules! register_gauge {
    ($gauge_name:expr, $description:expr) => {{
        let gauge = gauge!($gauge_name);
        describe_gauge!($gauge_name, $description);
        gauge
    }};
}

macro_rules! register_gauge_name {
    ($gauge_name:expr, $description:expr) => {{
        describe_gauge!($gauge_name, $description);
        $gauge_name.to_string()
    }};
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            total: register_gauge!("total", "Total scheduling events in the period"),
            local: register_gauge!("local", "% that got scheduled directly into an idle CPU"),
            open_idle: register_gauge!(
                "open_idle",
                "% of open layer tasks scheduled into occupied idle CPUs"
            ),
            affn_viol: register_gauge!(
                "affn_viol",
                "% which violated configured policies due to CPU affinity restrictions"
            ),
            excl_coll: register_gauge!(
                "excl_coll",
                "Number of times an exclusive task skipped a CPU as the sibling was also exclusive"
            ),
            excl_preempt: register_gauge!(
                "excl_preempt",
                "Number of times a sibling CPU was preempted for an exclusive task"
            ),
            excl_idle: register_gauge!(
                "excl_idle",
                "Number of times a CPU skipped dispatching due to sibling running an exclusive task"
            ),
            excl_wakeup: register_gauge!(
                "excl_wakeup",
                "Number of times an idle sibling CPU was woken up after an exclusive task is finished"
            ),
            proc_ms: register_gauge!(
                "proc_ms",
                "CPU time this binary has consumed during the period"
            ),
            busy: register_gauge!("busy", "CPU busy % (100% means all CPUs were fully occupied)"),
            util: register_gauge!(
                "util",
                "CPU utilization % (100% means one CPU was fully occupied)"
            ),
            load: register_gauge!("load", "Sum of weight * duty_cycle for all tasks"),
            fallback_cpu: register_gauge!(
                "fallback_cpu",
                "The next free or the first CPU if none is free"
            ),
            l_util: register_gauge_name!(
                "l_util",
                "CPU utilization of the layer (100% means one CPU was fully occupied)"
            ),
            l_util_frac: register_gauge_name!(
                "l_util_frac",
                "Fraction of total CPU utilization consumed by the layer"
            ),
            l_load: register_gauge_name!("l_load", "Sum of weight * duty_cycle for tasks in the layer"),
            l_load_frac: register_gauge_name!(
                "l_load_frac",
                "Fraction of total load consumed by the layer"
            ),
            l_tasks: register_gauge_name!("l_tasks", "Number of tasks in the layer"),
            l_total: register_gauge_name!("l_total", "Number of scheduling events in the layer"),
            l_sel_local: register_gauge_name!(
                "l_sel_local",
                "% of scheduling events directly into an idle CPU"
            ),
            l_enq_wakeup: register_gauge_name!(
                "l_enq_wakeup",
                "% of scheduling events enqueued to layer after wakeup"
            ),
            l_enq_expire: register_gauge_name!(
                "l_enq_expire",
                "% of scheduling events enqueued to layer after slice expiration"
            ),
            l_enq_last: register_gauge_name!(
                "l_enq_last",
                "% of scheduling events enqueued as last runnable task on CPU"
            ),
            l_enq_reenq: register_gauge_name!(
                "l_enq_reenq",
                "% of scheduling events re-enqueued due to RT preemption"
            ),
            l_min_exec: register_gauge_name!(
                "l_min_exec",
                "Number of times execution duration was shorter than min_exec_us"
            ),
            l_min_exec_us: register_gauge_name!(
                "l_min_exec_us",
                "Total execution duration extended due to min_exec_us"
            ),
            l_open_idle: register_gauge_name!(
                "l_open_idle",
                "% of scheduling events into idle CPUs occupied by other layers"
            ),
            l_preempt: register_gauge_name!(
                "l_preempt",
                "% of scheduling events that preempted other tasks"
            ),
            l_preempt_first: register_gauge_name!(
                "l_preempt_first",
                "% of scheduling events that first-preempted other tasks"
            ),
            l_preempt_idle: register_gauge_name!(
                "l_preempt_idle",
                "% of scheduling events that idle-preempted other tasks"
            ),
            l_preempt_fail: register_gauge_name!(
                "l_preempt_fail",
                "% of scheduling events that attempted to preempt other tasks but failed"
            ),
            l_affn_viol: register_gauge_name!(
                "l_affn_viol",
                "% of scheduling events that violated configured policies due to CPU affinity restrictions"
            ),
            l_keep: register_gauge_name!(
                "l_keep",
                "% of scheduling events that continued executing after slice expiration"
            ),
            l_keep_fail_max_exec: register_gauge_name!(
                "l_keep_fail_max_exec",
                "% of scheduling events that weren't allowed to continue executing after slice expiration due to overrunning max_exec duration limit"
            ),
            l_keep_fail_busy: register_gauge_name!(
                "l_keep_fail_busy",
                "% of scheduling events that weren't allowed to continue executing after slice expiration to accommodate other tasks"
            ),
            l_excl_collision: register_gauge_name!(
                "l_excl_collision",
                "Number of times an exclusive task skipped a CPU as the sibling was also exclusive"
            ),
            l_excl_preempt: register_gauge_name!(
                "l_excl_preempt",
                "Number of times a sibling CPU was preempted for an exclusive task"
            ),
            l_kick: register_gauge_name!(
                "l_kick",
                "% of scheduling events that kicked a CPU from enqueue path"
            ),
            l_yield: register_gauge_name!("l_yield", "% of scheduling events that yielded"),
            l_yield_ignore: register_gauge_name!("l_yield_ignore", "Number of times yield was ignored"),
            l_migration: register_gauge_name!(
                "l_migration",
                "% of scheduling events that migrated across CPUs"
            ),
            l_cur_nr_cpus: register_gauge_name!("l_cur_nr_cpus", "Current # of CPUs assigned to the layer"),
            l_min_nr_cpus: register_gauge_name!("l_min_nr_cpus", "Minimum # of CPUs assigned to the layer"),
            l_max_nr_cpus: register_gauge_name!("l_max_nr_cpus", "Maximum # of CPUs assigned to the layer"),
        }
    }
}
