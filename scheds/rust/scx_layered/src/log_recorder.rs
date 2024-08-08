// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright (c) Netflix, Inc.
// Author: Jose Fernandez

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use bitvec::vec::BitVec;
use log::info;
use log::warn;
use metrics::Counter;
use metrics::Gauge;
use metrics::Histogram;
use metrics::Key;
use metrics::KeyName;
use metrics::Label;
use metrics::Metadata;
use metrics::Recorder;
use metrics::SharedString;
use metrics::Unit;
use metrics_util::registry::AtomicStorage;
use metrics_util::registry::Registry;

use crate::Layer;
use crate::LayerKind;
use crate::LayerSpec;

pub struct ArcLogRecorder(Arc<LogRecorder>);

impl ArcLogRecorder {
    pub fn new(recorder: Arc<LogRecorder>) -> Self {
        Self(recorder)
    }
}

impl Recorder for ArcLogRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.0.describe_counter(key, unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.0.describe_gauge(key, unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.0.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
        self.0.register_counter(key, metadata)
    }

    fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
        self.0.register_gauge(key, metadata)
    }

    fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
        self.0.register_histogram(key, metadata)
    }
}

pub struct LogRecorder {
    registry: Arc<Registry<Key, AtomicStorage>>,
}

impl Recorder for LogRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        self.registry
            .get_or_create_counter(key, |c| c.clone().into())
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.registry.get_or_create_gauge(key, |g| g.clone().into())
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        self.registry
            .get_or_create_histogram(key, |h: &Arc<metrics_util::AtomicBucket<f64>>| {
                h.clone().into()
            })
    }
}

fn fmt_pct(v: f64) -> String {
    if v >= 99.995 {
        format!("{:5.1}", v)
    } else {
        format!("{:5.2}", v)
    }
}

fn fmt_num(v: f64) -> String {
    if v > 1_000_000.0 {
        format!("{:5.1}m", v / 1_000_000.0)
    } else if v > 1_000.0 {
        format!("{:5.1}k", v / 1_000.0)
    } else {
        format!("{:5.0} ", v)
    }
}

fn fmt_float(value: f64, max_decimals: usize) -> String {
    format!("{:.1$}", value, max_decimals)
}

fn format_bitvec(bitvec: &BitVec) -> String {
    let mut vals = Vec::<u32>::new();
    let mut val: u32 = 0;
    for (idx, bit) in bitvec.iter().enumerate() {
        if idx > 0 && idx % 32 == 0 {
            vals.push(val);
            val = 0;
        }
        if *bit {
            val |= 1 << (idx % 32);
        }
    }
    vals.push(val);
    let mut output = vals
        .iter()
        .fold(String::new(), |string, v| format!("{}{:08x} ", string, v));
    output.pop();
    output
}

impl LogRecorder {
    pub fn new() -> Self {
        LogRecorder {
            registry: Arc::new(Registry::<Key, AtomicStorage>::atomic()),
        }
    }

    pub fn report(&self, layer_specs: &Vec<LayerSpec>, layers: &Vec<Layer>) {
        let gauge_value = |name: &str| -> f64 {
            let key = Key::from_name(name.to_string());
            let gauge = self.registry.get_gauge(&key);
            match gauge {
                Some(gauge) => f64::from_bits(gauge.load(Relaxed)),
                None => {
                    warn!("Metric not found: {}", key);
                    0.0
                }
            }
        };

        let header_width = layer_specs
            .iter()
            .map(|spec| spec.name.len())
            .max()
            .unwrap()
            .max(4);

        info!(
            "tot={:7} local={} open_idle={} affn_viol={} proc={:?}ms",
            gauge_value("total"),
            fmt_pct(gauge_value("local")),
            fmt_pct(gauge_value("open_idle")),
            fmt_pct(gauge_value("affn_viol")),
            gauge_value("proc_ms"),
        );

        info!(
            "busy={:5.1} util={:7.1} load={:9.1} fallback_cpu={:3}",
            gauge_value("busy"),
            gauge_value("util"),
            gauge_value("load"),
            gauge_value("fallback_cpu"),
        );

        info!(
            "excl_coll={} excl_preempt={} excl_idle={} excl_wakeup={}",
            fmt_pct(gauge_value("excl_coll")),
            fmt_pct(gauge_value("excl_preempt")),
            fmt_pct(gauge_value("excl_idle")),
            fmt_pct(gauge_value("excl_wakeup")),
        );

        for (_, (spec, layer)) in layer_specs.iter().zip(layers.iter()).enumerate() {
            let layer_gauge_value = |name: &str| -> f64 {
                let labels = vec![Label::new("layer", spec.name.to_string())];
                let key = Key::from_parts(name.to_string(), labels);
                let gauge = self.registry.get_gauge(&key);
                match gauge {
                    Some(gauge) => f64::from_bits(gauge.load(Relaxed)),
                    None => {
                        warn!("Metric not found: {}", key);
                        0.0
                    }
                }
            };

            info!(
                "  {:<width$}: util/frac={:7.1}/{:5.1} load/frac={:9.1}:{:5.1} tasks={:6}",
                spec.name,
                layer_gauge_value("l_util"),
                layer_gauge_value("l_util_frac"),
                layer_gauge_value("l_load"),
                layer_gauge_value("l_load_frac"),
                layer_gauge_value("l_tasks"),
                width = header_width,
            );

            info!(
                "  {:<width$}  tot={:7} local={} wake/exp/last/reenq={}/{}/{}/{}",
                "",
                layer_gauge_value("l_total"),
                fmt_pct(layer_gauge_value("l_sel_local")),
                fmt_pct(layer_gauge_value("l_enq_wakeup")),
                fmt_pct(layer_gauge_value("l_enq_expire")),
                fmt_pct(layer_gauge_value("l_enq_last")),
                fmt_pct(layer_gauge_value("l_enq_reenq")),
                width = header_width,
            );

            info!(
                "  {:<width$}  keep/max/busy={}/{}/{} kick={} yield/ign={}/{}",
                "",
                fmt_pct(layer_gauge_value("l_keep")),
                fmt_pct(layer_gauge_value("l_keep_fail_max_exec")),
                fmt_pct(layer_gauge_value("l_keep_fail_busy")),
                layer_gauge_value("l_kick"),
                layer_gauge_value("l_yield"),
                fmt_num(layer_gauge_value("l_yield_ignore")),
                width = header_width,
            );

            info!(
                "  {:<width$}  open_idle={} mig={} affn_viol={}",
                "",
                fmt_pct(layer_gauge_value("l_open_idle")),
                fmt_pct(layer_gauge_value("l_migration")),
                fmt_pct(layer_gauge_value("l_affn_viol")),
                width = header_width,
            );

            info!(
                "  {:<width$}  preempt/first/idle/fail={}/{}/{}/{} min_exec={}/{:7.2}ms",
                "",
                fmt_pct(layer_gauge_value("l_preempt")),
                fmt_pct(layer_gauge_value("l_preempt_first")),
                fmt_pct(layer_gauge_value("l_preempt_idle")),
                fmt_pct(layer_gauge_value("l_preempt_fail")),
                fmt_float(layer_gauge_value("l_min_exec"), 2),
                layer_gauge_value("l_min_exec_us") / 1000.0,
                width = header_width,
            );

            // TODO: Include the formatted layer.cpus bitvec
            info!(
                "  {:<width$}  cpus={:3} [{:3},{:3}] {}",
                "",
                layer_gauge_value("l_cur_nr_cpus"),
                layer_gauge_value("l_min_nr_cpus"),
                layer_gauge_value("l_max_nr_cpus"),
                format_bitvec(&layer.cpus),
                width = header_width
            );

            match &layer.kind {
                LayerKind::Confined { exclusive, .. }
                | LayerKind::Grouped { exclusive, .. }
                | LayerKind::Open { exclusive, .. } => {
                    if *exclusive {
                        info!(
                            "  {:<width$}  excl_coll={} excl_preempt={}",
                            "",
                            fmt_pct(layer_gauge_value("l_excl_collision")),
                            fmt_pct(layer_gauge_value("l_excl_preempt")),
                            width = header_width,
                        );
                    } else if layer_gauge_value("l_excl_collision") != 0.0
                        || layer_gauge_value("l_excl_preempt") != 0.0
                    {
                        warn!(
                            "{}: exclusive is off but excl_coll={} excl_preempt={}",
                            spec.name,
                            fmt_pct(layer_gauge_value("l_excl_collision")),
                            fmt_pct(layer_gauge_value("l_excl_preempt")),
                        );
                    }
                }
            }
        }
    }
}
