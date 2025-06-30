use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of running tasks")]
    pub nr_running: u64,
    #[stat(desc = "Number of online CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Number of kthread direct dispatches")]
    pub nr_kthread_dispatches: u64,
    #[stat(desc = "Number of task direct dispatches")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of regular task dispatches")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Number of GPU-using task dispatches")]
    pub nr_gpu_task_dispatches: u64,
    #[stat(desc = "Number of inference workload dispatches")]
    pub nr_inference_dispatches: u64,
    #[stat(desc = "Number of training workload dispatches")]
    pub nr_training_dispatches: u64,
    #[stat(desc = "Number of validation workload dispatches")]
    pub nr_validation_dispatches: u64,
    #[stat(desc = "Number of preprocessing workload dispatches")]
    pub nr_preprocessing_dispatches: u64,
    #[stat(desc = "Number of data loading workload dispatches")]
    pub nr_data_loading_dispatches: u64,
    #[stat(desc = "Number of model loading workload dispatches")]
    pub nr_model_loading_dispatches: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2}/{:<2} | dispatch -> k: {:<5} d: {:<5} s: {:<5} g: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_cpus,
            self.nr_kthread_dispatches,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_gpu_task_dispatches
        )?;
        writeln!(
            w,
            "workloads -> inf: {:<5} train: {:<5} val: {:<5} prep: {:<5} data: {:<5} model: {:<5}",
            self.nr_inference_dispatches,
            self.nr_training_dispatches,
            self.nr_validation_dispatches,
            self.nr_preprocessing_dispatches,
            self.nr_data_loading_dispatches,
            self.nr_model_loading_dispatches
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_kthread_dispatches: self.nr_kthread_dispatches - rhs.nr_kthread_dispatches,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
            nr_gpu_task_dispatches: self.nr_gpu_task_dispatches - rhs.nr_gpu_task_dispatches,
            nr_inference_dispatches: self.nr_inference_dispatches - rhs.nr_inference_dispatches,
            nr_training_dispatches: self.nr_training_dispatches - rhs.nr_training_dispatches,
            nr_validation_dispatches: self.nr_validation_dispatches - rhs.nr_validation_dispatches,
            nr_preprocessing_dispatches: self.nr_preprocessing_dispatches - rhs.nr_preprocessing_dispatches,
            nr_data_loading_dispatches: self.nr_data_loading_dispatches - rhs.nr_data_loading_dispatches,
            nr_model_loading_dispatches: self.nr_model_loading_dispatches - rhs.nr_model_loading_dispatches,
            ..self.clone()
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
