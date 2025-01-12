use anyhow::bail;
use anyhow::Result;
use libc;
use log::{info, warn};
use scx_stats::prelude::*;
use serde::Deserialize;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

pub fn monitor_stats<T>(
    stats_args: &[(String, String)],
    intv: Duration,
    mut should_exit: impl FnMut() -> bool,
    mut output: impl FnMut(T) -> Result<()>,
) -> Result<()>
where
    T: for<'a> Deserialize<'a>,
{
    let mut retry_cnt: u32 = 0;

    const RETRYABLE_ERRORS: [std::io::ErrorKind; 2] = [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::ConnectionRefused,
    ];

    while !should_exit() {
        let mut client = match StatsClient::new().connect() {
            Ok(v) => v,
            Err(e) => match e.downcast_ref::<std::io::Error>() {
                Some(ioe) if RETRYABLE_ERRORS.contains(&ioe.kind()) => {
                    if retry_cnt == 1 {
                        info!("Stats server not available, retrying...");
                    }
                    retry_cnt += 1;
                    sleep(Duration::from_secs(1));
                    continue;
                }
                _ => Err(e)?,
            },
        };
        retry_cnt = 0;

        while !should_exit() {
            let stats = match client.request::<T>("stats", stats_args.to_owned()) {
                Ok(v) => v,
                Err(e) => match e.downcast_ref::<std::io::Error>() {
                    Some(ioe) => {
                        info!("Connection to stats_server failed ({})", &ioe);
                        sleep(Duration::from_secs(1));
                        break;
                    }
                    None => {
                        warn!("error on handling stats_server result {}", &e);
                        sleep(Duration::from_secs(1));
                        break;
                    }
                },
            };
            output(stats)?;
            sleep(intv);
        }
    }

    Ok(())
}

pub fn set_rlimit_infinity() {
    unsafe {
        // Call setrlimit to set the locked-in-memory limit to unlimited.
        let new_rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let res = libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlimit);
        if res != 0 {
            panic!("setrlimit failed with error code: {}", res);
        }
    };
}

pub fn read_file_usize(path: &Path) -> Result<usize> {
    let val = match std::fs::read_to_string(path) {
        Ok(val) => val,
        Err(_) => {
            bail!("Failed to open or read file {:?}", path);
        }
    };

    match val.trim().parse::<usize>() {
        Ok(parsed) => Ok(parsed),
        Err(_) => {
            bail!("Failed to parse {}", val);
        }
    }
}

/* Load is reported as weight * duty cycle
 *
 * In the Linux kernel, EEDVF uses default weight = 1 s.t.
 * load for a nice-0 thread runnable for time slice = 1
 *
 * To conform with cgroup weights convention, sched-ext uses
 * the convention of default weight = 100 with the formula
 * 100 * nice ^ 1.5. This means load for a nice-0 thread
 * runnable for time slice = 100.
 *
 * To ensure we report load metrics consistently with the Linux
 * kernel, we divide load by 100.0 prior to reporting metrics.
 * This is also more intuitive for users since 1 CPU roughly
 * means 1 unit of load.
 *
 * We only do this prior to reporting as its easier to work with
 * weight as integers in BPF / userspace than floating point.
 */
pub fn normalize_load_metric(metric: f64) -> f64 {
    metric / 100.0
}
