use anyhow::Result;
use anyhow::{anyhow, bail};
use log::{info, warn};
use nix::sys::resource::{getrlimit, setrlimit, Resource, RLIM_INFINITY};
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
                        info!("Connection to stats_server failed ({ioe})");
                        sleep(Duration::from_secs(1));
                        break;
                    }
                    None => {
                        warn!("error on handling stats_server result {e}");
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

pub fn try_set_rlimit_infinity() {
    // Increase MEMLOCK size since the BPF scheduler might use
    // more than the current limit
    if setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY).is_err() {
        // If there is an error in expanding rlimit to infinity,
        // show the current rlimits then proceed.
        if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_MEMLOCK) {
            warn!("Current MEMLOCK limit: soft={soft}, hard={hard}");
        } else {
            warn!("Cannot change or query MEMLOCK limit");
        }
    }
}

/// Read a file and parse its content into the specified type.
///
/// Trims null and whitespace before parsing.
///
/// # Errors
/// Returns an error if reading or parsing fails.
pub fn read_from_file<T>(path: &Path) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let val = match std::fs::read_to_string(path) {
        Ok(val) => val,
        Err(_) => {
            bail!("Failed to open or read file {:?}", path);
        }
    };
    let val = val.trim_end_matches('\0');

    match val.trim().parse::<T>() {
        Ok(parsed) => Ok(parsed),
        Err(_) => {
            bail!("Failed to parse content '{}' from {:?}", val.trim(), path);
        }
    }
}

pub fn read_file_usize_vec(path: &Path, separator: char) -> Result<Vec<usize>> {
    let val = std::fs::read_to_string(path)?;
    let val = val.trim_end_matches('\0');

    val.split(separator)
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .map_err(|_| anyhow!("Failed to parse '{}' as usize", s))
        })
        .collect::<Result<Vec<usize>>>()
}

pub fn read_file_byte(path: &Path) -> Result<usize> {
    let val = std::fs::read_to_string(path)?;
    let val = val.trim_end_matches('\0');
    let val = val.trim();

    // E.g., 10K, 10M, 10G, 10
    if let Some(sval) = val.strip_suffix("K") {
        let byte = sval.parse::<usize>()?;
        return Ok(byte * 1024);
    }
    if let Some(sval) = val.strip_suffix("M") {
        let byte = sval.parse::<usize>()?;
        return Ok(byte * 1024 * 1024);
    }
    if let Some(sval) = val.strip_suffix("G") {
        let byte = sval.parse::<usize>()?;
        return Ok(byte * 1024 * 1024 * 1024);
    }

    let byte = val.parse::<usize>()?;
    Ok(byte)
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
