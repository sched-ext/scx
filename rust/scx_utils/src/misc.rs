use anyhow::bail;
use anyhow::Result;
use libc;
use log::info;
use scx_stats::prelude::*;
use serde::Deserialize;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

pub fn monitor_stats<T>(
    stats_args: &Vec<(String, String)>,
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
                        info!("Stats server not avaliable, retrying...");
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
            let stats = match client.request::<T>("stats", stats_args.clone()) {
                Ok(v) => v,
                Err(e) => match e.downcast_ref::<std::io::Error>() {
                    Some(ioe) => {
                        info!("Connection to stats_server failed ({})", &ioe);
                        sleep(Duration::from_secs(1));
                        break;
                    }
                    None => Err(e)?,
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
    let val = match std::fs::read_to_string(&path) {
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
