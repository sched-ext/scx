use anyhow::Result;
use log::info;
use scx_stats::ScxStatsClient;
use serde::Deserialize;
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
    while !should_exit() {
        let mut client = match ScxStatsClient::new().connect() {
            Ok(v) => v,
            Err(e) => match e.downcast_ref::<std::io::Error>() {
                Some(ioe) if ioe.kind() == std::io::ErrorKind::ConnectionRefused => {
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
