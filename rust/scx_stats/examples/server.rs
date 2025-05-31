use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env::args;
use std::io::Read;
use std::thread::{current, spawn, ThreadId};

// Hacky definition sharing. See stats_def.rs.h.
include!("stats_defs.rs.h");

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    let stats = ClusterStats {
        name: "test cluster".into(),
        at: 12345,
        bitmap: vec![0xdeadbeef, 0xbeefdead],
        doms_dict: BTreeMap::from([
            (
                0,
                DomainStats {
                    name: "domain 0".into(),
                    events: 1234,
                    pressure: 1.234,
                },
            ),
            (
                3,
                DomainStats {
                    name: "domain 3".into(),
                    events: 5678,
                    pressure: 5.678,
                },
            ),
        ]),
    };

    std::assert_eq!(args().len(), 2, "Usage: server UNIX_SOCKET_PATH");
    let path = args().nth(1).unwrap();

    // If communication from the stats generating closure is not necessary,
    // StatsServer::<(), ()> can be used. This example sends thread ID and
    // receives the formatted string just for demonstration.
    let sdata = StatsServerData::<ThreadId, String>::new()
        .add_meta(ClusterStats::meta())
        .add_meta(DomainStats::meta())
        .add_stats(
            "top",
            Box::new(move |_args, (tx, rx)| {
                let id = current().id();
                let res = tx.send(id);
                debug!("Sendt {:?} {:?}", id, res);
                let res = rx.recv();
                debug!("Recevied {:?}", res);
                stats.to_json()
            }),
        );

    info!("stats_meta:");
    sdata.describe_meta(&mut std::io::stderr(), None).unwrap();

    let server = StatsServer::<ThreadId, String>::new(sdata)
        .set_path(&path)
        .launch()
        .unwrap();

    debug!("Doing unnecessary server channel handling");
    let (tx, rx) = server.channels();
    spawn(move || {
        while let Ok(id) = rx.recv() {
            if let Err(e) = tx.send(format!("hello {:?}", &id)) {
                warn!("Server channel errored ({:?})", e);
                break;
            }
        }
    });

    info!("Server listening. Run `client {:?}`.", &path);
    info!("Use `socat - UNIX-CONNECT:{:?}` for raw connection.", &path);
    info!("Press any key to exit.");

    let mut buf: [u8; 1] = [0];
    let _ = std::io::stdin().read(&mut buf);
}
