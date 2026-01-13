use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env::args;

// Hacky definition sharing. See stats_def.rs.h.
include!("stats_defs.rs.h");

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    std::assert_eq!(args().len(), 2, "Usage: client UNIX_SOCKET_PATH");
    let path = args().nth(1).unwrap();

    let mut client = StatsClient::new().set_path(path).connect(None).unwrap();

    println!("===== Requesting \"stats_meta\":");
    let resp = client.request::<BTreeMap<String, StatsMeta>>("stats_meta", vec![]);
    println!("{:#?}", resp);

    println!("\n===== Requesting \"stats\" without arguments:");
    let resp = client.request::<ClusterStats>("stats", vec![]);
    println!("{:#?}", resp);

    println!("\n===== Requesting \"stats\" with \"target\"=\"non-existent\":");
    let resp =
        client.request::<ClusterStats>("stats", vec![("target".into(), "non-existent".into())]);
    println!("{:#?}", resp);

    println!("\n===== Requesting \"stats\" with \"target\"=\"all\":");
    let resp = client.request::<ClusterStats>("stats", vec![("target".into(), "top".into())]);
    println!("{:#?}", resp);

    println!("\n===== Requesting \"stats\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stats", vec![("target".into(), "top".into())]);
    println!("{:#?}", resp);

    println!("\n===== Requesting \"stats_meta\" but receiving with serde_json::Value:");
    let resp = client
        .request::<serde_json::Value>("stats_meta", vec![])
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
}
