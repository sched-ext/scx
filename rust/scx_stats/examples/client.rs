use scx_stats::{ScxStatsClient, ScxStatsMeta};
use scx_stats_derive::Stats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env::args;

// DomainStat and ClusterStat definitions must match the ones in server.rs.
//
#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "domain statistics")]
struct DomainStats {
    pub name: String,
    #[stat(desc = "an event counter")]
    pub events: u64,
    #[stat(desc = "a gauge number")]
    pub pressure: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "cluster statistics", all)]
struct ClusterStats {
    pub name: String,
    #[stat(desc = "update timestamp")]
    pub at: u64,
    #[stat(desc = "some bitmap we want to report")]
    pub bitmap: Vec<u32>,
    #[stat(desc = "domain statistics", om_prefix = "d_")]
    pub doms_dict: BTreeMap<usize, DomainStats>,
}

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    std::assert_eq!(args().len(), 2, "Usage: client UNIX_SOCKET_PATH");
    let path = args().nth(1).unwrap();

    let mut client = ScxStatsClient::new().set_path(path).connect().unwrap();

    println!("===== Requesting \"stats_meta\":");
    let resp = client.request::<Vec<ScxStatsMeta>>("stats_meta", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stats\" without arguments:");
    let resp = client.request::<ClusterStats>("stats", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stats\" with \"target\"=\"non-existent\":");
    let resp =
        client.request::<ClusterStats>("stats", vec![("target".into(), "non-existent".into())]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stats\" with \"target\"=\"all\":");
    let resp = client.request::<ClusterStats>("stats", vec![("target".into(), "all".into())]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stats_meta\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stats_meta", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stats\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stats", vec![("target".into(), "all".into())]);
    println!("{:#?}", &resp);
}
