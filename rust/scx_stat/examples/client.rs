use scx_stat::{ScxStatClient, ScxStatMeta};
use scx_stat_derive::Stat;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env::args;

// DomainStat and ClusterStat definitions must match the ones in server.rs.
//
#[derive(Clone, Debug, Serialize, Deserialize, Stat)]
#[stat(desc = "domain statistics")]
struct DomainStat {
    dom_name: String,
    #[stat(desc = "domain last updated at")]
    pub dom_at: u64,
    #[stat(desc = "it's an i64 counter")]
    dom_i_cnt: i64,
    dom_u_cnt: u64,
    dom_f_cnt: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stat)]
#[stat(desc = "cluster statistics")]
struct ClusterStat {
    cls_name: String,
    #[stat(desc = "last updated at")]
    cls_at: u64,
    #[stat(desc = "domain statistics")]
    doms_dict: BTreeMap<usize, DomainStat>,
    doms_array: Vec<DomainStat>,
}

fn main() {
    std::assert_eq!(args().len(), 2, "Usage: client UNIX_SOCKET_PATH");
    let path = args().nth(1).unwrap();

    let mut client = ScxStatClient::new().set_path(path).connect().unwrap();

    println!("===== Requesting \"stat_meta\":");
    let resp = client.request::<Vec<ScxStatMeta>>("stat_meta", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stat\" without arguments:");
    let resp = client.request::<ClusterStat>("stat", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stat\" with \"target\"=\"non-existent\":");
    let resp =
        client.request::<ClusterStat>("stat", vec![("target".into(), "non-existent".into())]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stat\" with \"target\"=\"all\":");
    let resp = client.request::<ClusterStat>("stat", vec![("target".into(), "all".into())]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stat_meta\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stat_meta", vec![]);
    println!("{:#?}", &resp);

    println!("\n===== Requesting \"stat\" but receiving with serde_json::Value:");
    let resp = client.request::<serde_json::Value>("stat", vec![("target".into(), "all".into())]);
    println!("{:#?}", &resp);
}
