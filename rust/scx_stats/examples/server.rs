use scx_stats::{ScxStatsServer, Meta, ToJson};
use scx_stats_derive::Stats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env::args;
use std::io::Read;

// DomainStat and ClusterStat definitions must match the ones in client.rs.
//
#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "domain statistics")]
struct DomainStats {
    dom_name: String,
    #[stat(desc = "domain last updated at")]
    pub dom_at: u64,
    #[stat(desc = "it's an i64 counter")]
    dom_i_cnt: i64,
    dom_u_cnt: u64,
    dom_f_cnt: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "cluster statistics")]
struct ClusterStats {
    cls_name: String,
    #[stat(desc = "last updated at")]
    cls_at: u64,
    #[stat(desc = "domain statistics")]
    doms_dict: BTreeMap<usize, DomainStats>,
    doms_array: Vec<DomainStats>,
}

fn main() {
    let stats = ClusterStats {
        cls_name: "test cluster".into(),
        cls_at: 12345,
        doms_dict: BTreeMap::from([
            (
                0,
                DomainStats {
                    dom_name: "domain 0".into(),
                    dom_at: 1234,
                    dom_i_cnt: -1234,
                    dom_u_cnt: 1234,
                    dom_f_cnt: 1.234,
                },
            ),
            (
                3,
                DomainStats {
                    dom_name: "domain 3".into(),
                    dom_at: 5678,
                    dom_i_cnt: -5678,
                    dom_u_cnt: 5678,
                    dom_f_cnt: 5.678,
                },
            ),
        ]),
        doms_array: vec![
            DomainStats {
                dom_name: "domain 5".into(),
                dom_at: 5555,
                dom_i_cnt: -5555,
                dom_u_cnt: 5555,
                dom_f_cnt: 5.555,
            },
            DomainStats {
                dom_name: "domain 7".into(),
                dom_at: 7777,
                dom_i_cnt: -7777,
                dom_u_cnt: 7777,
                dom_f_cnt: 7.777,
            },
        ],
    };

    std::assert_eq!(args().len(), 2, "Usage: server UNIX_SOCKET_PATH");
    let path = args().nth(1).unwrap();

    ScxStatsServer::new()
        .set_path(&path)
        .add_stats_meta(ClusterStats::meta())
        .add_stats_meta(DomainStats::meta())
        .add_stats("all", Box::new(move |_| stats.to_json()))
        .launch()
        .unwrap();

    println!(
        "Server listening. Run `client {:?}`.\n\
         Use `socat - UNIX-CONNECT:{:?}` for raw connection.\n\
         Press any key to exit.",
        &path, &path,
    );

    let mut buf: [u8; 1] = [0];
    let _ = std::io::stdin().read(&mut buf);
}
