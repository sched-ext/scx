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
    pub name: String,
    #[stat(desc = "an event counter")]
    pub events: u64,
    #[stat(desc = "a gauge number")]
    pub pressure: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "cluster statistics")]
struct ClusterStats {
    pub name: String,
    #[stat(desc = "update timestamp")]
    pub at: u64,
    #[stat(desc = "some bitmap we want to report")]
    pub bitmap: Vec<u32>,
    #[stat(desc = "domain statistics")]
    pub doms_dict: BTreeMap<usize, DomainStats>,
}

fn main() {
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
