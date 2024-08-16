// To be included from server.rs and client.rs examples. This would usually
// be done through the usual pub struct definitions but it's cumbersome to
// do in the examples directory, so work around with c-like includes.

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "domain statistics", _om_prefix="d_", _om_label="domain_name")]
struct DomainStats {
    pub name: String,
    #[stat(desc = "an event counter")]
    pub events: u64,
    #[stat(desc = "a gauge number")]
    pub pressure: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
#[stat(desc = "cluster statistics", top)]
struct ClusterStats {
    pub name: String,
    #[stat(desc = "update timestamp")]
    pub at: u64,
    #[stat(desc = "some bitmap we want to report", _om_skip)]
    pub bitmap: Vec<u32>,
    #[stat(desc = "domain statistics")]
    pub doms_dict: BTreeMap<usize, DomainStats>,
}
