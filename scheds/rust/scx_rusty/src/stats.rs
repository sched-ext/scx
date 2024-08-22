use crate::load_balance::LoadEntity;
use std::fmt;

fn fmt_balance_stat(
    f: &mut fmt::Formatter<'_>,
    load: &LoadEntity,
    preamble: String,
) -> fmt::Result {
    let imbal = load.imbal();
    let load_sum = load.load_sum();
    let load_delta = load.delta();
    let get_fmt = |num: f64| {
        if num >= 0.0f64 {
            format!("{:+4.2}", num)
        } else {
            format!("{:4.2}", num)
        }
    };

    write!(
        f,
        "{} load={:4.2} imbal={} load_delta={}",
        preamble,
        load_sum,
        get_fmt(imbal),
        get_fmt(load_delta)
    )
}

pub struct DomainStats {
    pub id: usize,
    pub load: LoadEntity,
}

impl fmt::Display for DomainStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_balance_stat(f, &self.load, format!("  DOMAIN[{:02}]", self.id))
    }
}

pub struct NodeStats {
    pub id: usize,
    pub load: LoadEntity,
    pub domains: Vec<DomainStats>,
}

impl fmt::Display for NodeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_balance_stat(f, &self.load, format!("NODE[{:02}]", self.id))
    }
}
