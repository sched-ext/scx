use std::collections::BTreeMap;

fn signed(x: f64) -> String {
    if x >= 0.0f64 {
        format!("{:+7.2}", x)
    } else {
        format!("{:7.2}", x)
    }
}

pub struct DomainStats {
    pub load: f64,
    pub imbal: f64,
    pub delta: f64,
}

impl DomainStats {
    pub fn format(&self, id: usize) -> String {
        format!(
            "   DOM[{:02}] load={:6.2} imbal={} delta={}",
            id,
            self.load,
            signed(self.imbal),
            signed(self.delta)
        )
    }
}

pub struct NodeStats {
    pub load: f64,
    pub imbal: f64,
    pub delta: f64,
    pub domains: BTreeMap<usize, DomainStats>,
}

impl NodeStats {
    pub fn format(&self, id: usize) -> String {
        format!(
            "  NODE[{:02}] load={:6.2} imbal={} delta={}",
            id,
            self.load,
            signed(self.imbal),
            signed(self.delta)
        )
    }
}
