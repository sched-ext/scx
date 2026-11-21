pub use serde_json;

use std::path::PathBuf;

pub(crate) fn default_stats_base_path() -> PathBuf {
    std::env::var_os("SCX_STATS_BASE_PATH")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/scx"))
}

mod stats;
pub use stats::{
    Meta, StatsAttr, StatsData, StatsField, StatsFieldAttrs, StatsKind, StatsMeta, StatsMetaAux,
    StatsStructAttrs,
};

mod server;
pub use server::{
    StatsCloser, StatsErrno, StatsOpener, StatsOps, StatsReader, StatsReaderSend, StatsReaderSync,
    StatsRequest, StatsResponse, StatsServer, StatsServerData, ToJson,
};

mod client;
pub use client::StatsClient;

pub mod prelude {
    pub use crate::*;
}
