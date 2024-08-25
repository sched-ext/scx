pub use serde_json;

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
