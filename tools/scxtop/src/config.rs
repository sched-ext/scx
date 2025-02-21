// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::cli::Cli;
use crate::STATS_SOCKET_PATH;
use crate::TRACE_FILE_PREFIX;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use xdg;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// App tick rate in milliseconds.
    pub tick_rate_ms: usize,
    /// Extra verbose output.
    pub debug: bool,
    /// Exclude bpf event tracking.
    pub exclude_bpf: bool,
    /// Stats unix socket path.
    pub stats_socket_path: String,
    /// Trace file prefix for perfetto traces.
    pub trace_file_prefix: String,
    /// Number of ticks for traces.
    pub trace_ticks: usize,
    /// Number of worker threads
    pub worker_threads: u16,
    /// Number of ticks to warmup before collecting traces.
    pub trace_tick_warmup: usize,
}

pub fn get_config_path() -> Result<PathBuf> {
    let xdg_dirs = xdg::BaseDirectories::with_prefix("scxtop")?;
    let config_path = xdg_dirs.get_config_file("scxtop.toml");
    Ok(config_path)
}

impl Config {
    /// Returns the default config.
    pub fn default_config() -> Config {
        Config {
            tick_rate_ms: 250,
            debug: false,
            exclude_bpf: false,
            stats_socket_path: STATS_SOCKET_PATH.to_string(),
            trace_file_prefix: TRACE_FILE_PREFIX.to_string(),
            trace_ticks: 5,
            worker_threads: 4,
            trace_tick_warmup: 3,
        }
    }

    /// Loads the config from XDG configuration.
    pub fn load() -> Result<Config> {
        let config_path = get_config_path()?;
        let contents = fs::read_to_string(config_path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn merge_cli(config: &Config, cli: &Cli) -> Config {
        Config {
            tick_rate_ms: cli.tick_rate_ms.unwrap_or(config.tick_rate_ms),
            debug: cli.debug.unwrap_or(config.debug),
            exclude_bpf: cli.exclude_bpf.unwrap_or(config.exclude_bpf),
            stats_socket_path: match &cli.stats_socket_path {
                Some(s) => {
                    if !s.is_empty() {
                        s.to_string()
                    } else {
                        config.stats_socket_path.clone()
                    }
                }
                None => config.stats_socket_path.clone(),
            },
            trace_file_prefix: match &cli.trace_file_prefix {
                Some(s) => {
                    if !s.is_empty() {
                        s.to_string()
                    } else {
                        config.trace_file_prefix.clone()
                    }
                }
                None => config.trace_file_prefix.clone(),
            },
            trace_ticks: cli.trace_ticks.unwrap_or(config.trace_ticks),
            worker_threads: cli.worker_threads.unwrap_or(config.worker_threads),
            trace_tick_warmup: cli.trace_tick_warmup.unwrap_or(config.trace_tick_warmup),
        }
    }
}
