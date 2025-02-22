// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::cli::Cli;
use crate::AppTheme;
use crate::STATS_SOCKET_PATH;
use crate::TRACE_FILE_PREFIX;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use xdg;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// TUI theme.
    theme: Option<AppTheme>,
    /// App tick rate in milliseconds.
    tick_rate_ms: Option<usize>,
    /// Extra verbose output.
    debug: Option<bool>,
    /// Exclude bpf event tracking.
    exclude_bpf: Option<bool>,
    /// Stats unix socket path.
    stats_socket_path: Option<String>,
    /// Trace file prefix for perfetto traces.
    trace_file_prefix: Option<String>,
    /// Number of ticks for traces.
    trace_ticks: Option<usize>,
    /// Number of worker threads
    worker_threads: Option<u16>,
    /// Number of ticks to warmup before collecting traces.
    trace_tick_warmup: Option<usize>,
}

pub fn get_config_path() -> Result<PathBuf> {
    let xdg_dirs = xdg::BaseDirectories::with_prefix("scxtop")?;
    let config_path = xdg_dirs.get_config_file("scxtop.toml");
    Ok(config_path)
}

impl Config {
    /// App theme.
    pub fn theme(&self) -> &AppTheme {
        match &self.theme {
            Some(theme) => theme,
            None => &AppTheme::Default,
        }
    }

    /// Set the app theme.
    pub fn set_theme(&mut self, theme: AppTheme) {
        self.theme = Some(theme);
    }

    /// App tick rate in milliseconds.
    pub fn tick_rate_ms(&self) -> usize {
        self.tick_rate_ms.unwrap_or(250)
    }

    /// Set app tick rate in milliseconds.
    pub fn set_tick_rate_ms(&mut self, tick_rate_ms: usize) {
        self.tick_rate_ms = Some(tick_rate_ms);
    }

    /// Extra verbose output.
    pub fn debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    /// Exclude bpf event tracking.
    pub fn exclude_bpf(&self) -> bool {
        self.exclude_bpf.unwrap_or(false)
    }

    /// Stats unix socket path.
    pub fn stats_socket_path(&self) -> &str {
        match &self.stats_socket_path {
            Some(stats_socket_path) => stats_socket_path,
            None => STATS_SOCKET_PATH,
        }
    }

    /// Trace file prefix for perfetto traces.
    pub fn trace_file_prefix(&self) -> &str {
        match &self.trace_file_prefix {
            Some(trace_file_prefix) => trace_file_prefix,
            None => TRACE_FILE_PREFIX,
        }
    }

    /// Number of ticks for traces.
    pub fn trace_ticks(&self) -> usize {
        self.trace_ticks.unwrap_or(5)
    }

    /// Number of worker threads
    pub fn worker_threads(&self) -> u16 {
        self.worker_threads.unwrap_or(4)
    }

    /// Number of ticks to warmup before collecting traces.
    pub fn trace_tick_warmup(&self) -> usize {
        self.trace_tick_warmup.unwrap_or(3)
    }

    /// Returns a config with nothing set.
    pub fn empty_config() -> Config {
        Config {
            theme: None,
            tick_rate_ms: None,
            debug: None,
            exclude_bpf: None,
            stats_socket_path: None,
            trace_file_prefix: None,
            trace_ticks: None,
            worker_threads: None,
            trace_tick_warmup: None,
        }
    }

    /// Returns the default config.
    pub fn default_config() -> Config {
        let mut config = Config {
            theme: None,
            tick_rate_ms: None,
            debug: None,
            exclude_bpf: None,
            stats_socket_path: None,
            trace_file_prefix: None,
            trace_ticks: None,
            worker_threads: None,
            trace_tick_warmup: None,
        };
        config.tick_rate_ms = Some(config.tick_rate_ms());
        config.debug = Some(config.debug());
        config.exclude_bpf = Some(config.exclude_bpf());

        config
    }

    /// Loads the config from XDG configuration.
    pub fn load() -> Result<Config> {
        let config_path = get_config_path()?;
        let contents = fs::read_to_string(config_path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Merges a Config with a Cli config.
    pub fn merge_cli(config: &Config, cli: &Cli) -> Config {
        Config {
            theme: config.theme.clone(),
            tick_rate_ms: Some(cli.tick_rate_ms.unwrap_or(config.tick_rate_ms())),
            debug: Some(cli.debug.unwrap_or(config.debug())),
            exclude_bpf: Some(cli.exclude_bpf.unwrap_or(config.exclude_bpf())),
            stats_socket_path: match &cli.stats_socket_path {
                Some(s) => {
                    if !s.is_empty() {
                        Some(s.to_string())
                    } else {
                        config.stats_socket_path.clone()
                    }
                }
                None => config.stats_socket_path.clone(),
            },
            trace_file_prefix: match &cli.trace_file_prefix {
                Some(s) => {
                    if !s.is_empty() {
                        Some(s.to_string())
                    } else {
                        config.trace_file_prefix.clone()
                    }
                }
                None => config.trace_file_prefix.clone(),
            },
            trace_ticks: Some(cli.trace_ticks.unwrap_or(config.trace_ticks())),
            worker_threads: Some(cli.worker_threads.unwrap_or(config.worker_threads())),
            trace_tick_warmup: Some(cli.trace_tick_warmup.unwrap_or(config.trace_tick_warmup())),
        }
    }

    /// Saves the current config.
    pub fn save(&mut self) -> Result<()> {
        let config_path = get_config_path()?;
        if !config_path.exists() {
            fs::create_dir_all(config_path.parent().map(PathBuf::from).unwrap())?;
        }
        let config_str = toml::to_string(&self)?;
        Ok(fs::write(&config_path, config_str)?)
    }
}
