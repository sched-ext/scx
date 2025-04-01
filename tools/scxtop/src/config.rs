// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::cli::TuiArgs;
use crate::keymap::parse_action;
use crate::keymap::parse_key;
use crate::AppTheme;
use crate::KeyMap;
use crate::STATS_SOCKET_PATH;
use crate::TRACE_FILE_PREFIX;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use xdg;

/// `scxtop` can use a configuration file, which can be generated using the `S` key
/// in the default keymap configuration. The config file (`scxtop.toml`) follows the
/// [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).
///
/// An example configuration shows customization of default tick rates, theme and keymaps:
/// ```text
/// theme = "IAmBlue"
/// tick_rate_ms = 250
/// debug = false
/// exclude_bpf = false
/// worker_threads = 4
///
/// [keymap]
/// d = "AppStateDefault"
/// "?" = "AppStateHelp"
/// "[" = "DecBpfSampleRate"
/// q = "Quit"
/// "+" = "IncTickRate"
/// u = "ToggleUncoreFreq"
/// "Page Down" = "PageDown"
/// S = "SaveConfig"
/// Up = "Up"
/// P = "RecordTrace"
/// - = "DecTickRate"
/// L = "ToggleLocalization"
/// t = "ChangeTheme"
/// "]" = "IncBpfSampleRate"
/// Down = "Down"
/// l = "AppStateLlc"
/// k = "NextEvent"
/// a = "RecordTrace"
/// j = "PrevEvent"
/// v = "NextViewState"
/// h = "AppStateHelp"
/// n = "AppStateNode"
/// s = "AppStateScheduler"
/// e = "AppStateEvent"
/// w = "RecordTrace"
/// f = "ToggleCpuFreq"
/// Enter = "Enter"
/// "Page Up" = "PageUp"
/// x = "ClearEvent"
/// ```

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// Key mappings.
    pub keymap: Option<HashMap<String, String>>,
    /// Parsed keymap.
    #[serde(skip)]
    pub active_keymap: KeyMap,
    /// Configured perf events. Must be in format <alias>:<event_config>
    pub perf_events: Vec<String>,
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
    /// DEPRECATED: Number of ticks for traces. Use trace_duration_ms instead.
    trace_ticks: Option<usize>,
    /// Duration of trace in ms.
    trace_duration_ms: Option<u64>,
    /// Number of worker threads
    worker_threads: Option<u16>,
    /// DEPRECATED: Number of ticks to warmup before collecting traces. Use trace_warmup_ms instead.
    trace_tick_warmup: Option<usize>,
    /// Duration to warmup a trace before collecting in ms.
    trace_warmup_ms: Option<u64>,
}

impl From<TuiArgs> for Config {
    fn from(args: TuiArgs) -> Config {
        Config {
            active_keymap: KeyMap::empty(),
            debug: args.debug,
            exclude_bpf: args.exclude_bpf,
            keymap: None,
            perf_events: args.perf_events,
            stats_socket_path: args.stats_socket_path,
            theme: None,
            tick_rate_ms: args.tick_rate_ms,
            trace_file_prefix: args.trace_file_prefix,
            trace_tick_warmup: args.trace_tick_warmup,
            trace_warmup_ms: args.trace_warmup_ms,
            trace_ticks: args.trace_ticks,
            trace_duration_ms: args.trace_duration_ms,
            worker_threads: args.worker_threads,
        }
    }
}

pub fn get_config_path() -> Result<PathBuf> {
    let xdg_dirs = xdg::BaseDirectories::with_prefix("scxtop")?;
    let config_path = xdg_dirs.get_config_file("scxtop.toml");
    Ok(config_path)
}

impl Config {
    pub fn merge<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter().fold(Self::empty_config(), Self::or)
    }

    pub fn or(self, rhs: Self) -> Self {
        let active_keymap = if self.keymap.is_some() {
            self.active_keymap
        } else {
            rhs.active_keymap
        };

        Self {
            keymap: self.keymap.or(rhs.keymap),
            active_keymap,
            theme: self.theme.or(rhs.theme),
            tick_rate_ms: self.tick_rate_ms.or(rhs.tick_rate_ms),
            debug: self.debug.or(rhs.debug),
            exclude_bpf: self.exclude_bpf.or(rhs.exclude_bpf),
            perf_events: if !self.perf_events.is_empty() {
                self.perf_events
            } else {
                rhs.perf_events
            },
            stats_socket_path: self.stats_socket_path.or(rhs.stats_socket_path),
            trace_file_prefix: self.trace_file_prefix.or(rhs.trace_file_prefix),
            trace_ticks: self.trace_ticks.or(rhs.trace_ticks),
            trace_duration_ms: self.trace_duration_ms.or(rhs.trace_duration_ms),
            worker_threads: self.worker_threads.or(rhs.worker_threads),
            trace_tick_warmup: self.trace_tick_warmup.or(rhs.trace_tick_warmup),
            trace_warmup_ms: self.trace_warmup_ms.or(rhs.trace_warmup_ms),
        }
    }

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

    /// Duration of trace in ns.
    pub fn trace_duration_ns(&self) -> u64 {
        self.trace_duration_ms
            .or(self.trace_ticks.map(|t| (t * self.tick_rate_ms()) as u64))
            .unwrap_or(1_250)
            * 1_000_000
    }

    /// Number of worker threads
    pub fn worker_threads(&self) -> u16 {
        self.worker_threads.unwrap_or(4)
    }

    /// Duration to warmup a trace before collecting in ns.
    pub fn trace_warmup_ns(&self) -> u64 {
        self.trace_warmup_ms
            .or(self
                .trace_tick_warmup
                .map(|t| (t * self.tick_rate_ms()) as u64))
            .unwrap_or(750)
            * 1_000_000
    }

    /// Returns a config with nothing set.
    pub fn empty_config() -> Config {
        Config {
            keymap: None,
            active_keymap: KeyMap::empty(),
            theme: None,
            tick_rate_ms: None,
            debug: None,
            perf_events: vec![],
            exclude_bpf: None,
            stats_socket_path: None,
            trace_file_prefix: None,
            trace_ticks: None,
            trace_duration_ms: None,
            worker_threads: None,
            trace_tick_warmup: None,
            trace_warmup_ms: None,
        }
    }

    /// Returns the default config.
    pub fn default_config() -> Config {
        let mut config = Config {
            keymap: None,
            active_keymap: KeyMap::default(),
            theme: None,
            tick_rate_ms: None,
            debug: None,
            exclude_bpf: None,
            perf_events: vec![],
            stats_socket_path: None,
            trace_file_prefix: None,
            trace_ticks: None,
            trace_duration_ms: None,
            worker_threads: None,
            trace_tick_warmup: None,
            trace_warmup_ms: None,
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
        let mut config: Config = toml::from_str(&contents)?;

        if let Some(keymap_config) = &config.keymap {
            let mut keymap = KeyMap::default();
            for (key_str, action_str) in keymap_config {
                let key = parse_key(key_str)?;
                let action = parse_action(action_str)?;
                keymap.insert(key, action);
            }
            config.active_keymap = keymap;
        } else {
            config.active_keymap = KeyMap::default();
        }

        Ok(config)
    }

    /// Saves the current config.
    pub fn save(&mut self) -> Result<()> {
        self.keymap = Some(self.active_keymap.to_hashmap());
        let config_path = get_config_path()?;
        if !config_path.exists() {
            fs::create_dir_all(config_path.parent().map(PathBuf::from).unwrap())?;
        }
        let config_str = toml::to_string(&self)?;
        Ok(fs::write(&config_path, config_str)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_configs() {
        let mut a = Config::empty_config();
        a.theme = Some(AppTheme::MidnightGreen);
        a.tick_rate_ms = None;
        a.debug = Some(true);
        a.exclude_bpf = None;

        let mut b = Config::empty_config();
        b.theme = Some(AppTheme::IAmBlue);
        b.tick_rate_ms = Some(114);
        b.debug = None;
        a.exclude_bpf = None;

        let merged = Config::merge([a, b]);

        assert_eq!(merged.theme(), &AppTheme::MidnightGreen);
        assert_eq!(merged.tick_rate_ms(), 114);
        assert!(merged.debug());
        assert!(!merged.exclude_bpf());
    }
}
