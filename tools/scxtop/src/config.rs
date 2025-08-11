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
/// frame_rate_ms = 20
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
    /// App render rate in milliseconds.
    frame_rate_ms: Option<usize>,
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
    /// Default profiling event string, in the format <source>:<event>
    /// where `source` is one of kprobe, perf, or cpu.
    default_profiling_event: Option<String>,
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
            frame_rate_ms: args.frame_rate_ms,
            trace_file_prefix: args.trace_file_prefix,
            trace_tick_warmup: args.trace_tick_warmup,
            trace_warmup_ms: args.trace_warmup_ms,
            trace_ticks: args.trace_ticks,
            trace_duration_ms: args.trace_duration_ms,
            worker_threads: args.worker_threads,
            default_profiling_event: Some(args.default_profiling_event),
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
            frame_rate_ms: self.frame_rate_ms.or(rhs.frame_rate_ms),
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
            default_profiling_event: self.default_profiling_event.or(rhs.default_profiling_event),
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

    /// App render rate in milliseconds.
    pub fn frame_rate_ms(&self) -> usize {
        self.frame_rate_ms.unwrap_or(250)
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
        self.trace_duration_ms.unwrap_or(1_250) * 1_000_000
    }

    /// Number of worker threads
    pub fn worker_threads(&self) -> u16 {
        self.worker_threads.unwrap_or(4)
    }

    /// Default event
    pub fn default_profiling_event(&self) -> String {
        self.default_profiling_event
            .clone()
            .unwrap_or("cpu:cpu_total_util_percent".to_string())
    }

    /// Duration to warmup a trace before collecting in ns.
    pub fn trace_warmup_ns(&self) -> u64 {
        self.trace_warmup_ms.unwrap_or(750) * 1_000_000
    }

    /// Returns a config with nothing set.
    pub fn empty_config() -> Config {
        Config {
            keymap: None,
            active_keymap: KeyMap::empty(),
            theme: None,
            tick_rate_ms: None,
            frame_rate_ms: None,
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
            default_profiling_event: None,
        }
    }

    /// Returns the default config.
    pub fn default_config() -> Config {
        let mut config = Config {
            keymap: None,
            active_keymap: KeyMap::default(),
            theme: None,
            tick_rate_ms: None,
            frame_rate_ms: None,
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
            default_profiling_event: None,
        };
        config.tick_rate_ms = Some(config.tick_rate_ms());
        config.frame_rate_ms = Some(config.frame_rate_ms());
        config.debug = Some(config.debug());
        config.exclude_bpf = Some(config.exclude_bpf());

        config
    }

    /// Loads the config from XDG configuration.
    pub fn load_or_default() -> Result<Config> {
        let config_path = get_config_path()?;

        if !config_path.exists() {
            return Ok(Config::default_config());
        }

        let contents = fs::read_to_string(config_path)?;
        let mut config: Config = toml::from_str(&contents)?;

        config.resolve_keymap()?;

        Ok(config)
    }

    fn resolve_keymap(&mut self) -> Result<()> {
        if let Some(keymap_config) = &self.keymap {
            let mut keymap = KeyMap::default();
            for (key_str, action_str) in keymap_config {
                let key = parse_key(key_str)?;
                let action = parse_action(action_str)?;
                keymap.insert(key, action);
            }
            self.active_keymap = keymap;
        } else {
            self.active_keymap = KeyMap::default();
        }
        Ok(())
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
    use crate::Action;
    use clap::Parser;
    use std::path::Path;
    use tempfile::tempdir;

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

    #[test]
    fn test_config_from_tui_args() {
        let args = TuiArgs::try_parse_from(vec![
            "scxtop",
            "--debug",
            "true",
            "--exclude-bpf",
            "true",
            "--perf-events",
            "cpu:cycles",
            "mem:faults",
            "--stats-socket-path",
            "/tmp/my_socket",
            "--tick-rate-ms",
            "100",
            "--frame-rate-ms",
            "10",
            "--trace-file-prefix",
            "/var/log/trace",
            "--trace-warmup-ms",
            "500",
            "--trace-duration-ms",
            "1000",
            "--worker-threads",
            "8",
            "--default-profiling-event",
            "perf:cpu:instructions",
        ])
        .unwrap();

        let config: Config = args.into();

        assert!(config.debug.unwrap());
        assert!(config.exclude_bpf.unwrap());
        assert_eq!(
            config.perf_events,
            vec!["cpu:cycles".to_string(), "mem:faults".to_string()]
        );
        assert_eq!(
            config.stats_socket_path.unwrap(),
            "/tmp/my_socket".to_string()
        );
        assert_eq!(config.tick_rate_ms.unwrap(), 100);
        assert_eq!(config.frame_rate_ms.unwrap(), 10);
        assert_eq!(
            config.trace_file_prefix.unwrap(),
            "/var/log/trace".to_string()
        );
        assert_eq!(config.trace_duration_ms.unwrap(), 1000);
        assert_eq!(config.worker_threads.unwrap(), 8);
        assert_eq!(
            config.default_profiling_event.unwrap(),
            "perf:cpu:instructions".to_string()
        );
        assert!(config.keymap.is_none());
        assert!(config.active_keymap.is_empty());
        assert!(config.theme.is_none());
    }

    #[test]
    fn test_config_from_tui_args_defaults() {
        let args = TuiArgs::try_parse_from(vec!["scxtop"]).unwrap();

        let config: Config = args.into();

        assert!(config.debug.is_none());
        assert!(config.exclude_bpf.is_none());
        assert!(config.perf_events.is_empty());
        assert!(config.stats_socket_path.is_none());
        assert!(config.tick_rate_ms.is_none());
        assert!(config.tick_rate_ms.is_none());
        assert!(config.trace_file_prefix.is_none());
        assert!(config.trace_warmup_ms.is_none());
        assert!(config.trace_ticks.is_none());
        assert!(config.trace_duration_ms.is_none());
        assert!(config.worker_threads.is_none());
        assert_eq!(
            config.default_profiling_event.unwrap(),
            "cpu:cpu_total_util_percent".to_string()
        );
    }

    #[test]
    fn test_merge_configs_no_overwrite() {
        let mut a = Config::empty_config();
        a.theme = Some(AppTheme::SolarizedDark);
        a.tick_rate_ms = Some(100);
        a.debug = Some(true);
        a.exclude_bpf = Some(true);
        a.perf_events = vec!["event_a".to_string()];
        a.stats_socket_path = Some("/path/a".to_string());
        a.trace_file_prefix = Some("prefix_a".to_string());
        a.trace_ticks = Some(5);
        a.trace_duration_ms = Some(500);
        a.worker_threads = Some(2);
        a.trace_warmup_ms = Some(100);
        a.default_profiling_event = Some("default_a".to_string());

        let mut b = Config::empty_config();
        b.theme = Some(AppTheme::IAmBlue);
        b.tick_rate_ms = Some(200);
        b.debug = Some(false);
        b.exclude_bpf = Some(false);
        b.perf_events = vec!["event_b".to_string()];
        b.stats_socket_path = Some("/path/b".to_string());
        b.trace_file_prefix = Some("prefix_b".to_string());
        b.trace_ticks = Some(10);
        b.trace_duration_ms = Some(1000);
        b.worker_threads = Some(4);
        b.trace_warmup_ms = Some(200);
        b.default_profiling_event = Some("default_b".to_string());

        // Test `or` method
        let merged_or = a.clone().or(b.clone());

        assert_eq!(merged_or.theme(), &AppTheme::SolarizedDark);
        assert_eq!(merged_or.tick_rate_ms(), 100);
        assert!(merged_or.debug());
        assert!(merged_or.exclude_bpf());
        assert_eq!(merged_or.perf_events, vec!["event_a".to_string()]);
        assert_eq!(merged_or.stats_socket_path(), "/path/a");
        assert_eq!(merged_or.trace_file_prefix(), "prefix_a");
        assert_eq!(merged_or.trace_ticks, Some(5));
        assert_eq!(merged_or.trace_duration_ms, Some(500));
        assert_eq!(merged_or.worker_threads(), 2);
        assert_eq!(merged_or.trace_warmup_ms, Some(100));
        assert_eq!(merged_or.default_profiling_event(), "default_a");

        // Test `merge` method
        let merged = Config::merge([a, b]);

        assert_eq!(merged.theme(), &AppTheme::SolarizedDark);
        assert_eq!(merged.tick_rate_ms(), 100);
        assert!(merged.debug());
        assert!(merged.exclude_bpf());
        assert_eq!(merged.perf_events, vec!["event_a".to_string()]);
        assert_eq!(merged.stats_socket_path(), "/path/a");
        assert_eq!(merged.trace_file_prefix(), "prefix_a");
        assert_eq!(merged.trace_ticks, Some(5));
        assert_eq!(merged.trace_duration_ms, Some(500));
        assert_eq!(merged.worker_threads(), 2);
        assert_eq!(merged.trace_warmup_ms, Some(100));
        assert_eq!(merged.default_profiling_event(), "default_a");
    }

    #[test]
    fn test_merge_configs_overwrite() {
        // Test with some None values
        let mut a = Config::empty_config();
        a.theme = None;
        a.debug = None;
        a.tick_rate_ms = Some(300);
        a.exclude_bpf = Some(true);
        a.perf_events = vec![];

        let mut b = Config::empty_config();
        b.theme = Some(AppTheme::IAmBlue);
        b.tick_rate_ms = None;
        b.debug = Some(false);
        b.exclude_bpf = Some(false);
        b.perf_events = vec!["event_d".to_string()];

        let merged_or = a.clone().or(b.clone());
        assert_eq!(merged_or.theme(), &AppTheme::IAmBlue);
        assert_eq!(merged_or.tick_rate_ms(), 300);
        assert!(!merged_or.debug());
        assert!(merged_or.exclude_bpf());
        assert_eq!(merged_or.perf_events, vec!["event_d".to_string()]);
    }

    #[test]
    fn test_config_getters_and_setters() {
        let mut config = Config::empty_config();

        // Theme
        assert_eq!(config.theme(), &AppTheme::Default);
        config.set_theme(AppTheme::IAmBlue);
        assert_eq!(config.theme(), &AppTheme::IAmBlue);

        // Tick Rate
        assert_eq!(config.tick_rate_ms(), 250);
        config.set_tick_rate_ms(500);
        assert_eq!(config.tick_rate_ms(), 500);

        // Debug
        assert!(!config.debug());
        config.debug = Some(true);
        assert!(config.debug());

        // Exclude BPF
        assert!(!config.exclude_bpf());
        config.exclude_bpf = Some(true);
        assert!(config.exclude_bpf());

        // Stats Socket Path
        assert_eq!(config.stats_socket_path(), STATS_SOCKET_PATH);
        config.stats_socket_path = Some("/tmp/custom_socket".to_string());
        assert_eq!(config.stats_socket_path(), "/tmp/custom_socket");

        // Trace File Prefix
        assert_eq!(config.trace_file_prefix(), TRACE_FILE_PREFIX);
        config.trace_file_prefix = Some("/tmp/custom_trace".to_string());
        assert_eq!(config.trace_file_prefix(), "/tmp/custom_trace");

        // Trace Duration NS
        config.trace_duration_ms = Some(2000);
        assert_eq!(config.trace_duration_ns(), 2000 * 1_000_000);

        // Worker Threads
        assert_eq!(config.worker_threads(), 4);
        config.worker_threads = Some(8);
        assert_eq!(config.worker_threads(), 8);

        // Default Perf Event
        assert_eq!(
            config.default_profiling_event(),
            "cpu:cpu_total_util_percent".to_string()
        );
        config.default_profiling_event = Some("perf:cpu:instructions".to_string());
        assert_eq!(
            config.default_profiling_event(),
            "perf:cpu:instructions".to_string()
        );

        // Trace Warmup NS
        config.trace_warmup_ms = Some(1500);
        assert_eq!(config.trace_warmup_ns(), 1500 * 1_000_000);
    }

    #[test]
    fn test_empty_config() {
        let config = Config::empty_config();

        assert!(config.keymap.is_none());
        assert!(config.active_keymap.is_empty());
        assert!(config.theme.is_none());
        assert!(config.tick_rate_ms.is_none());
        assert!(config.frame_rate_ms.is_none());
        assert!(config.debug.is_none());
        assert!(config.perf_events.is_empty());
        assert!(config.exclude_bpf.is_none());
        assert!(config.stats_socket_path.is_none());
        assert!(config.trace_file_prefix.is_none());
        assert!(config.trace_ticks.is_none());
        assert!(config.trace_duration_ms.is_none());
        assert!(config.worker_threads.is_none());
        assert!(config.trace_tick_warmup.is_none());
        assert!(config.trace_warmup_ms.is_none());
        assert!(config.default_profiling_event.is_none());

        // Check getters return defaults
        assert_eq!(config.theme(), &AppTheme::Default);
        assert_eq!(config.tick_rate_ms(), 250);
        assert_eq!(config.frame_rate_ms(), 250);
        assert!(!config.debug());
        assert!(!config.exclude_bpf());
        assert_eq!(config.stats_socket_path(), STATS_SOCKET_PATH);
        assert_eq!(config.trace_file_prefix(), TRACE_FILE_PREFIX);
        assert_eq!(config.trace_duration_ns(), 1250 * 1_000_000);
        assert_eq!(config.worker_threads(), 4);
        assert_eq!(
            config.default_profiling_event(),
            "cpu:cpu_total_util_percent".to_string()
        );
        assert_eq!(config.trace_warmup_ns(), 750 * 1_000_000);
    }

    #[test]
    fn test_default_config() {
        let config = Config::default_config();

        // Check that optional fields that have defaults are Some(default_value)
        assert!(config.tick_rate_ms.is_some());
        assert_eq!(config.tick_rate_ms.unwrap(), 250);
        assert!(config.frame_rate_ms.is_some());
        assert!(config.debug.is_some());
        assert!(!config.debug.unwrap());
        assert!(config.exclude_bpf.is_some());
        assert!(!config.exclude_bpf.unwrap());

        // Other fields should still be None or empty vec/KeyMap
        assert!(config.keymap.is_none());
        assert!(!config.active_keymap.is_empty()); // Should be default KeyMap, which is not empty
        assert!(config.theme.is_none());
        assert!(config.perf_events.is_empty());
        assert!(config.stats_socket_path.is_none());
        assert!(config.trace_file_prefix.is_none());
        assert!(config.trace_ticks.is_none());
        assert!(config.trace_duration_ms.is_none());
        assert!(config.worker_threads.is_none());
        assert!(config.trace_tick_warmup.is_none());
        assert!(config.trace_warmup_ms.is_none());
        assert!(config.default_profiling_event.is_none());
    }

    // Helper to mock xdg::BaseDirectories for testing file paths
    struct MockXdgBaseDirectories {
        config_home: PathBuf,
    }

    impl MockXdgBaseDirectories {
        fn new(base_path: &Path) -> Self {
            MockXdgBaseDirectories {
                config_home: base_path.join(".config"),
            }
        }

        fn get_config_file(&self, file_name: &str) -> PathBuf {
            self.config_home.join("scxtop").join(file_name)
        }
    }

    // Mocking get_config_path for isolated testing
    // This would typically involve dependency injection or using a library
    // that allows mocking static functions, which is more complex in Rust.
    // For demonstration, we'll create a test function that would set up
    // a temporary directory and simulate the config path.
    fn get_mock_config_path(temp_dir_path: &Path) -> Result<PathBuf> {
        let mock_xdg_dirs = MockXdgBaseDirectories::new(temp_dir_path);
        Ok(mock_xdg_dirs.get_config_file("scxtop.toml"))
    }

    #[test]
    fn test_load_and_save_config() {
        let dir = tempdir().expect("Failed to create temporary directory");
        let config_path = get_mock_config_path(dir.path()).expect("Failed to get mock config path");

        // Ensure the parent directory exists for saving
        let config_parent_dir = config_path.parent().unwrap();
        fs::create_dir_all(config_parent_dir)
            .expect("Failed to create parent directory for config");

        let mut config_to_save = Config::default_config();
        config_to_save.set_theme(AppTheme::MidnightGreen);
        config_to_save.set_tick_rate_ms(5000);
        config_to_save.debug = Some(true);
        config_to_save.exclude_bpf = Some(true);
        config_to_save.perf_events = vec!["custom:event".to_string()];
        config_to_save.stats_socket_path = Some("/my/socket".to_string());
        config_to_save.trace_file_prefix = Some("my_trace".to_string());
        config_to_save.trace_duration_ms = Some(2000);
        config_to_save.worker_threads = Some(6);
        config_to_save.trace_warmup_ms = Some(500);
        config_to_save.default_profiling_event = Some("another:event".to_string());

        let mut test_keymap = HashMap::new();
        test_keymap.insert("i".to_string(), "Quit".to_string());
        test_keymap.insert("2".to_string(), "AppStateHelp".to_string());
        config_to_save.keymap = Some(test_keymap.clone());

        let mut active_keymap_for_save = KeyMap::empty();
        active_keymap_for_save.insert(parse_key("i").unwrap(), parse_action("Quit").unwrap());
        active_keymap_for_save.insert(
            parse_key("2").unwrap(),
            parse_action("AppStateHelp").unwrap(),
        );
        config_to_save.active_keymap = active_keymap_for_save;

        // Simulate save by writing to the mock path
        let saved_config_str =
            toml::to_string(&config_to_save).expect("Failed to serialize config");
        fs::write(&config_path, saved_config_str)
            .expect("Failed to write config to mock path for saving test");

        // For this test, we cannot directly call `Config::load()` as it uses the real `get_config_path()`.
        // Instead, we will simulate the loading process here directly using the mock path.
        let saved_content =
            fs::read_to_string(&config_path).expect("Failed to read saved config file");
        let loaded_from_file: Config =
            toml::from_str(&saved_content).expect("Failed to deserialize saved config");

        assert_eq!(loaded_from_file.theme, config_to_save.theme);
        assert_eq!(loaded_from_file.tick_rate_ms, config_to_save.tick_rate_ms);
        assert_eq!(loaded_from_file.debug, config_to_save.debug);
        assert_eq!(loaded_from_file.exclude_bpf, config_to_save.exclude_bpf);
        assert_eq!(loaded_from_file.perf_events, config_to_save.perf_events);
        assert_eq!(
            loaded_from_file.stats_socket_path,
            config_to_save.stats_socket_path
        );
        assert_eq!(
            loaded_from_file.trace_file_prefix,
            config_to_save.trace_file_prefix
        );
        assert_eq!(
            loaded_from_file.trace_duration_ms,
            config_to_save.trace_duration_ms
        );
        assert_eq!(
            loaded_from_file.worker_threads,
            config_to_save.worker_threads
        );
        assert_eq!(
            loaded_from_file.trace_warmup_ms,
            config_to_save.trace_warmup_ms
        );
        assert_eq!(
            loaded_from_file.default_profiling_event,
            config_to_save.default_profiling_event
        );
        assert_eq!(loaded_from_file.keymap, Some(test_keymap));
    }

    #[test]
    fn test_load_config() {
        let dir = tempdir().expect("Failed to create temporary directory");
        let config_path = get_mock_config_path(dir.path()).expect("Failed to get mock config path");

        // Ensure the parent directory exists for saving
        let config_parent_dir = config_path.parent().unwrap();
        fs::create_dir_all(config_parent_dir)
            .expect("Failed to create parent directory for config");

        // Create a dummy config file in the temporary directory
        let config_content = r#"
        theme = "IAmBlue"
        tick_rate_ms = 123
        debug = true
        exclude_bpf = true
        worker_threads = 5
        perf_events = ["my_event_1", "my_event_2"]
        stats_socket_path = "/test/socket"
        trace_file_prefix = "test_trace"
        trace_duration_ms = 1000
        trace_warmup_ms = 200
        default_profiling_event = "cpu:cycles"
        [keymap]
        i = "Quit"
        2 = "Enter"
        "#;
        fs::write(&config_path, config_content).expect("Failed to write dummy config file");

        let contents =
            fs::read_to_string(&config_path).expect("Failed to read file for loading test");
        let mut loaded_config: Config =
            toml::from_str(&contents).expect("Failed to deserialize for loading test");

        // Manually parse keymap as load() does
        if let Some(keymap_config) = &loaded_config.keymap {
            let mut keymap = KeyMap::default();
            for (key_str, action_str) in keymap_config {
                let key = parse_key(key_str).expect("Failed to parse key");
                let action = parse_action(action_str).expect("Failed to parse action");
                keymap.insert(key, action);
            }
            loaded_config.active_keymap = keymap;
        } else {
            loaded_config.active_keymap = KeyMap::default();
        }

        assert_eq!(loaded_config.theme(), &AppTheme::IAmBlue);
        assert_eq!(loaded_config.tick_rate_ms(), 123);
        assert!(loaded_config.debug());
        assert!(loaded_config.exclude_bpf());
        assert_eq!(loaded_config.worker_threads(), 5);
        assert_eq!(
            loaded_config.perf_events,
            vec!["my_event_1".to_string(), "my_event_2".to_string()]
        );
        assert_eq!(loaded_config.stats_socket_path(), "/test/socket");
        assert_eq!(loaded_config.trace_file_prefix(), "test_trace");
        assert_eq!(loaded_config.trace_duration_ms, Some(1000));
        assert_eq!(loaded_config.trace_warmup_ms, Some(200));
        assert_eq!(
            loaded_config.default_profiling_event(),
            "cpu:cycles".to_string()
        );

        // Verify active_keymap
        assert!(loaded_config
            .active_keymap
            .get(&parse_key("i").unwrap())
            .is_some_and(|action| *action == Action::Quit));
        assert!(loaded_config
            .active_keymap
            .get(&parse_key("2").unwrap())
            .is_some_and(|action| *action == Action::Enter));
    }

    #[test]
    fn test_config_integration_test_complex() {
        let dir = tempdir().expect("Failed to create temporary directory");
        let config_path = get_mock_config_path(dir.path()).expect("Failed to get mock config path");

        // Ensure the parent directory exists for saving
        let config_parent_dir = config_path.parent().unwrap();
        fs::create_dir_all(config_parent_dir)
            .expect("Failed to create parent directory for config");

        // Create a dummy config file in the temporary directory
        let saved_config = r#"
        perf_events = []
        theme = "MidnightGreen"
        tick_rate_ms = 500
        debug = false
        exclude_bpf = true
        default_profiling_event = "perf:mem:faults"

        [keymap]
        S = "SaveConfig"
        "+" = "IncTickRate"
        "[" = "DecBpfSampleRate"
        h = "AppStateHelp"
        Esc = "Esc"
        o = "NextViewState"
        P = "ToggleHwPressure"
        k = "NextEvent"
        Enter = "Enter"
        "]" = "IncBpfSampleRate"
        "?" = "AppStateHelp"
        u = "ToggleUncoreFreq"
        f = "ToggleCpuFreq"
        "Page Down" = "PageDown"
        Down = "Down"
        j = "PrevEvent"
        x = "ClearEvent"
        "Page Up" = "PageUp"
        l = "AppStateLlc"
        n = "AppStateNode"
        s = "AppStateScheduler"
        d = "AppStateDefault"
        m = "AppStateMangoApp"
        a = "RequestTrace"
        K = "AppStateKprobeEvent"
        L = "ToggleLocalization"
        Backspace = "Backspace"
        - = "DecTickRate"
        Up = "Up"
        t = "ChangeTheme"
        i = "Quit"
        e = "AppStatePerfEvent"
        "#;

        fs::write(&config_path, saved_config).expect("Failed to write dummy config file");

        let contents = fs::read_to_string(&config_path).expect("Failed to read file");
        let mut loaded_config: Config = toml::from_str(&contents).expect("Failed to deserialize");
        loaded_config
            .resolve_keymap()
            .expect("Failed to resolve keymap");

        let tui_args = TuiArgs::try_parse_from(vec![
            "scxtop",
            "--debug",
            "true",
            "--perf-events",
            "cpu:cycles",
            "mem:faults",
            "--default-profiling-event",
            "perf:cpu:instructions",
        ])
        .unwrap();

        // This is how the config is loaded in main
        let config = Config::merge([Config::from(tui_args.clone()), loaded_config]);

        assert_eq!(config.theme(), &AppTheme::MidnightGreen);
        assert_eq!(config.tick_rate_ms(), 500);
        assert!(config.debug());
        assert!(config.exclude_bpf());
        assert_eq!(
            config.perf_events,
            vec!["cpu:cycles".to_string(), "mem:faults".to_string()]
        );
        assert_eq!(
            config.default_profiling_event(),
            "perf:cpu:instructions".to_string()
        );

        assert!(config
            .active_keymap
            .get(&parse_key("i").unwrap())
            .is_some_and(|action| *action == Action::Quit));
        assert!(config
            .active_keymap
            .get(&parse_key("o").unwrap())
            .is_some_and(|action| *action == Action::NextViewState));
    }
}
