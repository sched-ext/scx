// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024-2025 Vladislav Nepogodin <vnepogodin@cachyos.org>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde::Serialize;

use crate::SchedMode;
use crate::SupportedSched;

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub default_sched: Option<SupportedSched>,
    pub default_mode: Option<SchedMode>,
    pub scheds: HashMap<String, Sched>,
    pub security: SecurityConfig,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Sched {
    pub auto_mode: Option<Vec<String>>,
    pub gaming_mode: Option<Vec<String>>,
    pub lowlatency_mode: Option<Vec<String>>,
    pub powersave_mode: Option<Vec<String>>,
    pub server_mode: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct SecurityConfig {
    /// Authorization mode: "permissive" (any user), "group" (group-based), "polkit" (Polkit)
    pub authorization_mode: AuthorizationMode,

    /// Group name required for D-Bus access (when authorization_mode = "group")
    pub required_group: Option<String>,

    /// Enable argument validation
    pub validate_arguments: bool,

    /// Use strict allowlist validation (requires allowlist config)
    pub strict_allowlist: bool,

    /// Maximum number of arguments per scheduler invocation
    pub max_arguments: usize,

    /// Maximum length of any single argument
    pub max_argument_length: usize,

    /// Enable auto-mode (automatic scheduler launch on CPU threshold)
    pub allow_auto_mode: bool,

    /// Maximum concurrent scheduler start attempts
    pub max_concurrent_starts: usize,

    /// Delay between retry attempts in milliseconds
    pub retry_delay_ms: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationMode {
    /// No authorization (backward compatible, insecure)
    Permissive,
    /// Require membership in specific group
    Group,
    /// Use Polkit for authorization
    Polkit,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            authorization_mode: AuthorizationMode::Permissive,
            required_group: Some("wheel".to_string()),
            validate_arguments: true,
            strict_allowlist: false,
            max_arguments: 128,
            max_argument_length: 4096,
            allow_auto_mode: true,
            // 0 means "use defaults from main.rs constants"
            max_concurrent_starts: 0,
            retry_delay_ms: 0,
        }
    }
}

/// Initialize config from first found config path, overwise fallback to default config
pub fn init_config() -> Result<Config> {
    let config = if let Ok(config_path) = get_config_path() {
        parse_config_file(&config_path)?
    } else {
        get_default_config()
    };

    config.validate()?;
    Ok(config)
}

// Maximum size for config file (1 MB)
const MAX_CONFIG_SIZE: usize = 1024 * 1024;

// Maximum nesting depth for TOML structures
const MAX_TOML_DEPTH: usize = 10;

pub fn parse_config_file(filepath: &str) -> Result<Config> {
    // Check file size before reading
    let metadata = std::fs::metadata(filepath)
        .with_context(|| format!("Failed to read metadata for {}", filepath))?;

    if metadata.len() > MAX_CONFIG_SIZE as u64 {
        anyhow::bail!(
            "Config file {} is too large: {} bytes exceeds maximum of {}",
            filepath,
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    // Read file content
    let file_content = fs::read_to_string(filepath)
        .with_context(|| format!("Failed to read config file {}", filepath))?;

    // Additional safety: double-check content size
    if file_content.len() > MAX_CONFIG_SIZE {
        anyhow::bail!("Config file content exceeds size limit");
    }

    parse_config_content(&file_content)
}

pub fn get_config_path() -> Result<String> {
    // Use fixed, absolute paths only - no environment variable interpolation
    // This prevents path traversal via environment manipulation
    let check_paths = [
        // locations for user config
        "/etc/scx_loader/config.toml",
        "/etc/scx_loader.toml",
        // locations for distributions to ship default configuration
        "/usr/share/scx_loader/config.toml",
        "/usr/share/scx_loader.toml",
    ];

    for check_path in check_paths {
        // Validate path is absolute
        let path = Path::new(check_path);
        if !path.is_absolute() {
            log::warn!("Skipping non-absolute path: {}", check_path);
            continue;
        }

        // Check if path exists before attempting canonicalization
        if !path.exists() {
            continue;
        }

        // Resolve symlinks and check final path
        match std::fs::canonicalize(path) {
            Ok(canonical) => {
                // Ensure canonical path starts with expected prefix
                let canonical_str = canonical.to_string_lossy();
                if !canonical_str.starts_with("/etc/scx_loader")
                    && !canonical_str.starts_with("/usr/share/scx_loader")
                {
                    log::warn!(
                        "Config path {} resolves outside allowed directories to {}",
                        check_path,
                        canonical_str
                    );
                    continue;
                }

                log::info!("Using config file: {}", canonical_str);
                return Ok(canonical.to_string_lossy().to_string());
            }
            Err(e) => {
                // Path exists but can't be canonicalized, skip
                log::warn!("Failed to canonicalize path {}: {}", check_path, e);
                continue;
            }
        }
    }

    anyhow::bail!(
        "Failed to find config in allowed locations: /etc/scx_loader/, /usr/share/scx_loader/"
    );
}

fn parse_config_content(file_content: &str) -> Result<Config> {
    if file_content.is_empty() {
        anyhow::bail!("The config file is empty!")
    }

    // Validate TOML structure depth (protection against TOML bombs)
    validate_toml_depth(file_content)?;

    // Parse with TOML parser
    let config: Config =
        toml::from_str(file_content).with_context(|| "Failed to parse TOML configuration")?;

    Ok(config)
}

fn validate_toml_depth(content: &str) -> Result<()> {
    let mut max_depth = 0;
    let mut current_depth = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Count opening brackets for nested tables
        let opens = trimmed.matches('[').count();
        let closes = trimmed.matches(']').count();

        // Account for table headers like [table.subtable]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Count dots in table name to determine depth
            let table_name = trimmed.trim_matches(|c| c == '[' || c == ']');
            let depth = table_name.matches('.').count() + 1;
            current_depth = depth;
        } else {
            // For inline tables and arrays
            current_depth += opens;
            current_depth = current_depth.saturating_sub(closes);
        }

        max_depth = max_depth.max(current_depth);

        if max_depth > MAX_TOML_DEPTH {
            anyhow::bail!(
                "TOML structure exceeds maximum nesting depth of {}",
                MAX_TOML_DEPTH
            );
        }
    }

    Ok(())
}

pub fn get_default_config() -> Config {
    let supported_scheds = [
        SupportedSched::Bpfland,
        SupportedSched::Rusty,
        SupportedSched::Lavd,
        SupportedSched::Flash,
        SupportedSched::P2DQ,
        SupportedSched::Tickless,
        SupportedSched::Rustland,
        SupportedSched::Cosmos,
    ];
    let scheds_map = HashMap::from(supported_scheds.map(init_default_config_entry));
    Config {
        default_sched: None,
        default_mode: Some(SchedMode::Auto),
        scheds: scheds_map,
        security: SecurityConfig::default(),
    }
}

/// Get the scx flags for the given sched mode
pub fn get_scx_flags_for_mode(
    config: &Config,
    scx_sched: &SupportedSched,
    sched_mode: SchedMode,
) -> Vec<String> {
    let scx_name: &str = scx_sched.clone().into();
    if let Some(sched_config) = config.scheds.get(scx_name) {
        let scx_flags = extract_scx_flags_from_config(sched_config, &sched_mode);

        // try to exact flags from config, otherwise fallback to hardcoded default
        scx_flags.unwrap_or({
            get_default_scx_flags_for_mode(scx_sched, sched_mode)
                .into_iter()
                .map(String::from)
                .collect()
        })
    } else {
        get_default_scx_flags_for_mode(scx_sched, sched_mode)
            .into_iter()
            .map(String::from)
            .collect()
    }
}

/// Extract the scx flags from config
fn extract_scx_flags_from_config(
    sched_config: &Sched,
    sched_mode: &SchedMode,
) -> Option<Vec<String>> {
    match sched_mode {
        SchedMode::Gaming => sched_config.gaming_mode.clone(),
        SchedMode::LowLatency => sched_config.lowlatency_mode.clone(),
        SchedMode::PowerSave => sched_config.powersave_mode.clone(),
        SchedMode::Server => sched_config.server_mode.clone(),
        SchedMode::Auto => sched_config.auto_mode.clone(),
    }
}

/// Get Sched object for configuration object
fn get_default_sched_for_config(scx_sched: &SupportedSched) -> Sched {
    Sched {
        auto_mode: Some(
            get_default_scx_flags_for_mode(scx_sched, SchedMode::Auto)
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        gaming_mode: Some(
            get_default_scx_flags_for_mode(scx_sched, SchedMode::Gaming)
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        lowlatency_mode: Some(
            get_default_scx_flags_for_mode(scx_sched, SchedMode::LowLatency)
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        powersave_mode: Some(
            get_default_scx_flags_for_mode(scx_sched, SchedMode::PowerSave)
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        server_mode: Some(
            get_default_scx_flags_for_mode(scx_sched, SchedMode::Server)
                .into_iter()
                .map(String::from)
                .collect(),
        ),
    }
}

/// Get the default scx flags for the given sched mode
fn get_default_scx_flags_for_mode(scx_sched: &SupportedSched, sched_mode: SchedMode) -> Vec<&str> {
    match scx_sched {
        SupportedSched::Bpfland => match sched_mode {
            SchedMode::Gaming => vec![],
            SchedMode::LowLatency => {
                vec!["-m", "performance", "-w"]
            }
            SchedMode::PowerSave => {
                vec!["-s", "20000", "-m", "powersave", "-I", "100", "-t", "100"]
            }
            SchedMode::Server => vec!["-s", "20000", "-S"],
            SchedMode::Auto => vec![],
        },
        SupportedSched::Lavd => match sched_mode {
            SchedMode::Gaming | SchedMode::LowLatency => vec!["--performance"],
            SchedMode::PowerSave => vec!["--powersave"],
            // NOTE: potentially adding --auto in future
            SchedMode::Server | SchedMode::Auto => vec![],
        },
        // scx_rusty doesn't support any of these modes
        SupportedSched::Rusty => vec![],
        SupportedSched::Flash => match sched_mode {
            SchedMode::Gaming => vec!["-m", "all"],
            SchedMode::LowLatency => vec!["-m", "performance", "-w", "-C", "0"],
            SchedMode::PowerSave => vec![
                "-m",
                "powersave",
                "-I",
                "10000",
                "-t",
                "10000",
                "-s",
                "10000",
                "-S",
                "1000",
            ],
            SchedMode::Server => vec![
                "-m", "all", "-s", "20000", "-S", "1000", "-I", "-1", "-D", "-L",
            ],
            SchedMode::Auto => vec![],
        },
        SupportedSched::P2DQ => match sched_mode {
            SchedMode::Gaming => vec!["--task-slice", "true", "-f", "--sched-mode", "performance"],
            SchedMode::LowLatency => vec!["-y", "-f", "--task-slice", "true"],
            SchedMode::PowerSave => vec!["--sched-mode", "efficiency"],
            SchedMode::Server => vec!["--keep-running"],
            SchedMode::Auto => vec![],
        },
        SupportedSched::Tickless => match sched_mode {
            SchedMode::Gaming => vec!["-f", "5000", "-s", "5000"],
            SchedMode::LowLatency => vec!["-f", "5000", "-s", "1000"],
            SchedMode::PowerSave => vec!["-f", "50", "-p"],
            SchedMode::Server => vec!["-f", "100"],
            SchedMode::Auto => vec![],
        },
        // scx_rustland doesn't support any of these modes
        SupportedSched::Rustland => vec![],
        SupportedSched::Cosmos => match sched_mode {
            SchedMode::Gaming => vec!["-c", "0", "-p", "0"],
            SchedMode::LowLatency => vec!["-m", "performance", "-c", "0", "-p", "0", "-w"],
            SchedMode::PowerSave => vec!["-m", "powersave", "-d", "-p", "5000"],
            SchedMode::Server => vec!["-a", "-s", "20000"],
            SchedMode::Auto => vec!["-d"],
        },
    }
}

/// Initializes entry for config sched map
fn init_default_config_entry(scx_sched: SupportedSched) -> (String, Sched) {
    let default_modes = get_default_sched_for_config(&scx_sched);
    (
        <SupportedSched as Into<&str>>::into(scx_sched).to_owned(),
        default_modes,
    )
}

/// Validate security configuration
pub fn validate_security_config(config: &SecurityConfig) -> Result<()> {
    if config.authorization_mode == AuthorizationMode::Group && config.required_group.is_none() {
        anyhow::bail!("authorization_mode 'group' requires required_group to be set");
    }

    if config.max_arguments == 0 {
        anyhow::bail!("max_arguments must be greater than 0");
    }

    if config.max_argument_length == 0 {
        anyhow::bail!("max_argument_length must be greater than 0");
    }

    // max_concurrent_starts: 0 means "use default", so allow it
    if config.max_concurrent_starts > 100 {
        anyhow::bail!("max_concurrent_starts must be 100 or less (0 uses default)");
    }

    // retry_delay_ms: 0 means "use default", so allow it
    if config.retry_delay_ms > 60_000 {
        anyhow::bail!("retry_delay_ms must be 60000 (60 seconds) or less (0 uses default)");
    }

    Ok(())
}

impl Config {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        validate_security_config(&self.security)?;

        // Validate scheduler configurations
        for (sched_name, sched_config) in &self.scheds {
            validate_sched_config(sched_name, sched_config, &self.security)?;
        }

        Ok(())
    }
}

fn validate_sched_config(
    sched_name: &str,
    sched_config: &Sched,
    security: &SecurityConfig,
) -> Result<()> {
    let modes = [
        ("auto_mode", &sched_config.auto_mode),
        ("gaming_mode", &sched_config.gaming_mode),
        ("lowlatency_mode", &sched_config.lowlatency_mode),
        ("powersave_mode", &sched_config.powersave_mode),
        ("server_mode", &sched_config.server_mode),
    ];

    for (mode_name, mode_args) in modes {
        if let Some(args) = mode_args {
            // Check argument count
            if args.len() > security.max_arguments {
                anyhow::bail!(
                    "Scheduler {} {}: too many arguments ({} > {})",
                    sched_name,
                    mode_name,
                    args.len(),
                    security.max_arguments
                );
            }

            // Check argument lengths
            for (idx, arg) in args.iter().enumerate() {
                if arg.len() > security.max_argument_length {
                    anyhow::bail!(
                        "Scheduler {} {} argument {}: too long ({} > {})",
                        sched_name,
                        mode_name,
                        idx,
                        arg.len(),
                        security.max_argument_length
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::*;

    #[test]
    fn test_default_config() {
        let config_str = r#"
default_mode = "Auto"

[scheds.scx_bpfland]
auto_mode = []
gaming_mode = []
lowlatency_mode = ["-m", "performance", "-w"]
powersave_mode = ["-s", "20000", "-m", "powersave", "-I", "100", "-t", "100"]
server_mode = ["-s", "20000", "-S"]

[scheds.scx_rusty]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []
server_mode = []

[scheds.scx_lavd]
auto_mode = []
gaming_mode = ["--performance"]
lowlatency_mode = ["--performance"]
powersave_mode = ["--powersave"]
server_mode = []

[scheds.scx_flash]
auto_mode = []
gaming_mode = ["-m", "all"]
lowlatency_mode = ["-m", "performance", "-w", "-C", "0"]
powersave_mode = ["-m", "powersave", "-I", "10000", "-t", "10000", "-s", "10000", "-S", "1000"]
server_mode = ["-m", "all", "-s", "20000", "-S", "1000", "-I", "-1", "-D", "-L"]

[scheds.scx_p2dq]
auto_mode = []
gaming_mode = ["--task-slice", "true", "-f", "--sched-mode", "performance"]
lowlatency_mode = ["-y", "-f", "--task-slice", "true"]
powersave_mode = ["--sched-mode", "efficiency"]
server_mode = ["--keep-running"]

[scheds.scx_tickless]
auto_mode = []
gaming_mode = ["-f", "5000", "-s", "5000"]
lowlatency_mode = ["-f", "5000", "-s", "1000"]
powersave_mode = ["-f", "50", "-p"]
server_mode = ["-f", "100"]

[scheds.scx_rustland]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []
server_mode = []

[scheds.scx_cosmos]
auto_mode = ["-d"]
gaming_mode = ["-c", "0", "-p", "0"]
lowlatency_mode = ["-m", "performance", "-c", "0", "-p", "0", "-w"]
powersave_mode = ["-m", "powersave", "-d", "-p", "5000"]
server_mode = ["-a", "-s", "20000"]
"#;

        let parsed_config = parse_config_content(config_str).expect("Failed to parse config");
        let expected_config = get_default_config();

        assert_eq!(parsed_config, expected_config);
    }

    #[test]
    fn test_simple_fallback_config_flags() {
        let config_str = r#"
default_mode = "Auto"
"#;

        let parsed_config = parse_config_content(config_str).expect("Failed to parse config");

        let bpfland_flags =
            get_scx_flags_for_mode(&parsed_config, &SupportedSched::Bpfland, SchedMode::Gaming);
        let expected_flags =
            get_default_scx_flags_for_mode(&SupportedSched::Bpfland, SchedMode::Gaming);
        assert_eq!(
            bpfland_flags
                .iter()
                .map(|x| x.as_str())
                .collect::<Vec<&str>>(),
            expected_flags
        );
    }

    #[test]
    fn test_sched_fallback_config_flags() {
        let config_str = r#"
default_mode = "Auto"

[scheds.scx_lavd]
auto_mode = ["--help"]
"#;

        let parsed_config = parse_config_content(config_str).expect("Failed to parse config");

        let lavd_flags =
            get_scx_flags_for_mode(&parsed_config, &SupportedSched::Lavd, SchedMode::Gaming);
        let expected_flags =
            get_default_scx_flags_for_mode(&SupportedSched::Lavd, SchedMode::Gaming);
        assert_eq!(
            lavd_flags.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
            expected_flags
        );

        let lavd_flags =
            get_scx_flags_for_mode(&parsed_config, &SupportedSched::Lavd, SchedMode::Auto);
        assert_eq!(
            lavd_flags.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
            vec!["--help"]
        );
    }

    #[test]
    fn test_empty_config() {
        let config_str = "";
        let result = parse_config_content(config_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_toml_depth_validation_pass() {
        let config_str = r#"
[security]
authorization_mode = "permissive"

[scheds.scx_rusty]
auto_mode = []
"#;
        let result = validate_toml_depth(config_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_toml_depth_validation_fail() {
        // Create a deeply nested structure (>10 levels)
        let config_str = r#"
[a.b.c.d.e.f.g.h.i.j.k]
value = "too deep"
"#;
        let result = validate_toml_depth(config_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nesting depth"));
    }

    #[test]
    fn test_scheduler_arg_count_validation() {
        let mut config = get_default_config();
        config.security.max_arguments = 5;

        // Add a scheduler with too many arguments
        let sched_config = Sched {
            auto_mode: Some(vec![
                "arg1".to_string(),
                "arg2".to_string(),
                "arg3".to_string(),
                "arg4".to_string(),
                "arg5".to_string(),
                "arg6".to_string(), // This exceeds the limit
            ]),
            gaming_mode: None,
            lowlatency_mode: None,
            powersave_mode: None,
            server_mode: None,
        };

        let result = validate_sched_config("test_sched", &sched_config, &config.security);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many arguments"));
    }

    #[test]
    fn test_scheduler_arg_length_validation() {
        let mut config = get_default_config();
        config.security.max_argument_length = 10;

        let sched_config = Sched {
            auto_mode: Some(vec!["this_is_way_too_long_for_the_limit".to_string()]),
            gaming_mode: None,
            lowlatency_mode: None,
            powersave_mode: None,
            server_mode: None,
        };

        let result = validate_sched_config("test_sched", &sched_config, &config.security);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_config_validation_with_valid_scheds() {
        let config = get_default_config();
        assert!(config.validate().is_ok());
    }
}
