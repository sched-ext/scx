// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Validation spec model (parsed from the TOML the agent points the harness at).
//!
//! Mirrors `tools/scx_forge_agent/spec.toml`: `[scheduler]` (what to build and run),
//! `[system]` (host/runtime settings), `[ai]` (model selection), `[tracing]`
//! (optional trace-cmd profiling, event list, and size cap), `[workload]`
//! (the load to apply, the numeric metric to emit, and how many times to repeat
//! the measurement), and `[goal]` (what the number means, which direction is
//! better, and the accept threshold).
//! Defaults match the previous Python harness's `.get(...)` fallbacks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

pub const METRIC_NAME: &str = "score";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub scheduler: Scheduler,
    #[serde(default)]
    pub system: System,
    #[serde(default)]
    pub ai: Ai,
    #[serde(default)]
    pub tracing: Tracing,
    #[serde(default)]
    pub workload: Workload,
    #[serde(default)]
    pub goal: Goal,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scheduler {
    /// Cargo package name of the scheduler crate to build and run.
    pub package: String,
    /// cargo profile: "release" -> target/release, "dev" -> target/debug,
    /// named -> target/<profile>.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Time in seconds to let the scheduler settle after it reports "enabled".
    #[serde(default = "default_warmup_time")]
    pub warmup_time: u64,
    /// Interval (seconds) for the scheduler's own --stats output.
    #[serde(default = "default_stats_interval")]
    pub stats_interval: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    /// Optional file containing the sudo password. Relative paths are resolved
    /// relative to the spec file directory by the optimizer. Empty means unset.
    #[serde(default)]
    pub sudo_passwd_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ai {
    /// Backend for the planner/reasoner role: an OpenAI-compatible API base URL
    /// (built-in `openai` backend), or one of the keywords `claude`, `codex`,
    /// `opencode`, `cursor-agent` (shell out to that agent CLI). Falls back to
    /// `$SCX_FORGE_BACKEND`.
    #[serde(default, alias = "base_url")]
    pub backend: Option<String>,
    /// Planner/reasoner model for the built-in `openai` backend.
    #[serde(default)]
    pub model: Option<String>,
    /// Backend for the patch/apply (coding) role: an OpenAI-compatible API base
    /// URL or one of `claude`, `codex`, `opencode`, `cursor-agent`. Falls back to
    /// `$SCX_FORGE_CODING_BACKEND`, then to the planner `backend`. Set this (with
    /// `coding_model`) to run the coding role on a separate backend.
    #[serde(default, alias = "coding_base_url")]
    pub coding_backend: Option<String>,
    /// Patch/apply model for the built-in `openai` backend. Empty means use
    /// `model`.
    #[serde(default)]
    pub coding_model: Option<String>,
    /// Max tool-calling iterations per LLM turn for the built-in `openai`
    /// backend.
    #[serde(default = "default_max_tool_iterations")]
    pub max_tool_iterations: u32,
    /// Wall-clock cap per planner or coding model turn.
    #[serde(default = "default_max_turn_seconds")]
    pub max_turn_seconds: u64,
    /// Maximum optimization rounds, shared across both phases. The AI-driven
    /// knob-tuning phase ends when the model decides it is done; the remaining
    /// rounds (up to this cap) go to code changes.
    #[serde(default = "default_rounds")]
    pub rounds: u32,
    /// Skip the AI-driven knob-tuning phase and go straight to code changes.
    #[serde(default)]
    pub skip_knobs: bool,
    /// Allow read-only cross-scheduler reference tools (list_schedulers,
    /// grep_schedulers, read_scheduler_file) that inspect other scheduler crates
    /// under scheds/rust. Disabled by default: the model focuses only on the
    /// target crate, which keeps the prompt and tool surface (and thus token
    /// usage) smaller. Enable to let the planner port mechanisms from other
    /// schedulers.
    #[serde(default)]
    pub cross_scheduler_refs: bool,
    /// LLM edit attempts to fix a broken build before reverting the round.
    #[serde(default = "default_build_fix_attempts")]
    pub build_fix_attempts: u32,
    /// LLM edit attempts to fix a runtime scheduler failure before reverting.
    #[serde(default = "default_runtime_fix_attempts")]
    pub runtime_fix_attempts: u32,
}

impl Default for Ai {
    fn default() -> Self {
        Ai {
            backend: None,
            model: None,
            coding_backend: None,
            coding_model: None,
            max_tool_iterations: default_max_tool_iterations(),
            max_turn_seconds: default_max_turn_seconds(),
            rounds: default_rounds(),
            skip_knobs: false,
            cross_scheduler_refs: false,
            build_fix_attempts: default_build_fix_attempts(),
            runtime_fix_attempts: default_runtime_fix_attempts(),
        }
    }
}

impl Ai {
    pub fn turn_timeout(&self) -> Duration {
        Duration::from_secs(self.max_turn_seconds)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tracing {
    /// Enable optional trace-cmd tracing during workloads (only used when
    /// trace-cmd is available). On by default.
    #[serde(default = "default_true")]
    pub enable_tracing: bool,
    /// Trace events passed to `trace-cmd record` with `-e`.
    #[serde(default = "default_trace_events")]
    pub trace_events: Vec<String>,
    /// Cap on the combined `trace.dat` size for a recording. Accepts a plain
    /// byte count or a human-readable size with a binary suffix (`K`, `M`, `G`,
    /// optionally followed by `B`), e.g. `256M`, `1G`. trace-cmd records into a
    /// circular file once the cap is hit, so the recording keeps the most recent
    /// data and the file stays bounded even for long or busy workloads.
    #[serde(default = "default_max_trace_size")]
    pub max_trace_size: String,
}

impl Default for Tracing {
    fn default() -> Self {
        Tracing {
            enable_tracing: true,
            trace_events: default_trace_events(),
            max_trace_size: default_max_trace_size(),
        }
    }
}

impl Tracing {
    /// Parse [`Tracing::max_trace_size`] into a byte count.
    pub fn max_trace_bytes(&self) -> Result<u64> {
        parse_size(&self.max_trace_size)
            .with_context(|| format!("[tracing].max_trace_size = {:?}", self.max_trace_size))
    }
}

/// Parse a size string into bytes: a plain integer, or an integer with a binary
/// suffix `K`/`M`/`G` (case-insensitive, optional trailing `B`). 1 K = 1024.
fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, suffix) = s.split_at(digits_end);
    let value: u64 = num
        .parse()
        .with_context(|| format!("invalid size {s:?}: expected a leading number"))?;
    let suffix = suffix.trim().trim_end_matches(['b', 'B']);
    let mult: u64 = match suffix {
        "" => 1,
        "k" | "K" => 1024,
        "m" | "M" => 1024 * 1024,
        "g" | "G" => 1024 * 1024 * 1024,
        other => anyhow::bail!("invalid size {s:?}: unknown suffix {other:?} (use K, M, or G)"),
    };
    value
        .checked_mul(mult)
        .with_context(|| format!("size {s:?} overflows u64"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    /// Shell command run while the scheduler is attached. Optional: when absent,
    /// the harness just observes for `duration` seconds (load runs externally).
    pub command: Option<String>,
    /// Hard cap in seconds; the workload is killed after this duration.
    #[serde(default = "default_duration")]
    pub duration: u64,
    /// Repeat the measured run N times; result reports median + stddev.
    #[serde(default = "default_runs")]
    pub runs: u64,
}

impl Default for Workload {
    fn default() -> Self {
        Workload {
            command: None,
            duration: default_duration(),
            runs: default_runs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    /// Plain-language statement of the goal (e.g. "minimize tail latency",
    /// "improve throughput"), shown to the model to frame the objective.
    pub prompt: Option<String>,
    /// "minimize" or "maximize". Direction of improvement for the metric.
    #[serde(default = "default_direction")]
    pub direction: String,
    /// Accept a round only if it improves the metric by more than this many
    /// stddevs.
    #[serde(default = "default_accept_threshold_stddev")]
    pub accept_threshold_stddev: f64,
}

impl Default for Goal {
    fn default() -> Self {
        Goal {
            prompt: None,
            direction: default_direction(),
            accept_threshold_stddev: default_accept_threshold_stddev(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_optional_system_sudo_passwd_file() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[system]
sudo_passwd_file = "secrets/sudo-pass"

[goal]
prompt = "minimize the measured value"
direction = "minimize"
"#,
        )
        .unwrap();

        assert_eq!(
            spec.system.sudo_passwd_file.as_deref(),
            Some(Path::new("secrets/sudo-pass"))
        );
    }

    #[test]
    fn parses_workload_fields() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"
warmup_time = 7

[workload]
duration = 42
runs = 3

[goal]
prompt = "minimize tail latency"
direction = "minimize"
"#,
        )
        .unwrap();

        assert_eq!(spec.goal.prompt.as_deref(), Some("minimize tail latency"));
        assert_eq!(spec.goal.direction, "minimize");
        assert_eq!(spec.runs(), 3);
        assert_eq!(spec.scheduler.warmup_time, 7);
        assert_eq!(spec.workload.duration, 42);
    }

    #[test]
    fn parses_ai_models() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[ai]
backend = "https://example.com/v1"
model = "planner"
coding_backend = "https://coder.example.com/v1"
coding_model = "coder"
max_tool_iterations = 7
max_turn_seconds = 123

[goal]
prompt = "minimize tail latency"
direction = "minimize"
"#,
        )
        .unwrap();

        assert_eq!(spec.ai.backend.as_deref(), Some("https://example.com/v1"));
        assert_eq!(spec.ai.model.as_deref(), Some("planner"));
        assert_eq!(
            spec.ai.coding_backend.as_deref(),
            Some("https://coder.example.com/v1")
        );
        assert_eq!(spec.ai.coding_model.as_deref(), Some("coder"));
        assert_eq!(spec.ai.max_tool_iterations, 7);
        assert_eq!(spec.ai.max_turn_seconds, 123);
    }

    #[test]
    fn accepts_legacy_base_url_aliases() {
        // Older specs used base_url / coding_base_url; serde aliases keep them
        // working after the rename to backend / coding_backend.
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[ai]
base_url = "https://example.com/v1"
coding_base_url = "claude"

[goal]
prompt = "minimize tail latency"
direction = "minimize"
"#,
        )
        .unwrap();

        assert_eq!(spec.ai.backend.as_deref(), Some("https://example.com/v1"));
        assert_eq!(spec.ai.coding_backend.as_deref(), Some("claude"));
    }

    #[test]
    fn workload_and_ai_defaults() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"
"#,
        )
        .unwrap();

        assert_eq!(spec.goal.accept_threshold_stddev, 1.0);
        assert_eq!(spec.ai.max_tool_iterations, 20);
        assert_eq!(spec.ai.max_turn_seconds, 300);
        assert_eq!(spec.ai.rounds, 32);
        assert_eq!(spec.ai.build_fix_attempts, 10);
        assert_eq!(spec.ai.runtime_fix_attempts, 5);
    }

    #[test]
    fn tracing_defaults() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"
"#,
        )
        .unwrap();

        assert!(spec.tracing.enable_tracing);
        assert_eq!(
            spec.tracing.trace_events,
            vec![
                "sched:sched_wakeup",
                "sched:sched_wakeup_new",
                "sched:sched_switch",
                "sched:sched_migrate_task",
            ]
        );
        assert_eq!(spec.tracing.max_trace_size, "256M");
        assert_eq!(spec.tracing.max_trace_bytes().unwrap(), 256 * 1024 * 1024);
    }

    #[test]
    fn parses_tracing_section() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[tracing]
enable_tracing = false
trace_events = ["sched:sched_switch", "sched:sched_process_exit"]
max_trace_size = "1G"
"#,
        )
        .unwrap();

        assert!(!spec.tracing.enable_tracing);
        assert_eq!(
            spec.tracing.trace_events,
            vec!["sched:sched_switch", "sched:sched_process_exit"]
        );
        assert_eq!(spec.tracing.max_trace_bytes().unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn validates_tracing_events() {
        let spec: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[tracing]
trace_events = []
"#,
        )
        .unwrap();

        assert!(spec
            .validate()
            .unwrap_err()
            .to_string()
            .contains("[tracing].trace_events must not be empty when tracing is enabled"));

        let disabled: Spec = toml::from_str(
            r#"
[scheduler]
package = "scx_forge"

[tracing]
enable_tracing = false
trace_events = []
"#,
        )
        .unwrap();

        disabled.validate().unwrap();
    }

    #[test]
    fn parse_size_accepts_suffixes_and_rejects_garbage() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("512K").unwrap(), 512 * 1024);
        assert_eq!(parse_size("256M").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("256MB").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("").is_err());
        assert!(parse_size("M").is_err());
        assert!(parse_size("10T").is_err());
    }
}

fn default_profile() -> String {
    "release".to_string()
}
fn default_warmup_time() -> u64 {
    2
}
fn default_stats_interval() -> u64 {
    1
}
fn default_build_fix_attempts() -> u32 {
    10
}
fn default_runtime_fix_attempts() -> u32 {
    5
}
fn default_duration() -> u64 {
    30
}
fn default_direction() -> String {
    "minimize".to_string()
}
fn default_runs() -> u64 {
    1
}
fn default_accept_threshold_stddev() -> f64 {
    1.0
}
fn default_max_tool_iterations() -> u32 {
    20
}
fn default_max_turn_seconds() -> u64 {
    crate::model_timeout::DEFAULT_TURN_TIMEOUT_SECS
}
fn default_rounds() -> u32 {
    32
}
fn default_true() -> bool {
    true
}
fn default_max_trace_size() -> String {
    "256M".to_string()
}
fn default_trace_events() -> Vec<String> {
    [
        "sched:sched_wakeup",
        "sched:sched_wakeup_new",
        "sched:sched_switch",
        "sched:sched_migrate_task",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Spec {
    /// Read and parse a TOML spec file.
    pub fn load(path: &Path) -> Result<Spec> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read spec {}", path.display()))?;
        let spec: Spec =
            toml::from_str(&text).with_context(|| format!("parse spec {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<()> {
        if self.ai.max_turn_seconds == 0 {
            anyhow::bail!("[ai].max_turn_seconds must be greater than 0");
        }
        if self.tracing.enable_tracing && self.tracing.trace_events.is_empty() {
            anyhow::bail!("[tracing].trace_events must not be empty when tracing is enabled");
        }
        if self
            .tracing
            .trace_events
            .iter()
            .any(|event| event.trim().is_empty())
        {
            anyhow::bail!("[tracing].trace_events must not contain empty event names");
        }
        // Validate the trace-size cap up front so a bad value fails the run early
        // rather than mid-recording.
        self.tracing.max_trace_bytes()?;
        Ok(())
    }

    /// Number of measured runs, clamped to at least 1 (matches Python max(1, runs)).
    pub fn runs(&self) -> u64 {
        self.workload.runs.max(1)
    }
}
