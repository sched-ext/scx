// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! scx-forge-agent: an LLM-driven optimizer for sched_ext schedulers.
//!
//! Hybrid loop: deterministic code owns build/validate/keep-revert/stop; the LLM
//! is called only to propose one coherent policy experiment per round (and to fix
//! build errors).
//! The reward function is the built-in validation harness (`validate.rs`). The
//! target scheduler is whatever `[scheduler].package` in the spec names (any
//! `scheds/rust/<name>` crate); the agent modifies that crate in place. See
//! `tools/scx_forge_agent/README.md`.

mod agent_cli;
mod api;
mod color;
mod config;
mod git;
mod http;
mod interrupt;
mod model_timeout;
mod progress;
mod report;
mod spec;
mod sudo;
mod tools;
mod usage;
mod validate;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use progress::ProgressSpinner;
use report::{Report, RoundRecord};

/// The resource markdown files are embedded at compile time so prompt edits stay
/// close to the domain text instead of the Rust control flow.
const SKILL_MD: &str = include_str!("../resources/SKILL.md");
const OPTIMIZER_MD: &str = include_str!("../resources/OPTIMIZER.md");
const KNOB_MD: &str = include_str!("../resources/KNOB.md");

#[derive(Debug)]
struct OptimizeOutcome {
    report: Report,
    interrupted: bool,
}

pub(crate) fn cargo_program() -> OsString {
    std::env::var_os("CARGO")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| OsString::from("cargo"))
}

#[derive(Parser, Debug)]
#[command(
    name = "scx-forge-agent",
    version,
    about = "LLM-driven sched_ext scheduler optimizer"
)]
struct OptimizeArgs {
    /// Path to the scx git repo (defaults to the git toplevel of the cwd).
    #[arg(long)]
    source: Option<PathBuf>,

    /// Override the scheduler crate directory, relative to --source. Defaults to
    /// `scheds/rust/<package>`, derived from the spec's [scheduler].package.
    #[arg(long)]
    crate_dir: Option<String>,

    /// Validation spec TOML (defaults to tools/scx_forge_agent/spec.toml). The
    /// scheduler to optimize (and the cargo profile) come from its [scheduler]
    /// section, so the same spec drives both the build gate and the harness.
    #[arg(long, visible_alias = "spec-toml", value_name = "SPEC_TOML")]
    spec: Option<PathBuf>,

    /// Save this run's compact attempt summary to PATH when the run completes.
    #[arg(long, value_name = "PATH")]
    save: Option<PathBuf>,

    /// Resume from a previously saved attempt-summary state file.
    #[arg(long, value_name = "PATH")]
    resume: Option<PathBuf>,

    /// Print the assembled prompt and planned loop without calling the model or
    /// loading a scheduler.
    #[arg(long)]
    dry_run: bool,

    /// After optimization completes, rebuild and run the final scheduler in the current terminal.
    #[arg(long)]
    keep_running: bool,

    /// Emit the final report as JSON instead of markdown.
    #[arg(long)]
    json: bool,

    /// Dump the full per-round transcript to stderr: prompts sent to the model,
    /// assistant replies, tool calls + results, token usage, and harness steps.
    #[arg(long)]
    verbose: bool,

    /// Disable ANSI color in live progress output.
    #[arg(long)]
    no_color: bool,
}

fn resolve_repo_root(source: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(s) = source {
        return Ok(s.clone());
    }
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("git rev-parse --show-toplevel")?;
    if !out.status.success() {
        anyhow::bail!("not inside a git repo; pass --source");
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

/// Build the scheduler crate. Returns Err(combined output) on failure.
fn cargo_build(
    source: &Path,
    package: &str,
    profile: &str,
    interrupted: &AtomicBool,
) -> std::result::Result<(), String> {
    let cargo = cargo_program();
    let mut command = Command::new(&cargo);
    command
        .args(["build", "--profile", profile, "-p", package])
        .current_dir(source)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn {} build: {e}", cargo.to_string_lossy()))?;
    let pid = child.id() as i32;
    loop {
        if interrupt::requested(interrupted) {
            unsafe {
                libc::kill(-pid, libc::SIGINT);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() >= deadline => {
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
            let out = child
                .wait_with_output()
                .map_err(|e| format!("collect {} build output: {e}", cargo.to_string_lossy()))?;
            let mut s = String::from("cargo build interrupted by Ctrl-C\n");
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            s.push_str(&String::from_utf8_lossy(&out.stdout));
            return Err(s);
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("poll {} build: {e}", cargo.to_string_lossy())),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("collect {} build output: {e}", cargo.to_string_lossy()))?;
    if out.status.success() {
        Ok(())
    } else {
        let mut s = String::from_utf8_lossy(&out.stderr).to_string();
        s.push_str(&String::from_utf8_lossy(&out.stdout));
        Err(s)
    }
}

fn cargo_build_with_progress(
    source: &Path,
    package: &str,
    profile: &str,
    show_progress: bool,
    color: color::Style,
    interrupted: &AtomicBool,
) -> std::result::Result<(), String> {
    let _spinner = show_progress
        .then(|| ProgressSpinner::stdout(format!("re-building scheduler {package}..."), color));
    cargo_build(source, package, profile, interrupted)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

fn expand_glob_path(path: &Path) -> Result<PathBuf> {
    let pattern = path.to_string_lossy();
    if glob::Pattern::escape(&pattern) == pattern {
        return Ok(path.to_path_buf());
    }

    let mut matches = glob::glob(&pattern)
        .with_context(|| format!("parse [system].sudo_passwd_file pattern: {pattern}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("expand [system].sudo_passwd_file pattern: {pattern}"))?;
    matches.sort();

    match matches.len() {
        0 => anyhow::bail!(
            "[system].sudo_passwd_file pattern matched no files: {}",
            path.display()
        ),
        1 => Ok(matches.remove(0)),
        n => anyhow::bail!(
            "[system].sudo_passwd_file pattern is ambiguous ({} matches): {}",
            n,
            path.display()
        ),
    }
}

fn expand_sudo_password_file(spec_path: &Path, pw: &Path) -> Result<PathBuf> {
    let raw = pw.to_string_lossy();
    let expanded = if raw == "~" {
        home_dir().context("expand ~ in [system].sudo_passwd_file: HOME is not set")?
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home_dir()
            .context("expand ~ in [system].sudo_passwd_file: HOME is not set")?
            .join(rest)
    } else {
        let path = PathBuf::from(raw.as_ref());
        if path.is_absolute() {
            path
        } else {
            spec_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        }
    };
    expand_glob_path(&expanded)
}

fn spec_sudo_password_file(spec_path: &Path, spec: &spec::Spec) -> Result<Option<PathBuf>> {
    let Some(pw) = spec.system.sudo_passwd_file.as_ref() else {
        return Ok(None);
    };
    if pw.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(expand_sudo_password_file(spec_path, pw)?))
}

fn configure_sudo_from_spec(spec_path: &Path, spec: &spec::Spec) -> Result<()> {
    let Some(pw) = spec_sudo_password_file(spec_path, spec)? else {
        return Ok(());
    };
    if !pw.is_file() {
        anyhow::bail!("[system].sudo_passwd_file not found: {}", pw.display());
    }
    std::env::set_var("SCX_SUDO_PASSWORD_FILE", &pw);
    Ok(())
}

fn agent_log(color: color::Style, msg: impl AsRef<str>) {
    eprintln!("{} {}", color.dim("[scx-forge-agent]"), msg.as_ref());
}

fn agent_info(color: color::Style, msg: impl AsRef<str>) {
    agent_log(color, color.cyan(msg));
}

fn agent_warn(color: color::Style, msg: impl AsRef<str>) {
    agent_log(color, color.yellow(msg));
}

fn agent_error(color: color::Style, msg: impl AsRef<str>) {
    agent_log(color, color.red(msg));
}

fn agent_success(color: color::Style, msg: impl AsRef<str>) {
    agent_log(color, color.green(msg));
}

fn agent_dim(color: color::Style, msg: impl AsRef<str>) {
    agent_log(color, color.dim(msg));
}

fn model_display_name(model: &config::ModelConfig) -> String {
    if model.model_id.trim().is_empty() {
        format!("{} default", model.backend.as_str())
    } else {
        model.model_id.clone()
    }
}

/// Backend label for the model footer: just the backend name for the subprocess
/// CLIs, and `openai @ <base_url>` for the built-in HTTP backend so the endpoint
/// is visible.
fn model_backend_label(model: &config::ModelConfig) -> String {
    if model.backend == config::Backend::OpenAi && !model.base_url.is_empty() {
        format!("{} @ {}", model.backend.as_str(), model.base_url)
    } else {
        model.backend.as_str().to_string()
    }
}

struct ActiveModelPrinter {
    enabled: bool,
    color: color::Style,
    active: Option<(String, config::Backend, String)>,
}

impl ActiveModelPrinter {
    fn new(enabled: bool, color: color::Style) -> Self {
        Self {
            enabled,
            color,
            active: None,
        }
    }

    fn use_model(&mut self, role: &str, model: &config::ModelConfig) {
        let model_name = model_display_name(model);
        let next = (role.to_string(), model.backend, model_name.clone());
        if !self.enabled || self.active.as_ref() == Some(&next) {
            self.active = Some(next);
            return;
        }

        println!(
            "{}",
            self.color.dim(format!(
                "[scx-forge-agent] using {role} model: {model_name} ({})",
                model_backend_label(model)
            ))
        );
        self.active = Some(next);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_coding_turn(
    client: &reqwest::Client,
    models: &config::ModelRoles,
    coding_system: &str,
    user: &str,
    scheduler_cwd: &Path,
    edit_tl: &api::ToolLoopConfig,
    verbose: bool,
    stream_stdout: bool,
    stderr_color: color::Style,
    active_model: &mut ActiveModelPrinter,
    total_usage: &mut usage::Usage,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<std::result::Result<String, String>> {
    active_model.use_model("coding", &models.coding);
    if models.coding.backend.is_subprocess() {
        let content = agent_cli::run(
            &models.coding,
            agent_cli::Mode::Edit,
            stream_stdout,
            coding_system,
            user,
            scheduler_cwd,
            verbose,
            stderr_color,
            total_usage,
            turn_timeout,
            interrupted,
        )
        .await?;
        return Ok(Ok(content));
    }

    match api::chat(
        client,
        &models.coding,
        coding_system,
        user,
        Some(edit_tl),
        verbose,
        stderr_color,
        stream_stdout,
        total_usage,
        turn_timeout,
        interrupted,
    )
    .await
    {
        Ok(content) => Ok(Ok(content)),
        Err(e) if api::is_api_error(&e) => Ok(Err(api::error_summary(&e))),
        Err(e) => Err(e),
    }
}

fn validation_failure_feedback(verdict: &validate::Verdict) -> String {
    let mut s = format!(
        "Validation failed at stage `{}`. Fix the current candidate before it is reverted.\n",
        verdict.stage
    );
    if verdict.stage == "runtime" {
        s.push_str(
            "The scheduler was not still enabled after the workload, so the candidate likely triggered a sched_ext runtime failure, stall, deadlock, BPF error, or abort and may have measured the default scheduler.\n",
        );
    } else if verdict.stage == "metric" {
        s.push_str(
            "The workload did not produce a parseable numeric metric. Treat this as a runtime failure of the candidate: the scheduler may have broken, stalled, or disrupted the workload before it could emit a valid score.\n",
        );
    }
    if !verdict.errors.is_empty() {
        s.push_str("\nErrors:\n");
        for err in &verdict.errors {
            s.push_str("- ");
            s.push_str(err);
            s.push('\n');
        }
    }
    if let Ok(raw) = serde_json::to_string_pretty(&verdict.raw) {
        s.push_str("\nVerdict JSON:\n");
        s.push_str(&raw);
        s.push('\n');
    }
    s
}

fn should_try_runtime_fix(verdict: &validate::Verdict) -> bool {
    matches!(verdict.stage.as_str(), "runtime" | "metric")
}

fn read_attempt_memory(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read state file {}", path.display()))?;
    let text = text.trim();
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text.to_string()))
    }
}

fn attempt_memory_for_prompt(memory: Option<&str>) -> Option<&str> {
    memory
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| suffix_at_char_boundary(s, 12_000))
}

fn attempt_summary_line(r: &RoundRecord) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} |\n",
        r.round,
        r.outcome.replace('|', "\\|"),
        r.value
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "-".into()),
        r.improvement
            .map(|v| format!("{v:+.3}"))
            .unwrap_or_else(|| "-".into()),
        r.policy_area.replace('|', "\\|"),
        r.direction.replace('|', "\\|"),
        r.summary.replace('|', "\\|").replace('\n', " "),
    )
}

fn run_attempt_summary(
    rep: &Report,
    package: &str,
    crate_dir: &str,
    spec_path: &Path,
    baseline_sha: &str,
) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let mut s = String::new();
    s.push_str(&format!("\n## Run {ts}\n\n"));
    s.push_str(&format!("- Package: `{package}`\n"));
    s.push_str(&format!("- Crate dir: `{crate_dir}`\n"));
    s.push_str(&format!("- Spec: `{}`\n", spec_path.display()));
    s.push_str(&format!("- Baseline: `{baseline_sha}`\n"));
    s.push_str(&format!(
        "- Objective: {} `{}`\n",
        rep.goal, rep.metric_name
    ));
    s.push_str(&format!(
        "- Start: {}\n",
        rep.start_value
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "-".into())
    ));
    s.push_str(&format!(
        "- Best: {}{}\n\n",
        rep.best_value
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "-".into()),
        rep.best_round
            .map(|r| format!(" (round {r})"))
            .unwrap_or_default()
    ));
    s.push_str("| round | outcome | value | improvement | area | direction | change |\n");
    s.push_str("|---:|---|---:|---:|---|---|---|\n");
    for r in &rep.rounds {
        s.push_str(&attempt_summary_line(r));
    }
    s
}

fn append_attempt_summary(
    path: &Path,
    summary: &str,
    color: color::Style,
    json: bool,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create state file dir {}", parent.display()))?;
    }
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open state file {}", path.display()))?;
    if !existed {
        writeln!(
            file,
            "# scx_forge_agent state\n\nThis file is written by scx-forge-agent when `--save` is used and can be loaded into future runs with `--resume` as factual context for future experiments."
        )
        .with_context(|| format!("initialize state file {}", path.display()))?;
    }
    file.write_all(summary.as_bytes())
        .with_context(|| format!("write state file {}", path.display()))?;
    if !json {
        println!(
            "{}",
            color.dim(format!(
                "[scx-forge-agent] saved attempt summary: {}",
                path.display()
            ))
        );
    }
    Ok(())
}

fn install_ctrl_c_handler(
    interrupted: Arc<AtomicBool>,
    color: color::Style,
    json: bool,
    source: PathBuf,
    crate_dir: String,
) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }

        interrupted.store(true, Ordering::SeqCst);
        if !json {
            eprintln!(
                "{}",
                color.yellow(
                    "[scx-forge-agent] Ctrl-C received; interrupting the current operation and printing the partial report. Press Ctrl-C again to exit immediately."
                )
            );
        }

        if tokio::signal::ctrl_c().await.is_ok() {
            if !json {
                eprintln!(
                    "{}",
                    color.red("[scx-forge-agent] second Ctrl-C received; exiting immediately.")
                );
            }
            // Best-effort cleanup before the forced exit: restore the crate to
            // the last accepted (best) state held in the index, dropping the
            // in-progress temporary edit, then unstage so the kept changes are
            // left as plain working-tree modifications - matching the graceful
            // exit path.
            git::discard(&source, &crate_dir).ok();
            git::unstage(&source, &crate_dir).ok();
            std::process::exit(130);
        }
    });
}

fn interrupted_requested(interrupted: &AtomicBool) -> bool {
    interrupt::requested(interrupted)
}

fn build_keep_running_scheduler(
    source: &Path,
    package: &str,
    profile: &str,
    stdout_color: color::Style,
    stderr_color: color::Style,
    json: bool,
    interrupted: &AtomicBool,
) -> Result<()> {
    agent_info(
        stderr_color,
        "preparing final scheduler for --keep-running foreground launch...",
    );
    cargo_build_with_progress(source, package, profile, !json, stdout_color, interrupted).map_err(
        |err| {
            anyhow::anyhow!(
                "final scheduler build failed for --keep-running:\n{}",
                suffix_at_char_boundary(&err, 4000)
            )
        },
    )?;

    Ok(())
}

fn start_keep_running_scheduler(
    source: &Path,
    package: &str,
    profile: &str,
    sudo: &sudo::Sudo,
    stderr_color: color::Style,
) -> Result<()> {
    agent_info(
        stderr_color,
        "starting final scheduler in foreground; press Ctrl-C to stop it",
    );
    std::io::stdout()
        .flush()
        .context("flush stdout before scheduler launch")?;
    std::io::stderr()
        .flush()
        .context("flush stderr before scheduler launch")?;
    validate::exec_scheduler_foreground(source, package, profile, sudo)
}

fn print_final_report(
    rep: &Report,
    interrupted: bool,
    json: bool,
    stdout_color: color::Style,
    crate_dir: &str,
) -> Result<()> {
    if json {
        let mut out = rep.to_json();
        if let Some(obj) = out.as_object_mut() {
            if interrupted {
                obj.insert("interrupted".to_string(), serde_json::Value::Bool(true));
            }
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if interrupted {
        println!(
            "{}\n",
            stdout_color.yellow("Interrupted by Ctrl-C; partial report follows.")
        );
    }

    println!("{}", rep.render_markdown());
    if rep.best_round.is_some() {
        println!(
            "\n{}",
            stdout_color.green(format!(
                "Winning variant applied in place; review with `git diff -- {}`.",
                crate_dir
            ))
        );
    } else {
        println!(
            "\n{}",
            stdout_color.yellow("No improvement found; crate left unchanged.")
        );
    }
    // Token usage for the whole run, at the bottom of the output.
    println!("\n{}", stdout_color.dim(rep.usage.footer_line()));

    Ok(())
}

fn base_system(package: &str, crate_dir: &str, scheduler_refs: bool) -> String {
    let refs_sentence = if scheduler_refs {
        " Read-only tools list_schedulers / grep_schedulers / read_scheduler_file \
         inspect other scheduler crates under `scheds/rust` for reference."
    } else {
        ""
    };
    format!(
        "You are optimizing the sched_ext scheduler `{package}` (the crate at \
         `{crate_dir}`) to improve a benchmark metric. A deterministic harness \
         builds, runs, and measures every change and keeps it only if the metric \
         improves.\n\n\
         File tools (read_file / list_dir / grep / edit_file) are rooted at the \
         crate, so paths are relative to the crate root: `src/bpf/main.bpf.c` for \
         the BPF policy, `src/main.rs` for the control plane.{refs_sentence} All \
         edits stay inside this crate, and the code must build and pass the BPF \
         verifier."
    )
}

fn planner_system_prompt(
    package: &str,
    crate_dir: &str,
    knob_help: Option<&str>,
    scheduler_refs: bool,
) -> String {
    let mut s = format!(
        "{}\n\n{OPTIMIZER_MD}\n\n\
         You are the PLANNER: inspect the crate's code and return one concrete \
         experiment plan. Do not edit files.",
        base_system(package, crate_dir, scheduler_refs)
    );
    if scheduler_refs {
        s.push_str(
            "\n\nThe cross-scheduler reference tools are enabled: you may also \
             explore other scheduler crates under `scheds/rust` \
             (list_schedulers / grep_schedulers / read_scheduler_file) and port a \
             self-consistent mechanism the target lacks, adapting it to this \
             crate's callbacks, maps, and task lifecycle. Cite which scheduler you \
             borrowed the idea from.",
        );
    }
    if let Some(help) = knob_help.map(str::trim).filter(|h| !h.is_empty()) {
        s.push_str(
            "\n\n## Already-implemented options (do NOT re-propose these)\n\
             The scheduler already exposes the command-line options below, and an \
             earlier sweep has tuned them to their best values. They are existing \
             configuration, not new logic: do not propose changing any of them as \
             your experiment - it will not improve the metric further. Infer from \
             this list what has already been tried, and propose a mechanism the \
             scheduler does not implement yet.\n\n```\n",
        );
        s.push_str(help);
        s.push_str("\n```\n");
    }
    s
}

/// Capture the scheduler's `--help` output so the planner can see which CLI
/// options (knobs) already exist. This is the always-current, zero-maintenance
/// source of truth for what the sweep has tuned - no hand-kept signatures.
/// Returns None if the binary is missing or errors.
fn scheduler_help_text(repo_root: &Path, package: &str, profile: &str) -> Option<String> {
    let bin = validate::binary_path(repo_root, package, profile);
    let out = std::process::Command::new(&bin)
        .arg("--help")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Sentinel a knob-phase planner emits when no untested knob value looks
/// promising any more, telling the controller to move on to code changes.
const KNOB_PHASE_DONE_SENTINEL: &str = "KNOB_PHASE_COMPLETE";

/// Two stages of the optimization: tune the scheduler's existing configuration
/// knobs first, then propose new mechanisms. The model drives the transition by
/// emitting the completion sentinel; both phases share the `[ai].rounds` budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Knob,
    Mechanism,
}

/// True if a knob-phase planner reply signals the knob space is exhausted.
fn knob_phase_complete(plan: &str) -> bool {
    plan.lines().any(|l| l.trim() == KNOB_PHASE_DONE_SENTINEL)
}

/// Assemble the scheduler-agnostic knob inventory the knob-phase model tunes
/// from: the binary's `--help` (every option, its default, and - for enums -
/// its possible values, rendered by clap). This needs no per-scheduler
/// hand-maintenance, works for any `scheds/rust/<package>` crate, and can never
/// go stale relative to the options the scheduler actually exposes.
fn knob_inventory(repo_root: &Path, package: &str, profile: &str) -> String {
    let mut s = String::new();
    if let Some(help) = scheduler_help_text(repo_root, package, profile) {
        s.push_str("## Command-line options (from --help)\n```\n");
        s.push_str(&help);
        s.push_str("\n```\n");
    }
    s
}

/// System prompt for the KNOB-TUNING phase: the model picks one existing option
/// per round and changes its default to a single untested value, or signals the
/// phase is done. It never writes new logic here.
fn knob_system_prompt(package: &str, crate_dir: &str, inventory: &str) -> String {
    let mut s = format!(
        "{}\n\n{}",
        base_system(package, crate_dir, false),
        KNOB_MD.trim()
    );
    s.push_str(&format!(
        "\n\n\
         When no untested option value looks promising (the knob space is \
         effectively exhausted), reply with exactly `{KNOB_PHASE_DONE_SENTINEL}` \
         on its own line and nothing else."
    ));
    s.push_str(
        "\n\n\
         Do not edit files; return the plan only.",
    );
    let inv = inventory.trim();
    if !inv.is_empty() {
        s.push_str("\n\n## Available configuration options\n");
        s.push_str(inv);
    }
    s
}

fn coding_system_prompt(package: &str, crate_dir: &str, scheduler_refs: bool) -> String {
    format!(
        "{}\n\n\
         You are the CODER: implement the experiment described in the user \
         message with the `edit_file` tool, keeping the edit focused and \
         preserving sched_ext lifecycle semantics. Follow the BPF safety rules in \
         the reference below; in particular split chained lookups like \
         `lookup_x(...)->field` into a pointer, a NULL check, then the deref.\n\n\
         Every change must alter scheduling behavior in this same edit. If you \
         add a struct field, map, global, or local, make sure it is BOTH read \
         and written by the code within the same change: read-only or write-only \
         state produces no change to scheduler behavior, wastes the round, and is \
         rejected. The value you write must flow into a decision that affects \
         placement, ordering, dispatch, vtime/deadline, slice, or preemption. \
         When done, reply with a one-line summary of the change.\n\n\
         --- BEGIN SKILL.md (sched_ext domain reference) ---\n\n{SKILL_MD}\n\n\
         --- END SKILL.md ---\n",
        base_system(package, crate_dir, scheduler_refs)
    )
}

/// Normalize a `git diff` for dedup: drop the `index <hash>..<hash>` lines whose
/// blob hashes are noise, so two textually identical changes compare equal.
fn normalize_diff(diff: &str) -> String {
    diff.lines()
        .filter(|l| !l.starts_with("index "))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn prefix_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let end = s
        .char_indices()
        .map(|(idx, _)| idx)
        .take_while(|idx| *idx <= max_bytes)
        .last()
        .unwrap_or(0);
    &s[..end]
}

fn suffix_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let target = s.len() - max_bytes;
    let start = s
        .char_indices()
        .map(|(idx, _)| idx)
        .find(|idx| *idx >= target)
        .unwrap_or(s.len());
    &s[start..]
}

fn normalize_attempt_summary(summary: &str) -> Option<String> {
    let normalized = summary
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if normalized.is_empty() || normalized == "no summary" {
        None
    } else {
        Some(normalized)
    }
}

fn planner_plan_rejection_reason(plan: &str) -> Option<&'static str> {
    let trimmed = plan.trim();
    if trimmed.is_empty() {
        return Some("empty planner response");
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("error:")
        || lower.starts_with("failed:")
        || lower.contains("error: unknown tool")
        || lower.contains("unknown tool:")
    {
        return Some("planner returned a tool error instead of a plan");
    }

    None
}

fn planner_recovery_note(reason: &str) -> String {
    format!(
        "The previous planner turn did not produce a usable plan ({reason}). \
         Tool failures and unknown tools are recoverable. Do not stop planning, \
         do not switch to coding, and do not call edit tools. Continue with the \
         advertised read-only tools and the context already gathered, then return \
         the concrete experiment plan now."
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttemptTags {
    policy_area: String,
    direction: String,
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn classify_policy_area(text: &str) -> &'static str {
    if contains_any(
        text,
        &[
            "select_cpu",
            "pick_cpu",
            "prev_cpu",
            "idle cpu",
            "idle_cpu",
            "wakeup cpu",
            "placement",
            "affinity",
            "migrate",
        ],
    ) {
        "placement"
    } else if contains_any(
        text,
        &[
            "vtime",
            "vruntime",
            "deadline",
            "lag",
            "dsq_insert_vtime",
            "virtual time",
        ],
    ) {
        "vtime"
    } else if contains_any(text, &["preempt", "kick", "resched", "yield", "yielding"]) {
        "preemption"
    } else if contains_any(text, &["slice", "quantum", "timeslice"]) {
        "slice"
    } else if contains_any(
        text,
        &[
            "dispatch",
            "consume",
            "move_to_local",
            "pull",
            "steal",
            "drain",
        ],
    ) {
        "dispatch"
    } else if contains_any(
        text,
        &[
            "topology", "domain", "llc", "numa", "node", "cpumask", "cluster",
        ],
    ) {
        "topology"
    } else if contains_any(
        text,
        &[
            "load balance",
            "load_balance",
            "queue depth",
            "nr_queued",
            "nr_running",
            "runnable",
        ],
    ) {
        "load_balance"
    } else if contains_any(
        text,
        &[
            "classify",
            "interactive",
            "latency",
            "batch",
            "weight",
            "per-task",
            "per task",
            "per-cpu",
            "per cpu",
        ],
    ) {
        "classification"
    } else {
        "unknown"
    }
}

fn direction_stopword(word: &str) -> bool {
    matches!(
        word,
        "a" | "an"
            | "and"
            | "as"
            | "by"
            | "for"
            | "from"
            | "in"
            | "into"
            | "of"
            | "on"
            | "or"
            | "the"
            | "to"
            | "with"
            | "changed"
            | "change"
            | "modified"
            | "modify"
            | "added"
            | "add"
            | "updated"
            | "update"
            | "use"
            | "uses"
            | "using"
            | "should"
            | "metric"
            | "score"
    )
}

fn classify_attempt(summary: &str, diff: &str) -> AttemptTags {
    let combined = format!("{summary}\n{diff}").to_ascii_lowercase();
    let area = classify_policy_area(&combined).to_string();
    let direction_src = if summary.trim().is_empty() {
        diff.lines().take(40).collect::<Vec<_>>().join(" ")
    } else {
        summary.to_string()
    };
    let mut words = normalize_attempt_summary(&direction_src)
        .unwrap_or_else(|| area.clone())
        .split_whitespace()
        .filter(|w| !direction_stopword(w))
        .take(8)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if words.is_empty() {
        words.push(area.clone());
    }
    AttemptTags {
        policy_area: area,
        direction: words.join("_"),
    }
}

fn normalized_improvement(goal: &str, delta: f64) -> f64 {
    if goal == "minimize" {
        -delta
    } else {
        delta
    }
}

#[allow(clippy::too_many_arguments)]
fn round_record(
    round: u32,
    summary: String,
    outcome: &str,
    value: Option<f64>,
    delta: Option<f64>,
    kept: bool,
    goal: &str,
    diff: &str,
) -> RoundRecord {
    let tags = classify_attempt(&summary, diff);
    RoundRecord {
        round,
        summary,
        outcome: outcome.to_string(),
        value,
        delta,
        improvement: delta.map(|d| normalized_improvement(goal, d)),
        policy_area: tags.policy_area,
        direction: tags.direction,
        kept,
    }
}

fn record_interrupted_round(
    rep: &mut Report,
    source: &Path,
    crate_dir: &str,
    round: u32,
    summary: String,
    goal: &str,
) {
    let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
    git::discard(source, crate_dir).ok();
    rep.rounds.push(round_record(
        round,
        summary,
        "interrupted",
        None,
        None,
        false,
        goal,
        &attempt_diff,
    ));
}

fn record_model_timeout_round(
    rep: &mut Report,
    source: &Path,
    crate_dir: &str,
    round: u32,
    summary: String,
    goal: &str,
    made_edit: bool,
) {
    let attempt_diff = if made_edit {
        git::worktree_diff(source, crate_dir).unwrap_or_default()
    } else {
        String::new()
    };
    git::discard(source, crate_dir).ok();
    rep.rounds.push(round_record(
        round,
        summary,
        "model-timeout",
        None,
        None,
        false,
        goal,
        &attempt_diff,
    ));
}

fn diff_file_path(line: &str) -> Option<String> {
    if !line.starts_with("diff --git ") {
        return None;
    }
    let path = line.split_whitespace().nth(3)?;
    Some(path.strip_prefix("b/").unwrap_or(path).to_string())
}

fn bpf_const_volatile_initializer_name(diff_line: &str) -> Option<String> {
    if !(diff_line.starts_with('+') || diff_line.starts_with('-'))
        || diff_line.starts_with("+++")
        || diff_line.starts_with("---")
    {
        return None;
    }
    let code = diff_line.get(1..)?.trim();
    if !code.starts_with("const volatile ") || !code.ends_with(';') {
        return None;
    }
    let lhs = code.split_once('=')?.0.trim();
    let name = lhs.split_whitespace().last()?;
    Some(
        name.split_once('[')
            .map_or(name, |(base, _)| base)
            .to_string(),
    )
}

fn bpf_const_volatile_initializer_only_vars(diff: &str) -> Option<Vec<String>> {
    let mut current_file = None;
    let mut vars = BTreeSet::new();

    for line in diff.lines() {
        if let Some(path) = diff_file_path(line) {
            current_file = Some(path);
            continue;
        }
        if !(line.starts_with('+') || line.starts_with('-'))
            || line.starts_with("+++")
            || line.starts_with("---")
        {
            continue;
        }
        let file = current_file.as_deref()?;
        if !file.ends_with(".bpf.c") {
            return None;
        }
        let name = bpf_const_volatile_initializer_name(line)?;
        vars.insert(name);
    }

    if vars.is_empty() {
        None
    } else {
        Some(vars.into_iter().collect())
    }
}

fn ineffective_round_edit_reason(diff: &str) -> Option<String> {
    let vars = bpf_const_volatile_initializer_only_vars(diff)?;
    Some(format!(
        "only changed BPF const volatile initializer(s): {}. Rust rodata assignments usually overwrite these defaults before load.",
        vars.join(", ")
    ))
}

fn ineffective_round_note(reason: &str) -> String {
    format!(
        "Your last edit was rejected before validation because it {reason} If tuning one of these knobs, update the Rust-side default / CLI plumbing / rodata_data assignment in src/main.rs in the same edit. Otherwise choose a runtime scheduling policy change such as task placement, queue ordering, DSQ selection/topology, dispatch pulling, deadline/vtime calculation, or preemption/kick behavior."
    )
}

fn history_table(rounds: &[RoundRecord]) -> String {
    if rounds.is_empty() {
        return "(no rounds yet)".to_string();
    }
    let mut s =
        String::from("round | outcome | value | improvement | area | direction | kept | change\n");
    for r in rounds {
        s.push_str(&format!(
            "{} | {} | {} | {} | {} | {} | {} | {}\n",
            r.round,
            r.outcome,
            r.value
                .map(|v| format!("{v:.3}"))
                .unwrap_or_else(|| "-".into()),
            r.improvement
                .map(|v| format!("{v:+.3}"))
                .unwrap_or_else(|| "-".into()),
            r.policy_area,
            r.direction,
            r.kept,
            r.summary,
        ));
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn round_context_prompt(
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: Option<f64>,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    crate_diff: &str,
    build_errors: Option<&str>,
    note: Option<&str>,
) -> String {
    let mut s = String::new();
    if let Some(d) = goal_description {
        s.push_str(&format!("Goal: {d}\n"));
    }
    s.push_str(&format!("Concretely, {goal} the metric `{metric_name}`.\n"));
    if let Some(b) = best_value {
        s.push_str(&format!("Best `{metric_name}` so far (accepted): {b:.3}\n"));
    }
    s.push_str(
        "Only changes that improve the metric this round are kept; non-improving \
         rounds are reverted. Make one self-contained change that affects \
         scheduling behavior immediately.\n",
    );
    if let Some(memory) = attempt_memory_for_prompt(attempt_memory) {
        s.push_str("\n## Previous run attempt memory\n");
        s.push_str(memory);
        s.push('\n');
    }
    s.push_str("\n## Optimization history\n");
    s.push_str(&history_table(history));

    s.push_str("\n## Last benchmark result (JSON)\n");
    s.push_str(prefix_at_char_boundary(last_verdict_json, 4000));
    s.push('\n');

    s.push_str("\n## Currently applied changes (diff vs baseline)\n");
    if crate_diff.trim().is_empty() {
        s.push_str("(none yet - the scheduler is at its baseline)\n");
    } else {
        s.push_str("```diff\n");
        s.push_str(prefix_at_char_boundary(crate_diff, 6000));
        s.push_str("\n```\n");
    }

    if let Some(err) = build_errors {
        s.push_str("\n## The previous build or validation FAILED. Fix it with one edit.\n```\n");
        s.push_str(suffix_at_char_boundary(err, 4000));
        s.push_str("\n```\n");
    }

    if let Some(n) = note {
        s.push_str(&format!("\n## Note\n{n}\n"));
    }

    s
}

#[allow(clippy::too_many_arguments)]
fn planner_prompt(
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: Option<f64>,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    crate_diff: &str,
    build_errors: Option<&str>,
    note: Option<&str>,
) -> String {
    let mut s = round_context_prompt(
        metric_name,
        goal,
        goal_description,
        best_value,
        history,
        attempt_memory,
        last_verdict_json,
        crate_diff,
        build_errors,
        note,
    );

    s.push_str(
        "\nReturn the experiment plan now (do not edit files). Make it specific \
         enough for the coding model to implement verbatim, and include a one-line \
         summary, the source scheduler you borrowed from, the files/functions to \
         change, the exact mechanism, and the expected effect on the metric. If a \
         tool errors or is missing, keep going and still return the plan.\n",
    );

    s
}

/// The coder is handed exactly the planner's plan - nothing else. Build-fix and
/// runtime-fix rounds have no plan, so they fall back to the round context plus
/// the failure to repair.
#[allow(clippy::too_many_arguments)]
fn edit_prompt(
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: Option<f64>,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    crate_diff: &str,
    build_errors: Option<&str>,
    note: Option<&str>,
    plan: Option<&str>,
) -> String {
    match plan.filter(|p| !p.trim().is_empty()) {
        // Normal round: the user message is the plan itself, nothing more.
        Some(plan) => format!(
            "Implement this experiment with the edit_file tool, then reply with a \
             one-line summary of the change.\n\n{}",
            prefix_at_char_boundary(plan, 6000).trim()
        ),
        // Fix round: give the coder the round context and the failure to repair.
        None => {
            let mut s = round_context_prompt(
                metric_name,
                goal,
                goal_description,
                best_value,
                history,
                attempt_memory,
                last_verdict_json,
                crate_diff,
                build_errors,
                note,
            );
            s.push_str(
                "\nMake the edit you believe will improve the metric now (or fix \
                 the failure above), then reply with a one-line summary of the change.\n",
            );
            s
        }
    }
}

/// Knob-phase planner prompt: the round context plus an instruction to pick one
/// option to retune (or end the phase). The available options live in the
/// knob-phase system prompt, not here.
#[allow(clippy::too_many_arguments)]
fn knob_planner_prompt(
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: Option<f64>,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    crate_diff: &str,
    note: Option<&str>,
) -> String {
    let mut s = round_context_prompt(
        metric_name,
        goal,
        goal_description,
        best_value,
        history,
        attempt_memory,
        last_verdict_json,
        crate_diff,
        None,
        note,
    );
    s.push_str(&format!(
        "\nPick the single most promising UNTESTED option value and return the \
         plan now (do not edit files): name the option, the exact new default \
         value, and the one-line `default_value`/`default_value_t` edit in \
         `src/main.rs` the coder should make. If every option value worth trying \
         has already been tested, reply with exactly `{KNOB_PHASE_DONE_SENTINEL}` \
         and nothing else.\n"
    ));
    s
}

/// Knob-phase coder prompt. With a planner plan (openai backend) it just asks
/// the coder to apply that one-line default change. Without a plan (subprocess
/// backends, which have no separate planner) it carries the round context plus
/// the knob inventory so the coder can pick and apply a knob itself.
#[allow(clippy::too_many_arguments)]
fn knob_edit_prompt(
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: Option<f64>,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    crate_diff: &str,
    note: Option<&str>,
    plan: Option<&str>,
    inventory: &str,
) -> String {
    const GUARDRAIL: &str = "Add or edit only the option's clap default in the \
        `Opts` struct in `src/main.rs` (the `default_value_t`/`default_value` \
        attribute). Do NOT touch the `to_bpf()` match arms or any BPF code.";
    match plan.filter(|p| !p.trim().is_empty()) {
        Some(plan) => format!(
            "Apply this knob change with the edit_file tool, then reply with a \
             one-line summary. {GUARDRAIL}\n\n{}",
            prefix_at_char_boundary(plan, 6000).trim()
        ),
        None => {
            let mut s = round_context_prompt(
                metric_name,
                goal,
                goal_description,
                best_value,
                history,
                attempt_memory,
                last_verdict_json,
                crate_diff,
                None,
                note,
            );
            let inv = inventory.trim();
            if !inv.is_empty() {
                s.push_str("\n## Available configuration options\n");
                s.push_str(inv);
                s.push('\n');
            }
            s.push_str(&format!(
                "\nRetune ONE existing option to a single untested value you \
                 expect will improve the metric, then reply with a one-line \
                 summary. {GUARDRAIL}\n"
            ));
            s
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_with_fix_loop(
    args: &OptimizeArgs,
    build_fix_attempts: u32,
    source: &Path,
    package: &str,
    profile: &str,
    crate_dir: &str,
    baseline_sha: &str,
    metric_name: &str,
    goal: &str,
    goal_description: Option<&str>,
    best_value: f64,
    history: &[RoundRecord],
    attempt_memory: Option<&str>,
    last_verdict_json: &str,
    client: &reqwest::Client,
    models: &config::ModelRoles,
    coding_system: &str,
    scheduler_cwd: &Path,
    edit_tl: &api::ToolLoopConfig,
    stdout_color: color::Style,
    stderr_color: color::Style,
    active_model: &mut ActiveModelPrinter,
    total_usage: &mut usage::Usage,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<Option<String>> {
    let mut build_err = cargo_build_with_progress(
        source,
        package,
        profile,
        !args.json,
        stdout_color,
        &interrupted,
    )
    .err();
    let mut fix = 0;
    if interrupted_requested(&interrupted) {
        return Ok(build_err.or_else(|| Some("interrupted by Ctrl-C".to_string())));
    }
    while build_err.is_some() && fix < build_fix_attempts && !interrupted_requested(&interrupted) {
        fix += 1;
        agent_warn(
            stderr_color,
            format!("build failed; fix attempt {fix}/{}", build_fix_attempts),
        );
        let diff_now = git::diff(source, baseline_sha, crate_dir).unwrap_or_default();
        let up = edit_prompt(
            metric_name,
            goal,
            goal_description,
            Some(best_value),
            history,
            attempt_memory,
            last_verdict_json,
            &diff_now,
            build_err.as_deref(),
            None,
            None,
        );
        let before_fix = normalize_diff(&diff_now);
        let fix_turn = run_coding_turn(
            client,
            models,
            coding_system,
            &up,
            scheduler_cwd,
            edit_tl,
            args.verbose,
            !args.json,
            stderr_color,
            active_model,
            total_usage,
            turn_timeout,
            interrupted.clone(),
        )
        .await;
        let fix_attempted = match fix_turn {
            Err(e) if interrupt::is(&e) => {
                return Ok(Some("interrupted by Ctrl-C".to_string()));
            }
            Err(e) => return Err(e),
            Ok(Ok(_)) => true,
            Ok(Err(msg)) => {
                let after_fix =
                    normalize_diff(&git::diff(source, baseline_sha, crate_dir).unwrap_or_default());
                if after_fix != before_fix {
                    agent_warn(
                        stderr_color,
                        format!("API error after build-fix edit; retrying build: {msg}"),
                    );
                    true
                } else {
                    agent_error(
                        stderr_color,
                        format!("API error during build-fix attempt; reverting round: {msg}"),
                    );
                    false
                }
            }
        };
        if !fix_attempted {
            break;
        }
        build_err = cargo_build_with_progress(
            source,
            package,
            profile,
            !args.json,
            stdout_color,
            &interrupted,
        )
        .err();
    }
    Ok(build_err)
}

#[tokio::main]
async fn main() -> Result<()> {
    optimize(OptimizeArgs::parse()).await
}

async fn optimize(args: OptimizeArgs) -> Result<()> {
    let stderr_color = color::Style::stderr(args.no_color);
    let stdout_color = color::Style::stdout(args.no_color);
    let source = resolve_repo_root(&args.source)?;

    // The validation harness is built into this binary; the spec it reads lives
    // with the agent and is the single source of truth for which scheduler to
    // optimize. Resolve and parse it first so the package/profile/crate_dir below
    // match exactly what the harness will build and run.
    let default_spec = source.join("tools/scx_forge_agent/spec.toml");
    let spec_path = args.spec.clone().unwrap_or_else(|| default_spec.clone());
    if !spec_path.is_file() {
        anyhow::bail!(
            "spec not found: {}\nThe default spec is {}; pass --spec or create it.",
            spec_path.display(),
            default_spec.display(),
        );
    }
    let spec = spec::Spec::load(&spec_path)
        .with_context(|| format!("load spec {}", spec_path.display()))?;
    let package = spec.scheduler.package.clone();
    if package.trim().is_empty() {
        anyhow::bail!("spec [scheduler].package is empty; set a crate name, e.g. scx_cosmos");
    }
    let profile = spec.scheduler.profile.clone();
    let accept_threshold_stddev = spec.goal.accept_threshold_stddev;
    // Derive the crate dir from the package by convention (scheds/rust/<package>);
    // --crate-dir overrides only the on-disk location, never which package is built.
    let crate_dir = args
        .crate_dir
        .clone()
        .unwrap_or_else(|| format!("scheds/rust/{package}"));
    let crate_dir_abs = source.join(&crate_dir);
    if !crate_dir_abs.is_dir() {
        anyhow::bail!("crate dir not found: {}", crate_dir_abs.display());
    }
    // Cross-scheduler reference tools are opt-in ([ai].cross_scheduler_refs). When
    // disabled, scheds_root stays None so the tools are neither advertised nor
    // dispatchable, and the prompts omit any mention of other schedulers.
    let scheds_root = if spec.ai.cross_scheduler_refs {
        let scheds_root = source.join("scheds/rust");
        scheds_root.is_dir().then_some(scheds_root)
    } else {
        None
    };
    // Each role's backend is selected by its `backend` value in the spec
    // ([ai].backend / [ai].coding_backend): a URL -> openai, or one of the
    // keywords claude/codex/opencode/cursor-agent -> that subprocess CLI.
    let models = config::resolve_roles_from_env(
        spec.ai.backend.as_deref(),
        spec.ai.model.as_deref(),
        spec.ai.coding_backend.as_deref(),
        spec.ai.coding_model.as_deref(),
    )?;
    let attempt_memory = match args.resume.as_deref() {
        Some(path) => read_attempt_memory(path)?,
        None => None,
    };

    let planner_system = planner_system_prompt(
        &package,
        &crate_dir,
        scheduler_help_text(&source, &package, &profile).as_deref(),
        scheds_root.is_some(),
    );
    let coding_system = coding_system_prompt(&package, &crate_dir, scheds_root.is_some());

    // --- dry-run: show the assembled context and plan, touch nothing. ---
    if args.dry_run {
        let sample_plan_user = planner_prompt(
            "<metric>",
            "<goal>",
            Some("<plain-language goal from spec [goal].prompt>"),
            None,
            &[],
            attempt_memory.as_deref(),
            "{ (a baseline run would appear here) }",
            "",
            None,
            None,
        );
        let sample_edit_user = edit_prompt(
            "<metric>",
            "<goal>",
            Some("<plain-language goal from spec [goal].prompt>"),
            None,
            &[],
            attempt_memory.as_deref(),
            "{ (a baseline run would appear here) }",
            "",
            None,
            None,
            Some("<planner output would appear here>"),
        );
        println!("=== resolved paths ===");
        println!("source        : {}", source.display());
        println!("package       : {package}");
        println!("crate_dir     : {}", crate_dir_abs.display());
        println!(
            "scheds_root   : {}",
            scheds_root
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(cross-scheduler refs disabled)".to_string())
        );
        println!("profile       : {profile}");
        println!(
            "planner       : {} ({})",
            model_display_name(&models.planner),
            model_backend_label(&models.planner)
        );
        println!(
            "coding        : {} ({})",
            model_display_name(&models.coding),
            model_backend_label(&models.coding)
        );
        println!("cargo         : {}", cargo_program().to_string_lossy());
        println!("spec          : {}", spec_path.display());
        println!(
            "tracing       : {}",
            if spec.tracing.enable_tracing {
                "enabled when trace-cmd is available"
            } else {
                "disabled"
            }
        );
        println!(
            "resume file   : {}",
            args.resume
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(disabled)".to_string())
        );
        println!(
            "save file     : {}",
            args.save
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(disabled)".to_string())
        );
        println!(
            "keep-running  : {}",
            if args.keep_running {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "attempt memory: {}",
            attempt_memory
                .as_ref()
                .map(|s| format!("{} bytes loaded", s.len()))
                .unwrap_or_else(|| "(none loaded)".to_string())
        );
        println!(
            "sudo pass file: {}",
            spec_sudo_password_file(&spec_path, &spec)
                .map(|p| {
                    p.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(not configured)".to_string())
                })
                .unwrap_or_else(|e| format!("ERROR: {e:#}"))
        );
        println!("rounds        : {}", spec.ai.rounds);
        println!(
            "\n=== planner system prompt ({} chars) ===",
            planner_system.len()
        );
        println!("{planner_system}");
        println!(
            "\n=== coding system prompt ({} chars) ===",
            coding_system.len()
        );
        println!("{coding_system}");
        println!("\n=== example planner user prompt ===\n{sample_plan_user}");
        println!("\n=== example coding user prompt ===\n{sample_edit_user}");
        let refs_tools = if scheds_root.is_some() {
            "; read-only scheduler-reference tools: list_schedulers/grep_schedulers/read_scheduler_file"
        } else {
            ""
        };
        let keep_running_step = if args.keep_running {
            "\n  6. restore the final accepted source, rebuild it, print the report, then exec the scheduler in the foreground"
        } else {
            ""
        };
        println!(
            "\n=== planned loop ===\n\
             round 0: validate baseline (current crate) -> seed best value & objective\n\
             each round 1..={}:\n  1. planner/reasoner chooses ONE experiment with read-only tools (openai backend, including host topology tools lscpu_e/numactl_hardware/cpu_cache_sizes)\n  \
             2. coding model applies the edit (target tools: rg when available/grep/read_file/list_dir/edit_file{refs_tools}; host topology tools: lscpu_e/numactl_hardware/cpu_cache_sizes)\n  \
             3. {} build --profile {} -p {} (fix loop up to {} attempts)\n  \
             4. built-in harness builds+runs spec {} -> verdict (runtime-fix loop up to {} attempts)\n  \
             5. keep iff improves by > {} * stddev (stage edit in place), else revert (restore from last accepted){keep_running_step}\n\
             The crate is edited in place on the current branch (no branch, no commits); the\n\
             winning variant is left as uncommitted working-tree changes.\n",
            spec.ai.rounds,
            cargo_program().to_string_lossy(),
            profile,
            package,
            spec.ai.build_fix_attempts,
            spec_path.display(),
            spec.ai.runtime_fix_attempts,
            accept_threshold_stddev,
        );
        return Ok(());
    }

    // The harness loads the scheduler as root. If the scheduler spec provides a
    // sudo password file, export it so the harness (and its teardown pkills)
    // can authenticate without requiring passwordless sudo.
    configure_sudo_from_spec(&spec_path, &spec)?;
    let sudo = sudo::Sudo::resolve()?;

    let client = http::build_http_client()?;
    let interrupted = Arc::new(AtomicBool::new(false));

    // --- git setup: require a clean crate dir, record the baseline. ---
    // We edit the crate in place on the current branch (no branch, no commits)
    // and use the index as the keep/revert checkpoint.
    git::ensure_clean(&source, &crate_dir)?;
    let baseline_sha = git::rev_parse(&source, "HEAD")?;

    // Install the handler after the clean check so that even an immediate
    // (double Ctrl-C) exit restores the crate to the last accepted state and
    // unstages it, keeping the optimal changes and dropping the temporary one.
    install_ctrl_c_handler(
        interrupted.clone(),
        stderr_color,
        args.json,
        source.clone(),
        crate_dir.clone(),
    );

    agent_info(
        stderr_color,
        format!(
            "editing {} in place (baseline {})",
            crate_dir,
            &baseline_sha[..baseline_sha.len().min(12)]
        ),
    );

    let run = optimize_loop(
        &args,
        &source,
        &spec_path,
        &spec,
        &package,
        &profile,
        &crate_dir,
        &sudo,
        &client,
        &models,
        &baseline_sha,
        scheds_root.as_deref(),
        attempt_memory.as_deref(),
        interrupted.clone(),
    );
    let result = run.await;

    match result {
        Ok(outcome) => {
            let OptimizeOutcome {
                report: rep,
                interrupted: was_interrupted,
            } = outcome;
            // Leave the winning variant as uncommitted working-tree changes; if
            // nothing was kept, the crate is already back at its baseline. Either
            // way, unstage so the result is plain modifications.
            git::discard(&source, &crate_dir).ok();
            git::unstage(&source, &crate_dir).ok();
            if let Some(save_path) = args.save.as_deref() {
                let attempt_summary =
                    run_attempt_summary(&rep, &package, &crate_dir, &spec_path, &baseline_sha);
                append_attempt_summary(save_path, &attempt_summary, stdout_color, args.json)?;
            }
            let start_keep_running = args.keep_running && !was_interrupted;
            if args.keep_running && was_interrupted {
                agent_warn(
                    stderr_color,
                    "--keep-running skipped because the optimization run was interrupted",
                );
            }
            if start_keep_running {
                build_keep_running_scheduler(
                    &source,
                    &package,
                    &profile,
                    stdout_color,
                    stderr_color,
                    args.json,
                    &interrupted,
                )?;
            }
            print_final_report(&rep, was_interrupted, args.json, stdout_color, &crate_dir)?;
            if start_keep_running {
                start_keep_running_scheduler(&source, &package, &profile, &sudo, stderr_color)?;
            }
            Ok(())
        }
        Err(e) => {
            // Restore the crate to the last accepted state (or baseline) and
            // unstage, so a failed run does not leave a half-applied edit behind.
            git::discard(&source, &crate_dir).ok();
            git::unstage(&source, &crate_dir).ok();
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn optimize_loop(
    args: &OptimizeArgs,
    source: &Path,
    spec_path: &Path,
    spec: &spec::Spec,
    package: &str,
    profile: &str,
    crate_dir: &str,
    sudo: &sudo::Sudo,
    client: &reqwest::Client,
    models: &config::ModelRoles,
    baseline_sha: &str,
    scheds_root: Option<&Path>,
    attempt_memory: Option<&str>,
    interrupted: Arc<AtomicBool>,
) -> Result<OptimizeOutcome> {
    let stderr_color = color::Style::stderr(args.no_color);
    let stdout_color = color::Style::stdout(args.no_color);
    let coding_system = coding_system_prompt(package, crate_dir, scheds_root.is_some());
    let model_turn_timeout = spec.ai.turn_timeout();

    // Round 0: baseline measurement of the current (unmodified) crate.
    agent_info(stderr_color, "round 0: measuring baseline...");
    let base = validate::run_validation(
        source,
        spec_path,
        sudo,
        args.verbose,
        (!args.json).then_some(stdout_color),
        spec.tracing.enable_tracing,
        &interrupted,
    )?;
    if interrupted_requested(&interrupted) {
        return Ok(OptimizeOutcome {
            report: Report {
                objective: format!("{} {}", base.goal, base.metric_name),
                goal: base.goal,
                metric_name: base.metric_name,
                start_value: None,
                best_value: None,
                best_round: None,
                rounds: Vec::new(),
                usage: usage::Usage::default(),
            },
            interrupted: true,
        });
    }
    if !base.is_complete() {
        anyhow::bail!(
            "baseline does not build/attach/measure (stage={}); fix the scheduler before optimizing.\nerrors: {:?}",
            base.stage, base.errors
        );
    }
    // The baseline build produced the binary, so capture its --help now: both
    // phases use it. The mechanism phase shows it as "already-implemented
    // options" to avoid re-proposing knobs; the knob phase tunes the options it
    // lists. --help is the single source of truth for the levers (auto-current,
    // no hand-maintained registry to drift).
    let help_text = scheduler_help_text(source, package, profile);
    let accept_threshold_stddev = spec.goal.accept_threshold_stddev;
    let planner_system = planner_system_prompt(
        package,
        crate_dir,
        help_text.as_deref(),
        scheds_root.is_some(),
    );
    let knob_inventory = knob_inventory(source, package, profile);
    let knob_system = knob_system_prompt(package, crate_dir, &knob_inventory);
    let metric_name = base.metric_name.clone();
    let goal = base.goal.clone();
    // Plain-language goal from the spec's [goal].prompt, shown to the model.
    let goal_description = spec.goal.prompt.clone();
    let mut best_value = base.median.or(base.value).unwrap();
    let start_value = best_value;

    let mut rep = Report {
        objective: format!("{goal} {metric_name}"),
        goal: goal.clone(),
        metric_name: metric_name.clone(),
        start_value: Some(start_value),
        best_value: Some(best_value),
        best_round: None,
        rounds: Vec::new(),
        usage: usage::Usage::default(),
    };
    let mut last_verdict_json = serde_json::to_string(&base.raw).unwrap_or_default();
    agent_success(
        stderr_color,
        format!("baseline {metric_name} = {best_value:.3} (goal: {goal})"),
    );

    // Token usage summed across every model call (round 0 makes none).
    let mut total_usage = usage::Usage::default();
    let mut active_model = ActiveModelPrinter::new(!args.json, stdout_color);

    let mut run_interrupted = interrupted_requested(&interrupted);
    if run_interrupted {
        rep.usage = total_usage;
        return Ok(OptimizeOutcome {
            report: rep,
            interrupted: true,
        });
    }

    // Optimization phase. The run starts in the AI-driven knob-tuning phase
    // (unless [ai].skip_knobs), where the model retunes one existing option per
    // round; it switches to the free-form code-change phase once the model emits
    // the completion sentinel. Both phases share the [ai].rounds budget, so the
    // run always ends at [ai].rounds even if the model never leaves the knob phase.
    let mut phase = if spec.ai.skip_knobs {
        Phase::Mechanism
    } else {
        Phase::Knob
    };

    for round in 1..=spec.ai.rounds {
        if interrupted_requested(&interrupted) {
            run_interrupted = true;
            break;
        }

        agent_info(stderr_color, format!("round {round}/{}", spec.ai.rounds));
        let crate_diff = git::diff(source, baseline_sha, crate_dir).unwrap_or_default();

        // 1. Produce this round's edit(s) via the configured backend. Re-prompt
        // if the result reproduces a change we already tried, so a model that
        // keeps re-deriving the same edit is pushed elsewhere instead of wasting
        // validation runs. "Made an edit" is detected by the working tree
        // changing vs the accepted baseline - uniform across backends.
        let scheduler_cwd = source.join(crate_dir);
        let planning_tl = api::tool_loop(
            &scheduler_cwd,
            scheds_root.as_deref(),
            false,
            spec.ai.max_tool_iterations,
        );
        let edit_tl = api::tool_loop(
            &scheduler_cwd,
            scheds_root.as_deref(),
            true,
            spec.ai.max_tool_iterations,
        );
        let accepted_norm = normalize_diff(&crate_diff);
        let derive_summary = |content: &str| -> String {
            if content.trim().is_empty() {
                "(no summary)".to_string()
            } else {
                content.lines().next().unwrap_or("").trim().to_string()
            }
        };
        let mut note: Option<String> = None;
        let summary;
        let mut made_edit;
        let mut ineffective_tries = 0u32;
        let mut api_tries = 0u32;
        let mut planner_retries = 0u32;
        let mut api_error: Option<String> = None;
        let mut model_timeout_err: Option<String> = None;
        let mut ineffective_edit: Option<String> = None;

        if phase == Phase::Knob {
            agent_info(stderr_color, format!("round {round}: knob-tuning phase"));
        }

        loop {
            // The planner produces a read-only plan for the coder. Skip it only
            // when a subprocess planner IS the coder (same backend + model):
            // there it plans and edits in one shot inside the coding turn below.
            // Otherwise run a dedicated planning turn - an openai chat with
            // read-only tools, or a subprocess CLI in plan mode - and hand the
            // plan to the (possibly different) coder.
            let plan = if models.planner.backend.is_subprocess()
                && models.planner.same_endpoint(&models.coding)
            {
                None
            } else {
                let knob_phase = phase == Phase::Knob;
                let up = if knob_phase {
                    knob_planner_prompt(
                        &metric_name,
                        &goal,
                        goal_description.as_deref(),
                        Some(best_value),
                        &rep.rounds,
                        attempt_memory,
                        &last_verdict_json,
                        &crate_diff,
                        note.as_deref(),
                    )
                } else {
                    planner_prompt(
                        &metric_name,
                        &goal,
                        goal_description.as_deref(),
                        Some(best_value),
                        &rep.rounds,
                        attempt_memory,
                        &last_verdict_json,
                        &crate_diff,
                        None,
                        note.as_deref(),
                    )
                };
                let system = if knob_phase {
                    &knob_system
                } else {
                    &planner_system
                };
                active_model.use_model("planner", &models.planner);
                // A subprocess planner runs read-only in plan mode and returns
                // its plan text; an openai planner runs the read-only tool loop.
                let planner_result = if models.planner.backend.is_subprocess() {
                    agent_cli::run(
                        &models.planner,
                        agent_cli::Mode::Plan,
                        !args.json,
                        system,
                        &up,
                        &scheduler_cwd,
                        args.verbose,
                        stderr_color,
                        &mut total_usage,
                        model_turn_timeout,
                        interrupted.clone(),
                    )
                    .await
                } else {
                    let stream_plan = !args.json;
                    api::chat(
                        client,
                        &models.planner,
                        system,
                        &up,
                        Some(&planning_tl),
                        args.verbose,
                        stderr_color,
                        stream_plan,
                        &mut total_usage,
                        model_turn_timeout,
                        interrupted.clone(),
                    )
                    .await
                };
                match planner_result {
                    Ok(plan) => {
                        // Knob phase: the model signals it has run out of useful
                        // knobs to retune. Switch to the code-change phase and
                        // re-plan this round there.
                        if knob_phase && knob_phase_complete(&plan) {
                            agent_info(
                                stderr_color,
                                "knob phase complete (model signaled exhaustion); switching to code-change phase",
                            );
                            phase = Phase::Mechanism;
                            note = None;
                            continue;
                        }
                        if let Some(reason) = planner_plan_rejection_reason(&plan) {
                            const MAX_PLANNER_RECOVERY_RETRIES: u32 = 2;
                            if planner_retries < MAX_PLANNER_RECOVERY_RETRIES {
                                planner_retries += 1;
                                agent_warn(
                                    stderr_color,
                                    format!(
                                        "planner did not produce a usable plan; retrying planner turn {planner_retries}/{MAX_PLANNER_RECOVERY_RETRIES}: {reason}"
                                    ),
                                );
                                note = Some(planner_recovery_note(reason));
                                continue;
                            }
                            agent_warn(
                                stderr_color,
                                format!(
                                    "planner still did not produce a usable plan after retries; continuing to coding without planner output: {reason}"
                                ),
                            );
                            None
                        } else {
                            Some(plan)
                        }
                    }
                    Err(e) if interrupt::is(&e) => {
                        summary = "interrupted during planner turn".to_string();
                        made_edit = false;
                        break;
                    }
                    Err(e) if model_timeout::is(&e) => {
                        let msg = model_timeout::summary(&e);
                        summary = format!("planner model turn timeout: {msg}");
                        made_edit = false;
                        model_timeout_err = Some(msg);
                        break;
                    }
                    Err(e) if api::is_api_error(&e) => {
                        let msg = api::error_summary(&e);
                        const MAX_API_ERROR_RETRIES: u32 = 2;
                        if api_tries < MAX_API_ERROR_RETRIES {
                            api_tries += 1;
                            agent_warn(
                                stderr_color,
                                format!(
                                    "planner API error before edit; retrying round attempt {api_tries}/{MAX_API_ERROR_RETRIES}: {msg}"
                                ),
                            );
                            continue;
                        }
                        summary = format!("planner api error: {msg}");
                        made_edit = false;
                        api_error = Some(msg);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            };

            let up = if phase == Phase::Knob {
                knob_edit_prompt(
                    &metric_name,
                    &goal,
                    goal_description.as_deref(),
                    Some(best_value),
                    &rep.rounds,
                    attempt_memory,
                    &last_verdict_json,
                    &crate_diff,
                    note.as_deref(),
                    plan.as_deref(),
                    &knob_inventory,
                )
            } else {
                edit_prompt(
                    &metric_name,
                    &goal,
                    goal_description.as_deref(),
                    Some(best_value),
                    &rep.rounds,
                    attempt_memory,
                    &last_verdict_json,
                    &crate_diff,
                    None,
                    note.as_deref(),
                    plan.as_deref(),
                )
            };
            let coding_turn = run_coding_turn(
                client,
                models,
                &coding_system,
                &up,
                &scheduler_cwd,
                &edit_tl,
                args.verbose,
                !args.json,
                stderr_color,
                &mut active_model,
                &mut total_usage,
                model_turn_timeout,
                interrupted.clone(),
            )
            .await;
            let content = match coding_turn {
                Err(e) if interrupt::is(&e) => {
                    let d = normalize_diff(
                        &git::diff(source, baseline_sha, crate_dir).unwrap_or_default(),
                    );
                    summary = "interrupted during coding turn".to_string();
                    made_edit = d != accepted_norm;
                    break;
                }
                Err(e) if model_timeout::is(&e) => {
                    let d = normalize_diff(
                        &git::diff(source, baseline_sha, crate_dir).unwrap_or_default(),
                    );
                    let msg = model_timeout::summary(&e);
                    summary = format!("coding model turn timeout: {msg}");
                    made_edit = d != accepted_norm;
                    model_timeout_err = Some(msg);
                    break;
                }
                Err(e) => return Err(e),
                Ok(Ok(content)) => content,
                Ok(Err(msg)) => {
                    let d = normalize_diff(
                        &git::diff(source, baseline_sha, crate_dir).unwrap_or_default(),
                    );
                    made_edit = d != accepted_norm;
                    if made_edit {
                        agent_warn(
                            stderr_color,
                            format!("API error after edit; continuing with current diff: {msg}"),
                        );
                        summary = format!("api error after edit; validating partial edit: {msg}");
                    } else {
                        const MAX_API_ERROR_RETRIES: u32 = 2;
                        if api_tries < MAX_API_ERROR_RETRIES {
                            api_tries += 1;
                            agent_warn(
                                    stderr_color,
                                    format!(
                                        "API error before edit; retrying round attempt {api_tries}/{MAX_API_ERROR_RETRIES}: {msg}"
                                    ),
                                );
                            continue;
                        }
                        summary = format!("api error: {msg}");
                        api_error = Some(msg);
                    }
                    break;
                }
            };
            let s = derive_summary(&content);
            let d = normalize_diff(&git::diff(source, baseline_sha, crate_dir).unwrap_or_default());
            made_edit = d != accepted_norm;
            if !made_edit {
                summary = s;
                break;
            }
            let current_round_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            if let Some(reason) = ineffective_round_edit_reason(&current_round_diff) {
                if ineffective_tries < 2 {
                    ineffective_tries += 1;
                    agent_warn(
                        stderr_color,
                        format!(
                            "ineffective edit rejected; re-prompting ({ineffective_tries}/2): {reason}"
                        ),
                    );
                    git::discard(source, crate_dir).ok();
                    note = Some(ineffective_round_note(&reason));
                    continue;
                }
                summary = format!("ineffective edit: {s}");
                ineffective_edit = Some(reason);
                break;
            }
            // The model decides what to change; whatever it produced is taken
            // as-is and measured (no duplicate-detection re-prompting).
            summary = s;
            break;
        }

        // Tag knob-phase rounds in the ledger so the report (and the later
        // mechanism phase reading the history) can tell configuration tuning
        // apart from code changes.
        let summary = if phase == Phase::Knob {
            format!("knob: {summary}")
        } else {
            summary
        };

        // Live cumulative token usage, refreshed each round (the final total is
        // also printed at the bottom of the report).
        agent_dim(
            stderr_color,
            format!("usage so far: {}", total_usage.footer_line()),
        );

        if interrupted_requested(&interrupted) {
            run_interrupted = true;
            record_interrupted_round(&mut rep, source, crate_dir, round, summary, &goal);
            break;
        }

        if let Some(err) = model_timeout_err.take() {
            agent_warn(
                stderr_color,
                format!("model turn timed out; skipping round: {err}"),
            );
            if !args.json {
                println!(
                    "{}",
                    stdout_color.yellow(format!("round {round}: model turn timeout (skipped)"))
                );
            }
            record_model_timeout_round(
                &mut rep, source, crate_dir, round, summary, &goal, made_edit,
            );
            continue;
        }

        if made_edit && ineffective_edit.is_none() {
            let current_round_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            ineffective_edit = ineffective_round_edit_reason(&current_round_diff);
        }

        if let Some(err) = api_error {
            agent_error(stderr_color, format!("API error; skipping round: {err}"));
            if !args.json {
                println!(
                    "{}",
                    stdout_color.red(format!("round {round}: API error (skipped)"))
                );
            }
            let attempt_diff = if made_edit {
                git::worktree_diff(source, crate_dir).unwrap_or_default()
            } else {
                String::new()
            };
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                "api-error",
                None,
                None,
                false,
                &goal,
                &attempt_diff,
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }

        if let Some(reason) = ineffective_edit {
            agent_warn(
                stderr_color,
                format!("ineffective edit; skipping round: {reason}"),
            );
            if !args.json {
                println!(
                    "{}",
                    stdout_color.yellow(format!(
                        "round {round}: (ineffective edit skipped: {reason})"
                    ))
                );
            }
            let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                "ineffective",
                None,
                None,
                false,
                &goal,
                &attempt_diff,
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }

        if !made_edit {
            agent_warn(stderr_color, "model made no edit; skipping round");
            if !args.json {
                println!(
                    "{}",
                    stdout_color.yellow(format!("round {round}: (no edit made)"))
                );
            }
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round, summary, "no-edit", None, None, false, &goal, "",
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }

        // Announce the change now (before the slow build/validate) so progress
        // is easy to follow live.
        if !args.json && models.coding.backend.is_subprocess() {
            println!("{}", stdout_color.bold(format!("round {round}: {summary}")));
        }

        // 2. Build gate with a fix sub-loop.
        let build_err = build_with_fix_loop(
            args,
            spec.ai.build_fix_attempts,
            source,
            package,
            profile,
            crate_dir,
            baseline_sha,
            &metric_name,
            &goal,
            goal_description.as_deref(),
            best_value,
            &rep.rounds,
            attempt_memory,
            &last_verdict_json,
            client,
            models,
            &coding_system,
            &scheduler_cwd,
            &edit_tl,
            stdout_color,
            stderr_color,
            &mut active_model,
            &mut total_usage,
            model_turn_timeout,
            interrupted.clone(),
        )
        .await;
        let build_err = match build_err {
            Ok(build_err) => build_err,
            Err(e) if interrupt::is(&e) => {
                run_interrupted = true;
                record_interrupted_round(&mut rep, source, crate_dir, round, summary, &goal);
                break;
            }
            Err(e) if model_timeout::is(&e) => {
                let msg = model_timeout::summary(&e);
                agent_warn(
                    stderr_color,
                    format!("model turn timeout during build fix; skipping round: {msg}"),
                );
                if !args.json {
                    println!(
                        "{}",
                        stdout_color.yellow(format!(
                            "round {round}: model turn timeout during build fix (skipped)"
                        ))
                    );
                }
                record_model_timeout_round(
                    &mut rep, source, crate_dir, round, summary, &goal, true,
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        if interrupted_requested(&interrupted) {
            run_interrupted = true;
            record_interrupted_round(&mut rep, source, crate_dir, round, summary, &goal);
            break;
        }
        if build_err.is_some() {
            agent_error(stderr_color, "build still failing; reverting round");
            if !args.json {
                println!(
                    "{}",
                    stdout_color.red(format!("  round {round} result: build failed (reverted)"))
                );
            }
            let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                "build-failed",
                None,
                None,
                false,
                &goal,
                &attempt_diff,
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }

        // 3. Validate.
        let verdict = validate::run_validation(
            source,
            spec_path,
            sudo,
            args.verbose,
            (!args.json).then_some(stdout_color),
            spec.tracing.enable_tracing,
            &interrupted,
        )?;
        let mut verdict = verdict;
        last_verdict_json = serde_json::to_string(&verdict.raw).unwrap_or_default();
        if interrupted_requested(&interrupted) {
            run_interrupted = true;
            record_interrupted_round(&mut rep, source, crate_dir, round, summary, &goal);
            break;
        }
        let mut runtime_fix = 0;
        let mut runtime_fix_build_failed = false;
        while should_try_runtime_fix(&verdict)
            && runtime_fix < spec.ai.runtime_fix_attempts
            && !interrupted_requested(&interrupted)
        {
            runtime_fix += 1;
            agent_warn(
                stderr_color,
                format!(
                    "validation stage={}; runtime-fix attempt {runtime_fix}/{}",
                    verdict.stage, spec.ai.runtime_fix_attempts
                ),
            );
            let diff_now = git::diff(source, baseline_sha, crate_dir).unwrap_or_default();
            let feedback = validation_failure_feedback(&verdict);
            let up = edit_prompt(
                &metric_name,
                &goal,
                goal_description.as_deref(),
                Some(best_value),
                &rep.rounds,
                attempt_memory,
                &last_verdict_json,
                &diff_now,
                Some(&feedback),
                None,
                None,
            );
            let before_fix = normalize_diff(&diff_now);
            let fix_turn = run_coding_turn(
                client,
                models,
                &coding_system,
                &up,
                &scheduler_cwd,
                &edit_tl,
                args.verbose,
                !args.json,
                stderr_color,
                &mut active_model,
                &mut total_usage,
                model_turn_timeout,
                interrupted.clone(),
            )
            .await;
            let fix_attempted = match fix_turn {
                Err(e) if interrupt::is(&e) => {
                    run_interrupted = true;
                    break;
                }
                Err(e) if model_timeout::is(&e) => {
                    model_timeout_err = Some(model_timeout::summary(&e));
                    break;
                }
                Err(e) => return Err(e),
                Ok(Ok(_)) => true,
                Ok(Err(msg)) => {
                    let after_fix = normalize_diff(
                        &git::diff(source, baseline_sha, crate_dir).unwrap_or_default(),
                    );
                    if after_fix != before_fix {
                        agent_warn(
                            stderr_color,
                            format!("API error after runtime-fix edit; retrying validation: {msg}"),
                        );
                        true
                    } else {
                        agent_error(
                            stderr_color,
                            format!("API error during runtime-fix attempt; reverting round: {msg}"),
                        );
                        false
                    }
                }
            };
            if !fix_attempted {
                break;
            }

            let build_err = build_with_fix_loop(
                args,
                spec.ai.build_fix_attempts,
                source,
                package,
                profile,
                crate_dir,
                baseline_sha,
                &metric_name,
                &goal,
                goal_description.as_deref(),
                best_value,
                &rep.rounds,
                attempt_memory,
                &last_verdict_json,
                client,
                models,
                &coding_system,
                &scheduler_cwd,
                &edit_tl,
                stdout_color,
                stderr_color,
                &mut active_model,
                &mut total_usage,
                model_turn_timeout,
                interrupted.clone(),
            )
            .await;
            let build_err = match build_err {
                Ok(build_err) => build_err,
                Err(e) if interrupt::is(&e) => {
                    run_interrupted = true;
                    break;
                }
                Err(e) if model_timeout::is(&e) => {
                    model_timeout_err = Some(model_timeout::summary(&e));
                    break;
                }
                Err(e) => return Err(e),
            };
            if build_err.is_some() {
                runtime_fix_build_failed = true;
                break;
            }

            verdict = validate::run_validation(
                source,
                spec_path,
                sudo,
                args.verbose,
                (!args.json).then_some(stdout_color),
                spec.tracing.enable_tracing,
                &interrupted,
            )?;
            last_verdict_json = serde_json::to_string(&verdict.raw).unwrap_or_default();
        }
        if interrupted_requested(&interrupted) {
            run_interrupted = true;
            record_interrupted_round(&mut rep, source, crate_dir, round, summary, &goal);
            break;
        }
        if let Some(err) = model_timeout_err.take() {
            agent_warn(
                stderr_color,
                format!("model turn timeout during runtime fix; skipping round: {err}"),
            );
            if !args.json {
                println!(
                    "{}",
                    stdout_color.yellow(format!(
                        "round {round}: model turn timeout during runtime fix (skipped)"
                    ))
                );
            }
            record_model_timeout_round(&mut rep, source, crate_dir, round, summary, &goal, true);
            continue;
        }
        if runtime_fix_build_failed {
            agent_error(
                stderr_color,
                "build failed while fixing runtime failure; reverting round",
            );
            if !args.json {
                println!(
                    "{}",
                    stdout_color.red(format!("  round {round} result: build failed (reverted)"))
                );
            }
            let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                "build-failed",
                None,
                None,
                false,
                &goal,
                &attempt_diff,
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }
        if !verdict.is_complete() {
            let outcome_label = match verdict.stage.as_str() {
                "build" => "build-failed",
                "attach" | "preflight" => "attach-failed",
                "runtime" | "metric" => "runtime-failed",
                _ => "metric-failed",
            };
            agent_error(
                stderr_color,
                format!("validation stage={} -> reverting", verdict.stage),
            );
            let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                outcome_label,
                None,
                None,
                false,
                &goal,
                &attempt_diff,
            ));
            // Failed/skipped rounds (build/attach/runtime/api errors, ineffective
            // or no edit) just move on to the next round; the run continues until
            // the [ai].rounds budget is reached.
            continue;
        }

        // 4. Keep/revert decision.
        let value = verdict.median.or(verdict.value).unwrap();
        let stddev = verdict.stddev.unwrap_or(0.0);
        let margin = accept_threshold_stddev * stddev;
        let improved = if goal == "minimize" {
            value < best_value - margin
        } else {
            value > best_value + margin
        };
        let delta = value - best_value;

        let attempt_diff = git::worktree_diff(source, crate_dir).unwrap_or_default();
        if improved {
            git::checkpoint(source, crate_dir).with_context(|| "stage accepted variant")?;
            best_value = value;
            rep.best_value = Some(best_value);
            rep.best_round = Some(round);
            rep.rounds.push(round_record(
                round,
                summary,
                "kept",
                Some(value),
                Some(delta),
                true,
                &goal,
                &attempt_diff,
            ));
            agent_success(
                stderr_color,
                format!("KEPT: {metric_name} = {value:.3} (Δ {delta:+.3})"),
            );
        } else {
            git::discard(source, crate_dir).ok();
            rep.rounds.push(round_record(
                round,
                summary,
                "reverted",
                Some(value),
                Some(delta),
                false,
                &goal,
                &attempt_diff,
            ));
            agent_warn(
                stderr_color,
                format!("reverted: {metric_name} = {value:.3} (Δ {delta:+.3}, margin {margin:.3})"),
            );
        }
    }

    if interrupted_requested(&interrupted) {
        run_interrupted = true;
    }
    rep.usage = total_usage;
    Ok(OptimizeOutcome {
        report: rep,
        interrupted: run_interrupted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_toml_alias() {
        let args = OptimizeArgs::try_parse_from([
            "scx-forge-agent",
            "--spec-toml",
            "/tmp/custom.spec.toml",
        ])
        .unwrap();

        assert_eq!(
            args.spec.as_deref(),
            Some(Path::new("/tmp/custom.spec.toml"))
        );
    }

    #[test]
    fn parses_save_and_resume() {
        let args = OptimizeArgs::try_parse_from([
            "scx-forge-agent",
            "--save",
            "/tmp/save.md",
            "--resume",
            "/tmp/resume.md",
        ])
        .unwrap();

        assert_eq!(args.save.as_deref(), Some(Path::new("/tmp/save.md")));
        assert_eq!(args.resume.as_deref(), Some(Path::new("/tmp/resume.md")));
    }

    #[test]
    fn parses_keep_running() {
        let args = OptimizeArgs::try_parse_from(["scx-forge-agent", "--keep-running"]).unwrap();

        assert!(args.keep_running);
    }

    #[test]
    fn expands_tilde_in_sudo_passwd_file() {
        let old_home = std::env::var_os("HOME");
        let home = std::env::temp_dir().join(format!("scx_home_test_{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);

        let path =
            expand_sudo_password_file(Path::new("/tmp/spec.toml"), Path::new("~/.pass")).unwrap();
        assert_eq!(path, home.join(".pass"));

        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn expands_relative_wildcard_in_sudo_passwd_file() {
        let base = std::env::temp_dir().join(format!("scx_glob_test_{}", std::process::id()));
        std::fs::create_dir_all(base.join("secrets")).unwrap();
        let pass = base.join("secrets/sudo-pass");
        std::fs::write(&pass, "pw\n").unwrap();

        let path = expand_sudo_password_file(&base.join("spec.toml"), Path::new("secrets/sudo-*"))
            .unwrap();
        assert_eq!(path, pass);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rejects_ambiguous_sudo_passwd_file_wildcard() {
        let base =
            std::env::temp_dir().join(format!("scx_glob_ambiguous_test_{}", std::process::id()));
        std::fs::create_dir_all(base.join("secrets")).unwrap();
        std::fs::write(base.join("secrets/a.pass"), "pw\n").unwrap();
        std::fs::write(base.join("secrets/b.pass"), "pw\n").unwrap();

        let err = expand_sudo_password_file(&base.join("spec.toml"), Path::new("secrets/*.pass"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous"), "got: {err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn optimizer_mission_is_neutral_and_knob_aware() {
        let optimizer_md = OPTIMIZER_MD
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let has = |phrase: &str| {
            optimizer_md.contains(&phrase.split_whitespace().collect::<Vec<_>>().join(" "))
        };

        // The static mission derives logic from observed runtime properties and
        // stays neutral about other schedulers: the cross-scheduler porting
        // guidance and tool names are injected by planner_system_prompt only when
        // [ai].cross_scheduler_refs is enabled, never baked into this resource.
        assert!(has("wakeup frequency"));
        assert!(!has("explore the other schedulers"));
        assert!(!has("read_scheduler_file"));
        assert!(!has("list_schedulers"));
        // The knob space is off-limits, stated generically against whatever
        // options the scheduler exposes - not a hardcoded list of scx_forge enums.
        assert!(has("Do not re-implement an existing knob"));
        assert!(has("changes the default value of an existing option"));
        assert!(!has("DSQ topology"));
        assert!(!has("idle-CPU policy"));
    }

    #[test]
    fn coder_prompt_is_just_the_plan() {
        let plan = "Summary: add wakeup-frequency-weighted deadlines.\nEdit task_dsq_key() in src/bpf/main.bpf.c.";
        let prompt = edit_prompt(
            "latency",
            "minimize",
            Some("reduce benchmark latency"),
            Some(10.0),
            &[],
            None,
            "{}",
            "",
            None,
            None,
            Some(plan),
        );
        // The coder sees only the plan plus a short apply instruction - none of
        // the round context (history, verdict, diff) leaks in.
        assert!(prompt.contains(plan));
        assert!(prompt.contains("Implement this experiment with the edit_file tool"));
        assert!(!prompt.contains("Optimization history"));
        assert!(!prompt.contains("Last benchmark result"));
        assert!(!prompt.contains("Currently applied changes"));
    }

    #[test]
    fn planner_prompt_does_not_request_edits() {
        let prompt = planner_prompt(
            "latency",
            "minimize",
            Some("reduce benchmark latency"),
            Some(10.0),
            &[],
            None,
            "{}",
            "",
            None,
            None,
        );

        assert!(prompt.contains("Return the experiment plan now"));
        assert!(prompt.contains("do not edit files"));
        assert!(!prompt.contains("Implement this experiment with the edit_file tool"));
    }

    #[test]
    fn planner_plan_rejection_catches_empty_and_tool_errors() {
        assert_eq!(
            planner_plan_rejection_reason("   "),
            Some("empty planner response")
        );
        assert_eq!(
            planner_plan_rejection_reason("ERROR: unknown tool: str_replace_editor"),
            Some("planner returned a tool error instead of a plan")
        );
        assert_eq!(
            planner_plan_rejection_reason(
                "Summary: switch enqueue to a per-LLC DSQ and update dispatch to pull from the same LLC queue."
            ),
            None
        );
    }

    #[test]
    fn planner_system_prompt_is_planner_only() {
        // Default (cross-scheduler refs disabled): planner-only, crate-focused,
        // with no mention of other schedulers.
        let prompt = planner_system_prompt("scx_forge", "scheds/rust/scx_forge", None, false);
        assert!(prompt.contains("You are the PLANNER"));
        assert!(prompt.contains("Do not edit files"));
        assert!(!prompt.contains("scheds/rust`"));
        assert!(!prompt.contains("list_schedulers"));

        // With refs enabled: the cross-scheduler porting guidance and tools are
        // advertised.
        let refs = planner_system_prompt("scx_forge", "scheds/rust/scx_forge", None, true);
        assert!(refs.contains("You are the PLANNER"));
        assert!(refs.contains("cross-scheduler reference tools are enabled"));
        assert!(refs.contains("read_scheduler_file"));
    }

    #[test]
    fn planner_system_prompt_lists_existing_knobs_from_help() {
        let help = "Options:\n  --dsq-topology <V>  topology\n  --ordering <V>  ordering";
        let prompt = planner_system_prompt("scx_forge", "scheds/rust/scx_forge", Some(help), false);
        assert!(prompt.contains("## Already-implemented options (do NOT re-propose these)"));
        assert!(prompt.contains("--dsq-topology"));
        assert!(prompt.contains("--ordering"));
        // Without help text, that injected section is omitted (the mission text
        // mentions the phrase in prose, so match the full injected header).
        let bare = planner_system_prompt("scx_forge", "scheds/rust/scx_forge", None, false);
        assert!(!bare.contains("## Already-implemented options (do NOT re-propose these)"));
    }

    #[test]
    fn prompt_includes_previous_attempt_memory() {
        let prompt = planner_prompt(
            "score",
            "maximize",
            Some("increase throughput"),
            Some(10.0),
            &[],
            Some("round 1 | reverted | bad placement idea"),
            "{}",
            "",
            None,
            None,
        );

        assert!(prompt.contains("Previous run attempt memory"));
        assert!(prompt.contains("bad placement idea"));
    }

    #[test]
    fn run_attempt_summary_records_rounds() {
        let mut rep = Report {
            objective: "maximize score".into(),
            goal: "maximize".into(),
            metric_name: "score".into(),
            start_value: Some(10.0),
            best_value: Some(12.0),
            best_round: Some(1),
            rounds: Vec::new(),
            usage: usage::Usage::default(),
        };
        rep.rounds.push(round_record(
            1,
            "Bias wakeup CPU placement".into(),
            "kept",
            Some(12.0),
            Some(2.0),
            true,
            "maximize",
            "select_cpu",
        ));

        let summary = run_attempt_summary(
            &rep,
            "scx_forge",
            "scheds/rust/scx_forge",
            Path::new("spec.toml"),
            "abc123",
        );

        assert!(summary.contains("Package: `scx_forge`"));
        assert!(summary.contains("| 1 | kept | 12.000 | +2.000 |"));
        assert!(summary.contains("Bias wakeup CPU placement"));
    }

    #[test]
    fn prompts_keep_history_neutral_after_failed_rounds() {
        let history = vec![round_record(
            1,
            "reduced timeslice by 10%".into(),
            "reverted",
            Some(11.0),
            Some(1.0),
            false,
            "minimize",
            "",
        )];
        let prompt = edit_prompt(
            "latency",
            "minimize",
            Some("reduce benchmark latency"),
            Some(10.0),
            &history,
            None,
            "{}",
            "",
            None,
            None,
            None,
        );

        assert!(prompt.contains("Optimization history"));
        // History is shown as neutral factual context, with no directive to
        // exploit kept results or ban reverted areas.
        assert!(!prompt.contains("Cooldown"));
        assert!(!prompt.contains("DIFFERENT policy seam"));
        assert!(!prompt.contains("do not answer with another timeslice/constant adjustment"));
        assert!(!prompt.contains("compose and adapt a reusable structural policy concept"));
    }

    #[test]
    fn knob_phase_complete_detects_sentinel_only_as_full_line() {
        // The sentinel ends the knob phase only when it stands on its own line.
        assert!(knob_phase_complete("KNOB_PHASE_COMPLETE"));
        assert!(knob_phase_complete("done tuning\nKNOB_PHASE_COMPLETE\n"));
        assert!(knob_phase_complete("  KNOB_PHASE_COMPLETE  "));
        // A normal plan that merely mentions it is not a completion signal.
        assert!(!knob_phase_complete(
            "Set ordering default to Deadline; this is not KNOB_PHASE_COMPLETE yet"
        ));
        assert!(!knob_phase_complete("Set idle_policy default to Waker."));
    }

    #[test]
    fn knob_system_prompt_constrains_to_clap_defaults_and_lists_options() {
        let inventory = "## Command-line options (from --help)\n```\n--ordering <ORDERING>  [possible values: vruntime, deadline, fifo]\n```\n";
        let prompt = knob_system_prompt("scx_forge", "scheds/rust/scx_forge", inventory);
        let prompt_words = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
        // It is the planner, scoped to retuning existing clap defaults.
        assert!(prompt.contains("KNOB-TUNING phase"));
        assert!(prompt.contains("Add or change only"));
        assert!(prompt.contains("default_value_t"));
        assert!(prompt.contains("optional string options"));
        assert!(prompt.contains("to_bpf()"));
        assert!(prompt.contains("KNOB_PHASE_COMPLETE"));
        assert!(prompt.contains("Bias knob selection by workload saturation"));
        assert!(prompt.contains("placement-style knobs"));
        assert!(prompt.contains("ordering-style knobs"));
        assert!(prompt_words.contains("saturated, unsaturated, or mixed"));
        assert!(prompt_words.contains("CPU capacity, fast/slow CPU preference"));
        assert!(prompt_words.contains("primary / performance domains"));
        assert!(!KNOB_MD.contains("KNOB_PHASE"));
        // The discovered options are embedded so the model knows what it can tune.
        assert!(prompt.contains("possible values: vruntime, deadline, fifo"));
    }

    #[test]
    fn knob_edit_prompt_carries_inventory_only_without_a_plan() {
        let inventory = "OPTION_INVENTORY_MARKER";
        // With a plan (openai backend) the coder just applies it; the inventory
        // already reached the planner, so it is not repeated here.
        let with_plan = knob_edit_prompt(
            "latency",
            "minimize",
            None,
            Some(10.0),
            &[],
            None,
            "{}",
            "",
            None,
            Some("Set ordering default to Deadline"),
            inventory,
        );
        assert!(with_plan.contains("Set ordering default to Deadline"));
        assert!(with_plan.contains("to_bpf()"));
        assert!(!with_plan.contains(inventory));
        // Without a plan (subprocess backend) the coder must see the inventory to
        // pick a knob itself.
        let no_plan = knob_edit_prompt(
            "latency",
            "minimize",
            None,
            Some(10.0),
            &[],
            None,
            "{}",
            "",
            None,
            None,
            inventory,
        );
        assert!(no_plan.contains(inventory));
    }

    #[test]
    fn classify_attempt_tags_policy_area_and_direction() {
        let tags = classify_attempt(
            "Bias wakeup CPU placement toward idle siblings",
            "diff --git a/src/bpf/main.bpf.c b/src/bpf/main.bpf.c\n+select_cpu_idle_sibling();",
        );

        assert_eq!(tags.policy_area, "placement");
        assert!(tags.direction.contains("bias"));
        assert!(tags.direction.contains("wakeup"));
    }

    #[test]
    fn detects_bpf_const_volatile_initializer_only_diff() {
        let diff = r#"diff --git a/scheds/rust/scx_forge/src/bpf/main.bpf.c b/scheds/rust/scx_forge/src/bpf/main.bpf.c
index 1d6827ca2..179c31d0d 100644
--- a/scheds/rust/scx_forge/src/bpf/main.bpf.c
+++ b/scheds/rust/scx_forge/src/bpf/main.bpf.c
@@ -48,7 +48,7 @@ const volatile bool debug;
 /*
  * Default task time slice.
  */
-const volatile u64 slice_ns = NSEC_PER_MSEC;
+const volatile u64 slice_ns = NSEC_PER_MSEC / 2;
 
 /*
  * SMT (Simultaneous Multi-Threading) is enabled on the system.
"#;

        let reason = ineffective_round_edit_reason(diff).unwrap();
        assert!(reason.contains("slice_ns"));
        assert!(reason.contains("Rust rodata"));
    }

    #[test]
    fn allows_bpf_const_volatile_diff_when_rust_is_changed_too() {
        let diff = r#"diff --git a/scheds/rust/scx_forge/src/bpf/main.bpf.c b/scheds/rust/scx_forge/src/bpf/main.bpf.c
--- a/scheds/rust/scx_forge/src/bpf/main.bpf.c
+++ b/scheds/rust/scx_forge/src/bpf/main.bpf.c
@@ -48,7 +48,7 @@
-const volatile u64 slice_ns = NSEC_PER_MSEC;
+const volatile u64 slice_ns = NSEC_PER_MSEC / 2;
diff --git a/scheds/rust/scx_forge/src/main.rs b/scheds/rust/scx_forge/src/main.rs
--- a/scheds/rust/scx_forge/src/main.rs
+++ b/scheds/rust/scx_forge/src/main.rs
@@ -164,7 +164,7 @@
-        rodata.slice_ns = opts.slice_us * 1000;
+        rodata.slice_ns = opts.slice_us * 500;
"#;

        assert!(ineffective_round_edit_reason(diff).is_none());
    }

    #[test]
    fn allows_bpf_policy_logic_diff() {
        let diff = r#"diff --git a/scheds/rust/scx_forge/src/bpf/main.bpf.c b/scheds/rust/scx_forge/src/bpf/main.bpf.c
--- a/scheds/rust/scx_forge/src/bpf/main.bpf.c
+++ b/scheds/rust/scx_forge/src/bpf/main.bpf.c
@@ -342,7 +342,7 @@
-        return slice_ns;
+        return slice_ns / 2;
"#;

        assert!(ineffective_round_edit_reason(diff).is_none());
    }
}
