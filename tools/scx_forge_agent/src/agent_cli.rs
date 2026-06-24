// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Subprocess backends: drive a round's edits by shelling out to the `claude`,
//! `opencode`, `codex`, or `cursor-agent` CLI in non-interactive mode, run with
//! the scheduler crate directory as the cwd so the CLI's own tools edit the files
//! in place. The controller then builds/validates the resulting diff exactly as
//! it does for the built-in `openai` backend, so keep/revert/dedup work
//! unchanged.
//!
//! Each CLI runs in one of two [`Mode`]s. In [`Mode::Edit`] it edits the crate
//! in place with its approval/permission prompts disabled and full write access,
//! so only run that where it is acceptable. In [`Mode::Plan`] it runs read-only
//! and returns a textual plan that is handed to the coder role: `claude` uses its
//! `plan` permission mode, `codex` a `read-only` sandbox, and `cursor-agent` its
//! `plan` mode (all genuinely cannot write); `opencode` uses its built-in `plan`
//! agent on a best-effort basis and may still touch files (its edits are just
//! validated/reverted like any other round).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{atomic::AtomicBool, mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::color::Style;
use crate::config::{Backend, ModelConfig};
use crate::interrupt;
use crate::model_timeout::ModelTurnDeadline;
use crate::usage::Usage;

/// How a subprocess backend runs this turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read-only planning turn: produce a textual plan, do not edit (best-effort
    /// for `opencode`).
    Plan,
    /// Make edits in place (approvals/sandbox disabled).
    Edit,
}

/// Streams a subprocess backend's assistant text and reasoning to stdout as the
/// CLI emits it, mirroring the openai backend. This is chunk-level: each CLI
/// event (text block / part / item) is printed whole as it arrives, not
/// token-by-token. Reasoning is dimmed to set it apart from the answer. Tool-call
/// lines are printed separately to stderr and are not handled here.
struct StreamPrinter {
    enabled: bool,
    color: Style,
    started: bool,
    last_was_newline: bool,
}

impl StreamPrinter {
    fn new(enabled: bool, color: Style) -> Self {
        Self {
            enabled,
            color,
            started: false,
            last_was_newline: true,
        }
    }

    fn emit(&mut self, to_print: &str, raw: &str) -> Result<()> {
        if raw.is_empty() {
            return Ok(());
        }
        if !self.enabled {
            return Ok(());
        }
        print!("{to_print}");
        let _ = std::io::stdout().flush();
        self.started = true;
        self.last_was_newline = raw.ends_with('\n');
        Ok(())
    }

    /// Assistant answer/plan text, printed verbatim.
    fn text(&mut self, s: &str) -> Result<()> {
        self.emit(s, s)
    }

    /// Reasoning / thinking, dimmed to distinguish it from the answer. Trailing
    /// newline is tracked from the raw text, not the styled (ANSI-wrapped) string.
    fn reasoning(&mut self, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let styled = self.color.dim(s);
        self.emit(&styled, s)
    }

    /// End the current line if the last chunk did not already. Use after a
    /// whole-block event (claude/codex) so consecutive blocks don't run together;
    /// also called once at the end via [`finish`].
    fn newline(&mut self) {
        if self.enabled && self.started && !self.last_was_newline {
            println!();
            self.last_was_newline = true;
        }
    }

    fn finish(&mut self) {
        self.newline();
    }
}

/// Run one prompt through the configured subprocess backend in `cwd`, returning
/// the CLI's final text. In [`Mode::Edit`] this is the round's change summary
/// (the CLI edits `cwd` directly); in [`Mode::Plan`] it is the plan handed to the
/// coder. When `stream_stdout` is set the assistant's text and reasoning are
/// streamed to stdout as the CLI emits them (chunk-level, mirroring the openai
/// backend). Token usage reported by the CLI is summed into `usage` (reliably for
/// `claude`; `opencode`/`codex` only when they emit it).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    model: &ModelConfig,
    mode: Mode,
    stream_stdout: bool,
    system: &str,
    user: &str,
    cwd: &Path,
    verbose: bool,
    color: Style,
    usage: &mut Usage,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<String> {
    let backend = model.backend;
    let model_id = model.model_id.clone();
    let system = system.to_string();
    let user = user.to_string();
    let cwd = cwd.to_path_buf();

    let join = tokio::task::spawn_blocking(move || match backend {
        Backend::Claude => invoke_claude(
            &model_id,
            mode,
            stream_stdout,
            &system,
            &user,
            &cwd,
            verbose,
            color,
            turn_timeout,
            interrupted,
        ),
        Backend::Opencode => invoke_opencode(
            &model_id,
            mode,
            stream_stdout,
            &system,
            &user,
            &cwd,
            verbose,
            color,
            turn_timeout,
            interrupted,
        ),
        Backend::Codex => invoke_codex(
            &model_id,
            mode,
            stream_stdout,
            &system,
            &user,
            &cwd,
            verbose,
            color,
            turn_timeout,
            interrupted,
        ),
        Backend::Cursor => invoke_cursor(
            &model_id,
            mode,
            stream_stdout,
            &system,
            &user,
            &cwd,
            verbose,
            color,
            turn_timeout,
            interrupted,
        ),
        Backend::OpenAi => unreachable!("openai backend does not use agent_cli"),
    })
    .await;

    match join {
        Ok(Ok((text, u))) => {
            usage.add(&u);
            Ok(text)
        }
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow!("{} worker task failed: {e}", backend.as_str())),
    }
}

fn first_line(s: &str) -> &str {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no stderr)")
}

fn terminate_process_group(child: &mut Child, pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGINT);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// Spawn `cmd` with `stdin_payload` piped in, stream stdout line-by-line, call
/// `on_event` for each JSON line (echoing raw lines to stderr when verbose), and
/// return the exit status plus captured stderr.
fn run_streaming(
    mut cmd: Command,
    label: &str,
    stdin_payload: &str,
    verbose: bool,
    color: Style,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
    mut on_event: impl FnMut(&Value) -> Result<()>,
) -> Result<(ExitStatus, String)> {
    let deadline = ModelTurnDeadline::new(turn_timeout);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn `{label}` CLI"))?;
    let pid = child.id() as i32;
    {
        let stdin = child
            .stdin
            .as_mut()
            .with_context(|| format!("{label} CLI: stdin not captured"))?;
        stdin
            .write_all(stdin_payload.as_bytes())
            .with_context(|| format!("{label} CLI: write prompt to stdin"))?;
    }
    drop(child.stdin.take());

    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("{label} CLI: stdout not captured"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .with_context(|| format!("{label} CLI: stderr not captured"))?;
    // Drain stderr on a side thread so a chatty stderr can't fill its pipe and
    // deadlock the process while we read stdout.
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    let (tx, rx) = mpsc::channel();
    let stdout_thread = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line_res in reader.lines() {
            if tx.send(line_res).is_err() {
                break;
            }
        }
    });

    let mut handle_line = |line_res: std::io::Result<String>| -> Result<()> {
        let line = line_res.with_context(|| format!("{label} CLI: read stdout line"))?;
        if line.trim().is_empty() {
            return Ok(());
        }
        if verbose {
            eprintln!("{} {line}", color.dim(format!("[{label}] <-")));
        }
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            on_event(&v)?;
        }
        Ok(())
    };

    let cleanup_after_abort =
        |child: &mut Child,
         pid: i32,
         stdout_thread: std::thread::JoinHandle<()>,
         stderr_thread: std::thread::JoinHandle<String>| {
            terminate_process_group(child, pid);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
        };

    let status = loop {
        if interrupt::requested(&interrupted) {
            terminate_process_group(&mut child, pid);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(interrupt::err());
        }

        while let Ok(line_res) = rx.try_recv() {
            if deadline.expired() {
                cleanup_after_abort(&mut child, pid, stdout_thread, stderr_thread);
                return Err(deadline.timeout().into());
            }
            if let Err(e) = handle_line(line_res) {
                cleanup_after_abort(&mut child, pid, stdout_thread, stderr_thread);
                return Err(e);
            }
        }

        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{label} CLI: poll for completion"))?
        {
            break status;
        }

        if deadline.expired() {
            cleanup_after_abort(&mut child, pid, stdout_thread, stderr_thread);
            return Err(deadline.timeout().into());
        }

        match rx.recv_timeout(deadline.remaining().min(Duration::from_millis(100))) {
            Ok(line_res) => {
                if let Err(e) = handle_line(line_res) {
                    cleanup_after_abort(&mut child, pid, stdout_thread, stderr_thread);
                    return Err(e);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(status) = child
                    .try_wait()
                    .with_context(|| format!("{label} CLI: poll for completion"))?
                {
                    break status;
                }
            }
        }
    };

    let _ = stdout_thread.join();
    while let Ok(line_res) = rx.try_recv() {
        handle_line(line_res)?;
    }
    let stderr_buf = stderr_thread.join().unwrap_or_default();
    Ok((status, stderr_buf))
}

/// Print a concise tool-call line (matches the openai backend's non-verbose output).
fn print_tool(name: &str, color: Style) {
    eprintln!("{} {}", color.dim("  ->"), color.cyan(name));
}

/// Pick the most informative argument from a tool-call input object (the command
/// run, or the file/path/pattern it targets), truncated for one-line display.
fn arg_hint(input: Option<&Value>) -> Option<String> {
    let input = input?;
    if let Some(c) = input.get("command") {
        let c = format_command(c);
        if !c.is_empty() {
            return Some(truncate(&c, 100));
        }
    }
    for key in [
        "file_path",
        "filePath",
        "path",
        "relativePath",
        "pattern",
        "query",
    ] {
        if let Some(s) = input.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(truncate(s, 100));
            }
        }
    }
    None
}

/// `name(hint)` when a salient argument is available, else just `name`.
fn tool_label(name: &str, input: Option<&Value>) -> String {
    match arg_hint(input) {
        Some(h) => format!("{name}({h})"),
        None => name.to_string(),
    }
}

// --- claude -----------------------------------------------------------------

/// Whether the installed `claude` advertises `--include-partial-messages` (added
/// in newer versions). Detected once from `claude --help` and cached: older
/// builds reject unknown flags, so we must not pass it blindly. When absent we
/// fall back to chunk-level output (the result-event text printed at turn end).
fn claude_supports_partial_messages() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        Command::new("claude")
            .arg("--help")
            .output()
            .ok()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                out.contains("--include-partial-messages")
                    || err.contains("--include-partial-messages")
            })
            .unwrap_or(false)
    })
}

#[derive(Default)]
struct ClaudePlanCapture {
    exit_plan: Option<String>,
    write_plan: Option<String>,
    plan_path: Option<PathBuf>,
}

fn nonempty_string(v: Option<&Value>) -> Option<String> {
    v.and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
}

fn claude_plan_path(input: &Value) -> Option<PathBuf> {
    for key in ["planFilePath", "plan_file_path", "file_path", "path"] {
        if let Some(path) = input.get(key).and_then(|v| v.as_str()) {
            let path = PathBuf::from(path);
            if is_claude_plan_path(&path) {
                return Some(path);
            }
        }
    }
    None
}

fn is_claude_plan_path(path: &Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("md") {
        return false;
    }

    let mut prev_was_claude = false;
    for component in path.components() {
        let Some(component) = component.as_os_str().to_str() else {
            prev_was_claude = false;
            continue;
        };
        if prev_was_claude && component == "plans" {
            return true;
        }
        prev_was_claude = component == ".claude";
    }
    false
}

impl ClaudePlanCapture {
    fn observe_tool_use(&mut self, name: &str, input: Option<&Value>) {
        let Some(input) = input else {
            return;
        };

        if name.eq_ignore_ascii_case("ExitPlanMode") {
            if let Some(plan) = nonempty_string(input.get("plan")) {
                self.exit_plan = Some(plan);
            }
            if let Some(path) = claude_plan_path(input) {
                self.plan_path = Some(path);
            }
        } else if name.eq_ignore_ascii_case("Write") {
            if let Some(path) = claude_plan_path(input) {
                self.plan_path = Some(path);
                if let Some(plan) = nonempty_string(input.get("content")) {
                    self.write_plan = Some(plan);
                }
            }
        }
    }

    fn resolve(&self) -> Result<Option<String>> {
        if let Some(plan) = self.exit_plan.as_deref().filter(|s| !s.trim().is_empty()) {
            return Ok(Some(plan.to_string()));
        }
        if let Some(plan) = self.write_plan.as_deref().filter(|s| !s.trim().is_empty()) {
            return Ok(Some(plan.to_string()));
        }
        if let Some(path) = &self.plan_path {
            let plan = std::fs::read_to_string(path)
                .with_context(|| format!("read claude plan file {}", path.display()))?;
            if !plan.trim().is_empty() {
                return Ok(Some(plan));
            }
        }
        Ok(None)
    }
}

fn print_recovered_claude_plan(
    printer: &mut StreamPrinter,
    stream_stdout: bool,
    plan: &str,
) -> Result<()> {
    if stream_stdout {
        printer.text(plan)?;
        printer.newline();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn invoke_claude(
    model_id: &str,
    mode: Mode,
    stream_stdout: bool,
    system: &str,
    user: &str,
    cwd: &PathBuf,
    verbose: bool,
    color: Style,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<(String, Usage)> {
    let mut cmd = Command::new("claude");
    cmd.current_dir(cwd)
        .arg("--print")
        .arg("--output-format")
        .arg("stream-json")
        // stream-json with --print needs --verbose to emit per-turn events.
        .arg("--verbose");
    // When streaming, ask claude for token-level partial-message events
    // (content_block_delta) so text appears incrementally instead of as one block
    // at the end of the turn. Only pass the flag when this claude advertises it -
    // older builds reject unknown flags; without it we fall back to printing the
    // result text once at turn end (the safety net below).
    if stream_stdout && claude_supports_partial_messages() {
        cmd.arg("--include-partial-messages");
    }
    match mode {
        // Plan mode reads/greps the tree with read-only tools and refuses edits;
        // the headless `--print` run returns the plan as its result text.
        Mode::Plan => {
            cmd.arg("--permission-mode").arg("plan");
        }
        Mode::Edit => {
            cmd.arg("--dangerously-skip-permissions");
        }
    }
    if !model_id.is_empty() {
        cmd.arg("--model").arg(model_id);
    }
    // NOTE: do NOT pass the system prompt via --append-system-prompt. The claude
    // CLI re-tokenizes that option's value and parses embedded `--flags` / `---`
    // out of it, which our prompt (markdown, code with `--`) trips, making claude
    // print its usage and exit. Prepend it to the stdin payload instead - stdin
    // is not arg-parsed.
    let payload = if system.is_empty() {
        user.to_string()
    } else {
        format!("{system}\n\n{user}")
    };

    let mut final_text: Option<String> = None;
    let mut error: Option<String> = None;
    let mut usage = Usage::default();
    let mut plan_capture = ClaudePlanCapture::default();
    let mut printer = StreamPrinter::new(stream_stdout, color);
    let (status, stderr_buf) = run_streaming(
        cmd,
        "claude",
        &payload,
        verbose,
        color,
        turn_timeout,
        interrupted,
        |v| -> Result<()> {
            match v.get("type").and_then(|t| t.as_str()) {
                // Token-level deltas (with --include-partial-messages): stream text
                // and reasoning to stdout as they are produced.
                Some("stream_event") => {
                    let event = v.get("event");
                    let etype = event.and_then(|e| e.get("type")).and_then(|t| t.as_str());
                    match etype {
                        Some("content_block_delta") => {
                            if let Some(delta) = event.and_then(|e| e.get("delta")) {
                                if let Some(t) = delta.get("text").and_then(|t| t.as_str()) {
                                    printer.text(t)?;
                                } else if let Some(t) =
                                    delta.get("thinking").and_then(|t| t.as_str())
                                {
                                    printer.reasoning(t)?;
                                }
                            }
                        }
                        // End the streamed block's line so the next block (or tool
                        // call) starts fresh.
                        Some("content_block_stop") => printer.newline(),
                        _ => {}
                    }
                }
                // The recap assistant message carries tool_use blocks; any text was
                // already streamed via deltas above, so only surface tool calls here.
                Some("assistant") => {
                    if let Some(blocks) = v
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_array())
                    {
                        for b in blocks {
                            if b.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                                let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
                                let input = b.get("input");
                                print_tool(&tool_label(name, input), color);
                                if mode == Mode::Plan {
                                    plan_capture.observe_tool_use(name, input);
                                }
                            }
                        }
                    }
                }
                Some("result") => {
                    // The result event carries cumulative token usage for the turn.
                    if let Some(u) = v.get("usage") {
                        usage = Usage::from_anthropic(u);
                    }
                    if v.get("is_error").and_then(|x| x.as_bool()).unwrap_or(false) {
                        error = Some(
                            v.get("result")
                                .and_then(|x| x.as_str())
                                .unwrap_or("(no message)")
                                .to_string(),
                        );
                    } else {
                        let result = v
                            .get("result")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        // Safety net: if nothing was streamed (deltas unavailable,
                        // e.g. an older claude without --include-partial-messages),
                        // print the answer once so the plan/summary is still shown.
                        if !printer.started {
                            printer.text(&result)?;
                            printer.newline();
                        }
                        final_text = Some(result);
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    printer.finish();
    printer.finish();

    if let Some(e) = error {
        anyhow::bail!("claude CLI reported error: {e}");
    }
    let recovered_plan = if mode == Mode::Plan {
        plan_capture.resolve()?
    } else {
        None
    };
    let Some(mut text) = final_text else {
        if let Some(plan) = recovered_plan {
            print_recovered_claude_plan(&mut printer, stream_stdout, &plan)?;
            return Ok((plan, usage));
        }
        anyhow::bail!(
            "claude CLI exited with {status} without a result event; stderr: {}",
            first_line(&stderr_buf)
        );
    };
    if text.trim().is_empty() {
        if let Some(plan) = recovered_plan {
            print_recovered_claude_plan(&mut printer, stream_stdout, &plan)?;
            text = plan;
        }
    }
    Ok((text, usage))
}

// --- opencode ---------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn invoke_opencode(
    model_id: &str,
    mode: Mode,
    stream_stdout: bool,
    system: &str,
    user: &str,
    cwd: &PathBuf,
    verbose: bool,
    color: Style,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<(String, Usage)> {
    let mut cmd = Command::new("opencode");
    cmd.current_dir(cwd).arg("run").arg("--format").arg("json");
    if mode == Mode::Plan {
        // opencode ships a built-in read-only `plan` agent. Best-effort: if a
        // given install lacks it the run may still edit, which is acceptable -
        // the controller validates/reverts the diff like any other round.
        cmd.arg("--agent").arg("plan");
    }
    if !model_id.is_empty() {
        cmd.arg("-m").arg(model_id);
    }
    // opencode has no system-prompt flag; prepend it to the user message.
    let payload = if system.is_empty() {
        user.to_string()
    } else {
        format!("{system}\n\n{user}")
    };

    let mut text_parts: Vec<String> = Vec::new();
    let mut saw_event = false;
    let mut usage = Usage::default();
    let mut printer = StreamPrinter::new(stream_stdout, color);
    let (status, stderr_buf) = run_streaming(
        cmd,
        "opencode",
        &payload,
        verbose,
        color,
        turn_timeout,
        interrupted,
        |v| -> Result<()> {
            saw_event = true;
            // Best-effort: capture a `usage` object if the CLI emits one (shape varies).
            if let Some(u) = v.get("usage") {
                usage = Usage::from_any(u);
            }
            match v.get("type").and_then(|t| t.as_str()) {
                Some("tool_use") => {
                    let part = v.get("part");
                    let name = part
                        .and_then(|p| p.get("tool"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("tool");
                    // opencode carries the call args under part.state.input
                    // (older builds: part.input).
                    let input = part
                        .and_then(|p| p.get("state").and_then(|s| s.get("input")))
                        .or_else(|| part.and_then(|p| p.get("input")));
                    print_tool(&tool_label(name, input), color);
                }
                Some("text") => {
                    if let Some(part) = v.get("part") {
                        let synthetic = part
                            .get("synthetic")
                            .and_then(|x| x.as_bool())
                            .unwrap_or(false)
                            || part
                                .get("metadata")
                                .and_then(|m| m.get("compaction_continue"))
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                        if !synthetic {
                            if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                if !t.is_empty() {
                                    text_parts.push(t.to_string());
                                    printer.text(t)?;
                                    printer.newline();
                                }
                            }
                        }
                    }
                }
                Some("reasoning") => {
                    if let Some(t) = v
                        .get("part")
                        .and_then(|p| p.get("text"))
                        .and_then(|t| t.as_str())
                    {
                        printer.reasoning(t)?;
                        printer.newline();
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    printer.finish();

    if !saw_event {
        anyhow::bail!(
            "opencode CLI exited with {status} without any events; stderr: {}",
            first_line(&stderr_buf)
        );
    }
    Ok((text_parts.join("\n\n"), usage))
}

// --- codex ------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() > max {
        let head: String = s.chars().take(max).collect();
        format!("{head}...")
    } else {
        s.to_string()
    }
}

/// codex `command` is a string or an argv array; render it as a single line.
fn format_command(v: &Value) -> String {
    match v {
        Value::String(s) => s.replace('\n', " "),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Best-effort changed-file paths from a codex `file_change` item.
fn codex_file_paths(item: &Value) -> Vec<String> {
    if let Some(p) = item.get("path").and_then(|p| p.as_str()) {
        return vec![p.to_string()];
    }
    for key in ["changes", "files"] {
        if let Some(arr) = item.get(key).and_then(|c| c.as_array()) {
            let paths: Vec<String> = arr
                .iter()
                .filter_map(|c| {
                    c.get("path")
                        .and_then(|p| p.as_str())
                        .or_else(|| c.as_str())
                        .map(|s| s.to_string())
                })
                .collect();
            if !paths.is_empty() {
                return paths;
            }
        }
    }
    Vec::new()
}

/// A concise label for a codex `item.completed` item, or None for non-tool items
/// (assistant text / reasoning). Includes the command run or files changed.
fn codex_item_label(item: &Value) -> Option<String> {
    let ty = item
        .get("type")
        .or_else(|| item.get("item_type"))
        .and_then(|t| t.as_str())?;
    match ty {
        "agent_message" | "reasoning" => None,
        "command_execution" => {
            let cmd = item.get("command").map(format_command).unwrap_or_default();
            Some(if cmd.is_empty() {
                ty.to_string()
            } else {
                format!("{ty}: {}", truncate(&cmd, 120))
            })
        }
        "file_change" => {
            let paths = codex_file_paths(item);
            Some(if paths.is_empty() {
                ty.to_string()
            } else {
                format!("{ty}: {}", paths.join(", "))
            })
        }
        // tool_call / mcp_tool_call / function_call and anything else tool-ish.
        other => {
            let name = item
                .get("name")
                .or_else(|| item.get("tool"))
                .and_then(|n| n.as_str());
            Some(match name {
                Some(n) if !n.is_empty() => format!("{other}: {n}"),
                _ => other.to_string(),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke_codex(
    model_id: &str,
    mode: Mode,
    stream_stdout: bool,
    system: &str,
    user: &str,
    cwd: &PathBuf,
    verbose: bool,
    color: Style,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<(String, Usage)> {
    // codex writes the final message to a file; use a unique path in the temp dir.
    let out_path = std::env::temp_dir().join(format!("scx-forge-codex-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&out_path);

    let mut cmd = Command::new("codex");
    cmd.current_dir(cwd)
        .arg("--ask-for-approval")
        .arg("never")
        .arg("exec")
        .arg("--json")
        .arg("--color")
        .arg("never")
        .arg("--output-last-message")
        .arg(&out_path)
        .arg("-C")
        .arg(cwd);
    match mode {
        // A read-only sandbox lets codex inspect the tree but blocks writes; the
        // final message is the plan.
        Mode::Plan => {
            cmd.arg("--sandbox").arg("read-only");
        }
        Mode::Edit => {
            cmd.arg("--dangerously-bypass-approvals-and-sandbox");
        }
    }
    cmd.arg("--skip-git-repo-check");
    if !model_id.is_empty() {
        cmd.arg("--model").arg(model_id);
    }
    // "-" so codex reads the prompt from stdin rather than argv.
    cmd.arg("-");

    let payload = if system.is_empty() {
        user.to_string()
    } else {
        format!("{system}\n\n{user}")
    };

    let mut usage = Usage::default();
    let mut printer = StreamPrinter::new(stream_stdout, color);
    let (status, stderr_buf) = run_streaming(
        cmd,
        "codex",
        &payload,
        verbose,
        color,
        turn_timeout,
        interrupted,
        |v| -> Result<()> {
            // Best-effort: codex reports cumulative token usage on a token_count /
            // turn event (top-level `usage`, or `info.total_token_usage`). Keep the
            // last one seen.
            let u = v
                .get("usage")
                .or_else(|| v.get("info").and_then(|i| i.get("total_token_usage")))
                .or_else(|| v.get("info").and_then(|i| i.get("usage")));
            if let Some(u) = u {
                usage = Usage::from_any(u);
            }
            // Stream assistant text/reasoning to stdout and surface command/tool
            // execution items (with their command / changed paths) to stderr as
            // they complete.
            if v.get("type").and_then(|t| t.as_str()) == Some("item.completed") {
                if let Some(item) = v.get("item") {
                    let ty = item
                        .get("type")
                        .or_else(|| item.get("item_type"))
                        .and_then(|t| t.as_str());
                    match ty {
                        Some("agent_message") => {
                            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                                printer.text(t)?;
                                printer.newline();
                            }
                        }
                        Some("reasoning") => {
                            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                                printer.reasoning(t)?;
                                printer.newline();
                            }
                        }
                        _ => {
                            if let Some(label) = codex_item_label(item) {
                                print_tool(&label, color);
                            }
                        }
                    }
                }
            }
            Ok(())
        },
    )?;
    printer.finish();

    let final_text = std::fs::read_to_string(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);

    if !status.success() {
        anyhow::bail!(
            "codex CLI exited with {status}; stderr: {}",
            first_line(&stderr_buf)
        );
    }
    if final_text.trim().is_empty() {
        anyhow::bail!(
            "codex CLI produced no final message; stderr: {}",
            first_line(&stderr_buf)
        );
    }
    Ok((final_text, usage))
}

// --- cursor-agent -----------------------------------------------------------

/// A concise label for a cursor-agent `tool_call` event. The `tool_call` object
/// carries the tool under a single `<name>ToolCall` key (e.g. `shellToolCall`,
/// `readToolCall`, `editToolCall`) alongside bookkeeping keys like
/// `hookAdditionalContexts` / `toolCallId`. serde_json orders object keys
/// alphabetically, so pick the `*ToolCall` key explicitly rather than the first
/// one; strip the suffix and pull a salient argument (command / path) from `args`.
fn cursor_tool_label(tc: &Value) -> String {
    if let Some((key, body)) = tc
        .as_object()
        .and_then(|m| m.iter().find(|(k, _)| k.ends_with("ToolCall")))
    {
        let name = key.strip_suffix("ToolCall").unwrap_or(key);
        return tool_label(name, body.get("args"));
    }
    "tool".to_string()
}

/// cursor streams a message as fragment deltas (with `--stream-partial-output`),
/// then repeats the whole message as one consolidation event whose text equals
/// the accumulated fragments. Track the running segment so that consolidation is
/// dropped instead of printed a second time. Returns true if `text` is a new
/// fragment to print, false if it is the repeat (and the segment is reset, ready
/// for the next message).
fn cursor_is_new_fragment(segment: &mut String, text: &str) -> bool {
    if !segment.is_empty() && text == *segment {
        segment.clear();
        false
    } else {
        segment.push_str(text);
        true
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke_cursor(
    model_id: &str,
    mode: Mode,
    stream_stdout: bool,
    system: &str,
    user: &str,
    cwd: &PathBuf,
    verbose: bool,
    color: Style,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<(String, Usage)> {
    let mut cmd = Command::new("cursor-agent");
    cmd.current_dir(cwd)
        .arg("--print")
        .arg("--output-format")
        .arg("stream-json")
        // Pin the workspace to the crate dir and trust it so the headless run
        // never blocks on a workspace-trust prompt.
        .arg("--workspace")
        .arg(cwd)
        .arg("--trust")
        // Auto-approve any configured MCP servers so a headless run never stalls
        // waiting to approve them.
        .arg("--approve-mcps");
    // With --stream-partial-output cursor emits assistant text as incremental
    // deltas (each its own assistant event) instead of one block at turn end.
    if stream_stdout {
        cmd.arg("--stream-partial-output");
    }
    match mode {
        // plan mode is read-only (analyze, propose plans, no edits); the result
        // event carries the plan text.
        Mode::Plan => {
            cmd.arg("--mode").arg("plan");
        }
        // --force allows every tool call (incl. write/shell) without prompting.
        Mode::Edit => {
            cmd.arg("--force");
        }
    }
    if !model_id.is_empty() {
        cmd.arg("--model").arg(model_id);
    }
    // cursor-agent reads the prompt from stdin when no positional prompt is given,
    // which avoids arg-parsing our markdown/`--`-laden prompt.
    let payload = if system.is_empty() {
        user.to_string()
    } else {
        format!("{system}\n\n{user}")
    };

    let mut final_text: Option<String> = None;
    let mut error: Option<String> = None;
    let mut usage = Usage::default();
    let mut printer = StreamPrinter::new(stream_stdout, color);
    // Running text/thinking segments, used to drop cursor's per-message
    // consolidation events (which repeat the accumulated fragments verbatim).
    let mut text_seg = String::new();
    let mut think_seg = String::new();
    let (status, stderr_buf) = run_streaming(
        cmd,
        "cursor-agent",
        &payload,
        verbose,
        color,
        turn_timeout,
        interrupted,
        |v| -> Result<()> {
            match v.get("type").and_then(|t| t.as_str()) {
                // Assistant text/thinking. With --stream-partial-output cursor
                // emits fragment deltas, then repeats the whole message as one
                // consolidation event; cursor_is_new_fragment drops that repeat so
                // each piece is printed exactly once.
                Some("assistant") => {
                    if let Some(blocks) = v
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_array())
                    {
                        for b in blocks {
                            let text = b.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            if text.is_empty() {
                                continue;
                            }
                            match b.get("type").and_then(|t| t.as_str()) {
                                Some("text") => {
                                    if cursor_is_new_fragment(&mut text_seg, text) {
                                        printer.text(text)?;
                                    }
                                }
                                Some("thinking") | Some("reasoning") => {
                                    if cursor_is_new_fragment(&mut think_seg, text) {
                                        printer.reasoning(text)?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                // Surface each tool call once, when it starts.
                Some("tool_call") => {
                    if v.get("subtype").and_then(|s| s.as_str()) == Some("started") {
                        if let Some(tc) = v.get("tool_call") {
                            print_tool(&cursor_tool_label(tc), color);
                        }
                    }
                }
                Some("result") => {
                    if let Some(u) = v.get("usage") {
                        usage = Usage::from_cursor(u);
                    }
                    if v.get("is_error").and_then(|x| x.as_bool()).unwrap_or(false) {
                        error = Some(
                            v.get("result")
                                .and_then(|x| x.as_str())
                                .unwrap_or("(no message)")
                                .to_string(),
                        );
                    } else {
                        let result = v
                            .get("result")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        // Safety net: if nothing streamed (deltas disabled), print
                        // the answer once so the plan/summary is still shown.
                        if !printer.started {
                            printer.text(&result)?;
                            printer.newline();
                        }
                        final_text = Some(result);
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    printer.finish();

    if let Some(e) = error {
        anyhow::bail!("cursor-agent CLI reported error: {e}");
    }
    if !status.success() {
        anyhow::bail!(
            "cursor-agent CLI exited with {status}; stderr: {}",
            first_line(&stderr_buf)
        );
    }
    let text = final_text.ok_or_else(|| {
        anyhow!(
            "cursor-agent CLI exited with {status} without a result event; stderr: {}",
            first_line(&stderr_buf)
        )
    })?;
    Ok((text, usage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codex_command_string_label() {
        let item = json!({"type": "command_execution", "command": "cargo build -p scx_forge"});
        assert_eq!(
            codex_item_label(&item).unwrap(),
            "command_execution: cargo build -p scx_forge"
        );
    }

    #[test]
    fn codex_command_argv_label() {
        let item = json!({"type": "command_execution", "command": ["grep", "-n", "foo", "x.c"]});
        assert_eq!(
            codex_item_label(&item).unwrap(),
            "command_execution: grep -n foo x.c"
        );
    }

    #[test]
    fn codex_file_change_path_label() {
        let item = json!({"type": "file_change", "path": "src/bpf/main.bpf.c"});
        assert_eq!(
            codex_item_label(&item).unwrap(),
            "file_change: src/bpf/main.bpf.c"
        );
    }

    #[test]
    fn codex_file_change_changes_array_label() {
        let item = json!({"type": "file_change",
            "changes": [{"path": "a.c", "kind": "modify"}, {"path": "b.h"}]});
        assert_eq!(codex_item_label(&item).unwrap(), "file_change: a.c, b.h");
    }

    #[test]
    fn codex_agent_message_has_no_label() {
        let item = json!({"type": "agent_message", "text": "done"});
        assert_eq!(codex_item_label(&item), None);
    }

    #[test]
    fn codex_long_command_truncated() {
        let item = json!({"type": "command_execution", "command": "x".repeat(200)});
        let label = codex_item_label(&item).unwrap();
        assert!(label.ends_with("..."));
        assert!(label.len() < 160);
    }

    #[test]
    fn tool_label_uses_file_path() {
        let input = json!({"file_path": "src/bpf/main.bpf.c", "old_string": "a"});
        assert_eq!(tool_label("Edit", Some(&input)), "Edit(src/bpf/main.bpf.c)");
    }

    #[test]
    fn tool_label_uses_command_then_pattern() {
        assert_eq!(
            tool_label("Bash", Some(&json!({"command": "cargo build"}))),
            "Bash(cargo build)"
        );
        assert_eq!(
            tool_label("Grep", Some(&json!({"pattern": "budget_slice"}))),
            "Grep(budget_slice)"
        );
    }

    #[test]
    fn tool_label_without_args_is_bare_name() {
        assert_eq!(tool_label("read", None), "read");
        assert_eq!(tool_label("read", Some(&json!({}))), "read");
    }

    #[test]
    fn claude_plan_capture_prefers_exit_plan_text() {
        let mut capture = ClaudePlanCapture::default();
        capture.observe_tool_use(
            "Write",
            Some(&json!({
                "file_path": "/home/me/.claude/plans/example.md",
                "content": "plan from write"
            })),
        );
        capture.observe_tool_use(
            "ExitPlanMode",
            Some(&json!({
                "plan": "plan from exit",
                "planFilePath": "/home/me/.claude/plans/example.md"
            })),
        );

        assert_eq!(capture.resolve().unwrap().unwrap(), "plan from exit");
    }

    #[test]
    fn claude_plan_capture_uses_write_content_for_plan_file() {
        let mut capture = ClaudePlanCapture::default();
        capture.observe_tool_use(
            "Write",
            Some(&json!({
                "file_path": "/home/me/.claude/plans/example.md",
                "content": "plan from write"
            })),
        );

        assert_eq!(capture.resolve().unwrap().unwrap(), "plan from write");
    }

    #[test]
    fn claude_plan_capture_reads_plan_file_when_content_missing() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "scx-forge-agent-claude-plan-test-{}-{unique}",
            std::process::id()
        ));
        let plan_dir = root.join(".claude").join("plans");
        let plan_path = plan_dir.join("example.md");
        std::fs::create_dir_all(&plan_dir).unwrap();
        std::fs::write(&plan_path, "plan from file").unwrap();

        let mut capture = ClaudePlanCapture::default();
        capture.observe_tool_use(
            "ExitPlanMode",
            Some(&json!({
                "planFilePath": plan_path
            })),
        );

        assert_eq!(capture.resolve().unwrap().unwrap(), "plan from file");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_plan_capture_ignores_non_plan_writes() {
        let mut capture = ClaudePlanCapture::default();
        capture.observe_tool_use(
            "Write",
            Some(&json!({
                "file_path": "/tmp/not-a-claude-plan.md",
                "content": "not a plan file"
            })),
        );

        assert_eq!(capture.resolve().unwrap(), None);
    }

    #[test]
    fn cursor_shell_tool_label() {
        let tc = json!({"shellToolCall": {"args": {"command": "cargo build -p scx_forge"}}});
        assert_eq!(cursor_tool_label(&tc), "shell(cargo build -p scx_forge)");
    }

    #[test]
    fn cursor_edit_tool_label_uses_path() {
        let tc = json!({"editToolCall": {"args": {"relativePath": "src/bpf/main.bpf.c"}}});
        assert_eq!(cursor_tool_label(&tc), "edit(src/bpf/main.bpf.c)");
    }

    #[test]
    fn cursor_tool_label_without_args_is_bare_name() {
        let tc = json!({"lsToolCall": {}});
        assert_eq!(cursor_tool_label(&tc), "ls");
    }

    #[test]
    fn cursor_tool_label_ignores_bookkeeping_keys() {
        // serde_json sorts keys alphabetically; a tool whose name sorts after
        // "hookAdditionalContexts" (e.g. readToolCall/shellToolCall) must still be
        // picked over the bookkeeping keys.
        let tc = json!({
            "hookAdditionalContexts": [],
            "startedAtMs": "123",
            "toolCallId": "abc",
            "readToolCall": {"args": {"path": "src/main.rs"}},
        });
        assert_eq!(cursor_tool_label(&tc), "read(src/main.rs)");

        let tc = json!({
            "hookAdditionalContexts": [],
            "shellToolCall": {"args": {"command": "cargo test"}},
            "toolCallId": "x",
        });
        assert_eq!(cursor_tool_label(&tc), "shell(cargo test)");
    }

    #[test]
    fn cursor_fragment_dedup_drops_consolidation() {
        let mut seg = String::new();
        // Fragment deltas are new text to print.
        assert!(cursor_is_new_fragment(&mut seg, "Hello"));
        assert!(cursor_is_new_fragment(&mut seg, " world"));
        // The consolidation repeats the accumulated text: dropped, segment reset.
        assert!(!cursor_is_new_fragment(&mut seg, "Hello world"));
        assert!(seg.is_empty());
        // The next message starts fresh and prints again.
        assert!(cursor_is_new_fragment(&mut seg, "Hello world"));
        assert!(cursor_is_new_fragment(&mut seg, "!"));
        assert!(!cursor_is_new_fragment(&mut seg, "Hello world!"));
    }
}
