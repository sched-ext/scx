// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! OpenAI-compatible `/chat/completions` client with a tool-calling loop.
//!
//! Builds the request body, applies bearer auth, parses the first choice, and
//! when the assistant returns `tool_calls` runs them via
//! [`crate::tools::execute_tool`] and feeds the results back until it returns plain
//! content. Prompt-cache markers and token-budget trimming are intentionally
//! omitted for this first cut.

use std::collections::{BTreeMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};
use std::{error::Error, fmt};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::color::Style;
use crate::config::ModelConfig;
use crate::interrupt;
use crate::model_timeout::ModelTurnDeadline;
use crate::tools;

/// A stderr spinner shown until the first streamed response chunk arrives.
/// Active only on a TTY; a no-op otherwise so logs and redirected output stay clean.
struct Spinner {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Spinner {
    fn start(label: &str, color: Style) -> Spinner {
        if !std::io::stderr().is_terminal() {
            return Spinner { handle: None };
        }
        let label = label.to_string();
        let handle = tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0usize;
            loop {
                eprint!(
                    "\r{} {}",
                    color.dim(frames[i % frames.len()]),
                    color.dim(&label)
                );
                let _ = std::io::stderr().flush();
                i += 1;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        });
        Spinner {
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the system message. With `cache=true` the content is an Anthropic-style
/// block carrying `cache_control: ephemeral` so the (large, constant) system
/// prompt can be cached across requests; with `cache=false` it's a plain string,
/// byte-identical to a no-caching request.
fn system_message(system: &str, cache: bool) -> Value {
    if cache {
        json!({
            "role": "system",
            "content": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        })
    } else {
        json!({"role": "system", "content": system})
    }
}

fn path_with_line_range(path: &str, v: &Value) -> String {
    let start = v.get("start_line").and_then(|x| x.as_u64());
    let end = v.get("end_line").and_then(|x| x.as_u64());
    match (start, end) {
        (None, None) => format!("{path}:1-EOF"),
        (Some(start), None) => format!("{path}:{start}-EOF"),
        (None, Some(end)) => format!("{path}:1-{end}"),
        (Some(start), Some(end)) => format!("{path}:{start}-{end}"),
    }
}

/// A short, human-friendly label for a tool call (shown in non-verbose output):
/// prefers the most salient argument (`path`/`pattern`) over the raw JSON.
fn tool_call_label(name: &str, args: &str) -> String {
    let hint = serde_json::from_str::<Value>(args)
        .ok()
        .and_then(|v| {
            let scheduler = v.get("scheduler").and_then(|x| x.as_str());
            if name == "read_file" {
                if let Some(path) = v.get("path").and_then(|x| x.as_str()) {
                    return Some(path_with_line_range(path, &v));
                }
            }
            if name == "read_scheduler_file" {
                if let (Some(scheduler), Some(path)) =
                    (scheduler, v.get("path").and_then(|x| x.as_str()))
                {
                    return Some(format!("{scheduler}/{}", path_with_line_range(path, &v)));
                }
            }
            if name == "grep_schedulers" {
                if let (Some(scheduler), Some(pattern)) =
                    (scheduler, v.get("pattern").and_then(|x| x.as_str()))
                {
                    return Some(format!("{scheduler}:{pattern}"));
                }
            }
            v.get("path")
                .or_else(|| v.get("pattern"))
                .or_else(|| v.get("url"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| preview(args, 80).replace('\n', " "));
    format!("{name}({hint})")
}

/// Read/edit sandbox + iteration cap for the tool loop.
pub struct ToolLoopConfig {
    pub sandbox: PathBuf,
    pub scheds_root: Option<PathBuf>,
    pub allow_edit: bool,
    pub max_iterations: u32,
}

/// HTTP status failure returned by the OpenAI-compatible endpoint.
#[derive(Debug)]
pub struct ApiStatusError {
    status: reqwest::StatusCode,
    body: String,
}

impl fmt::Display for ApiStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "API error {}: {}", self.status, self.body)
    }
}

impl Error for ApiStatusError {}

/// True if an error came from the provider/request layer rather than local tool
/// execution or response parsing. The controller can skip a round for these.
pub fn is_api_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ApiStatusError>().is_some()
        || err
            .chain()
            .any(|cause| cause.downcast_ref::<reqwest::Error>().is_some())
}

/// One-line provider/request error for logs and reports.
pub fn error_summary(err: &anyhow::Error) -> String {
    let raw = err
        .downcast_ref::<ApiStatusError>()
        .map(|e| e.to_string())
        .unwrap_or_else(|| err.to_string());
    let one_line = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 500;
    if one_line.chars().count() > MAX {
        format!("{}...", one_line.chars().take(MAX).collect::<String>())
    } else {
        one_line
    }
}

fn apply_bearer(req: reqwest::RequestBuilder, api_key: &str) -> reqwest::RequestBuilder {
    if api_key.is_empty() {
        req
    } else {
        req.header("Authorization", format!("Bearer {api_key}"))
    }
}

/// `arguments` may arrive as a JSON string (OpenAI) or an inline object; normalize to a string.
fn arguments_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// OpenAI-compatible chat history requires `function.arguments` to be a string.
fn normalize_tool_call_arguments(tc: &mut Value) {
    let Some(func) = tc.get_mut("function").and_then(|f| f.as_object_mut()) else {
        return;
    };
    let args = func
        .get("arguments")
        .map(arguments_to_string)
        .unwrap_or_else(|| "{}".to_string());
    func.insert("arguments".to_string(), Value::String(args));
}

fn normalize_tool_calls(mut calls: Vec<Value>) -> Vec<Value> {
    for tc in &mut calls {
        normalize_tool_call_arguments(tc);
    }
    calls
}

/// Return a copy of `calls` safe to store in the chat history that gets re-sent
/// on the next request.
///
/// OpenAI-compatible endpoints reject a tool_call whose `function.arguments` is
/// not valid JSON. A model can emit a truncated/garbled call (e.g. an
/// unterminated string when its output is cut off), and re-sending that verbatim
/// makes the *next* request fail with a provider 400 - turning a recoverable
/// tool error into a dead end for the whole turn. Replace any unparseable
/// `arguments` with `{}` so the history stays well-formed. The original
/// (malformed) call is still executed, so the model gets the informative
/// "arguments are not valid JSON" tool result and can retry.
fn sanitize_tool_calls_for_history(calls: &[Value]) -> Vec<Value> {
    calls
        .iter()
        .map(|tc| {
            let mut tc = tc.clone();
            if let Some(func) = tc.get_mut("function").and_then(|f| f.as_object_mut()) {
                let valid = func
                    .get("arguments")
                    .and_then(|a| a.as_str())
                    .is_some_and(|s| serde_json::from_str::<Value>(s).is_ok());
                if !valid {
                    func.insert("arguments".to_string(), Value::String("{}".to_string()));
                }
            }
            tc
        })
        .collect()
}

fn message_content_to_string(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// Max characters of any single field printed in a verbose transcript dump.
const DUMP_MAX_CHARS: usize = 8000;
const SLOW_TOOL_LOG_AFTER: Duration = Duration::from_millis(500);

/// Truncate `s` to `max` chars with an elision marker, for verbose dumps.
fn preview(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n > max {
        let head: String = s.chars().take(max).collect();
        format!("{head}\n    [... {} more chars elided ...]", n - max)
    } else {
        s.to_string()
    }
}

const TOOL_CALL_OPEN: &str = "<tool_call>";
const TOOL_CALL_CLOSE: &str = "</tool_call>";

/// Parse one `<tool_call>` block body (`{"name":..., "arguments"/"parameters":...}`)
/// into a synthetic OpenAI-shaped tool call, or None if it isn't a valid call.
fn parse_one_text_call(inner: &str, idx: usize) -> Option<Value> {
    let v: Value = serde_json::from_str(inner.trim()).ok()?;
    let name = v.get("name").and_then(|n| n.as_str())?;
    let args = v
        .get("arguments")
        .or_else(|| v.get("parameters"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some(json!({
        "id": format!("text_call_{idx}"),
        "type": "function",
        "function": {"name": name, "arguments": arguments_to_string(&args)},
    }))
}

/// Fallback for models that emit tool calls as `<tool_call>{...}</tool_call>` text
/// in the message content instead of the structured `tool_calls` field (the
/// Hermes/Qwen convention). Returns the parsed calls (in OpenAI shape) plus the
/// content with the blocks stripped out.
fn parse_text_tool_calls(content: &str) -> (Vec<Value>, String) {
    let mut calls = Vec::new();
    let mut stripped = String::new();
    let mut rest = content;
    let mut idx = 0usize;
    while let Some(start) = rest.find(TOOL_CALL_OPEN) {
        stripped.push_str(&rest[..start]);
        let after = &rest[start + TOOL_CALL_OPEN.len()..];
        let (inner, consumed) = match after.find(TOOL_CALL_CLOSE) {
            Some(end) => (
                &after[..end],
                start + TOOL_CALL_OPEN.len() + end + TOOL_CALL_CLOSE.len(),
            ),
            None => (after, rest.len()),
        };
        if let Some(call) = parse_one_text_call(inner, idx) {
            calls.push(call);
            idx += 1;
        }
        rest = &rest[consumed..];
    }
    stripped.push_str(rest);
    (calls, stripped.trim().to_string())
}

#[derive(Default)]
struct PendingToolCall {
    id: String,
    ty: String,
    name: String,
    arguments: String,
}

#[derive(Default)]
struct StreamedChat {
    content: String,
    tool_calls: BTreeMap<usize, PendingToolCall>,
    usage: Option<crate::usage::Usage>,
    raw_events: String,
}

impl StreamedChat {
    fn into_message(self) -> Value {
        let content = if self.content.is_empty() {
            Value::Null
        } else {
            Value::String(self.content)
        };
        let mut message = json!({
            "role": "assistant",
            "content": content,
        });
        if !self.tool_calls.is_empty() {
            let calls: Vec<Value> = self
                .tool_calls
                .into_iter()
                .map(|(idx, call)| {
                    json!({
                        "id": if call.id.is_empty() { format!("stream_call_{idx}") } else { call.id },
                        "type": if call.ty.is_empty() { "function".to_string() } else { call.ty },
                        "function": {
                            "name": call.name,
                            "arguments": if call.arguments.is_empty() { "{}".to_string() } else { call.arguments },
                        },
                    })
                })
                .collect();
            message.as_object_mut().unwrap().insert(
                "tool_calls".to_string(),
                Value::Array(normalize_tool_calls(calls)),
            );
        }
        message
    }
}

enum StreamPrintState {
    Visible,
    InToolCall,
}

struct StreamTextPrinter {
    enabled: bool,
    started: bool,
    saw_tool_call: bool,
    last_was_newline: bool,
    state: StreamPrintState,
    buf: String,
}

fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

impl StreamTextPrinter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            started: false,
            saw_tool_call: false,
            last_was_newline: false,
            state: StreamPrintState::Visible,
            buf: String::new(),
        }
    }

    fn emit(&mut self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        self.started = true;
        print!("{text}");
        std::io::stdout()
            .flush()
            .context("flush streamed assistant text")?;
        self.last_was_newline = text.ends_with('\n');
        Ok(())
    }

    fn note_tool_call(&mut self) {
        self.saw_tool_call = true;
    }

    fn emit_before_tool_call(&mut self, text: &str) -> Result<()> {
        let visible = text.trim_end();
        if !visible.is_empty() {
            self.emit(visible)?;
        }
        Ok(())
    }

    fn push(&mut self, text: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.buf.push_str(text);
        loop {
            match self.state {
                StreamPrintState::Visible => {
                    if let Some(pos) = self.buf.find(TOOL_CALL_OPEN) {
                        let visible = self.buf[..pos].to_string();
                        self.note_tool_call();
                        self.emit_before_tool_call(&visible)?;
                        self.buf.drain(..pos + TOOL_CALL_OPEN.len());
                        self.state = StreamPrintState::InToolCall;
                    } else {
                        let keep = TOOL_CALL_OPEN.len().saturating_sub(1);
                        let emit_len = self.buf.len().saturating_sub(keep);
                        if emit_len == 0 {
                            break;
                        }
                        let emit_len = floor_char_boundary(&self.buf, emit_len);
                        if emit_len == 0 {
                            break;
                        }
                        let visible = self.buf[..emit_len].to_string();
                        if self.started || !visible.trim().is_empty() {
                            self.emit(&visible)?;
                        }
                        self.buf.drain(..emit_len);
                        break;
                    }
                }
                StreamPrintState::InToolCall => {
                    if let Some(pos) = self.buf.find(TOOL_CALL_CLOSE) {
                        self.buf.drain(..pos + TOOL_CALL_CLOSE.len());
                        self.state = StreamPrintState::Visible;
                    } else {
                        let keep = TOOL_CALL_CLOSE.len().saturating_sub(1);
                        if self.buf.len() > keep {
                            let drop_len = self.buf.len() - keep;
                            let drop_len = floor_char_boundary(&self.buf, drop_len);
                            if drop_len > 0 {
                                self.buf.drain(..drop_len);
                            }
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if matches!(self.state, StreamPrintState::Visible) && !self.buf.is_empty() {
            let visible = std::mem::take(&mut self.buf);
            if !visible.trim().is_empty() {
                if self.saw_tool_call {
                    self.emit(visible.trim_end())?;
                } else {
                    self.emit(&visible)?;
                }
            }
        }
        if self.started && !self.last_was_newline {
            println!();
        }
        Ok(())
    }
}

fn append_json_text(dst: &mut String, v: &Value) {
    match v {
        Value::String(s) => dst.push_str(s),
        Value::Null => {}
        other => dst.push_str(&other.to_string()),
    }
}

fn apply_stream_delta(delta: &Value, streamed: &mut StreamedChat) -> Result<Option<String>> {
    let mut visible = String::new();
    if let Some(content) = delta.get("content") {
        if let Some(s) = content.as_str() {
            streamed.content.push_str(s);
            visible.push_str(s);
        }
    }

    if let Some(calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
        for (fallback_idx, tc) in calls.iter().enumerate() {
            let idx = tc
                .get("index")
                .and_then(|v| v.as_u64())
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(fallback_idx);
            let entry = streamed.tool_calls.entry(idx).or_default();
            if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                if entry.id.is_empty() {
                    entry.id = id.to_string();
                } else if entry.id != id {
                    entry.id.push_str(id);
                }
            }
            if let Some(ty) = tc.get("type").and_then(|v| v.as_str()) {
                if entry.ty.is_empty() {
                    entry.ty = ty.to_string();
                } else if entry.ty != ty {
                    entry.ty.push_str(ty);
                }
            }
            if let Some(func) = tc.get("function") {
                if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                    entry.name.push_str(name);
                }
                if let Some(args) = func.get("arguments") {
                    append_json_text(&mut entry.arguments, args);
                }
            }
        }
    }

    if let Some(func) = delta.get("function_call") {
        let entry = streamed.tool_calls.entry(0).or_default();
        if entry.id.is_empty() {
            entry.id = "stream_call_0".to_string();
        }
        if entry.ty.is_empty() {
            entry.ty = "function".to_string();
        }
        if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
            entry.name.push_str(name);
        }
        if let Some(args) = func.get("arguments") {
            append_json_text(&mut entry.arguments, args);
        }
    }

    Ok((!visible.is_empty()).then_some(visible))
}

fn find_sse_delimiter(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2));
    let crlf = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn sse_data(event: &[u8]) -> Result<Option<String>> {
    let text = std::str::from_utf8(event).context("parse streaming SSE as UTF-8")?;
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
        .collect::<Vec<_>>();
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data.join("\n")))
    }
}

async fn read_streamed_chat(
    mut resp: reqwest::Response,
    stream_stdout: bool,
    spinner: &mut Spinner,
) -> Result<StreamedChat> {
    let mut streamed = StreamedChat::default();
    let mut printer = StreamTextPrinter::new(stream_stdout);
    let mut buf = Vec::<u8>::new();

    while let Some(chunk) = resp.chunk().await.context("read streaming chat chunk")? {
        buf.extend_from_slice(&chunk);
        while let Some((pos, delim_len)) = find_sse_delimiter(&buf) {
            let event = buf.drain(..pos).collect::<Vec<_>>();
            buf.drain(..delim_len);
            let Some(data) = sse_data(&event)? else {
                continue;
            };
            if data.trim() == "[DONE]" {
                printer.finish()?;
                return Ok(streamed);
            }
            streamed.raw_events.push_str(&data);
            streamed.raw_events.push('\n');
            let parsed: Value = serde_json::from_str(&data)
                .with_context(|| format!("parse streaming chat JSON event: {data}"))?;
            if let Some(u) = parsed.get("usage").filter(|u| !u.is_null()) {
                streamed.usage = Some(crate::usage::Usage::from_openai(u));
            }
            let Some(delta) = parsed
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .and_then(|c| c.get("delta"))
            else {
                continue;
            };
            let has_tool_delta =
                delta.get("tool_calls").is_some() || delta.get("function_call").is_some();
            if delta.get("content").is_some() {
                spinner.stop();
            }
            if has_tool_delta {
                printer.note_tool_call();
            }
            if let Some(text) = apply_stream_delta(delta, &mut streamed)? {
                printer.push(&text)?;
            }
        }
    }

    printer.finish()?;
    Ok(streamed)
}

/// Run a chat turn with an optional tool loop. Returns the final assistant text.
/// Every request's token usage is summed into `usage` (the tool loop makes one
/// request per iteration).
pub async fn chat(
    client: &reqwest::Client,
    model: &ModelConfig,
    system: &str,
    user: &str,
    tool_loop: Option<&ToolLoopConfig>,
    verbose: bool,
    color: Style,
    stream_stdout: bool,
    usage: &mut crate::usage::Usage,
    turn_timeout: Duration,
    interrupted: Arc<AtomicBool>,
) -> Result<String> {
    let deadline = ModelTurnDeadline::new(turn_timeout);
    let url = format!("{}/chat/completions", model.base_url.trim_end_matches('/'));
    // Try Anthropic-style prompt caching: mark the large constant system prompt
    // with cache_control so it isn't reprocessed on every tool-loop iteration /
    // round. Servers that don't support it usually ignore the field; one that
    // rejects it triggers a one-time fallback to plain content (see below).
    let mut use_cache = true;
    let mut use_stream_options = true;
    let mut messages: Vec<Value> = vec![
        system_message(system, use_cache),
        json!({"role": "user", "content": user}),
    ];

    if verbose {
        eprintln!(
            "\n{} {}",
            color.dim("[api]"),
            color.bold(format!(
                "new turn (model={}, system prompt={} chars)",
                model.model_id,
                system.len()
            ))
        );
        eprintln!(
            "{} {}\n{}",
            color.dim("[api]"),
            color.blue("user:"),
            preview(user, DUMP_MAX_CHARS)
        );
    }

    let mut tool_iterations = 0u32;
    let mut edits_applied = 0usize;
    let mut disable_tools = false;
    let mut force_edit = false;
    let mut force_attempts = 0u32;
    let mut request_n = 0u32;
    // Read-only (name, args) pairs already executed this turn. A model that gets
    // stuck re-reading the same location burns iterations and bloats the context
    // (every iteration re-sends the whole conversation), so identical read-only
    // calls are short-circuited instead of re-run.
    let mut seen_tool_calls: HashSet<String> = HashSet::new();

    loop {
        deadline.check()?;
        if interrupt::requested(&interrupted) {
            return Err(interrupt::err());
        }

        // A forced-edit request is bounded: after MAX_FORCE_ATTEMPTS we give up
        // and let the model reply with a summary, so we never loop forever on a
        // model/endpoint that won't emit an edit_file call.
        const MAX_FORCE_ATTEMPTS: u32 = 3;
        if force_edit {
            force_attempts += 1;
            if force_attempts > MAX_FORCE_ATTEMPTS {
                force_edit = false;
                disable_tools = true;
            }
        }

        let mut body = serde_json::Map::new();
        body.insert("model".into(), json!(model.model_id));
        body.insert("messages".into(), json!(&messages));
        body.insert("stream".into(), json!(true));
        if use_stream_options {
            body.insert(
                "stream_options".into(),
                json!({
                    "include_usage": true,
                }),
            );
        }
        if let Some(cfg) = tool_loop {
            body.insert(
                "tools".into(),
                tools::openai_tools_json(cfg.allow_edit, cfg.scheds_root.is_some()),
            );
            // Force the edit when exploration is exhausted; otherwise let the
            // model choose tools freely, or disable them once we want a summary.
            let tool_choice = if force_edit && cfg.allow_edit {
                json!({"type": "function", "function": {"name": "edit_file"}})
            } else if disable_tools {
                json!("none")
            } else {
                json!("auto")
            };
            body.insert("tool_choice".into(), tool_choice);
        }
        let body = Value::Object(body);

        request_n += 1;
        if verbose {
            let tc = if tool_loop.is_none() {
                ""
            } else if force_edit {
                " tool_choice=edit_file(forced)"
            } else if disable_tools {
                " tool_choice=none"
            } else {
                " tool_choice=auto"
            };
            eprintln!(
                "{} {}",
                color.dim("[api]"),
                color.cyan(format!(
                    "POST {url} (request #{request_n}, {} messages{tc})",
                    messages.len()
                ))
            );
        }

        let mut spinner = Spinner::start("thinking...", color);
        let resp = tokio::select! {
            resp = apply_bearer(client.post(&url), &model.api_key).json(&body).send() => {
                resp.context("POST chat/completions")?
            }
            _ = interrupt::wait(interrupted.clone()) => {
                spinner.stop();
                return Err(interrupt::err());
            }
            _ = tokio::time::sleep(deadline.remaining()) => {
                spinner.stop();
                return Err(deadline.timeout().into());
            }
        };
        let status = resp.status();
        if !status.is_success() {
            spinner.stop();
            let text = tokio::select! {
                text = resp.text() => text.context("read chat/completions body")?,
                _ = interrupt::wait(interrupted.clone()) => return Err(interrupt::err()),
                _ = tokio::time::sleep(deadline.remaining()) => {
                    return Err(deadline.timeout().into());
                }
            };
            // A server that rejects the prompt-cache markers: silently drop them
            // and retry once without caching, then stick to plain content.
            if use_cache {
                use_cache = false;
                messages[0] = system_message(system, false);
                if verbose {
                    eprintln!(
                        "{} {}",
                        color.dim("[api]"),
                        color.yellow(format!(
                            "request rejected ({status}); retrying without prompt-cache markers"
                        ))
                    );
                }
                continue;
            }
            if use_stream_options
                && (text.contains("stream_options") || text.contains("include_usage"))
            {
                use_stream_options = false;
                if verbose {
                    eprintln!(
                        "{} {}",
                        color.dim("[api]"),
                        color.yellow("stream usage option rejected; retrying without it")
                    );
                }
                continue;
            }
            return Err(ApiStatusError { status, body: text }.into());
        }

        let streamed = tokio::select! {
            streamed = read_streamed_chat(resp, stream_stdout, &mut spinner) => streamed?,
            _ = interrupt::wait(interrupted.clone()) => {
                spinner.stop();
                return Err(interrupt::err());
            }
            _ = tokio::time::sleep(deadline.remaining()) => {
                spinner.stop();
                return Err(deadline.timeout().into());
            }
        };
        spinner.stop();
        let raw_events = streamed.raw_events.clone();
        let streamed_usage = streamed.usage;
        let message = streamed.into_message();

        if verbose {
            eprintln!(
                "{} {}\n{}",
                color.dim("[api]"),
                color.blue(format!(
                    "raw streamed response ({} bytes):",
                    raw_events.len()
                )),
                preview(&raw_events, 20000)
            );
        }

        if verbose {
            let content = message_content_to_string(&message);
            if !content.trim().is_empty() {
                eprintln!(
                    "{} {}\n{}",
                    color.dim("[api]"),
                    color.blue("assistant:"),
                    preview(&content, DUMP_MAX_CHARS)
                );
            }
        }
        if let Some(u) = streamed_usage {
            usage.add(&u);
            if verbose {
                eprintln!(
                    "{} {}",
                    color.dim("[api]"),
                    color.dim(format!("usage: {}", u.footer_line()))
                );
            }
        }

        let tool_calls: Option<Vec<Value>> = message
            .get("tool_calls")
            .and_then(|tc| tc.as_array())
            .filter(|a| !a.is_empty())
            .cloned()
            .map(normalize_tool_calls);

        // Fallback: some models emit tool calls as <tool_call>{...}</tool_call>
        // text in `content` instead of the structured field. When structured
        // calls are absent, parse them from the text and rebuild the assistant
        // message so the follow-up request and tool_call_id references stay valid.
        let (tool_calls, assistant_message) = if tool_calls.is_none() && tool_loop.is_some() {
            let (parsed, stripped) = parse_text_tool_calls(&message_content_to_string(&message));
            if parsed.is_empty() {
                (tool_calls, message)
            } else {
                if verbose {
                    eprintln!(
                        "{} {}",
                        color.dim("[api]"),
                        color.yellow(format!(
                            "{} tool call(s) parsed from <tool_call> text",
                            parsed.len()
                        ))
                    );
                }
                let assistant = json!({
                    "role": "assistant",
                    "content": if stripped.is_empty() { Value::Null } else { Value::String(stripped) },
                    "tool_calls": sanitize_tool_calls_for_history(&parsed),
                });
                (Some(parsed), assistant)
            }
        } else {
            let assistant = match &tool_calls {
                Some(calls) => {
                    let mut assistant = message;
                    if let Some(obj) = assistant.as_object_mut() {
                        obj.insert(
                            "tool_calls".to_string(),
                            Value::Array(sanitize_tool_calls_for_history(calls)),
                        );
                    }
                    assistant
                }
                None => message,
            };
            (tool_calls, assistant)
        };

        if let (Some(arr), Some(cfg)) = (tool_calls, tool_loop) {
            messages.push(assistant_message);

            // Summary mode: tools are off; acknowledge any stray calls and let
            // the model reply with its one-line summary.
            if disable_tools {
                for tc in &arr {
                    if let Some(id) = tc.get("id").and_then(|x| x.as_str()) {
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": id,
                            "content": "Tools are disabled now; reply with your one-line summary of the change you made."
                        }));
                    }
                }
                continue;
            }

            // Exploration budget exhausted. If nothing has been edited yet, force
            // the model to make an edit_file call next; otherwise switch to
            // summary mode. (Forcing is safe: a weak edit just gets reverted.)
            if tool_iterations >= cfg.max_iterations && !force_edit {
                let nudge = if cfg.allow_edit && edits_applied == 0 {
                    force_edit = true;
                    "Exploration budget reached. You MUST make at least one edit_file change now."
                } else {
                    disable_tools = true;
                    "Exploration budget reached; reply with your one-line summary of the change you made."
                };
                for tc in &arr {
                    if let Some(id) = tc.get("id").and_then(|x| x.as_str()) {
                        messages
                            .push(json!({"role": "tool", "tool_call_id": id, "content": nudge}));
                    }
                }
                continue;
            }
            tool_iterations += 1;

            for tc in &arr {
                let id = tc
                    .get("id")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow!("tool_calls[].id missing"))?;
                let func = tc
                    .get("function")
                    .ok_or_else(|| anyhow!("tool_calls[].function missing"))?;
                let name = func
                    .get("name")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow!("tool_calls[].function.name missing"))?;
                let args = func
                    .get("arguments")
                    .map(arguments_to_string)
                    .unwrap_or_else(|| "{}".to_string());

                // Always surface the tool call (not just in verbose mode), with
                // the run's cumulative token usage so far appended.
                eprintln!(
                    "{} {}  ({})",
                    color.dim("  ->"),
                    color.cyan(tool_call_label(name, &args)),
                    color.dim(usage.footer_line())
                );

                // Short-circuit identical read-only calls. Re-running them returns
                // the same bytes and re-appends them to the conversation, which is
                // how a stuck model balloons the context; hand back a brief marker
                // instead so it moves on. Write tools are never deduped (a retry
                // with corrected args is legitimate, and they mutate state).
                if !tools::is_write_tool(name)
                    && !seen_tool_calls.insert(format!("{name}\u{0}{args}"))
                {
                    eprintln!(
                        "{} {} {}",
                        color.dim("  <-"),
                        color.cyan(tool_call_label(name, &args)),
                        color.yellow("skipped: identical call already made this turn")
                    );
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "content": "Identical call already executed earlier in this turn; \
                                    its result has not changed and is shown above. Do not \
                                    repeat it - use that result, read a different location, \
                                    or make your edit_file change now.",
                    }));
                    continue;
                }

                let tool_started = Instant::now();
                let out = match tokio::select! {
                    out = tools::execute_tool_async(
                    &cfg.sandbox,
                    cfg.scheds_root.as_deref(),
                    name,
                    &args,
                    cfg.allow_edit,
                    ) => out,
                    _ = interrupt::wait(interrupted.clone()) => return Err(interrupt::err()),
                    _ = tokio::time::sleep(deadline.remaining()) => {
                        return Err(deadline.timeout().into());
                    }
                } {
                    Ok(out) => {
                        let elapsed = tool_started.elapsed();
                        if verbose || elapsed >= SLOW_TOOL_LOG_AFTER {
                            eprintln!(
                                "{} {} done in {:.1}s ({} bytes)",
                                color.dim("  <-"),
                                color.cyan(tool_call_label(name, &args)),
                                elapsed.as_secs_f64(),
                                out.len()
                            );
                        }
                        if tools::is_write_tool(name) {
                            edits_applied += 1;
                        }
                        out
                    }
                    // Never abort on a tool error: hand it back so the model
                    // can retry. These are recoverable and often intermediate
                    // misses (e.g. edit_file old_string mismatches), so show
                    // them as warnings rather than errors in user-facing logs.
                    Err(e) => {
                        // Returned to the model verbatim; the ERROR: prefix
                        // helps it recognize the failed call and retry.
                        let msg = format!("ERROR: {e:#}");
                        // Displayed as a warning (no ERROR: prefix, yellow):
                        // the failure is recoverable, not a hard error.
                        let shown = format!("{e:#}");
                        eprintln!(
                            "{} {} failed after {:.1}s: {}",
                            color.dim("  <-"),
                            color.cyan(tool_call_label(name, &args)),
                            tool_started.elapsed().as_secs_f64(),
                            color.yellow(preview(shown.lines().next().unwrap_or(&shown), 300))
                        );
                        if verbose {
                            eprintln!(
                                "     {}",
                                color.yellow(preview(shown.lines().next().unwrap_or(&shown), 300))
                            );
                        }
                        msg
                    }
                };
                if verbose {
                    eprintln!(
                        "{} {}\n{}",
                        color.dim("[api]"),
                        color.blue(format!("tool result [{name}]:")),
                        preview(&out, 2000)
                    );
                }
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": id,
                    "content": out,
                }));
            }
            // Once a forced edit lands, stop forcing but RESUME normal tool use
            // (tool_choice=auto) so the model is free to make further edits if it
            // wants, then summarize. If it errored (edits still 0), keep
            // force_edit set to retry; the loop-top attempt counter bounds it.
            if force_edit && edits_applied > 0 {
                force_edit = false;
            }
            continue;
        }

        // The model ended its turn with no tool call. If it never edited and we
        // can still force one, push a directive and force edit_file next (covers
        // the model "giving up" before hitting the exploration budget).
        if let Some(cfg) = tool_loop {
            if cfg.allow_edit && edits_applied == 0 && !disable_tools {
                force_edit = true;
                messages.push(assistant_message);
                messages.push(json!({
                    "role": "user",
                    "content": "You have not made any edit yet. Make your edit_file change(s) now - actually call the tool, do not just describe the change."
                }));
                continue;
            }
        }

        let content = message_content_to_string(&assistant_message);
        return Ok(content);
    }
}

/// Convenience: a tool loop config rooted at `sandbox`.
pub fn tool_loop(
    sandbox: &Path,
    scheds_root: Option<&Path>,
    allow_edit: bool,
    max_iterations: u32,
) -> ToolLoopConfig {
    ToolLoopConfig {
        sandbox: sandbox.to_path_buf(),
        scheds_root: scheds_root.map(Path::to_path_buf),
        allow_edit,
        max_iterations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_message_cache_markers() {
        let cached = system_message("SYS", true);
        assert_eq!(cached["content"][0]["text"], "SYS");
        assert_eq!(cached["content"][0]["cache_control"]["type"], "ephemeral");

        let plain = system_message("SYS", false);
        assert_eq!(plain["content"], "SYS");
        assert!(plain["content"].is_string());
    }

    #[test]
    fn api_status_errors_are_classified() {
        let err: anyhow::Error = ApiStatusError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "Already borrowed".to_string(),
        }
        .into();

        assert!(is_api_error(&err));
        assert!(error_summary(&err).contains("Already borrowed"));
    }

    #[test]
    fn tool_call_label_includes_scheduler_for_scheduler_file_reads() {
        let args = json!({
            "scheduler": "scx_rusty",
            "path": "src/bpf/main.bpf.c",
            "start_line": 10,
            "end_line": 40,
        })
        .to_string();
        assert_eq!(
            tool_call_label("read_scheduler_file", &args),
            "read_scheduler_file(scx_rusty/src/bpf/main.bpf.c:10-40)"
        );
    }

    #[test]
    fn tool_call_label_includes_range_for_file_reads() {
        let bounded = json!({
            "path": "src/main.rs",
            "start_line": 20,
            "end_line": 80,
        })
        .to_string();
        assert_eq!(
            tool_call_label("read_file", &bounded),
            "read_file(src/main.rs:20-80)"
        );

        let unbounded = json!({
            "path": "src/main.rs",
        })
        .to_string();
        assert_eq!(
            tool_call_label("read_file", &unbounded),
            "read_file(src/main.rs:1-EOF)"
        );
    }

    #[test]
    fn tool_call_label_includes_scheduler_for_scheduler_grep() {
        let args = json!({
            "scheduler": "scx_lavd",
            "pattern": "vtime",
        })
        .to_string();
        assert_eq!(
            tool_call_label("grep_schedulers", &args),
            "grep_schedulers(scx_lavd:vtime)"
        );
    }

    #[test]
    fn parses_single_text_tool_call() {
        let content = "I'll lower the slice.\n<tool_call>\n{\"name\": \"edit_file\", \"arguments\": {\"path\": \"src/bpf/main.bpf.c\", \"old_string\": \"a\", \"new_string\": \"b\"}}\n</tool_call>";
        let (calls, stripped) = parse_text_tool_calls(content);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["function"]["name"], "edit_file");
        let args: Value =
            serde_json::from_str(calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["path"], "src/bpf/main.bpf.c");
        assert_eq!(calls[0]["type"], "function");
        assert!(calls[0]["id"].as_str().unwrap().starts_with("text_call_"));
        assert_eq!(stripped, "I'll lower the slice.");
    }

    #[test]
    fn parses_multiple_calls_and_unique_ids() {
        let content = "<tool_call>{\"name\":\"grep\",\"arguments\":{\"pattern\":\"x\"}}</tool_call><tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"y\"}}</tool_call>";
        let (calls, stripped) = parse_text_tool_calls(content);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["function"]["name"], "grep");
        assert_eq!(calls[1]["function"]["name"], "read_file");
        assert!(calls[0]["function"]["arguments"].is_string());
        assert!(calls[1]["function"]["arguments"].is_string());
        assert_ne!(calls[0]["id"], calls[1]["id"]);
        assert_eq!(stripped, "");
    }

    #[test]
    fn accepts_parameters_key_and_missing_close_tag() {
        // "parameters" instead of "arguments", and no closing tag.
        let content = "<tool_call>{\"name\":\"list_dir\",\"parameters\":{\"path\":\".\"}}";
        let (calls, _) = parse_text_tool_calls(content);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["function"]["name"], "list_dir");
        let args: Value =
            serde_json::from_str(calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["path"], ".");
    }

    #[test]
    fn normalizes_structured_tool_call_arguments_for_replay() {
        let calls = normalize_tool_calls(vec![json!({
            "id": "call_0",
            "type": "function",
            "function": {
                "name": "list_dir",
                "arguments": {"path": "."},
            },
        })]);

        assert_eq!(calls.len(), 1);
        assert!(calls[0]["function"]["arguments"].is_string());
        let args: Value =
            serde_json::from_str(calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["path"], ".");
    }

    #[test]
    fn normalizes_missing_tool_call_arguments_to_empty_object_string() {
        let calls = normalize_tool_calls(vec![json!({
            "id": "call_0",
            "type": "function",
            "function": {"name": "list_schedulers"},
        })]);

        assert_eq!(calls[0]["function"]["arguments"], "{}");
    }

    #[test]
    fn sanitize_replaces_malformed_tool_call_arguments_but_keeps_valid_ones() {
        // A truncated/unterminated arguments string (as emitted when the model's
        // output is cut off) must be replaced with `{}` so the re-sent history is
        // valid JSON and the next request does not 400; valid calls are untouched.
        let calls = vec![
            json!({
                "id": "bad",
                "type": "function",
                "function": {
                    "name": "edit_file",
                    "arguments": "{\"path\": \"src/main.rs\", \"old_string\": \"void f(",
                },
            }),
            json!({
                "id": "good",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": "{\"path\": \"src/main.rs\"}",
                },
            }),
        ];

        let sanitized = sanitize_tool_calls_for_history(&calls);
        assert_eq!(sanitized[0]["function"]["arguments"], "{}");
        // The original (malformed) call is left intact for execution.
        assert_ne!(calls[0]["function"]["arguments"], "{}");
        // A well-formed call is passed through verbatim.
        assert_eq!(
            sanitized[1]["function"]["arguments"],
            "{\"path\": \"src/main.rs\"}"
        );
    }

    #[test]
    fn assembles_streamed_tool_call_deltas() {
        let mut streamed = StreamedChat::default();

        let visible = apply_stream_delta(
            &json!({
                "content": "I will inspect it.",
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_", "arguments": "{\"path\":\"src"}
                }]
            }),
            &mut streamed,
        )
        .unwrap();
        assert_eq!(visible.as_deref(), Some("I will inspect it."));

        apply_stream_delta(
            &json!({
                "tool_calls": [{
                    "index": 0,
                    "function": {"name": "file", "arguments": "/bpf/main.bpf.c\"}"}
                }]
            }),
            &mut streamed,
        )
        .unwrap();

        let message = streamed.into_message();
        assert_eq!(message["content"], "I will inspect it.");
        assert_eq!(message["tool_calls"][0]["id"], "call_1");
        assert_eq!(message["tool_calls"][0]["function"]["name"], "read_file");
        let args: Value = serde_json::from_str(
            message["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(args["path"], "src/bpf/main.bpf.c");
    }

    #[test]
    fn stream_printer_handles_multibyte_visible_prefix() {
        let mut printer = StreamTextPrinter::new(true);
        printer.push("或许是 **").unwrap();
        printer.finish().unwrap();
    }

    #[test]
    fn stream_printer_handles_multibyte_hidden_tool_call_buffer() {
        let mut printer = StreamTextPrinter::new(true);
        printer.push("<tool_call>或许是 **").unwrap();
        printer.finish().unwrap();
    }

    #[test]
    fn stream_printer_suppresses_whitespace_before_text_tool_call() {
        let mut printer = StreamTextPrinter::new(true);
        printer
            .push("\n\n<tool_call>{\"name\":\"list_dir\"}")
            .unwrap();
        printer.finish().unwrap();

        assert!(!printer.started);
    }

    #[test]
    fn stream_printer_suppresses_whitespace_only_structured_tool_call_text() {
        let mut printer = StreamTextPrinter::new(true);
        printer.push("\n\n").unwrap();
        printer.note_tool_call();
        printer.finish().unwrap();

        assert!(!printer.started);
    }

    #[test]
    fn stream_printer_trims_blank_lines_before_tool_call_after_text() {
        let mut printer = StreamTextPrinter::new(true);
        printer
            .push("Let me inspect:\n\n<tool_call>{\"name\":\"list_dir\"}")
            .unwrap();
        printer.finish().unwrap();

        assert!(printer.started);
        assert!(!printer.last_was_newline);
    }

    #[test]
    fn floor_char_boundary_does_not_split_utf8() {
        let text = "或许是 **";
        assert_eq!(floor_char_boundary(text, 0), 0);
        assert_eq!(floor_char_boundary(text, 1), 0);
        assert_eq!(floor_char_boundary(text, 2), 0);
        assert_eq!(floor_char_boundary(text, 3), 3);
    }

    #[test]
    fn parses_sse_data_events() {
        let event = b"event: ignored\ndata: {\"a\":1}\n\n";
        assert_eq!(sse_data(event).unwrap().as_deref(), Some("{\"a\":1}"));
        let (pos, len) = find_sse_delimiter(event).unwrap();
        assert_eq!(&event[pos..pos + len], b"\n\n");
    }

    #[test]
    fn no_tool_call_text_yields_no_calls() {
        let (calls, stripped) = parse_text_tool_calls("just a plain summary line");
        assert!(calls.is_empty());
        assert_eq!(stripped, "just a plain summary line");
    }

    #[test]
    fn skips_malformed_block() {
        let (calls, _) = parse_text_tool_calls("<tool_call>not json</tool_call>");
        assert!(calls.is_empty());
    }
}
