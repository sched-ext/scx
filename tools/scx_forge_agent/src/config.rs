// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Model configuration from the spec and `SCX_FORGE_*` environment variables,
//! and the backend the agent uses to drive edits.
//!
//! Each role's backend is selected by its `backend` field. `[ai].backend` (and
//! `[ai].coding_backend`) accept either an OpenAI-compatible URL or one of the
//! special keywords `claude`, `codex`, `opencode`, `cursor-agent`, which select
//! that subprocess CLI for the role. The planner and coding roles resolve
//! independently, so they can use different backends (e.g. an `openai` planner
//! with a `claude` coder).
//!
//! For the `openai` backend the built-in HTTP tool loop talks to an
//! OpenAI-compatible endpoint:
//! - planner: `[ai].backend` (or `$SCX_FORGE_BACKEND`), `$SCX_FORGE_API_KEY`
//!   (optional, omit for keyless local backends like Ollama), `[ai].model`.
//! - coding:  `[ai].coding_backend` (or `$SCX_FORGE_CODING_BACKEND`, else the
//!   planner backend), `$SCX_FORGE_CODING_API_KEY` (else `$SCX_FORGE_API_KEY`),
//!   `[ai].coding_model` (else `[ai].model`).
//!
//! Spec values take precedence over the matching env var. The `SCX_FORGE_*`
//! names are deliberately agent-specific so they do not collide with the
//! `OPENAI_*` vars that subprocess CLIs (e.g. codex) read for their own auth.
//!
//! For the subprocess backends (`claude`, `opencode`, `codex`, `cursor-agent`)
//! the agent shells out to that CLI to make the edits. Those CLIs use their own
//! native auth/config (each reads whatever it documents, e.g. `OPENAI_*` for
//! codex, `ANTHROPIC_*` for claude, `CURSOR_API_KEY` for cursor-agent) from the
//! inherited environment. `[ai].model` /
//! `[ai].coding_model` are still honored and passed to the CLI as its model id
//! (e.g. `haiku` for claude); leave them unset to use the CLI's own default.
//! When a subprocess planner and the coder are the same backend+model it plans
//! and edits in one shot; when they differ the planner runs read-only in plan
//! mode (see [`crate::agent_cli::Mode`]) and hands its plan to the coder.

use anyhow::{Context, Result};

/// Which mechanism the agent uses to produce each round's edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Built-in HTTP chat/completions tool loop (default).
    OpenAi,
    /// Shell out to the `claude` CLI.
    Claude,
    /// Shell out to the `opencode` CLI (`opencode run`).
    Opencode,
    /// Shell out to the `codex` CLI (`codex exec`).
    Codex,
    /// Shell out to the `cursor-agent` CLI (`cursor-agent --print`).
    Cursor,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::OpenAi => "openai",
            Backend::Claude => "claude",
            Backend::Opencode => "opencode",
            Backend::Codex => "codex",
            Backend::Cursor => "cursor-agent",
        }
    }

    /// True for the CLI-subprocess backends (everything except the built-in HTTP loop).
    pub fn is_subprocess(self) -> bool {
        !matches!(self, Backend::OpenAi)
    }

    /// Map a `backend` field value to a backend: the keywords `claude`, `codex`,
    /// `opencode`, and `cursor-agent` (also `cursor`) select that subprocess CLI;
    /// anything else (a URL) is the built-in `openai` backend.
    pub fn from_value(value: &str) -> Backend {
        match value.trim().to_ascii_lowercase().as_str() {
            "claude" => Backend::Claude,
            "codex" => Backend::Codex,
            "opencode" => Backend::Opencode,
            "cursor-agent" | "cursor" => Backend::Cursor,
            _ => Backend::OpenAi,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub backend: Backend,
    /// Model id. Required for `openai`; optional for subprocess backends (empty =
    /// let the CLI choose its own default).
    pub model_id: String,
    pub base_url: String,
    pub api_key: String,
}

impl ModelConfig {
    /// True when two roles resolve to the same backend, model, and endpoint. When
    /// the planner and coder are identical there is no point running a separate
    /// planning turn: a subprocess planner already plans and edits in one shot.
    pub fn same_endpoint(&self, other: &ModelConfig) -> bool {
        self.backend == other.backend
            && self.model_id == other.model_id
            && self.base_url == other.base_url
    }
}

#[derive(Debug, Clone)]
pub struct ModelRoles {
    pub planner: ModelConfig,
    pub coding: ModelConfig,
}

/// Strip trailing slashes and an optional `/v1`, then append `/v1`.
fn normalize_base_url(raw: &str) -> String {
    let mut s = raw.trim().trim_end_matches('/').to_string();
    if let Some(without) = s.strip_suffix("/v1") {
        s = without.trim_end_matches('/').to_string();
    }
    format!("{}/v1", s.trim_end_matches('/'))
}

fn trimmed_nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// Read and trim an environment variable, returning `None` when unset or empty.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Normalize a base URL and reject one that is empty after trimming.
fn normalize_checked(raw: &str) -> Result<String> {
    let url = normalize_base_url(raw);
    if url.is_empty() || url == "/v1" {
        anyhow::bail!("base URL is set but empty after trim: {raw:?}");
    }
    Ok(url)
}

/// Resolve one role's [`ModelConfig`] from its `backend` field value.
///
/// The model id comes from `spec_model`, else it inherits `fallback` (the
/// planner) when that role runs on the *same* backend. The model is optional for
/// subprocess CLIs (empty -> the CLI's own default; a value like `haiku` is
/// passed to the CLI) and required for the `openai` backend. For `openai` the
/// URL and API key are also resolved; the coding API key falls back to the
/// planner's.
fn resolve_role(
    role: &str,
    backend_value: &str,
    spec_model: Option<&str>,
    api_key_env: &str,
    fallback: Option<&ModelConfig>,
) -> Result<ModelConfig> {
    let backend = Backend::from_value(backend_value);

    // Inherit the planner's model only when this role uses the same backend; a
    // model id is backend-specific, so it must not leak across backends.
    let model_id = trimmed_nonempty(spec_model).or_else(|| {
        fallback
            .filter(|f| f.backend == backend)
            .map(|f| f.model_id.clone())
            .filter(|s| !s.is_empty())
    });

    if backend.is_subprocess() {
        return Ok(ModelConfig {
            backend,
            model_id: model_id.unwrap_or_default(),
            base_url: String::new(),
            api_key: String::new(),
        });
    }

    let model_id = model_id
        .with_context(|| format!("set the {role} model ([ai].model / [ai].coding_model)"))?;
    let api_key = env_nonempty(api_key_env)
        .or_else(|| fallback.map(|f| f.api_key.clone()))
        .unwrap_or_default();
    Ok(ModelConfig {
        backend,
        model_id,
        base_url: normalize_checked(backend_value)?,
        api_key,
    })
}

/// Resolve both model roles. Each role's backend is selected by its `backend`
/// value (a URL -> `openai`; the keywords `claude`/`codex`/`opencode` -> that
/// subprocess CLI), so the planner and coder can run on different backends.
///
/// - planner: `backend` (or `$SCX_FORGE_BACKEND`), `$SCX_FORGE_API_KEY`, `model`.
/// - coding:  `coding_backend` (or `$SCX_FORGE_CODING_BACKEND`, else the planner
///   backend value), `$SCX_FORGE_CODING_API_KEY` (else `$SCX_FORGE_API_KEY`),
///   `coding_model` (else `model`).
pub fn resolve_roles_from_env(
    spec_backend: Option<&str>,
    spec_model: Option<&str>,
    spec_coding_backend: Option<&str>,
    spec_coding_model: Option<&str>,
) -> Result<ModelRoles> {
    let planner_backend = trimmed_nonempty(spec_backend)
        .or_else(|| env_nonempty("SCX_FORGE_BACKEND"))
        .context(
            "set [ai].backend or $SCX_FORGE_BACKEND (an OpenAI-compatible API base URL, or one of: claude, codex, opencode, cursor-agent)",
        )?;
    let planner = resolve_role(
        "planner",
        &planner_backend,
        spec_model,
        "SCX_FORGE_API_KEY",
        None,
    )?;

    // Coding backend value: spec, env, else inherit the planner's value.
    let coding_backend = trimmed_nonempty(spec_coding_backend)
        .or_else(|| env_nonempty("SCX_FORGE_CODING_BACKEND"))
        .unwrap_or_else(|| planner_backend.clone());
    let coding = resolve_role(
        "coding",
        &coding_backend,
        spec_coding_model,
        "SCX_FORGE_CODING_API_KEY",
        Some(&planner),
    )?;

    Ok(ModelRoles { planner, coding })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_selects_backend() {
        assert_eq!(Backend::from_value("claude"), Backend::Claude);
        assert_eq!(Backend::from_value(" CODEX "), Backend::Codex);
        assert_eq!(Backend::from_value("opencode"), Backend::Opencode);
        assert_eq!(Backend::from_value("cursor-agent"), Backend::Cursor);
        assert_eq!(Backend::from_value("cursor"), Backend::Cursor);
        assert_eq!(
            Backend::from_value("http://localhost:11434/v1"),
            Backend::OpenAi
        );
    }

    #[test]
    fn resolve_role_subprocess_passes_model_or_defaults() {
        // An explicit model id is forwarded to the CLI.
        let cfg = resolve_role(
            "planner",
            "claude",
            Some("haiku"),
            "SCX_FORGE_API_KEY",
            None,
        )
        .unwrap();
        assert_eq!(cfg.backend, Backend::Claude);
        assert_eq!(cfg.model_id, "haiku");
        assert!(cfg.base_url.is_empty());

        // No model id -> empty, i.e. the CLI's own default.
        let cfg = resolve_role("planner", "codex", None, "SCX_FORGE_API_KEY", None).unwrap();
        assert_eq!(cfg.backend, Backend::Codex);
        assert!(cfg.model_id.is_empty());
    }

    #[test]
    fn resolve_role_does_not_inherit_model_across_backends() {
        let planner = resolve_role(
            "planner",
            "http://example.com",
            Some("openai-model"),
            "SCX_FORGE_API_KEY",
            None,
        )
        .unwrap();
        // A claude coder must not inherit the openai planner's model id.
        let coding = resolve_role(
            "coding",
            "claude",
            None,
            "SCX_FORGE_CODING_API_KEY",
            Some(&planner),
        )
        .unwrap();
        assert_eq!(coding.backend, Backend::Claude);
        assert!(coding.model_id.is_empty());
    }

    #[test]
    fn resolve_role_openai_resolves_url_and_inherits_model() {
        let planner = resolve_role(
            "planner",
            "http://example.com",
            Some("planner-model"),
            "SCX_FORGE_API_KEY",
            None,
        )
        .unwrap();
        assert_eq!(planner.backend, Backend::OpenAi);
        assert_eq!(planner.model_id, "planner-model");
        assert_eq!(planner.base_url, "http://example.com/v1");

        // Coding inherits the planner's model when its own is unset.
        let coding = resolve_role(
            "coding",
            "http://coder.example.com/v1/",
            None,
            "SCX_FORGE_CODING_API_KEY",
            Some(&planner),
        )
        .unwrap();
        assert_eq!(coding.model_id, "planner-model");
        assert_eq!(coding.base_url, "http://coder.example.com/v1");
    }

    #[test]
    fn normalize_checked_appends_v1_and_rejects_empty() {
        assert_eq!(
            normalize_checked("https://example.com").unwrap(),
            "https://example.com/v1"
        );
        assert_eq!(
            normalize_checked("https://example.com/v1/").unwrap(),
            "https://example.com/v1"
        );
        assert!(normalize_checked("   ").is_err());
    }
}
