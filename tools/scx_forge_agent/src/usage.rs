// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Token-usage accounting summed across the whole optimization run, plus the
//! one-line footer (`prompt:24.3k  tokens:515`) printed at the bottom of the
//! output. The footer shape mirrors boro's progress UI.
//!
//! `prompt` is the cumulative input-token count across every model request the
//! run made (each tool-loop iteration resends the growing message history, so it
//! grows fast); `completion` is the cumulative output tokens. `cache_read` /
//! `cache_creation` are shown only when nonzero (prompt-cache hits/writes).

use serde_json::{json, Value};

#[derive(Debug, Default, Clone, Copy)]
pub struct Usage {
    pub prompt: u64,
    pub completion: u64,
    pub cache_read: u64,
    pub cache_creation: u64,
}

impl Usage {
    pub fn add(&mut self, other: &Usage) {
        self.prompt += other.prompt;
        self.completion += other.completion;
        self.cache_read += other.cache_read;
        self.cache_creation += other.cache_creation;
    }

    /// Parse an OpenAI-style `usage` object:
    /// `{ prompt_tokens, completion_tokens, prompt_tokens_details: { cached_tokens } }`.
    pub fn from_openai(usage: &Value) -> Usage {
        let g = |k: &str| usage.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let cache_read = usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Usage {
            prompt: g("prompt_tokens"),
            completion: g("completion_tokens"),
            cache_read,
            cache_creation: 0,
        }
    }

    /// Parse an Anthropic-style `usage` object (the `claude` CLI result event):
    /// `{ input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens }`.
    pub fn from_anthropic(usage: &Value) -> Usage {
        let g = |k: &str| usage.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        Usage {
            prompt: g("input_tokens"),
            completion: g("output_tokens"),
            cache_read: g("cache_read_input_tokens"),
            cache_creation: g("cache_creation_input_tokens"),
        }
    }

    /// Parse a `cursor-agent` result-event `usage` object (camelCase):
    /// `{ inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens }`.
    pub fn from_cursor(usage: &Value) -> Usage {
        let g = |k: &str| usage.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        Usage {
            prompt: g("inputTokens"),
            completion: g("outputTokens"),
            cache_read: g("cacheReadTokens"),
            cache_creation: g("cacheWriteTokens"),
        }
    }

    /// Parse a `usage` object that may be in either OpenAI or Anthropic shape
    /// (used for subprocess backends whose event schema is less certain).
    pub fn from_any(usage: &Value) -> Usage {
        if usage.get("prompt_tokens").is_some() || usage.get("completion_tokens").is_some() {
            Usage::from_openai(usage)
        } else {
            Usage::from_anthropic(usage)
        }
    }

    pub fn to_json(self) -> Value {
        json!({
            "prompt": self.prompt,
            "completion": self.completion,
            "cache_read": self.cache_read,
            "cache_creation": self.cache_creation,
        })
    }

    /// One-line footer: `prompt:24.3k  tokens:515` (cache_r/cache_w shown only
    /// when nonzero).
    pub fn footer_line(&self) -> String {
        let mut s = format!("prompt:{}", fmt_tokens(self.prompt));
        if self.cache_read > 0 || self.cache_creation > 0 {
            s.push_str(&format!(
                "  cache_r:{}  cache_w:{}",
                fmt_tokens(self.cache_read),
                fmt_tokens(self.cache_creation),
            ));
        }
        s.push_str(&format!("  tokens:{}", fmt_tokens(self.completion)));
        s
    }
}

/// Compact token count: exact below 1000, else scaled to k/M/G with one decimal
/// (a trailing `.0` is dropped). Matches boro's footer formatting.
fn fmt_tokens(n: u64) -> String {
    const K: f64 = 1000.0;
    if n < 1000 {
        return n.to_string();
    }
    if n < 1_000_000 {
        return fmt_scaled(n as f64 / K, "k");
    }
    if n < 1_000_000_000 {
        return fmt_scaled(n as f64 / (K * K), "M");
    }
    fmt_scaled(n as f64 / (K * K * K), "G")
}

fn fmt_scaled(value: f64, suffix: &str) -> String {
    let t = (value * 10.0).round() / 10.0;
    if (t - t.floor()).abs() < 0.001 {
        format!("{}{}", t as u64, suffix)
    } else {
        format!("{t:.1}{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn footer_shape_matches_boro() {
        let u = Usage {
            prompt: 1234,
            completion: 56,
            ..Default::default()
        };
        assert_eq!(u.footer_line(), "prompt:1.2k  tokens:56");
        let u = Usage {
            prompt: 1234,
            completion: 56,
            cache_read: 90,
            cache_creation: 78,
        };
        assert_eq!(
            u.footer_line(),
            "prompt:1.2k  cache_r:90  cache_w:78  tokens:56"
        );
    }

    #[test]
    fn fmt_tokens_scales() {
        assert_eq!(fmt_tokens(515), "515");
        assert_eq!(fmt_tokens(999), "999");
        assert_eq!(fmt_tokens(24_300), "24.3k");
        assert_eq!(fmt_tokens(2000), "2k"); // trailing .0 dropped
        assert_eq!(fmt_tokens(1_500_000), "1.5M");
    }

    #[test]
    fn add_sums_fields() {
        let mut a = Usage {
            prompt: 10,
            completion: 1,
            cache_read: 2,
            cache_creation: 3,
        };
        a.add(&Usage {
            prompt: 5,
            completion: 4,
            cache_read: 6,
            cache_creation: 7,
        });
        assert_eq!(
            (a.prompt, a.completion, a.cache_read, a.cache_creation),
            (15, 5, 8, 10)
        );
    }

    #[test]
    fn parse_openai_and_anthropic() {
        let o = Usage::from_openai(&json!({
            "prompt_tokens": 100, "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 80}
        }));
        assert_eq!((o.prompt, o.completion, o.cache_read), (100, 20, 80));
        let a = Usage::from_anthropic(&json!({
            "input_tokens": 7, "output_tokens": 9,
            "cache_read_input_tokens": 11, "cache_creation_input_tokens": 13
        }));
        assert_eq!(
            (a.prompt, a.completion, a.cache_read, a.cache_creation),
            (7, 9, 11, 13)
        );
    }

    #[test]
    fn parse_cursor() {
        let c = Usage::from_cursor(&json!({
            "inputTokens": 12660, "outputTokens": 93,
            "cacheReadTokens": 23872, "cacheWriteTokens": 5
        }));
        assert_eq!(
            (c.prompt, c.completion, c.cache_read, c.cache_creation),
            (12660, 93, 23872, 5)
        );
    }
}
