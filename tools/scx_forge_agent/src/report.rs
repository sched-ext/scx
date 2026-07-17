// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Optimization run report: per-round history table, markdown and JSON renderers.

use serde_json::{json, Value};

use crate::usage::Usage;

#[derive(Debug, Clone)]
pub struct RoundRecord {
    pub round: u32,
    /// One-line change summary from the model.
    pub summary: String,
    /// Terminal outcome: "kept", "reverted", "build-failed", "attach-failed",
    /// "metric-failed", "no-edit", "duplicate", "ineffective", "api-error",
    /// or "interrupted".
    pub outcome: String,
    pub value: Option<f64>,
    pub delta: Option<f64>,
    /// Direction-normalized improvement: positive is better for both minimize
    /// and maximize objectives.
    pub improvement: Option<f64>,
    pub policy_area: String,
    pub direction: String,
    pub kept: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub objective: String,
    pub goal: String,
    pub metric_name: String,
    pub start_value: Option<f64>,
    pub best_value: Option<f64>,
    pub best_round: Option<u32>,
    pub rounds: Vec<RoundRecord>,
    /// Token usage summed across every model call the run made.
    pub usage: Usage,
}

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.3}"),
        None => "-".to_string(),
    }
}

/// Left-pad `s` to `width` display columns (right-aligned).
fn pad_left(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width {
        s.to_string()
    } else {
        format!("{}{s}", " ".repeat(width - n))
    }
}

/// Right-pad `s` to `width` display columns (left-aligned).
fn pad_right(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - n))
    }
}

impl Report {
    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("# scx_forge_agent optimization report\n\n");
        s.push_str(&format!(
            "- Objective: **{} {}**\n",
            self.goal, self.metric_name
        ));
        s.push_str(&format!(
            "- Starting scheduler value: {}\n",
            fmt_opt(self.start_value)
        ));
        s.push_str(&format!(
            "- Best scheduler value: {}{}\n",
            fmt_opt(self.best_value),
            match self.best_round {
                Some(r) => format!(" (round {r})"),
                None => String::new(),
            }
        ));
        if let (Some(start), Some(best)) = (self.start_value, self.best_value) {
            if start != 0.0 {
                let pct = if self.goal == "minimize" {
                    (start - best) / start * 100.0
                } else {
                    (best - start) / start * 100.0
                };
                s.push_str(&format!("- Improvement over start: {pct:.2}%\n"));
            }
        }
        s.push('\n');

        // Aligned table: pad the short columns to their content width (numeric
        // ones right-aligned) so it lines up in a terminal; the free-form Change
        // column is left unpadded as the last column. Still valid markdown.
        let cells: Vec<[String; 5]> = self
            .rounds
            .iter()
            .map(|r| {
                [
                    r.round.to_string(),
                    r.outcome.clone(),
                    fmt_opt(r.value),
                    fmt_opt(r.delta),
                    r.summary.replace('|', "\\|").replace('\n', " "),
                ]
            })
            .collect();

        let width = |col: usize, header: &str| -> usize {
            cells
                .iter()
                .map(|c| c[col].chars().count())
                .chain(std::iter::once(header.chars().count()))
                .max()
                .unwrap_or(0)
        };
        let (wr, wo, wv, wd) = (
            width(0, "Round"),
            width(1, "Outcome"),
            width(2, "Value"),
            width(3, "Δ"),
        );

        // header + alignment separator (`---:` = right-aligned in markdown).
        s.push_str(&format!(
            "| {} | {} | {} | {} | Change |\n",
            pad_left("Round", wr),
            pad_right("Outcome", wo),
            pad_left("Value", wv),
            pad_left("Δ", wd),
        ));
        s.push_str(&format!(
            "|{}:|{}|{}:|{}:|--------|\n",
            "-".repeat(wr + 1),
            "-".repeat(wo + 2),
            "-".repeat(wv + 1),
            "-".repeat(wd + 1),
        ));
        for c in &cells {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                pad_left(&c[0], wr),
                pad_right(&c[1], wo),
                pad_left(&c[2], wv),
                pad_left(&c[3], wd),
                c[4],
            ));
        }
        s
    }

    pub fn to_json(&self) -> Value {
        json!({
            "objective": self.objective,
            "goal": self.goal,
            "metric_name": self.metric_name,
            "start_value": self.start_value,
            "best_value": self.best_value,
            "best_round": self.best_round,
            "rounds": self.rounds.iter().map(|r| json!({
                "round": r.round,
                "outcome": r.outcome,
                "value": r.value,
                "delta": r.delta,
                "improvement": r.improvement,
                "policy_area": r.policy_area,
                "direction": r.direction,
                "kept": r.kept,
                "summary": r.summary,
            })).collect::<Vec<_>>(),
            "usage": self.usage.to_json(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        round: u32,
        outcome: &str,
        value: Option<f64>,
        delta: Option<f64>,
        s: &str,
    ) -> RoundRecord {
        RoundRecord {
            round,
            summary: s.to_string(),
            outcome: outcome.to_string(),
            value,
            delta,
            improvement: delta.map(|d| -d),
            policy_area: "slice".into(),
            direction: "test_direction".into(),
            kept: outcome == "kept",
        }
    }

    #[test]
    fn table_columns_are_aligned() {
        let rep = Report {
            objective: "minimize p99".into(),
            goal: "minimize".into(),
            metric_name: "p99_wakeup_latency_us".into(),
            start_value: Some(5224.0),
            best_value: Some(5208.0),
            best_round: Some(3),
            rounds: vec![
                rec(1, "no-edit", None, None, "<tool_call>"),
                rec(
                    2,
                    "reverted",
                    Some(5224.0),
                    Some(0.0),
                    "Reduced SLEEP_VLAG_LIMIT_NS from 20ms to 5ms.",
                ),
                rec(
                    3,
                    "kept",
                    Some(5208.0),
                    Some(-16.0),
                    "Reduced SLEEP_VLAG_LIMIT_NS from 20ms to 10ms.",
                ),
            ],
            usage: Usage::default(),
        };
        let out = rep.render_markdown();
        let table: Vec<&str> = out.lines().filter(|l| l.starts_with('|')).collect();
        // header + separator + 3 rows
        assert_eq!(table.len(), 5);
        // Column boundaries ('|') must line up across rows by DISPLAY column (char
        // position, not byte offset - the Δ header is multibyte).
        let pipes = |l: &str| -> Vec<usize> {
            l.chars()
                .enumerate()
                .filter(|(_, c)| *c == '|')
                .map(|(i, _)| i)
                .collect()
        };
        let header_pipes = pipes(table[0]);
        // first 5 pipe positions (the 4 padded columns) must match on every row.
        for line in &table {
            let p = pipes(line);
            assert!(p.len() >= 5, "row has too few columns: {line}");
            assert_eq!(&p[..5], &header_pipes[..5], "misaligned row: {line}");
        }
    }
}
