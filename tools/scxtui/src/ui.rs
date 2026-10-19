// SPDX-License-Identifier: GPL-2.0

//! Rendering. Almost a pure function of the [`App`] state — the one
//! exception is the log view writing its viewport height and clamped scroll
//! offset back into the app, so paging and bounds always match the actual
//! terminal size.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, ArgsInput, View};
use crate::logs;

const SCHED_PREFIX: &str = "scx_";

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(3),
        ],
    )
    .areas(frame.area());

    draw_header(frame, app, header);

    match app.view {
        View::Schedulers => {
            let [left, right] = Layout::new(
                Direction::Horizontal,
                [Constraint::Percentage(40), Constraint::Percentage(60)],
            )
            .areas(body);
            draw_scheduler_list(frame, app, left);
            draw_status_panel(frame, app, right);
        }
        View::Logs => draw_logs(frame, app, body),
    }

    draw_footer(frame, app, footer);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            " scxtui ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" backend: "),
        Span::styled(app.backend_label(), Style::default().fg(Color::Cyan)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_scheduler_list(frame: &mut Frame, app: &App, area: Rect) {
    let current = app
        .status
        .as_ref()
        .and_then(crate::backend::Status::running);

    let items: Vec<ListItem> = app
        .schedulers
        .iter()
        .map(|sched| {
            let is_running = Some(sched.as_str()) == current;
            let marker = if is_running { "● " } else { "  " };
            let style = if is_running {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(Color::Green)),
                Span::styled(strip_prefix(sched), style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Schedulers "))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_status_panel(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    match &app.status {
        Some(status) => {
            // What runs now: the unit's process, never the file.
            match (status.active, &status.process) {
                (true, Some(process)) => {
                    lines.push(kv("State", "running", Color::Green));
                    lines.push(kv("Scheduler", strip_prefix(&process.sched), Color::White));
                    let mode = match app.running_mode() {
                        Some(mode) => format!("{} profile", mode.label()),
                        None if process.args.is_empty() => "no flags".to_owned(),
                        None => "custom flags".to_owned(),
                    };
                    let args = if process.args.is_empty() {
                        mode
                    } else {
                        format!("{mode}: {}", format_flags(&process.args))
                    };
                    lines.push(kv("Running with", &args, Color::White));
                }
                (true, None) => lines.push(kv(
                    "State",
                    "scx.service active, process not readable",
                    Color::Yellow,
                )),
                (false, _) => lines.push(kv("State", "scx.service inactive", Color::Yellow)),
            }

            // What the next start would run: file plus overrides.
            // An incompletely resolved environment is not shown as a
            // hypothesis: a partial answer reads as a fact.
            if let Some(err) = &status.config_error {
                lines.push(kv("Next start", "unknown", Color::Red));
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ {err}"),
                    Style::default().fg(Color::Red),
                )));
            } else {
                let next = match &status.next_sched {
                    Some(sched) if status.next_flags.is_empty() => strip_prefix(sched).to_owned(),
                    Some(sched) => format!(
                        "{} {}",
                        strip_prefix(sched),
                        format_flags(&status.next_flags)
                    ),
                    None => "nothing configured".to_owned(),
                };
                let next_color = match (status.running(), status.next_sched.as_deref()) {
                    // Config edited under the unit: a restart changes things.
                    (Some(running), Some(next)) if running != next => Color::Yellow,
                    _ => Color::White,
                };
                lines.push(kv("Next start", &next, next_color));
            }
            if let Some(sched) = &status.override_sched {
                lines.push(kv(
                    "Override",
                    &format!("SCX_SCHEDULER_OVERRIDE={}", strip_prefix(sched)),
                    Color::Yellow,
                ));
            }
            if let Some(flags) = &status.override_flags {
                lines.push(kv(
                    "Override",
                    &format!("SCX_FLAGS_OVERRIDE={}", format_flags(flags)),
                    Color::Yellow,
                ));
            }
        }
        None => {
            let reason = app
                .status_error
                .as_deref()
                .map_or_else(|| "unknown".to_owned(), |err| format!("unknown — {err}"));
            lines.push(kv("State", &reason, Color::Red));
        }
    }

    lines.push(Line::default());
    draw_kernel_section(app, &mut lines);

    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("Profile: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("◀ {} ▶", app.selected_mode().label()),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  (Tab to cycle)"),
    ]));
    // Preview of what Enter would write to SCX_FLAGS for this selection.
    let flags = app.selected_flags();
    let preview = if flags.is_empty() {
        "  no flags — scheduler defaults".to_owned()
    } else {
        format!("  {}", format_flags(&flags))
    };
    lines.push(Line::from(Span::styled(
        preview,
        Style::default().fg(Color::Gray),
    )));
    let source = app.profiles.source.as_deref().map_or_else(
        || "built-in defaults".to_owned(),
        |path| path.display().to_string(),
    );
    lines.push(Line::from(Span::styled(
        format!("  profiles from {source}"),
        Style::default().fg(Color::DarkGray),
    )));

    if let Some(input) = &app.args_input {
        lines.push(Line::default());
        let mut spans = vec![Span::styled(
            "Args: ",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        spans.extend(input_spans(input));
        lines.push(Line::from(spans));
        lines.push(Line::from(Span::styled(
            "  written to SCX_FLAGS as typed, whitespace-separated; replaces the profile's flags",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let panel = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" Status "));
    frame.render_widget(panel, area);
}

fn draw_logs(frame: &mut Frame, app: &mut App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    app.log_page = height.max(1);

    let total = app.log_lines.len();
    let max_scroll = total.saturating_sub(height);
    // Clamp and write back, so `g` (jump to top, scroll = MAX) and paging
    // past the ends settle on real bounds.
    if app.log_scroll > max_scroll {
        app.log_scroll = max_scroll;
    }
    let end = total - app.log_scroll;
    let start = end.saturating_sub(height);

    let lines: Vec<Line> = app.log_lines[start..end]
        .iter()
        .map(|line| {
            if line.continuation {
                Line::from(Span::styled(
                    format!("           ↳ {}", line.text),
                    Style::default().fg(Color::DarkGray),
                ))
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("{:8} ", line.time),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(line.text.clone(), priority_style(line.priority)),
                ])
            }
        })
        .collect();

    let boot = if app.log_previous_boot {
        "-1 (previous)"
    } else {
        "0 (current)"
    };
    let title = format!(" Logs — {} · boot {} · {} lines ", logs::UNIT, boot, total);

    let panel = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(Style::default().add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(panel, area);
}

/// The kernel-truth section: what `sched_ext` itself reports, plus soft
/// warnings whenever it disagrees with what the unit state implies. The
/// service only knows whether its unit is active; the kernel knows what
/// is actually attached.
fn draw_kernel_section(app: &App, lines: &mut Vec<Line>) {
    let Some(kernel) = &app.kernel else {
        lines.push(kv(
            "Kernel",
            "sched_ext not available in this kernel",
            Color::DarkGray,
        ));
        return;
    };

    let ops_suffix = kernel
        .ops
        .as_deref()
        .map(|ops| format!(" · ops: {ops}"))
        .unwrap_or_default();
    let color = if kernel.enabled() {
        Color::Green
    } else {
        Color::White
    };
    lines.push(kv(
        "Kernel",
        &format!("sched_ext {}{}", kernel.state, ops_suffix),
        color,
    ));

    // Classification lives on App (`kernel_warning`), shared with the
    // event loop's dispute tripwire.
    if let Some(text) = app.kernel_warning() {
        lines.push(Line::from(Span::styled(
            format!("  ⚠ {text}"),
            Style::default().fg(Color::Yellow),
        )));
    }
}

fn priority_style(priority: u8) -> Style {
    match priority {
        0..=3 => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        4 => Style::default().fg(Color::Yellow),
        7 => Style::default().fg(Color::DarkGray),
        _ => Style::default(),
    }
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let [keys_area, message_area] = Layout::new(
        Direction::Vertical,
        [Constraint::Length(1), Constraint::Length(2)],
    )
    .areas(area);

    let key_help = match app.view {
        View::Schedulers if app.args_input.is_some() => {
            " type arguments · Enter start/switch · Esc cancel"
        }
        View::Schedulers => {
            " ↑/↓ select · Tab profile · Enter start/switch · a args · s stop · r restart · d default · l logs · t monitor · R refresh · q quit"
        }
        View::Logs => {
            " ↑/↓ scroll · PgUp/PgDn page · g/G top/bottom · b boot · R reload · q/Esc back"
        }
    };

    let keys = Line::from(Span::styled(key_help, Style::default().fg(Color::DarkGray)));
    frame.render_widget(Paragraph::new(keys), keys_area);

    if let Some(message) = &app.message {
        let color = if message.is_error {
            Color::Red
        } else {
            Color::Green
        };
        let line = Line::from(Span::styled(
            format!(" {}", message.text),
            Style::default().fg(color),
        ));
        frame.render_widget(
            Paragraph::new(line).wrap(Wrap { trim: false }),
            message_area,
        );
    }
}

fn kv<'a>(key: &'a str, value: &str, value_color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{key}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_owned(), Style::default().fg(value_color)),
    ])
}

fn strip_prefix(sched: &str) -> &str {
    sched.strip_prefix(SCHED_PREFIX).unwrap_or(sched)
}

/// Renders the field content with a reversed-video block as the cursor.
/// A styled span instead of the real terminal cursor keeps the position
/// correct under the paragraph's wrapping without any coordinate math;
/// at the end of the buffer the block sits on a synthetic space.
fn input_spans(input: &ArgsInput) -> Vec<Span<'static>> {
    let mut before = String::new();
    let mut at = None;
    let mut after = String::new();
    for (i, c) in input.buffer.chars().enumerate() {
        match i.cmp(&input.cursor) {
            std::cmp::Ordering::Less => before.push(c),
            std::cmp::Ordering::Equal => at = Some(c),
            std::cmp::Ordering::Greater => after.push(c),
        }
    }
    let cursor = at.map_or_else(|| " ".to_owned(), |c| c.to_string());
    vec![
        Span::raw(before),
        Span::styled(cursor, Style::default().add_modifier(Modifier::REVERSED)),
        Span::raw(after),
    ]
}

/// Renders the flag vector so token boundaries survive spaces and quotes:
/// `shell_words::join`, whose output parses back into the same vector.
fn format_flags(flags: &[String]) -> String {
    shell_words::join(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_format_round_trips() {
        let flags = ["--name", "foo bar", "", "a'b"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(shell_words::split(&format_flags(&flags)), Ok(flags));
    }
}
