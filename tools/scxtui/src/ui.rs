// SPDX-License-Identifier: GPL-2.0

//! Rendering. Almost a pure function of the [`App`] state; the one
//! exception is the log view writing its viewport height and clamped
//! scroll offset back into the app.

use crate::model::{Current, DEFAULT_ID, Entry};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, Field, Input, View};
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
        View::Profiles | View::Advanced => {
            let [left, right] = Layout::new(
                Direction::Horizontal,
                [Constraint::Percentage(45), Constraint::Percentage(55)],
            )
            .areas(body);
            if app.view == View::Profiles {
                draw_profile_list(frame, app, left);
            } else {
                draw_scheduler_list(frame, app, left);
            }
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
        Span::raw(" via "),
        Span::styled(app.backend_label(), Style::default().fg(Color::Cyan)),
        Span::raw(if app.view == View::Advanced {
            "  advanced"
        } else {
            ""
        }),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn backing(entry: &Entry) -> String {
    match (&entry.action, &entry.sched) {
        (Some(_), _) => "kernel default".to_owned(),
        (None, Some(sched)) if entry.args.is_empty() => strip_prefix(sched).to_owned(),
        (None, Some(sched)) => format!("{} {}", strip_prefix(sched), entry.args.join(" ")),
        _ => String::new(),
    }
}

fn draw_profile_list(frame: &mut Frame, app: &App, area: Rect) {
    let running = app
        .listing
        .as_ref()
        .and_then(|l| l.current.profile.as_deref());
    let items: Vec<ListItem> = app
        .profiles()
        .iter()
        .map(|entry| {
            let is_running = Some(entry.id.as_str()) == running;
            let marker = if is_running { "● " } else { "  " };
            let style = if is_running {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else if !entry.available {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let mut lines = vec![Line::from(vec![
                Span::styled(marker, Style::default().fg(Color::Green)),
                Span::styled(entry.label.clone(), style),
                Span::styled(
                    if entry.available {
                        String::new()
                    } else {
                        "  (not installed)".to_owned()
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ])];
            lines.push(Line::from(Span::styled(
                format!("    {}", backing(entry)),
                Style::default().fg(Color::DarkGray),
            )));
            if !entry.description.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("    {}", entry.description),
                    Style::default().fg(Color::Gray),
                )));
            }
            ListItem::new(lines)
        })
        .collect();

    let title = match &app.listing {
        Some(l) if l.customized => " Profiles (administrator's list) ",
        _ => " Profiles ",
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_scheduler_list(frame: &mut Frame, app: &App, area: Rect) {
    let running = app
        .listing
        .as_ref()
        .and_then(|l| l.current.running.as_ref())
        .map(|r| r.sched.as_str());
    let items: Vec<ListItem> = app
        .installed()
        .iter()
        .map(|sched| {
            let is_running = Some(sched.as_str()) == running;
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Schedulers (advanced) "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = ListState::default().with_selected(Some(app.sched_selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn state_line(current: &Current) -> (String, Color) {
    match (&current.profile, current.custom, &current.applied) {
        (Some(id), _, _) if id == DEFAULT_ID => {
            ("default: the kernel's scheduler".to_owned(), Color::White)
        }
        (Some(id), _, _) => (format!("profile {id} running"), Color::Green),
        (None, true, _) => (
            "custom: no profile matches what runs".to_owned(),
            Color::Yellow,
        ),
        (None, false, Some(id)) => (format!("profile {id} applied but not running"), Color::Red),
        (None, false, None) => ("nothing applied".to_owned(), Color::Yellow),
    }
}

fn draw_status_panel(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    match &app.listing {
        Some(listing) => {
            let current = &listing.current;
            let (state, color) = state_line(current);
            lines.push(kv("State", &state, color));
            match &current.running {
                Some(r) if r.args.is_empty() => {
                    lines.push(kv("Running", strip_prefix(&r.sched), Color::White));
                }
                Some(r) => lines.push(kv(
                    "Running",
                    &format!("{} {}", strip_prefix(&r.sched), format_flags(&r.args)),
                    Color::White,
                )),
                None if current.unit.active => lines.push(kv(
                    "Running",
                    "scx.service active, process not readable",
                    Color::Yellow,
                )),
                None => lines.push(kv(
                    "Running",
                    "nothing (scx.service inactive)",
                    Color::White,
                )),
            }
            if let Some(err) = &current.config_error {
                lines.push(kv("Next start", "unknown", Color::Red));
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ {err}"),
                    Style::default().fg(Color::Red),
                )));
            } else {
                match &current.next {
                    Some(next) => {
                        let text = format!(
                            "{} {}{}",
                            strip_prefix(next.name()),
                            format_flags(&next.args),
                            if next.overridden {
                                " (SCX_*_OVERRIDE in effect)"
                            } else {
                                ""
                            }
                        );
                        let changed = current
                            .running
                            .as_ref()
                            .is_some_and(|r| r.sched != next.name() || r.args != next.args);
                        let color = if next.overridden || changed {
                            Color::Yellow
                        } else {
                            Color::White
                        };
                        lines.push(kv("Next start", text.trim_end(), color));
                    }
                    None => lines.push(kv("Next start", "nothing configured", Color::White)),
                }
            }
            if let Some(f) = &current.failure {
                lines.push(kv(
                    "Last start",
                    &format!("failed ({}): {}", f.status, f.message),
                    Color::Red,
                ));
            }
        }
        None => {
            let reason = app
                .listing_error
                .as_deref()
                .map_or_else(|| "unknown".to_owned(), |err| format!("unknown; {err}"));
            lines.push(kv("State", &reason, Color::Red));
        }
    }

    lines.push(Line::default());
    draw_kernel_section(app, &mut lines);

    lines.push(Line::default());
    match app.view {
        View::Profiles => {
            if let Some(entry) = app.selected_profile() {
                lines.push(Line::from(vec![
                    Span::styled("Selected: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(entry.label.clone(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("  {}", backing(entry)),
                    Style::default().fg(Color::Gray),
                )));
                if let Some(path) = &entry.path {
                    lines.push(Line::from(Span::styled(
                        format!("  {path}"),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
            if let Some(listing) = &app.listing {
                lines.push(Line::from(Span::styled(
                    format!("  profiles from {}", listing.source.display()),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        View::Advanced => {
            if let Some(sched) = app.selected_scheduler() {
                lines.push(Line::from(vec![
                    Span::styled("Selected: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        strip_prefix(sched).to_owned(),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw("  (Enter runs it with its own defaults, a with arguments you type)"),
                ]));
            }
            lines.push(Line::from(Span::styled(
                "  a scheduler unsuited to the workload can perform worse than the kernel's \
default; what starts here shows as Custom in every client",
                Style::default().fg(Color::Yellow),
            )));
        }
        View::Logs => {}
    }

    if let Some(open) = &app.field {
        lines.push(Line::default());
        let (label, hint) = match &open.field {
            Field::Args => (
                "Args: ",
                "the selected scheduler's own command-line arguments, as to `scxcli run`; \
Enter runs it with them, Esc cancels",
            ),
            Field::SaveAs { .. } => (
                "Profile id: ",
                "lowercase letters, digits and '-'; saves what runs now as a profile",
            ),
            Field::ConfirmDelete(_) => (
                "Delete? ",
                "y deletes the selected profile, anything else cancels",
            ),
        };
        let mut spans = vec![Span::styled(
            label,
            Style::default().add_modifier(Modifier::BOLD),
        )];
        if let Field::ConfirmDelete(id) = &open.field {
            spans.push(Span::styled(id.clone(), Style::default().fg(Color::Red)));
        } else {
            spans.extend(input_spans(&open.input));
        }
        lines.push(Line::from(spans));
        lines.push(Line::from(Span::styled(
            format!("  {hint}"),
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
    let title = format!(" Logs: {} · boot {} · {} lines ", logs::UNIT, boot, total);

    let panel = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(Style::default().add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(panel, area);
}

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

    let key_help = match (app.view, &app.field) {
        (_, Some(open)) => match open.field {
            Field::Args => " type scheduler arguments · Enter run with them · Esc cancel",
            Field::SaveAs { .. } => " type a profile id · Enter save · Esc cancel",
            Field::ConfirmDelete(_) => " y delete · any other key cancels",
        },
        (View::Profiles, None) => {
            " ↑/↓ select · Enter apply/resume · s stop · w save running as profile · J/K move · x delete · D restore shipped · A advanced · l logs · t monitor · R refresh · q quit"
        }
        (View::Advanced, None) => {
            " ↑/↓ select · Enter run with defaults · a run with args · s stop · w save running as profile · l logs · t monitor · R refresh · A/Esc back"
        }
        (View::Logs, None) => {
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
fn input_spans(input: &Input) -> Vec<Span<'static>> {
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

/// Renders a flag vector so token boundaries survive: `shell_words::join`.
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
