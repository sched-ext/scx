// SPDX-License-Identifier: GPL-2.0

//! Rendering. Almost a pure function of the [`App`] state; the one
//! exception is the log view writing its viewport height and clamped
//! scroll offset back into the app.

use crate::model::{Current, DEFAULT_ID, Listing, Tier};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, Input, View, is_running, is_selected};
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
        View::Recommended | View::All => {
            let [left, right] = Layout::new(
                Direction::Horizontal,
                [Constraint::Percentage(45), Constraint::Percentage(55)],
            )
            .areas(body);
            if app.view == View::Recommended {
                draw_recommended_list(frame, app, left);
            } else {
                draw_all_list(frame, app, left);
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
        Span::raw(if app.view == View::All {
            "  all schedulers"
        } else {
            ""
        }),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// The marker in front of a list entry: running, selected for the next
/// start but not running, or nothing.
fn marker(listing: Option<&Listing>, id: &str) -> (&'static str, Style) {
    match listing {
        Some(l) if is_running(l, id) => (
            "● ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Some(l) if is_selected(l, id) => ("○ ", Style::default().fg(Color::Yellow)),
        _ => ("  ", Style::default()),
    }
}

fn draw_recommended_list(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .recommended()
        .iter()
        .map(|pick| {
            let (mark, style) = marker(app.listing.as_ref(), &pick.id);
            let style = if !pick.available {
                Style::default().fg(Color::DarkGray)
            } else {
                style
            };
            let mut lines = vec![Line::from(vec![
                Span::styled(mark, style),
                Span::styled(pick.label.clone(), style),
                Span::styled(
                    if pick.available {
                        String::new()
                    } else {
                        "  (not installed)".to_owned()
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ])];
            if !pick.description.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("    {}", pick.description),
                    Style::default().fg(Color::Gray),
                )));
            }
            ListItem::new(lines)
        })
        .collect();

    let title = match &app.listing {
        Some(l) if l.customized => " Recommended (administrator's catalog) ",
        _ => " Recommended ",
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

/// One item of the full list: a group header, or the scheduler at
/// that index of the listing's `all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllRow {
    Header { tier: Tier, first: bool },
    Scheduler(usize),
}

/// The full list's items in order: a header before the first scheduler
/// of each tier, then the schedulers. Pure, so the mapping between the
/// cursor (a scheduler index) and the item list is tested on its own.
fn all_list_rows(all: &[crate::model::Installed]) -> Vec<AllRow> {
    let mut rows = Vec::with_capacity(all.len() + 3);
    let mut last: Option<Tier> = None;
    for (idx, sched) in all.iter().enumerate() {
        if last != Some(sched.tier) {
            rows.push(AllRow::Header {
                tier: sched.tier,
                first: rows.is_empty(),
            });
            last = Some(sched.tier);
        }
        rows.push(AllRow::Scheduler(idx));
    }
    rows
}

fn draw_all_list(frame: &mut Frame, app: &App, area: Rect) {
    // Stable first, experimental after, then what the catalog does not
    // name, as the listing orders them. Each group is named once, by a
    // header item of its own (a rule and the name, the rule left off
    // the first group, which starts at the frame). Headers are items
    // so that the list lays them out, but they are never the selected
    // item: the cursor is a scheduler, and its position in the item
    // list is looked up by `all_list_rows`.
    let rows = all_list_rows(app.all());
    let rule = "\u{2500}".repeat(usize::from(area.width.saturating_sub(4)));
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            AllRow::Header { tier, first } => {
                let (title, style) = match tier {
                    Tier::Stable => ("  stable", Style::default().fg(Color::DarkGray)),
                    Tier::Experimental => ("  experimental", Style::default().fg(Color::Yellow)),
                    Tier::Unknown => ("  not in the catalog", Style::default().fg(Color::DarkGray)),
                };
                let mut lines = Vec::new();
                if !first {
                    lines.push(Line::from(Span::styled(
                        rule.clone(),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
                lines.push(Line::from(Span::styled(title, style)));
                ListItem::new(lines)
            }
            AllRow::Scheduler(idx) => {
                let sched = &app.all()[*idx];
                let (mark, style) = marker(app.listing.as_ref(), &sched.name);
                ListItem::new(Line::from(vec![
                    Span::styled(mark, style),
                    Span::styled(strip_prefix(&sched.name).to_owned(), style),
                    Span::styled(
                        if sched.recommended {
                            "  recommended"
                        } else {
                            ""
                        },
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            }
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" All installed schedulers "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let selected = rows
        .iter()
        .position(|row| *row == AllRow::Scheduler(app.sched_selected));
    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, area, &mut state);
}

fn state_line(current: &Current) -> (String, Color) {
    match current.scheduler.as_deref() {
        Some(DEFAULT_ID) => ("default (kernel scheduler)".to_owned(), Color::White),
        Some(name) => (format!("{} running", strip_prefix(name)), Color::Green),
        None if current.attached() => (
            "a scheduler is attached outside scx.service".to_owned(),
            Color::Yellow,
        ),
        None => (
            "scx.service is active, nothing attached yet".to_owned(),
            Color::Yellow,
        ),
    }
}

/// What the configuration says the unit runs, and whether that is what
/// runs now. One line, since the file and the next start are the same
/// thing unless an override is in effect, which the line then says.
fn configured_line(current: &Current) -> (String, Color) {
    let Some(next) = &current.next else {
        return ("nothing".to_owned(), Color::White);
    };
    let what = format!("{} {}", strip_prefix(next.name()), format_flags(&next.args));
    let what = what.trim_end();
    if next.overridden {
        return (format!("{what} (SCX_*_OVERRIDE in effect)"), Color::Yellow);
    }
    // "running" takes the kernel's word as well as the unit's: the
    // unit's process exists before its scheduler is attached, and
    // `scheduler` is set only once the kernel reports it.
    let running = current.scheduler.as_deref() == Some(next.name())
        && current
            .running
            .as_ref()
            .is_some_and(|r| r.sched == next.name() && r.args == next.args);
    // "not running" and no more: `failure` is the unit's last run,
    // which may have been another configuration, and the Last start
    // line below reports it on its own.
    if running {
        (format!("{what} (running)"), Color::White)
    } else {
        (format!("{what} (not running)"), Color::Yellow)
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
                lines.push(kv("Configured", "unknown", Color::Red));
                lines.push(Line::from(Span::styled(
                    format!("  ⚠ {err}"),
                    Style::default().fg(Color::Red),
                )));
            } else {
                let (text, color) = configured_line(current);
                lines.push(kv("Configured", &text, color));
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
        View::Recommended => {
            if let Some(pick) = app.selected_pick() {
                lines.push(Line::from(vec![
                    Span::styled("Focused: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(pick.label.clone(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!(
                        "  {}",
                        if pick.id == DEFAULT_ID {
                            "kernel default".to_owned()
                        } else {
                            pick.id.clone()
                        }
                    ),
                    Style::default().fg(Color::Gray),
                )));
                if let Some(path) = &pick.path {
                    lines.push(Line::from(Span::styled(
                        format!("  {path}"),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
            if let Some(listing) = &app.listing {
                lines.push(Line::from(Span::styled(
                    format!("  catalog from {}", listing.source.display()),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        View::All => {
            if let Some(sched) = app.selected_scheduler() {
                lines.push(Line::from(vec![
                    Span::styled("Focused: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        strip_prefix(&sched.name).to_owned(),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(
                        "  (Enter starts it with its own defaults, a with arguments you type)",
                    ),
                ]));
                match sched.tier {
                    Tier::Stable => {}
                    Tier::Experimental => lines.push(Line::from(Span::styled(
                        "  experimental: the catalog does not classify this scheduler as stable",
                        Style::default().fg(Color::Yellow),
                    ))),
                    Tier::Unknown => lines.push(Line::from(Span::styled(
                        "  the catalog says nothing about this scheduler; it is installed, and \
that is all that is known",
                        Style::default().fg(Color::DarkGray),
                    ))),
                }
                lines.push(Line::from(Span::styled(
                    format!("  {}", sched.path),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines.push(Line::from(Span::styled(
                "  a scheduler unsuited to the workload can perform worse than the kernel's \
default",
                Style::default().fg(Color::Yellow),
            )));
        }
        View::Logs => {}
    }

    if let Some(input) = &app.args {
        lines.push(Line::default());
        let mut spans = vec![Span::styled(
            "Args: ",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        spans.extend(input_spans(input));
        lines.push(Line::from(spans));
        lines.push(Line::from(Span::styled(
            "  the selected scheduler's own command-line arguments, as to `scxcli run`; Enter \
runs it with them, Esc cancels",
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

    let key_help = match (app.view, &app.args) {
        (_, Some(_)) => " type scheduler arguments · Enter run with them · Esc cancel",
        (View::Recommended, None) => {
            " ↑/↓ select · Enter start · s stop · A all schedulers · l logs · t monitor · R refresh · q quit"
        }
        (View::All, None) => {
            " ↑/↓ select · Enter start with defaults · a run with args · s stop · l logs · t monitor · R refresh · A/Esc back"
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
    use crate::model::Installed;

    fn installed(name: &str, tier: Tier) -> Installed {
        Installed {
            name: name.into(),
            path: format!("/usr/bin/{name}"),
            recommended: false,
            tier,
        }
    }

    /// A header goes before the first scheduler of each tier and
    /// nowhere else; the rule is left off the first header; the
    /// scheduler items keep the listing's indices.
    #[test]
    fn the_full_list_puts_one_header_before_each_group() {
        let all = [
            installed("scx_cosmos", Tier::Stable),
            installed("scx_rusty", Tier::Stable),
            installed("scx_flow", Tier::Experimental),
            installed("scx_rake", Tier::Unknown),
        ];
        assert_eq!(
            all_list_rows(&all),
            vec![
                AllRow::Header {
                    tier: Tier::Stable,
                    first: true
                },
                AllRow::Scheduler(0),
                AllRow::Scheduler(1),
                AllRow::Header {
                    tier: Tier::Experimental,
                    first: false
                },
                AllRow::Scheduler(2),
                AllRow::Header {
                    tier: Tier::Unknown,
                    first: false
                },
                AllRow::Scheduler(3),
            ]
        );
        assert!(all_list_rows(&[]).is_empty());
        // A list that starts with an experimental scheduler still has
        // its first header without a rule.
        assert_eq!(
            all_list_rows(&[installed("scx_flow", Tier::Experimental)])[0],
            AllRow::Header {
                tier: Tier::Experimental,
                first: true
            }
        );
    }

    #[test]
    fn flags_format_round_trips() {
        let flags = ["--name", "foo bar", "", "a'b"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(shell_words::split(&format_flags(&flags)), Ok(flags));
    }
}
