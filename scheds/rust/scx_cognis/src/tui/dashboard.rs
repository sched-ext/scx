// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// TUI Dashboard — built with ratatui.
//
// Renders six panels:
//   1. Header (scheduler name, live CPU/queued/base-slice counts).
//   2. System overview (running/queued tasks, hierarchy routing, congestion stats).
//   3. Userspace fallback event mix (interactive/compute/io/rt gauges).
//   4. Profile and fallback slice state.
//   5. Fallback latency chart (rolling 120-sample line chart).
//   6. PID watchlist from exit-observation tracking.
//
// All history buffers use HistoryRing — a fixed-size circular array that
// never reallocates after init (zero-alloc after DashboardState creation).

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::{
    cursor::Show,
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::Alignment,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, List, ListItem, Paragraph},
    Frame, Terminal,
};

use crate::ai::SHAME_MAX;
use crate::stats::Metrics;

// ── HistoryRing ────────────────────────────────────────────────────────────

/// Fixed-size circular ring buffer for f64 time-series data.
///
/// Replaces `VecDeque<f64>` in DashboardState: the ring is allocated once
/// at `DashboardState::default()` and never re-allocates thereafter.
#[derive(Debug, Clone)]
pub struct HistoryRing {
    buf: [f64; HISTORY_LEN],
    head: usize,
    len: usize,
}

impl HistoryRing {
    pub const fn new() -> Self {
        Self {
            buf: [0.0; HISTORY_LEN],
            head: 0,
            len: 0,
        }
    }

    /// Append a value, overwriting the oldest when full.
    pub fn push(&mut self, v: f64) {
        self.buf[self.head] = v;
        self.head = (self.head + 1) % HISTORY_LEN;
        if self.len < HISTORY_LEN {
            self.len += 1;
        }
    }

    /// Iterate values in chronological order (oldest first).
    pub fn iter_ordered(&self) -> impl Iterator<Item = f64> + '_ {
        let start = if self.len < HISTORY_LEN { 0 } else { self.head };
        (0..self.len).map(move |i| self.buf[(start + i) % HISTORY_LEN])
    }

    /// Maximum value in the ring, defaulting to `default` if empty.
    pub fn max_or(&self, default: f64) -> f64 {
        self.iter_ordered().fold(default, f64::max)
    }
}

impl Default for HistoryRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Dashboard State ────────────────────────────────────────────────────────

const HISTORY_LEN: usize = 120; // ~2 minutes at 1 Hz

#[derive(Debug, Default, Clone, Copy)]
pub struct WallEntry {
    pub pid: i32,
    pub comm: [u8; 16],
    pub trust: f64,
    pub is_flagged: bool,
}

impl WallEntry {
    pub const ZERO: Self = Self {
        pid: 0,
        comm: [0; 16],
        trust: 0.0,
        is_flagged: false,
    };

    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.comm[..end]).unwrap_or("?")
    }
}

/// All mutable state the dashboard needs to render.
#[derive(Debug, Clone)]
pub struct DashboardState {
    pub metrics: Metrics,
    pub inference_us: f64, // Most recent inference latency (µs)
    pub inference_hist: HistoryRing,
    pub watchlist_entries: [WallEntry; SHAME_MAX],
    pub wall_len: usize,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            metrics: Metrics::default(),
            inference_us: 0.0,
            inference_hist: HistoryRing::new(),
            watchlist_entries: [WallEntry::ZERO; SHAME_MAX],
            wall_len: 0,
        }
    }
}

impl DashboardState {
    pub fn push_history(&mut self) {
        self.inference_hist.push(self.inference_us);
    }

    pub fn set_watchlist(&mut self, entries: &[WallEntry; SHAME_MAX], len: usize) {
        self.watchlist_entries = *entries;
        self.wall_len = len.min(SHAME_MAX);
    }
}

// ── Terminal setup / teardown ──────────────────────────────────────────────

pub type Term = Terminal<CrosstermBackend<io::Stdout>>;

static TUI_TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn setup_terminal() -> Result<Term, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(err) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        let _ = disable_raw_mode();
        return Err(err);
    }
    let backend = CrosstermBackend::new(stdout);
    let terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(err) => {
            let _ = restore_stdout_terminal();
            return Err(err);
        }
    };
    TUI_TERMINAL_ACTIVE.store(true, Ordering::Release);
    Ok(terminal)
}

pub fn restore_terminal(term: &mut Term) -> Result<(), io::Error> {
    restore_stdout_terminal()?;
    term.show_cursor()?;
    Ok(())
}

fn restore_stdout_terminal() -> Result<(), io::Error> {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen, DisableMouseCapture, Show)?;
    stdout.flush()?;
    TUI_TERMINAL_ACTIVE.store(false, Ordering::Release);
    Ok(())
}

pub fn emergency_restore_terminal() {
    if TUI_TERMINAL_ACTIVE.load(Ordering::Acquire) {
        let _ = restore_stdout_terminal();
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

/// Draw one frame.
pub fn draw(frame: &mut Frame, state: &DashboardState) {
    let area = frame.size();

    // Top-level split: header + body.
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, root[0], &state.metrics);

    // Body: left column + right column.
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(root[1]);

    // Left column: overview + fallback event mix + slice state.
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(0),
        ])
        .split(body[0]);

    draw_overview(frame, left[0], &state.metrics);
    draw_classification(frame, left[1], &state.metrics);
    draw_slice_control(frame, left[2], state);

    // Right column: fallback latency chart + PID watchlist.
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[1]);

    draw_latency_chart(frame, right[0], state);
    draw_watchlist(frame, right[1], &state.watchlist_entries[..state.wall_len]);

    // Footer (single-line): version / core info centered at the bottom.
    let footer_area = root[2];
    let footer_text = Line::from(Span::raw(format!(
        "Cognis v{} — core {}",
        env!("CARGO_PKG_VERSION"),
        scx_rustland_core::VERSION
    )));
    let footer_para = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::NONE))
        .alignment(Alignment::Center);
    frame.render_widget(footer_para, footer_area);
}

fn draw_header(f: &mut Frame, area: Rect, m: &Metrics) {
    let text = Line::from(vec![
        Span::styled(
            " scx_cognis ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ BPF-first CPU Scheduler │ "),
        Span::styled(
            format!(
                "CPUs: {}  Running: {}  Queued: {}  Base: {}µs  Assigned≈{}µs  sched:{}:{}:{}",
                m.nr_cpus,
                m.nr_running,
                m.nr_queued,
                m.base_slice_us,
                m.assigned_slice_us,
                m.sched_p50_us,
                m.sched_p95_us,
                m.sched_p99_us
            ),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  [ press 'q' to quit ]"),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));
    let para = Paragraph::new(text).block(block);
    f.render_widget(para, area);
}

fn draw_overview(f: &mut Frame, area: Rect, m: &Metrics) {
    let load_pct = if m.nr_cpus > 0 {
        (m.nr_running * 100 / m.nr_cpus).min(100)
    } else {
        0
    };

    let items = [
        Line::from(format!(
            "  Dispatched (user/kernel/fail):  {} / {} / {}",
            m.nr_user_dispatches, m.nr_kernel_dispatches, m.nr_failed_dispatches
        )),
        Line::from(format!(
            "  BPF Route (local/llc/node/shared): {} / {} / {} / {}",
            m.nr_local_dispatches,
            m.nr_llc_dispatches,
            m.nr_node_dispatches,
            m.nr_shared_dispatches
        )),
        Line::from(format!(
            "  Remote Steals (llc/node):       {} / {}",
            m.nr_xllc_steals, m.nr_xnode_steals
        )),
        Line::from(format!(
            "  Bounce / Cancelled:             {} / {}",
            m.nr_bounce_dispatches, m.nr_cancel_dispatches
        )),
        Line::from(format!(
            "  Congestion / Page Faults:       {} / {}",
            m.nr_sched_congested, m.nr_page_faults
        )),
        Line::from(format!("  CPU Load:                       {}%", load_pct)),
    ];
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        " Overview ",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    let para = Paragraph::new(Vec::from(items)).block(block);
    f.render_widget(para, area);
}

fn draw_classification(f: &mut Frame, area: Rect, m: &Metrics) {
    let total = (m.nr_interactive + m.nr_compute + m.nr_iowait + m.nr_realtime).max(1);

    let items = [
        gauge_line("Interactive", m.nr_interactive, total, Color::Green),
        gauge_line("Compute    ", m.nr_compute, total, Color::Red),
        gauge_line("I/O Wait   ", m.nr_iowait, total, Color::Blue),
        gauge_line("RealTime   ", m.nr_realtime, total, Color::Magenta),
        Line::from(format!(
            "  Watchlist: below-threshold={} adverse-exit={}",
            m.nr_quarantined, m.nr_flagged
        )),
    ];
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        " Fallback Event Mix ",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    let para = Paragraph::new(Vec::from(items)).block(block);
    f.render_widget(para, area);
}

fn gauge_line(label: &str, n: u64, total: u64, color: Color) -> Line<'static> {
    let pct = (n * 100 / total) as usize;
    let bar = "█".repeat(pct / 5).to_owned() + &"░".repeat(20 - pct / 5);
    Line::from(vec![
        Span::raw(format!("  {label}: ")),
        Span::styled(bar, Style::default().fg(color)),
        Span::raw(format!(" {n:>4} ({pct:>3}%)")),
    ])
}

fn draw_slice_control(f: &mut Frame, area: Rect, state: &DashboardState) {
    let items = [
        Line::from(format!(
            "  Base Slice:        {}µs",
            state.metrics.base_slice_us
        )),
        Line::from(format!(
            "  Assigned Slice≈   {}µs",
            state.metrics.assigned_slice_us
        )),
        Line::from(format!(
            "  Slice Bounds:     {}µs min/{}µs max",
            state.metrics.slice_min_us, state.metrics.slice_max_us
        )),
        Line::from(format!("  Inference:        {:.2}µs", state.inference_us)),
        Line::from(vec![
            Span::raw("  Latency Budget:   "),
            Span::styled(
                if state.inference_us < 10.0 {
                    "under 10us"
                } else {
                    "over 10us"
                },
                Style::default().fg(if state.inference_us < 10.0 {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]),
    ];
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        " Slice Control ",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    let para = Paragraph::new(Vec::from(items)).block(block);
    f.render_widget(para, area);
}

fn draw_latency_chart(f: &mut Frame, area: Rect, state: &DashboardState) {
    let mut data = [(0.0f64, 0.0f64); HISTORY_LEN];
    let mut data_len = 0usize;
    for (i, v) in state.inference_hist.iter_ordered().enumerate() {
        data[data_len] = (i as f64, v);
        data_len += 1;
    }

    let max_y = state.inference_hist.max_or(10.0);
    let max_x = data_len.max(1) as f64;
    let data = &data[..data_len];

    let datasets = vec![Dataset::default()
        .name("Inference µs")
        .marker(symbols::Marker::Dot)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(data)];

    let chart = Chart::new(datasets)
        .block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                " Fallback Latency (µs) ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, max_x]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .labels(vec![
                    Span::raw("0"),
                    Span::styled("10µs", Style::default().fg(Color::Green)),
                    Span::raw(format!("{:.0}", max_y)),
                ])
                .bounds([0.0, max_y.max(15.0)]),
        );

    f.render_widget(chart, area);
}

fn draw_watchlist(f: &mut Frame, area: Rect, entries: &[WallEntry]) {
    let header = ListItem::new(Line::from(vec![Span::styled(
        " PID     COMM                TRUST   NOTE",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )]));

    let items =
        std::iter::once(header).chain(entries.iter().take(area.height as usize - 4).map(|e| {
            let flag = if e.is_flagged { " adverse" } else { "" };
            let color = if e.trust < 0.2 {
                Color::Red
            } else {
                Color::Yellow
            };
            ListItem::new(Line::from(vec![Span::styled(
                format!(" {:<7} {:<20} {:.2} {}", e.pid, e.comm_str(), e.trust, flag),
                Style::default().fg(color),
            )]))
        }));

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(Span::styled(
        " PID Watchlist ",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )));
    f.render_widget(list, area);
}

// ── Main TUI run loop ─────────────────────────────────────────────────────

/// Shared state handed from the scheduler thread to the TUI thread.
pub type SharedState = Arc<Mutex<DashboardState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(Mutex::new(DashboardState::default()))
}

/// Drain pending terminal events and return `true` if the user requested quit.
///
/// Uses `poll(Duration::ZERO)` semantics so the call never blocks the
/// scheduler loop; crossterm guarantees that `read()` won't block after a
/// successful zero-timeout `poll()`.
pub fn poll_tui_quit() -> bool {
    use crossterm::event::{self, Event, KeyCode};

    while event::poll(Duration::from_millis(0)).unwrap_or(false) {
        if let Ok(Event::Key(key)) = event::read() {
            if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                return true;
            }
        }
    }

    false
}

/// Render one TUI frame and check for quit key.  Call this from the
/// scheduler's main loop to drive the TUI without spawning a thread.
///
/// * `last_hist` — caller-owned `Instant` that governs history push (500 ms).
pub fn tick_tui(state: &SharedState, terminal: &mut Term, last_hist: &mut Instant) {
    // Push history every 500 ms.
    if last_hist.elapsed() >= Duration::from_millis(500) {
        *last_hist = Instant::now();
        if let Ok(mut s) = state.lock() {
            s.push_history();
        }
    }

    // Draw frame.
    if let Ok(snap) = state.lock() {
        let snap = snap.clone();
        let _ = terminal.draw(|f| draw(f, &snap));
    }
}
