// SPDX-License-Identifier: GPL-2.0
//
// TUI module for scx_cake
//
// Provides a ratatui-based terminal UI for real-time scheduler statistics.

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arboard::Clipboard;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::bpf_skel::types::cake_stats;
use crate::bpf_skel::BpfSkel;
use crate::stats::TIER_NAMES;
use crate::topology::TopologyInfo;

fn aggregate_stats(skel: &BpfSkel) -> cake_stats {
    let mut total: cake_stats = Default::default();

    if let Some(bss) = &skel.maps.bss_data {
        for s in &bss.global_stats {
            // Sum all fields
            total.nr_new_flow_dispatches += s.nr_new_flow_dispatches;
            total.nr_old_flow_dispatches += s.nr_old_flow_dispatches;

            for i in 0..crate::stats::TIER_NAMES.len() {
                total.nr_tier_dispatches[i] += s.nr_tier_dispatches[i];
                total.nr_starvation_preempts_tier[i] += s.nr_starvation_preempts_tier[i];
            }

            total.nr_sparse_promotions += s.nr_sparse_promotions;
            total.nr_sparse_demotions += s.nr_sparse_demotions;
            total.nr_input_preempts += s.nr_input_preempts;

            total.nr_wait_demotions += s.nr_wait_demotions;
            total.total_wait_ns += s.total_wait_ns;
            total.nr_waits += s.nr_waits;
            if s.max_wait_ns > total.max_wait_ns {
                total.max_wait_ns = s.max_wait_ns;
            }
        }
    }

    total
}

/// TUI Application state
pub struct TuiApp {
    start_time: Instant,
    status_message: Option<(String, Instant)>,
    topology: TopologyInfo,
}

impl TuiApp {
    pub fn new(topology: TopologyInfo) -> Self {
        Self {
            start_time: Instant::now(),
            status_message: None,
            topology,
        }
    }

    /// Format uptime as "Xm Ys" or "Xh Ym"
    fn format_uptime(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    /// Set a temporary status message that disappears after 2 seconds
    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), Instant::now()));
    }

    /// Get current status message if not expired
    fn get_status(&self) -> Option<&str> {
        match &self.status_message {
            Some((msg, timestamp)) if timestamp.elapsed() < Duration::from_secs(2) => Some(msg),
            _ => None,
        }
    }
}

/// Initialize the terminal for TUI mode
fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    io::stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(io::stdout());
    Terminal::new(backend).context("Failed to create terminal")
}

/// Restore terminal to normal mode
fn restore_terminal() -> Result<()> {
    disable_raw_mode().context("Failed to disable raw mode")?;
    io::stdout()
        .execute(LeaveAlternateScreen)
        .context("Failed to leave alternate screen")?;
    Ok(())
}

/// Format stats as a copyable text string
fn format_stats_for_clipboard(stats: &cake_stats, uptime: &str) -> String {
    let total_dispatches = stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
    let new_pct = if total_dispatches > 0 {
        (stats.nr_new_flow_dispatches as f64 / total_dispatches as f64) * 100.0
    } else {
        0.0
    };

    let mut output = String::new();
    output.push_str(&format!(
        "=== scx_cake Statistics (Uptime: {}) ===\n\n",
        uptime
    ));
    output.push_str(&format!(
        "Dispatches: {} total ({:.1}% new-flow)\n\n",
        total_dispatches, new_pct
    ));

    output.push_str("Tier           Dispatches    StarvPreempt\n");
    output.push_str("───────────────────────────────────────────\n");
    for (i, name) in TIER_NAMES.iter().enumerate() {
        output.push_str(&format!(
            "{:12}   {:>10}    {:>12}\n",
            name, stats.nr_tier_dispatches[i], stats.nr_starvation_preempts_tier[i]
        ));
    }

    output.push_str(&format!(
        "\nSparse flow: +{} promotions, -{} demotions\n",
        stats.nr_sparse_promotions, stats.nr_sparse_demotions
    ));
    output.push_str(&format!(
        "Input: {} preempts fired\n",
        stats.nr_input_preempts
    ));

    let avg_wait = if stats.nr_waits > 0 {
        stats.total_wait_ns as f64 / stats.nr_waits as f64 / 1000.0
    } else {
        0.0
    };
    output.push_str(&format!(
        "\nWait Stats: Avg {:.1}µs, Max {}µs, Demotions: {}\n",
        avg_wait,
        stats.max_wait_ns / 1000,
        stats.nr_wait_demotions
    ));

    output
}

/// Draw the UI
fn draw_ui(frame: &mut Frame, app: &TuiApp, stats: &cake_stats) {
    let area = frame.area();

    // Create main layout: header, stats table, footer
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Stats table
            Constraint::Length(5), // Summary
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // --- Header ---
    let total_dispatches = stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
    let new_pct = if total_dispatches > 0 {
        (stats.nr_new_flow_dispatches as f64 / total_dispatches as f64) * 100.0
    } else {
        0.0
    };

    // Build topology info string
    let topo_info = format!(
        "CPUs: {} {}{}{}",
        app.topology.nr_cpus,
        if app.topology.has_dual_ccd {
            "[Dual-CCD]"
        } else {
            ""
        },
        if app.topology.has_hybrid_cores {
            "[Hybrid]"
        } else {
            ""
        },
        if app.topology.smt_enabled {
            "[SMT]"
        } else {
            ""
        },
    );

    let header_text = format!(
        " {}  │  Dispatches: {} ({:.1}% new)  │  Uptime: {}",
        topo_info,
        total_dispatches,
        new_pct,
        app.format_uptime()
    );
    let header = Paragraph::new(header_text).block(
        Block::default()
            .title(" scx_cake Statistics ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    frame.render_widget(header, layout[0]);

    // --- Stats Table ---
    let header_cells = ["Tier", "Dispatches", "StarvPreempt"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header_row = Row::new(header_cells).height(1);

    let rows: Vec<Row> = TIER_NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let cells = vec![
                Cell::from(*name).style(tier_style(i)),
                Cell::from(format!("{}", stats.nr_tier_dispatches[i])),
                Cell::from(format!("{}", stats.nr_starvation_preempts_tier[i])),
            ];
            Row::new(cells).height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(14),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .title(" Per-Tier Statistics ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    frame.render_widget(table, layout[1]);

    // --- Summary ---
    let avg_wait = if stats.nr_waits > 0 {
        stats.total_wait_ns as f64 / stats.nr_waits as f64 / 1000.0
    } else {
        0.0
    };

    let summary_text = format!(
        " Sparse: +{} promo, -{} demo | Input Preempts: {}\n \
          Wait: Avg {:.1}µs, Max {}µs | Demotions: {}",
        stats.nr_sparse_promotions,
        stats.nr_sparse_demotions,
        stats.nr_input_preempts,
        avg_wait,
        stats.max_wait_ns / 1000,
        stats.nr_wait_demotions
    );
    let summary = Paragraph::new(summary_text).block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    frame.render_widget(summary, layout[2]);

    // --- Footer (key bindings + status) ---
    let footer_text = match app.get_status() {
        Some(status) => format!(" [q] Quit  [c] Copy  [r] Reset  │  {}", status),
        None => " [q] Quit  [c] Copy to clipboard  [r] Reset stats".to_string(),
    };
    let (fg_color, border_color) = if app.get_status().is_some() {
        (Color::Green, Color::Green)
    } else {
        (Color::DarkGray, Color::DarkGray)
    };
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(fg_color))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );
    frame.render_widget(footer, layout[3]);
}

/// Get color style for a tier
fn tier_style(tier: usize) -> Style {
    match tier {
        0 => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD), // CritLatency - highest priority
        1 => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD), // Realtime
        2 => Style::default().fg(Color::Magenta),                          // Critical
        3 => Style::default().fg(Color::Green),                            // Gaming
        4 => Style::default().fg(Color::Yellow),                           // Interactive
        5 => Style::default().fg(Color::Blue),                             // Batch
        6 => Style::default().fg(Color::DarkGray),                         // Background
        _ => Style::default(),
    }
}

/// Run the TUI event loop
pub fn run_tui(
    skel: &mut BpfSkel,
    shutdown: Arc<AtomicBool>,
    interval_secs: u64,
    topology: TopologyInfo,
) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = TuiApp::new(topology);
    let tick_rate = Duration::from_secs(interval_secs);
    let mut last_tick = Instant::now();

    // Initialize clipboard (may fail on headless systems)
    let mut clipboard = Clipboard::new().ok();

    loop {
        // Check for shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check for UEI exit
        if scx_utils::uei_exited!(skel, uei) {
            break;
        }

        // Get current stats (aggregate from per-cpu BSS array)
        let stats = aggregate_stats(skel);

        // Draw UI
        terminal.draw(|frame| draw_ui(frame, &app, &stats))?;

        // Handle events with timeout
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            shutdown.store(true, Ordering::Relaxed);
                            break;
                        }
                        KeyCode::Char('c') => {
                            // Copy stats to clipboard
                            let text = format_stats_for_clipboard(&stats, &app.format_uptime());
                            match &mut clipboard {
                                Some(cb) => match cb.set_text(text) {
                                    Ok(_) => app.set_status("✓ Copied to clipboard!"),
                                    Err(_) => app.set_status("✗ Failed to copy"),
                                },
                                None => app.set_status("✗ Clipboard not available"),
                            }
                        }
                        KeyCode::Char('r') => {
                            // Reset stats (clear the BSS array)
                            if let Some(bss) = &mut skel.maps.bss_data {
                                for s in &mut bss.global_stats {
                                    *s = Default::default();
                                }
                                app.set_status("✓ Stats reset");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
