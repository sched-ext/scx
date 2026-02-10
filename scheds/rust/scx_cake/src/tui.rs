// SPDX-License-Identifier: GPL-2.0
// TUI module - ratatui-based terminal UI for real-time scheduler statistics

use std::io::{self, Stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arboard::Clipboard;
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    buffer::Buffer,
    prelude::*,
    widgets::{Block, BorderType, Borders, Cell, Padding, Paragraph, Row, Table, Widget},
};
use tachyonfx::{fx, EffectManager};

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

/// Render a progress gauge inline for calibration progress
/// Updates a single line in-place, no newlines until complete
pub fn render_calibration_progress(current: usize, total: usize, is_complete: bool) {
    use std::io::Write;

    if total == 0 {
        return;
    }

    let percent = ((current as f64 / total as f64) * 100.0) as u16;

    // ANSI colors
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    // Build progress bar (40 chars wide)
    let bar_width = 40;
    let filled = ((current as f64 / total as f64) * bar_width as f64) as usize;
    let empty = bar_width - filled;

    let bar = format!(
        "{}{}{}{}{}",
        cyan,
        "█".repeat(filled),
        reset,
        "░".repeat(empty),
        reset
    );

    if is_complete {
        // Final output with checkmark and newline
        print!(
            "\r{green}✓{reset} {bold}ETD Calibration Complete{reset} [{bar}] {current}/{total} pairs ({percent}%)\n",
            green = green,
            reset = reset,
            bold = bold,
            bar = bar,
            current = current,
            total = total,
            percent = percent
        );
    } else {
        // In-progress: overwrite same line with \r
        print!(
            "\r{cyan}⏳{reset} {bold}ETD Calibration{reset} [{bar}] {current}/{total} pairs ({percent}%)   ",
            cyan = cyan,
            reset = reset,
            bold = bold,
            bar = bar,
            current = current,
            total = total,
            percent = percent
        );
    }

    let _ = io::stdout().flush();
}

/// Parameters for the startup screen
pub struct StartupParams<'a> {
    pub topology: &'a TopologyInfo,
    pub latency_matrix: &'a [Vec<f64>],
    pub profile: &'a str,
    pub quantum: u64,
    pub starvation: u64,
}

/// Render a beautiful one-time startup screen using Ratatui
/// This renders directly to stdout inline (persists in terminal like println)
pub fn render_startup_screen(params: StartupParams) -> Result<()> {
    // Get terminal size
    let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));
    let nr_cpus = params.latency_matrix.len();

    // Layout dimensions
    let left_height = 6 + 6 + (nr_cpus / 8 + 6);
    let matrix_height = nr_cpus + 6;
    let body_height = left_height.max(matrix_height);
    let total_height = (4 + body_height + 3) as u16;

    let area = Rect::new(0, 0, width, total_height);
    let mut buffer = Buffer::empty(area);

    // tachyonfx setup
    let mut fx_manager: EffectManager<()> = EffectManager::default();
    let duration_ms = 4200u32;

    // 1. Slow, elegant dissolve for the main UI
    fx_manager.add_effect(fx::dissolve(2000u32));

    // 2. Coalesce effect peaks in the middle-end
    fx_manager.add_effect(fx::sequence(&[fx::delay(1200u32, fx::coalesce(1800u32))]));

    // Enter Alternate Screen for smooth animation
    execute!(io::stdout(), EnterAlternateScreen, Hide)?;

    let start_time = Instant::now();
    let frame_rate = Duration::from_millis(16); // ~60fps

    while start_time.elapsed().as_millis() < duration_ms as u128 {
        let frame_start = Instant::now();
        let elapsed_ms = start_time.elapsed().as_millis() as u32;
        buffer.reset();

        render_startup_widgets(&mut buffer, area, &params, elapsed_ms);

        let t_duration = tachyonfx::Duration::from_millis(elapsed_ms);
        fx_manager.process_effects(t_duration, &mut buffer, area);

        // Print frame starting from top of alternate screen
        execute!(io::stdout(), MoveTo(0, 0))?;

        // Render only what fits in the current terminal height to avoid scrolling artifacts
        let render_height = total_height.min(height);
        for y in 0..render_height {
            let mut last_style = Style::default();
            for x in 0..width {
                let cell = &buffer[(x, y)];
                let cell_style = cell.style();
                if cell_style != last_style {
                    print!("{}", cell_style.to_ansi_sequence());
                    last_style = cell_style;
                }
                print!("{}", cell.symbol());
            }
            if y < render_height - 1 {
                print!("\x1b[0m\r\n");
            } else {
                print!("\x1b[0m");
            }
        }
        io::stdout().flush()?;

        let sleep_time = frame_rate.saturating_sub(frame_start.elapsed());
        if !sleep_time.is_zero() {
            std::thread::sleep(sleep_time);
        }
    }

    // Exit Alternate Screen and show cursor
    execute!(io::stdout(), LeaveAlternateScreen, Show)?;

    // Print final static frame to normal terminal (inline/persists)
    buffer.reset();
    render_startup_widgets(
        &mut buffer,
        area,
        &params,
        duration_ms, // Full completion
    );

    // Ensure animation is at 100% completion for final print
    let final_duration = tachyonfx::Duration::from_millis(duration_ms);
    fx_manager.process_effects(final_duration, &mut buffer, area);

    for y in 0..total_height {
        let mut last_style = Style::default();
        for x in 0..width {
            let cell = &buffer[(x, y)];
            let cell_style = cell.style();
            if cell_style != last_style {
                print!("{}", cell_style.to_ansi_sequence());
                last_style = cell_style;
            }
            print!("{}", cell.symbol());
        }
        println!("\x1b[0m");
    }
    io::stdout().flush()?;

    Ok(())
}

// Helper trait to convert Ratatui Style to ANSI sequences for inline printing
trait ToAnsi {
    fn to_ansi_sequence(&self) -> String;
}

impl ToAnsi for Style {
    fn to_ansi_sequence(&self) -> String {
        let mut seq = String::from("\x1b[0");

        if let Some(fg) = self.fg {
            match fg {
                Color::Rgb(r, g, b) => seq.push_str(&format!(";38;2;{};{};{}", r, g, b)),
                Color::Black => seq.push_str(";30"),
                Color::Red => seq.push_str(";31"),
                Color::Green => seq.push_str(";32"),
                Color::Yellow => seq.push_str(";33"),
                Color::Blue => seq.push_str(";34"),
                Color::Magenta => seq.push_str(";35"),
                Color::Cyan => seq.push_str(";36"),
                Color::Gray => seq.push_str(";37"),
                Color::DarkGray => seq.push_str(";90"),
                Color::LightRed => seq.push_str(";91"),
                Color::LightGreen => seq.push_str(";92"),
                Color::LightYellow => seq.push_str(";93"),
                Color::LightBlue => seq.push_str(";94"),
                Color::LightMagenta => seq.push_str(";95"),
                Color::LightCyan => seq.push_str(";96"),
                Color::White => seq.push_str(";97"),
                _ => {}
            }
        }

        if let Some(bg) = self.bg {
            match bg {
                Color::Rgb(r, g, b) => seq.push_str(&format!(";48;2;{};{};{}", r, g, b)),
                Color::Black => seq.push_str(";40"),
                _ => {} // Simplified bg for now
            }
        }

        if self.add_modifier.contains(Modifier::BOLD) {
            seq.push_str(";1");
        }
        if self.add_modifier.contains(Modifier::ITALIC) {
            seq.push_str(";3");
        }
        if self.add_modifier.contains(Modifier::DIM) {
            seq.push_str(";2");
        }

        seq.push('m');
        seq
    }
}

/// Render the startup UI widgets to a buffer (inline version for persistent terminal output)
fn render_startup_widgets(
    buffer: &mut Buffer,
    area: Rect,
    params: &StartupParams,
    elapsed_ms: u32,
) {
    // --- Layout Configuration ---
    // Split into Header and Body
    let outer_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Header/Title (Needs 4 for subtitle + borders)
            Constraint::Min(20),   // Dashboard Body
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Split Body into Left (Info), Middle (Heatmap), and Right (Data)
    let dashboard_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22), // System info
            Constraint::Percentage(39), // Latency heatmap
            Constraint::Fill(1),        // Latency data (fills all remaining space)
        ])
        .split(outer_layout[1]);

    // Left Column Layout: Specs, Profile, Topology
    let left_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Specs
            Constraint::Length(6), // Profile
            Constraint::Min(8),    // Topology
        ])
        .split(dashboard_layout[0]);

    // --- Title ---
    let author_full = "by RitzDaCat";
    // Typewriting effect: show 1 char every 100ms, starting at 1000ms
    let typing_start = 1000u32;
    let ms_per_char = 100u32;
    let chars_to_show = if elapsed_ms < typing_start {
        0
    } else {
        ((elapsed_ms - typing_start) / ms_per_char).min(author_full.len() as u32) as usize
    };
    let author_typed = &author_full[..chars_to_show];

    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" 🍰 ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "scx_cake ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("v1.02", Style::default().fg(Color::White)),
            Span::styled(
                " │ Gaming Oriented Scheduler",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            author_typed,
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim()),
    )
    .alignment(Alignment::Center);
    title.render(outer_layout[0], buffer);

    // --- System Specs ---
    let smt_str = if params.topology.smt_enabled {
        "On"
    } else {
        "Off"
    };
    let hardware_rows = vec![
        Row::new(vec![
            Cell::from("CPUs").style(Style::default().fg(Color::Cyan)),
            Cell::from(params.topology.nr_cpus.to_string()),
        ]),
        Row::new(vec![
            Cell::from("SMT").style(Style::default().fg(Color::Cyan)),
            Cell::from(smt_str),
        ]),
        Row::new(vec![
            Cell::from("Layout").style(Style::default().fg(Color::Cyan)),
            Cell::from(if params.topology.has_dual_ccd {
                "Multi-CCD"
            } else {
                "Single"
            }),
        ]),
    ];

    let hardware_block = Table::new(hardware_rows, [Constraint::Length(10), Constraint::Min(10)])
        .block(
            Block::default()
                .title(" System ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan).dim()),
        );
    Widget::render(hardware_block, left_layout[0], buffer);

    // --- Profile Intelligence ---
    let profile_text = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                params.profile,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Quantum: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}µs", params.quantum),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Preempt: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}ms", params.starvation / 1000),
                Style::default().fg(Color::White),
            ),
        ]),
    ])
    .block(
        Block::default()
            .title(" Profile ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim()),
    );
    profile_text.render(left_layout[1], buffer);

    // --- Topology Overview ---
    let topology_grid = build_cpu_topology_grid_compact(params.topology);
    topology_grid.render(left_layout[2], buffer);

    // --- Empirical Fabric (The Heatmap) ---
    let heatmap = LatencyHeatmap::new(params.latency_matrix, params.topology);
    heatmap.render(dashboard_layout[1], buffer);

    // --- Numerical Truth (Raw Data) ---
    let data_table = LatencyTable::new(params.latency_matrix, params.topology);
    data_table.render(dashboard_layout[2], buffer);

    // --- Footer ---
    let footer = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            "● ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Cake is online!",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ])])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim()),
    )
    .alignment(Alignment::Center);

    footer.render(outer_layout[2], buffer);
}

/// Compact CPU topology schematic for Left Column
fn build_cpu_topology_grid_compact(topology: &TopologyInfo) -> Paragraph<'static> {
    let nr_cpus = topology.nr_cpus.min(64);
    let mut lines = Vec::new();

    lines.push(Line::from(""));

    let mut current_line = Vec::new();
    for cpu in 0..nr_cpus {
        // Dot indicator for core type
        let symbol = if topology.cpu_is_big.get(cpu).copied().unwrap_or(0) != 0 {
            "◆" // P-core
        } else {
            "◇" // E-core/Uniform
        };

        let color = if topology.cpu_is_big.get(cpu).copied().unwrap_or(0) != 0 {
            Color::Magenta
        } else {
            Color::Cyan
        };

        current_line.push(Span::styled(
            format!("{} ", symbol),
            Style::default().fg(color),
        ));

        if (cpu + 1) % 8 == 0 {
            lines.push(Line::from(current_line));
            current_line = Vec::new();
        }
    }
    if !current_line.is_empty() {
        lines.push(Line::from(current_line));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" ◆ ", Style::default().fg(Color::Magenta)),
        Span::styled("Performance  ", Style::default().fg(Color::Gray).dim()),
        Span::styled(" ◇ ", Style::default().fg(Color::Cyan)),
        Span::styled("Efficiency", Style::default().fg(Color::Gray).dim()),
    ]));

    Paragraph::new(lines).block(
        Block::default()
            .title(" Topology ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim())
            .padding(Padding::horizontal(1)),
    )
}

/// Custom Widget for high-density Latency Heatmap
struct LatencyHeatmap<'a> {
    matrix: &'a [Vec<f64>],
    topology: &'a TopologyInfo,
}

impl<'a> LatencyHeatmap<'a> {
    fn new(matrix: &'a [Vec<f64>], topology: &'a TopologyInfo) -> Self {
        Self { matrix, topology }
    }
}

impl<'a> Widget for LatencyHeatmap<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let nr_cpus = self.matrix.len();

        let block = Block::default()
            .title(" Latency Heatmap ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim());

        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width < 10 || inner_area.height < 5 {
            return;
        }

        // Header for Target CPUs (X-axis)
        for j in 0..nr_cpus {
            let x = inner_area.x + 6 + (j as u16 * 2);
            if x < inner_area.right() {
                buf.set_string(
                    x,
                    inner_area.y,
                    format!("{:1}", j % 10),
                    Style::default().fg(Color::Cyan).dim(),
                );
            }
        }

        for i in 0..nr_cpus {
            let y = inner_area.y + 1 + i as u16;
            if y >= inner_area.bottom() {
                break;
            }

            // Row Label (Source CPU)
            buf.set_string(
                inner_area.x + 1,
                y,
                format!("C{:02}", i),
                Style::default().fg(Color::Cyan).dim(),
            );

            for j in 0..nr_cpus {
                let x = inner_area.x + 6 + (j as u16 * 2);
                if x >= inner_area.right() - 1 {
                    continue;
                }

                let is_self = i == j;
                let is_smt = self.topology.cpu_sibling_map[i] as usize == j;
                let same_ccd = self.topology.cpu_llc_id[i] == self.topology.cpu_llc_id[j];

                let style = if is_self {
                    Style::default().fg(Color::Rgb(40, 40, 40))
                } else if is_smt {
                    Style::default().fg(Color::Rgb(0, 255, 150)) // Turquoise
                } else if same_ccd {
                    Style::default().fg(Color::Rgb(0, 200, 255)) // Cyan
                } else {
                    Style::default().fg(Color::Rgb(255, 180, 0)) // Amber
                };

                buf.set_string(x, y, "█", style);
                buf.set_string(x + 1, y, " ", Style::default());
            }
        }

        // Legend at bottom
        let legend_y = inner_area.bottom().saturating_sub(1);
        let legend_x = inner_area.x + 1;
        if legend_y > inner_area.y + nr_cpus as u16 {
            buf.set_string(
                legend_x,
                legend_y,
                "█ SMT",
                Style::default().fg(Color::Rgb(0, 255, 150)),
            );
            buf.set_string(
                legend_x + 9,
                legend_y,
                "█ Same CCD",
                Style::default().fg(Color::Rgb(0, 200, 255)),
            );
            buf.set_string(
                legend_x + 22,
                legend_y,
                "█ Cross-CCD",
                Style::default().fg(Color::Rgb(255, 180, 0)),
            );
        }
    }
}

/// Custom Widget for numerical latency table
struct LatencyTable<'a> {
    matrix: &'a [Vec<f64>],
    topology: &'a TopologyInfo,
}

impl<'a> LatencyTable<'a> {
    fn new(matrix: &'a [Vec<f64>], topology: &'a TopologyInfo) -> Self {
        Self { matrix, topology }
    }
}

impl<'a> Widget for LatencyTable<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let nr_cpus = self.matrix.len();

        let block = Block::default()
            .title(" Latency Data ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim());

        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width < 10 || inner_area.height < 5 {
            return;
        }

        // Header for Target CPUs
        for j in 0..nr_cpus {
            let x = inner_area.x + 5 + (j as u16 * 3);
            if x < inner_area.right() {
                buf.set_string(
                    x,
                    inner_area.y,
                    format!("{:>2}", j),
                    Style::default().fg(Color::Cyan).dim(),
                );
            }
        }

        for i in 0..nr_cpus {
            let y = inner_area.y + 1 + i as u16;
            if y >= inner_area.bottom() {
                break;
            }

            buf.set_string(
                inner_area.x + 1,
                y,
                format!("C{:02}", i),
                Style::default().fg(Color::Cyan).dim(),
            );

            for j in 0..nr_cpus {
                let x = inner_area.x + 5 + (j as u16 * 3);
                if x >= inner_area.right() - 2 {
                    continue;
                }

                let val = self.matrix[i][j].min(999.0);
                let is_self = i == j;
                let is_smt = self.topology.cpu_sibling_map[i] as usize == j;
                let same_ccd = self.topology.cpu_llc_id[i] == self.topology.cpu_llc_id[j];

                let style = if is_self {
                    Style::default().fg(Color::Rgb(40, 40, 40))
                } else if is_smt {
                    Style::default().fg(Color::Rgb(0, 255, 150))
                } else if same_ccd {
                    Style::default().fg(Color::Rgb(0, 200, 255))
                } else {
                    Style::default().fg(Color::Rgb(255, 180, 0))
                };

                buf.set_string(x, y, format!("{:>2.0}", val), style);
            }
        }
    }
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
    let total_starvation: u64 = stats.nr_starvation_preempts_tier.iter().sum();
    let summary_text = format!(
        " Dispatches: {} | Starvation preempts: {}",
        stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches,
        total_starvation
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
            .add_modifier(Modifier::BOLD), // Critical (<100µs)
        1 => Style::default().fg(Color::Green), // Interactive (<2ms)
        2 => Style::default().fg(Color::Yellow), // Frame (<8ms)
        3 => Style::default().fg(Color::DarkGray), // Bulk (≥8ms)
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
