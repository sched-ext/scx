// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::{AppTheme, PerfStatCollector, PerfStatCounters, PerfStatViewMode, ProcData};
use anyhow::Result;
use num_format::{SystemLocale, ToFormattedString};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Cell, Padding, Paragraph, Row, Sparkline, Table};
use ratatui::Frame;
use std::collections::BTreeMap;

/// Parameters for rendering perf stat view
pub struct PerfStatViewParams<'a> {
    pub collector: &'a PerfStatCollector,
    pub view_mode: &'a PerfStatViewMode,
    pub aggregation: &'a crate::PerfStatAggregationLevel,
    pub filter_pid: Option<i32>,
    pub proc_data: &'a BTreeMap<i32, ProcData>,
    pub tick_rate_ms: usize,
    pub localize: bool,
    pub locale: &'a SystemLocale,
    pub theme: &'a AppTheme,
}

/// Renderer for perf stat view
pub struct PerfStatRenderer;

impl PerfStatRenderer {
    /// Main render entry point
    pub fn render_perf_stat_view(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        if !params.collector.is_active() {
            Self::render_inactive_message(frame, area, params.theme);
            return Ok(());
        }

        // Dispatch based on aggregation level
        use crate::PerfStatAggregationLevel;
        match params.aggregation {
            PerfStatAggregationLevel::System => {
                // Render single system-wide view
                match params.view_mode {
                    PerfStatViewMode::Table => Self::render_table_view(frame, area, params),
                    PerfStatViewMode::Chart => Self::render_chart_view(frame, area, params),
                }
            }
            PerfStatAggregationLevel::Llc => {
                // Render grid of LLC panels
                Self::render_llc_grid(frame, area, params)
            }
            PerfStatAggregationLevel::Node => {
                // Render grid of NUMA node panels
                Self::render_node_grid(frame, area, params)
            }
        }
    }

    /// Render table view showing all counters and derived metrics
    fn render_table_view(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        // Check if we're filtering by process but don't have counters
        if params.filter_pid.is_some() && !params.collector.has_process_counters() {
            Self::render_process_filter_error(
                frame,
                area,
                params.filter_pid.unwrap(),
                params.theme,
            );
            return Ok(());
        }

        // Split into sections: header, system counters, derived metrics, per-CPU summary
        let [header_area, counters_area, metrics_area, percpu_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .areas(area);

        // Render header with title and filter info
        Self::render_header(frame, header_area, params)?;

        // Render main counter table
        Self::render_counter_table(frame, counters_area, params)?;

        // Render derived metrics table
        Self::render_derived_metrics_table(frame, metrics_area, params)?;

        // Render per-CPU summary
        Self::render_per_cpu_summary(frame, percpu_area, params)?;

        Ok(())
    }

    /// Render header section
    fn render_header(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        let title = if let Some(pid) = params.filter_pid {
            let proc_name = params
                .proc_data
                .get(&pid)
                .map(|p| p.process_name.as_str())
                .unwrap_or("unknown");
            format!(
                "Performance Counter Statistics - {} (PID: {})",
                proc_name, pid
            )
        } else {
            "Performance Counter Statistics (System-Wide)".to_string()
        };

        let num_cpus = params.collector.per_cpu_counters.len();
        let status_text = format!("● Active - {} CPUs monitored", num_cpus);

        let mode_text = if params.filter_pid.is_some() {
            format!(
                "View: {} | Aggregation: {} | 'v' view | 'a' agg | 'c' clear filter",
                match params.view_mode {
                    PerfStatViewMode::Table => "Table",
                    PerfStatViewMode::Chart => "Chart",
                },
                params.aggregation
            )
        } else {
            format!(
                "View: {} | Aggregation: {} | 'v' view | 'a' agg | 'p' filter",
                match params.view_mode {
                    PerfStatViewMode::Table => "Table",
                    PerfStatViewMode::Chart => "Chart",
                },
                params.aggregation
            )
        };

        let block = Block::bordered()
            .title_top(
                Line::from(title)
                    .style(params.theme.title_style())
                    .centered(),
            )
            .title_top(
                Line::from(status_text)
                    .style(params.theme.text_important_color())
                    .right_aligned(),
            )
            .title_bottom(
                Line::from(mode_text)
                    .style(params.theme.text_color())
                    .centered(),
            )
            .border_type(BorderType::Rounded)
            .style(params.theme.border_style());

        frame.render_widget(block, area);
        Ok(())
    }

    /// Render main counter table (similar to perf stat output)
    fn render_counter_table(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        // Use process counters if filtering, otherwise system counters
        let counters = if params.filter_pid.is_some() {
            params
                .collector
                .process_counters
                .as_ref()
                .unwrap_or(&params.collector.system_counters)
        } else {
            &params.collector.system_counters
        };
        let duration_ms = params.tick_rate_ms as f64 / 1000.0;

        // Table columns: Counter Name | Value | Rate | Notes
        let header = Row::new(vec![
            Cell::from("Counter").style(params.theme.title_style()),
            Cell::from("Value").style(params.theme.title_style()),
            Cell::from("Rate/sec").style(params.theme.title_style()),
            Cell::from("Notes").style(params.theme.title_style()),
        ]);

        let rows = vec![
            Self::create_counter_row(
                "cpu-clock",
                counters.cycles_delta,
                duration_ms,
                format!(
                    "{:.3} CPUs utilized",
                    counters.cycles_delta as f64 / duration_ms / 1_000_000_000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "context-switches",
                counters.context_switches_delta,
                duration_ms,
                format!(
                    "{:.3} K/sec",
                    counters.context_switches_delta as f64 / duration_ms / 1000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "cpu-migrations",
                counters.cpu_migrations_delta,
                duration_ms,
                format!(
                    "{:.3} K/sec",
                    counters.cpu_migrations_delta as f64 / duration_ms / 1000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "page-faults",
                counters.page_faults_delta,
                duration_ms,
                format!(
                    "{:.3} K/sec",
                    counters.page_faults_delta as f64 / duration_ms / 1000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "cycles",
                counters.cycles_delta,
                duration_ms,
                format!(
                    "{:.3} GHz",
                    counters.cycles_delta as f64 / duration_ms / 1_000_000_000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "instructions",
                counters.instructions_delta,
                duration_ms,
                Self::format_ipc_note(counters),
                params,
            ),
            Self::create_counter_row(
                "branches",
                counters.branches_delta,
                duration_ms,
                format!(
                    "{:.3} M/sec",
                    counters.branches_delta as f64 / duration_ms / 1_000_000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "branch-misses",
                counters.branch_misses_delta,
                duration_ms,
                Self::format_branch_miss_note(counters),
                params,
            ),
            Self::create_counter_row(
                "cache-references",
                counters.cache_references_delta,
                duration_ms,
                format!(
                    "{:.3} M/sec",
                    counters.cache_references_delta as f64 / duration_ms / 1_000_000.0
                ),
                params,
            ),
            Self::create_counter_row(
                "cache-misses",
                counters.cache_misses_delta,
                duration_ms,
                Self::format_cache_miss_note(counters),
                params,
            ),
            Self::create_counter_row(
                "stalled-cycles-frontend",
                counters.stalled_cycles_frontend_delta,
                duration_ms,
                Self::format_stalled_frontend_note(counters),
                params,
            ),
            Self::create_counter_row(
                "stalled-cycles-backend",
                counters.stalled_cycles_backend_delta,
                duration_ms,
                Self::format_stalled_backend_note(counters),
                params,
            ),
        ];

        let table = Table::new(
            rows,
            vec![
                Constraint::Percentage(30), // Counter name
                Constraint::Percentage(20), // Value
                Constraint::Percentage(20), // Rate
                Constraint::Percentage(30), // Notes
            ],
        )
        .header(header)
        .block(
            Block::bordered()
                .title_top(
                    Line::from("Performance Counters")
                        .style(params.theme.title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(params.theme.border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Create a row for the counter table
    fn create_counter_row(
        name: &str,
        value: u64,
        duration_secs: f64,
        notes: String,
        params: &PerfStatViewParams,
    ) -> Row<'static> {
        let rate = if duration_secs > 0.0 {
            (value as f64 / duration_secs) as u64
        } else {
            0
        };

        let value_str = if params.localize {
            value.to_formatted_string(params.locale)
        } else {
            value.to_string()
        };

        let rate_str = if params.localize {
            rate.to_formatted_string(params.locale)
        } else {
            rate.to_string()
        };

        Row::new(vec![
            Cell::from(name.to_string()).style(params.theme.text_color()),
            Cell::from(value_str).style(params.theme.text_important_color()),
            Cell::from(rate_str).style(params.theme.text_color()),
            Cell::from(notes).style(params.theme.text_color()),
        ])
    }

    /// Format IPC note (instructions per cycle)
    fn format_ipc_note(counters: &PerfStatCounters) -> String {
        let metrics = counters.derived_metrics();
        if counters.cycles_delta > 0 {
            format!("{:.2} insn per cycle", metrics.ipc)
        } else {
            "".to_string()
        }
    }

    /// Format branch miss note
    fn format_branch_miss_note(counters: &PerfStatCounters) -> String {
        let metrics = counters.derived_metrics();
        if counters.branches_delta > 0 {
            format!("{:.2}% of all branches", metrics.branch_miss_rate)
        } else {
            "".to_string()
        }
    }

    /// Format cache miss note
    fn format_cache_miss_note(counters: &PerfStatCounters) -> String {
        let metrics = counters.derived_metrics();
        if counters.cache_references_delta > 0 {
            format!("{:.2}% of all cache accesses", metrics.cache_miss_rate)
        } else {
            "".to_string()
        }
    }

    /// Format stalled frontend note
    fn format_stalled_frontend_note(counters: &PerfStatCounters) -> String {
        let metrics = counters.derived_metrics();
        if counters.cycles_delta > 0 {
            format!("{:.2}% frontend cycles idle", metrics.stalled_frontend_pct)
        } else {
            "".to_string()
        }
    }

    /// Format stalled backend note
    fn format_stalled_backend_note(counters: &PerfStatCounters) -> String {
        let metrics = counters.derived_metrics();
        if counters.cycles_delta > 0 {
            format!("{:.2}% backend cycles idle", metrics.stalled_backend_pct)
        } else {
            "".to_string()
        }
    }

    /// Render derived metrics table (IPC, stalls, etc.)
    fn render_derived_metrics_table(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        // Use process counters if filtering, otherwise system counters
        let counters = if params.filter_pid.is_some() {
            params
                .collector
                .process_counters
                .as_ref()
                .unwrap_or(&params.collector.system_counters)
        } else {
            &params.collector.system_counters
        };
        let metrics = counters.derived_metrics();

        let header = Row::new(vec![
            Cell::from("Metric").style(params.theme.title_style()),
            Cell::from("Value").style(params.theme.title_style()),
            Cell::from("Status").style(params.theme.title_style()),
        ]);

        let rows = vec![
            Self::create_metric_row(
                "IPC (Instructions per Cycle)",
                format!("{:.3}", metrics.ipc),
                Self::get_ipc_status_color(metrics.ipc, params.theme),
                params,
            ),
            Self::create_metric_row(
                "Cache Miss Rate",
                format!("{:.2}%", metrics.cache_miss_rate),
                Self::get_miss_rate_status_color(metrics.cache_miss_rate, params.theme),
                params,
            ),
            Self::create_metric_row(
                "Branch Miss Rate",
                format!("{:.2}%", metrics.branch_miss_rate),
                Self::get_miss_rate_status_color(metrics.branch_miss_rate, params.theme),
                params,
            ),
            Self::create_metric_row(
                "Frontend Stalls",
                format!("{:.2}%", metrics.stalled_frontend_pct),
                Self::get_stall_status_color(metrics.stalled_frontend_pct, params.theme),
                params,
            ),
            Self::create_metric_row(
                "Backend Stalls",
                format!("{:.2}%", metrics.stalled_backend_pct),
                Self::get_stall_status_color(metrics.stalled_backend_pct, params.theme),
                params,
            ),
        ];

        let table = Table::new(
            rows,
            vec![
                Constraint::Percentage(50), // Metric name
                Constraint::Percentage(25), // Value
                Constraint::Percentage(25), // Status
            ],
        )
        .header(header)
        .block(
            Block::bordered()
                .title_top(
                    Line::from("Derived Metrics")
                        .style(params.theme.title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(params.theme.border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Create a row for the derived metrics table
    fn create_metric_row(
        name: &str,
        value: String,
        status_color: Color,
        params: &PerfStatViewParams,
    ) -> Row<'static> {
        let status = if status_color == params.theme.positive_value_color() {
            "Good"
        } else if status_color == params.theme.negative_value_color() {
            "Poor"
        } else {
            "OK"
        };

        Row::new(vec![
            Cell::from(name.to_string()).style(params.theme.text_color()),
            Cell::from(value).style(params.theme.text_important_color()),
            Cell::from(status.to_string()).style(Style::default().fg(status_color)),
        ])
    }

    /// Get status color for IPC (higher is better)
    fn get_ipc_status_color(ipc: f64, theme: &AppTheme) -> Color {
        if ipc >= 1.0 {
            theme.positive_value_color()
        } else if ipc >= 0.5 {
            theme.text_important_color()
        } else {
            theme.negative_value_color()
        }
    }

    /// Get status color for miss rates (lower is better)
    fn get_miss_rate_status_color(rate: f64, theme: &AppTheme) -> Color {
        if rate < 3.0 {
            theme.positive_value_color()
        } else if rate < 10.0 {
            theme.text_important_color()
        } else {
            theme.negative_value_color()
        }
    }

    /// Get status color for stall percentages (lower is better)
    fn get_stall_status_color(pct: f64, theme: &AppTheme) -> Color {
        if pct < 20.0 {
            theme.positive_value_color()
        } else if pct < 40.0 {
            theme.text_important_color()
        } else {
            theme.negative_value_color()
        }
    }

    /// Render per-CPU summary (top CPUs by activity)
    fn render_per_cpu_summary(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        // Get top 5 CPUs by instructions
        let mut cpu_activity: Vec<(usize, u64)> = params
            .collector
            .per_cpu_counters
            .iter()
            .map(|(cpu, counters)| (*cpu, counters.instructions_delta))
            .collect();
        cpu_activity.sort_by(|a, b| b.1.cmp(&a.1));
        cpu_activity.truncate(5);

        let header = Row::new(vec![
            Cell::from("CPU").style(params.theme.title_style()),
            Cell::from("Instructions").style(params.theme.title_style()),
            Cell::from("IPC").style(params.theme.title_style()),
            Cell::from("Cache Miss %").style(params.theme.title_style()),
        ]);

        let rows: Vec<Row> = cpu_activity
            .iter()
            .filter_map(|(cpu, _)| {
                params.collector.per_cpu_counters.get(cpu).map(|counters| {
                    let metrics = counters.derived_metrics();
                    let instructions_str = if params.localize {
                        counters
                            .instructions_delta
                            .to_formatted_string(params.locale)
                    } else {
                        counters.instructions_delta.to_string()
                    };

                    Row::new(vec![
                        Cell::from(format!("CPU {}", cpu)).style(params.theme.text_color()),
                        Cell::from(instructions_str).style(params.theme.text_important_color()),
                        Cell::from(format!("{:.2}", metrics.ipc)).style(params.theme.text_color()),
                        Cell::from(format!("{:.2}%", metrics.cache_miss_rate))
                            .style(params.theme.text_color()),
                    ])
                })
            })
            .collect();

        let table = Table::new(
            rows,
            vec![
                Constraint::Percentage(25),
                Constraint::Percentage(35),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ],
        )
        .header(header)
        .block(
            Block::bordered()
                .title_top(
                    Line::from("Top CPUs by Activity")
                        .style(params.theme.title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(params.theme.border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Render chart view (placeholder for Phase 4)
    fn render_chart_view(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        let history = &params.collector.system_history;

        // Check if we have any data
        if history.ipc_history.is_empty() {
            Self::render_empty_chart(frame, area, "Collecting data...", params.theme);
            return Ok(());
        }

        // Split into grid: 2x3 for different metrics
        let [top_row, middle_row, bottom_row] = Layout::vertical([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .areas(area);

        let [ipc_area, cache_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(top_row);

        let [branch_area, stalls_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(middle_row);

        let [cycles_area, instructions_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(bottom_row);

        // Render individual charts
        Self::render_ipc_chart(frame, ipc_area, params)?;
        Self::render_cache_miss_chart(frame, cache_area, params)?;
        Self::render_branch_miss_chart(frame, branch_area, params)?;
        Self::render_stalls_chart(frame, stalls_area, params)?;
        Self::render_cycles_chart(frame, cycles_area, params)?;
        Self::render_instructions_chart(frame, instructions_area, params)?;

        Ok(())
    }

    /// Render IPC trend chart
    fn render_ipc_chart(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        let history = &params.collector.system_history.ipc_history;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "IPC", params.theme);
            return Ok(());
        }

        // Convert to u64 for Sparkline (scale by 1000 to preserve precision)
        let mut data: Vec<u64> = history.iter().map(|&v| (v * 1000.0) as u64).collect();

        // Adjust data to fill available width (accounting for border)
        let target_width = area.width.saturating_sub(2) as usize;
        data = Self::adjust_data_for_width(data, target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0.0);
        let avg = history.iter().sum::<f64>() / history.len() as f64;
        let min = history.iter().copied().fold(f64::INFINITY, f64::min);
        let max = history.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(Self::get_ipc_status_color(current, params.theme))
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("IPC (Instructions per Cycle)")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.3} | Avg: {:.3} | Min: {:.3} | Max: {:.3}",
                            current, avg, min, max
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render cache miss rate chart
    fn render_cache_miss_chart(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        let history = &params.collector.system_history.cache_miss_rate_history;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "Cache Miss Rate", params.theme);
            return Ok(());
        }

        // Scale percentages by 100 for display
        let mut data: Vec<u64> = history.iter().map(|&v| (v * 100.0) as u64).collect();

        // Adjust data to fill available width
        let target_width = area.width.saturating_sub(2) as usize;
        data = Self::adjust_data_for_width(data, target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0.0);
        let avg = history.iter().sum::<f64>() / history.len() as f64;
        let min = history.iter().copied().fold(f64::INFINITY, f64::min);
        let max = history.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(Self::get_miss_rate_status_color(current, params.theme))
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Cache Miss Rate (%)")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.2}% | Avg: {:.2}% | Min: {:.2}% | Max: {:.2}%",
                            current, avg, min, max
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render branch miss rate chart
    fn render_branch_miss_chart(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        let history = &params.collector.system_history.branch_miss_rate_history;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "Branch Miss Rate", params.theme);
            return Ok(());
        }

        let mut data: Vec<u64> = history.iter().map(|&v| (v * 100.0) as u64).collect();

        // Adjust data to fill available width
        let target_width = area.width.saturating_sub(2) as usize;
        data = Self::adjust_data_for_width(data, target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0.0);
        let avg = history.iter().sum::<f64>() / history.len() as f64;
        let min = history.iter().copied().fold(f64::INFINITY, f64::min);
        let max = history.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(Self::get_miss_rate_status_color(current, params.theme))
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Branch Miss Rate (%)")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.2}% | Avg: {:.2}% | Min: {:.2}% | Max: {:.2}%",
                            current, avg, min, max
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render frontend/backend stalls chart
    fn render_stalls_chart(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        let history = &params.collector.system_history.stalled_frontend_pct_history;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "Pipeline Stalls", params.theme);
            return Ok(());
        }

        let mut data: Vec<u64> = history.iter().map(|&v| (v * 100.0) as u64).collect();

        // Adjust data to fill available width
        let target_width = area.width.saturating_sub(2) as usize;
        data = Self::adjust_data_for_width(data, target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0.0);
        let avg = history.iter().sum::<f64>() / history.len() as f64;
        let min = history.iter().copied().fold(f64::INFINITY, f64::min);
        let max = history.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(Self::get_stall_status_color(current, params.theme))
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Frontend Stalls (%)")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.2}% | Avg: {:.2}% | Min: {:.2}% | Max: {:.2}%",
                            current, avg, min, max
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render cycles per second chart
    fn render_cycles_chart(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        let history = &params.collector.system_history.cycles_per_sec;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "Cycles/sec", params.theme);
            return Ok(());
        }

        // Adjust data to fill available width
        let target_width = area.width.saturating_sub(2) as usize;
        let data = Self::adjust_data_for_width(history.clone(), target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0);
        let avg = history.iter().sum::<u64>() / history.len() as u64;
        let min = history.iter().copied().min().unwrap_or(0);
        let max = history.iter().copied().max().unwrap_or(0);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(params.theme.sparkline_style())
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Cycles/sec")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.2} | Avg: {:.2} | Min: {:.2} | Max: {:.2} GHz",
                            current as f64 / 1_000_000_000.0,
                            avg as f64 / 1_000_000_000.0,
                            min as f64 / 1_000_000_000.0,
                            max as f64 / 1_000_000_000.0
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render instructions per second chart
    fn render_instructions_chart(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
    ) -> Result<()> {
        let history = &params.collector.system_history.instructions_per_sec;

        if history.is_empty() {
            Self::render_empty_chart(frame, area, "Instructions/sec", params.theme);
            return Ok(());
        }

        // Adjust data to fill available width
        let target_width = area.width.saturating_sub(2) as usize;
        let data = Self::adjust_data_for_width(history.clone(), target_width);

        let max_val = data.iter().copied().max().unwrap_or(1);
        let current = history.last().copied().unwrap_or(0);
        let avg = history.iter().sum::<u64>() / history.len() as u64;
        let min = history.iter().copied().min().unwrap_or(0);
        let max = history.iter().copied().max().unwrap_or(0);

        let sparkline = Sparkline::default()
            .data(&data)
            .max(max_val)
            .direction(ratatui::widgets::RenderDirection::RightToLeft)
            .style(params.theme.sparkline_style())
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Instructions/sec")
                            .style(params.theme.title_style())
                            .centered(),
                    )
                    .title_bottom(
                        Line::from(format!(
                            "Cur: {:.2} | Avg: {:.2} | Min: {:.2} | Max: {:.2} B/s",
                            current as f64 / 1_000_000_000.0,
                            avg as f64 / 1_000_000_000.0,
                            min as f64 / 1_000_000_000.0,
                            max as f64 / 1_000_000_000.0
                        ))
                        .style(params.theme.text_color())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style()),
            );

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render grid of LLC panels
    fn render_llc_grid(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        let llc_ids: Vec<usize> = params.collector.per_llc_counters.keys().copied().collect();

        if llc_ids.is_empty() {
            Self::render_empty_chart(frame, area, "No LLC data available", params.theme);
            return Ok(());
        }

        Self::render_domain_grid(frame, area, params, &llc_ids, "LLC")
    }

    /// Render grid of NUMA node panels
    fn render_node_grid(frame: &mut Frame, area: Rect, params: &PerfStatViewParams) -> Result<()> {
        let node_ids: Vec<usize> = params.collector.per_node_counters.keys().copied().collect();

        if node_ids.is_empty() {
            Self::render_empty_chart(frame, area, "No NUMA node data available", params.theme);
            return Ok(());
        }

        Self::render_domain_grid(frame, area, params, &node_ids, "Node")
    }

    /// Render grid of domain panels (generic for LLC or NUMA)
    fn render_domain_grid(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
        domain_ids: &[usize],
        domain_type: &str,
    ) -> Result<()> {
        // Header area
        let [header_area, grid_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);

        // Render header
        let title = format!(
            "Performance Counters by {} - {} domains",
            domain_type,
            domain_ids.len()
        );
        let mode_text = format!(
            "Aggregation: {} | 'a' toggle | 'v' view mode ({})",
            domain_type, params.view_mode
        );

        let block = Block::bordered()
            .title_top(
                Line::from(title)
                    .style(params.theme.title_style())
                    .centered(),
            )
            .title_bottom(
                Line::from(mode_text)
                    .style(params.theme.text_color())
                    .centered(),
            )
            .border_type(BorderType::Rounded)
            .style(params.theme.border_style());

        frame.render_widget(block, header_area);

        // Calculate grid layout
        let num_domains = domain_ids.len();
        let cols = if num_domains >= 4 {
            3
        } else if num_domains >= 2 {
            2
        } else {
            1
        };
        let rows = num_domains.div_ceil(cols);

        // Create grid
        let row_constraints: Vec<Constraint> = (0..rows)
            .map(|_| Constraint::Ratio(1, rows as u32))
            .collect();
        let row_areas = Layout::vertical(row_constraints).split(grid_area);

        let mut domain_idx = 0;
        for &row_area in row_areas.iter() {
            let col_constraints: Vec<Constraint> = (0..cols)
                .map(|_| Constraint::Ratio(1, cols as u32))
                .collect();
            let col_areas = Layout::horizontal(col_constraints).split(row_area);

            for &col_area in col_areas.iter() {
                if domain_idx < num_domains {
                    let domain_id = domain_ids[domain_idx];
                    Self::render_domain_panel(frame, col_area, params, domain_id, domain_type)?;
                    domain_idx += 1;
                }
            }
        }

        Ok(())
    }

    /// Render a compact panel for one LLC or NUMA node
    fn render_domain_panel(
        frame: &mut Frame,
        area: Rect,
        params: &PerfStatViewParams,
        domain_id: usize,
        domain_type: &str,
    ) -> Result<()> {
        use crate::PerfStatAggregationLevel;

        // Get counters for this domain
        let counters = match params.aggregation {
            PerfStatAggregationLevel::Llc => params.collector.per_llc_counters.get(&domain_id),
            PerfStatAggregationLevel::Node => params.collector.per_node_counters.get(&domain_id),
            PerfStatAggregationLevel::System => unreachable!(),
        };

        if counters.is_none() {
            return Ok(());
        }
        let counters = counters.unwrap();
        let metrics = counters.derived_metrics();

        // Format metrics
        let lines = vec![
            Line::from(format!("IPC: {:.3}", metrics.ipc))
                .style(Style::default().fg(Self::get_ipc_status_color(metrics.ipc, params.theme))),
            Line::from(format!("Cache Miss: {:.2}%", metrics.cache_miss_rate)).style(
                Style::default().fg(Self::get_miss_rate_status_color(
                    metrics.cache_miss_rate,
                    params.theme,
                )),
            ),
            Line::from(format!("Branch Miss: {:.2}%", metrics.branch_miss_rate)).style(
                Style::default().fg(Self::get_miss_rate_status_color(
                    metrics.branch_miss_rate,
                    params.theme,
                )),
            ),
            Line::from(format!(
                "Frontend Stall: {:.1}%",
                metrics.stalled_frontend_pct
            ))
            .style(Style::default().fg(Self::get_stall_status_color(
                metrics.stalled_frontend_pct,
                params.theme,
            ))),
            Line::from(format!(
                "Cycles: {:.2} GHz",
                counters.cycles_delta as f64
                    / (params.tick_rate_ms as f64 / 1000.0)
                    / 1_000_000_000.0
            )),
        ];

        let block = Block::bordered()
            .title_top(
                Line::from(format!("{} {}", domain_type, domain_id))
                    .style(params.theme.title_style())
                    .centered(),
            )
            .border_type(BorderType::Rounded)
            .style(params.theme.border_style());

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);

        Ok(())
    }

    /// Adjust data vector to match target width (truncate or pad with zeros on left)
    fn adjust_data_for_width(mut data: Vec<u64>, target_width: usize) -> Vec<u64> {
        if target_width == 0 {
            return vec![0];
        }

        if data.len() > target_width {
            // Take the most recent samples (from the right)
            data = data.split_off(data.len() - target_width);
        } else if data.len() < target_width {
            // Pad with zeros on the left
            let padding_needed = target_width - data.len();
            let mut padded = vec![0; padding_needed];
            padded.extend(data);
            data = padded;
        }

        data
    }

    /// Render empty chart placeholder
    fn render_empty_chart(frame: &mut Frame, area: Rect, title: &str, theme: &AppTheme) {
        let text = vec![Line::from(""), Line::from("Collecting data...")];

        let paragraph = Paragraph::new(text).alignment(Alignment::Center).block(
            Block::bordered()
                .title_top(Line::from(title).style(theme.title_style()).centered())
                .border_type(BorderType::Rounded)
                .style(theme.border_style()),
        );

        frame.render_widget(paragraph, area);
    }

    /// Render message when collection is inactive
    fn render_inactive_message(frame: &mut Frame, area: Rect, theme: &AppTheme) {
        let text = vec![
            Line::from(""),
            Line::from("Performance counter collection is not active."),
            Line::from(""),
            Line::from("This view will populate automatically when activated."),
        ];

        let paragraph = Paragraph::new(text).alignment(Alignment::Center).block(
            Block::bordered()
                .title_top(
                    Line::from("Perf Stat View")
                        .style(theme.title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(theme.border_style())
                .padding(Padding::uniform(2)),
        );

        frame.render_widget(paragraph, area);
    }

    /// Render error message when process filtering fails
    fn render_process_filter_error(frame: &mut Frame, area: Rect, pid: i32, _theme: &AppTheme) {
        let text = vec![
            Line::from(""),
            Line::from(format!(
                "Failed to collect performance counters for PID {}",
                pid
            )),
            Line::from(""),
            Line::from("Possible reasons:"),
            Line::from("  • Process has terminated"),
            Line::from("  • Insufficient permissions"),
            Line::from("  • Hardware doesn't support all counters"),
            Line::from(""),
            Line::from("Press 'c' to clear filter and return to system-wide view"),
        ];

        let paragraph = Paragraph::new(text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Process Filter Error")
                            .style(Style::default().fg(Color::Red))
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(Style::default().fg(Color::Red))
                    .padding(Padding::uniform(2)),
            );

        frame.render_widget(paragraph, area);
    }
}
