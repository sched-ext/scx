// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_prog_data::{BpfProgData, BpfProgStats, SchedExtOpType};
use crate::columns::Columns;
use crate::symbol_data::SymbolSample;
use crate::AppTheme;
use anyhow::Result;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::bar::NINE_LEVELS;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Sparkline, Table, TableState};
use ratatui::Frame;
use std::collections::VecDeque;

/// Parameters for rendering BPF programs list
pub struct ProgramsListParams<'a> {
    pub bpf_program_stats: &'a BpfProgStats,
    pub filtered_programs: &'a [(u32, BpfProgData)],
    pub bpf_program_columns: &'a Columns<u32, BpfProgData>,
    pub bpf_overhead_history: &'a VecDeque<f64>,
    pub filtering: bool,
    pub filter_input: &'a str,
    pub event_input_buffer: &'a str,
    pub theme: &'a AppTheme,
    pub tick_rate_ms: usize,
}

/// Parameters for rendering BPF program details
pub struct ProgramDetailParams<'a> {
    pub selected_program_data: Option<&'a BpfProgData>,
    pub bpf_program_stats: &'a BpfProgStats,
    pub filtered_symbols: &'a [SymbolSample],
    pub bpf_perf_sampling_active: bool,
    pub active_event_name: &'a str,
    pub theme: &'a AppTheme,
    pub tick_rate_ms: usize,
}

/// Parameters for rendering BPF programs table
pub struct ProgramsTableParams<'a> {
    pub bpf_program_stats: &'a BpfProgStats,
    pub programs_to_display: &'a [(u32, BpfProgData)],
    pub bpf_program_columns: &'a Columns<u32, BpfProgData>,
    pub filtering: bool,
    pub event_input_buffer: &'a str,
    pub theme: &'a AppTheme,
    pub tick_rate_ms: usize,
}

/// Renderer for BPF programs views
pub struct BpfProgramRenderer;

impl BpfProgramRenderer {
    /// Renders the BPF programs list view with overhead sparkline
    pub fn render_programs_list(
        frame: &mut Frame,
        table_state: &mut TableState,
        params: &ProgramsListParams,
    ) -> Result<()> {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),   // Table area
                Constraint::Length(5), // Sparkline section
            ])
            .split(frame.area());

        if params.filtering && !params.event_input_buffer.is_empty() {
            // Further split table area for filter input
            let table_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(3)])
                .split(main_chunks[0]);

            let table_params = ProgramsTableParams {
                bpf_program_stats: params.bpf_program_stats,
                programs_to_display: params.filtered_programs,
                bpf_program_columns: params.bpf_program_columns,
                filtering: params.filtering,
                event_input_buffer: params.event_input_buffer,
                theme: params.theme,
                tick_rate_ms: params.tick_rate_ms,
            };

            Self::render_programs_table(frame, table_chunks[0], table_state, &table_params)?;
            Self::render_filter_input(frame, table_chunks[1], params.filter_input, params.theme)?;
        } else {
            let table_params = ProgramsTableParams {
                bpf_program_stats: params.bpf_program_stats,
                programs_to_display: params.filtered_programs,
                bpf_program_columns: params.bpf_program_columns,
                filtering: params.filtering,
                event_input_buffer: params.event_input_buffer,
                theme: params.theme,
                tick_rate_ms: params.tick_rate_ms,
            };

            Self::render_programs_table(frame, main_chunks[0], table_state, &table_params)?;
        }

        // Render overhead sparkline
        Self::render_overhead_sparkline(
            frame,
            main_chunks[1],
            params.bpf_overhead_history,
            params.theme,
        )?;

        Ok(())
    }

    /// Renders the BPF program detail view
    pub fn render_program_detail(
        frame: &mut Frame,
        symbol_table_state: &mut TableState,
        params: &ProgramDetailParams,
    ) -> Result<()> {
        let area = frame.area();

        if let Some(prog_data) = params.selected_program_data {
            // Split the area based on whether this is a sched_ext program
            let chunks = if prog_data.is_sched_ext {
                // For sched_ext programs, include operation breakdown section
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(10), // Program info
                        Constraint::Length(8),  // Runtime stats
                        Constraint::Min(15),    // Historical sparklines (fills remaining space)
                        Constraint::Length(12), // Operation breakdown
                        Constraint::Min(10),    // Symbol table
                    ])
                    .split(area)
            } else {
                // For non-sched_ext programs, use original layout
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(10), // Program info
                        Constraint::Length(8),  // Runtime stats
                        Constraint::Min(15),    // Historical sparklines (fills remaining space)
                        Constraint::Min(10),    // Symbol table
                    ])
                    .split(area)
            };

            // Render program information with BPF_ENABLE_STATS emphasis
            Self::render_program_info(
                frame,
                chunks[0],
                prog_data,
                params.bpf_perf_sampling_active,
                params.active_event_name,
                params.theme,
                params.tick_rate_ms,
            )?;

            // Render runtime statistics collected via BPF_ENABLE_STATS
            Self::render_runtime_stats(
                frame,
                chunks[1],
                prog_data,
                params.bpf_program_stats,
                params.theme,
            )?;

            // Render historical sparklines
            Self::render_program_sparklines(frame, chunks[2], prog_data, params.theme)?;

            if prog_data.is_sched_ext {
                // Render operation breakdown for sched_ext programs
                Self::render_operation_breakdown(
                    frame,
                    chunks[3],
                    params.bpf_program_stats,
                    params.theme,
                )?;
                // Render symbol table in the last chunk
                Self::render_symbol_table(
                    frame,
                    chunks[4],
                    params.filtered_symbols,
                    symbol_table_state,
                    params.theme,
                )?;
            } else {
                // Render symbol table (perf top style)
                Self::render_symbol_table(
                    frame,
                    chunks[3],
                    params.filtered_symbols,
                    symbol_table_state,
                    params.theme,
                )?;
            }
        } else {
            // No program selected, show message
            let paragraph = Paragraph::new("No BPF program selected")
                .block(
                    Block::bordered()
                        .title("BPF Program Detail")
                        .border_style(params.theme.border_style()),
                )
                .style(Style::default().fg(params.theme.text_color()));

            frame.render_widget(paragraph, area);
        }

        Ok(())
    }

    /// Renders the BPF programs table
    fn render_programs_table(
        frame: &mut Frame,
        area: Rect,
        table_state: &mut TableState,
        params: &ProgramsTableParams,
    ) -> Result<()> {
        // Build table rows with sched_ext highlighting
        let rows: Vec<Row> = params
            .programs_to_display
            .iter()
            .map(|(id, data)| {
                let cols = params.bpf_program_columns.visible_columns();
                let cells: Vec<Cell> = cols
                    .map(|col| {
                        let mut value = (col.value_fn)(*id, data);
                        // Special handling for runtime percentage column
                        if col.header == "Runtime %" {
                            let percentage =
                                data.runtime_percentage(params.bpf_program_stats.total_runtime_ns);
                            value = format!("{:.2}%", percentage);
                        }
                        Cell::from(value)
                    })
                    .collect();

                // Apply sched_ext highlighting
                let row = Row::new(cells);
                if data.is_sched_ext {
                    row.style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    row
                }
            })
            .collect();

        // Create header
        let header = Row::new(
            params
                .bpf_program_columns
                .visible_columns()
                .map(|col| Cell::from(col.header))
                .collect::<Vec<_>>(),
        )
        .style(params.theme.title_style())
        .height(1);

        // Get constraints for visible columns
        let constraints: Vec<Constraint> = params
            .bpf_program_columns
            .visible_columns()
            .map(|col| col.constraint)
            .collect();

        // Create title with filter information
        let title = if params.filtering {
            format!(
                "BPF Programs ({}/{} programs) - Filtering: {} - Press Enter for details, Esc to clear filter",
                params.programs_to_display.len(),
                params.bpf_program_stats.programs.len(),
                params.event_input_buffer
            )
        } else {
            format!(
                "BPF Programs ({} programs) - Press f to filter, Enter for details",
                params.bpf_program_stats.programs.len()
            )
        };

        // Create table widget
        let table = Table::new(rows, constraints)
            .header(header)
            .block(
                Block::bordered()
                    .title(title)
                    .border_style(params.theme.border_style())
                    .title_top(
                        Line::from(format!("{}ms", params.tick_rate_ms))
                            .style(params.theme.text_important_color())
                            .right_aligned(),
                    ),
            )
            .style(Style::default().fg(params.theme.text_color()))
            .row_highlight_style(Style::default().fg(params.theme.text_enabled_color()))
            .highlight_symbol(">> ");

        // Render the table
        frame.render_stateful_widget(table, area, table_state);
        Ok(())
    }

    /// Renders the filter input area
    fn render_filter_input(
        frame: &mut Frame,
        area: Rect,
        filter_input: &str,
        theme: &AppTheme,
    ) -> Result<()> {
        let input = Paragraph::new(filter_input)
            .style(Style::default().fg(theme.text_color()))
            .block(
                Block::bordered()
                    .title("Filter")
                    .border_style(theme.border_style()),
            );

        frame.render_widget(input, area);
        Ok(())
    }

    /// Render BPF overhead sparkline showing trend over time
    fn render_overhead_sparkline(
        frame: &mut Frame,
        area: Rect,
        bpf_overhead_history: &VecDeque<f64>,
        theme: &AppTheme,
    ) -> Result<()> {
        if bpf_overhead_history.is_empty() {
            // No data yet, show empty sparkline
            let sparkline = Sparkline::default()
                .block(
                    Block::bordered()
                        .title("BPF CPU Overhead: No data yet")
                        .border_style(theme.border_style()),
                )
                .style(Style::default().fg(Color::Cyan));

            frame.render_widget(sparkline, area);
            return Ok(());
        }

        // Calculate the number of data points needed to fill the width
        // Subtract 2 for borders
        let available_width = area.width.saturating_sub(2) as usize;

        // Prepare data to fill the entire width
        let mut data: Vec<u64> = Vec::with_capacity(available_width);

        if bpf_overhead_history.len() >= available_width {
            // We have enough data, take the most recent points
            data = bpf_overhead_history
                .iter()
                .rev()
                .take(available_width)
                .rev()
                .map(|v| (*v * 100.0) as u64)
                .collect();
        } else {
            // Not enough data yet, pad with zeros at the beginning
            let padding = available_width - bpf_overhead_history.len();
            data.extend(std::iter::repeat_n(0, padding));
            data.extend(bpf_overhead_history.iter().map(|v| (*v * 100.0) as u64));
        }

        let current_overhead = bpf_overhead_history.back().unwrap_or(&0.0);

        let sparkline = Sparkline::default()
            .block(
                Block::bordered()
                    .title(format!("BPF CPU Overhead: {:.2}%", current_overhead))
                    .border_style(theme.border_style()),
            )
            .data(&data)
            .style(Style::default().fg(Color::Cyan));

        frame.render_widget(sparkline, area);
        Ok(())
    }

    /// Render per-operation breakdown for sched_ext programs
    fn render_operation_breakdown(
        frame: &mut Frame,
        area: Rect,
        bpf_program_stats: &BpfProgStats,
        theme: &AppTheme,
    ) -> Result<()> {
        // Sort operations by runtime descending
        let mut ops: Vec<(&SchedExtOpType, &crate::bpf_prog_data::OperationStats)> =
            bpf_program_stats.operation_stats.iter().collect();
        ops.sort_by(|a, b| b.1.total_runtime_ns.cmp(&a.1.total_runtime_ns));

        let mut text = vec![
            Line::from(Span::styled(
                "sched_ext Callback Statistics:",
                Style::default().fg(theme.title_style().fg.unwrap_or(Color::Yellow)),
            )),
            Line::from(""),
            // Header row
            Line::from(vec![
                Span::styled(
                    format!("{:>12}  ", "Operation"),
                    Style::default()
                        .fg(theme.text_color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:>10}       ", "Calls"),
                    Style::default()
                        .fg(theme.text_color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:>8}       ", "Avg Time"),
                    Style::default()
                        .fg(theme.text_color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:>8}", "% Runtime"),
                    Style::default()
                        .fg(theme.text_color())
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        // Show top 8 operations
        for (op_type, stats) in ops.iter().take(8) {
            let avg_ns = if stats.total_calls > 0 {
                stats.total_runtime_ns / stats.total_calls
            } else {
                0
            };

            let pct = if bpf_program_stats.total_runtime_ns > 0 {
                (stats.total_runtime_ns as f64 / bpf_program_stats.total_runtime_ns as f64) * 100.0
            } else {
                0.0
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("{:>12}: ", op_type.display_name()),
                    Style::default().fg(theme.text_color()),
                ),
                Span::styled(
                    format!("{:>10} calls  ", stats.total_calls),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled(
                    format!("{:>8.2}μs avg  ", avg_ns as f64 / 1000.0),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled(
                    format!("{:>5.1}%", pct),
                    Style::default().fg(if pct > 50.0 { Color::Red } else { Color::Green }),
                ),
            ]);
            text.push(line);
        }

        let paragraph = Paragraph::new(text).block(
            Block::bordered()
                .title("sched_ext Callback Operations")
                .border_style(theme.border_style()),
        );

        frame.render_widget(paragraph, area);
        Ok(())
    }

    /// Renders BPF program information with emphasis on BPF_ENABLE_STATS data collection
    fn render_program_info(
        frame: &mut Frame,
        area: Rect,
        prog_data: &BpfProgData,
        bpf_perf_sampling_active: bool,
        active_event_name: &str,
        theme: &AppTheme,
        tick_rate_ms: usize,
    ) -> Result<()> {
        let info_text = vec![
            Line::from(vec![
                Span::styled("Program ID: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.id.to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled("  Type: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.prog_type.clone(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    if prog_data.name.is_empty() {
                        format!("<unnamed-{}>", prog_data.id)
                    } else {
                        prog_data.name.clone()
                    },
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled("Instructions: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.verified_insns.to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled("  BTF ID: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    if prog_data.btf_id == 0 {
                        "-".to_string()
                    } else {
                        prog_data.btf_id.to_string()
                    },
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled("UID: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.uid.to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled(
                    "  GPL Compatible: ",
                    Style::default().fg(theme.text_color()),
                ),
                Span::styled(
                    if prog_data.gpl_compatible {
                        "Yes"
                    } else {
                        "No"
                    }
                    .to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(""),
        ];

        // Create title with perf sampling status
        let title = if bpf_perf_sampling_active {
            format!(
                "BPF Program {} Details - Perf Sampling ACTIVE ({}) - Press 'p' to stop",
                prog_data.id, active_event_name
            )
        } else {
            format!(
                "BPF Program {} Details - Press 'p' to enable perf sampling",
                prog_data.id
            )
        };

        let paragraph = Paragraph::new(info_text)
            .block(
                Block::bordered()
                    .title(title)
                    .border_style(theme.border_style())
                    .title_top(
                        Line::from(format!("{}ms", tick_rate_ms))
                            .style(theme.text_important_color())
                            .right_aligned(),
                    ),
            )
            .style(Style::default().fg(theme.text_color()));

        frame.render_widget(paragraph, area);
        Ok(())
    }

    /// Renders BPF runtime statistics collected via BPF_ENABLE_STATS
    fn render_runtime_stats(
        frame: &mut Frame,
        area: Rect,
        prog_data: &BpfProgData,
        bpf_program_stats: &BpfProgStats,
        theme: &AppTheme,
    ) -> Result<()> {
        let avg_runtime_ns = if prog_data.run_cnt > 0 {
            prog_data.run_time_ns / prog_data.run_cnt
        } else {
            0
        };

        let runtime_percentage = prog_data.runtime_percentage(bpf_program_stats.total_runtime_ns);

        let stats_text = vec![
            Line::from(vec![
                Span::styled("Total Runtime: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    if prog_data.run_time_ns > 1_000_000_000 {
                        format!("{:.2}s", prog_data.run_time_ns as f64 / 1_000_000_000.0)
                    } else if prog_data.run_time_ns > 1_000_000 {
                        format!("{:.2}ms", prog_data.run_time_ns as f64 / 1_000_000.0)
                    } else if prog_data.run_time_ns > 1_000 {
                        format!("{:.2}μs", prog_data.run_time_ns as f64 / 1_000.0)
                    } else {
                        format!("{}ns", prog_data.run_time_ns)
                    },
                    Style::default()
                        .fg(theme.text_enabled_color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  Runtime %: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    format!("{:.2}%", runtime_percentage),
                    Style::default()
                        .fg(theme.text_enabled_color())
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Run Count: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.run_cnt.to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
                Span::styled("  Avg Runtime: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    if avg_runtime_ns > 1_000_000 {
                        format!("{:.2}ms", avg_runtime_ns as f64 / 1_000_000.0)
                    } else if avg_runtime_ns > 1_000 {
                        format!("{:.2}μs", avg_runtime_ns as f64 / 1_000.0)
                    } else {
                        format!("{}ns", avg_runtime_ns)
                    },
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled("Maps: ", Style::default().fg(theme.text_color())),
                Span::styled(
                    prog_data.nr_map_ids.to_string(),
                    Style::default().fg(theme.text_enabled_color()),
                ),
            ]),
            Line::from(""),
        ];

        let paragraph = Paragraph::new(stats_text)
            .block(
                Block::bordered()
                    .title("Runtime Statistics")
                    .border_style(theme.border_style()),
            )
            .style(Style::default().fg(theme.text_color()));

        frame.render_widget(paragraph, area);
        Ok(())
    }

    /// Renders historical sparklines for BPF program metrics
    fn render_program_sparklines(
        frame: &mut Frame,
        area: Rect,
        prog_data: &BpfProgData,
        theme: &AppTheme,
    ) -> Result<()> {
        // Split area into three horizontal sparklines (side by side)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
            ])
            .spacing(0)
            .split(area);

        // Calculate available width for data (subtract 2 for borders)
        let available_width = chunks[0].width.saturating_sub(2) as usize;

        // Convert runtime_history to Vec<u64> for Sparkline, trimming to available width
        let runtime_data: Vec<u64> = prog_data
            .runtime_history
            .iter()
            .rev()
            .take(available_width)
            .rev()
            .copied()
            .collect();

        // Convert calls_history deltas to calls per second, trimming to available width
        let mut calls_per_sec_data: Vec<u64> = Vec::new();
        if prog_data.calls_history.len() >= 2 && prog_data.timestamp_history.len() >= 2 {
            let start_idx = prog_data
                .calls_history
                .len()
                .saturating_sub(available_width + 1);
            for i in (start_idx + 1)..prog_data.calls_history.len() {
                let call_delta =
                    prog_data.calls_history[i].saturating_sub(prog_data.calls_history[i - 1]);
                let time_delta_ns = prog_data.timestamp_history[i]
                    .saturating_sub(prog_data.timestamp_history[i - 1]);

                if time_delta_ns > 0 {
                    let calls_per_sec =
                        (call_delta as f64 / time_delta_ns as f64) * 1_000_000_000.0;
                    calls_per_sec_data.push(calls_per_sec as u64);
                } else {
                    calls_per_sec_data.push(0);
                }
            }
        }

        // Calculate percentile data for sparkline (p50, p90, p99 over time), trimming to available width
        // For simplicity, we'll use a rolling window approach
        let mut p99_data: Vec<u64> = Vec::new();
        if prog_data.runtime_history.len() >= 10 {
            let start_idx = 9.max(
                prog_data
                    .runtime_history
                    .len()
                    .saturating_sub(available_width),
            );
            for i in start_idx..prog_data.runtime_history.len() {
                let window_start = i.saturating_sub(9);
                let window: Vec<u64> = prog_data
                    .runtime_history
                    .iter()
                    .skip(window_start)
                    .take(i - window_start + 1)
                    .copied()
                    .collect();
                let mut sorted = window.clone();
                sorted.sort_unstable();
                let idx = ((sorted.len() - 1) as f64 * 0.99) as usize;
                p99_data.push(sorted[idx]);
            }
        }

        // Helper function to calculate min/max/avg
        let calc_stats = |data: &[u64]| -> (u64, u64, u64) {
            if data.is_empty() {
                return (0, 0, 0);
            }
            let min = *data.iter().min().unwrap_or(&0);
            let max = *data.iter().max().unwrap_or(&0);
            let sum: u64 = data.iter().sum();
            let avg = sum / data.len() as u64;
            (min, max, avg)
        };

        // Calculate stats for each dataset
        let (runtime_min, runtime_max, runtime_avg) = calc_stats(&runtime_data);
        let (calls_min, calls_max, calls_avg) = calc_stats(&calls_per_sec_data);
        let (p99_min, p99_max, p99_avg) = calc_stats(&p99_data);

        // Runtime sparkline with min/max/avg labels
        let runtime_sparkline = Sparkline::default()
            .block(
                Block::bordered()
                    .title(format!(
                        "Runtime (ns/call) Min:{} Avg:{} Max:{}",
                        runtime_min, runtime_avg, runtime_max
                    ))
                    .border_style(theme.border_style()),
            )
            .data(&runtime_data)
            .max(runtime_max.max(1))
            .bar_set(NINE_LEVELS)
            .style(Style::default().fg(theme.text_important_color()));

        // Calls per second sparkline with min/max/avg labels
        let calls_sparkline = Sparkline::default()
            .block(
                Block::bordered()
                    .title(format!(
                        "Calls/sec Min:{} Avg:{} Max:{}",
                        calls_min, calls_avg, calls_max
                    ))
                    .border_style(theme.border_style()),
            )
            .data(&calls_per_sec_data)
            .max(calls_max.max(1))
            .bar_set(NINE_LEVELS)
            .style(Style::default().fg(theme.positive_value_color()));

        // P99 sparkline with min/max/avg labels
        let p99_sparkline = Sparkline::default()
            .block(
                Block::bordered()
                    .title(format!(
                        "P99 Runtime Min:{} Avg:{} Max:{}",
                        p99_min, p99_avg, p99_max
                    ))
                    .border_style(theme.border_style()),
            )
            .data(&p99_data)
            .max(p99_max.max(1))
            .bar_set(NINE_LEVELS)
            .style(Style::default().fg(theme.userspace_symbol_color()));

        frame.render_widget(runtime_sparkline, chunks[0]);
        frame.render_widget(calls_sparkline, chunks[1]);
        frame.render_widget(p99_sparkline, chunks[2]);

        Ok(())
    }

    /// Renders BPF program symbol table (perf top style)
    fn render_symbol_table(
        frame: &mut Frame,
        area: Rect,
        filtered_symbols: &[SymbolSample],
        symbol_table_state: &mut TableState,
        theme: &AppTheme,
    ) -> Result<()> {
        // Build table rows from filtered symbols with module name and source location
        let rows: Vec<Row> = filtered_symbols
            .iter()
            .map(|symbol| {
                let source_location = if let (Some(file), Some(line)) = (
                    &symbol.symbol_info.file_name,
                    symbol.symbol_info.line_number,
                ) {
                    format!("{}:{}", file, line)
                } else {
                    "-".to_string()
                };

                Row::new(vec![
                    Cell::from(format!("{:.2}%", symbol.percentage)),
                    Cell::from(symbol.count.to_string()),
                    Cell::from(format!("0x{:x}", symbol.symbol_info.address)),
                    Cell::from(symbol.symbol_info.symbol_name.clone()),
                    Cell::from(symbol.symbol_info.module_name.clone()),
                    Cell::from(source_location),
                ])
            })
            .collect();

        // Create header
        let header = Row::new(vec![
            Cell::from("Overhead"),
            Cell::from("Samples"),
            Cell::from("Address"),
            Cell::from("Symbol"),
            Cell::from("Module"),
            Cell::from("Source"),
        ])
        .style(theme.title_style())
        .height(1);

        // Define column constraints
        let constraints = vec![
            Constraint::Length(10), // Overhead
            Constraint::Length(10), // Samples
            Constraint::Length(16), // Address
            Constraint::Fill(1),    // Symbol (with line number included in name)
            Constraint::Length(10), // Module
            Constraint::Length(20), // Source location
        ];

        // Create table widget
        let table = Table::new(rows, constraints)
            .header(header)
            .block(
                Block::bordered()
                    .title(format!(
                        "BPF Program Symbols ({} symbols) - Line numbers from jited_line_info",
                        filtered_symbols.len()
                    ))
                    .border_style(theme.border_style()),
            )
            .style(Style::default().fg(theme.text_color()))
            .row_highlight_style(Style::default().fg(theme.text_enabled_color()))
            .highlight_symbol(">> ");

        // Render the table
        frame.render_stateful_widget(table, area, symbol_table_state);
        Ok(())
    }
}
