// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::util::sanitize_nbsp;
use crate::{AppTheme, EventData, ProcData, StatAggregation, VecStats, ViewState};
use anyhow::Result;
use num_format::{SystemLocale, ToFormattedString};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, Paragraph, RenderDirection,
    Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, Table, TableState,
};
use ratatui::Frame;
use std::collections::{BTreeMap, HashSet};

/// Parameters for rendering scheduler views
pub struct SchedulerViewParams<'a> {
    pub event: &'a str,
    pub scheduler_name: &'a str,
    pub dsq_data: &'a BTreeMap<u64, EventData>,
    pub sample_rate: u32,
    pub localize: bool,
    pub locale: &'a SystemLocale,
    pub theme: &'a AppTheme,
    pub render_title: bool,
    pub render_sample_rate: bool,
}

/// Parameters for DSQ visualization
pub struct DsqRenderParams<'a> {
    pub event: &'a str,
    pub dsq_data: &'a BTreeMap<u64, EventData>,
    pub sample_rate: u32,
    pub localize: bool,
    pub locale: &'a SystemLocale,
    pub theme: &'a AppTheme,
    pub render_title: bool,
    pub render_sample_rate: bool,
}

/// Parameters for DSQ summary table
pub struct DsqSummaryParams<'a> {
    pub scheduler_name: &'a str,
    pub dsq_data: &'a BTreeMap<u64, EventData>,
    pub sample_rate: u32,
    pub dsq_filter_text: &'a str,
    pub filtering: bool,
    pub filter_input: &'a str,
    pub theme: &'a AppTheme,
}

/// Parameters for process latency table
pub struct ProcessLatencyParams<'a> {
    pub proc_data: &'a BTreeMap<i32, ProcData>,
    pub dsq_filter_text: &'a str,
    pub theme: &'a AppTheme,
}

/// Renderer for scheduler views
pub struct SchedulerRenderer;

impl SchedulerRenderer {
    /// Renders the main scheduler view
    #[allow(clippy::too_many_arguments)]
    pub fn render_scheduler_view(
        frame: &mut Frame,
        area: Rect,
        view_state: &ViewState,
        max_sched_events: usize,
        params: &SchedulerViewParams,
    ) -> Result<usize> {
        // If no scheduler is attached, display a message and return early.
        if params.scheduler_name.is_empty() {
            Self::render_error_msg(frame, area, "Missing Scheduler");
            return Ok(max_sched_events);
        }

        match view_state {
            ViewState::Sparkline => {
                Self::render_scheduler_sparklines(frame, area, max_sched_events, params)
            }
            ViewState::BarChart => Self::render_scheduler_barchart(frame, area, params),
            ViewState::LineGauge => {
                Self::render_scheduler_sparklines(frame, area, max_sched_events, params)
            }
        }
    }

    /// Renders DSQ latency summary table with percentile aggregations.
    /// Returns the number of rows for scroll state management.
    pub fn render_dsq_summary_table(
        frame: &mut Frame,
        area: Rect,
        params: &DsqSummaryParams,
        table_state: &mut TableState,
    ) -> Result<usize> {
        let percentile_set: HashSet<StatAggregation> = [
            StatAggregation::P50,
            StatAggregation::P90,
            StatAggregation::P99,
        ]
        .into_iter()
        .collect();

        struct DsqEntry {
            dsq_id: u64,
            p50: u64,
            p90: u64,
            p99: u64,
            avg: u64,
            max: u64,
            q_max: u64,
            count: usize,
        }

        let mut entries: Vec<DsqEntry> = Vec::new();
        for (dsq_id, event_data) in params.dsq_data.iter() {
            if !params.dsq_filter_text.is_empty() {
                let dsq_hex = format!("{:#X}", dsq_id);
                let filter_upper = params.dsq_filter_text.to_uppercase();
                if !dsq_hex.to_uppercase().contains(&filter_upper) {
                    continue;
                }
            }
            let lat_data = event_data.event_data_immut("dsq_lat_us");
            let non_zero: Vec<u64> = lat_data.into_iter().filter(|&v| v > 0).collect();
            if non_zero.is_empty() {
                continue;
            }
            let lat_stats = VecStats::new(&non_zero, Some(percentile_set.clone()));
            let nr_queued_data = event_data.event_data_immut("dsq_nr_queued");
            let nr_non_zero: Vec<u64> = nr_queued_data.into_iter().filter(|&v| v > 0).collect();
            let nr_stats = VecStats::new(&nr_non_zero, None);

            let pmap = lat_stats.percentiles.as_ref();
            entries.push(DsqEntry {
                dsq_id: *dsq_id,
                p50: pmap
                    .and_then(|m| m.get(&StatAggregation::P50))
                    .copied()
                    .unwrap_or(0),
                p90: pmap
                    .and_then(|m| m.get(&StatAggregation::P90))
                    .copied()
                    .unwrap_or(0),
                p99: pmap
                    .and_then(|m| m.get(&StatAggregation::P99))
                    .copied()
                    .unwrap_or(0),
                avg: lat_stats.avg,
                max: lat_stats.max,
                q_max: nr_stats.max,
                count: non_zero.len(),
            });
        }

        // Sort by avg desc, then p99 desc, then q_max desc
        entries.sort_by(|a, b| {
            b.avg
                .cmp(&a.avg)
                .then(b.p99.cmp(&a.p99))
                .then(b.q_max.cmp(&a.q_max))
        });

        let row_count = entries.len();

        let rows: Vec<Row> = entries
            .iter()
            .map(|e| {
                let color = Self::latency_group_color(e.p90, params.theme);
                Row::new(vec![
                    Cell::from(format!("{:#X}", e.dsq_id)),
                    Cell::from(format!("{}", e.p50)),
                    Cell::from(format!("{}", e.p90)),
                    Cell::from(format!("{}", e.p99)),
                    Cell::from(format!("{}", e.avg)),
                    Cell::from(format!("{}", e.max)),
                    Cell::from(format!("{}", e.q_max)),
                    Cell::from(format!("{}", e.count)),
                ])
                .style(Style::default().fg(color))
            })
            .collect();

        let header = Row::new(vec![
            Cell::from("DSQ"),
            Cell::from("p50"),
            Cell::from("p90"),
            Cell::from("p99"),
            Cell::from("avg ▼"),
            Cell::from("max"),
            Cell::from("q_max"),
            Cell::from("count"),
        ])
        .style(params.theme.text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Min(14),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
        ];

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(params.theme.border_style())
            .title_top(
                Line::from(format!(
                    "{} DSQ Latency Summary (μs)",
                    params.scheduler_name
                ))
                .style(params.theme.title_style())
                .centered(),
            )
            .title_top(
                Line::from(vec![
                    Span::styled("f", params.theme.text_important_color()),
                    Span::styled(
                        if params.filtering {
                            format!("ilter DSQ: {}_", params.filter_input)
                        } else if !params.dsq_filter_text.is_empty() {
                            format!("ilter DSQ: {}", params.dsq_filter_text)
                        } else {
                            "ilter".to_string()
                        },
                        params.theme.text_color(),
                    ),
                ])
                .left_aligned(),
            )
            .title_top(
                Line::from(format!("sample rate {}", params.sample_rate))
                    .style(params.theme.text_important_color())
                    .right_aligned(),
            );

        let table = Table::new(rows, constraints)
            .header(header)
            .block(block)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(table, area, table_state);

        // Scrollbar
        let visible_rows = area.height.saturating_sub(4) as usize;
        if row_count > visible_rows {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));
            let scroll_pos = table_state.selected().unwrap_or(0);
            let mut scrollbar_state = ScrollbarState::new(row_count).position(scroll_pos);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(ratatui::layout::Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        }

        Ok(row_count)
    }

    /// Renders per-process scheduling latency table.
    /// Returns the number of rows for scroll state management.
    pub fn render_process_latency_table(
        frame: &mut Frame,
        area: Rect,
        params: &ProcessLatencyParams,
        table_state: &mut TableState,
    ) -> Result<usize> {
        let percentile_set: HashSet<StatAggregation> = [
            StatAggregation::P50,
            StatAggregation::P90,
            StatAggregation::P99,
        ]
        .into_iter()
        .collect();

        struct ProcEntry {
            pid: i32,
            comm: String,
            dsq: String,
            cpu: i32,
            p50: u64,
            p90: u64,
            p99: u64,
            slice_avg_us: u64,
            count: usize,
        }

        let mut entries: Vec<ProcEntry> = Vec::new();

        for (pid, proc_data) in params.proc_data.iter() {
            if !params.dsq_filter_text.is_empty() {
                let proc_dsq_hex = proc_data
                    .dsq
                    .map(|d| format!("{:#X}", d))
                    .unwrap_or_default();
                let filter_upper = params.dsq_filter_text.to_uppercase();
                if !proc_dsq_hex.to_uppercase().contains(&filter_upper) {
                    continue;
                }
            }
            let lat_data = proc_data.event_data_immut("lat_us");
            let non_zero: Vec<u64> = lat_data.into_iter().filter(|&v| v > 0).collect();
            if non_zero.is_empty() {
                continue;
            }
            let lat_stats = VecStats::new(&non_zero, Some(percentile_set.clone()));
            let pmap = lat_stats.percentiles.as_ref();

            let slice_data = proc_data.event_data_immut("slice_consumed");
            let slice_non_zero: Vec<u64> = slice_data.into_iter().filter(|&v| v > 0).collect();
            let slice_stats = VecStats::new(&slice_non_zero, None);

            entries.push(ProcEntry {
                pid: *pid,
                comm: proc_data.process_name.clone(),
                dsq: proc_data
                    .dsq
                    .map(|d| format!("{:#X}", d))
                    .unwrap_or_default(),
                cpu: proc_data.cpu,
                p50: pmap
                    .and_then(|m| m.get(&StatAggregation::P50))
                    .copied()
                    .unwrap_or(0),
                p90: pmap
                    .and_then(|m| m.get(&StatAggregation::P90))
                    .copied()
                    .unwrap_or(0),
                p99: pmap
                    .and_then(|m| m.get(&StatAggregation::P99))
                    .copied()
                    .unwrap_or(0),
                slice_avg_us: slice_stats.avg / 1000, // ns to μs
                count: non_zero.len(),
            });
        }

        // Sort by p90 descending (highest latency first)
        entries.sort_by(|a, b| b.p90.cmp(&a.p90));

        let header = Row::new(vec![
            Cell::from("PID"),
            Cell::from("COMM"),
            Cell::from("DSQ"),
            Cell::from("CPU"),
            Cell::from("lat p50"),
            Cell::from("lat p90"),
            Cell::from("lat p99"),
            Cell::from("slice(μs)"),
            Cell::from("count"),
        ])
        .style(params.theme.text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Min(8),
            Constraint::Min(16),
            Constraint::Min(14),
            Constraint::Min(5),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(8),
            Constraint::Min(10),
            Constraint::Min(8),
        ];

        let rows: Vec<Row> = entries
            .iter()
            .map(|e| {
                let color = Self::latency_group_color(e.p90, params.theme);
                Row::new(vec![
                    Cell::from(format!("{}", e.pid)),
                    Cell::from(e.comm.clone()),
                    Cell::from(e.dsq.clone()),
                    Cell::from(format!("{}", e.cpu)),
                    Cell::from(format!("{}", e.p50)),
                    Cell::from(format!("{}", e.p90)),
                    Cell::from(format!("{}", e.p99)),
                    Cell::from(format!("{}", e.slice_avg_us)),
                    Cell::from(format!("{}", e.count)),
                ])
                .style(Style::default().fg(color))
            })
            .collect();

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(params.theme.border_style())
            .title_top(
                Line::from(format!(
                    "Process Scheduling Latency (μs) ({} procs)",
                    entries.len()
                ))
                .style(params.theme.title_style())
                .centered(),
            );

        let row_count = entries.len();

        let table = Table::new(rows, constraints)
            .header(header)
            .block(block)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(table, area, table_state);

        // Scrollbar
        let visible_rows = area.height.saturating_sub(4) as usize;
        if row_count > visible_rows {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));
            let scroll_pos = table_state.selected().unwrap_or(0);
            let mut scrollbar_state = ScrollbarState::new(row_count).position(scroll_pos);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(ratatui::layout::Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        }

        Ok(row_count)
    }

    /// Returns color based on latency group thresholds (similar to rsched)
    fn latency_group_color(p90_us: u64, theme: &AppTheme) -> Color {
        // Latency groups matching rsched:
        // <10μs green, 10-100μs light green, 100-1000μs yellow, 1-10ms orange, >10ms red
        theme.gradient_5(p90_us as f64, 10.0, 100.0, 1000.0, 10000.0, false)
    }

    /// Renders the scheduler state as sparklines.
    #[allow(clippy::too_many_arguments)]
    fn render_scheduler_sparklines(
        frame: &mut Frame,
        area: Rect,
        max_sched_events: usize,
        params: &SchedulerViewParams,
    ) -> Result<usize> {
        let num_dsqs = params
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(params.event))
            .count();

        let mut dsq_constraints = Vec::new();

        let area_width = area.width as usize;
        let new_max_sched_events = if area_width != max_sched_events {
            area_width
        } else {
            max_sched_events
        };

        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(if params.render_title {
                    Line::from(params.scheduler_name.to_string())
                        .style(params.theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(params.theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(new_max_sched_events);
        }

        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        let dsq_params = DsqRenderParams {
            event: params.event,
            dsq_data: params.dsq_data,
            sample_rate: params.sample_rate,
            localize: params.localize,
            locale: params.locale,
            theme: params.theme,
            render_title: true,
            render_sample_rate: params.render_sample_rate,
        };

        Self::dsq_sparklines(&dsq_params)
            .iter()
            .enumerate()
            .for_each(|(j, dsq_sparkline)| {
                frame.render_widget(dsq_sparkline, dsqs_verticle[j]);
            });

        Ok(new_max_sched_events)
    }

    /// Renders the scheduler state as barcharts.
    #[allow(clippy::too_many_arguments)]
    fn render_scheduler_barchart(
        frame: &mut Frame,
        area: Rect,
        params: &SchedulerViewParams,
    ) -> Result<usize> {
        let num_dsqs = params.dsq_data.len();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(if params.render_title {
                    Line::from(params.scheduler_name.to_string())
                        .style(params.theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(params.theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(0);
        }

        let dsq_global_iter = params
            .dsq_data
            .values()
            .flat_map(|dsq_data| dsq_data.event_data_immut(params.event))
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(if params.localize {
                    format!(
                        "{} avg {} max {} min {}",
                        params.event,
                        sanitize_nbsp(stats.avg.to_formatted_string(params.locale)),
                        sanitize_nbsp(stats.max.to_formatted_string(params.locale)),
                        sanitize_nbsp(stats.min.to_formatted_string(params.locale))
                    )
                } else {
                    format!(
                        "{} avg {} max {} min {}",
                        params.event, stats.avg, stats.max, stats.min,
                    )
                })
                .style(params.theme.title_style())
                .centered(),
            )
            .title_top(if params.render_sample_rate {
                Line::from(format!("sample rate {}", params.sample_rate))
                    .style(params.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(params.theme.border_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = Self::dsq_bars(
            params.event,
            params.dsq_data,
            params.localize,
            params.locale,
            params.theme,
        );

        let barchart = BarChart::default()
            .data(BarGroup::default().bars(&dsq_bars))
            .block(bar_block)
            .direction(Direction::Horizontal)
            .bar_gap(0)
            .bar_width(1);

        frame.render_widget(barchart, area);
        Ok(0)
    }

    /// Creates a sparkline for a single DSQ
    #[allow(clippy::too_many_arguments)]
    fn dsq_sparkline(
        dsq_id: u64,
        borders: Borders,
        render_title: bool,
        render_sample_rate: bool,
        params: &DsqRenderParams,
    ) -> Sparkline<'static> {
        let data = if params.dsq_data.contains_key(&dsq_id) {
            let dsq_data = params.dsq_data.get(&dsq_id).unwrap();
            dsq_data.event_data_immut(params.event)
        } else {
            Vec::new()
        };
        // XXX: this should be max across all CPUs
        let stats = VecStats::new(&data, None);
        Sparkline::default()
            .data(&data)
            .max(stats.max)
            .direction(RenderDirection::RightToLeft)
            .style(params.theme.sparkline_style())
            .block(
                Block::new()
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(params.theme.border_style())
                    .title_top(if render_sample_rate {
                        Line::from(format!("sample rate {}", params.sample_rate))
                            .style(params.theme.text_important_color())
                            .right_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(if render_title {
                        Line::from(format!("{} ", params.event))
                            .style(params.theme.title_style())
                            .left_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(
                        Line::from(if params.localize {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id,
                                sanitize_nbsp(stats.avg.to_formatted_string(params.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(params.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(params.locale))
                            )
                        } else {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id, stats.avg, stats.max, stats.min,
                            )
                        })
                        .style(params.theme.title_style())
                        .centered(),
                    ),
            )
    }

    /// Generates dsq sparklines.
    fn dsq_sparklines(params: &DsqRenderParams) -> Vec<Sparkline<'static>> {
        params
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(params.event))
            .enumerate()
            .map(|(j, (dsq_id, _data))| {
                Self::dsq_sparkline(
                    *dsq_id,
                    Borders::ALL,
                    j == 0 && params.render_title,
                    j == 0 && params.render_sample_rate,
                    params,
                )
            })
            .collect()
    }

    /// Generates a DSQ bar chart.
    fn dsq_bar(
        dsq: u64,
        value: u64,
        max: u64,
        min: u64,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Bar<'static> {
        let gradient_color = Self::gradient5_color(value, max, min, theme);

        Bar::default()
            .value(value)
            .style(Style::default().fg(gradient_color))
            .label(Line::from(format!("{dsq:#X}")))
            .text_value(if localize {
                sanitize_nbsp(value.to_formatted_string(locale))
            } else {
                format!("{value}")
            })
    }

    /// Generates DSQ bar charts.
    fn dsq_bars(
        event: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
    ) -> Vec<Bar<'static>> {
        dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .map(|(dsq_id, dsq_data)| {
                let values = dsq_data.event_data_immut(event);
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, None);
                Self::dsq_bar(
                    *dsq_id, value, stats.max, stats.min, localize, locale, theme,
                )
            })
            .collect()
    }

    /// Returns the gradient color.
    fn gradient5_color(value: u64, max: u64, min: u64, theme: &AppTheme) -> Color {
        if max > min {
            let range = max - min;
            let very_low_threshold = min as f64 + (range as f64 * 0.2);
            let low_threshold = min as f64 + (range as f64 * 0.4);
            let high_threshold = min as f64 + (range as f64 * 0.6);
            let very_high_threshold = min as f64 + (range as f64 * 0.8);

            theme.gradient_5(
                value as f64,
                very_low_threshold,
                low_threshold,
                high_threshold,
                very_high_threshold,
                false,
            )
        } else {
            theme.sparkline_style().fg.unwrap_or_default()
        }
    }

    /// Draw an error message.
    fn render_error_msg(frame: &mut Frame, area: Rect, msg: &str) {
        frame.render_widget(Clear, area);

        let top_pad = area.height.saturating_sub(1) / 2;

        let mut lines: Vec<Line> = Vec::with_capacity(top_pad as usize + 1);
        for _ in 0..top_pad {
            lines.push(Line::raw(""));
        }
        lines.push(Line::from(Span::styled(
            msg,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(Style::default().fg(Color::Red));

        let para = Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(block);

        frame.render_widget(para, area);
    }
}
