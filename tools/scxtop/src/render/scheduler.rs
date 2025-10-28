// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::util::sanitize_nbsp;
use crate::{AppTheme, EventData, VecStats, ViewState};
use anyhow::Result;
use num_format::{SystemLocale, ToFormattedString};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Borders, Clear, Paragraph, RenderDirection,
    Sparkline,
};
use ratatui::Frame;
use std::collections::BTreeMap;

/// Context for scheduler rendering operations
pub struct SchedulerViewContext<'a> {
    pub event: &'a str,
    pub view_state: &'a ViewState,
    pub scheduler_name: &'a str,
    pub dsq_data: &'a BTreeMap<u64, EventData>,
    pub sample_rate: u32,
    pub max_sched_events: usize,
}

/// Configuration for rendering scheduler views
pub struct SchedulerRenderConfig<'a> {
    pub localize: bool,
    pub locale: &'a SystemLocale,
    pub theme: &'a AppTheme,
    pub render_title: bool,
    pub render_sample_rate: bool,
}

impl<'a> SchedulerRenderConfig<'a> {
    pub fn new(
        localize: bool,
        locale: &'a SystemLocale,
        theme: &'a AppTheme,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Self {
        Self {
            localize,
            locale,
            theme,
            render_title,
            render_sample_rate,
        }
    }
}

/// Configuration for scheduler statistics display
pub struct SchedulerStatsConfig {
    pub tick_rate_ms: usize,
    pub dispatch_keep_last: i64,
    pub select_cpu_fallback: i64,
}

impl SchedulerStatsConfig {
    pub fn new(tick_rate_ms: usize, dispatch_keep_last: i64, select_cpu_fallback: i64) -> Self {
        Self {
            tick_rate_ms,
            dispatch_keep_last,
            select_cpu_fallback,
        }
    }
}

/// Renderer for scheduler views
pub struct SchedulerRenderer;

impl SchedulerRenderer {
    /// Renders the main scheduler view
    pub fn render_scheduler_view(
        frame: &mut Frame,
        area: Rect,
        ctx: &SchedulerViewContext,
        config: &SchedulerRenderConfig,
    ) -> Result<usize> {
        // If no scheduler is attached, display a message and return early.
        if ctx.scheduler_name.is_empty() {
            Self::render_error_msg(frame, area, "Missing Scheduler");
            return Ok(ctx.max_sched_events);
        }

        match ctx.view_state {
            ViewState::Sparkline => Self::render_scheduler_sparklines(frame, area, ctx, config),
            ViewState::BarChart => Self::render_scheduler_barchart(frame, area, ctx, config),
            ViewState::LineGauge => Self::render_scheduler_sparklines(frame, area, ctx, config),
        }
    }

    /// Renders scheduler statistics panel
    pub fn render_scheduler_stats(
        frame: &mut Frame,
        area: Rect,
        scheduler_name: &str,
        sched_stats_raw: &str,
        stats_config: &SchedulerStatsConfig,
        theme: &AppTheme,
    ) -> Result<()> {
        let paragraph = Paragraph::new(sched_stats_raw.to_string());
        let block = Block::bordered()
            .title_top(
                Line::from(scheduler_name.to_string())
                    .style(theme.title_style())
                    .centered(),
            )
            .title_top(
                Line::from(format!("{}ms", stats_config.tick_rate_ms))
                    .style(theme.text_important_color())
                    .right_aligned(),
            )
            .title_bottom(
                Line::from(format!("keep_last {}", stats_config.dispatch_keep_last))
                    .style(theme.text_important_color())
                    .right_aligned(),
            )
            .title_bottom(
                Line::from(format!("select_fall {}", stats_config.select_cpu_fallback))
                    .style(theme.text_important_color())
                    .left_aligned(),
            )
            .style(theme.border_style())
            .border_type(BorderType::Rounded);

        frame.render_widget(paragraph.block(block), area);

        Ok(())
    }

    /// Renders the scheduler state as sparklines.
    fn render_scheduler_sparklines(
        frame: &mut Frame,
        area: Rect,
        ctx: &SchedulerViewContext,
        config: &SchedulerRenderConfig,
    ) -> Result<usize> {
        let num_dsqs = ctx
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(ctx.event))
            .count();

        let mut dsq_constraints = Vec::new();

        let area_width = area.width as usize;
        let new_max_sched_events = if area_width != ctx.max_sched_events {
            area_width
        } else {
            ctx.max_sched_events
        };

        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(if config.render_title {
                    Line::from(ctx.scheduler_name.to_string())
                        .style(config.theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(config.theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(new_max_sched_events);
        }

        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        Self::dsq_sparklines(ctx.event, ctx.dsq_data, ctx.sample_rate, config, true)
            .iter()
            .enumerate()
            .for_each(|(j, dsq_sparkline)| {
                frame.render_widget(dsq_sparkline, dsqs_verticle[j]);
            });

        Ok(new_max_sched_events)
    }

    /// Renders the scheduler state as barcharts.
    fn render_scheduler_barchart(
        frame: &mut Frame,
        area: Rect,
        ctx: &SchedulerViewContext,
        config: &SchedulerRenderConfig,
    ) -> Result<usize> {
        let num_dsqs = ctx.dsq_data.len();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(if config.render_title {
                    Line::from(ctx.scheduler_name.to_string())
                        .style(config.theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(config.theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(0);
        }

        let dsq_global_iter = ctx
            .dsq_data
            .values()
            .flat_map(|dsq_data| dsq_data.event_data_immut(ctx.event))
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(if config.localize {
                    format!(
                        "{} avg {} max {} min {}",
                        ctx.event,
                        sanitize_nbsp(stats.avg.to_formatted_string(config.locale)),
                        sanitize_nbsp(stats.max.to_formatted_string(config.locale)),
                        sanitize_nbsp(stats.min.to_formatted_string(config.locale))
                    )
                } else {
                    format!(
                        "{} avg {} max {} min {}",
                        ctx.event, stats.avg, stats.max, stats.min,
                    )
                })
                .style(config.theme.title_style())
                .centered(),
            )
            .title_top(if config.render_sample_rate {
                Line::from(format!("sample rate {}", ctx.sample_rate))
                    .style(config.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(config.theme.border_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = Self::dsq_bars(ctx.event, ctx.dsq_data, config);

        let barchart = BarChart::default()
            .data(BarGroup::default().bars(&dsq_bars))
            .block(bar_block)
            .max(stats.max)
            .direction(Direction::Horizontal)
            .bar_gap(0)
            .bar_width(1);

        frame.render_widget(barchart, area);
        Ok(0)
    }

    /// Creates a sparkline for a single DSQ
    fn dsq_sparkline(
        event: &str,
        dsq_id: u64,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        borders: Borders,
        config: &SchedulerRenderConfig,
    ) -> Sparkline<'static> {
        let data = if dsq_data.contains_key(&dsq_id) {
            let dsq_data = dsq_data.get(&dsq_id).unwrap();
            dsq_data.event_data_immut(event)
        } else {
            Vec::new()
        };
        // XXX: this should be max across all CPUs
        let stats = VecStats::new(&data, None);
        Sparkline::default()
            .data(&data)
            .max(stats.max)
            .direction(RenderDirection::RightToLeft)
            .style(config.theme.sparkline_style())
            .block(
                Block::new()
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(config.theme.border_style())
                    .title_top(if config.render_sample_rate {
                        Line::from(format!("sample rate {}", sample_rate))
                            .style(config.theme.text_important_color())
                            .right_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(if config.render_title {
                        Line::from(format!("{event} "))
                            .style(config.theme.title_style())
                            .left_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(
                        Line::from(if config.localize {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id,
                                sanitize_nbsp(stats.avg.to_formatted_string(config.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(config.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(config.locale))
                            )
                        } else {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id, stats.avg, stats.max, stats.min,
                            )
                        })
                        .style(config.theme.title_style())
                        .centered(),
                    ),
            )
    }

    /// Generates dsq sparklines.
    fn dsq_sparklines(
        event: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        config: &SchedulerRenderConfig,
        render_first_title: bool,
    ) -> Vec<Sparkline<'static>> {
        dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .enumerate()
            .map(|(j, (dsq_id, _data))| {
                let is_first = j == 0;
                let item_config = if is_first && render_first_title {
                    config
                } else {
                    &SchedulerRenderConfig {
                        localize: config.localize,
                        locale: config.locale,
                        theme: config.theme,
                        render_title: is_first && render_first_title && config.render_title,
                        render_sample_rate: is_first
                            && render_first_title
                            && config.render_sample_rate,
                    }
                };
                Self::dsq_sparkline(
                    event,
                    *dsq_id,
                    dsq_data,
                    sample_rate,
                    Borders::ALL,
                    item_config,
                )
            })
            .collect()
    }

    /// Generates a DSQ bar chart.
    fn dsq_bar(
        dsq: u64,
        value: u64,
        avg: u64,
        max: u64,
        min: u64,
        config: &SchedulerRenderConfig,
    ) -> Bar<'static> {
        let gradient_color = Self::gradient5_color(value, max, min, config.theme);

        Bar::default()
            .value(value)
            .style(Style::default().fg(gradient_color))
            .label(Line::from(if config.localize {
                format!(
                    "{:#X} avg {} max {} min {}",
                    dsq,
                    sanitize_nbsp(avg.to_formatted_string(config.locale)),
                    sanitize_nbsp(max.to_formatted_string(config.locale)),
                    sanitize_nbsp(min.to_formatted_string(config.locale))
                )
            } else {
                format!("{dsq:#X} avg {avg} max {max} min {min}",)
            }))
            .text_value(if config.localize {
                sanitize_nbsp(value.to_formatted_string(config.locale))
            } else {
                format!("{value}")
            })
    }

    /// Generates DSQ bar charts.
    fn dsq_bars(
        event: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        config: &SchedulerRenderConfig,
    ) -> Vec<Bar<'static>> {
        dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .map(|(dsq_id, dsq_data)| {
                let values = dsq_data.event_data_immut(event);
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, None);
                Self::dsq_bar(*dsq_id, value, stats.avg, stats.max, stats.min, config)
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
