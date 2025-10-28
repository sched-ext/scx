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

/// Renderer for scheduler views
pub struct SchedulerRenderer;

impl SchedulerRenderer {
    /// Renders the main scheduler view
    #[allow(clippy::too_many_arguments)]
    pub fn render_scheduler_view(
        frame: &mut Frame,
        event: &str,
        area: Rect,
        view_state: &ViewState,
        scheduler_name: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        max_sched_events: usize,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Result<usize> {
        // If no scheduler is attached, display a message and return early.
        if scheduler_name.is_empty() {
            Self::render_error_msg(frame, area, "Missing Scheduler");
            return Ok(max_sched_events);
        }

        match view_state {
            ViewState::Sparkline => Self::render_scheduler_sparklines(
                frame,
                event,
                area,
                scheduler_name,
                dsq_data,
                sample_rate,
                max_sched_events,
                localize,
                locale,
                theme,
                render_title,
                render_sample_rate,
            ),
            ViewState::BarChart => Self::render_scheduler_barchart(
                frame,
                event,
                area,
                scheduler_name,
                dsq_data,
                sample_rate,
                localize,
                locale,
                theme,
                render_title,
                render_sample_rate,
            ),
            ViewState::LineGauge => Self::render_scheduler_sparklines(
                frame,
                event,
                area,
                scheduler_name,
                dsq_data,
                sample_rate,
                max_sched_events,
                localize,
                locale,
                theme,
                render_title,
                render_sample_rate,
            ),
        }
    }

    /// Renders scheduler statistics panel
    #[allow(clippy::too_many_arguments)]
    pub fn render_scheduler_stats(
        frame: &mut Frame,
        area: Rect,
        scheduler_name: &str,
        sched_stats_raw: &str,
        tick_rate_ms: usize,
        dispatch_keep_last: i64,
        select_cpu_fallback: i64,
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
                Line::from(format!("{}ms", tick_rate_ms))
                    .style(theme.text_important_color())
                    .right_aligned(),
            )
            .title_bottom(
                Line::from(format!("keep_last {}", dispatch_keep_last))
                    .style(theme.text_important_color())
                    .right_aligned(),
            )
            .title_bottom(
                Line::from(format!("select_fall {}", select_cpu_fallback))
                    .style(theme.text_important_color())
                    .left_aligned(),
            )
            .style(theme.border_style())
            .border_type(BorderType::Rounded);

        frame.render_widget(paragraph.block(block), area);

        Ok(())
    }

    /// Renders the scheduler state as sparklines.
    #[allow(clippy::too_many_arguments)]
    fn render_scheduler_sparklines(
        frame: &mut Frame,
        event: &str,
        area: Rect,
        scheduler_name: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        max_sched_events: usize,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Result<usize> {
        let num_dsqs = dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
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
                .title_top(if render_title {
                    Line::from(scheduler_name.to_string())
                        .style(theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(new_max_sched_events);
        }

        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        Self::dsq_sparklines(
            event,
            dsq_data,
            sample_rate,
            localize,
            locale,
            theme,
            true,
            render_sample_rate,
        )
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
        event: &str,
        area: Rect,
        scheduler_name: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Result<usize> {
        let num_dsqs = dsq_data.len();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(if render_title {
                    Line::from(scheduler_name.to_string())
                        .style(theme.title_style())
                        .centered()
                } else {
                    Line::from("".to_string())
                })
                .style(theme.border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(0);
        }

        let dsq_global_iter = dsq_data
            .values()
            .flat_map(|dsq_data| dsq_data.event_data_immut(event))
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(if localize {
                    format!(
                        "{} avg {} max {} min {}",
                        event,
                        sanitize_nbsp(stats.avg.to_formatted_string(locale)),
                        sanitize_nbsp(stats.max.to_formatted_string(locale)),
                        sanitize_nbsp(stats.min.to_formatted_string(locale))
                    )
                } else {
                    format!(
                        "{} avg {} max {} min {}",
                        event, stats.avg, stats.max, stats.min,
                    )
                })
                .style(theme.title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {sample_rate}"))
                    .style(theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(theme.border_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = Self::dsq_bars(event, dsq_data, localize, locale, theme);

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
    #[allow(clippy::too_many_arguments)]
    fn dsq_sparkline(
        event: &str,
        dsq_id: u64,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        borders: Borders,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
        render_title: bool,
        render_sample_rate: bool,
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
            .style(theme.sparkline_style())
            .block(
                Block::new()
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(theme.border_style())
                    .title_top(if render_sample_rate {
                        Line::from(format!("sample rate {}", sample_rate))
                            .style(theme.text_important_color())
                            .right_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(if render_title {
                        Line::from(format!("{event} "))
                            .style(theme.title_style())
                            .left_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(
                        Line::from(if localize {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id,
                                sanitize_nbsp(stats.avg.to_formatted_string(locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(locale))
                            )
                        } else {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id, stats.avg, stats.max, stats.min,
                            )
                        })
                        .style(theme.title_style())
                        .centered(),
                    ),
            )
    }

    /// Generates dsq sparklines.
    #[allow(clippy::too_many_arguments)]
    fn dsq_sparklines(
        event: &str,
        dsq_data: &BTreeMap<u64, EventData>,
        sample_rate: u32,
        localize: bool,
        locale: &SystemLocale,
        theme: &AppTheme,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Vec<Sparkline<'static>> {
        dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .enumerate()
            .map(|(j, (dsq_id, _data))| {
                Self::dsq_sparkline(
                    event,
                    *dsq_id,
                    dsq_data,
                    sample_rate,
                    Borders::ALL,
                    localize,
                    locale,
                    theme,
                    j == 0 && render_title,
                    j == 0 && render_sample_rate,
                )
            })
            .collect()
    }

    /// Generates a DSQ bar chart.
    #[allow(clippy::too_many_arguments)]
    fn dsq_bar(
        dsq: u64,
        value: u64,
        avg: u64,
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
            .label(Line::from(if localize {
                format!(
                    "{:#X} avg {} max {} min {}",
                    dsq,
                    sanitize_nbsp(avg.to_formatted_string(locale)),
                    sanitize_nbsp(max.to_formatted_string(locale)),
                    sanitize_nbsp(min.to_formatted_string(locale))
                )
            } else {
                format!("{dsq:#X} avg {avg} max {max} min {min}",)
            }))
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
                    *dsq_id, value, stats.avg, stats.max, stats.min, localize, locale, theme,
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
