// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bandwidth_stats::{
    BandwidthStats, EVENT_LLC_OCCUPANCY, EVENT_MBM_LOCAL_BPS, EVENT_MBM_TOTAL_BPS,
};
use crate::util::{format_bytes, format_bytes_per_sec};
use crate::{AppTheme, LlcData, NodeData, ViewState};

use anyhow::Result;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols::bar::NINE_LEVELS;
use ratatui::symbols::line::THICK;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Borders, LineGauge, Paragraph, RenderDirection,
    Sparkline, Wrap,
};
use ratatui::Frame;

use std::collections::BTreeMap;

pub struct BandwidthRenderer;

#[derive(Copy, Clone)]
enum Metric {
    MbmLocal,
    MbmRemote,
    MbmTotal,
    Occupancy,
}

impl Metric {
    fn title(self) -> &'static str {
        match self {
            Metric::MbmLocal => "Local Memory Bandwidth",
            Metric::MbmRemote => "Remote Memory Bandwidth",
            Metric::MbmTotal => "Total Memory Bandwidth",
            Metric::Occupancy => "L3 Cache Occupancy",
        }
    }

    fn format(self, v: u64) -> String {
        match self {
            Metric::MbmLocal | Metric::MbmRemote | Metric::MbmTotal => format_bytes_per_sec(v),
            Metric::Occupancy => format_bytes(v),
        }
    }
}

impl BandwidthRenderer {
    #[allow(clippy::too_many_arguments)]
    pub fn render_bandwidth_view(
        frame: &mut Frame,
        stats: &BandwidthStats,
        llc_data: &BTreeMap<usize, LlcData>,
        node_data: &BTreeMap<usize, NodeData>,
        view_state: &ViewState,
        tick_rate_ms: usize,
        theme: &AppTheme,
    ) -> Result<()> {
        let area = frame.area();

        if !stats.is_available() {
            render_unavailable(frame, area, stats, theme);
            return Ok(());
        }

        let (has_local, has_total, has_occupancy) = stats.feature_flags();
        let metrics: Vec<Metric> = [
            (Metric::MbmLocal, has_local),
            (Metric::MbmRemote, has_local && has_total),
            (Metric::MbmTotal, has_total),
            (Metric::Occupancy, has_occupancy),
        ]
        .into_iter()
        .filter_map(|(m, on)| if on { Some(m) } else { None })
        .collect();

        if metrics.is_empty() {
            render_unavailable(frame, area, stats, theme);
            return Ok(());
        }

        let header_line = Line::from(vec![
            Span::styled("source: ", theme.text_color()),
            Span::styled(stats.source_label(), theme.text_important_color()),
            Span::styled("   tick: ", theme.text_color()),
            Span::styled(format!("{tick_rate_ms}ms"), theme.text_important_color()),
            Span::styled("   view: ", theme.text_color()),
            Span::styled(view_state.to_string(), theme.text_important_color()),
        ]);
        let [header_area, body_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(header_line).alignment(Alignment::Center),
            header_area,
        );

        let row_constraints: Vec<Constraint> =
            vec![Constraint::Ratio(1, metrics.len() as u32); metrics.len()];
        let rows = Layout::vertical(row_constraints).split(body_area);

        for (i, metric) in metrics.iter().enumerate() {
            let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(rows[i]);
            render_llc_panel(frame, left, *metric, llc_data, view_state, theme);
            render_node_panel(frame, right, *metric, node_data, view_state, theme);
        }

        Ok(())
    }
}

fn render_unavailable(frame: &mut Frame, area: Rect, stats: &BandwidthStats, theme: &AppTheme) {
    let text = vec![
        Line::from(Span::styled(
            "Memory-bandwidth monitoring unavailable",
            theme.title_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            stats.source_label(),
            theme.text_important_color(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Requires Intel RDT / AMD PQoS with the resctrl filesystem mounted.",
            theme.text_color(),
        )),
        Line::from(Span::styled(
            "Try:  sudo mount -t resctrl resctrl /sys/fs/resctrl",
            theme.text_color(),
        )),
    ];
    let block = Block::bordered()
        .title(
            Line::from("Bandwidth")
                .style(theme.title_style())
                .centered(),
        )
        .border_type(BorderType::Rounded)
        .style(theme.border_style());
    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn series_for_metric<F>(metric: Metric, read: F) -> Vec<u64>
where
    F: Fn(&str) -> Vec<u64>,
{
    match metric {
        Metric::MbmLocal => read(EVENT_MBM_LOCAL_BPS),
        Metric::MbmTotal => read(EVENT_MBM_TOTAL_BPS),
        Metric::Occupancy => read(EVENT_LLC_OCCUPANCY),
        Metric::MbmRemote => {
            // Derived: total − local per sample, saturating at zero to
            // absorb the case where local reads race ahead of total on
            // the first prime tick.
            let total = read(EVENT_MBM_TOTAL_BPS);
            let local = read(EVENT_MBM_LOCAL_BPS);
            total
                .iter()
                .zip(local.iter().chain(std::iter::repeat(&0)))
                .map(|(t, l)| t.saturating_sub(*l))
                .collect()
        }
    }
}

fn llc_values(metric: Metric, llc_data: &BTreeMap<usize, LlcData>) -> Vec<(usize, Vec<u64>, u64)> {
    llc_data
        .iter()
        .map(|(id, d)| {
            let series = series_for_metric(metric, |e| d.event_data_immut(e));
            let current = series.last().copied().unwrap_or(0);
            (*id, series, current)
        })
        .collect()
}

fn node_values(
    metric: Metric,
    node_data: &BTreeMap<usize, NodeData>,
) -> Vec<(usize, Vec<u64>, u64)> {
    node_data
        .iter()
        .map(|(id, d)| {
            let series = series_for_metric(metric, |e| d.event_data_immut(e));
            let current = series.last().copied().unwrap_or(0);
            (*id, series, current)
        })
        .collect()
}

/// Nearest-rank percentile over a pre-sorted slice.
fn percentile_sorted(sorted: &[u64], p: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    // ceil(p/100 * n) - 1, saturating to 0.
    let idx = (n as u64 * p as u64).div_ceil(100).saturating_sub(1) as usize;
    sorted[idx.min(n - 1)]
}

fn stats_line(
    theme: &AppTheme,
    title: &str,
    metric: Metric,
    entries: &[(usize, Vec<u64>, u64)],
    system_total: u64,
) -> Line<'static> {
    // Flatten every history sample from every entry — that's the pool the
    // window-wide max/avg/p95 are computed over. Percentiles across only
    // the current per-entry values are meaningless at 2-8 entries.
    let mut flat: Vec<u64> = entries
        .iter()
        .flat_map(|(_, s, _)| s.iter().copied())
        .collect();
    flat.sort_unstable();

    let max = flat.last().copied().unwrap_or(0);
    let avg: u64 = if flat.is_empty() {
        0
    } else {
        (flat.iter().map(|v| *v as u128).sum::<u128>() / flat.len() as u128) as u64
    };
    let p95 = percentile_sorted(&flat, 95);

    Line::from(vec![
        Span::styled(format!("{title} — "), theme.title_style()),
        Span::styled(metric.title(), theme.title_style()),
        Span::styled("  ∑=", theme.text_color()),
        Span::styled(metric.format(system_total), theme.text_important_color()),
        Span::styled("  max=", theme.text_color()),
        Span::styled(metric.format(max), theme.text_important_color()),
        Span::styled("  p95=", theme.text_color()),
        Span::styled(metric.format(p95), theme.text_important_color()),
        Span::styled("  avg=", theme.text_color()),
        Span::styled(metric.format(avg), theme.text_important_color()),
    ])
    .centered()
}

fn panel_block(theme: &AppTheme, title: Line<'static>) -> Block<'static> {
    Block::bordered()
        .title_top(title)
        .border_type(BorderType::Rounded)
        .style(theme.border_style())
}

fn render_llc_panel(
    frame: &mut Frame,
    area: Rect,
    metric: Metric,
    llc_data: &BTreeMap<usize, LlcData>,
    view_state: &ViewState,
    theme: &AppTheme,
) {
    let entries = llc_values(metric, llc_data);
    let system_total: u64 = entries.iter().map(|(_, _, c)| *c).sum();
    let title = stats_line(theme, "LLCs", metric, &entries, system_total);
    render_topology_panel(
        frame, area, view_state, theme, title, "LLC", metric, &entries,
    );
}

fn render_node_panel(
    frame: &mut Frame,
    area: Rect,
    metric: Metric,
    node_data: &BTreeMap<usize, NodeData>,
    view_state: &ViewState,
    theme: &AppTheme,
) {
    let entries = node_values(metric, node_data);
    let system_total: u64 = entries.iter().map(|(_, _, c)| *c).sum();
    let title = stats_line(theme, "Nodes", metric, &entries, system_total);
    render_topology_panel(
        frame, area, view_state, theme, title, "Node", metric, &entries,
    );
}

#[allow(clippy::too_many_arguments)]
fn render_topology_panel(
    frame: &mut Frame,
    area: Rect,
    view_state: &ViewState,
    theme: &AppTheme,
    title: Line<'static>,
    label_prefix: &str,
    metric: Metric,
    entries: &[(usize, Vec<u64>, u64)],
) {
    let max_current = entries.iter().map(|(_, _, c)| *c).max().unwrap_or(0);
    let max_ever = entries
        .iter()
        .flat_map(|(_, s, _)| s.iter().copied())
        .max()
        .unwrap_or(0)
        .max(max_current);

    let block = panel_block(theme, title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if entries.is_empty() || inner.height == 0 {
        return;
    }

    match view_state {
        ViewState::Sparkline => {
            render_sparklines(frame, inner, theme, label_prefix, metric, entries, max_ever);
        }
        ViewState::BarChart => {
            render_barchart(frame, inner, theme, label_prefix, metric, entries, max_ever);
        }
        ViewState::LineGauge => {
            render_line_gauges(frame, inner, theme, label_prefix, metric, entries, max_ever);
        }
    }
}

fn render_sparklines(
    frame: &mut Frame,
    area: Rect,
    theme: &AppTheme,
    label_prefix: &str,
    metric: Metric,
    entries: &[(usize, Vec<u64>, u64)],
    global_max: u64,
) {
    let visible = (area.height as usize).min(entries.len());
    if visible == 0 {
        return;
    }
    let constraints = vec![Constraint::Ratio(1, visible as u32); visible];
    let rows = Layout::vertical(constraints).split(area);
    for (i, (id, series, current)) in entries.iter().take(visible).enumerate() {
        let label = format!("{label_prefix}{id} {}", metric.format(*current));
        let sparkline = Sparkline::default()
            .direction(RenderDirection::RightToLeft)
            .data(series.as_slice())
            .max(global_max.max(1))
            .bar_set(NINE_LEVELS)
            .style(Style::default().fg(theme.text_important_color()))
            .block(Block::default().title(Line::from(label).style(theme.text_color())));
        frame.render_widget(sparkline, rows[i]);
    }
}

fn render_barchart(
    frame: &mut Frame,
    area: Rect,
    theme: &AppTheme,
    label_prefix: &str,
    metric: Metric,
    entries: &[(usize, Vec<u64>, u64)],
    max_current: u64,
) {
    if entries.is_empty() || area.height == 0 {
        return;
    }
    let bars: Vec<Bar> = entries
        .iter()
        .map(|(id, _, current)| {
            Bar::default()
                .value(*current)
                .label(Line::from(format!("{label_prefix}{id}")).style(theme.text_color()))
                .text_value(metric.format(*current))
                .style(Style::default().fg(theme.text_important_color()))
        })
        .collect();

    // Horizontal bars stack vertically; bar_width is the row-thickness of
    // each bar. Scale it so the group fills the panel height instead of
    // leaving dead space below.
    let bar_width = (area.height as usize / entries.len()).max(1) as u16;

    let chart = BarChart::default()
        .data(BarGroup::default().bars(&bars))
        .max(max_current.max(1))
        .direction(Direction::Horizontal)
        .bar_gap(0)
        .bar_width(bar_width)
        .block(Block::default().borders(Borders::NONE));
    frame.render_widget(chart, area);
}

fn render_line_gauges(
    frame: &mut Frame,
    area: Rect,
    theme: &AppTheme,
    label_prefix: &str,
    metric: Metric,
    entries: &[(usize, Vec<u64>, u64)],
    max_current: u64,
) {
    let visible = (area.height as usize).min(entries.len());
    if visible == 0 {
        return;
    }
    // Split the panel evenly so each gauge (which draws on a single line
    // anyway) sits in its own vertically-centered slice, filling the panel.
    let constraints = vec![Constraint::Ratio(1, visible as u32); visible];
    let rows = Layout::vertical(constraints).split(area);
    let denom = max_current.max(1) as f64;
    for (i, (id, _, current)) in entries.iter().take(visible).enumerate() {
        let ratio = ((*current as f64) / denom).clamp(0.0, 1.0);
        let label = format!("{label_prefix}{id} {}", metric.format(*current));
        let gauge = LineGauge::default()
            .ratio(ratio)
            .filled_symbol(THICK.horizontal)
            .unfilled_symbol(THICK.horizontal)
            .label(Line::from(label).style(theme.text_color()))
            .filled_style(
                Style::default()
                    .fg(theme.text_important_color())
                    .bg(Color::Reset),
            )
            .unfilled_style(
                Style::default()
                    .fg(theme.border_style().fg.unwrap_or(Color::Gray))
                    .bg(Color::Reset),
            );
        frame.render_widget(gauge, rows[i]);
    }
}
