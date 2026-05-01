// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_graphs_tab(frame: &mut Frame, app: &TuiApp, stats: &cake_stats, area: Rect) {
    let report = build_telemetry_report(stats, app);
    let layout = Layout::vertical([
        Constraint::Length(7),
        Constraint::Percentage(46),
        Constraint::Percentage(54),
    ])
    .split(area);
    let top = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[0]);

    let coverage_style = if report.degraded_count() == 0 {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::LightRed)
    };
    let coverage_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Status "),
            dashboard_value(report.status_label(), coverage_style),
            dashboard_sep("  "),
            dashboard_label("degraded "),
            dashboard_value(report.degraded_count().to_string(), coverage_style),
        ]),
        Line::from(vec![
            dashboard_label("Timeline "),
            dashboard_value(
                format!(
                    "{}/{} samples",
                    report.health.timeline_samples, report.health.timeline_expected
                ),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Wake graph "),
            dashboard_value(
                format!(
                    "edges={} wake_est={} wait_est={} obs={} drops={}",
                    report.graph.wake_edges,
                    report.graph.wake_events,
                    report.graph.wait_samples,
                    report.graph.observed_events,
                    report.graph.event_drops,
                ),
                if report.graph.event_drops == 0 {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::LightRed)
                },
            ),
        ]),
        Line::from(vec![
            dashboard_label("Worst wait "),
            dashboard_value(
                format!("{}us", report.graph.wait_max_us),
                low_is_good_style(report.graph.wait_max_us, 50, 500),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Coverage", Color::Cyan))
    .wrap(Wrap { trim: false });
    frame.render_widget(coverage_panel, top[0]);

    let mut degraded_lines = Vec::new();
    for item in report
        .coverage
        .iter()
        .filter(|item| item.quality.is_degraded() || item.drops > 0)
        .take(4)
    {
        degraded_lines.push(Line::from(vec![
            dashboard_label(format!("{} ", item.name)),
            dashboard_value(
                format!(
                    "{} drops={} {}",
                    item.quality.label(),
                    item.drops,
                    item.note
                ),
                Style::default().fg(Color::LightRed),
            ),
        ]));
    }
    if degraded_lines.is_empty() {
        degraded_lines.push(Line::from(vec![
            dashboard_label("Sources "),
            dashboard_value(
                "all expected debug sources healthy",
                Style::default().fg(Color::Green),
            ),
        ]));
    }
    let degraded_panel = Paragraph::new(degraded_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block("Coverage Gaps", Color::LightRed))
        .wrap(Wrap { trim: false });
    frame.render_widget(degraded_panel, top[1]);

    let graph_layout = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);
    let top_rows = app.wake_edges.iter().take(12).map(|edge| {
        Row::new(vec![
            Cell::from(wake_edge_task_label(app, edge.waker_pid, edge.waker_tgid)),
            Cell::from(wake_edge_task_label(app, edge.wakee_pid, edge.wakee_tgid)),
            Cell::from(edge.wake_count.to_string()),
            Cell::from(edge.observed_event_count.to_string()),
            Cell::from(format!(
                "{}/{}us",
                wake_edge_avg_us(edge),
                edge.wait_max_ns / 1000
            )),
            Cell::from(format!(
                "{}/{}",
                edge.target_hit_count, edge.target_miss_count
            )),
        ])
    });
    let top_table = Table::new(
        top_rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(14),
            Constraint::Length(10),
        ],
    )
    .header(Row::new(vec![
        "Waker", "Wakee", "WakeEst", "Obs", "Wait", "Target",
    ]))
    .block(dashboard_block("Top Wake Edges (sampled)", Color::Yellow));
    frame.render_widget(top_table, graph_layout[0]);

    let mut latency_edges: Vec<&WakeEdgeRow> = app
        .wake_edges
        .iter()
        .filter(|edge| edge.wait_count > 0)
        .collect();
    latency_edges.sort_by(|a, b| {
        b.wait_max_ns
            .cmp(&a.wait_max_ns)
            .then_with(|| wake_edge_avg_us(b).cmp(&wake_edge_avg_us(a)))
            .then_with(|| b.wait_count.cmp(&a.wait_count))
    });
    let latency_rows = latency_edges.iter().take(12).map(|edge| {
        Row::new(vec![
            Cell::from(wake_edge_task_label(app, edge.waker_pid, edge.waker_tgid)),
            Cell::from(wake_edge_task_label(app, edge.wakee_pid, edge.wakee_tgid)),
            Cell::from(edge.wait_count.to_string()),
            Cell::from(edge.observed_event_count.to_string()),
            Cell::from(format!(
                "{}/{}us",
                wake_edge_avg_us(edge),
                edge.wait_max_ns / 1000
            )),
            Cell::from(format_wake_edge_bucket_summary(edge)),
        ])
    });
    let latency_table = Table::new(
        latency_rows,
        [
            Constraint::Percentage(22),
            Constraint::Percentage(22),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(14),
            Constraint::Percentage(34),
        ],
    )
    .header(Row::new(vec![
        "Waker", "Wakee", "WaitEst", "Obs", "Wait", "Buckets",
    ]))
    .block(dashboard_block(
        "Latency Edges (sampled)",
        Color::LightMagenta,
    ));
    frame.render_widget(latency_table, graph_layout[1]);

    let bottom_layout =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(layout[2]);
    let tgid_rows = wake_tgid_summaries(app)
        .into_iter()
        .take(14)
        .map(|summary| {
            Row::new(vec![
                Cell::from(wake_tgid_label(app, summary.tgid)),
                Cell::from(summary.self_wake_count().to_string()),
                Cell::from(summary.outbound_wake_count.to_string()),
                Cell::from(format!(
                    "{}/{}us",
                    bucket_avg_us(summary.self_wait_ns, summary.self_wait_count),
                    summary.self_wait_max_ns / 1000
                )),
                Cell::from(summary.self_target_miss_count.to_string()),
            ])
        });
    let tgid_table = Table::new(
        tgid_rows,
        [
            Constraint::Percentage(34),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(vec!["TGID", "InEst", "OutEst", "Wait", "Miss"]))
    .block(dashboard_block(
        "App Wake Neighborhoods (est)",
        Color::Green,
    ));
    frame.render_widget(tgid_table, bottom_layout[0]);

    let event_lines: Vec<Line> = if app.debug_events.is_empty() {
        vec![Line::from(vec![
            dashboard_label("Events "),
            dashboard_note("none observed"),
        ])]
    } else {
        app.debug_events
            .iter()
            .take(12)
            .map(|ev| {
                Line::from(vec![
                    dashboard_label(format!("pid={} ", ev.pid)),
                    dashboard_value(debug_event_label(ev), Style::default().fg(Color::LightCyan)),
                ])
            })
            .collect()
    };
    let event_panel = Paragraph::new(event_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block("Recent Debug Events", Color::Cyan))
        .wrap(Wrap { trim: false });
    frame.render_widget(event_panel, bottom_layout[1]);
}
