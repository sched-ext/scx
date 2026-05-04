// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_topology_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let nr_cpus = app.latency_matrix.len();
    let heatmap_min_width = (6 + nr_cpus * 2 + 4) as u16;
    let cpu_work_window = app.cpu_work_window(Duration::from_secs(60));
    let (work_elapsed, cpu_work, work_label) = if let Some((elapsed, window)) = cpu_work_window {
        (
            elapsed,
            window,
            format!("Cake runtime share {}s", elapsed.as_secs()),
        )
    } else {
        (
            app.start_time.elapsed().max(Duration::from_secs(1)),
            app.per_cpu_work.clone(),
            "Cake runtime share lifetime".to_string(),
        )
    };
    let cpu_rows = scheduler_cpu_rows(&cpu_work, &app.topology, &app.cpu_stats, work_elapsed);
    let core_rows = scheduler_core_rows(&cpu_work, &app.topology, &app.cpu_stats, work_elapsed);
    let scheduler_share = scheduler_share_by_cpu(&cpu_work);
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let focused_app = focused_app_with_total(app, &tgid_roles);
    let focus_cpu_mask = focused_app
        .as_ref()
        .map(|(row, _)| app_focus_cpu_mask(app, row.tgid, 6));
    let focus_label = focused_app
        .as_ref()
        .map(|(row, _)| format!("{}[{}]", row.comm, row.tgid));
    let right_min_width = 84u16;

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(22),
            Constraint::Min(heatmap_min_width),
            Constraint::Min(right_min_width),
        ])
        .split(area);
    let topology_grid = build_cpu_topology_grid_compact(
        &app.topology,
        &app.cpu_stats,
        &scheduler_share,
        &work_label,
        focus_label.as_deref(),
        focus_cpu_mask.as_deref(),
    );
    frame.render_widget(topology_grid, layout[0]);

    // Dynamic heatmap title based on latency measurement state
    let heatmap_title = if app.latency_probe_handle.is_some() {
        " Latency Heatmap Measuring... ".to_string()
    } else if app
        .latency_matrix
        .iter()
        .any(|row| row.iter().any(|&v| v > 0.0))
    {
        " Latency Heatmap (ns) ".to_string()
    } else {
        " Latency Heatmap [b] Measure ".to_string()
    };
    let heatmap = LatencyHeatmap::new(&app.latency_matrix, &app.topology, &heatmap_title);
    frame.render_widget(heatmap, layout[1]);

    let right_layout = if focused_app.is_some() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),
                Constraint::Percentage(48),
                Constraint::Percentage(46),
            ])
            .split(layout[2])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(layout[2])
    };
    let cpu_title = format!(
        "Scheduler CPU Work [Cake | SMT | Sys] ({:.0}s, skew {:.1}x)",
        work_elapsed.as_secs_f64(),
        scheduler_balance_ratio(&cpu_work)
    );
    let core_title = format!(
        "Scheduler Core Balance [Cake | SMT overlap | Sys] ({:.0}s)",
        work_elapsed.as_secs_f64()
    );
    let cpu_table = build_scheduler_cpu_table(
        &cpu_rows,
        &cpu_title,
        right_layout[if focused_app.is_some() { 1 } else { 0 }]
            .height
            .saturating_sub(3) as usize,
    );
    let core_table = build_scheduler_core_table(
        &core_rows,
        &core_title,
        right_layout[if focused_app.is_some() { 2 } else { 1 }]
            .height
            .saturating_sub(3) as usize,
    );
    if let Some((focus, total_runtime_ns)) = &focused_app {
        let (state, state_style) = app_health_state(focus);
        let quantum_total = focus.quantum_full + focus.quantum_yield + focus.quantum_preempt;
        let focus_panel = Paragraph::new(vec![
            Line::from(vec![
                dashboard_label("Focus "),
                dashboard_value(
                    format!("{}[{}] {}", focus.comm, focus.tgid, state),
                    state_style,
                ),
                dashboard_sep("  "),
                dashboard_label("runtime "),
                dashboard_value(
                    format!(
                        "{:.1}% {:.1}ms/s",
                        pct(focus.runtime_ns, *total_runtime_ns),
                        focus.runtime_ns_per_sec / 1_000_000.0
                    ),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                dashboard_label("CPUs "),
                dashboard_value(
                    app_cpu_distribution_label(app, focus.tgid, 5),
                    Style::default().fg(Color::LightBlue),
                ),
            ]),
            Line::from(vec![
                dashboard_label("Cores "),
                dashboard_value(
                    app_core_distribution_label(app, focus.tgid, 5),
                    Style::default().fg(Color::LightMagenta),
                ),
                dashboard_sep("  "),
                dashboard_label("q b/p "),
                dashboard_value(
                    format!(
                        "{:.0}/{:.0}%",
                        pct(focus.quantum_yield, quantum_total),
                        pct(focus.quantum_preempt, quantum_total)
                    ),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ])
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block(
            "Focused App Placement",
            Color::LightMagenta,
        ))
        .wrap(Wrap { trim: false });
        frame.render_widget(focus_panel, right_layout[0]);
    }
    frame.render_widget(
        cpu_table,
        right_layout[if focused_app.is_some() { 1 } else { 0 }],
    );
    frame.render_widget(
        core_table,
        right_layout[if focused_app.is_some() { 2 } else { 1 }],
    );
}
