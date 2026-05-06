// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_apps_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let rows = build_app_health_rows(app, &tgid_roles);
    let total_runtime_ns: u64 = rows.iter().map(|row| row.runtime_ns).sum();

    if rows.is_empty() {
        app.app_table_state.select(None);
        let empty = Paragraph::new(vec![
            Line::from(vec![
                dashboard_label("Apps "),
                dashboard_note("collecting task data"),
            ]),
            app_data_quality_line(app),
        ])
        .block(dashboard_block("Apps", Color::LightGreen))
        .wrap(Wrap { trim: false });
        frame.render_widget(empty, area);
        return;
    }

    let selected_idx = app
        .app_table_state
        .selected()
        .unwrap_or(0)
        .min(rows.len().saturating_sub(1));
    app.app_table_state.select(Some(selected_idx));
    let selected = rows[selected_idx].clone();

    let layout = if area.width >= 140 {
        Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)]).split(area)
    } else {
        Layout::vertical([Constraint::Length(12), Constraint::Min(12)]).split(area)
    };

    let app_header = Row::new(vec![
        Cell::from("App").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Role").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Hot").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RT%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ms/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("run/s").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("wait").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Qblk").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SMT").style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let app_rows: Vec<Row> =
        rows.iter()
            .map(|row| {
                let quantum_total = row.quantum_full + row.quantum_yield + row.quantum_preempt;
                let wait_avg_us = avg_ns(row.wait_self_ns, row.wait_self_count) / 1000;
                let wait_max_us = row.wait_self_max_ns / 1000;
                let (_, state_style) = app_health_state(row);
                let is_focused = app.focused_tgid == Some(row.tgid);
                let app_style = if is_focused {
                    Style::default()
                        .fg(row.role.color())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(row.role.color())
                };
                Row::new(vec![
                    Cell::from(format!(
                        "{}{} {}",
                        if is_focused { "*" } else { " " },
                        row.comm,
                        row.tgid
                    ))
                    .style(app_style),
                    Cell::from(row.role.label()).style(Style::default().fg(row.role.color())),
                    Cell::from(format!("{}/{}", row.hot_tasks, row.tasks))
                        .style(Style::default().fg(Color::Cyan)),
                    Cell::from(format!("{:.1}", pct(row.runtime_ns, total_runtime_ns)))
                        .style(Style::default().fg(Color::Green)),
                    Cell::from(format!("{:.1}", row.runtime_ns_per_sec / 1_000_000.0))
                        .style(Style::default().fg(Color::Green)),
                    Cell::from(format!("{:.1}", row.runs_per_sec))
                        .style(Style::default().fg(Color::LightCyan)),
                    Cell::from(format!("{}/{}", wait_avg_us, wait_max_us))
                        .style(low_is_good_style(wait_max_us, 1_000, 5_000)),
                    Cell::from(format!("{:.0}%", pct(row.quantum_yield, quantum_total)))
                        .style(Style::default().fg(Color::Yellow)),
                    Cell::from(format!(
                        "{:.0}%",
                        pct(row.smt_contended_runtime_ns, row.runtime_ns)
                    ))
                    .style(state_style),
                ])
            })
            .collect();
    let app_title = format!(
        "Apps  rows={}  selected={}  focus={}  wakegraph={} obs={}",
        rows.len(),
        selected.comm,
        focused_app_label(app),
        wake_graph_capture_label(app),
        app.wake_edge_observed_events
    );
    let app_table = Table::new(
        app_rows,
        [
            Constraint::Length(22),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(6),
        ],
    )
    .header(app_header)
    .block(dashboard_block(&app_title, Color::LightGreen))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");
    frame.render_stateful_widget(app_table, layout[0], &mut app.app_table_state);

    let selected_tasks = app_task_rows(app, selected.tgid);
    let selected_pids: Vec<u32> = selected_tasks.iter().map(|row| row.pid).collect();
    let tgid_health = format_tgid_health_summary(app, selected.tgid, &selected_pids);
    let quantum_total = selected.quantum_full + selected.quantum_yield + selected.quantum_preempt;
    let avg_run_us = if selected.runs > 0 {
        selected.runtime_ns / selected.runs / 1000
    } else {
        0
    };
    let avg_run_q = if app.quantum_us > 0 {
        avg_run_us as f64 * 100.0 / app.quantum_us as f64
    } else {
        0.0
    };
    let (state_label, state_style) = app_health_state(&selected);
    let selected_wake = wake_tgid_summaries(app)
        .into_iter()
        .find(|summary| summary.tgid == selected.tgid);

    let detail_layout = Layout::vertical([
        Constraint::Length(9),
        Constraint::Min(8),
        Constraint::Length(7),
    ])
    .split(layout[1]);
    let leader = if selected.leader_comm.is_empty() || selected.leader_comm == selected.comm {
        "-".to_string()
    } else {
        selected.leader_comm.clone()
    };
    let detail_title = format!("{} / TGID {}", selected.comm, selected.tgid);
    let focus_state = if app.focused_tgid == Some(selected.tgid) {
        "pinned"
    } else {
        "press Enter/p to pin"
    };
    let health_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Focus "),
            dashboard_value(
                focus_state,
                if app.focused_tgid == Some(selected.tgid) {
                    Style::default().fg(Color::LightMagenta)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
            dashboard_sep("  "),
            dashboard_label("Top CPUs "),
            dashboard_value(
                app_cpu_distribution_label(app, selected.tgid, 3),
                Style::default().fg(Color::LightBlue),
            ),
        ]),
        Line::from(vec![
            dashboard_label("State "),
            dashboard_value(state_label, state_style),
            dashboard_sep("  "),
            dashboard_label("Role "),
            dashboard_value(
                selected.role.label(),
                Style::default().fg(selected.role.color()),
            ),
            dashboard_sep("  "),
            dashboard_label("Leader "),
            dashboard_value(leader, Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            dashboard_label("Runtime "),
            dashboard_value(
                format!(
                    "{}ms {:.1}%  {:.1}ms/s  {:.1}run/s",
                    format_runtime_ms(selected.runtime_ns),
                    pct(selected.runtime_ns, total_runtime_ns),
                    selected.runtime_ns_per_sec / 1_000_000.0,
                    selected.runs_per_sec
                ),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Latency "),
            dashboard_value(
                format!(
                    "avg_run={}us avg_run/q={:.1}% max={} wait_self={}/{}us blocked=max{}us/n{}",
                    avg_run_us,
                    avg_run_q,
                    display_runtime_us(selected.max_runtime_us),
                    avg_ns(selected.wait_self_ns, selected.wait_self_count) / 1000,
                    selected.wait_self_max_ns / 1000,
                    selected.blocked_wait_max_us,
                    selected.blocked_count
                ),
                low_is_good_style(selected.blocked_wait_max_us as u64, 1_000, 5_000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Placement "),
            dashboard_value(
                format!(
                    "aff[min/max/r]={}/{}/{} smt={:.1}% ov={:.1}% sticky_hogs={}",
                    selected.min_allowed_cpus,
                    selected.max_allowed_cpus,
                    selected.restricted_tasks,
                    pct(selected.smt_contended_runtime_ns, selected.runtime_ns),
                    pct(selected.smt_overlap_runtime_ns, selected.runtime_ns),
                    selected.sticky_hogs
                ),
                Style::default().fg(Color::LightBlue),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Quantum "),
            dashboard_value(
                format!(
                    "f/b/p={:.0}/{:.0}/{:.0}% counts={}/{}/{}",
                    pct(selected.quantum_full, quantum_total),
                    pct(selected.quantum_yield, quantum_total),
                    pct(selected.quantum_preempt, quantum_total),
                    selected.quantum_full,
                    selected.quantum_yield,
                    selected.quantum_preempt
                ),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Startup "),
            dashboard_value(tgid_health, Style::default().fg(Color::Cyan)),
        ]),
        app_data_quality_line(app),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block(&detail_title, selected.role.color()))
    .wrap(Wrap { trim: false });
    frame.render_widget(health_panel, detail_layout[0]);

    let task_header = Row::new(vec![
        Cell::from("PID").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("COMM").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Role").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("UTIL%").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("run/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ms/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("avg/max").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("wait").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("place").style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Q f/b/p").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let task_rows: Vec<Row> = selected_tasks
        .iter()
        .take(12)
        .map(|row| {
            let role = task_role(row, &tgid_roles);
            let placement = placement_summary(row, &app.topology);
            let quantum_total =
                row.quantum_full_count + row.quantum_yield_count + row.quantum_preempt_count;
            let top_core_label = placement
                .top_core
                .map(|(core, count)| {
                    format!(
                        "K{:02}/{}%",
                        core,
                        (count * 100) / placement.total_samples.max(1)
                    )
                })
                .unwrap_or_else(|| "-".to_string());
            let placement_label =
                format!("{} {}", placement_spread_label(&placement), top_core_label);
            Row::new(vec![
                Cell::from(row.pid.to_string()).style(Style::default().fg(Color::Yellow)),
                Cell::from(row.comm.clone()).style(Style::default().fg(role.color())),
                Cell::from(role.label()).style(Style::default().fg(role.color())),
                Cell::from(format!("{:.1}", pelt_util_pct(row.pelt_util as u64)))
                    .style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{:.1}", row.runs_per_sec))
                    .style(Style::default().fg(Color::Green)),
                Cell::from(format!("{:.1}", runtime_rate_ms(row)))
                    .style(Style::default().fg(Color::Green)),
                Cell::from(format!(
                    "{}/{}",
                    avg_task_runtime_us(row),
                    display_runtime_us(row.max_runtime_us)
                ))
                .style(low_is_good_style(row.max_runtime_us as u64, 500, 2_000)),
                Cell::from(format!(
                    "{}/{}",
                    row.wait_duration_ns / 1000,
                    row.blocked_wait_max_us
                ))
                .style(low_is_good_style(
                    row.blocked_wait_max_us as u64,
                    1_000,
                    5_000,
                )),
                Cell::from(placement_label).style(Style::default().fg(Color::LightBlue)),
                Cell::from(format!(
                    "{:.0}/{:.0}/{:.0}",
                    pct(row.quantum_full_count, quantum_total),
                    pct(row.quantum_yield_count, quantum_total),
                    pct(row.quantum_preempt_count, quantum_total),
                ))
                .style(Style::default().fg(Color::LightMagenta)),
            ])
        })
        .collect();
    let task_table = Table::new(
        task_rows,
        [
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(9),
        ],
    )
    .header(task_header)
    .block(dashboard_block("Top Threads", Color::Cyan));
    frame.render_widget(task_table, detail_layout[1]);

    let wake_lines = if let Some(summary) = selected_wake {
        vec![
            Line::from(vec![
                dashboard_label("Wake "),
                dashboard_value(
                    format!(
                        "in/int/out={}/{}/{} edges={}",
                        summary.inbound_wake_count,
                        summary.internal_wake_count,
                        summary.outbound_wake_count,
                        summary.edge_count
                    ),
                    Style::default().fg(Color::LightCyan),
                ),
            ]),
            Line::from(vec![
                dashboard_label("Wait "),
                dashboard_value(
                    format!(
                        "self={}/{}us({}) out={}/{}us({})",
                        bucket_avg_us(summary.self_wait_ns, summary.self_wait_count),
                        summary.self_wait_max_ns / 1000,
                        summary.self_wait_count,
                        bucket_avg_us(summary.outbound_wait_ns, summary.outbound_wait_count),
                        summary.outbound_wait_max_ns / 1000,
                        summary.outbound_wait_count
                    ),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                dashboard_label("Target "),
                dashboard_value(
                    format!(
                        "self h/m={}/{} out h/m={}/{} follow self s/m={}/{}",
                        summary.self_target_hit_count,
                        summary.self_target_miss_count,
                        summary.outbound_target_hit_count,
                        summary.outbound_target_miss_count,
                        summary.self_follow_same_cpu_count,
                        summary.self_follow_migrate_count
                    ),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                dashboard_label("Wake "),
                dashboard_note("no wakegraph edges for selected app"),
            ]),
            app_data_quality_line(app),
        ]
    };
    let wake_panel = Paragraph::new(wake_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block("Wake Chain", Color::LightMagenta))
        .wrap(Wrap { trim: false });
    frame.render_widget(wake_panel, detail_layout[2]);
}
