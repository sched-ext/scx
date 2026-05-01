// SPDX-License-Identifier: GPL-2.0

use super::*;

pub(super) fn draw_dashboard_tab(
    frame: &mut Frame,
    app: &mut TuiApp,
    stats: &cake_stats,
    area: Rect,
) {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let minute_window = Duration::from_secs(60);
    let minute_step = Duration::from_secs(1);
    let minute_samples = app.timeline_samples(minute_window, minute_step);
    let minute_expected = expected_timeline_samples(minute_window, minute_step);
    let minute_avg_step = average_timeline_sample_secs(&minute_samples);
    let minute_history_span = timeline_history_span(&app.timeline_history);
    let (balance_scope, balance_diag) =
        if let Some((elapsed, window)) = app.cpu_work_window(Duration::from_secs(60)) {
            let cpu_rows = scheduler_cpu_rows(&window, &app.topology, &app.cpu_stats, elapsed);
            let core_rows = scheduler_core_rows(&window, &app.topology, &app.cpu_stats, elapsed);
            (
                format!("{:.0}s", elapsed.as_secs_f64()),
                build_balance_diagnosis(&cpu_rows, &core_rows),
            )
        } else {
            let elapsed = app.start_time.elapsed().max(Duration::from_secs(1));
            let cpu_rows =
                scheduler_cpu_rows(&app.per_cpu_work, &app.topology, &app.cpu_stats, elapsed);
            let core_rows =
                scheduler_core_rows(&app.per_cpu_work, &app.topology, &app.cpu_stats, elapsed);
            (
                "life".to_string(),
                build_balance_diagnosis(&cpu_rows, &core_rows),
            )
        };
    let long_run_rows = build_long_run_owner_rows(app, &tgid_roles, 3);
    let focused_app = focused_app_with_total(app, &tgid_roles);

    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let path_total: u64 = stats.select_path_count[1..6].iter().sum();
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;

    // PELT tier summary: count tasks by utilization bands
    let (mut wc0, mut wc1, mut wc2, mut wc3) = (0u32, 0u32, 0u32, 0u32);
    for row in app.task_rows.values() {
        if !row_has_bpf_matrix_data(row) {
            continue;
        }
        match row.pelt_util {
            0..=49 => wc0 += 1,
            50..=255 => wc1 += 1,
            256..=799 => wc2 += 1,
            _ => wc3 += 1,
        }
    }

    let topo_flags = format!(
        "{}C{}{}{}",
        app.topology.nr_cpus,
        if app.topology.has_dual_ccd {
            " 2CCD"
        } else {
            ""
        },
        if app.topology.has_hybrid_cores {
            " HYB"
        } else {
            ""
        },
        if app.topology.smt_enabled { " SMT" } else { "" },
    );

    let outer_layout = Layout::vertical([
        Constraint::Length(12),
        Constraint::Length(11),
        Constraint::Min(10),
    ])
    .split(area);

    let summary_rows =
        Layout::vertical([Constraint::Length(6), Constraint::Length(6)]).split(outer_layout[0]);
    let summary_top = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(summary_rows[0]);
    let summary_bottom =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(summary_rows[1]);

    let queue_style = if dsq_depth <= 4 {
        Style::default().fg(Color::Green)
    } else if dsq_depth <= 10 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    };
    let shared_queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);
    let shared_queue_net_style = if shared_queue_net > 0 {
        Style::default().fg(Color::Yellow)
    } else if shared_queue_net < 0 {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let runtime_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Topology "),
            dashboard_value(topo_flags, Style::default().fg(Color::Cyan)),
            dashboard_sep("  "),
            dashboard_label("Uptime "),
            dashboard_value(app.format_uptime(), Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            dashboard_label("Tracked tasks "),
            dashboard_value(
                app.bpf_task_count.to_string(),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_label("Arena "),
            dashboard_value(
                app.arena_active.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("View "),
            dashboard_value(
                app.task_filter.label(),
                Style::default().fg(Color::LightMagenta),
            ),
        ]),
        Line::from({
            let mut spans = vec![
                dashboard_label("Queue depth "),
                dashboard_value(dsq_depth.to_string(), queue_style),
                dashboard_sep("  "),
                dashboard_label("PELT bands "),
                dashboard_value(
                    format!("idle {}", wc0),
                    Style::default().fg(Color::LightCyan),
                ),
                dashboard_sep("  "),
                dashboard_value(format!("light {}", wc1), Style::default().fg(Color::Green)),
                dashboard_sep("  "),
                dashboard_value(format!("busy {}", wc2), Style::default().fg(Color::Yellow)),
                dashboard_sep("  "),
                dashboard_value(format!("hot {}", wc3), Style::default().fg(Color::LightRed)),
            ];
            if stats.nr_dropped_allocations > 0 {
                spans.push(dashboard_sep("  "));
                spans.push(dashboard_label("ENOMEM "));
                spans.push(dashboard_value(
                    stats.nr_dropped_allocations.to_string(),
                    Style::default().fg(Color::LightRed),
                ));
            }
            spans
        }),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Runtime", Color::Cyan))
    .wrap(Wrap { trim: false });
    frame.render_widget(runtime_panel, summary_top[0]);

    let dispatch_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Dispatches "),
            dashboard_value(
                total_dsq_dispatches.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("local / steal / miss "),
            dashboard_value(
                format!(
                    "{} / {} / {}",
                    stats.nr_local_dispatches, stats.nr_stolen_dispatches, stats.nr_dispatch_misses
                ),
                Style::default().fg(Color::LightCyan),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Shared Q depth/in/out/net "),
            dashboard_value(
                format!(
                    "{} / {} / {} / {:+}",
                    dsq_depth, stats.nr_dsq_queued, stats.nr_dsq_consumed, shared_queue_net
                ),
                shared_queue_net_style,
            ),
        ]),
        Line::from(vec![
            dashboard_label("Wake d/b/q "),
            dashboard_value(
                format!(
                    "{:.0}/{:.0}/{:.0}%",
                    pct(stats.nr_wakeup_direct_dispatches, wake_total),
                    pct(stats.nr_wakeup_dsq_fallback_busy, wake_total),
                    pct(stats.nr_wakeup_dsq_fallback_queued, wake_total)
                ),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_label("Path h/i/t "),
            dashboard_value(
                format!(
                    "{:.0}/{:.0}/{:.0}%",
                    pct(stats.select_path_count[1], path_total),
                    pct(stats.select_path_count[4], path_total),
                    pct(stats.select_path_count[5], path_total)
                ),
                Style::default().fg(Color::Cyan),
            ),
            dashboard_sep("  "),
            dashboard_label("steer home "),
            dashboard_value(
                format!(
                    "{:.0}%",
                    pct(stats.nr_home_cpu_steers, stats.nr_steer_eligible)
                ),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Dispatch", Color::Yellow))
    .wrap(Wrap { trim: false });
    frame.render_widget(dispatch_panel, summary_top[1]);

    let select_avg = avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls);
    let enqueue_avg = avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls);
    let running_avg = avg_ns(stats.total_running_ns, stats.nr_running_calls);
    let stopping_avg = avg_ns(stats.total_stopping_ns, stats.nr_stopping_calls);
    let lifecycle_enqueue_avg = avg_us(
        stats.lifecycle_init_enqueue_us,
        stats.lifecycle_init_enqueue_count,
    );
    let lifecycle_select_avg = avg_us(
        stats.lifecycle_init_select_us,
        stats.lifecycle_init_select_count,
    );
    let lifecycle_run_avg = avg_us(stats.lifecycle_init_run_us, stats.lifecycle_init_run_count);
    let lifecycle_run_stop_avg = avg_ns(stats.task_runtime_ns, stats.task_run_count) / 1000;
    let lifecycle_exit_avg = avg_us(
        stats.lifecycle_init_exit_us,
        stats.lifecycle_init_exit_count,
    );
    let dir_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[1],
        stats.wake_reason_wait_count[1],
    );
    let busy_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[2],
        stats.wake_reason_wait_count[2],
    );
    let queue_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[3],
        stats.wake_reason_wait_count[3],
    );
    let wake_edge_wait_count: u64 = app.wake_edges.iter().map(|edge| edge.wait_count).sum();
    let wake_edge_wait_ns: u64 = app.wake_edges.iter().map(|edge| edge.wait_ns).sum();
    let wake_edge_avg_us = bucket_avg_us(wake_edge_wait_ns, wake_edge_wait_count);
    let wake_edge_capture = wake_graph_capture_label(app);
    let wake_edge_capture_style = if app.wake_edge_missed_updates > 0 {
        Style::default().fg(Color::LightRed)
    } else {
        low_is_good_style(wake_edge_avg_us, 25, 250)
    };
    let timing_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Callback avg "),
            dashboard_value(
                format!("select {}ns", select_avg),
                low_is_good_style(select_avg, 1_000, 5_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("enqueue {}ns", enqueue_avg),
                low_is_good_style(enqueue_avg, 1_000, 5_000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Callback avg "),
            dashboard_value(
                format!("running {}ns", running_avg),
                low_is_good_style(running_avg, 1_000, 5_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("stopping {}ns", stopping_avg),
                low_is_good_style(stopping_avg, 1_000, 5_000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Wake wait avg "),
            dashboard_value(
                format!("direct {}us", dir_wait_us),
                low_is_good_style(dir_wait_us, 10, 100),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("busy {}us", busy_wait_us),
                low_is_good_style(busy_wait_us, 10, 100),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("queue {}us", queue_wait_us),
                low_is_good_style(queue_wait_us, 10, 100),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Lifecycle avg "),
            dashboard_value(
                format!("e {}us", lifecycle_enqueue_avg),
                low_is_good_style(lifecycle_enqueue_avg, 100, 1_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("s {}us", lifecycle_select_avg),
                low_is_good_style(lifecycle_select_avg, 100, 1_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("r {}us", lifecycle_run_avg),
                low_is_good_style(lifecycle_run_avg, 100, 1_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("rs {}us", lifecycle_run_stop_avg),
                low_is_good_style(lifecycle_run_stop_avg, 500, 2_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("x {}us", lifecycle_exit_avg),
                Style::default().fg(Color::LightCyan),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Timing", Color::Green))
    .wrap(Wrap { trim: false });
    frame.render_widget(timing_panel, summary_bottom[0]);

    let health_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Quantum outcome "),
            dashboard_value(
                format!("full {:.0}%", pct(stats.nr_quantum_full, quantum_total)),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("block {:.0}%", pct(stats.nr_quantum_yield, quantum_total)),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "preempt {:.0}%",
                    pct(stats.nr_quantum_preempt, quantum_total)
                ),
                Style::default().fg(Color::LightRed),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Literal sched_yield "),
            dashboard_value(
                stats.nr_sched_yield_calls.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("Kick-to-run avg "),
            dashboard_value(
                format!(
                    "idle {}us",
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[1],
                        stats.nr_wake_kick_observed[1]
                    )
                ),
                low_is_good_style(
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[1],
                        stats.nr_wake_kick_observed[1],
                    ),
                    10,
                    100,
                ),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "preempt {}us",
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[2],
                        stats.nr_wake_kick_observed[2]
                    )
                ),
                low_is_good_style(
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[2],
                        stats.nr_wake_kick_observed[2],
                    ),
                    10,
                    100,
                ),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Target hit / miss "),
            dashboard_value(
                format!(
                    "direct {}/{}",
                    stats.wake_target_hit_count[1], stats.wake_target_miss_count[1]
                ),
                Style::default().fg(Color::Cyan),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "busy {}/{}",
                    stats.wake_target_hit_count[2], stats.wake_target_miss_count[2]
                ),
                Style::default().fg(Color::LightMagenta),
            ),
            dashboard_sep("  "),
            dashboard_label("Edges "),
            dashboard_value(
                format!(
                    "{} {} avg {}us obs {} drops {} drop {:.0}%",
                    wake_edge_capture,
                    app.wake_edges.len(),
                    wake_edge_avg_us,
                    app.wake_edge_observed_events,
                    app.wake_edge_missed_updates,
                    wake_graph_miss_pct(app)
                ),
                wake_edge_capture_style,
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Lifecycle", Color::LightMagenta))
    .wrap(Wrap { trim: false });
    frame.render_widget(health_panel, summary_bottom[1]);

    // --- PELT Utilization Tier Panel ---
    // Aggregate by fixed PELT bands for display only.
    let mut tier_pids = [0u32; 4];
    let mut tier_avg_rt_sum = [0u64; 4];
    let mut tier_jitter_sum = [0u64; 4];
    let mut tier_runs_per_sec = [0.0f64; 4];
    let mut tier_wait_sum = [0u64; 4];
    let mut tier_active = [0u32; 4];

    for row in app.task_rows.values() {
        if !row_has_bpf_matrix_data(row) {
            continue;
        }
        // PELT tier aggregation
        let t = match row.pelt_util {
            0..=49 => 0,
            50..=255 => 1,
            256..=799 => 2,
            _ => 3,
        };
        tier_pids[t] += 1;
        tier_avg_rt_sum[t] += row.pelt_util as u64;
        tier_active[t] += 1;
        let j = row.jitter_accum_ns / row.total_runs as u64;
        tier_jitter_sum[t] += j / 1000;
        tier_runs_per_sec[t] += row.runs_per_sec;
        tier_wait_sum[t] += row.wait_duration_ns / 1000;
    }

    let total_runs_sec: f64 = tier_runs_per_sec.iter().sum();

    let analysis_layout =
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(outer_layout[1]);
    let analysis_right =
        Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).split(analysis_layout[1]);

    let tier_names = ["Idle <5%", "Light 5-25%", "Busy 25-78%", "Hot >=78%"];
    let tier_colors = [Color::LightCyan, Color::Green, Color::Yellow, Color::Red];

    let tier_header = Row::new(vec![
        Cell::from("Band").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Tasks").style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Avg util").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Jitter").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Last wait").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Runs/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Work %").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let tier_rows: Vec<Row> = (0..4)
        .map(|t| {
            let count = tier_active[t].max(1) as u64;
            let avg_rt = tier_avg_rt_sum[t] / count;
            let avg_jit = tier_jitter_sum[t] / count;
            let avg_wait = tier_wait_sum[t] / count;
            let work_pct = if total_runs_sec > 0.0 {
                (tier_runs_per_sec[t] / total_runs_sec) * 100.0
            } else {
                0.0
            };

            Row::new(vec![
                Cell::from(tier_names[t]).style(
                    Style::default()
                        .fg(tier_colors[t])
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format!("{}", tier_pids[t])).style(Style::default().fg(Color::Gray)),
                Cell::from(format!("{}", avg_rt)).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{} µs", avg_jit)).style(low_is_good_style(avg_jit, 10, 100)),
                Cell::from(format!("{}", avg_wait)).style(low_is_good_style(avg_wait, 10, 100)),
                Cell::from(format!("{:.1}", tier_runs_per_sec[t]))
                    .style(Style::default().fg(Color::Green)),
                Cell::from(format!("{:.1}%", work_pct)).style(Style::default().fg(Color::Magenta)),
            ])
        })
        .collect();

    let tier_table = Table::new(
        tier_rows,
        [
            Constraint::Length(15), // Band
            Constraint::Length(6),  // Tasks
            Constraint::Length(10), // Avg util
            Constraint::Length(10), // Jitter
            Constraint::Length(10), // Last wait
            Constraint::Length(9),  // RUNS/s
            Constraint::Length(7),  // Work %
        ],
    )
    .header(tier_header)
    .block(dashboard_block("PELT Utilization Bands", Color::Yellow));
    frame.render_widget(tier_table, analysis_layout[0]);

    let wakewait_line = {
        let mut parts = Vec::new();
        for (idx, label) in ["direct", "busy", "queued"].iter().enumerate() {
            let count = stats.wake_reason_wait_count[idx + 1];
            let avg_us = if count > 0 {
                stats.wake_reason_wait_ns[idx + 1] / count / 1000
            } else {
                0
            };
            let max_us = stats.wake_reason_wait_max_ns[idx + 1] / 1000;
            parts.push(format!("{} {}/{}us ({})", label, avg_us, max_us, count));
        }
        parts.join("  ")
    };
    let coverage_style = if minute_samples.len() >= minute_expected && minute_avg_step <= 1.25 {
        Style::default().fg(Color::Green)
    } else if minute_samples.len() >= minute_expected.saturating_sub(2) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    };
    let coverage_line = Line::from(vec![
        dashboard_label("Coverage "),
        dashboard_value(
            format!(
                "{}/{}  avg step {:.2}s  history {:.0}s",
                minute_samples.len(),
                minute_expected,
                minute_avg_step,
                minute_history_span.as_secs_f64()
            ),
            coverage_style,
        ),
    ]);
    let minute_lines = summarize_timeline_samples(&minute_samples, minute_expected)
        .map(|lines| {
            let mut collected = vec![coverage_line.clone()];
            collected.extend(lines);
            collected
        })
        .unwrap_or_else(|| {
            vec![
                coverage_line,
                Line::from(vec![
                    dashboard_label("Runs/s "),
                    dashboard_note("collecting samples"),
                ]),
                Line::from(vec![
                    dashboard_label("Callback avg "),
                    dashboard_note("waiting for enough history"),
                ]),
                Line::from(vec![
                    dashboard_label("Path share "),
                    dashboard_note("waiting for enough history"),
                ]),
            ]
        });
    let minute_panel = Paragraph::new(minute_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block("Last 60s @1s Samples", Color::Cyan))
        .wrap(Wrap { trim: false });
    frame.render_widget(minute_panel, analysis_right[0]);

    let target_line = format!(
        "postwake target hit/miss {}  follow same/mig {}",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    );
    let slice_line = format!(
        "full={} ({:.1}%) block={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} wake_kick i/p={}/{} affine i/p={}/{}",
        stats.nr_quantum_full,
        pct(stats.nr_quantum_full, quantum_total),
        stats.nr_quantum_yield,
        pct(stats.nr_quantum_yield, quantum_total),
        stats.nr_quantum_preempt,
        pct(stats.nr_quantum_preempt, quantum_total),
        stats.nr_sched_yield_calls,
        stats.nr_wake_kick_idle,
        stats.nr_wake_kick_preempt,
        stats.nr_affine_kick_idle,
        stats.nr_affine_kick_preempt,
    );
    let smt_runtime_ns = stats.smt_solo_runtime_ns + stats.smt_contended_runtime_ns;
    let smt_runs = stats.smt_solo_run_count + stats.smt_contended_run_count;
    let smt_line = format!(
        "runtime cont={:.1}% overlap={:.1}% runs cont={:.1}% avg_run s/c={}/{}us wake s/c={}/{}us active start/stop={}/{}",
        pct(stats.smt_contended_runtime_ns, smt_runtime_ns),
        pct(stats.smt_overlap_runtime_ns, smt_runtime_ns),
        pct(stats.smt_contended_run_count, smt_runs),
        avg_ns(stats.smt_solo_runtime_ns, stats.smt_solo_run_count) / 1000,
        avg_ns(stats.smt_contended_runtime_ns, stats.smt_contended_run_count) / 1000,
        avg_ns(stats.smt_wake_wait_ns[0], stats.smt_wake_wait_count[0]) / 1000,
        avg_ns(stats.smt_wake_wait_ns[1], stats.smt_wake_wait_count[1]) / 1000,
        stats.smt_sibling_active_start_count,
        stats.smt_sibling_active_stop_count,
    );
    let kick_line = format!(
        "idle {}/{} avg={}us max={}us  preempt {}/{} avg={}us max={}us bins {}",
        stats.nr_wake_kick_quick[1],
        stats.nr_wake_kick_observed[1],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[1],
            stats.nr_wake_kick_observed[1]
        ),
        stats.max_wake_kick_to_run_ns[1] / 1000,
        stats.nr_wake_kick_quick[2],
        stats.nr_wake_kick_observed[2],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[2],
            stats.nr_wake_kick_observed[2]
        ),
        stats.max_wake_kick_to_run_ns[2] / 1000,
        format_kick_bucket_summary(&stats.wake_kick_bucket_count),
    );
    let place_path_line = format!(
        "path[{}] deps same/cross={}/{}",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    );
    let mut signal_lines = Vec::new();
    if let Some((focus, total_runtime_ns)) = &focused_app {
        let (state_label, state_style) = app_health_state(focus);
        let quantum_total = focus.quantum_full + focus.quantum_yield + focus.quantum_preempt;
        signal_lines.push(Line::from(vec![
            dashboard_label("Focus "),
            dashboard_value(
                format!(
                    "{}[{}] {} rt={:.1}% {:.1}ms/s {:.1}run/s wait={}/{}us q[b/p]={:.0}/{:.0}% smt={:.1}%",
                    focus.comm,
                    focus.tgid,
                    state_label,
                    pct(focus.runtime_ns, *total_runtime_ns),
                    focus.runtime_ns_per_sec / 1_000_000.0,
                    focus.runs_per_sec,
                    avg_ns(focus.wait_self_ns, focus.wait_self_count) / 1000,
                    focus.wait_self_max_ns / 1000,
                    pct(focus.quantum_yield, quantum_total),
                    pct(focus.quantum_preempt, quantum_total),
                    pct(focus.smt_contended_runtime_ns, focus.runtime_ns),
                ),
                state_style,
            ),
        ]));
        signal_lines.push(Line::from(vec![
            dashboard_label("Focus place "),
            dashboard_value(
                format!(
                    "cpu {}  core {}  wake self/in/out={}/{}/{} blocked=max{}us/n{}",
                    app_cpu_distribution_label(app, focus.tgid, 4),
                    app_core_distribution_label(app, focus.tgid, 4),
                    focus.wake_self,
                    focus.wake_in,
                    focus.wake_out,
                    focus.blocked_wait_max_us,
                    focus.blocked_count,
                ),
                Style::default().fg(Color::LightBlue),
            ),
        ]));
    } else if let Some(tgid) = app.focused_tgid {
        signal_lines.push(Line::from(vec![
            dashboard_label("Focus "),
            dashboard_value(
                format!("tgid {} no longer active in captured task rows", tgid),
                Style::default().fg(Color::Yellow),
            ),
        ]));
    }
    if let Some(diag) = &balance_diag {
        let balance_style = if diag.cpu_skew <= 4.0 {
            Style::default().fg(Color::Green)
        } else if diag.cpu_skew <= 10.0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::LightRed)
        };
        signal_lines.push(Line::from(vec![
            dashboard_label("Balance "),
            dashboard_value(
                format!(
                    "{} top {} {:.1}% {}us {:.1}/s  core {} {:.1}% hot {:.0}% sib {:.0}%  {}",
                    balance_scope,
                    diag.top_cpu_share_label,
                    diag.top_cpu_share_pct,
                    diag.top_cpu_avg_run_us,
                    diag.top_cpu_runs_per_sec,
                    diag.top_core_share_label,
                    diag.top_core_share_pct,
                    diag.top_core_hot_thr_pct,
                    diag.top_core_sib_pct,
                    diag.driver,
                ),
                balance_style,
            ),
        ]));
        signal_lines.push(Line::from(vec![
            dashboard_label("Balance "),
            dashboard_value(
                format!(
                    "rate leader {} {:.1}/s {}us  skew c/c {:.1}x/{:.1}x  hot/cold cpu {}/{} core {}/{}  sticky {}",
                    diag.top_cpu_rate_label,
                    diag.top_cpu_rate_runs_per_sec,
                    diag.top_cpu_rate_avg_run_us,
                    diag.cpu_skew,
                    diag.core_skew,
                    diag.hot_cpu_count,
                    diag.cold_cpu_count,
                    diag.hot_core_count,
                    diag.cold_core_count,
                    if diag.sticky_core { "yes" } else { "no" },
                ),
                Style::default().fg(Color::LightCyan),
            ),
        ]));
    }
    if let Some(owner) = long_run_rows.first() {
        signal_lines.push(Line::from(vec![
            dashboard_label("Long-run owner "),
            dashboard_value(
                long_run_owner_compact(owner),
                if owner.runtime_share_pct <= 15.0 {
                    Style::default().fg(Color::Green)
                } else if owner.runtime_share_pct <= 30.0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::LightRed)
                },
            ),
        ]));
        if let Some(second) = long_run_rows.get(1) {
            signal_lines.push(Line::from(vec![
                dashboard_label("Next owner "),
                dashboard_value(
                    long_run_owner_compact(second),
                    Style::default().fg(Color::LightCyan),
                ),
            ]));
        }
    }
    signal_lines.extend([
        Line::from(vec![
            dashboard_label("Wake wait (<5ms) "),
            dashboard_value(wakewait_line, Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            dashboard_label("Target accuracy "),
            dashboard_value(target_line, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            dashboard_label("Kick to run "),
            dashboard_value(kick_line, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            dashboard_label("Placement paths "),
            dashboard_value(place_path_line, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            dashboard_label("SMT contention "),
            dashboard_value(smt_line, Style::default().fg(Color::LightBlue)),
        ]),
        Line::from(vec![
            dashboard_label("Quantum outcomes "),
            dashboard_value(slice_line, Style::default().fg(Color::Green)),
        ]),
    ]);
    if !app.debug_events.is_empty() {
        if let Some(ev) = app.debug_events.front() {
            signal_lines.push(Line::from(vec![
                dashboard_label("Latest event "),
                dashboard_value(debug_event_label(ev), Style::default().fg(Color::LightRed)),
            ]));
        }
    } else {
        signal_lines.push(Line::from(vec![
            dashboard_label("Latest event "),
            dashboard_note("none"),
        ]));
    }
    let debug_panel = Paragraph::new(signal_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block(
            "Scheduler Health, Balance & Outliers",
            Color::LightMagenta,
        ))
        .wrap(Wrap { trim: false });
    frame.render_widget(debug_panel, analysis_right[1]);

    let matrix_header = Row::new(vec![
        // ── Identity (DarkGray = secondary, Yellow = primary key) ──
        Cell::from("PPID").style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PID").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ST").style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("COMM").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Classification (LightMagenta) ──
        Cell::from("CLS").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Activity / latency (Cyan) ──
        Cell::from("PELT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAXµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("GAPµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("JITµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAITµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("LIFE").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNS/s").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Placement (Magenta) ──
        Cell::from("CPU").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SPRD").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RES%").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SMT%").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Callback Overhead (LightCyan) ──
        Cell::from("SELns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ENQns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("STOPns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Gate Distribution (Green) ──
        Cell::from("G1%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G3%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("DSQ%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Placement / churn (Magenta) ──
        Cell::from("MIGR/s").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let mut matrix_rows: Vec<Row> = Vec::new();
    let mut last_tgid: u32 = 0;

    // Pre-compute thread counts per tgid for the header
    let mut tgid_thread_counts: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    for pid in &app.sorted_pids {
        if let Some(row) = app.task_rows.get(pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { *pid };
            *tgid_thread_counts.entry(tgid).or_insert(0) += 1;
        }
    }
    let tgid_identities = build_tgid_identities(app);

    for pid in &app.sorted_pids {
        let row = match app.task_rows.get(pid) {
            Some(r) => r,
            None => continue,
        };
        let tgid = if row.tgid > 0 { row.tgid } else { *pid };

        // Insert process group header when tgid changes
        if tgid != last_tgid {
            let thread_count = tgid_thread_counts.get(&tgid).copied().unwrap_or(1);
            let identity = tgid_identities
                .get(&tgid)
                .cloned()
                .unwrap_or_else(|| fallback_tgid_identity(tgid, row));
            let proc_name = tgid_header_name(&identity);
            let is_collapsed = app.collapsed_tgids.contains(&tgid);
            if thread_count > 1 || tgid != *pid {
                let arrow = if is_collapsed { "▶" } else { "▼" };
                let header_text = format!(
                    "{} {} (PID {}) — {} threads",
                    arrow, proc_name, tgid, thread_count
                );
                let header_cells = vec![Cell::from(header_text).style(
                    Style::default()
                        .fg(Color::LightBlue)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                )];
                matrix_rows.push(Row::new(header_cells).height(1));
            }
            last_tgid = tgid;
        }

        // Skip entire PPID group if collapsed
        if app.collapsed_ppids.contains(&row.ppid) && row.ppid > 0 {
            continue;
        }

        // Skip child threads if their TGID is collapsed
        if tgid != *pid && app.collapsed_tgids.contains(&tgid) {
            continue;
        }

        let jitter_us = avg_jitter_us(row);
        let indent = if tgid != *pid { "  " } else { "" };
        let placement = placement_summary(row, &app.topology);
        let role = task_role(row, &tgid_roles);
        let last_wait_us = row.wait_duration_ns / 1000;
        let gap_style = if row.dispatch_gap_us > 1_000_000 {
            Style::default().fg(Color::DarkGray)
        } else {
            low_is_good_style(row.dispatch_gap_us, 50, 500)
        };
        let cells = vec![
            Cell::from(format!("{}{}", indent, row.ppid))
                .style(Style::default().fg(Color::DarkGray)),
            Cell::from(format!("{}", row.pid)).style(Style::default().fg(Color::Yellow)),
            Cell::from(row.status.short_label()).style(Style::default().fg(row.status.color())),
            Cell::from(row.comm.as_str()).style(Style::default().fg(role.color())),
            Cell::from(class_label(row)).style(Style::default().fg(class_color(row))),
            Cell::from(format!("{}", row.pelt_util)).style(Style::default().fg(Color::Cyan)),
            Cell::from(display_runtime_us(row.max_runtime_us)).style(low_is_good_style(
                row.max_runtime_us as u64,
                500,
                2_000,
            )),
            Cell::from(display_gap_us(row.dispatch_gap_us)).style(gap_style),
            Cell::from(format!("{}", jitter_us)).style(low_is_good_style(jitter_us, 10, 100)),
            Cell::from(format!("{}", last_wait_us)).style(low_is_good_style(last_wait_us, 10, 100)),
            Cell::from(format_lifecycle_compact(row)).style(Style::default().fg(Color::Cyan)),
            Cell::from(format!("{:.1}", row.runs_per_sec)).style(Style::default().fg(Color::Green)),
            Cell::from(format!("C{:02}", row.core_placement))
                .style(Style::default().fg(Color::Magenta)),
            Cell::from(placement_spread_label(&placement)).style(spread_style(
                placement.active_cpu_count,
                placement.active_core_count,
            )),
            Cell::from(placement_residency_label(&placement)).style(high_is_good_style(
                placement
                    .top_core
                    .map(|(_, count)| (count * 100) as f64 / placement.total_samples.max(1) as f64)
                    .unwrap_or(0.0),
                70.0,
                90.0,
            )),
            Cell::from(format!("{}", placement.smt_secondary_pct)).style(low_is_good_style(
                placement.smt_secondary_pct,
                5,
                20,
            )),
            Cell::from(format!("{}", row.select_cpu_ns)).style(low_is_good_style(
                row.select_cpu_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.enqueue_ns)).style(low_is_good_style(
                row.enqueue_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.stopping_duration_ns)).style(low_is_good_style(
                row.stopping_duration_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.running_duration_ns)).style(low_is_good_style(
                row.running_duration_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[0])).style(high_is_good_style(
                row.gate_hit_pcts[0],
                25.0,
                60.0,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[3])).style(low_is_good_style(
                row.gate_hit_pcts[3] as u64,
                20,
                50,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[9])).style(low_is_good_style(
                row.gate_hit_pcts[9] as u64,
                10,
                25,
            )),
            Cell::from(format!("{:.1}", row.migrations_per_sec)).style(low_is_good_style(
                row.migrations_per_sec as u64,
                1,
                10,
            )),
        ];
        matrix_rows.push(Row::new(cells).height(1));
    }
    let filter_label = app.task_filter.label();
    let matrix_title = format!(
        "Live Task Matrix  [{}]  rows={}  tracked={}  legend in Reference",
        filter_label,
        app.sorted_pids.len(),
        app.bpf_task_count
    );

    let matrix_table = Table::new(
        matrix_rows,
        [
            Constraint::Length(6),  // PPID
            Constraint::Length(8),  // PID
            Constraint::Length(3),  // ST
            Constraint::Length(15), // COMM
            Constraint::Length(5),  // CLS
            Constraint::Length(6),  // PELT
            Constraint::Length(7),  // MAXµs
            Constraint::Length(7),  // GAPµs
            Constraint::Length(7),  // JITµs
            Constraint::Length(8),  // WAITµs
            Constraint::Length(18), // LIFE
            Constraint::Length(7),  // RUNS/s
            Constraint::Length(4),  // CPU
            Constraint::Length(5),  // SPRD
            Constraint::Length(7),  // RES%
            Constraint::Length(5),  // SMT%
            Constraint::Length(6),  // SELns
            Constraint::Length(6),  // ENQns
            Constraint::Length(7),  // STOPns
            Constraint::Length(6),  // RUNns
            Constraint::Length(4),  // G1%
            Constraint::Length(4),  // G3%
            Constraint::Length(4),  // DSQ%
            Constraint::Length(7),  // MIGR/s
        ],
    )
    .header(matrix_header)
    .block(dashboard_block(&matrix_title, Color::Blue))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    // Using render_stateful_widget instead of render_widget to manage scroll table state
    frame.render_stateful_widget(matrix_table, outer_layout[2], &mut app.table_state);
}
