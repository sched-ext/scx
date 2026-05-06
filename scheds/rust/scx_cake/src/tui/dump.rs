// SPDX-License-Identifier: GPL-2.0

use super::diagnostics::{
    build_service_report, format_service_report_json, format_service_report_text,
};
use super::report::build_telemetry_report;
use super::*;

const FLIGHT_SPIKE_ROWS: usize = 24;

#[derive(Default)]
struct FlightMinuteSummary {
    start_elapsed: Duration,
    end_elapsed: Duration,
    sample_secs: f64,
    samples: usize,
    run_total: u64,
    run_rate_low: f64,
    wake_total: u64,
    wait_ge5ms: u64,
    cb_ge10us: u64,
    dispatch_misses: u64,
    queue_net: i128,
    load_avg_sum: f32,
    load_count: usize,
    load_max_pct: f32,
    load_hot_cpu: Option<u16>,
    temp_avg_sum: f32,
    temp_count: usize,
    temp_max_c: f32,
    temp_hot_cpu: Option<u16>,
    path_count: [u64; SELECT_PATH_MAX],
    quantum_count: [u64; 3],
}

impl FlightMinuteSummary {
    fn new(sample: &TimelineSample) -> Self {
        Self {
            start_elapsed: sample.start_elapsed,
            end_elapsed: sample.end_elapsed,
            run_rate_low: f64::MAX,
            ..Self::default()
        }
    }

    fn record(&mut self, sample: &TimelineSample) {
        let secs = sample.elapsed.as_secs_f64().max(0.1);
        let run_rate = per_sec(sample.stats.nr_running_calls, secs);
        self.end_elapsed = sample.end_elapsed;
        self.sample_secs += secs;
        self.samples += 1;
        self.run_total += sample.stats.nr_running_calls;
        self.run_rate_low = self.run_rate_low.min(run_rate);
        self.wake_total += flight_wake_total(&sample.stats);
        self.wait_ge5ms += flight_wait_ge5ms(&sample.stats);
        self.cb_ge10us += flight_cb_ge10us(&sample.stats);
        self.dispatch_misses += sample.stats.nr_dispatch_misses;
        self.queue_net += signed_diff_u64(sample.stats.nr_dsq_queued, sample.stats.nr_dsq_consumed);
        self.load_avg_sum += sample.system.cpu_load_avg_pct;
        self.load_count += 1;
        if sample.system.cpu_load_max_pct >= self.load_max_pct {
            self.load_max_pct = sample.system.cpu_load_max_pct;
            self.load_hot_cpu = sample.system.cpu_load_hot_cpu;
        }
        if sample.system.cpu_temp_avg_c > 0.0 {
            self.temp_avg_sum += sample.system.cpu_temp_avg_c;
            self.temp_count += 1;
        }
        if sample.system.cpu_temp_max_c >= self.temp_max_c {
            self.temp_max_c = sample.system.cpu_temp_max_c;
            self.temp_hot_cpu = sample.system.cpu_temp_hot_cpu;
        }
        for path in 1..SELECT_PATH_MAX {
            self.path_count[path] += sample.stats.select_path_count[path];
        }
        self.quantum_count[0] += sample.stats.nr_quantum_full;
        self.quantum_count[1] += sample.stats.nr_quantum_yield;
        self.quantum_count[2] += sample.stats.nr_quantum_preempt;
    }
}

fn append_wake_graph_section(output: &mut String, app: &TuiApp) {
    if app.wake_edges.is_empty()
        && app.wake_edge_slots_used == 0
        && app.wake_edge_missed_updates == 0
    {
        return;
    }

    let wake_total: u64 = app.wake_edges.iter().map(|edge| edge.wake_count).sum();
    let wait_total: u64 = app.wake_edges.iter().map(|edge| edge.wait_count).sum();
    let wait_ns: u64 = app.wake_edges.iter().map(|edge| edge.wait_ns).sum();
    let wait_max_ns: u64 = app
        .wake_edges
        .iter()
        .map(|edge| edge.wait_max_ns)
        .max()
        .unwrap_or(0);
    let target_hit: u64 = app
        .wake_edges
        .iter()
        .map(|edge| edge.target_hit_count)
        .sum();
    let target_miss: u64 = app
        .wake_edges
        .iter()
        .map(|edge| edge.target_miss_count)
        .sum();
    let follow_same: u64 = app
        .wake_edges
        .iter()
        .map(|edge| edge.follow_same_cpu_count)
        .sum();
    let follow_migrate: u64 = app
        .wake_edges
        .iter()
        .map(|edge| edge.follow_migrate_count)
        .sum();

    output.push_str(&format!(
        "wakegraph: capture={} source=ringbuf_sampled edges={} wake_est={} observed={} weight_sum={} important={} wait_est={}/{}us({}) target_est[h/m]={}/{} follow_est[s/m]={}/{} event_drops={} drop_est={:.1}%\n",
        wake_graph_capture_label(app),
        app.wake_edges.len(),
        wake_total,
        app.wake_edge_observed_events,
        app.wake_edge_sample_weight_sum,
        app.wake_edge_important_events,
        bucket_avg_us(wait_ns, wait_total),
        wait_max_ns / 1000,
        wait_total,
        target_hit,
        target_miss,
        follow_same,
        follow_migrate,
        app.wake_edge_missed_updates,
        wake_graph_miss_pct(app),
    ));
    output.push_str(
        "wakegraph.legend: sampled graph uses one-second epoch sampling; *_est counts are sample-weighted estimates, observed is actual ringbuf events, important events are unsampled slow/miss/migrate facts\n",
    );
    output.push_str("wakegraph.tgids:\n");
    for summary in wake_tgid_summaries(app).iter().take(16) {
        output.push_str(&format!("  {}\n", wake_tgid_line(app, summary)));
    }
    output.push_str("wakegraph.top:\n");
    for edge in app.wake_edges.iter().take(24) {
        output.push_str(&format!("  {}\n", wake_edge_line(app, edge)));
    }
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
            .then_with(|| b.wake_count.cmp(&a.wake_count))
    });
    output.push_str("wakegraph.latency:\n");
    for edge in latency_edges.iter().take(12) {
        output.push_str(&format!("  {}\n", wake_edge_line(app, edge)));
    }
}

#[cfg(debug_assertions)]
fn append_derived_wake_graph_section(output: &mut String, app: &TuiApp) {
    let graph = derive_wake_graph_from_task_rows(app);
    let wake_total: u64 = graph.edges.iter().map(|edge| edge.wake_count).sum();
    let wait_total: u64 = graph.edges.iter().map(|edge| edge.wait_count).sum();
    let wait_ns: u64 = graph.edges.iter().map(|edge| edge.wait_ns).sum();
    let wait_max_ns: u64 = graph
        .edges
        .iter()
        .map(|edge| edge.wait_max_ns)
        .max()
        .unwrap_or(0);

    output.push_str(&format!(
        "wakegraph.derived: source=task_iter quality=debug_derived_latest_waker attribution=latest_waker approximate_edges=yes edges={} wake={} wait={}/{}us({})\n",
        graph.edges.len(),
        wake_total,
        bucket_avg_us(wait_ns, wait_total),
        wait_max_ns / 1000,
        wait_total,
    ));
    output.push_str(
        "wakegraph.derived.legend: task rows keep cumulative wake counts but only latest waker identity, so edge attribution is approximate; wait/path/place come from task_iter snapshots\n",
    );
    if graph.edges.is_empty() {
        return;
    }

    output.push_str("wakegraph.derived.tgids:\n");
    for summary in wake_tgid_summaries_from_edges(&graph.edges).iter().take(16) {
        output.push_str(&format!("  {}\n", wake_tgid_line(app, summary)));
    }
    output.push_str("wakegraph.derived.top:\n");
    for edge in graph.edges.iter().take(24) {
        output.push_str(&format!("  {}\n", wake_edge_line(app, edge)));
    }

    let mut latency_edges: Vec<&WakeEdgeRow> = graph
        .edges
        .iter()
        .filter(|edge| edge.wait_count > 0)
        .collect();
    latency_edges.sort_by(|a, b| {
        b.wait_max_ns
            .cmp(&a.wait_max_ns)
            .then_with(|| wake_edge_avg_us(b).cmp(&wake_edge_avg_us(a)))
            .then_with(|| b.wait_count.cmp(&a.wait_count))
            .then_with(|| b.wake_count.cmp(&a.wake_count))
    });
    output.push_str("wakegraph.derived.latency:\n");
    for edge in latency_edges.iter().take(12) {
        output.push_str(&format!("  {}\n", wake_edge_line(app, edge)));
    }
}

fn format_tgid_wake_graph(app: &TuiApp, tgid: u32) -> Option<String> {
    let mut edges: Vec<&WakeEdgeRow> = app
        .wake_edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid || edge.wakee_tgid == tgid)
        .collect();
    if edges.is_empty() {
        return None;
    }

    edges.sort_by(|a, b| {
        b.wait_count
            .cmp(&a.wait_count)
            .then_with(|| b.wake_count.cmp(&a.wake_count))
            .then_with(|| b.wait_ns.cmp(&a.wait_ns))
    });

    let internal_wakes: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid && edge.wakee_tgid == tgid)
        .map(|edge| edge.wake_count)
        .sum();
    let outbound_wakes: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid && edge.wakee_tgid != tgid)
        .map(|edge| edge.wake_count)
        .sum();
    let inbound_wakes: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid != tgid && edge.wakee_tgid == tgid)
        .map(|edge| edge.wake_count)
        .sum();
    let self_wait_total: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.wait_count)
        .sum();
    let self_wait_ns: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.wait_ns)
        .sum();
    let self_wait_max_ns: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.wait_max_ns)
        .max()
        .unwrap_or(0);
    let out_wait_total: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid && edge.wakee_tgid != tgid)
        .map(|edge| edge.wait_count)
        .sum();
    let out_wait_ns: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid && edge.wakee_tgid != tgid)
        .map(|edge| edge.wait_ns)
        .sum();
    let out_wait_max_ns: u64 = edges
        .iter()
        .filter(|edge| edge.waker_tgid == tgid && edge.wakee_tgid != tgid)
        .map(|edge| edge.wait_max_ns)
        .max()
        .unwrap_or(0);
    let self_target_hit: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.target_hit_count)
        .sum();
    let self_target_miss: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.target_miss_count)
        .sum();
    let self_follow_same: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.follow_same_cpu_count)
        .sum();
    let self_follow_migrate: u64 = edges
        .iter()
        .filter(|edge| edge.wakee_tgid == tgid)
        .map(|edge| edge.follow_migrate_count)
        .sum();
    let observed_events: u64 = edges.iter().map(|edge| edge.observed_event_count).sum();
    let sample_weight_sum: u64 = edges.iter().map(|edge| edge.sample_weight_sum).sum();

    let mut out = format!(
        "  wakegraph: cap={} edges={} observed={} weight_sum={} wake_est[in/int/out]={}/{}/{} wait_est_self={}/{}us({}) wait_est_out={}/{}us({}) target_est_self[h/m]={}/{} follow_est_self[s/m]={}/{}\n",
        wake_graph_capture_label(app),
        edges.len(),
        observed_events,
        sample_weight_sum,
        inbound_wakes,
        internal_wakes,
        outbound_wakes,
        bucket_avg_us(self_wait_ns, self_wait_total),
        self_wait_max_ns / 1000,
        self_wait_total,
        bucket_avg_us(out_wait_ns, out_wait_total),
        out_wait_max_ns / 1000,
        out_wait_total,
        self_target_hit,
        self_target_miss,
        self_follow_same,
        self_follow_migrate,
    );
    for edge in edges.iter().take(6) {
        out.push_str(&format!("    {}\n", wake_edge_line(app, edge)));
    }
    Some(out)
}

fn append_select_cpu_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    elapsed: Duration,
) {
    let rows = select_cpu_rows(counters);
    let target_total: u64 = counters
        .iter()
        .map(|counter| counter.select_target_total)
        .sum();
    let prev_total: u64 = counters
        .iter()
        .map(|counter| counter.select_prev_total)
        .sum();
    if target_total == 0 && prev_total == 0 {
        return;
    }

    let target_reason = select_reason_totals(counters, false);
    let prev_reason = select_reason_totals(counters, true);
    let top_target = rows
        .iter()
        .max_by_key(|row| row.target_total)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_target_pct = rows
        .iter()
        .max_by_key(|row| row.target_total)
        .map(|row| row.target_pct)
        .unwrap_or(0.0);
    let top_prev = rows
        .iter()
        .max_by_key(|row| row.prev_total)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_prev_pct = rows
        .iter()
        .max_by_key(|row| row.prev_total)
        .map(|row| row.prev_pct)
        .unwrap_or(0.0);

    output.push_str(&format!(
        "{}: sampled={:.1}s target_total={} prev_total={} top_target={} {:.1}% top_prev={} {:.1}% target_skew={:.1}x prev_skew={:.1}x\n",
        label,
        elapsed.as_secs_f64(),
        target_total,
        prev_total,
        top_target,
        top_target_pct,
        top_prev,
        top_prev_pct,
        select_balance_ratio(counters, false),
        select_balance_ratio(counters, true),
    ));
    output.push_str(&format!(
        "{}.legend: hm=home_cpu hc=home_core pp=prev_primary ps=primary_scan hy=hybrid_scan kp=kernel_prev ki=kernel_idle tn=tunnel pc=pressure_core sbp=scoreboard_prev sbs=scoreboard_scan\n",
        label
    ));
    output.push_str(&format!(
        "{}.reasons.target: {}\n",
        label,
        format_select_reason_summary(&target_reason)
    ));
    output.push_str(&format!(
        "{}.reasons.prev: {}\n",
        label,
        format_select_reason_summary(&prev_reason)
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in rows {
        output.push_str(&format!(
            "  cpu=C{:02} target={} ({:.1}%) prev={} ({:.1}%) tgt={} prev={}\n",
            row.cpu,
            row.target_total,
            row.target_pct,
            row.prev_total,
            row.prev_pct,
            format_select_reason_mix(&row.target_reason, row.target_total),
            format_select_reason_mix(&row.prev_reason, row.prev_total),
        ));
    }
}

fn append_home_seed_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    elapsed: Duration,
) {
    let rows = home_seed_rows(counters);
    if rows.is_empty() {
        return;
    }

    let secs = elapsed.as_secs_f64().max(0.1);
    let total: u64 = counters.iter().map(|counter| counter.home_seed_total).sum();
    let reason_total = home_seed_reason_totals(counters);
    let attributed: u64 = reason_total[1..].iter().sum();
    let unattributed = total.saturating_sub(attributed);
    let top = rows
        .iter()
        .max_by_key(|row| row.seeds)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_pct = rows
        .iter()
        .max_by_key(|row| row.seeds)
        .map(|row| row.seed_pct)
        .unwrap_or(0.0);

    output.push_str(&format!(
        "{}: sampled={:.1}s seeds={} ({:.1}/s) top={} {:.1}% skew={:.1}x unattributed={} reasons={}\n",
        label,
        elapsed.as_secs_f64(),
        total,
        per_sec(total, secs),
        top,
        top_pct,
        home_seed_balance_ratio(counters),
        unattributed,
        format_select_reason_summary(&reason_total),
    ));
    output.push_str(&format!(
        "{}.legend: first time cake_running converts sentinel home_cpu into learned primary CPU; reason=last select_cpu reason before first run\n",
        label
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in rows.iter().take(32) {
        output.push_str(&format!(
            "  cpu=C{:02} seeds={} ({:.1}%, {:.1}/s) reason={}\n",
            row.cpu,
            row.seeds,
            row.seed_pct,
            per_sec(row.seeds, secs),
            format_select_reason_mix(&row.reason, row.seeds),
        ));
    }
    if rows.len() > 32 {
        output.push_str(&format!("  ... +{} more CPUs\n", rows.len() - 32));
    }
}

fn append_pressure_probe_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    totals: &PressureProbeCounters,
    elapsed: Duration,
) {
    let total_eval: u64 = totals.total.iter().map(|site| site[0]).sum();
    if total_eval == 0 {
        return;
    }

    output.push_str(&format!(
        "{}.legend: ev=evaluated ba=anchor(structural blocker) bs=score bd=delta bb=sibling_busy ok=success anchor=inv(invalid_cpu) sec(smt_secondary_anchor) nosib(no_sibling) aff(affinity)\n",
        label
    ));

    for site in 0..PRESSURE_SITE_MAX {
        let rows = pressure_probe_rows(counters, site);
        let eval_total = totals.total[site][0];
        if eval_total == 0 {
            continue;
        }

        let accounted_eval: u64 = rows.iter().map(|row| row.eval_total).sum();
        let unattributed = eval_total.saturating_sub(accounted_eval);
        let top_anchor = rows
            .iter()
            .max_by_key(|row| row.eval_total)
            .map(|row| format!("C{:02}", row.cpu))
            .unwrap_or_else(|| "-".to_string());
        let top_anchor_pct = rows
            .iter()
            .max_by_key(|row| row.eval_total)
            .map(|row| row.eval_pct)
            .unwrap_or(0.0);

        output.push_str(&format!(
            "{}.{}: sampled={:.1}s eval={} unattributed={} top_anchor={} {:.1}% eval_skew={:.1}x outcomes={} anchor={}\n",
            label,
            pressure_probe_site_label(site),
            elapsed.as_secs_f64(),
            eval_total,
            unattributed,
            top_anchor,
            top_anchor_pct,
            pressure_probe_balance_ratio(counters, site),
            format_pressure_probe_summary(&totals.total[site]),
            format_pressure_anchor_summary(&totals.anchor_block[site], totals.total[site][1]),
        ));
        output.push_str(&format!(
            "{}.{}.rows:\n",
            label,
            pressure_probe_site_label(site)
        ));
        for row in rows {
            output.push_str(&format!(
                "  cpu=C{:02} eval={} ({:.1}%) outcomes={} anchor={}\n",
                row.cpu,
                row.eval_total,
                row.eval_pct,
                format_pressure_probe_mix(&row.outcome, row.eval_total),
                format_pressure_anchor_summary(&row.anchor_block, row.outcome[1]),
            ));
        }
    }
}

fn decision_conf_value(confidence: u64, shift: u32) -> u64 {
    (confidence >> shift) & CAKE_CONF_NIBBLE_MASK
}

fn decision_conf_effective_value(confidence: u64, shift: u32) -> u64 {
    let value = decision_conf_value(confidence, shift);
    if value == 0 {
        8
    } else {
        value
    }
}

fn decision_load_shock_value(confidence: u64) -> u64 {
    decision_conf_value(confidence, CAKE_CONF_LOAD_SHOCK_SHIFT)
}

fn decision_floor_owner_ready(confidence: u64) -> bool {
    let owner_stable = decision_conf_effective_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT);
    let route = decision_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT);
    let trust = decision_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT);
    let pull = decision_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);
    let shock = decision_load_shock_value(confidence);

    owner_stable >= 12 || (route == 15 && trust == 15 && pull >= 12 && shock < 8)
}

fn decision_route_label(kind: u64) -> &'static str {
    match kind {
        1 => "prev",
        2 => "slot0",
        3 => "slot1",
        4 => "slot2",
        5 => "slot3",
        6 => "tunnel",
        _ => "none",
    }
}

fn accel_route_label(kind: usize) -> &'static str {
    match kind {
        1 => "prev",
        2 => "s0",
        3 => "s1",
        4 => "s2",
        5 => "s3",
        6 => "tun",
        _ => "none",
    }
}

fn accel_block_label(reason: usize) -> &'static str {
    match reason {
        0 => "invalid_prev",
        1 => "affinity",
        2 => "kthread",
        3 => "route_low",
        4 => "select_low",
        5 => "trust_low",
        6 => "load_shock",
        7 => "floor_low",
        8 => "owner_low",
        9 => "pull_low",
        10 => "audit",
        11 => "latency_gate",
        12 => "unknown_route",
        _ => "?",
    }
}

fn accel_probe_label(outcome: usize) -> &'static str {
    match outcome {
        0 => "hit",
        1 => "busy",
        2 => "dirty",
        3 => "smt_busy",
        4 => "claim_fail",
        5 => "claim_skip",
        6 => "invalid",
        _ => "?",
    }
}

fn decision_floor_label(gear: u64) -> &'static str {
    match gear {
        1 => "audit",
        2 => "narrow",
        3 => "floor",
        _ => "recovery",
    }
}

fn format_trust_state(trust: CpuTrustSnapshot) -> String {
    if trust.policy == 0 && trust.blocked == 0 && trust.demotion_count == 0 {
        return "off".to_string();
    }

    let prev = if trust.prev_direct_active() {
        "prev=active"
    } else if trust.prev_direct_blocked() {
        "prev=blocked"
    } else if trust.prev_direct_enabled() {
        "prev=enabled"
    } else {
        "prev=off"
    };

    format!(
        "{} gen={} bgen={} block=0x{:x} demote={} reason={}",
        prev,
        trust.generation,
        trust.blocked_generation,
        trust.blocked,
        trust.demotion_count,
        crate::trust::trust_demotion_label(trust.reason),
    )
}

fn format_decision_confidence(confidence: u64) -> String {
    if confidence == 0 {
        return "untrained".to_string();
    }

    format!(
        "sel={}/{} claim={} disp={} kick={} pull={} route={}:{} gear={} trust={} stable={} shock={} aud={}/{} acct_audit={}",
        decision_conf_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_SELECT_ROW4_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_CLAIM_HEALTH_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_KICK_SHAPE_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT),
        decision_route_label(decision_conf_value(confidence, CAKE_CONF_ROUTE_KIND_SHIFT)),
        decision_conf_value(confidence, CAKE_CONF_ROUTE_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_LOAD_SHOCK_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_ROUTE_AUDIT_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_PULL_AUDIT_SHIFT),
        decision_conf_value(confidence, CAKE_CONF_ACCOUNT_AUDIT_SHIFT),
    )
}

fn decision_floor_ready(confidence: u64) -> bool {
    decision_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT) == 3
        && decision_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= 12
        && decision_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= 12
        && decision_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= 12
        && decision_floor_owner_ready(confidence)
        && decision_load_shock_value(confidence) < 8
        && decision_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT) >= 8
}

fn decision_route_ready(confidence: u64) -> bool {
    decision_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= 12
        && decision_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= 12
        && decision_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= 12
        && decision_load_shock_value(confidence) < 12
}

fn decision_fail_flags(confidence: u64) -> String {
    if confidence == 0 {
        return "untrained".to_string();
    }

    let mut flags = Vec::new();
    if decision_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) < 12 {
        flags.push("route_low");
    }
    if decision_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) < 12 {
        flags.push("select_low");
    }
    if decision_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) < 12 {
        flags.push("status_trust_low");
    }
    if !decision_floor_owner_ready(confidence) {
        flags.push("owner_unstable_floor_only");
    }
    let load_shock = decision_load_shock_value(confidence);
    if load_shock >= 12 {
        flags.push("load_shock");
    } else if load_shock >= 8 {
        flags.push("load_shock_floor_only");
    }
    if decision_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT) < 8 {
        flags.push("pull_low");
    }
    if flags.is_empty() {
        "clear".to_string()
    } else {
        flags.join("|")
    }
}

fn format_accel_route_triplet(
    attempt: &[u64; ACCEL_ROUTE_MAX],
    hit: &[u64; ACCEL_ROUTE_MAX],
    miss: &[u64; ACCEL_ROUTE_MAX],
) -> String {
    let mut parts = Vec::new();
    for route in 1..ACCEL_ROUTE_MAX {
        if attempt[route] == 0 && hit[route] == 0 && miss[route] == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}/{}({:.1}%)",
            accel_route_label(route),
            attempt[route],
            hit[route],
            miss[route],
            pct(hit[route], hit[route] + miss[route]),
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_accel_route_blocks(blocks: &[u64; ACCEL_ROUTE_BLOCK_MAX]) -> String {
    let mut parts = Vec::new();
    for (reason, count) in blocks.iter().enumerate().take(ACCEL_ROUTE_BLOCK_MAX) {
        if *count == 0 {
            continue;
        }
        parts.push(format!("{}={}", accel_block_label(reason), count));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_accel_probe_matrix(probes: &[[u64; ACCEL_PROBE_OUTCOME_MAX]; ACCEL_ROUTE_MAX]) -> String {
    let mut parts = Vec::new();
    for (route, route_probes) in probes.iter().enumerate().take(ACCEL_ROUTE_MAX).skip(1) {
        let total: u64 = route_probes.iter().sum();
        if total == 0 {
            continue;
        }
        let outcomes = (0..ACCEL_PROBE_OUTCOME_MAX)
            .filter(|outcome| route_probes[*outcome] > 0)
            .map(|outcome| format!("{}={}", accel_probe_label(outcome), route_probes[outcome]))
            .collect::<Vec<_>>()
            .join("/");
        parts.push(format!("{}[{}]", accel_route_label(route), outcomes));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_accel_fallback_summary(stats: &cake_stats) -> String {
    format!(
        "native[entry/dfl/and]={}/{}/{} pull[pull/probe/skip]={}/{}/{} pull_probe[empty/work]={}/{} acct[relaxed/audit]={}/{}",
        stats.accel_native_fallback_count[0],
        stats.accel_native_fallback_count[1],
        stats.accel_native_fallback_count[2],
        stats.accel_pull_mode_count[0],
        stats.accel_pull_mode_count[1],
        stats.accel_pull_mode_count[2],
        stats.accel_pull_probe_count[0],
        stats.accel_pull_probe_count[1],
        stats.accel_accounting_relaxed,
        stats.accel_accounting_audit,
    )
}

fn format_trust_last_reason_cpus(counters: &[CpuWorkCounters]) -> String {
    let mut none = 0_u64;
    let mut claim_miss = 0_u64;
    let mut unknown = 0_u64;

    for counter in counters {
        if counter.trust.demotion_count == 0 {
            continue;
        }
        match counter.trust.reason {
            crate::trust::CAKE_TRUST_DEMOTE_NONE => none += 1,
            crate::trust::CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS => claim_miss += 1,
            _ => unknown += 1,
        }
    }

    let mut parts = Vec::new();
    if none > 0 {
        parts.push(format!("none={}", none));
    }
    if claim_miss > 0 {
        parts.push(format!("prev_claim_miss={}", claim_miss));
    }
    if unknown > 0 {
        parts.push(format!("unknown={}", unknown));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn accelerator_capture_label() -> &'static str {
    #[cfg(cake_bpf_release)]
    {
        "release"
    }
    #[cfg(all(not(cake_bpf_release), cake_hot_telemetry))]
    {
        "debug-hot-telemetry"
    }
    #[cfg(all(not(cake_bpf_release), not(cake_hot_telemetry)))]
    {
        "debug-no-hot-telemetry"
    }
}

fn append_accelerator_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    stats: &cake_stats,
    elapsed: Duration,
) {
    let secs = elapsed.as_secs_f64().max(0.1);
    let conf_rows: Vec<(usize, &CpuWorkCounters)> = counters
        .iter()
        .enumerate()
        .filter(|(_, counter)| counter.decision_confidence != 0)
        .collect();
    let mut gear_count = [0_u64; 4];
    let mut route_count = [0_u64; 7];
    let mut route_ready = 0_u64;
    let mut floor_ready = 0_u64;
    let mut shock = 0_u64;
    let mut trust_low = 0_u64;
    let mut owner_low = 0_u64;
    let mut trust_prev_enabled = 0_u64;
    let mut trust_prev_active = 0_u64;
    let mut trust_prev_blocked = 0_u64;
    let mut trust_prev_demotions = 0_u64;

    for (_, counter) in &conf_rows {
        let confidence = counter.decision_confidence;
        let gear = decision_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT) as usize;
        let route = decision_conf_value(confidence, CAKE_CONF_ROUTE_KIND_SHIFT) as usize;

        if gear < gear_count.len() {
            gear_count[gear] += 1;
        }
        if route < route_count.len() {
            route_count[route] += 1;
        }
        if decision_route_ready(confidence) {
            route_ready += 1;
        }
        if decision_floor_ready(confidence) {
            floor_ready += 1;
        }
        if decision_load_shock_value(confidence) >= 8 {
            shock += 1;
        }
        if decision_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) < 12 {
            trust_low += 1;
        }
        if decision_conf_effective_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT) < 12 {
            owner_low += 1;
        }
    }
    for counter in counters {
        if counter.trust.prev_direct_enabled() {
            trust_prev_enabled += 1;
        }
        if counter.trust.prev_direct_active() {
            trust_prev_active += 1;
        }
        if counter.trust.prev_direct_blocked() {
            trust_prev_blocked += 1;
        }
        trust_prev_demotions =
            trust_prev_demotions.saturating_add(counter.trust.demotion_count as u64);
    }

    let path_total: u64 = stats.select_path_count[1..SELECT_PATH_MAX].iter().sum();
    let wake_target_hit: u64 = stats.wake_target_hit_count[1..].iter().sum();
    let wake_target_miss: u64 = stats.wake_target_miss_count[1..].iter().sum();
    let wake_target_total = wake_target_hit + wake_target_miss;
    let dispatch_hit = stats.nr_dispatch_llc_local_hit + stats.nr_dispatch_llc_steal_hit;
    let dispatch_total = dispatch_hit + stats.nr_dispatch_misses;
    let wake_direct = stats.nr_wakeup_direct_dispatches;
    let wake_busy = stats.nr_wakeup_dsq_fallback_busy;
    let wake_queued = stats.nr_wakeup_dsq_fallback_queued;
    let wake_total = wake_direct + wake_busy + wake_queued;

    output.push_str(&format!(
        "{}: sampled={:.1}s source={} cpus={} trained={} route_ready={} ({:.1}%) floor_ready={} ({:.1}%) gear[recovery/audit/narrow/floor]={}/{}/{}/{} route[none/prev/s0/s1/s2/s3/tunnel]={}/{}/{}/{}/{}/{}/{} shock={} trust_low={} owner_low={}\n",
        label,
        elapsed.as_secs_f64(),
        accelerator_capture_label(),
        counters.len(),
        conf_rows.len(),
        route_ready,
        pct(route_ready, conf_rows.len() as u64),
        floor_ready,
        pct(floor_ready, conf_rows.len() as u64),
        gear_count[0],
        gear_count[1],
        gear_count[2],
        gear_count[3],
        route_count[0],
        route_count[1],
        route_count[2],
        route_count[3],
        route_count[4],
        route_count[5],
        route_count[6],
        shock,
        trust_low,
        owner_low,
    ));
    output.push_str(&format!(
        "{}.prediction: select_paths={} tunnel={} ({:.1}%) idle={} ({:.1}%) target_hit/miss={}/{} ({:.1}% hit) wake[d/b/q]={}/{}/{} ({:.1}% direct) dispatch_hit/miss={}/{} ({:.1}% hit)\n",
        label,
        format_path_summary(&stats.select_path_count),
        stats.select_path_count[5],
        pct(stats.select_path_count[5], path_total),
        stats.select_path_count[4],
        pct(stats.select_path_count[4], path_total),
        wake_target_hit,
        wake_target_miss,
        pct(wake_target_hit, wake_target_total),
        wake_direct,
        wake_busy,
        wake_queued,
        pct(wake_direct, wake_total),
        dispatch_hit,
        stats.nr_dispatch_misses,
        pct(dispatch_hit, dispatch_total),
    ));
    output.push_str(&format!(
        "{}.scoreboard: queue_net={} wake_target={} smt_solo/contended={}/{} localq_ins/run={}/{} ({:.1}/s/{:.1}/s)\n",
        label,
        signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed),
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        stats.smt_solo_run_count,
        stats.smt_contended_run_count,
        counters.iter().map(|counter| counter.local_pending_inserts).sum::<u64>(),
        counters.iter().map(|counter| counter.local_pending_runs).sum::<u64>(),
        per_sec(counters.iter().map(|counter| counter.local_pending_inserts).sum::<u64>(), secs),
        per_sec(counters.iter().map(|counter| counter.local_pending_runs).sum::<u64>(), secs),
    ));
    output.push_str(&format!(
        "{}.route_pred: route[attempt/hit/miss(hit%)]={} block={}\n",
        label,
        format_accel_route_triplet(
            &stats.accel_route_attempt_count,
            &stats.accel_route_hit_count,
            &stats.accel_route_miss_count,
        ),
        format_accel_route_blocks(&stats.accel_route_block_count),
    ));
    output.push_str(&format!(
        "{}.fastscan: route[attempt/hit/miss(hit%)]={} probe={}\n",
        label,
        format_accel_route_triplet(
            &stats.accel_fast_attempt_count,
            &stats.accel_fast_hit_count,
            &stats.accel_fast_miss_count,
        ),
        format_accel_probe_matrix(&stats.accel_scoreboard_probe_count),
    ));
    output.push_str(&format!(
        "{}.fallback: {}\n",
        label,
        format_accel_fallback_summary(stats),
    ));
    output.push_str(&format!(
        "{}.trust: prev_direct[state active/enabled/blocked]={}/{}/{} demotions={} ({:.2}/s) last_reason_cpus={} trusted_prev[attempt/hit/miss(hit%)]={}/{}/{}({:.1}%) rate[a/h/m]={:.1}/{:.1}/{:.1}/s\n",
        label,
        trust_prev_active,
        trust_prev_enabled,
        trust_prev_blocked,
        trust_prev_demotions,
        per_sec(trust_prev_demotions, secs),
        format_trust_last_reason_cpus(counters),
        stats.accel_trust_prev_attempt,
        stats.accel_trust_prev_hit,
        stats.accel_trust_prev_miss,
        pct(stats.accel_trust_prev_hit, stats.accel_trust_prev_attempt),
        per_sec(stats.accel_trust_prev_attempt, secs),
        per_sec(stats.accel_trust_prev_hit, secs),
        per_sec(stats.accel_trust_prev_miss, secs),
    ));
    output.push_str(&format!(
        "{}.legend: trained=CPUs whose packed confidence has been updated route_ready=prediction can replay a learned route before fallback floor_ready=tunnel tier shock/trust are route gates owner is a floor-only gate fallback is the safe kernel baseline trust.prev_direct is the userspace-governed BPF branch shedder route_pred shows peak floor-path attempts block names why prediction refused fastscan shows scoreboard claims before native fallback probe names scoreboard reality after prediction\n",
        label
    ));

    let mut rows = conf_rows;
    rows.sort_by(|a, b| {
        let a_conf = a.1.decision_confidence;
        let b_conf = b.1.decision_confidence;
        decision_floor_ready(b_conf)
            .cmp(&decision_floor_ready(a_conf))
            .then_with(|| {
                decision_conf_value(b_conf, CAKE_CONF_FLOOR_GEAR_SHIFT)
                    .cmp(&decision_conf_value(a_conf, CAKE_CONF_FLOOR_GEAR_SHIFT))
            })
            .then_with(|| {
                decision_conf_effective_value(b_conf, CAKE_CONF_ROUTE_SHIFT).cmp(
                    &decision_conf_effective_value(a_conf, CAKE_CONF_ROUTE_SHIFT),
                )
            })
    });
    output.push_str(&format!("{}.rows:\n", label));
    if rows.is_empty() {
        output.push_str("  none yet: no CPU has trained confidence state in this capture\n");
    }
    for (cpu, counter) in rows.iter().take(24) {
        let confidence = counter.decision_confidence;
        output.push_str(&format!(
            "  cpu=C{:02} floor={} route_ready={} floor_ready={} route={} fail_flags={} trust={} press={} pending={} conf={}\n",
            cpu,
            decision_floor_label(decision_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT)),
            if decision_route_ready(confidence) {
                "yes"
            } else {
                "no"
            },
            if decision_floor_ready(confidence) {
                "yes"
            } else {
                "no"
            },
            decision_route_label(decision_conf_value(confidence, CAKE_CONF_ROUTE_KIND_SHIFT)),
            decision_fail_flags(confidence),
            format_trust_state(counter.trust),
            counter.cpu_pressure,
            counter.local_pending,
            format_decision_confidence(confidence),
        ));
    }
    if rows.len() > 24 {
        output.push_str(&format!("  ... +{} more CPUs\n", rows.len() - 24));
    }
}

fn append_local_queue_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    elapsed: Duration,
) {
    let rows = local_queue_rows(counters);
    if rows.is_empty() {
        return;
    }

    let secs = elapsed.as_secs_f64().max(0.1);
    let inserts: u64 = counters
        .iter()
        .map(|counter| counter.local_pending_inserts)
        .sum();
    let runs: u64 = counters
        .iter()
        .map(|counter| counter.local_pending_runs)
        .sum();
    let pending_now: u64 = counters
        .iter()
        .map(|counter| counter.local_pending as u64)
        .sum();
    let max_cpu_pending = counters
        .iter()
        .map(|counter| counter.local_pending_max)
        .max()
        .unwrap_or(0);
    let direct: u64 = counters
        .iter()
        .map(|counter| counter.wake_direct_target)
        .sum();
    let busy: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_target)
        .sum();
    let busy_local: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_local_target)
        .sum();
    let busy_remote: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_remote_target)
        .sum();
    let top_pending = rows
        .iter()
        .max_by_key(|row| row.pending)
        .filter(|row| row.pending > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_busy = rows
        .iter()
        .max_by_key(|row| row.busy)
        .filter(|row| row.busy > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_wait = counters
        .iter()
        .enumerate()
        .max_by_key(|(_, counter)| target_wait_total_ns(counter))
        .filter(|(_, counter)| target_wait_total_ns(counter) > 0)
        .map(|(cpu, _)| format!("C{:02}", cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_pressure = rows
        .iter()
        .max_by_key(|row| row.pressure)
        .filter(|row| row.pressure > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());

    output.push_str(&format!(
        "{}: sampled={:.1}s inserts={} ({:.1}/s) runs_seen={} ({:.1}/s) pending_now={} max_cpu_pending={} wake_target:direct={} busy={} busy_local={} busy_remote={} top_pending={} top_busy={} top_wait={} top_pressure={}\n",
        label,
        elapsed.as_secs_f64(),
        inserts,
        per_sec(inserts, secs),
        runs,
        per_sec(runs, secs),
        pending_now,
        max_cpu_pending,
        direct,
        busy,
        busy_local,
        busy_remote,
        top_pending,
        top_busy,
        top_wait,
        top_pressure,
    ));
    output.push_str(&format!(
        "{}.legend: pend=estimated SCX_DSQ_LOCAL_ON inserts not yet observed running max=per-cpu peak since reset press=cpu_pressure trust=userspace governor/BPF demotion state conf=packed confidence sel=early/row4 route=kind:confidence gear=floor mode trust=status stable=owner shock=load aud=route/pull acct_audit=account wait=target wake-to-run avg/max/p99bucket(samples)\n",
        label
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in rows.iter().take(32) {
        output.push_str(&format!(
            "  cpu=C{:02} press={} trust={} conf={} pend={} max={} ins={} ({:.1}/s) run_seen={} ({:.1}/s) wake_target[d/b/l/r]={}/{}/{}/{} wait={}\n",
            row.cpu,
            row.pressure,
            format_trust_state(row.trust),
            format_decision_confidence(row.decision_confidence),
            row.pending,
            row.pending_max,
            row.inserts,
            per_sec(row.inserts, secs),
            row.runs,
            per_sec(row.runs, secs),
            row.direct,
            row.busy,
            row.busy_local,
            row.busy_remote,
            format_local_queue_wait(row),
        ));
    }
    if rows.len() > 32 {
        output.push_str(&format!("  ... +{} more CPUs\n", rows.len() - 32));
    }
}

fn format_row_place_wait_summary(row: &TaskTelemetryRow) -> String {
    let mut parts = Vec::new();
    for cls in 0..4 {
        let count = row.home_place_wait_count[cls];
        if count == 0 {
            continue;
        }
        let avg_us = row.home_place_wait_ns[cls] / count as u64 / 1000;
        parts.push(format!(
            "{}={}/{}/{}",
            place_class_label(cls),
            avg_us,
            row.home_place_wait_max_us[cls],
            count
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wakewait_summary(sum_ns: &[u64], count: &[u64], max_ns: &[u64]) -> String {
    let mut parts = Vec::new();
    for reason in 1..4 {
        let samples = count[reason];
        let avg_us = if samples > 0 {
            sum_ns[reason] / samples / 1000
        } else {
            0
        };
        let max_us = max_ns[reason] / 1000;
        parts.push(format!(
            "{}={}/{}us({})",
            ["dir", "busy", "queue"][reason - 1],
            avg_us,
            max_us,
            samples
        ));
    }
    parts.join(" ")
}

pub(super) fn format_tgid_health_summary(app: &TuiApp, tgid: u32, dump_pids: &[u32]) -> String {
    let mut threads = 0u32;
    let mut hot_threads = 0u32;
    let mut run_rate = 0.0;
    let mut max_wait_us = 0u64;
    let mut max_gap_us = 0u64;
    let mut max_start_us = 0u32;
    let mut max_hot_start_us = 0u32;
    let mut cpu_seen = [false; crate::topology::MAX_CPUS];
    let mut core_seen = [false; crate::topology::MAX_CORES];
    let mut smt_samples = 0u64;
    let mut run_samples = 0u64;
    let mut enqueue_first = 0u32;
    let mut select_first = 0u32;
    let mut running_first = 0u32;
    let mut full_startup_phase = 0u32;

    for pid in dump_pids {
        let Some(row) = app.task_rows.get(pid) else {
            continue;
        };
        let row_tgid = if row.tgid > 0 { row.tgid } else { row.pid };
        if row_tgid != tgid {
            continue;
        }

        threads += 1;
        let is_hot = row.runs_per_sec >= 10.0 || row.pelt_util > 0;
        if is_hot {
            hot_threads += 1;
            max_hot_start_us = max_hot_start_us.max(row.startup_latency_us);
        }
        run_rate += row.runs_per_sec;
        max_wait_us = max_wait_us.max(row.wait_duration_ns / 1000);
        max_gap_us = max_gap_us.max(row.max_dispatch_gap_us);
        max_start_us = max_start_us.max(row.startup_latency_us);
        match row.startup_first_phase {
            STARTUP_PHASE_ENQUEUE => enqueue_first += 1,
            STARTUP_PHASE_SELECT => select_first += 1,
            STARTUP_PHASE_RUNNING => running_first += 1,
            _ => {}
        }
        if row.startup_phase_mask
            & (STARTUP_MASK_ENQUEUE | STARTUP_MASK_SELECT | STARTUP_MASK_RUNNING)
            == (STARTUP_MASK_ENQUEUE | STARTUP_MASK_SELECT | STARTUP_MASK_RUNNING)
        {
            full_startup_phase += 1;
        }

        let nr_cpus = app.topology.nr_cpus.min(crate::topology::MAX_CPUS);
        for (cpu, seen) in cpu_seen.iter_mut().enumerate().take(nr_cpus) {
            let samples = row.cpu_run_count[cpu] as u64;
            if samples == 0 {
                continue;
            }
            *seen = true;
            let core = app.topology.cpu_core_id[cpu] as usize;
            if core < crate::topology::MAX_CORES {
                core_seen[core] = true;
            }
            run_samples += samples;
            if is_secondary_smt_cpu(&app.topology, cpu) {
                smt_samples += samples;
            }
        }
    }

    let active_cpus = cpu_seen.iter().filter(|seen| **seen).count();
    let active_cores = core_seen.iter().filter(|seen| **seen).count();
    format!(
        "health run/s={:.1} hot_threads={}/{} wait={}us gap={} lifecycle_run_max_us[hot/all]={}/{} lifecycle_first[e/s/r]={}/{}/{} lifecycle_full={}/{} spread={}/{} smt={:.0}%",
        run_rate,
        hot_threads,
        threads,
        max_wait_us,
        display_gap_us(max_gap_us),
        max_hot_start_us,
        max_start_us,
        enqueue_first,
        select_first,
        running_first,
        full_startup_phase,
        threads,
        active_cpus,
        active_cores,
        pct(smt_samples, run_samples),
    )
}

fn append_cpu_work_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    topology: &TopologyInfo,
    cpu_stats: &[(f32, f32)],
    elapsed: Duration,
) {
    let cpu_rows = scheduler_cpu_rows(counters, topology, cpu_stats, elapsed);
    let core_rows = scheduler_core_rows(counters, topology, cpu_stats, elapsed);
    let active_cpu_count = counters
        .iter()
        .filter(|counter| counter.task_runtime_ns > 0 || counter.task_run_count > 0)
        .count();
    let active_core_count = core_rows
        .iter()
        .filter(|row| row.total_runtime_ns > 0 || row.runs > 0)
        .count();
    let total_runtime_ns: u64 = counters.iter().map(|counter| counter.task_runtime_ns).sum();
    let total_runs: u64 = counters.iter().map(|counter| counter.task_run_count).sum();
    let smt_solo_runtime_ns: u64 = counters
        .iter()
        .map(|counter| counter.smt_solo_runtime_ns)
        .sum();
    let smt_contended_runtime_ns: u64 = counters
        .iter()
        .map(|counter| counter.smt_contended_runtime_ns)
        .sum();
    let smt_overlap_runtime_ns: u64 = counters
        .iter()
        .map(|counter| counter.smt_overlap_runtime_ns)
        .sum();
    let smt_solo_runs: u64 = counters
        .iter()
        .map(|counter| counter.smt_solo_run_count)
        .sum();
    let smt_contended_runs: u64 = counters
        .iter()
        .map(|counter| counter.smt_contended_run_count)
        .sum();
    let smt_active_start: u64 = counters
        .iter()
        .map(|counter| counter.smt_sibling_active_start_count)
        .sum();
    let smt_active_stop: u64 = counters
        .iter()
        .map(|counter| counter.smt_sibling_active_stop_count)
        .sum();
    let smt_wait_ns = [
        counters
            .iter()
            .map(|counter| counter.smt_wake_wait_ns[0])
            .sum::<u64>(),
        counters
            .iter()
            .map(|counter| counter.smt_wake_wait_ns[1])
            .sum::<u64>(),
    ];
    let smt_wait_count = [
        counters
            .iter()
            .map(|counter| counter.smt_wake_wait_count[0])
            .sum::<u64>(),
        counters
            .iter()
            .map(|counter| counter.smt_wake_wait_count[1])
            .sum::<u64>(),
    ];
    let smt_runtime_ns = smt_solo_runtime_ns + smt_contended_runtime_ns;
    let smt_runs = smt_solo_runs + smt_contended_runs;
    let top_cpu = cpu_rows
        .first()
        .map(|row| format!("C{:02} {:.1}%", row.cpu, row.share_pct))
        .unwrap_or_else(|| "-".to_string());
    let top_core = core_rows
        .first()
        .map(|row| format!("K{:02} {:.1}%", row.core, row.share_pct))
        .unwrap_or_else(|| "-".to_string());

    output.push_str(&format!(
        "{}: sampled={:.1}s active_cpu={}/{} active_core={}/{} runtime_ms={} runs={} top_cpu_cake={} top_core_cake={} skew={:.1}x\n",
        label,
        elapsed.as_secs_f64(),
        active_cpu_count,
        counters.len(),
        active_core_count,
        topology.nr_phys_cpus,
        format_runtime_ms(total_runtime_ns),
        total_runs,
        top_cpu,
        top_core,
        scheduler_balance_ratio(counters),
    ));
    output.push_str(&format!(
        "{}.smt: runtime_contended={:.1}% overlap={:.1}% runs_contended={:.1}% active_start={} active_stop={} avg_run_us[s/c]={}/{} wake_avg_us[s/c]={}/{}\n",
        label,
        pct(smt_contended_runtime_ns, smt_runtime_ns),
        pct(smt_overlap_runtime_ns, smt_runtime_ns),
        pct(smt_contended_runs, smt_runs),
        smt_active_start,
        smt_active_stop,
        avg_ns(smt_solo_runtime_ns, smt_solo_runs) / 1000,
        avg_ns(smt_contended_runtime_ns, smt_contended_runs) / 1000,
        avg_ns(smt_wait_ns[0], smt_wait_count[0]) / 1000,
        avg_ns(smt_wait_ns[1], smt_wait_count[1]) / 1000,
    ));
    output.push_str(&format!(
        "{}.legend: cake=tracked runtime share sys=system cpu load hot_thr=share on the busier sibling sib=share on the SMT sibling smt%=runtime with observed sibling overlap ov%=estimated overlap q%[f/b/p]=quantum full/blocked/preempt mix\n",
        label
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in &cpu_rows {
        output.push_str(&format!(
            "  cpu=C{:02} core={} llc={} thr={} cake={:.1}% runs={} runs/s={:.1} runtime_ms={} avg_run_us={} smt%={:.0} ov%={:.0} cavg_us={} wait_us[s/c]={}/{} q%[f/b/p]={:.0}/{:.0}/{:.0} q[f/b/p]={}/{}/{} sys={:.0}% temp={:.0}C\n",
            row.cpu,
            row.core,
            row.llc,
            if row.is_secondary_smt { "smt2" } else { "prim" },
            row.share_pct,
            row.runs,
            row.runs_per_sec,
            format_runtime_ms(row.total_runtime_ns),
            row.avg_run_us,
            row.smt_contended_pct,
            row.smt_overlap_pct,
            row.smt_contended_avg_run_us,
            row.smt_wait_solo_us,
            row.smt_wait_contended_us,
            row.full_pct,
            row.yield_pct,
            row.preempt_pct,
            counters[row.cpu].quantum_full,
            counters[row.cpu].quantum_yield,
            counters[row.cpu].quantum_preempt,
            row.system_load,
            row.temp_c,
        ));
    }
    output.push_str(&format!("{}.cores:\n", label));
    for row in &core_rows {
        output.push_str(&format!(
            "  core=K{:02} cpus={} cake={:.1}% runs={} runs/s={:.1} runtime_ms={} avg_run_us={} smt_ov%={:.0} primary_cont%={:.0} smt_cont%={:.0} p_impact={:.2} wait_us[s/c]={}/{} q%[f/b/p]={:.0}/{:.0}/{:.0} hot_thr={:.0}% sib={:.0}% sys={:.0}%\n",
            row.core,
            row.cpu_label,
            row.share_pct,
            row.runs,
            row.runs_per_sec,
            format_runtime_ms(row.total_runtime_ns),
            row.avg_run_us,
            row.smt_overlap_pct,
            row.primary_contended_pct,
            row.secondary_contended_pct,
            row.primary_smt_impact,
            row.smt_wait_solo_us,
            row.smt_wait_contended_us,
            row.full_pct,
            row.yield_pct,
            row.preempt_pct,
            row.top_cpu_share_pct,
            row.secondary_smt_pct,
            row.avg_system_load,
        ));
    }
}

fn append_long_run_owner_section(
    output: &mut String,
    label: &str,
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
) {
    let rows = build_long_run_owner_rows(app, tgid_roles, usize::MAX);
    let total_runtime_ns: u64 = app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row))
        .map(|row| row.total_runtime_ns)
        .sum();
    output.push_str(&format!(
        "{}: owners={} total_runtime_ms={} source=task_total_runtime place=top_run_residency share=tracked_task_runtime\n",
        label,
        rows.len(),
        format_runtime_ms(total_runtime_ns),
    ));
    if rows.is_empty() {
        return;
    }

    output.push_str(&format!("{}.top:\n", label));
    for row in rows.iter().take(16) {
        output.push_str(&format!(
            "  pid={} tgid={} ppid={} comm={} role={} util_pct={:.1} cpu={} core={} spread={}/{} smt2={} allowed={} home={} score={} hbusy={:.1}% hchg={} tsmt={:.1}%/{:.1}% behind=max{}us/n{} runtime_ms={} share={:.1}% rt_ms_s={:.1} runs={} run_s={:.1} avg_run_us={} max_run_us={}\n",
            row.pid,
            row.tgid,
            row.ppid,
            row.comm,
            row.role.label(),
            pelt_util_pct(row.pelt_util as u64),
            cpu_owner_label(row),
            core_owner_label(row),
            row.active_cpu_count,
            row.active_core_count,
            row.smt_secondary_pct,
            row.allowed_cpus,
            if row.home_cpu == 0xff {
                "-".to_string()
            } else {
                format!("C{:02}", row.home_cpu)
            },
            row.home_score,
            row.home_busy_pct,
            row.home_change_count,
            row.smt_contended_pct,
            row.smt_overlap_pct,
            row.blocked_wait_max_us,
            row.blocked_count,
            format_runtime_ms(row.total_runtime_ns),
            row.runtime_share_pct,
            row.runtime_ns_per_sec / 1_000_000.0,
            row.runs,
            row.runs_per_sec,
            row.avg_run_us,
            display_runtime_us(row.max_runtime_us),
        ));
    }

    let mut by_cpu: HashMap<usize, Vec<&LongRunOwnerRow>> = HashMap::new();
    let mut by_core: HashMap<usize, Vec<&LongRunOwnerRow>> = HashMap::new();
    for row in &rows {
        if let Some(cpu) = row.top_cpu {
            by_cpu.entry(cpu).or_default().push(row);
        }
        if let Some(core) = row.top_core {
            by_core.entry(core).or_default().push(row);
        }
    }

    let mut cpu_heads: Vec<(usize, &LongRunOwnerRow)> = by_cpu
        .iter_mut()
        .filter_map(|(cpu, owners)| {
            owners.sort_by(|a, b| {
                b.total_runtime_ns
                    .cmp(&a.total_runtime_ns)
                    .then_with(|| a.pid.cmp(&b.pid))
            });
            owners.first().copied().map(|owner| (*cpu, owner))
        })
        .collect();
    cpu_heads.sort_by(|a, b| {
        b.1.total_runtime_ns
            .cmp(&a.1.total_runtime_ns)
            .then_with(|| a.0.cmp(&b.0))
    });
    output.push_str(&format!("{}.cpu:\n", label));
    for (cpu, owner) in cpu_heads.iter().take(8) {
        output.push_str(&format!(
            "  cpu=C{:02} owner={} pid={} role={} runtime_ms={} share={:.1}% res={} allowed={} home_score={} hbusy={:.1}% tsmt={:.1}% avg_run_us={} max_run_us={} run_s={:.1}\n",
            cpu,
            owner.comm,
            owner.pid,
            owner.role.label(),
            format_runtime_ms(owner.total_runtime_ns),
            owner.runtime_share_pct,
            cpu_owner_label(owner),
            owner.allowed_cpus,
            owner.home_score,
            owner.home_busy_pct,
            owner.smt_contended_pct,
            owner.avg_run_us,
            display_runtime_us(owner.max_runtime_us),
            owner.runs_per_sec,
        ));
    }

    let mut core_heads: Vec<(usize, &LongRunOwnerRow)> = by_core
        .iter_mut()
        .filter_map(|(core, owners)| {
            owners.sort_by(|a, b| {
                b.total_runtime_ns
                    .cmp(&a.total_runtime_ns)
                    .then_with(|| a.pid.cmp(&b.pid))
            });
            owners.first().copied().map(|owner| (*core, owner))
        })
        .collect();
    core_heads.sort_by(|a, b| {
        b.1.total_runtime_ns
            .cmp(&a.1.total_runtime_ns)
            .then_with(|| a.0.cmp(&b.0))
    });
    output.push_str(&format!("{}.core:\n", label));
    for (core, owner) in core_heads.iter().take(8) {
        output.push_str(&format!(
            "  core=K{:02} owner={} pid={} role={} runtime_ms={} share={:.1}% res={} allowed={} home_score={} hbusy={:.1}% tsmt={:.1}% avg_run_us={} max_run_us={} run_s={:.1}\n",
            core,
            owner.comm,
            owner.pid,
            owner.role.label(),
            format_runtime_ms(owner.total_runtime_ns),
            owner.runtime_share_pct,
            core_owner_label(owner),
            owner.allowed_cpus,
            owner.home_score,
            owner.home_busy_pct,
            owner.smt_contended_pct,
            owner.avg_run_us,
            display_runtime_us(owner.max_runtime_us),
            owner.runs_per_sec,
        ));
    }
}

pub(super) fn build_app_health_rows(
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
) -> Vec<AppHealthRow> {
    let mut rows: HashMap<u32, AppHealthRow> = HashMap::new();
    let nr_cpus = app.topology.nr_cpus.max(1) as u16;
    let identities = build_tgid_identities(app);

    for row in app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row))
    {
        let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
        let role = task_role(row, tgid_roles);
        let identity = identities
            .get(&tgid)
            .cloned()
            .unwrap_or_else(|| fallback_tgid_identity(tgid, row));
        let entry = rows.entry(tgid).or_insert_with(|| AppHealthRow {
            tgid,
            comm: identity.app_comm.clone(),
            leader_comm: identity.leader_comm.clone(),
            dominant_runtime_comm: identity.dominant_runtime_comm.clone(),
            dominant_runtime_ns: identity.dominant_runtime_ns,
            dominant_thread_comm: identity.dominant_thread_comm.clone(),
            dominant_thread_count: identity.dominant_thread_count,
            comm_kinds: identity.comm_kinds,
            role,
            min_allowed_cpus: nr_cpus,
            ..Default::default()
        });

        entry.role = tgid_roles.get(&tgid).copied().unwrap_or(role);
        entry.tasks += 1;
        if row.pelt_util >= 128 || row.runtime_ns_per_sec >= 10_000_000.0 {
            entry.hot_tasks += 1;
        }
        entry.pelt_max = entry.pelt_max.max(row.pelt_util);
        entry.runtime_ns += row.total_runtime_ns;
        entry.runtime_ns_per_sec += row.runtime_ns_per_sec;
        entry.runs_per_sec += row.runs_per_sec;
        entry.runs += row.total_runs as u64;
        entry.migrations_per_sec += row.migrations_per_sec;
        entry.quantum_full += row.quantum_full_count;
        entry.quantum_yield += row.quantum_yield_count;
        entry.quantum_preempt += row.quantum_preempt_count;
        entry.yield_count += row.yield_count as u64;
        entry.max_runtime_us = entry.max_runtime_us.max(row.max_runtime_us);
        entry.smt_contended_runtime_ns += row.smt_contended_runtime_ns;
        entry.smt_overlap_runtime_ns += row.smt_overlap_runtime_ns;
        entry.blocked_count += row.blocked_count as u64;
        entry.blocked_wait_max_us = entry.blocked_wait_max_us.max(row.blocked_wait_max_us);

        let allowed = if row.allowed_cpus == 0 {
            nr_cpus
        } else {
            row.allowed_cpus
        };
        entry.min_allowed_cpus = entry.min_allowed_cpus.min(allowed);
        entry.max_allowed_cpus = entry.max_allowed_cpus.max(allowed);
        if allowed < nr_cpus {
            entry.restricted_tasks += 1;
        }

        let placement = placement_summary(row, &app.topology);
        let top_cpu_pct = placement
            .top_cpu
            .map(|(_, count)| (count * 100) / placement.total_samples.max(1))
            .unwrap_or(0);
        let quantum_total =
            row.quantum_full_count + row.quantum_yield_count + row.quantum_preempt_count;
        let full_pct = pct(row.quantum_full_count, quantum_total);
        if allowed > 1
            && placement.active_cpu_count <= 1
            && top_cpu_pct >= 90
            && row.pelt_util >= 512
            && full_pct >= 50.0
        {
            entry.sticky_hogs += 1;
        }
    }

    for counter in &app.per_cpu_work {
        if counter.blocked_owner_wait_count == 0 || counter.blocked_waiter_pid == 0 {
            continue;
        }
        let Some(waiter) = app.task_rows.get(&counter.blocked_waiter_pid) else {
            continue;
        };
        let tgid = if waiter.tgid > 0 {
            waiter.tgid
        } else {
            waiter.pid
        };
        if let Some(entry) = rows.get_mut(&tgid) {
            entry.blocked_count += counter.blocked_owner_wait_count;
            entry.blocked_wait_max_us = entry
                .blocked_wait_max_us
                .max((counter.blocked_owner_wait_max_ns / 1000).min(u32::MAX as u64) as u32);
        }
    }

    for edge in &app.wake_edges {
        if edge.waker_tgid == 0 || edge.wakee_tgid == 0 {
            continue;
        }
        if edge.waker_tgid == edge.wakee_tgid {
            if let Some(row) = rows.get_mut(&edge.wakee_tgid) {
                row.wake_self += edge.wake_count;
                row.wait_self_ns += edge.wait_ns;
                row.wait_self_count += edge.wait_count;
                row.wait_self_max_ns = row.wait_self_max_ns.max(edge.wait_max_ns);
            }
        } else {
            if let Some(row) = rows.get_mut(&edge.wakee_tgid) {
                row.wake_in += edge.wake_count;
                row.wait_self_ns += edge.wait_ns;
                row.wait_self_count += edge.wait_count;
                row.wait_self_max_ns = row.wait_self_max_ns.max(edge.wait_max_ns);
            }
            if let Some(row) = rows.get_mut(&edge.waker_tgid) {
                row.wake_out += edge.wake_count;
                row.wait_out_ns += edge.wait_ns;
                row.wait_out_count += edge.wait_count;
                row.wait_out_max_ns = row.wait_out_max_ns.max(edge.wait_max_ns);
            }
        }
    }

    let mut out: Vec<AppHealthRow> = rows.into_values().collect();
    out.sort_by(|a, b| {
        b.runtime_ns
            .cmp(&a.runtime_ns)
            .then_with(|| b.pelt_max.cmp(&a.pelt_max))
            .then_with(|| a.tgid.cmp(&b.tgid))
    });
    out
}

fn append_app_health_section(
    output: &mut String,
    label: &str,
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
) {
    let rows = build_app_health_rows(app, tgid_roles);
    let total_runtime_ns: u64 = rows.iter().map(|row| row.runtime_ns).sum();
    let secs = app.start_time.elapsed().as_secs_f64().max(0.1);
    output.push_str(&format!(
        "{}: apps={} total_runtime_ms={} source=task_rollup quantum=exact_u64/{}us wake=debug_bounded syld=debug_u16_sat\n",
        label,
        rows.len(),
        format_runtime_ms(total_runtime_ns),
        app.quantum_us,
    ));
    for row in rows.iter().take(16) {
        let quantum_total = row.quantum_full + row.quantum_yield + row.quantum_preempt;
        let avg_run_us = if row.runs > 0 {
            row.runtime_ns / row.runs / 1000
        } else {
            0
        };
        let avg_quantum_pct = if app.quantum_us > 0 {
            (avg_run_us as f64 * 100.0) / app.quantum_us as f64
        } else {
            0.0
        };
        let leader = if row.leader_comm.is_empty() || row.leader_comm == row.comm {
            "-"
        } else {
            row.leader_comm.as_str()
        };
        let dominant_runtime = if row.dominant_runtime_comm.is_empty() {
            "-"
        } else {
            row.dominant_runtime_comm.as_str()
        };
        let dominant_thread = if row.dominant_thread_comm.is_empty() {
            "-"
        } else {
            row.dominant_thread_comm.as_str()
        };
        output.push_str(&format!(
            "  tgid={} comm={} leader={} dom_rt={}:{:.0}% dom_active_threads={}:{}/{} active_comms={} role={} hot_tasks={}/{} pelt_max={} runtime_ms={} share={:.1}% rtms/s={:.1} run={} avg_run_us={} avg_run/q={:.1}% max_run_us={} syld={} q%[f/b/p]={:.0}/{:.0}/{:.0} q={}/{}/{} qps[f/b/p]={:.1}/{:.1}/{:.1} aff[min/max/r]={}/{}/{} sticky_hogs={} mig/s={:.1} tsmt={:.1}%/{:.1}% blocked=max{}us/n{} wake[self/in/out]={}/{}/{} wait_self={}/{}us({}) wait_out={}/{}us({})\n",
            row.tgid,
            row.comm,
            leader,
            dominant_runtime,
            pct(row.dominant_runtime_ns, row.runtime_ns),
            dominant_thread,
            row.dominant_thread_count,
            row.tasks,
            row.comm_kinds,
            row.role.label(),
            row.hot_tasks,
            row.tasks,
            row.pelt_max,
            format_runtime_ms(row.runtime_ns),
            pct(row.runtime_ns, total_runtime_ns),
            row.runtime_ns_per_sec / 1_000_000.0,
            row.runs,
            avg_run_us,
            avg_quantum_pct,
            display_runtime_us(row.max_runtime_us),
            row.yield_count,
            pct(row.quantum_full, quantum_total),
            pct(row.quantum_yield, quantum_total),
            pct(row.quantum_preempt, quantum_total),
            row.quantum_full,
            row.quantum_yield,
            row.quantum_preempt,
            per_sec(row.quantum_full, secs),
            per_sec(row.quantum_yield, secs),
            per_sec(row.quantum_preempt, secs),
            row.min_allowed_cpus,
            row.max_allowed_cpus,
            row.restricted_tasks,
            row.sticky_hogs,
            row.migrations_per_sec,
            pct(row.smt_contended_runtime_ns, row.runtime_ns),
            pct(row.smt_overlap_runtime_ns, row.runtime_ns),
            row.blocked_wait_max_us,
            row.blocked_count,
            row.wake_self,
            row.wake_in,
            row.wake_out,
            avg_ns(row.wait_self_ns, row.wait_self_count) / 1000,
            row.wait_self_max_ns / 1000,
            row.wait_self_count,
            avg_ns(row.wait_out_ns, row.wait_out_count) / 1000,
            row.wait_out_max_ns / 1000,
            row.wait_out_count,
        ));
    }
}

fn append_focused_app_section(
    output: &mut String,
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
) {
    let Some(focused_tgid) = app.focused_tgid else {
        return;
    };
    let Some((row, total_runtime_ns)) = focused_app_with_total(app, tgid_roles) else {
        output.push_str(&format!(
            "focus: tgid={} state=stale reason=no_live_bpf_rows\n",
            focused_tgid
        ));
        return;
    };

    let (state, _) = app_health_state(&row);
    let quantum_total = row.quantum_full + row.quantum_yield + row.quantum_preempt;
    let avg_run_us = if row.runs > 0 {
        row.runtime_ns / row.runs / 1000
    } else {
        0
    };
    output.push_str(&format!(
        "focus: tgid={} comm={} state={} role={} tasks={}/{} runtime_ms={} share={:.1}% rtms/s={:.1} run/s={:.1} avg_run_us={} max_run_us={} syld={} wait_self={}/{}us({}) q%[f/b/p]={:.0}/{:.0}/{:.0} smt={:.1}%/{:.1}% wake[self/in/out]={}/{}/{} blocked=max{}us/n{} cpus={} cores={}\n",
        row.tgid,
        row.comm,
        state,
        row.role.label(),
        row.hot_tasks,
        row.tasks,
        format_runtime_ms(row.runtime_ns),
        pct(row.runtime_ns, total_runtime_ns),
        row.runtime_ns_per_sec / 1_000_000.0,
        row.runs_per_sec,
        avg_run_us,
        display_runtime_us(row.max_runtime_us),
        row.yield_count,
        avg_ns(row.wait_self_ns, row.wait_self_count) / 1000,
        row.wait_self_max_ns / 1000,
        row.wait_self_count,
        pct(row.quantum_full, quantum_total),
        pct(row.quantum_yield, quantum_total),
        pct(row.quantum_preempt, quantum_total),
        pct(row.smt_contended_runtime_ns, row.runtime_ns),
        pct(row.smt_overlap_runtime_ns, row.runtime_ns),
        row.wake_self,
        row.wake_in,
        row.wake_out,
        row.blocked_wait_max_us,
        row.blocked_count,
        app_cpu_distribution_label(app, row.tgid, 6),
        app_core_distribution_label(app, row.tgid, 6),
    ));

    let tasks = app_task_rows(app, row.tgid);
    let pids: Vec<u32> = tasks.iter().map(|task| task.pid).collect();
    output.push_str(&format!(
        "focus.startup: {}\n",
        format_tgid_health_summary(app, row.tgid, &pids)
    ));
    if let Some(wake_graph) = format_tgid_wake_graph(app, row.tgid) {
        output.push_str(&format!("focus.wakegraph: {}\n", wake_graph));
    }
    output.push_str("focus.threads:\n");
    for task in tasks.iter().take(10) {
        let placement = placement_summary(task, &app.topology);
        let task_quantum_total =
            task.quantum_full_count + task.quantum_yield_count + task.quantum_preempt_count;
        output.push_str(&format!(
            "  pid={} comm={} role={} util_pct={:.1} rtms/s={:.1} run/s={:.1} avg/max_us={}/{} wait={}us blocked=max{}us q%[f/b/p]={:.0}/{:.0}/{:.0} place={}/{} res={} smt={:.1}%\n",
            task.pid,
            task.comm,
            task_role(task, tgid_roles).label(),
            pelt_util_pct(task.pelt_util as u64),
            runtime_rate_ms(task),
            task.runs_per_sec,
            avg_task_runtime_us(task),
            display_runtime_us(task.max_runtime_us),
            task.wait_duration_ns / 1000,
            task.blocked_wait_max_us,
            pct(task.quantum_full_count, task_quantum_total),
            pct(task.quantum_yield_count, task_quantum_total),
            pct(task.quantum_preempt_count, task_quantum_total),
            placement.active_cpu_count,
            placement.active_core_count,
            placement_residency_label(&placement),
            task_smt_contended_pct(task),
        ));
    }
}

#[cfg(debug_assertions)]
fn append_wake_chain_section(output: &mut String, app: &TuiApp) {
    use crate::task_anatomy::{
        derive_task_anatomy, derive_wake_chain_score, wake_chain_decay_labels,
        wake_chain_reason_labels, WAKE_CHAIN_DECAY_FULL_QUANTUM, WAKE_CHAIN_DECAY_LONG_RUN,
        WAKE_CHAIN_DECAY_LOW_ACTIVITY, WAKE_CHAIN_REASON_BLOCKS_EARLY,
        WAKE_CHAIN_REASON_LATENCY_PRIO, WAKE_CHAIN_REASON_MIGRATION_PAIN,
        WAKE_CHAIN_REASON_SHORT_RUN, WAKE_CHAIN_REASON_SMT_PAIN, WAKE_CHAIN_REASON_WAIT_TAIL,
        WAKE_CHAIN_REASON_WAKE_DENSE, WAKE_CHAIN_SCORE_HIGH,
    };

    let mut rows: Vec<(&TaskTelemetryRow, crate::task_anatomy::WakeChainScore)> = app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row))
        .map(|row| {
            let input = task_anatomy_input_from_row(row, app.topology.nr_cpus as u16);
            (row, derive_wake_chain_score(&input))
        })
        .collect();

    let mut buckets = [0u32; 16];
    let mut reason_counts = [0u32; 7];
    let mut decay_counts = [0u32; 3];
    let mut high_count = 0u32;
    let mut total_score = 0u64;

    for (_, score) in &rows {
        let idx = usize::from(score.score.min(15));
        buckets[idx] += 1;
        total_score += u64::from(score.score);
        if score.score >= WAKE_CHAIN_SCORE_HIGH {
            high_count += 1;
        }
        for (slot, bit) in [
            WAKE_CHAIN_REASON_SHORT_RUN,
            WAKE_CHAIN_REASON_WAKE_DENSE,
            WAKE_CHAIN_REASON_BLOCKS_EARLY,
            WAKE_CHAIN_REASON_WAIT_TAIL,
            WAKE_CHAIN_REASON_MIGRATION_PAIN,
            WAKE_CHAIN_REASON_SMT_PAIN,
            WAKE_CHAIN_REASON_LATENCY_PRIO,
        ]
        .iter()
        .enumerate()
        {
            if score.reason_mask & bit != 0 {
                reason_counts[slot] += 1;
            }
        }
        for (slot, bit) in [
            WAKE_CHAIN_DECAY_FULL_QUANTUM,
            WAKE_CHAIN_DECAY_LONG_RUN,
            WAKE_CHAIN_DECAY_LOW_ACTIVITY,
        ]
        .iter()
        .enumerate()
        {
            if score.decay_mask & bit != 0 {
                decay_counts[slot] += 1;
            }
        }
    }

    let avg_score = if rows.is_empty() {
        0.0
    } else {
        total_score as f64 / rows.len() as f64
    };
    let bucket_text = buckets
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(score, count)| format!("{}={}", score, count))
        .collect::<Vec<_>>()
        .join(" ");

    output.push_str(&format!(
        "wake.chain: source=debug_derived policy_effect=bpf_locality_guard candidates={} high={} threshold={} avg_score={:.1} reasons=[short_run={} wake_dense={} blocks_early={} wait_tail={} migration_pain={} smt_pain={} latency_prio={}] decay=[full_quantum={} long_run={} low_activity={}] buckets=[{}]\n",
        rows.len(),
        high_count,
        WAKE_CHAIN_SCORE_HIGH,
        avg_score,
        reason_counts[0],
        reason_counts[1],
        reason_counts[2],
        reason_counts[3],
        reason_counts[4],
        reason_counts[5],
        reason_counts[6],
        decay_counts[0],
        decay_counts[1],
        decay_counts[2],
        if bucket_text.is_empty() { "-".to_string() } else { bucket_text },
    ));

    rows.sort_by(|(a, a_score), (b, b_score)| {
        b_score
            .score
            .cmp(&a_score.score)
            .then_with(|| b.total_runtime_ns.cmp(&a.total_runtime_ns))
            .then_with(|| b.total_runs.cmp(&a.total_runs))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    output.push_str("wake.chain.top:\n");
    for (row, score) in rows.iter().filter(|(_, score)| score.score > 0).take(24) {
        let input = task_anatomy_input_from_row(row, app.topology.nr_cpus as u16);
        let anatomy = derive_task_anatomy(&input, None);
        output.push_str(&format!(
            "  pid={} tgid={} comm={} chain={} policy_score={} reasons={} decay={} risk={} rtms/s={:.1} runs/s={:.1} avg_run_us={} wait_us={} mig/s={:.1} smt={:.1}% place={} path={}\n",
            row.pid,
            row.tgid,
            row.comm,
            score.score,
            row.wake_chain_policy_score,
            wake_chain_reason_labels(score.reason_mask),
            wake_chain_decay_labels(score.decay_mask),
            anatomy.risk_label(),
            runtime_rate_ms(row),
            row.runs_per_sec,
            avg_task_runtime_us(row),
            row.wait_duration_ns / 1000,
            row.migrations_per_sec,
            task_smt_contended_pct(row),
            row.last_place_class,
            row.last_select_path,
        ));
    }
}

#[cfg(debug_assertions)]
fn row_proc_source_label(row: &TaskTelemetryRow) -> &'static str {
    match (row.proc_snapshot_seen, row.proc_schedstat_seen) {
        (true, true) => "proc+schedstat",
        (true, false) => "proc",
        (false, true) => "schedstat",
        (false, false) => "missing",
    }
}

#[cfg(debug_assertions)]
fn append_task_anatomy_section(output: &mut String, app: &TuiApp) {
    use crate::task_anatomy::{derive_task_anatomy, lane_labels, shape_labels};

    let mut rows: Vec<&TaskTelemetryRow> = app
        .task_rows
        .values()
        .filter(|row| row_has_bpf_matrix_data(row))
        .collect();
    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| b.total_runs.cmp(&a.total_runs))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    let proc_rows = rows.iter().filter(|row| row.proc_snapshot_seen).count();
    let schedstat_rows = rows.iter().filter(|row| row.proc_schedstat_seen).count();
    let missing_rows = rows
        .iter()
        .filter(|row| !row.proc_snapshot_seen && !row.proc_schedstat_seen)
        .count();
    output.push_str(&format!(
        "task.anatomy: source=debug_derived labels=candidate raw_source=bpf_iter proc_source=mixed proc_rows={} schedstat_rows={} missing_rows={}\n",
        proc_rows, schedstat_rows, missing_rows,
    ));
    for row in rows.iter().take(32) {
        let input = task_anatomy_input_from_row(row, app.topology.nr_cpus as u16);
        let anatomy = derive_task_anatomy(&input, None);
        output.push_str(&format!(
            "  pid={} tgid={} comm={} policy={} prio={}/{}/{} user={} kthread={} aff={}/{} shape={} lane_candidate={} risk={} raw_source=bpf_iter shape_source=derived lane_source={} proc_source={}\n",
            row.pid,
            row.tgid,
            row.comm,
            row.task_policy,
            row.task_prio,
            row.task_static_prio,
            row.task_normal_prio,
            row.task_has_mm as u8,
            row.task_is_kthread as u8,
            row.allowed_cpus,
            app.topology.nr_cpus,
            shape_labels(&anatomy),
            lane_labels(&anatomy),
            anatomy.risk_label(),
            anatomy.lane_source.label(),
            row_proc_source_label(row),
        ));
    }
}

#[cfg(debug_assertions)]
fn append_gaming_qos_section(output: &mut String, app: &TuiApp) {
    use crate::task_anatomy::{
        derive_task_anatomy, LANE_INPUT, LANE_NETWORK, LANE_RENDER_FRAME, LANE_SHADER_IO,
        LANE_THROUGHPUT,
    };

    let mut input_count = 0u32;
    let mut render_count = 0u32;
    let mut network_count = 0u32;
    let mut shader_io_count = 0u32;
    let mut throughput_count = 0u32;
    let mut input_wait_risk = 0u32;
    let mut input_gap_lifetime = 0u32;
    let mut input_gap_5_50ms = 0u32;
    let mut input_gap_50_100ms = 0u32;
    let mut input_gap_100ms_plus = 0u32;
    let mut input_gap_sleep = 0u32;

    for row in app
        .task_rows
        .values()
        .filter(|row| row_has_bpf_matrix_data(row))
    {
        let input = task_anatomy_input_from_row(row, app.topology.nr_cpus as u16);
        let anatomy = derive_task_anatomy(&input, None);
        if anatomy.has_lane(LANE_INPUT) {
            input_count += 1;
            if row.wait_duration_ns / 1000 >= 1000 {
                input_wait_risk += 1;
            }
            if row.max_dispatch_gap_us >= 5000 {
                input_gap_lifetime += 1;
                if row.max_dispatch_gap_us > 1_000_000 {
                    input_gap_sleep += 1;
                } else if row.max_dispatch_gap_us >= 100_000 {
                    input_gap_100ms_plus += 1;
                } else if row.max_dispatch_gap_us >= 50_000 {
                    input_gap_50_100ms += 1;
                } else {
                    input_gap_5_50ms += 1;
                }
            }
        }
        if anatomy.has_lane(LANE_RENDER_FRAME) {
            render_count += 1;
        }
        if anatomy.has_lane(LANE_NETWORK) {
            network_count += 1;
        }
        if anatomy.has_lane(LANE_SHADER_IO) {
            shader_io_count += 1;
        }
        if anatomy.has_lane(LANE_THROUGHPUT) {
            throughput_count += 1;
        }
    }

    let input_state = if input_count == 0 {
        "unknown"
    } else if input_wait_risk == 0 {
        "clear"
    } else {
        "watch"
    };

    output.push_str(&format!(
        "gaming.qos: source=scheduler_telemetry benchmark=external_only labels=candidate input_latency={} input_candidates={} input_wait_risk={} input_gap_lifetime={} input_gap_5_50ms={} input_gap_50_100ms={} input_gap_100ms_plus={} input_gap_sleep={} render_candidates={} network_candidates={} shader_io_candidates={} throughput_candidates={}\n",
        input_state,
        input_count,
        input_wait_risk,
        input_gap_lifetime,
        input_gap_5_50ms,
        input_gap_50_100ms,
        input_gap_100ms_plus,
        input_gap_sleep,
        render_count,
        network_count,
        shader_io_count,
        throughput_count,
    ));
}

#[cfg(debug_assertions)]
fn strict_busy_preempt_decision(wakee_class: u8, owner_class: u8, target_pressure: u8) -> usize {
    if wakee_class == crate::task_anatomy::STRICT_WAKE_CLASS_SHIELD
        || owner_class == crate::task_anatomy::STRICT_WAKE_CLASS_CONTAIN
        || target_pressure >= 64
    {
        BUSY_PREEMPT_SHADOW_ALLOW
    } else {
        BUSY_PREEMPT_SHADOW_SKIP
    }
}

#[cfg(debug_assertions)]
fn derive_strict_wake_policy_snapshot(app: &TuiApp) -> DerivedStrictWakePolicy {
    use crate::task_anatomy::derive_strict_wake_policy;

    let mut derived = DerivedStrictWakePolicy::default();
    let mut class_by_pid: HashMap<u32, u8> = HashMap::new();

    let mut rows: Vec<&TaskTelemetryRow> = app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row))
        .collect();
    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| b.total_runs.cmp(&a.total_runs))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    for row in rows {
        let input = strict_wake_policy_input_from_row(row);
        let decision = derive_strict_wake_policy(&input);
        let class = decision.class as usize;
        if class >= WAKE_CLASS_MAX {
            continue;
        }

        derived.source_rows = derived.source_rows.saturating_add(1);
        derived.class_sample_count[class] = derived.class_sample_count[class].saturating_add(1);
        class_by_pid.insert(row.pid, decision.class);

        for reason in 0..WAKE_CLASS_REASON_MAX {
            if decision.reason_mask & (1u32 << reason) != 0 {
                derived.reason_count[reason] = derived.reason_count[reason].saturating_add(1);
            }
        }

        let mut saw_wait_sample = false;
        for idx in 0..row.wake_reason_count.len() {
            let count = row.wake_reason_count[idx] as u64;
            if count == 0 {
                continue;
            }
            saw_wait_sample = true;
            let wait_ns = row.wake_reason_wait_ns[idx];
            let max_ns = row.wake_reason_max_us[idx] as u64 * 1000;
            derived.wait_ns[class] = derived.wait_ns[class].saturating_add(wait_ns);
            derived.wait_count[class] = derived.wait_count[class].saturating_add(count);
            derived.wait_max_ns[class] = derived.wait_max_ns[class].max(max_ns);
            let avg_ns = if count > 0 { wait_ns / count } else { 0 };
            let bucket = wake_bucket_index(avg_ns.max(max_ns));
            derived.bucket_count[class][bucket] =
                derived.bucket_count[class][bucket].saturating_add(count);
        }

        if !saw_wait_sample && row.wait_duration_ns > 0 {
            derived.wait_ns[class] = derived.wait_ns[class].saturating_add(row.wait_duration_ns);
            derived.wait_count[class] = derived.wait_count[class].saturating_add(1);
            derived.wait_max_ns[class] = derived.wait_max_ns[class].max(row.wait_duration_ns);
            let bucket = wake_bucket_index(row.wait_duration_ns);
            derived.bucket_count[class][bucket] =
                derived.bucket_count[class][bucket].saturating_add(1);
        }
    }

    for (cpu, counter) in app.per_cpu_work.iter().enumerate() {
        if counter.blocked_owner_wait_count == 0 || counter.blocked_waiter_pid == 0 {
            continue;
        }
        let samples = counter.blocked_owner_wait_count.max(1);
        let wakee_class = class_by_pid
            .get(&counter.blocked_waiter_pid)
            .copied()
            .unwrap_or(crate::task_anatomy::STRICT_WAKE_CLASS_NONE);
        let owner_class = class_by_pid
            .get(&counter.blocked_owner_pid)
            .copied()
            .unwrap_or(crate::task_anatomy::STRICT_WAKE_CLASS_NONE);
        let decision = strict_busy_preempt_decision(wakee_class, owner_class, counter.cpu_pressure);
        if decision < BUSY_PREEMPT_SHADOW_MAX {
            derived.busy_shadow_count[decision] =
                derived.busy_shadow_count[decision].saturating_add(samples);
        }

        let wakee_idx = wakee_class as usize;
        if wakee_idx < WAKE_CLASS_MAX {
            derived.busy_shadow_wakee_class_count[wakee_idx] =
                derived.busy_shadow_wakee_class_count[wakee_idx].saturating_add(samples);
        }
        let owner_idx = owner_class as usize;
        if owner_idx < WAKE_CLASS_MAX {
            derived.busy_shadow_owner_class_count[owner_idx] =
                derived.busy_shadow_owner_class_count[owner_idx].saturating_add(samples);
        }

        let wake_target_local = app
            .task_rows
            .get(&counter.blocked_waiter_pid)
            .map(|row| row.waker_cpu as usize == cpu)
            .unwrap_or(false);
        if wake_target_local {
            derived.busy_shadow_local = derived.busy_shadow_local.saturating_add(samples);
        } else {
            derived.busy_shadow_remote = derived.busy_shadow_remote.saturating_add(samples);
        }
    }

    derived
}

#[cfg(debug_assertions)]
fn append_debug_cost_section(output: &mut String, cost: crate::task_anatomy::DebugTelemetryCost) {
    output.push_str(&format!(
        "debug.cost: iter_read_us={} proc_refresh_us={} anatomy_derive_us={} render_us={} dump_us={} iter_rows={} proc_refreshes={} proc_cache_hits={}\n",
        cost.iter_read_us,
        cost.proc_refresh_us,
        cost.anatomy_derive_us,
        cost.render_us,
        cost.dump_us,
        cost.iter_rows,
        cost.proc_refreshes,
        cost.proc_cache_hits,
    ));
}

fn flight_wake_total(stats: &cake_stats) -> u64 {
    stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued
}

fn flight_wait_ge5ms(stats: &cake_stats) -> u64 {
    stats
        .wake_reason_bucket_count
        .iter()
        .skip(1)
        .map(|buckets| buckets[WAKE_BUCKET_MAX - 1])
        .sum()
}

fn flight_cb_ge10us(stats: &cake_stats) -> u64 {
    stats
        .callback_hist
        .iter()
        .map(|buckets| buckets[buckets.len() - 1])
        .sum()
}

fn flight_spike_score(sample: &TimelineSample) -> u64 {
    let stats = &sample.stats;
    let wait_tail = flight_wait_ge5ms(stats);
    let cb_tail = flight_cb_ge10us(stats);
    let queue_build = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let busy_wake = stats.nr_wakeup_dsq_fallback_busy + stats.nr_wakeup_busy_local_target;
    let load_pressure = if sample.system.cpu_load_max_pct >= 90.0 {
        ((sample.system.cpu_load_max_pct - 89.0) * 10.0) as u64
    } else {
        0
    };
    let thermal_pressure = if sample.system.cpu_temp_max_c >= 85.0 {
        ((sample.system.cpu_temp_max_c - 84.0) * 10.0) as u64
    } else {
        0
    };

    wait_tail.saturating_mul(10_000)
        + cb_tail.saturating_mul(1_000)
        + stats.nr_dispatch_misses.saturating_mul(500)
        + busy_wake.saturating_mul(100)
        + queue_build.saturating_mul(50)
        + load_pressure
        + thermal_pressure
}

fn flight_spike_reason(sample: &TimelineSample) -> &'static str {
    let stats = &sample.stats;
    if flight_wait_ge5ms(stats) > 0 {
        "wake_tail"
    } else if flight_cb_ge10us(stats) > 0 {
        "callback_tail"
    } else if stats.nr_dispatch_misses > 0 {
        "dispatch_miss"
    } else if stats.nr_dsq_queued > stats.nr_dsq_consumed {
        "queue_build"
    } else if stats.nr_wakeup_dsq_fallback_busy > 0 || stats.nr_wakeup_busy_local_target > 0 {
        "busy_wake"
    } else if sample.system.cpu_load_max_pct >= 90.0 {
        "cpu_load"
    } else if sample.system.cpu_temp_max_c >= 85.0 {
        "cpu_temp"
    } else {
        "mixed"
    }
}

fn flight_minute_rows(samples: &[TimelineSample]) -> Vec<FlightMinuteSummary> {
    let mut rows = Vec::new();
    let mut current_minute = None;
    let mut current = None;

    for sample in samples {
        let minute = sample.end_elapsed.as_secs() / 60;
        if current_minute != Some(minute) {
            if let Some(row) = current.take() {
                rows.push(row);
            }
            current_minute = Some(minute);
            current = Some(FlightMinuteSummary::new(sample));
        }
        if let Some(row) = &mut current {
            row.record(sample);
        }
    }

    if let Some(row) = current {
        rows.push(row);
    }
    rows
}

fn format_flight_minute_row(row: &FlightMinuteSummary) -> String {
    let path_total: u64 = row.path_count[1..SELECT_PATH_MAX].iter().sum();
    let quantum_total: u64 = row.quantum_count.iter().sum();
    let load_avg = if row.load_count > 0 {
        row.load_avg_sum / row.load_count as f32
    } else {
        0.0
    };
    let temp_avg = if row.temp_count > 0 {
        row.temp_avg_sum / row.temp_count as f32
    } else {
        0.0
    };
    let run_low = if row.run_rate_low.is_finite() {
        row.run_rate_low
    } else {
        0.0
    };

    format!(
        "  t+{}..{} span={:.0}s n={} run/s={:.1} low={:.1} wake/s={:.1} wait>=5ms={} cb>=10us={} miss/s={:.1} qnet={:+} load={:.0}/{:.0}%@{} temp={:.1}/{:.1}C@{} path%={:.0}/{:.0}/{:.0}/{:.0}/{:.0} slice%={:.0}/{:.0}/{:.0}",
        timeline_elapsed_label(row.start_elapsed),
        timeline_elapsed_label(row.end_elapsed),
        row.sample_secs,
        row.samples,
        per_sec(row.run_total, row.sample_secs),
        run_low,
        per_sec(row.wake_total, row.sample_secs),
        row.wait_ge5ms,
        row.cb_ge10us,
        per_sec(row.dispatch_misses, row.sample_secs),
        row.queue_net,
        load_avg,
        row.load_max_pct,
        timeline_cpu_label(row.load_hot_cpu),
        temp_avg,
        row.temp_max_c,
        timeline_cpu_label(row.temp_hot_cpu),
        pct(row.path_count[1], path_total),
        pct(row.path_count[2], path_total),
        pct(row.path_count[3], path_total),
        pct(row.path_count[4], path_total),
        pct(row.path_count[5], path_total),
        pct(row.quantum_count[0], quantum_total),
        pct(row.quantum_count[1], quantum_total),
        pct(row.quantum_count[2], quantum_total),
    )
}

fn format_flight_spike_row(score: u64, sample: &TimelineSample) -> String {
    let secs = sample.elapsed.as_secs_f64().max(0.1);
    let stats = &sample.stats;
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);

    format!(
        "  score={} t+{}..{} ago={:>4}..{:>4}s reason={} run/s={:.1} wake/s={:.1} wait>=5ms={} cb>=10us={} miss={} qnet={:+} load={:.0}/{:.0}%@{} temp={:.1}/{:.1}C@{}",
        score,
        timeline_elapsed_label(sample.start_elapsed),
        timeline_elapsed_label(sample.end_elapsed),
        sample.start_ago_secs,
        sample.end_ago_secs,
        flight_spike_reason(sample),
        per_sec(stats.nr_running_calls, secs),
        per_sec(flight_wake_total(stats), secs),
        flight_wait_ge5ms(stats),
        flight_cb_ge10us(stats),
        stats.nr_dispatch_misses,
        queue_net,
        sample.system.cpu_load_avg_pct,
        sample.system.cpu_load_max_pct,
        timeline_cpu_label(sample.system.cpu_load_hot_cpu),
        sample.system.cpu_temp_avg_c,
        sample.system.cpu_temp_max_c,
        timeline_cpu_label(sample.system.cpu_temp_hot_cpu),
    )
}

fn format_flight_second_row(sample: &TimelineSample) -> String {
    let secs = sample.elapsed.as_secs_f64().max(0.1);
    let stats = &sample.stats;
    let path_total: u64 = stats.select_path_count[1..SELECT_PATH_MAX].iter().sum();
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);

    format!(
        "  t+{}..{} run/s={:.1} wake/s={:.1} wait>=5ms={} cb>=10us={} miss={} qnet={:+} load={:.0}/{:.0}%@{} temp={:.1}/{:.1}C@{} path%={:.0}/{:.0}/{:.0}/{:.0}/{:.0} slice%={:.0}/{:.0}/{:.0}",
        timeline_elapsed_label(sample.start_elapsed),
        timeline_elapsed_label(sample.end_elapsed),
        per_sec(stats.nr_running_calls, secs),
        per_sec(flight_wake_total(stats), secs),
        flight_wait_ge5ms(stats),
        flight_cb_ge10us(stats),
        stats.nr_dispatch_misses,
        queue_net,
        sample.system.cpu_load_avg_pct,
        sample.system.cpu_load_max_pct,
        timeline_cpu_label(sample.system.cpu_load_hot_cpu),
        sample.system.cpu_temp_avg_c,
        sample.system.cpu_temp_max_c,
        timeline_cpu_label(sample.system.cpu_temp_hot_cpu),
        pct(stats.select_path_count[1], path_total),
        pct(stats.select_path_count[2], path_total),
        pct(stats.select_path_count[3], path_total),
        pct(stats.select_path_count[4], path_total),
        pct(stats.select_path_count[5], path_total),
        pct(stats.nr_quantum_full, quantum_total),
        pct(stats.nr_quantum_yield, quantum_total),
        pct(stats.nr_quantum_preempt, quantum_total),
    )
}

fn append_flight_recorder_section(output: &mut String, app: &TuiApp) {
    let samples = app.retained_timeline_samples();
    if samples.is_empty() {
        return;
    }

    let span = timeline_history_span(&app.timeline_history);
    let first = samples.first().unwrap();
    let last = samples.last().unwrap();
    let minute_rows = flight_minute_rows(&samples);
    let mut spike_rows: Vec<(u64, TimelineSample)> = samples
        .iter()
        .copied()
        .map(|sample| (flight_spike_score(&sample), sample))
        .filter(|(score, _)| *score > 0)
        .collect();
    spike_rows.sort_by(|a, b| b.0.cmp(&a.0));
    spike_rows.truncate(FLIGHT_SPIKE_ROWS);

    output.push_str(&format!(
        "\nflight: source=userspace_1s retained={} span={:.1}s first=t+{} last=t+{} minutes={} spikes={} load_temp=sampled_from_sysinfo\n",
        samples.len(),
        span.as_secs_f64(),
        timeline_elapsed_label(first.start_elapsed),
        timeline_elapsed_label(last.end_elapsed),
        minute_rows.len(),
        spike_rows.len(),
    ));
    output.push_str(
        "flight.guide: for a lag time, match t+MM:SS or t+HH:MM:SS in flight.minute, then inspect flight.spikes and timeline.last60 if the issue was recent\n",
    );
    output.push_str(
        "flight.minute.cols: [time span n run/s low wake/s wait>=5ms cb>=10us dispatch_miss/s qnet load=avg/max@cpu temp=avg/max@cpu path%=home/core/prim/idle/tun slice%=full/block/preempt]\n",
    );
    for row in &minute_rows {
        output.push_str(&format!("{}\n", format_flight_minute_row(row)));
    }

    if !spike_rows.is_empty() {
        output.push_str(
            "flight.spikes.cols: [score time ago reason run/s wake/s wait>=5ms cb>=10us dispatch_miss qnet load temp]\n",
        );
        for (score, sample) in &spike_rows {
            output.push_str(&format!("{}\n", format_flight_spike_row(*score, sample)));
        }
    }
    output.push_str(
        "flight.second.cols: [time run/s wake/s wait>=5ms cb>=10us dispatch_miss qnet load temp path%=home/core/prim/idle/tun slice%=full/block/preempt]\n",
    );
    for sample in &samples {
        output.push_str(&format!("{}\n", format_flight_second_row(sample)));
    }
}

fn append_blocked_behind_section(output: &mut String, label: &str, app: &TuiApp) {
    let mut rows: Vec<(usize, &CpuWorkCounters)> = app
        .per_cpu_work
        .iter()
        .enumerate()
        .filter(|(_, counter)| {
            counter.blocked_owner_wait_count > 0 && counter.blocked_owner_pid > 0
        })
        .collect();
    rows.sort_by(|a, b| {
        b.1.blocked_owner_wait_max_ns
            .cmp(&a.1.blocked_owner_wait_max_ns)
            .then_with(|| {
                b.1.blocked_owner_wait_count
                    .cmp(&a.1.blocked_owner_wait_count)
            })
            .then_with(|| a.0.cmp(&b.0))
    });
    output.push_str(&format!("{}: cpus={}\n", label, rows.len()));
    for (cpu, counter) in rows.iter().take(16) {
        let blocker = app
            .task_rows
            .get(&counter.blocked_owner_pid)
            .map(|task| format!("{}[{}]", task.comm, task.pid))
            .unwrap_or_else(|| format!("unknown[{}]", counter.blocked_owner_pid));
        let waiter = app
            .task_rows
            .get(&counter.blocked_waiter_pid)
            .map(|task| format!("{}[{}] tgid={}", task.comm, task.pid, task.tgid))
            .unwrap_or_else(|| format!("unknown[{}] tgid=0", counter.blocked_waiter_pid));
        output.push_str(&format!(
            "  cpu=C{:02} owner={} waiter={} total={}us avg={}us max={}us count={}\n",
            cpu,
            blocker,
            waiter,
            counter.blocked_owner_wait_ns / 1000,
            avg_ns(
                counter.blocked_owner_wait_ns,
                counter.blocked_owner_wait_count
            ) / 1000,
            counter.blocked_owner_wait_max_ns / 1000,
            counter.blocked_owner_wait_count,
        ));
    }
}

fn format_wake_class_counts(counts: &[u64]) -> String {
    counts
        .iter()
        .enumerate()
        .map(|(class, count)| format!("{}={}", wake_class_label(class), count))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_wake_class_reasons(counts: &[u64]) -> String {
    counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(reason, count)| format!("{}={}", wake_class_reason_label(reason), count))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_wake_class_transitions<const TO: usize>(counts: &[[u64; TO]]) -> String {
    let parts: Vec<_> = counts
        .iter()
        .enumerate()
        .flat_map(|(from, row)| {
            row.iter().enumerate().filter_map(move |(to, count)| {
                if *count > 0 {
                    Some(format!(
                        "{}->{}={}",
                        wake_class_label(from),
                        wake_class_label(to),
                        count
                    ))
                } else {
                    None
                }
            })
        })
        .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_busy_preempt_shadow(stats: &cake_stats) -> String {
    format!(
        "allow={} skip={} local={} remote={} wakee=[{}] owner=[{}]",
        stats
            .busy_preempt_shadow_count
            .first()
            .copied()
            .unwrap_or(0),
        stats.busy_preempt_shadow_count.get(1).copied().unwrap_or(0),
        stats.busy_preempt_shadow_local,
        stats.busy_preempt_shadow_remote,
        format_wake_class_counts(&stats.busy_preempt_shadow_wakee_class_count),
        format_wake_class_counts(&stats.busy_preempt_shadow_owner_class_count),
    )
}

#[cfg(debug_assertions)]
fn format_derived_strict_busy_preempt_shadow(derived: &DerivedStrictWakePolicy) -> String {
    format!(
        "allow={} skip={} local={} remote={} wakee=[{}] owner=[{}]",
        derived
            .busy_shadow_count
            .get(BUSY_PREEMPT_SHADOW_ALLOW)
            .copied()
            .unwrap_or(0),
        derived
            .busy_shadow_count
            .get(BUSY_PREEMPT_SHADOW_SKIP)
            .copied()
            .unwrap_or(0),
        derived.busy_shadow_local,
        derived.busy_shadow_remote,
        format_wake_class_counts(&derived.busy_shadow_wakee_class_count),
        format_wake_class_counts(&derived.busy_shadow_owner_class_count),
    )
}

#[cfg(debug_assertions)]
fn format_derived_strict_wake_class_wait(derived: &DerivedStrictWakePolicy) -> String {
    derived
        .wait_count
        .iter()
        .enumerate()
        .map(|(class, count)| {
            format!(
                "{}={}/{}us({})",
                wake_class_label(class),
                avg_ns(derived.wait_ns[class], *count) / 1000,
                derived.wait_max_ns[class] / 1000,
                count
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(debug_assertions)]
fn format_derived_strict_wake_class_buckets(derived: &DerivedStrictWakePolicy) -> String {
    let parts: Vec<_> = derived
        .bucket_count
        .iter()
        .enumerate()
        .filter_map(|(class, buckets)| {
            if buckets.iter().all(|count| *count == 0) {
                None
            } else {
                Some(format!(
                    "{}={}/{}/{}/{}/{}",
                    wake_class_label(class),
                    buckets[0],
                    buckets[1],
                    buckets[2],
                    buckets[3],
                    buckets[4]
                ))
            }
        })
        .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn append_wake_policy_section(output: &mut String, label: &str, stats: &cake_stats) {
    output.push_str(&format!(
        "{}: class=[{}] reasons=[{}] transitions=[{}] busy_shadow:{}\n",
        label,
        format_wake_class_counts(&stats.wake_class_sample_count),
        format_wake_class_reasons(&stats.wake_class_reason_count),
        format_wake_class_transitions(&stats.wake_class_transition_count),
        format_busy_preempt_shadow(stats),
    ));
}

#[cfg(debug_assertions)]
fn append_strict_wake_policy_derived_section(
    output: &mut String,
    label: &str,
    derived: &DerivedStrictWakePolicy,
) {
    output.push_str(&format!(
        "{}: source=task_anatomy quality=debug_derived_shadow snapshot=latest policy_effect=none rows={} class=[{}] reasons=[{}] wait=[{}] buckets=[{}] transitions=[{}] busy_shadow:{}\n",
        label,
        derived.source_rows,
        format_wake_class_counts(&derived.class_sample_count),
        format_wake_class_reasons(&derived.reason_count),
        format_derived_strict_wake_class_wait(derived),
        format_derived_strict_wake_class_buckets(derived),
        format_wake_class_transitions(&derived.transition_count),
        format_derived_strict_busy_preempt_shadow(derived),
    ));
}

fn append_window_stats(
    output: &mut String,
    label: &str,
    elapsed: Duration,
    stats: &cake_stats,
    queue_now: u64,
) {
    let secs = elapsed.as_secs_f64().max(0.1);
    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let direct_total = stats.nr_direct_local_inserts;
    let shared_total = stats.nr_shared_vtime_inserts;
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);

    output.push_str(&format!("\nwindow: {} sampled={:.1}s\n", label, secs));
    output.push_str(&format!(
        "win.disp: dsq_total={} ({:.1}/s) local={} steal={} miss={} ({:.1}/s) queue_now={} ins:direct={} ({:.1}/s) affine={} ({:.1}/s) shared={} ({:.1}/s) shared[w/r/p/o]={}/{}/{}/{} direct[k/o]={}/{} wake:direct={} ({:.1}%) busy={} ({:.1}%) queued={} ({:.1}%) total={} ({:.1}/s) steer:elig={} ({:.1}/s) home={} ({:.1}/s) core={} ({:.1}/s) primary={} ({:.1}/s) miss:home_busy={} prev_busy={} scan={} guard:primary_scan={} hot_guard:primary_scan={} credit:primary_scan={} chain:guard={} chain:credit={}\n",
        total_dsq_dispatches,
        per_sec(total_dsq_dispatches, secs),
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        per_sec(stats.nr_dispatch_misses, secs),
        queue_now,
        direct_total,
        per_sec(direct_total, secs),
        stats.nr_direct_affine_inserts,
        per_sec(stats.nr_direct_affine_inserts, secs),
        shared_total,
        per_sec(shared_total, secs),
        stats.nr_shared_wakeup_inserts,
        stats.nr_shared_requeue_inserts,
        stats.nr_shared_preserve_inserts,
        stats.nr_shared_other_inserts,
        stats.nr_direct_kthread_inserts,
        stats.nr_direct_other_inserts,
        stats.nr_wakeup_direct_dispatches,
        pct(stats.nr_wakeup_direct_dispatches, wake_total),
        stats.nr_wakeup_dsq_fallback_busy,
        pct(stats.nr_wakeup_dsq_fallback_busy, wake_total),
        stats.nr_wakeup_dsq_fallback_queued,
        pct(stats.nr_wakeup_dsq_fallback_queued, wake_total),
        wake_total,
        per_sec(wake_total, secs),
        stats.nr_steer_eligible,
        per_sec(stats.nr_steer_eligible, secs),
        stats.nr_home_cpu_steers,
        per_sec(stats.nr_home_cpu_steers, secs),
        stats.nr_home_core_steers,
        per_sec(stats.nr_home_core_steers, secs),
        stats.nr_primary_cpu_steers,
        per_sec(stats.nr_primary_cpu_steers, secs),
        stats.nr_home_cpu_busy_misses,
        stats.nr_prev_primary_busy_misses,
        stats.nr_primary_scan_misses,
        stats.nr_primary_scan_guarded,
        stats.nr_primary_scan_hot_guarded,
        stats.nr_primary_scan_credit_used,
        stats.nr_wake_chain_locality_guarded,
        stats.nr_wake_chain_locality_credit_used,
    ));
    output.push_str(&format!(
        "win.queue.shared: depth_now={} in={} ({:.1}/s) out={} ({:.1}/s) net={:+} ({:+.1}/s)\n",
        queue_now,
        stats.nr_dsq_queued,
        per_sec(stats.nr_dsq_queued, secs),
        stats.nr_dsq_consumed,
        per_sec(stats.nr_dsq_consumed, secs),
        queue_net,
        queue_net as f64 / secs,
    ));
    output.push_str(&format!(
        "win.cb: sel_avg_ns={} enq_avg_ns={} disp_avg_ns={} run_avg_ns={} stop_avg_ns={} slow=sel:{} enq:{} disp:{} run:{} stop:{}\n",
        avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls),
        avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls),
        avg_ns(stats.total_dispatch_ns, stats.nr_dispatch_calls),
        avg_ns(stats.total_running_ns, stats.nr_running_calls),
        avg_ns(stats.total_stopping_ns, stats.nr_stopping_calls),
        stats.callback_slow[0],
        stats.callback_slow[1],
        stats.callback_slow[2],
        stats.callback_slow[3],
        stats.callback_slow[4],
    ));
    output.push_str(&format!(
        "win.cbhist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]\n",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    ));
    output.push_str(&format!(
        "win.hotpath: run=same:{}/chg:{} ({:.1}/{:.1}/s) stop=run:{}/blk:{} ({:.1}/{:.1}/s) enq=kth:{} init:{} preserve:{} requeue:{} wake:{} affine[p/r/d]={}/{}/{} llc=wake_idle:{} wake_busy:{} nonwake:{} disp=lhit:{} lmiss:{} steal:{} keep:{}\n",
        stats.nr_running_same_task,
        stats.nr_running_task_change,
        per_sec(stats.nr_running_same_task, secs),
        per_sec(stats.nr_running_task_change, secs),
        stats.nr_stopping_runnable,
        stats.nr_stopping_blocked,
        per_sec(stats.nr_stopping_runnable, secs),
        per_sec(stats.nr_stopping_blocked, secs),
        stats.nr_enqueue_path_kthread,
        stats.nr_enqueue_path_initial,
        stats.nr_enqueue_path_preserve,
        stats.nr_enqueue_path_requeue,
        stats.nr_enqueue_path_wakeup,
        stats.nr_enqueue_path_affine_preserve,
        stats.nr_enqueue_path_affine_requeue,
        stats.nr_enqueue_path_affine_dispatch,
        stats.nr_llc_vtime_wake_idle_direct,
        stats.nr_llc_vtime_wake_busy_shared,
        stats.nr_llc_vtime_nonwake_shared,
        stats.nr_dispatch_llc_local_hit,
        stats.nr_dispatch_llc_local_miss,
        stats.nr_dispatch_llc_steal_hit,
        stats.nr_dispatch_keep_running,
    ));
    output.push_str(&format!(
        "win.wakewait.all: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_all_ns,
            &stats.wake_reason_wait_all_count,
            &stats.wake_reason_wait_all_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.wakewait<=5ms: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_ns,
            &stats.wake_reason_wait_count,
            &stats.wake_reason_wait_max_ns,
        )
    ));
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;
    output.push_str(&format!(
        "win.slice: full={} ({:.1}%) blocked={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} kick:wake[i/p]={}/{} affine[i/p]={}/{}\n",
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
    ));
    append_wake_policy_section(output, &format!("win.wakepolicy.{}", label), stats);
    let smt_runtime_ns = stats.smt_solo_runtime_ns + stats.smt_contended_runtime_ns;
    let smt_runs = stats.smt_solo_run_count + stats.smt_contended_run_count;
    output.push_str(&format!(
        "win.smt: runtime_contended={:.1}% overlap={:.1}% runs_contended={:.1}% avg_run_us[s/c]={}/{} wake_avg_us[s/c]={}/{} active_start/stop={}/{}\n",
        pct(stats.smt_contended_runtime_ns, smt_runtime_ns),
        pct(stats.smt_overlap_runtime_ns, smt_runtime_ns),
        pct(stats.smt_contended_run_count, smt_runs),
        avg_ns(stats.smt_solo_runtime_ns, stats.smt_solo_run_count) / 1000,
        avg_ns(stats.smt_contended_runtime_ns, stats.smt_contended_run_count) / 1000,
        avg_ns(stats.smt_wake_wait_ns[0], stats.smt_wake_wait_count[0]) / 1000,
        avg_ns(stats.smt_wake_wait_ns[1], stats.smt_wake_wait_count[1]) / 1000,
        stats.smt_sibling_active_start_count,
        stats.smt_sibling_active_stop_count,
    ));
    output.push_str(&format!(
        "win.wakebins: {}\n",
        format_wake_bucket_summary(&stats.wake_reason_bucket_count)
    ));
    output.push_str(&format!(
        "win.decision.wait: {}\n",
        format_select_decision_wait_summary(
            &stats.select_reason_wait_ns,
            &stats.select_reason_wait_count,
            &stats.select_reason_wait_max_ns,
            &stats.select_reason_bucket_count,
        )
    ));
    output.push_str(&format!(
        "win.decision.select: {}\n",
        format_select_decision_cost_summary(
            &stats.select_reason_select_ns,
            &stats.select_reason_select_count,
            &stats.select_reason_select_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.decision.migrate: {}\n",
        format_select_migration_summary(
            &stats.select_path_migration_count,
            &stats.select_reason_migration_count,
        )
    ));
    output.push_str(&format!(
        "win.postwake.target_hit/miss: {}  win.postwake.follow_same/mig: {}\n",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    ));
    output.push_str(&format!(
        "win.kickrun: idle={}/{} avg={}us max={}us preempt={}/{} avg={}us max={}us\n",
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
    ));
    output.push_str(&format!(
        "win.kickbins: {}\n",
        format_kick_bucket_summary(&stats.wake_kick_bucket_count)
    ));
    output.push_str(&format!(
        "win.path: {}  deps:same_tgid={} ({:.1}/s) cross_tgid={} ({:.1}/s)\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        per_sec(stats.nr_wake_same_tgid, secs),
        stats.nr_wake_cross_tgid,
        per_sec(stats.nr_wake_cross_tgid, secs),
    ));
    output.push_str(&format!(
        "win.place.home.wait<=5ms: {}\n",
        format_place_wait_summary(
            &stats.home_place_wait_ns,
            &stats.home_place_wait_count,
            &stats.home_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.place.run: {}\n",
        format_place_wait_summary(
            &stats.home_place_run_ns,
            &stats.home_place_run_count,
            &stats.home_place_run_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.place.waker.wait<=5ms: {}\n",
        format_place_wait_summary(
            &stats.waker_place_wait_ns,
            &stats.waker_place_wait_count,
            &stats.waker_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.coh/s: idle_remote={:.1} busy={:.1} idle={:.1} pend_remote={:.1} set={:.1} clr={:.1}\n",
        per_sec(stats.nr_idle_hint_remote_reads, secs),
        per_sec(stats.nr_idle_hint_remote_busy, secs),
        per_sec(stats.nr_idle_hint_remote_idle, secs),
        per_sec(stats.nr_busy_pending_remote_sets, secs),
        per_sec(stats.nr_idle_hint_set_writes + stats.nr_idle_hint_set_skips, secs),
        per_sec(stats.nr_idle_hint_clear_writes + stats.nr_idle_hint_clear_skips, secs),
    ));
    output.push_str(&format!(
        "win.bypass/s: requeue_fast={:.1} busy_local_skip={:.1} busy_remote_skip={:.1} busy_pending_skip={:.1}\n",
        per_sec(stats.nr_enqueue_requeue_fastpath, secs),
        per_sec(stats.nr_enqueue_busy_local_skip_depth, secs),
        per_sec(stats.nr_enqueue_busy_remote_skip_depth, secs),
        per_sec(stats.nr_busy_pending_set_skips, secs),
    ));
}

/// Format stats as a copyable text string
pub(super) fn format_stats_for_clipboard(stats: &cake_stats, app: &TuiApp) -> String {
    #[cfg(debug_assertions)]
    let dump_start = Instant::now();
    #[cfg(debug_assertions)]
    let anatomy_derive_us;

    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let cap = capacity_summary(app, &tgid_roles);
    let report = build_telemetry_report(stats, app);

    let mut output = String::new();
    output.push_str(&app.system_info.format_header());

    output.push_str(&format!(
        "cake: uptime={} state=IDLE detector=disabled\n",
        app.format_uptime(),
    ));
    output.push_str("scope: lifetime\n");
    output.push_str(
        "capture: global=exact task.life=exact task.rate=delta_per_tick task.stage=latest_observed task.affinity=exact task.home=debug_exact task.quantum=exact_u64 task.behind=latest_observed wakewait.all=exact wakewait<=5ms=bounded wakegraph.ringbuf=debug_sampled_weighted homeseed=debug_exact localq=debug_estimate accelerator=cpu_bss_confidence+bpf_stats windows=delta_snapshots history=rolling_1s_samples flight=userspace_1s_retained",
    );
    #[cfg(debug_assertions)]
    output.push_str(" wakegraph.derived=debug_derived_latest_waker task.anatomy=debug_derived gaming.qos=debug_derived wake.chain=debug_derived+bpf_locality_guard wakepolicy.strict.derived=debug_shadow");
    output.push('\n');
    let service_report = build_service_report(stats, app, &report);
    output.push_str(&format_service_report_text(&service_report));
    output.push_str(&report.coverage_text());
    output.push_str(
        "task.fields: latest={LASTWus,SELns,ENQns,STOPns,RUNns,LASTGAPus,path/place,life=i0/e/s/r/x:first/seen,behind} rate={RUN/s,MIG/s,RTms/s} life={RTms,AVGRTus(run_stop),MAXRUNus,RJITus,wakeus<=5ms,WHIST,Qf/b/p exact_u64,SYLD,affinity,home,cpu/core spread,task_smt}",
    );
    #[cfg(debug_assertions)]
    output.push_str(" anatomy={policy,prio,flags,shape,lane_candidate,source,risk} wake_chain={chain,policy_score,reasons,decay}");
    output.push('\n');
    output.push_str(
        "slice.meaning: blocked=task stopped with slice left and was not runnable; sched_yield=explicit cake_yield callback count\n",
    );
    append_focused_app_section(&mut output, app, &tgid_roles);
    #[cfg(debug_assertions)]
    {
        let anatomy_start = Instant::now();
        append_wake_chain_section(&mut output, app);
        append_gaming_qos_section(&mut output, app);
        append_task_anatomy_section(&mut output, app);
        anatomy_derive_us = anatomy_start.elapsed().as_micros() as u64;
    }
    let life_elapsed = app.start_time.elapsed().max(Duration::from_secs(1));
    let life_cpu_rows = scheduler_cpu_rows(
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        life_elapsed,
    );
    let life_core_rows = scheduler_core_rows(
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        life_elapsed,
    );
    let life_balance = build_balance_diagnosis(&life_cpu_rows, &life_core_rows);
    let timeline_window = Duration::from_secs(60);
    let timeline_step = Duration::from_secs(1);
    let timeline_samples = app.timeline_samples(timeline_window, timeline_step);
    let timeline_expected = expected_timeline_samples(timeline_window, timeline_step);
    let timeline_span = timeline_history_span(&app.timeline_history);

    // Compact dispatch stats
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let direct_total = stats.nr_direct_local_inserts;
    let shared_total = stats.nr_shared_vtime_inserts;
    output.push_str(&format!(
        "disp: dsq_total={} local={} steal={} miss={} queue={} ins:direct={} affine={} shared={} shared[w/r/p/o]={}/{}/{}/{} direct[k/o]={}/{} wake:direct={} busy={} queued={} total={} busy_local={} busy_remote={} flow:tunnel_prev={} handoff={} supp={} steer:elig={} home={} core={} primary={} miss:home_busy={} prev_busy={} scan={} guard:primary_scan={} hot_guard:primary_scan={} credit:primary_scan={} chain:guard={} chain:credit={}\n",
        total_dsq_dispatches,
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        dsq_depth,
        direct_total,
        stats.nr_direct_affine_inserts,
        shared_total,
        stats.nr_shared_wakeup_inserts,
        stats.nr_shared_requeue_inserts,
        stats.nr_shared_preserve_inserts,
        stats.nr_shared_other_inserts,
        stats.nr_direct_kthread_inserts,
        stats.nr_direct_other_inserts,
        stats.nr_wakeup_direct_dispatches,
        stats.nr_wakeup_dsq_fallback_busy,
        stats.nr_wakeup_dsq_fallback_queued,
        wake_total,
        stats.nr_wakeup_busy_local_target,
        stats.nr_wakeup_busy_remote_target,
        stats.nr_prev_cpu_tunnels,
        stats.nr_busy_handoff_dispatches,
        stats.nr_busy_keep_suppressed,
        stats.nr_steer_eligible,
        stats.nr_home_cpu_steers,
        stats.nr_home_core_steers,
        stats.nr_primary_cpu_steers,
        stats.nr_home_cpu_busy_misses,
        stats.nr_prev_primary_busy_misses,
        stats.nr_primary_scan_misses,
        stats.nr_primary_scan_guarded,
        stats.nr_primary_scan_hot_guarded,
        stats.nr_primary_scan_credit_used,
        stats.nr_wake_chain_locality_guarded,
        stats.nr_wake_chain_locality_credit_used,
    ));
    output.push_str(&format!(
        "queue.shared: depth_now={} in={} out={} net={:+}\n",
        dsq_depth, stats.nr_dsq_queued, stats.nr_dsq_consumed, queue_net,
    ));

    // Compact callback profile (totals + averages)
    let stop_total = stats.nr_stop_deferred_skip + stats.nr_stop_deferred;
    output.push_str(&format!(
        "cb.stop: tot_µs={} max_ns={} calls={} task_telemetry={} sampled_skip={}\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
        if stats.nr_stop_deferred_skip == 0 {
            "exact"
        } else {
            "mixed"
        },
        stats.nr_stop_deferred_skip,
    ));
    output.push_str(&format!(
        "cb.run: tot_µs={} max_ns={} calls={}  cb.enq: tot_µs={} calls={}  sel: tot_µs={} g1_µs={} g2_µs={} calls={}  cb.disp: tot_µs={} max_ns={} calls={}\n",
        stats.total_running_ns / 1000, stats.max_running_ns, stats.nr_running_calls,
        stats.total_enqueue_latency_ns / 1000, stats.nr_enqueue_calls,
        stats.total_select_cpu_ns / 1000, stats.total_gate1_latency_ns / 1000, stats.total_gate2_latency_ns / 1000, stats.nr_select_cpu_calls,
        stats.total_dispatch_ns / 1000, stats.max_dispatch_ns, stats.nr_dispatch_calls,
    ));
    output.push_str(&format!(
        "cb.avg: sel={}ns enq={}ns disp={}ns run={}ns stop={}ns\n",
        avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls),
        avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls),
        avg_ns(stats.total_dispatch_ns, stats.nr_dispatch_calls),
        avg_ns(stats.total_running_ns, stats.nr_running_calls),
        avg_ns(stats.total_stopping_ns, stop_total),
    ));
    output.push_str(&format!(
        "cb.hist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]\n",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    ));
    output.push_str(&format!(
        "hotpath: run=same:{} change:{} stop=runnable:{} blocked:{} enq=kthread:{} initial:{} preserve:{} requeue:{} wakeup:{} affine[p/r/d]={}/{}/{} llc=wake_idle:{} wake_busy:{} nonwake:{} dispatch=local_hit:{} local_miss:{} steal_hit:{} keep_running:{}\n",
        stats.nr_running_same_task,
        stats.nr_running_task_change,
        stats.nr_stopping_runnable,
        stats.nr_stopping_blocked,
        stats.nr_enqueue_path_kthread,
        stats.nr_enqueue_path_initial,
        stats.nr_enqueue_path_preserve,
        stats.nr_enqueue_path_requeue,
        stats.nr_enqueue_path_wakeup,
        stats.nr_enqueue_path_affine_preserve,
        stats.nr_enqueue_path_affine_requeue,
        stats.nr_enqueue_path_affine_dispatch,
        stats.nr_llc_vtime_wake_idle_direct,
        stats.nr_llc_vtime_wake_busy_shared,
        stats.nr_llc_vtime_nonwake_shared,
        stats.nr_dispatch_llc_local_hit,
        stats.nr_dispatch_llc_local_miss,
        stats.nr_dispatch_llc_steal_hit,
        stats.nr_dispatch_keep_running,
    ));
    output.push_str(&format!(
        "lifecycle.avg: init_enqueue={}us({}) init_select={}us({}) init_run={}us({}) run_stop={}us({}) init_exit={}us({})\n",
        avg_us(
            stats.lifecycle_init_enqueue_us,
            stats.lifecycle_init_enqueue_count,
        ),
        stats.lifecycle_init_enqueue_count,
        avg_us(
            stats.lifecycle_init_select_us,
            stats.lifecycle_init_select_count,
        ),
        stats.lifecycle_init_select_count,
        avg_us(stats.lifecycle_init_run_us, stats.lifecycle_init_run_count),
        stats.lifecycle_init_run_count,
        avg_ns(stats.task_runtime_ns, stats.task_run_count) / 1000,
        stats.task_run_count,
        avg_us(stats.lifecycle_init_exit_us, stats.lifecycle_init_exit_count),
        stats.lifecycle_init_exit_count,
    ));
    output.push_str(&format!(
        "wakewait.all: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_all_ns,
            &stats.wake_reason_wait_all_count,
            &stats.wake_reason_wait_all_max_ns,
        )
    ));
    output.push_str(&format!(
        "wakewait<=5ms: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_ns,
            &stats.wake_reason_wait_count,
            &stats.wake_reason_wait_max_ns,
        )
    ));
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;
    output.push_str(&format!(
        "slice: quantum={}us full={} ({:.1}%) blocked={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} kick:wake[i/p]={}/{} affine[i/p]={}/{}\n",
        app.quantum_us,
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
    ));
    append_wake_policy_section(&mut output, "wakepolicy.life", stats);
    #[cfg(debug_assertions)]
    {
        let strict_derived = derive_strict_wake_policy_snapshot(app);
        append_strict_wake_policy_derived_section(
            &mut output,
            "wakepolicy.strict.derived.life",
            &strict_derived,
        );
    }
    let smt_runtime_ns = stats.smt_solo_runtime_ns + stats.smt_contended_runtime_ns;
    let smt_runs = stats.smt_solo_run_count + stats.smt_contended_run_count;
    output.push_str(&format!(
        "smt: runtime_contended={:.1}% overlap={:.1}% runs_contended={:.1}% avg_run_us[s/c]={}/{} wake_avg_us[s/c]={}/{} active_start/stop={}/{}\n",
        pct(stats.smt_contended_runtime_ns, smt_runtime_ns),
        pct(stats.smt_overlap_runtime_ns, smt_runtime_ns),
        pct(stats.smt_contended_run_count, smt_runs),
        avg_ns(stats.smt_solo_runtime_ns, stats.smt_solo_run_count) / 1000,
        avg_ns(stats.smt_contended_runtime_ns, stats.smt_contended_run_count) / 1000,
        avg_ns(stats.smt_wake_wait_ns[0], stats.smt_wake_wait_count[0]) / 1000,
        avg_ns(stats.smt_wake_wait_ns[1], stats.smt_wake_wait_count[1]) / 1000,
        stats.smt_sibling_active_start_count,
        stats.smt_sibling_active_stop_count,
    ));
    output.push_str(&format!(
        "wakebins: {}\n",
        format_wake_bucket_summary(&stats.wake_reason_bucket_count)
    ));
    output.push_str(&format!(
        "decision.wait: {}\n",
        format_select_decision_wait_summary(
            &stats.select_reason_wait_ns,
            &stats.select_reason_wait_count,
            &stats.select_reason_wait_max_ns,
            &stats.select_reason_bucket_count,
        )
    ));
    output.push_str(&format!(
        "decision.select: {}\n",
        format_select_decision_cost_summary(
            &stats.select_reason_select_ns,
            &stats.select_reason_select_count,
            &stats.select_reason_select_max_ns,
        )
    ));
    output.push_str(&format!(
        "decision.migrate: {}\n",
        format_select_migration_summary(
            &stats.select_path_migration_count,
            &stats.select_reason_migration_count,
        )
    ));
    output.push_str(&format!(
        "postwake.target_hit/miss: {}  postwake.follow_same/mig: {}\n",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    ));
    output.push_str(&format!(
        "kickrun: idle={}/{} avg={}us max={}us  preempt={}/{} avg={}us max={}us\n",
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
    ));
    output.push_str(&format!(
        "kickbins: {}\n",
        format_kick_bucket_summary(&stats.wake_kick_bucket_count)
    ));
    output.push_str(&format!(
        "place.path: {}  deps:same_tgid={} cross_tgid={}\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    ));
    output.push_str(&format!(
        "place.home.wait<=5ms: {}\n",
        format_place_wait_summary(
            &stats.home_place_wait_ns,
            &stats.home_place_wait_count,
            &stats.home_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "place.home.run: {}\n",
        format_place_wait_summary(
            &stats.home_place_run_ns,
            &stats.home_place_run_count,
            &stats.home_place_run_max_ns,
        )
    ));
    output.push_str(&format!(
        "place.waker.wait<=5ms: {}\n",
        format_place_wait_summary(
            &stats.waker_place_wait_ns,
            &stats.waker_place_wait_count,
            &stats.waker_place_wait_max_ns,
        )
    ));
    append_wake_graph_section(&mut output, app);
    #[cfg(debug_assertions)]
    append_derived_wake_graph_section(&mut output, app);
    output.push_str(&format!(
        "coh: idle_remote={} busy={} idle={} pend_remote={} set_w/s={}/{} clr_w/s={}/{}\n",
        stats.nr_idle_hint_remote_reads,
        stats.nr_idle_hint_remote_busy,
        stats.nr_idle_hint_remote_idle,
        stats.nr_busy_pending_remote_sets,
        stats.nr_idle_hint_set_writes,
        stats.nr_idle_hint_set_skips,
        stats.nr_idle_hint_clear_writes,
        stats.nr_idle_hint_clear_skips,
    ));
    output.push_str(&format!(
        "bypass: requeue_fast={} busy_local_skip_depth={} busy_remote_skip_depth={} busy_pending_skip={}\n",
        stats.nr_enqueue_requeue_fastpath,
        stats.nr_enqueue_busy_local_skip_depth,
        stats.nr_enqueue_busy_remote_skip_depth,
        stats.nr_busy_pending_set_skips,
    ));
    output.push_str(&format!(
        "cap: hard_tasks={} hard_hot={} soft_tasks={} soft_hot={} build_tasks={} build_hot={} shared_top_cores={} build_shared={} hard_smt={} hard_scatter={} focus_scatter={}\n",
        cap.hard_latency_tasks,
        cap.hard_latency_hot,
        cap.soft_latency_tasks,
        cap.soft_latency_hot,
        cap.build_tasks,
        cap.build_hot,
        cap.shared_top_cores,
        cap.build_shared_tasks,
        cap.hard_latency_smt_heavy,
        cap.hard_latency_scattered,
        cap.focus_scattered,
    ));
    output.push_str(&format!(
        "roles: game={} render={} ui={} audio={} build={} kcritical={}\n",
        cap.game_tasks,
        cap.render_tasks,
        cap.ui_tasks,
        cap.audio_tasks,
        cap.build_tasks,
        cap.critical_tasks,
    ));
    output.push_str(&format!(
        "context: lifetime_sampled={:.1}s cpu_work_life={:.1}s timeline_history={} timeline_span={:.1}s avg_step={:.2}s last60s_coverage={}/{}\n",
        app.start_time.elapsed().as_secs_f64(),
        life_elapsed.as_secs_f64(),
        app.timeline_history.len(),
        timeline_span.as_secs_f64(),
        if app.timeline_history.is_empty() {
            0.0
        } else {
            timeline_span.as_secs_f64() / app.timeline_history.len() as f64
        },
        timeline_samples.len(),
        timeline_expected,
    ));
    if let Some(diag) = &life_balance {
        output.push_str(&format!(
            "balance.life: driver={} top_cpu={} {:.1}% {}us {:.1}/s top_rate_cpu={} {:.1}/s {}us top_core={} {:.1}% hot_thr={:.0}% sib={:.0}% top_rate_core={} {:.1}/s cpu_skew={:.1}x core_skew={:.1}x hot/cold cpu={}/{} core={}/{} sticky_core={} hard_scatter={} focus_scatter={} hard_smt={}\n",
            diag.driver,
            diag.top_cpu_share_label,
            diag.top_cpu_share_pct,
            diag.top_cpu_avg_run_us,
            diag.top_cpu_runs_per_sec,
            diag.top_cpu_rate_label,
            diag.top_cpu_rate_runs_per_sec,
            diag.top_cpu_rate_avg_run_us,
            diag.top_core_share_label,
            diag.top_core_share_pct,
            diag.top_core_hot_thr_pct,
            diag.top_core_sib_pct,
            diag.top_core_rate_label,
            diag.top_core_rate_runs_per_sec,
            diag.cpu_skew,
            diag.core_skew,
            diag.hot_cpu_count,
            diag.cold_cpu_count,
            diag.hot_core_count,
            diag.cold_core_count,
            if diag.sticky_core { "yes" } else { "no" },
            cap.hard_latency_scattered,
            cap.focus_scattered,
            cap.hard_latency_smt_heavy,
        ));
    }
    append_cpu_work_section(
        &mut output,
        "cpu.work.life",
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        app.start_time.elapsed(),
    );
    append_long_run_owner_section(&mut output, "longrun.life", app, &tgid_roles);
    append_app_health_section(&mut output, "app.health.life", app, &tgid_roles);
    append_blocked_behind_section(&mut output, "blocked.behind.life", app);
    append_local_queue_section(
        &mut output,
        "localq.life",
        &app.per_cpu_work,
        app.start_time.elapsed(),
    );
    append_accelerator_section(
        &mut output,
        "accelerator.life",
        &app.per_cpu_work,
        stats,
        app.start_time.elapsed(),
    );
    append_select_cpu_section(
        &mut output,
        "select.life",
        &app.per_cpu_work,
        app.start_time.elapsed(),
    );
    append_home_seed_section(
        &mut output,
        "homeseed.life",
        &app.per_cpu_work,
        app.start_time.elapsed(),
    );
    append_pressure_probe_section(
        &mut output,
        "pressure.life",
        &app.per_cpu_work,
        &app.pressure_probe,
        app.start_time.elapsed(),
    );
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(30)) {
        append_window_stats(&mut output, "30s", elapsed, &delta, dsq_depth);
    }
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(60)) {
        append_window_stats(&mut output, "60s", elapsed, &delta, dsq_depth);
    }
    if let Some((elapsed, window)) = app.cpu_work_window(Duration::from_secs(60)) {
        let cpu_rows_60 = scheduler_cpu_rows(&window, &app.topology, &app.cpu_stats, elapsed);
        let core_rows_60 = scheduler_core_rows(&window, &app.topology, &app.cpu_stats, elapsed);
        if let Some(diag) = build_balance_diagnosis(&cpu_rows_60, &core_rows_60) {
            output.push_str(&format!(
                "balance.60s: sampled={:.1}s driver={} top_cpu={} {:.1}% {}us {:.1}/s top_rate_cpu={} {:.1}/s {}us top_core={} {:.1}% hot_thr={:.0}% sib={:.0}% top_rate_core={} {:.1}/s cpu_skew={:.1}x core_skew={:.1}x hot/cold cpu={}/{} core={}/{} sticky_core={}\n",
                elapsed.as_secs_f64(),
                diag.driver,
                diag.top_cpu_share_label,
                diag.top_cpu_share_pct,
                diag.top_cpu_avg_run_us,
                diag.top_cpu_runs_per_sec,
                diag.top_cpu_rate_label,
                diag.top_cpu_rate_runs_per_sec,
                diag.top_cpu_rate_avg_run_us,
                diag.top_core_share_label,
                diag.top_core_share_pct,
                diag.top_core_hot_thr_pct,
                diag.top_core_sib_pct,
                diag.top_core_rate_label,
                diag.top_core_rate_runs_per_sec,
                diag.cpu_skew,
                diag.core_skew,
                diag.hot_cpu_count,
                diag.cold_cpu_count,
                diag.hot_core_count,
                diag.cold_core_count,
                if diag.sticky_core { "yes" } else { "no" },
            ));
        }
        append_cpu_work_section(
            &mut output,
            "cpu.work.60s",
            &window,
            &app.topology,
            &app.cpu_stats,
            elapsed,
        );
        append_local_queue_section(&mut output, "localq.60s", &window, elapsed);
        if let Some((_stats_elapsed, stats_window)) =
            app.windowed_stats(stats, Duration::from_secs(60))
        {
            append_accelerator_section(
                &mut output,
                "accelerator.60s",
                &window,
                &stats_window,
                elapsed,
            );
        }
        append_select_cpu_section(&mut output, "select.60s", &window, elapsed);
        append_home_seed_section(&mut output, "homeseed.60s", &window, elapsed);
        if let Some((pressure_elapsed, pressure_window)) =
            app.pressure_probe_window(Duration::from_secs(60))
        {
            append_pressure_probe_section(
                &mut output,
                "pressure.60s",
                &window,
                &pressure_window,
                pressure_elapsed,
            );
        }
    }
    if let Some(summary_lines) = summarize_timeline_samples(&timeline_samples, timeline_expected) {
        output.push_str("\nwindow: last60s sampled=rolling_1s history=latest_60\n");
        for line in summary_lines {
            output.push_str(&line.to_string());
            output.push('\n');
        }
        output.push_str(
            "timeline.cols: [time ago span run/s wake/s wake%=dir/busy/q path%=home/core/prim/idle/tun cbns=sel/enq/run/stop waitus<=5ms=dir/busy/q slice%=full/block/preempt load=avg/max@cpu temp=avg/max@cpu]\n",
        );
        for sample in &timeline_samples {
            output.push_str(&format!("{}\n", format_timeline_sample_row(sample)));
        }
    }
    append_flight_recorder_section(&mut output, app);
    if !app.debug_events.is_empty() {
        output.push_str("events:\n");
        for ev in app.debug_events.iter().take(8) {
            output.push_str(&format!(
                "  ts={} pid={} {}\n",
                ev.ts_ns,
                ev.pid,
                debug_event_label(ev)
            ));
        }
    }

    // Task matrix header — compact column key
    output.push_str(
        "\ntask.scope: rows=live_bpf_tracked life=since_task_first_tracked_this_run rate=latest_tui_tick latest=last_observed windows=separate_30s_60s recent=bounded_debug_events\n",
    );
    output.push_str(
        "tasks: [PPID PID ST COMM CLS UTIL% MAXRUNus LASTGAPus RJITus LASTWus LIFE RUN/s CPU SPRD RES% SMT2% SELns ENQns STOPns RUNns FAST% NAT% TUN% MIG/s]\n",
    );
    output.push_str(
        "       [detail: ROLE STEER(home/primary) DIRECT Q[f/b/p] SYLD PRMPT LIFE(i0/e/s/r/x:first/seen) MAXGAPus DSQINSns RUNS RTms AVGRTus RTms/s SLICEOCC% LLC/COUNT PLACE(cpu/core dist) STREAK WAKER TGID CLS V/ICSW WAKEus<=5ms(dir/busy/q) HWAIT<=5ms WHIST]\n",
    );

    let all_dump_pids: Vec<u32> = app
        .task_rows
        .iter()
        .filter(|(_, row)| row_has_bpf_matrix_data(row))
        .map(|(pid, _)| *pid)
        .collect();
    let dead_hidden = all_dump_pids
        .iter()
        .filter(|pid| {
            app.task_rows
                .get(pid)
                .map(|row| row.status == TaskStatus::Dead)
                .unwrap_or(false)
        })
        .count();
    // Prefer live rows so dump reviews stay benchmark-focused even if stale tasks are retained in TUI state.
    let mut dump_pids: Vec<u32> = all_dump_pids
        .iter()
        .copied()
        .filter(|pid| {
            app.task_rows
                .get(pid)
                .map(|row| row.status != TaskStatus::Dead)
                .unwrap_or(false)
        })
        .collect();
    let live_only = !dump_pids.is_empty();
    if !live_only {
        dump_pids = all_dump_pids.clone();
    }
    dump_pids.sort_by(|a, b| {
        let r_a = app.task_rows.get(a).unwrap();
        let r_b = app.task_rows.get(b).unwrap();
        r_b.pelt_util.cmp(&r_a.pelt_util)
    });
    // TGID grouping (same logic as TUI)
    let mut tgid_rank: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (i, pid) in dump_pids.iter().enumerate() {
        if let Some(row) = app.task_rows.get(pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { *pid };
            tgid_rank.entry(tgid).or_insert(i);
        }
    }
    dump_pids.sort_by(|a, b| {
        let r_a = app.task_rows.get(a).unwrap();
        let r_b = app.task_rows.get(b).unwrap();
        let tgid_a = if r_a.tgid > 0 { r_a.tgid } else { *a };
        let tgid_b = if r_b.tgid > 0 { r_b.tgid } else { *b };
        let rank_a = tgid_rank.get(&tgid_a).copied().unwrap_or(usize::MAX);
        let rank_b = tgid_rank.get(&tgid_b).copied().unwrap_or(usize::MAX);
        rank_a
            .cmp(&rank_b)
            .then_with(|| r_b.pelt_util.cmp(&r_a.pelt_util))
    });
    let dump_total_rows = dump_pids.len();
    let dump_group_count = tgid_rank.len();
    output.push_str(&format!(
        "dump: full {} of {} {} BPF-tracked rows across {} TGIDs ordered by grouped PELT activity dead_hidden={}\n",
        dump_pids.len(),
        dump_total_rows,
        if live_only { "live" } else { "tracked" },
        dump_group_count,
        dead_hidden,
    ));

    // Pre-compute thread counts per tgid
    let mut tgid_counts: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    for &pid in &dump_pids {
        if let Some(row) = app.task_rows.get(&pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { pid };
            *tgid_counts.entry(tgid).or_insert(0) += 1;
        }
    }
    let tgid_identities = build_tgid_identities(app);

    let mut last_tgid: u32 = 0;
    for &pid in &dump_pids {
        if let Some(row) = app.task_rows.get(&pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { pid };

            // Process group header
            if tgid != last_tgid {
                let count = tgid_counts.get(&tgid).copied().unwrap_or(1);
                let identity = tgid_identities
                    .get(&tgid)
                    .cloned()
                    .unwrap_or_else(|| fallback_tgid_identity(tgid, row));
                let proc_name = tgid_header_name(&identity);
                let group_role = tgid_roles
                    .get(&tgid)
                    .copied()
                    .unwrap_or(WorkloadRole::Other);
                if count > 1 || tgid != pid {
                    let health = format_tgid_health_summary(app, tgid, &dump_pids);
                    output.push_str(&format!(
                        "\n▼ {} (PID {} PPID {}) — {} threads [{}] {}\n",
                        proc_name,
                        tgid,
                        row.ppid,
                        count,
                        group_role.label(),
                        health,
                    ));
                    if let Some(wake_graph) = format_tgid_wake_graph(app, tgid) {
                        output.push_str(&wake_graph);
                    }
                }
                last_tgid = tgid;
            }

            let j_us = avg_jitter_us(row);
            let status_str = match row.status {
                TaskStatus::Alive => "●",
                TaskStatus::Idle => "○",
                TaskStatus::Dead => "✗",
            };
            let indent = if tgid != pid { "  " } else { "" };
            let cls_str = class_label(row);
            let last_wait_us = row.wait_duration_ns / 1000;
            let placement = placement_summary(row, &app.topology);
            let role = task_role(row, &tgid_roles);
            let wake_avg = |idx: usize| -> u64 {
                if row.wake_reason_count[idx] > 0 {
                    row.wake_reason_wait_ns[idx] / row.wake_reason_count[idx] as u64 / 1000
                } else {
                    0
                }
            };
            let wait_str = if row.status == TaskStatus::Dead && last_wait_us > 10000 {
                format!("{}†", last_wait_us)
            } else {
                format!("{}", last_wait_us)
            };
            output.push_str(&format!(
                "{}{:<5} {:<7} {:<3} {:<15} {:<4} {:<6.1} {:<8} {:<9} {:<6} {:<7} {:<18} {:<7.1} C{:<3} {:<5} {:<7} {:<5} {:<5} {:<6} {:<6} {:<6} {:<5.0} {:<4.0} {:<4.0} {:<7.1}\n",
                indent,
                row.ppid,
                row.pid,
                status_str,
                row.comm,
                cls_str,
                pelt_util_pct(row.pelt_util as u64),
                display_runtime_us(row.max_runtime_us),
                display_gap_us(row.dispatch_gap_us),
                j_us,
                wait_str,
                format_lifecycle_compact(row),
                row.runs_per_sec,
                row.core_placement,
                placement_spread_label(&placement),
                placement_residency_label(&placement),
                placement.smt_secondary_pct,
                row.select_cpu_ns,
                row.enqueue_ns,
                row.stopping_duration_ns,
                row.running_duration_ns,
                row.gate_hit_pcts[0],
                row.gate_hit_pcts[3],
                row.gate_hit_pcts[9],
                row.migrations_per_sec,
            ));
            // detail-A: gate % (FAST/NAT/TUN) + all extended fields, compact labels
            output.push_str(&format!(
                "{}  role={}/{} steer={}/{} path={}/{}/{} waker={} deps={}/{} dir={} q={}/{}/{} syld={} prmpt={} aff={} home=[{}] behind={} tsmt={:.1}%/{:.1}% sruns={}/{} life={} maxgap={} dsqins={}ns runs={} rt={}ms avgrt={}us rtms/s={:.1} slice_occ={}% llc=L{:02}/{} place=[{}|{} smt={}%] streak={} tgid={} cls={} v/icsw={}/{} wakeus<=5ms={}/{}/{} hwait<=5ms=[{}] whist={}/{}/{}/{}\n",
                indent,
                role.label(),
                capacity_band(row, role).label(),
                row.home_steer_hits,
                row.primary_steer_hits,
                select_path_label(row.last_select_path as usize),
                select_reason_short_label(row.last_select_reason as usize),
                place_class_label(row.last_place_class as usize),
                place_class_label(row.last_waker_place_class as usize),
                row.wake_same_tgid_count,
                row.wake_cross_tgid_count,
                row.direct_dispatch_count,
                row.quantum_full_count,
                row.quantum_yield_count,
                row.quantum_preempt_count,
                row.yield_count,
                row.preempt_count,
                affinity_label(row, &app.topology),
                home_quality_label(row),
                blocker_label(row, &app.task_rows),
                task_smt_contended_pct(row),
                task_smt_overlap_pct(row),
                row.smt_solo_runs,
                row.smt_contended_runs,
                format_startup_phase(row),
                display_gap_us(row.max_dispatch_gap_us), row.dsq_insert_ns, row.total_runs,
                format_runtime_ms(row.total_runtime_ns),
                avg_task_runtime_us(row),
                runtime_rate_ms(row),
                slice_occupancy_display_pct(row.slice_util_pct),
                row.llc_id,
                placement.active_llc_count,
                top_cpu_distribution(&row.cpu_run_count, &app.topology, 3),
                top_core_distribution(&row.cpu_run_count, &app.topology, 3),
                placement.smt_secondary_pct,
                row.same_cpu_streak,
                row.tgid,
                class_label(row),
                row.nvcsw_delta,
                row.nivcsw_delta,
                wake_avg(0), wake_avg(1), wake_avg(2),
                format_row_place_wait_summary(row),
                row.wait_hist[0], row.wait_hist[1], row.wait_hist[2], row.wait_hist[3],
            ));
        }
    }

    #[cfg(debug_assertions)]
    {
        let mut cost = app.debug_cost;
        cost.dump_us = dump_start.elapsed().as_micros() as u64;
        cost.anatomy_derive_us = anatomy_derive_us;
        append_debug_cost_section(&mut output, cost);
    }

    output
}

pub(super) fn format_stats_json(stats: &cake_stats, app: &TuiApp) -> String {
    let report = build_telemetry_report(stats, app);
    format_service_report_json(&build_service_report(stats, app, &report))
}
