// SPDX-License-Identifier: GPL-2.0

use super::report::build_telemetry_report;
use super::*;
use crate::telemetry_report::{
    AcceleratorSummary, CoverageItem, GraphSummary, HealthSummary, LifecycleSummary,
    TelemetryReport,
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use strum::{Display, EnumIter};

const SERVICE_SCHEMA_VERSION: u32 = 8;
const SERVICE_TEXT_VERSION: u32 = 4;
const ACCEL_NATIVE_ENTRY_IDX: usize = 0;

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(super) enum ServiceStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(super) enum MonitorState {
    Pass,
    Warn,
    Fail,
    NotReady,
}

impl MonitorState {
    fn score(self) -> u8 {
        match self {
            MonitorState::Pass => 100,
            MonitorState::Warn => 60,
            MonitorState::Fail => 20,
            MonitorState::NotReady => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(super) enum DiagnosticSeverity {
    Info,
    Warn,
    Fail,
}

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub(super) enum MonitorId {
    Telemetry,
    Prediction,
    FloorPath,
    TrustPrevDirect,
    Scoreboard,
    Fallback,
    WakeLatency,
    CallbackCost,
    History,
}

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub(super) enum DiagnosticCodeId {
    #[serde(rename = "CAKE-OBS-001")]
    #[strum(serialize = "CAKE-OBS-001")]
    CakeObs001,
    #[serde(rename = "CAKE-PRED-001")]
    #[strum(serialize = "CAKE-PRED-001")]
    CakePred001,
    #[serde(rename = "CAKE-FLOOR-002")]
    #[strum(serialize = "CAKE-FLOOR-002")]
    CakeFloor002,
    #[serde(rename = "CAKE-TRUST-010")]
    #[strum(serialize = "CAKE-TRUST-010")]
    CakeTrust010,
    #[serde(rename = "CAKE-SCORE-020")]
    #[strum(serialize = "CAKE-SCORE-020")]
    CakeScore020,
    #[serde(rename = "CAKE-FALL-030")]
    #[strum(serialize = "CAKE-FALL-030")]
    CakeFall030,
    #[serde(rename = "CAKE-WAKE-040")]
    #[strum(serialize = "CAKE-WAKE-040")]
    CakeWake040,
    #[serde(rename = "CAKE-COST-050")]
    #[strum(serialize = "CAKE-COST-050")]
    CakeCost050,
    #[serde(rename = "CAKE-HIST-060")]
    #[strum(serialize = "CAKE-HIST-060")]
    CakeHist060,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Metric {
    pub name: String,
    pub value: String,
    pub unit: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MonitorSnapshot {
    pub id: MonitorId,
    pub state: MonitorState,
    pub score: u8,
    pub source: String,
    pub window: String,
    pub summary: String,
    pub affected_cpus: Vec<u16>,
    pub affected_tasks: Vec<u32>,
    pub metrics: Vec<Metric>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct FreezeFrame {
    pub code: DiagnosticCodeId,
    pub elapsed_secs: u64,
    pub cpu: Option<u16>,
    pub tgid: Option<u32>,
    pub comm: Option<String>,
    pub summary: String,
    pub metrics: Vec<Metric>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DiagnosticCode {
    pub code: DiagnosticCodeId,
    pub severity: DiagnosticSeverity,
    pub active: bool,
    pub first_seen_secs: u64,
    pub last_seen_secs: u64,
    pub count: u64,
    pub summary: String,
    pub detail: String,
    pub affected_cpus: Vec<u16>,
    pub affected_tasks: Vec<u32>,
    pub freeze_frame: FreezeFrame,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct LiveData {
    pub trained_cpus: usize,
    pub route_ready_cpus: u64,
    pub floor_ready_cpus: u64,
    pub route_pred_attempts_60s: u64,
    pub route_pred_hits_60s: u64,
    pub route_pred_misses_60s: u64,
    pub route_pred_hit_pct_60s: f64,
    pub trust_prev_active_cpus: u64,
    pub trust_prev_enabled_cpus: u64,
    pub trust_prev_blocked_cpus: u64,
    pub trust_prev_attempts_60s: u64,
    pub trust_prev_hits_60s: u64,
    pub trust_prev_misses_60s: u64,
    pub trust_prev_hit_pct_60s: f64,
    pub trust_prev_demotions_60s: u64,
    pub trust_prev_demotions_per_sec: f64,
    pub native_fallback_60s: u64,
    pub native_fallback_per_sec: f64,
    pub scoreboard_attempts_60s: u64,
    pub scoreboard_claim_fail_60s: u64,
    pub scoreboard_claim_fail_pct_60s: f64,
    pub wake_ge5ms_60s: u64,
    pub wake_wait_max_us: u64,
    pub select_avg_ns_60s: u64,
    pub enqueue_avg_ns_60s: u64,
    pub running_avg_ns_60s: u64,
    pub stopping_avg_ns_60s: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct HistoryBucket {
    pub start_ago_secs: u64,
    pub end_ago_secs: u64,
    pub sample_secs: f64,
    pub samples: usize,
    pub route_pred_attempts: u64,
    pub route_pred_hits: u64,
    pub route_pred_misses: u64,
    pub route_pred_hit_pct: f64,
    pub trust_prev_attempts: u64,
    pub trust_prev_hits: u64,
    pub trust_prev_misses: u64,
    pub trust_prev_hit_pct: f64,
    pub native_fallbacks: u64,
    pub native_fallback_per_sec: f64,
    pub wake_ge5ms: u64,
    pub select_avg_ns: u64,
    pub enqueue_avg_ns: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct DiagnosticHistory {
    pub last60s: Vec<HistoryBucket>,
    pub last10m: Vec<HistoryBucket>,
    pub session: Vec<HistoryBucket>,
    pub note: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ServiceReport {
    pub schema_version: u32,
    pub text_version: u32,
    pub status: ServiceStatus,
    pub degraded_count: usize,
    pub uptime_secs: u64,
    pub health: HealthSummary,
    pub lifecycle: LifecycleSummary,
    pub accelerator: AcceleratorSummary,
    pub graph: GraphSummary,
    pub coverage: Vec<CoverageItem>,
    pub live_data: LiveData,
    pub monitors: Vec<MonitorSnapshot>,
    pub active_codes: Vec<DiagnosticCode>,
    pub code_history: Vec<DiagnosticCode>,
    pub freeze_frames: Vec<FreezeFrame>,
    pub history: DiagnosticHistory,
}

#[derive(Default)]
pub(super) struct DiagnosticRecorder {
    active: BTreeMap<DiagnosticCodeId, DiagnosticCode>,
    history: VecDeque<DiagnosticCode>,
}

impl DiagnosticRecorder {
    pub(super) fn update(&mut self, current: Vec<DiagnosticCode>) {
        let mut seen = BTreeMap::new();
        for code in current {
            seen.insert(code.code, code);
        }

        let previous = self.active.keys().copied().collect::<Vec<_>>();
        for code_id in previous {
            if !seen.contains_key(&code_id) {
                if let Some(mut cleared) = self.active.remove(&code_id) {
                    cleared.active = false;
                    self.push_history(cleared);
                }
            }
        }

        for (code_id, code) in seen {
            if let Some(active) = self.active.get_mut(&code_id) {
                active.last_seen_secs = code.last_seen_secs;
                active.count = active.count.saturating_add(1);
                active.severity = code.severity;
                active.summary = code.summary;
                active.detail = code.detail;
                active.affected_cpus = code.affected_cpus;
                active.affected_tasks = code.affected_tasks;
                active.freeze_frame = code.freeze_frame;
            } else {
                self.push_history(code.clone());
                self.active.insert(code_id, code);
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn clear(&mut self) {
        self.active.clear();
        self.history.clear();
    }

    fn has_observed(&self) -> bool {
        !self.active.is_empty() || !self.history.is_empty()
    }

    fn push_history(&mut self, code: DiagnosticCode) {
        self.history.push_back(code);
        while self.history.len() > 128 {
            self.history.pop_front();
        }
    }
}

pub(super) struct DiagnosticEvaluation {
    pub live_data: LiveData,
    pub monitors: Vec<MonitorSnapshot>,
    pub current_codes: Vec<DiagnosticCode>,
}

pub(super) fn evaluate_diagnostics(
    stats: &cake_stats,
    app: &TuiApp,
    report: &TelemetryReport,
) -> DiagnosticEvaluation {
    let live_data = build_live_data(stats, app, &report.accelerator);
    let monitors = build_monitors(app, report, &live_data);
    let current_codes = build_codes(app, report, &live_data, &monitors);
    DiagnosticEvaluation {
        live_data,
        monitors,
        current_codes,
    }
}

pub(super) fn build_service_report(
    stats: &cake_stats,
    app: &TuiApp,
    report: &TelemetryReport,
) -> ServiceReport {
    let evaluation = evaluate_diagnostics(stats, app, report);
    let active_codes = projected_active_codes(&evaluation.current_codes, &app.diagnostic_recorder);
    let code_history = projected_code_history(&active_codes, &app.diagnostic_recorder);
    let freeze_frames = projected_freeze_frames(&active_codes, &app.diagnostic_recorder);
    let status = if active_codes
        .iter()
        .any(|code| code.severity == DiagnosticSeverity::Fail)
    {
        ServiceStatus::Fail
    } else if active_codes
        .iter()
        .any(|code| code.severity == DiagnosticSeverity::Warn)
    {
        ServiceStatus::Warn
    } else {
        ServiceStatus::Ok
    };

    ServiceReport {
        schema_version: SERVICE_SCHEMA_VERSION,
        text_version: SERVICE_TEXT_VERSION,
        status,
        degraded_count: report.degraded_count(),
        uptime_secs: app.start_time.elapsed().as_secs(),
        health: report.health.clone(),
        lifecycle: report.lifecycle.clone(),
        accelerator: report.accelerator.clone(),
        graph: report.graph.clone(),
        coverage: report.coverage.clone(),
        live_data: evaluation.live_data,
        monitors: evaluation.monitors,
        code_history,
        active_codes,
        freeze_frames,
        history: build_history(app),
    }
}

fn projected_active_codes(
    current: &[DiagnosticCode],
    recorder: &DiagnosticRecorder,
) -> Vec<DiagnosticCode> {
    if !recorder.has_observed() {
        return current.to_vec();
    }

    current
        .iter()
        .map(|code| {
            let Some(previous) = recorder.active.get(&code.code) else {
                return code.clone();
            };
            let mut projected = previous.clone();
            projected.active = true;
            projected.last_seen_secs = code.last_seen_secs;
            projected.severity = code.severity;
            projected.summary = code.summary.clone();
            projected.detail = code.detail.clone();
            projected.affected_cpus = code.affected_cpus.clone();
            projected.affected_tasks = code.affected_tasks.clone();
            projected.freeze_frame = code.freeze_frame.clone();
            projected
        })
        .collect()
}

fn projected_code_history(
    active_codes: &[DiagnosticCode],
    recorder: &DiagnosticRecorder,
) -> Vec<DiagnosticCode> {
    if !recorder.has_observed() {
        return active_codes.to_vec();
    }

    recorder
        .history
        .iter()
        .cloned()
        .chain(active_codes.iter().cloned())
        .collect()
}

fn projected_freeze_frames(
    active_codes: &[DiagnosticCode],
    recorder: &DiagnosticRecorder,
) -> Vec<FreezeFrame> {
    if !recorder.has_observed() {
        return active_codes
            .iter()
            .map(|code| code.freeze_frame.clone())
            .collect();
    }

    active_codes
        .iter()
        .map(|code| code.freeze_frame.clone())
        .chain(
            recorder
                .history
                .iter()
                .rev()
                .take(24)
                .map(|code| code.freeze_frame.clone()),
        )
        .collect()
}

pub(super) fn draw_live_data_tab(frame: &mut Frame, app: &TuiApp, stats: &cake_stats, area: Rect) {
    let report = build_telemetry_report(stats, app);
    let service = build_service_report(stats, app, &report);
    let layout = Layout::vertical([
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Min(10),
    ])
    .split(area);
    let live = &service.live_data;
    let trained = live.trained_cpus as u64;
    let route_gap = trained.saturating_sub(live.route_ready_cpus);
    let floor_gap = trained.saturating_sub(live.floor_ready_cpus);
    let top_code = top_active_code_label(&service);
    let top_code_style = top_active_code_style(&service);
    let data_source = data_source_label(&service);
    let data_source_style = monitor_state(&service, MonitorId::Telemetry)
        .map(monitor_state_style)
        .unwrap_or_else(|| Style::default().fg(Color::DarkGray));
    let top = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Policy health "),
            dashboard_value(
                service_status_user_label(service.status),
                service_status_style(service.status),
            ),
            dashboard_sep("  "),
            dashboard_label("Active codes "),
            dashboard_value(
                service.active_codes.len().to_string(),
                low_is_good_style(service.active_codes.len() as u64, 1, 3),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Data source "),
            dashboard_value(data_source, data_source_style),
        ]),
        Line::from(vec![
            dashboard_label("Top code "),
            dashboard_value(top_code, top_code_style),
        ]),
        Line::from(vec![
            dashboard_label("CPU ready "),
            dashboard_value(
                format!(
                    "trained={}/{} route={}/{} floor={}/{} gap route={} floor={}",
                    live.trained_cpus,
                    app.topology.nr_cpus,
                    live.route_ready_cpus,
                    live.trained_cpus,
                    live.floor_ready_cpus,
                    live.trained_cpus,
                    route_gap,
                    floor_gap
                ),
                readiness_style(live),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Route pred "),
            dashboard_value(
                format!(
                    "hit {:.1}% attempts={} hits={} misses={}",
                    live.route_pred_hit_pct_60s,
                    compact_count(live.route_pred_attempts_60s),
                    compact_count(live.route_pred_hits_60s),
                    compact_count(live.route_pred_misses_60s)
                ),
                pct_style(live.route_pred_hit_pct_60s, 98.0, 95.0),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Read as "),
            dashboard_value(readiness_takeaway(live), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            dashboard_label("Meaning "),
            dashboard_value(
                service_status_meaning(service.status),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Goal "),
            dashboard_value(
                "trained=all CPUs, floor=all trained, route pred >=98%",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Use "),
            dashboard_value(
                "Monitors show the full scorecard; Codes explain active problems",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ])
    .block(dashboard_block(
        "Live Data - Health & Readiness",
        Color::Cyan,
    ));
    frame.render_widget(top, layout[0]);

    let mid = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Prev direct "),
            dashboard_value(
                format!(
                    "active/enabled/blocked {}/{}/{} hit {:.1}% demote {:.2}/s",
                    live.trust_prev_active_cpus,
                    live.trust_prev_enabled_cpus,
                    live.trust_prev_blocked_cpus,
                    live.trust_prev_hit_pct_60s,
                    live.trust_prev_demotions_per_sec
                ),
                trust_prev_style(live),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Native fallback "),
            dashboard_value(
                format!(
                    "{:.1}/s total60={}",
                    live.native_fallback_per_sec,
                    compact_count(live.native_fallback_60s)
                ),
                low_is_good_style(live.native_fallback_per_sec as u64, 500, 2000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Scoreboard "),
            dashboard_value(
                format!(
                    "claim_fail {:.1}% fails={} attempts={}",
                    live.scoreboard_claim_fail_pct_60s,
                    compact_count(live.scoreboard_claim_fail_60s),
                    compact_count(live.scoreboard_attempts_60s)
                ),
                low_is_good_style(live.scoreboard_claim_fail_pct_60s as u64, 5, 15),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Read as "),
            dashboard_value(fast_path_takeaway(live), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            dashboard_label("Goal "),
            dashboard_value(
                "demote <0.25/s, fallback <500/s, claim_fail <5%",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Why care "),
            dashboard_value(
                "each trusted claim can skip broader probes and native fallback work",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ])
    .block(dashboard_block("Live Data - Fast Path", Color::Green));
    frame.render_widget(mid, layout[1]);

    let bottom = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Wake tail "),
            dashboard_value(
                format!(
                    ">=5ms={} max={}us",
                    live.wake_ge5ms_60s, live.wake_wait_max_us
                ),
                low_is_good_style(live.wake_wait_max_us, 5000, 10000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Callback avg ns "),
            dashboard_value(
                format!(
                    "select={} enqueue={} running={} stopping={}",
                    live.select_avg_ns_60s,
                    live.enqueue_avg_ns_60s,
                    live.running_avg_ns_60s,
                    live.stopping_avg_ns_60s
                ),
                callback_style(live),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Read as "),
            dashboard_value(latency_takeaway(live), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            dashboard_label("Goal "),
            dashboard_value(
                "wake >=5ms stays 0, max <5000us, callback averages <1000ns",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Next "),
            dashboard_value(
                "if this is green but games feel bad, inspect Apps and Topology",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ])
    .block(dashboard_block("Live Data - Latency", Color::Yellow));
    frame.render_widget(bottom, layout[2]);
}

pub(super) fn draw_monitors_tab(frame: &mut Frame, app: &TuiApp, stats: &cake_stats, area: Rect) {
    let report = build_telemetry_report(stats, app);
    let service = build_service_report(stats, app, &report);
    let layout = Layout::vertical([Constraint::Length(8), Constraint::Min(8)]).split(area);
    let pass = monitor_count(&service, MonitorState::Pass);
    let warn = monitor_count(&service, MonitorState::Warn);
    let fail = monitor_count(&service, MonitorState::Fail);
    let not_ready = monitor_count(&service, MonitorState::NotReady);

    let guide = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Purpose "),
            dashboard_value(
                "Monitors are the scheduler scorecard: each row checks one subsystem against a threshold.",
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            dashboard_label("States "),
            dashboard_value(
                monitor_state_user_label(MonitorState::Pass),
                monitor_state_style(MonitorState::Pass),
            ),
            dashboard_note(" healthy  "),
            dashboard_value(
                monitor_state_user_label(MonitorState::Warn),
                monitor_state_style(MonitorState::Warn),
            ),
            dashboard_note(" degraded  "),
            dashboard_value(
                monitor_state_user_label(MonitorState::Fail),
                monitor_state_style(MonitorState::Fail),
            ),
            dashboard_note(" crossed threshold  "),
            dashboard_value(
                monitor_state_user_label(MonitorState::NotReady),
                monitor_state_style(MonitorState::NotReady),
            ),
            dashboard_note(" warming up"),
        ]),
        Line::from(vec![
            dashboard_label("Score "),
            dashboard_value("100/60/20/0", Style::default().fg(Color::Cyan)),
            dashboard_note(" is a triage weight, not a performance percent"),
        ]),
        Line::from(vec![
            dashboard_label("Read "),
            dashboard_value(
                format!(
                    "pass={} warn={} action={} warmup={}  inspect action/warn first",
                    pass, warn, fail, not_ready
                ),
                service_status_style(service.status),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Use "),
            dashboard_value(
                "Live Data gives the plain read; Codes gives evidence/freeze frames; Trends shows if it persists.",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ])
    .block(dashboard_block("Monitor Guide", Color::LightGreen))
    .wrap(Wrap { trim: false });
    frame.render_widget(guide, layout[0]);

    let rows = service.monitors.iter().map(|monitor| {
        Row::new(vec![
            Cell::from(monitor_label(monitor.id)).style(Style::default().fg(Color::Cyan)),
            Cell::from(monitor_state_user_label(monitor.state))
                .style(monitor_state_style(monitor.state)),
            Cell::from(monitor.score.to_string()),
            Cell::from(monitor.window.clone()),
            Cell::from(monitor_checks(monitor.id)),
            Cell::from(monitor_read_as(monitor)),
            Cell::from(monitor_next_step(monitor)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(12),
            Constraint::Length(30),
            Constraint::Length(42),
            Constraint::Min(34),
        ],
    )
    .header(Row::new(vec![
        "Monitor",
        "State",
        "Score",
        "Window",
        "Checks",
        "Current Read",
        "Next",
    ]))
    .block(dashboard_block("Monitor Scorecard", Color::LightGreen));
    frame.render_widget(table, layout[1]);
}

pub(super) fn draw_codes_tab(frame: &mut Frame, app: &TuiApp, stats: &cake_stats, area: Rect) {
    let report = build_telemetry_report(stats, app);
    let service = build_service_report(stats, app, &report);
    let layout =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
    let rows = service.active_codes.iter().map(|code| {
        Row::new(vec![
            Cell::from(code.code.to_string()).style(Style::default().fg(Color::Yellow)),
            Cell::from(code.severity.to_string()).style(severity_style(code.severity)),
            Cell::from(code.count.to_string()),
            Cell::from(format!("{}s", code.first_seen_secs)),
            Cell::from(format!("{}s", code.last_seen_secs)),
            Cell::from(format_cpu_list(&code.affected_cpus)),
            Cell::from(code.summary.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(18),
            Constraint::Min(24),
        ],
    )
    .header(Row::new(vec![
        "Code", "Severity", "Count", "First", "Last", "CPUs", "Summary",
    ]))
    .block(dashboard_block("Diagnostic Codes", Color::LightRed));
    frame.render_widget(table, layout[0]);

    let frame_rows = service.freeze_frames.iter().take(12).map(|frame| {
        Row::new(vec![
            Cell::from(frame.code.to_string()).style(Style::default().fg(Color::Yellow)),
            Cell::from(format!("{}s", frame.elapsed_secs)),
            Cell::from(
                frame
                    .cpu
                    .map(|cpu| format!("C{:02}", cpu))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(frame.comm.clone().unwrap_or_else(|| "-".to_string())),
            Cell::from(frame.summary.clone()),
        ])
    });
    let frames = Table::new(
        frame_rows,
        [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(24),
            Constraint::Min(30),
        ],
    )
    .header(Row::new(vec!["Code", "At", "CPU", "App", "Freeze Frame"]))
    .block(dashboard_block("Freeze Frames", Color::LightMagenta));
    frame.render_widget(frames, layout[1]);
}

pub(super) fn format_service_report_json(report: &ServiceReport) -> String {
    match serde_json::to_string_pretty(report) {
        Ok(mut json) => {
            json.push('\n');
            json
        }
        Err(err) => format!(
            "{{\"schema_version\":{},\"status\":\"fail\",\"error\":\"{}\"}}\n",
            SERVICE_SCHEMA_VERSION, err
        ),
    }
}

pub(super) fn format_service_report_text(report: &ServiceReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "service.header: schema={} text={} status={} uptime={}s degraded={} monitors={} active_codes={} freeze_frames={}\n",
        report.schema_version,
        report.text_version,
        service_status_user_label(report.status),
        report.uptime_secs,
        report.degraded_count,
        report.monitors.len(),
        report.active_codes.len(),
        report.freeze_frames.len(),
    ));
    out.push_str(&format!(
        "readiness: pass={} warn={} action={} warmup={}\n",
        report
            .monitors
            .iter()
            .filter(|monitor| monitor.state == MonitorState::Pass)
            .count(),
        report
            .monitors
            .iter()
            .filter(|monitor| monitor.state == MonitorState::Warn)
            .count(),
        report
            .monitors
            .iter()
            .filter(|monitor| monitor.state == MonitorState::Fail)
            .count(),
        report
            .monitors
            .iter()
            .filter(|monitor| monitor.state == MonitorState::NotReady)
            .count(),
    ));
    out.push_str("readiness.monitors:\n");
    for monitor in &report.monitors {
        out.push_str(&format!(
            "  id={} state={} score={} window={} source={} cpus={} tasks={} summary={}\n",
            monitor.id,
            monitor_state_user_label(monitor.state),
            monitor.score,
            monitor.window,
            monitor.source,
            format_cpu_list(&monitor.affected_cpus),
            format_task_list(&monitor.affected_tasks),
            monitor.summary,
        ));
    }
    out.push_str("dtc.active:\n");
    if report.active_codes.is_empty() {
        out.push_str("  none\n");
    } else {
        for code in &report.active_codes {
            out.push_str(&format!(
                "  code={} severity={} count={} first=t+{}s last=t+{}s cpus={} summary={}\n",
                code.code,
                code.severity,
                code.count,
                code.first_seen_secs,
                code.last_seen_secs,
                format_cpu_list(&code.affected_cpus),
                code.summary,
            ));
        }
    }
    out.push_str("freeze_frames:\n");
    if report.freeze_frames.is_empty() {
        out.push_str("  none\n");
    } else {
        for frame in report.freeze_frames.iter().take(12) {
            out.push_str(&format!(
                "  code={} t+{}s cpu={} tgid={} comm={} summary={} metrics={}\n",
                frame.code,
                frame.elapsed_secs,
                frame
                    .cpu
                    .map(|cpu| format!("C{:02}", cpu))
                    .unwrap_or_else(|| "-".to_string()),
                frame
                    .tgid
                    .map(|tgid| tgid.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                frame.comm.as_deref().unwrap_or("-"),
                frame.summary,
                format_metrics(&frame.metrics),
            ));
        }
    }
    out.push_str(&format!(
        "live_data.snapshot: trained={} route_ready={} floor_ready={} route_pred60={}/{}/{}({:.1}%) trust_prev[state active/enabled/blocked]={}/{}/{} trust_prev60={}/{}/{}({:.1}%) demote60={}({:.2}/s) native60={}({:.1}/s) score_claim_fail60={}/{:.1}% wake_ge5ms60={} wake_max60={}us cbns[sel/enq/run/stop]={}/{}/{}/{}\n",
        report.live_data.trained_cpus,
        report.live_data.route_ready_cpus,
        report.live_data.floor_ready_cpus,
        report.live_data.route_pred_attempts_60s,
        report.live_data.route_pred_hits_60s,
        report.live_data.route_pred_misses_60s,
        report.live_data.route_pred_hit_pct_60s,
        report.live_data.trust_prev_active_cpus,
        report.live_data.trust_prev_enabled_cpus,
        report.live_data.trust_prev_blocked_cpus,
        report.live_data.trust_prev_attempts_60s,
        report.live_data.trust_prev_hits_60s,
        report.live_data.trust_prev_misses_60s,
        report.live_data.trust_prev_hit_pct_60s,
        report.live_data.trust_prev_demotions_60s,
        report.live_data.trust_prev_demotions_per_sec,
        report.live_data.native_fallback_60s,
        report.live_data.native_fallback_per_sec,
        report.live_data.scoreboard_claim_fail_60s,
        report.live_data.scoreboard_claim_fail_pct_60s,
        report.live_data.wake_ge5ms_60s,
        report.live_data.wake_wait_max_us,
        report.live_data.select_avg_ns_60s,
        report.live_data.enqueue_avg_ns_60s,
        report.live_data.running_avg_ns_60s,
        report.live_data.stopping_avg_ns_60s,
    ));
    out.push_str(&format!(
        "history.summary: last60s={} last10m={} session={} note={}\n",
        report.history.last60s.len(),
        report.history.last10m.len(),
        report.history.session.len(),
        report.history.note,
    ));
    append_history_text(&mut out, "history.last60s", &report.history.last60s, 12);
    append_history_text(&mut out, "history.last10m", &report.history.last10m, 12);
    append_history_text(&mut out, "history.session", &report.history.session, 12);
    out
}

fn build_live_data(stats: &cake_stats, app: &TuiApp, accelerator: &AcceleratorSummary) -> LiveData {
    let (stats_elapsed, stats_window) = app
        .windowed_stats(stats, Duration::from_secs(60))
        .unwrap_or_else(|| (app.start_time.elapsed().max(Duration::from_secs(1)), *stats));
    let secs = stats_elapsed.as_secs_f64().max(0.1);
    let (work_elapsed, work_window) =
        app.cpu_work_window(Duration::from_secs(60))
            .unwrap_or_else(|| {
                (
                    app.start_time.elapsed().max(Duration::from_secs(1)),
                    app.per_cpu_work.clone(),
                )
            });
    let work_secs = work_elapsed.as_secs_f64().max(0.1);
    let route_pred_attempts = route_total(&stats_window.accel_route_attempt_count);
    let route_pred_hits = route_total(&stats_window.accel_route_hit_count);
    let route_pred_misses = route_total(&stats_window.accel_route_miss_count);
    let trust_prev_attempts = stats_window.accel_trust_prev_attempt;
    let trust_prev_hits = stats_window.accel_trust_prev_hit;
    let trust_prev_misses = stats_window.accel_trust_prev_miss;
    let trust_demotions = work_window
        .iter()
        .map(|counter| counter.trust.demotion_count as u64)
        .sum();
    let native_fallback = native_fallback_entries(&stats_window);
    let scoreboard_attempts = route_total(&stats_window.accel_fast_attempt_count);
    let scoreboard_claim_fail = stats_window
        .accel_scoreboard_probe_count
        .iter()
        .map(|route| route[4])
        .sum();

    LiveData {
        trained_cpus: accelerator.trained_cpus,
        route_ready_cpus: accelerator.route_ready_cpus,
        floor_ready_cpus: accelerator.floor_ready_cpus,
        route_pred_attempts_60s: route_pred_attempts,
        route_pred_hits_60s: route_pred_hits,
        route_pred_misses_60s: route_pred_misses,
        route_pred_hit_pct_60s: pct(route_pred_hits, route_pred_hits + route_pred_misses),
        trust_prev_active_cpus: accelerator.trust_prev_active_cpus,
        trust_prev_enabled_cpus: accelerator.trust_prev_enabled_cpus,
        trust_prev_blocked_cpus: accelerator.trust_prev_blocked_cpus,
        trust_prev_attempts_60s: trust_prev_attempts,
        trust_prev_hits_60s: trust_prev_hits,
        trust_prev_misses_60s: trust_prev_misses,
        trust_prev_hit_pct_60s: pct(trust_prev_hits, trust_prev_attempts),
        trust_prev_demotions_60s: trust_demotions,
        trust_prev_demotions_per_sec: per_sec(trust_demotions, work_secs),
        native_fallback_60s: native_fallback,
        native_fallback_per_sec: per_sec(native_fallback, secs),
        scoreboard_attempts_60s: scoreboard_attempts,
        scoreboard_claim_fail_60s: scoreboard_claim_fail,
        scoreboard_claim_fail_pct_60s: pct(scoreboard_claim_fail, scoreboard_attempts),
        wake_ge5ms_60s: wake_ge5ms(&stats_window),
        wake_wait_max_us: wake_wait_all_max_us(&stats_window),
        select_avg_ns_60s: avg_ns(
            stats_window.total_select_cpu_ns,
            stats_window.nr_select_cpu_calls,
        ),
        enqueue_avg_ns_60s: avg_ns(
            stats_window.total_enqueue_latency_ns,
            stats_window.nr_enqueue_calls,
        ),
        running_avg_ns_60s: avg_ns(stats_window.total_running_ns, stats_window.nr_running_calls),
        stopping_avg_ns_60s: avg_ns(
            stats_window.total_stopping_ns,
            stats_window.nr_stopping_calls,
        ),
    }
}

fn build_monitors(app: &TuiApp, report: &TelemetryReport, live: &LiveData) -> Vec<MonitorSnapshot> {
    let mut monitors = Vec::new();
    let floor_blocked = floor_blocked_cpus(app);
    let trust_blocked = trust_blocked_cpus(app);
    let coverage_state = if report.degraded_count() == 0 {
        MonitorState::Pass
    } else {
        MonitorState::Warn
    };
    monitors.push(monitor(
        MonitorId::Telemetry,
        coverage_state,
        monitor_input(
            "runtime",
            "coverage",
            format!(
                "coverage degraded={} sections={} timeline={}/{}",
                report.degraded_count(),
                report.coverage.len(),
                report.health.timeline_samples,
                report.health.timeline_expected
            ),
            Vec::new(),
            Vec::new(),
            vec![metric("degraded", report.degraded_count(), "sections")],
        ),
    ));

    let pred_state = if live.route_pred_attempts_60s < 1_000 {
        MonitorState::NotReady
    } else if live.route_pred_hit_pct_60s < 95.0 {
        MonitorState::Fail
    } else if live.route_pred_hit_pct_60s < 98.0 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::Prediction,
        pred_state,
        monitor_input(
            "60s",
            "accel_route_*",
            format!(
                "route predictor {:.1}% over {} attempts",
                live.route_pred_hit_pct_60s, live.route_pred_attempts_60s
            ),
            Vec::new(),
            Vec::new(),
            vec![
                metric("attempts", live.route_pred_attempts_60s, "count"),
                metric(
                    "hit_pct",
                    format!("{:.1}", live.route_pred_hit_pct_60s),
                    "%",
                ),
            ],
        ),
    ));

    let floor_state = if live.trained_cpus == 0 {
        MonitorState::NotReady
    } else {
        let floor_pct = pct(live.floor_ready_cpus, live.trained_cpus as u64);
        if floor_pct < 75.0 {
            MonitorState::Fail
        } else if live.floor_ready_cpus < live.trained_cpus as u64 {
            MonitorState::Warn
        } else {
            MonitorState::Pass
        }
    };
    monitors.push(monitor(
        MonitorId::FloorPath,
        floor_state,
        monitor_input(
            "snapshot",
            "cpu_bss.decision_confidence",
            format!(
                "floor_ready={}/{} route_ready={}",
                live.floor_ready_cpus, live.trained_cpus, live.route_ready_cpus
            ),
            floor_blocked,
            Vec::new(),
            vec![
                metric("floor_ready", live.floor_ready_cpus, "cpus"),
                metric("trained", live.trained_cpus, "cpus"),
            ],
        ),
    ));

    let trust_state = if live.trust_prev_attempts_60s < 100 && live.trust_prev_active_cpus == 0 {
        MonitorState::NotReady
    } else if live.trust_prev_hit_pct_60s < 95.0 || live.trust_prev_demotions_per_sec > 1.0 {
        MonitorState::Fail
    } else if live.trust_prev_hit_pct_60s < 99.0 || live.trust_prev_demotions_per_sec > 0.25 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::TrustPrevDirect,
        trust_state,
        monitor_input(
            "60s+snapshot",
            "trust_user/trust_bpf+accel_trust_prev_*",
            format!(
                "active={} hit={:.1}% demote={:.2}/s",
                live.trust_prev_active_cpus,
                live.trust_prev_hit_pct_60s,
                live.trust_prev_demotions_per_sec
            ),
            trust_blocked,
            Vec::new(),
            vec![
                metric("active", live.trust_prev_active_cpus, "cpus"),
                metric(
                    "hit_pct",
                    format!("{:.1}", live.trust_prev_hit_pct_60s),
                    "%",
                ),
                metric(
                    "demotions_per_sec",
                    format!("{:.2}", live.trust_prev_demotions_per_sec),
                    "/s",
                ),
            ],
        ),
    ));

    let scoreboard_state = if live.scoreboard_attempts_60s < 100 {
        MonitorState::NotReady
    } else if live.scoreboard_claim_fail_pct_60s > 15.0 {
        MonitorState::Fail
    } else if live.scoreboard_claim_fail_pct_60s > 5.0 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::Scoreboard,
        scoreboard_state,
        monitor_input(
            "60s",
            "accel_fast_*+scoreboard_probe",
            format!(
                "claim_fail={}/{:.1}% attempts={}",
                live.scoreboard_claim_fail_60s,
                live.scoreboard_claim_fail_pct_60s,
                live.scoreboard_attempts_60s
            ),
            Vec::new(),
            Vec::new(),
            vec![
                metric("attempts", live.scoreboard_attempts_60s, "count"),
                metric("claim_fail", live.scoreboard_claim_fail_60s, "count"),
            ],
        ),
    ));

    let fallback_state = if live.native_fallback_per_sec > 2_000.0 {
        MonitorState::Fail
    } else if live.native_fallback_per_sec > 500.0 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::Fallback,
        fallback_state,
        monitor_input(
            "60s",
            "accel_native_fallback_count[entry]",
            format!("native fallback {:.1}/s", live.native_fallback_per_sec),
            Vec::new(),
            Vec::new(),
            vec![metric(
                "native_fallback_per_sec",
                format!("{:.1}", live.native_fallback_per_sec),
                "/s",
            )],
        ),
    ));

    let wake_state = if live.wake_wait_max_us > 10_000 || live.wake_ge5ms_60s > 0 {
        MonitorState::Fail
    } else if live.wake_wait_max_us > 5_000 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::WakeLatency,
        wake_state,
        monitor_input(
            "60s+snapshot",
            "wake buckets+wakewait.all",
            format!(
                "wake_ge5ms={} max={}us",
                live.wake_ge5ms_60s, live.wake_wait_max_us
            ),
            Vec::new(),
            Vec::new(),
            vec![
                metric("wake_ge5ms", live.wake_ge5ms_60s, "count"),
                metric("wake_wait_max", live.wake_wait_max_us, "us"),
            ],
        ),
    ));

    let callback_max = [
        live.select_avg_ns_60s,
        live.enqueue_avg_ns_60s,
        live.running_avg_ns_60s,
        live.stopping_avg_ns_60s,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let cost_state = if callback_max > 5_000 {
        MonitorState::Fail
    } else if callback_max > 1_000 {
        MonitorState::Warn
    } else {
        MonitorState::Pass
    };
    monitors.push(monitor(
        MonitorId::CallbackCost,
        cost_state,
        monitor_input(
            "60s",
            "callback stopwatches",
            format!("max_avg_callback={}ns", callback_max),
            Vec::new(),
            Vec::new(),
            vec![
                metric("select_avg", live.select_avg_ns_60s, "ns"),
                metric("enqueue_avg", live.enqueue_avg_ns_60s, "ns"),
                metric("running_avg", live.running_avg_ns_60s, "ns"),
                metric("stopping_avg", live.stopping_avg_ns_60s, "ns"),
            ],
        ),
    ));

    let history_state =
        if report.health.timeline_samples >= report.health.timeline_expected.saturating_sub(2) {
            MonitorState::Pass
        } else {
            MonitorState::Warn
        };
    monitors.push(monitor(
        MonitorId::History,
        history_state,
        monitor_input(
            "last60s",
            "timeline_history",
            format!(
                "timeline samples {}/{}",
                report.health.timeline_samples, report.health.timeline_expected
            ),
            Vec::new(),
            Vec::new(),
            vec![
                metric("samples", report.health.timeline_samples, "count"),
                metric("expected", report.health.timeline_expected, "count"),
            ],
        ),
    ));

    monitors
}

fn build_codes(
    app: &TuiApp,
    report: &TelemetryReport,
    live: &LiveData,
    monitors: &[MonitorSnapshot],
) -> Vec<DiagnosticCode> {
    let mut codes = Vec::new();
    for monitor in monitors {
        let Some((code, fail_summary, warn_summary)) = code_for_monitor(monitor.id) else {
            continue;
        };
        let severity = match monitor.state {
            MonitorState::Fail => DiagnosticSeverity::Fail,
            MonitorState::Warn => DiagnosticSeverity::Warn,
            MonitorState::Pass | MonitorState::NotReady => continue,
        };
        let summary = if severity == DiagnosticSeverity::Fail {
            fail_summary
        } else {
            warn_summary
        };
        codes.push(diagnostic_code(
            app,
            code,
            severity,
            diagnostic_code_input(
                summary,
                monitor.summary.clone(),
                monitor.affected_cpus.clone(),
                monitor.affected_tasks.clone(),
                monitor.metrics.clone(),
            ),
        ));
    }

    if report.degraded_count() > 0
        && !codes
            .iter()
            .any(|code| code.code == DiagnosticCodeId::CakeObs001)
    {
        codes.push(diagnostic_code(
            app,
            DiagnosticCodeId::CakeObs001,
            DiagnosticSeverity::Warn,
            diagnostic_code_input(
                "telemetry coverage degraded",
                format!("degraded sections={}", report.degraded_count()),
                Vec::new(),
                Vec::new(),
                vec![metric("degraded", report.degraded_count(), "sections")],
            ),
        ));
    }
    if live.native_fallback_per_sec > 2_000.0
        && !codes
            .iter()
            .any(|code| code.code == DiagnosticCodeId::CakeFall030)
    {
        codes.push(diagnostic_code(
            app,
            DiagnosticCodeId::CakeFall030,
            DiagnosticSeverity::Fail,
            diagnostic_code_input(
                "native fallback storm",
                format!("native fallback {:.1}/s", live.native_fallback_per_sec),
                Vec::new(),
                Vec::new(),
                vec![metric(
                    "native_fallback_per_sec",
                    format!("{:.1}", live.native_fallback_per_sec),
                    "/s",
                )],
            ),
        ));
    }

    codes.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.code.to_string().cmp(&b.code.to_string()))
    });
    codes
}

fn code_for_monitor(monitor: MonitorId) -> Option<(DiagnosticCodeId, &'static str, &'static str)> {
    match monitor {
        MonitorId::Telemetry => Some((
            DiagnosticCodeId::CakeObs001,
            "telemetry source failed",
            "telemetry source degraded",
        )),
        MonitorId::Prediction => Some((
            DiagnosticCodeId::CakePred001,
            "route predictor hit rate failed",
            "route predictor hit rate below target",
        )),
        MonitorId::FloorPath => Some((
            DiagnosticCodeId::CakeFloor002,
            "floor path readiness failed",
            "floor path not ready on all trained CPUs",
        )),
        MonitorId::TrustPrevDirect => Some((
            DiagnosticCodeId::CakeTrust010,
            "trust.prev_direct failed",
            "trust.prev_direct unstable",
        )),
        MonitorId::Scoreboard => Some((
            DiagnosticCodeId::CakeScore020,
            "scoreboard claim failures high",
            "scoreboard claim failures above target",
        )),
        MonitorId::Fallback => Some((
            DiagnosticCodeId::CakeFall030,
            "native fallback rate failed",
            "native fallback rate above target",
        )),
        MonitorId::WakeLatency => Some((
            DiagnosticCodeId::CakeWake040,
            "wake latency tail detected",
            "wake latency tail elevated",
        )),
        MonitorId::CallbackCost => Some((
            DiagnosticCodeId::CakeCost050,
            "callback cost failed",
            "callback cost above target",
        )),
        MonitorId::History => Some((
            DiagnosticCodeId::CakeHist060,
            "history coverage failed",
            "history coverage incomplete",
        )),
    }
}

struct DiagnosticCodeInput {
    summary: String,
    detail: String,
    affected_cpus: Vec<u16>,
    affected_tasks: Vec<u32>,
    metrics: Vec<Metric>,
}

fn diagnostic_code_input(
    summary: impl Into<String>,
    detail: impl Into<String>,
    affected_cpus: Vec<u16>,
    affected_tasks: Vec<u32>,
    metrics: Vec<Metric>,
) -> DiagnosticCodeInput {
    DiagnosticCodeInput {
        summary: summary.into(),
        detail: detail.into(),
        affected_cpus,
        affected_tasks,
        metrics,
    }
}

fn diagnostic_code(
    app: &TuiApp,
    code: DiagnosticCodeId,
    severity: DiagnosticSeverity,
    input: DiagnosticCodeInput,
) -> DiagnosticCode {
    let elapsed_secs = app.start_time.elapsed().as_secs();
    let (tgid, comm) = focused_app_identity(app);
    let DiagnosticCodeInput {
        summary,
        detail,
        affected_cpus,
        affected_tasks,
        metrics,
    } = input;
    let freeze_frame = FreezeFrame {
        code,
        elapsed_secs,
        cpu: affected_cpus.first().copied(),
        tgid,
        comm,
        summary: detail.clone(),
        metrics: metrics.clone(),
    };
    DiagnosticCode {
        code,
        severity,
        active: true,
        first_seen_secs: elapsed_secs,
        last_seen_secs: elapsed_secs,
        count: 1,
        summary,
        detail,
        affected_cpus,
        affected_tasks,
        freeze_frame,
    }
}

fn build_history(app: &TuiApp) -> DiagnosticHistory {
    let retained = app.retained_timeline_samples();
    DiagnosticHistory {
        last60s: aggregate_history(&retained, 60, 1, 60),
        last10m: aggregate_history(&retained, 600, 5, 120),
        session: aggregate_history(&retained, u64::MAX, 60, 120),
        note: "1s buckets are retained in userspace; 5s and 60s buckets are derived at dump time"
            .to_string(),
    }
}

fn aggregate_history(
    samples: &[TimelineSample],
    max_age_secs: u64,
    bucket_secs: usize,
    max_buckets: usize,
) -> Vec<HistoryBucket> {
    let filtered = samples
        .iter()
        .filter(|sample| sample.end_ago_secs <= max_age_secs)
        .collect::<Vec<_>>();
    if filtered.is_empty() || bucket_secs == 0 {
        return Vec::new();
    }

    let start = filtered
        .len()
        .saturating_sub(bucket_secs.saturating_mul(max_buckets));
    filtered[start..]
        .chunks(bucket_secs)
        .filter_map(history_bucket_from_samples)
        .collect()
}

fn history_bucket_from_samples(samples: &[&TimelineSample]) -> Option<HistoryBucket> {
    let first = samples.first()?;
    let last = samples.last()?;
    let sample_secs: f64 = samples
        .iter()
        .map(|sample| sample.elapsed.as_secs_f64())
        .sum();
    let mut route_attempts = 0_u64;
    let mut route_hits = 0_u64;
    let mut route_misses = 0_u64;
    let mut trust_attempts = 0_u64;
    let mut trust_hits = 0_u64;
    let mut trust_misses = 0_u64;
    let mut native_fallbacks = 0_u64;
    let mut wake_tail = 0_u64;
    let mut select_ns = 0_u64;
    let mut select_count = 0_u64;
    let mut enqueue_ns = 0_u64;
    let mut enqueue_count = 0_u64;

    for sample in samples {
        route_attempts =
            route_attempts.saturating_add(route_total(&sample.stats.accel_route_attempt_count));
        route_hits = route_hits.saturating_add(route_total(&sample.stats.accel_route_hit_count));
        route_misses =
            route_misses.saturating_add(route_total(&sample.stats.accel_route_miss_count));
        trust_attempts = trust_attempts.saturating_add(sample.stats.accel_trust_prev_attempt);
        trust_hits = trust_hits.saturating_add(sample.stats.accel_trust_prev_hit);
        trust_misses = trust_misses.saturating_add(sample.stats.accel_trust_prev_miss);
        native_fallbacks = native_fallbacks.saturating_add(native_fallback_entries(&sample.stats));
        wake_tail = wake_tail.saturating_add(wake_ge5ms(&sample.stats));
        select_ns = select_ns.saturating_add(sample.stats.total_select_cpu_ns);
        select_count = select_count.saturating_add(sample.stats.nr_select_cpu_calls);
        enqueue_ns = enqueue_ns.saturating_add(sample.stats.total_enqueue_latency_ns);
        enqueue_count = enqueue_count.saturating_add(sample.stats.nr_enqueue_calls);
    }

    Some(HistoryBucket {
        start_ago_secs: first.start_ago_secs,
        end_ago_secs: last.end_ago_secs,
        sample_secs,
        samples: samples.len(),
        route_pred_attempts: route_attempts,
        route_pred_hits: route_hits,
        route_pred_misses: route_misses,
        route_pred_hit_pct: pct(route_hits, route_hits + route_misses),
        trust_prev_attempts: trust_attempts,
        trust_prev_hits: trust_hits,
        trust_prev_misses: trust_misses,
        trust_prev_hit_pct: pct(trust_hits, trust_attempts),
        native_fallbacks,
        native_fallback_per_sec: per_sec(native_fallbacks, sample_secs.max(0.1)),
        wake_ge5ms: wake_tail,
        select_avg_ns: avg_ns(select_ns, select_count),
        enqueue_avg_ns: avg_ns(enqueue_ns, enqueue_count),
    })
}

struct MonitorInput {
    window: String,
    source: String,
    summary: String,
    affected_cpus: Vec<u16>,
    affected_tasks: Vec<u32>,
    metrics: Vec<Metric>,
}

fn monitor_input(
    window: impl Into<String>,
    source: impl Into<String>,
    summary: impl Into<String>,
    affected_cpus: Vec<u16>,
    affected_tasks: Vec<u32>,
    metrics: Vec<Metric>,
) -> MonitorInput {
    MonitorInput {
        window: window.into(),
        source: source.into(),
        summary: summary.into(),
        affected_cpus,
        affected_tasks,
        metrics,
    }
}

fn monitor(id: MonitorId, state: MonitorState, input: MonitorInput) -> MonitorSnapshot {
    let MonitorInput {
        window,
        source,
        summary,
        affected_cpus,
        affected_tasks,
        metrics,
    } = input;
    MonitorSnapshot {
        id,
        state,
        score: state.score(),
        window,
        source,
        summary,
        affected_cpus,
        affected_tasks,
        metrics,
    }
}

fn route_total<const N: usize>(values: &[u64; N]) -> u64 {
    values.iter().skip(1).sum()
}

fn wake_ge5ms(stats: &cake_stats) -> u64 {
    stats
        .wake_reason_bucket_count
        .iter()
        .skip(1)
        .map(|buckets| buckets[WAKE_BUCKET_MAX - 1])
        .sum()
}

fn wake_wait_all_max_us(stats: &cake_stats) -> u64 {
    stats
        .wake_reason_wait_all_max_ns
        .iter()
        .skip(1)
        .map(|max_ns| max_ns / 1000)
        .max()
        .unwrap_or(0)
}

fn native_fallback_entries(stats: &cake_stats) -> u64 {
    stats.accel_native_fallback_count[ACCEL_NATIVE_ENTRY_IDX]
}

fn floor_blocked_cpus(app: &TuiApp) -> Vec<u16> {
    app.per_cpu_work
        .iter()
        .enumerate()
        .filter(|(_, counter)| {
            counter.decision_confidence != 0 && !diag_floor_ready(counter.decision_confidence)
        })
        .map(|(cpu, _)| cpu as u16)
        .collect()
}

fn trust_blocked_cpus(app: &TuiApp) -> Vec<u16> {
    app.per_cpu_work
        .iter()
        .enumerate()
        .filter(|(_, counter)| counter.trust.prev_direct_blocked())
        .map(|(cpu, _)| cpu as u16)
        .collect()
}

fn diag_conf_value(confidence: u64, shift: u32) -> u64 {
    (confidence >> shift) & CAKE_CONF_NIBBLE_MASK
}

fn diag_conf_effective_value(confidence: u64, shift: u32) -> u64 {
    let value = diag_conf_value(confidence, shift);
    if value == 0 {
        8
    } else {
        value
    }
}

fn diag_load_shock_value(confidence: u64) -> u64 {
    diag_conf_value(confidence, CAKE_CONF_LOAD_SHOCK_SHIFT)
}

fn diag_floor_owner_ready(confidence: u64) -> bool {
    let owner_stable = diag_conf_effective_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT);
    let route = diag_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT);
    let trust = diag_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT);
    let pull = diag_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);
    let shock = diag_load_shock_value(confidence);

    owner_stable >= 12 || (route == 15 && trust == 15 && pull >= 12 && shock < 8)
}

fn diag_floor_ready(confidence: u64) -> bool {
    diag_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT) == 3
        && diag_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= 12
        && diag_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= 12
        && diag_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= 12
        && diag_floor_owner_ready(confidence)
        && diag_load_shock_value(confidence) < 8
        && diag_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT) >= 8
}

fn metric(name: impl Into<String>, value: impl IntoMetricValue, unit: impl Into<String>) -> Metric {
    Metric {
        name: name.into(),
        value: value.into_metric_value(),
        unit: unit.into(),
    }
}

trait IntoMetricValue {
    fn into_metric_value(self) -> String;
}

impl IntoMetricValue for u64 {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

impl IntoMetricValue for usize {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

impl IntoMetricValue for String {
    fn into_metric_value(self) -> String {
        self
    }
}

impl IntoMetricValue for &str {
    fn into_metric_value(self) -> String {
        self.to_string()
    }
}

fn severity_rank(severity: DiagnosticSeverity) -> u8 {
    match severity {
        DiagnosticSeverity::Info => 0,
        DiagnosticSeverity::Warn => 1,
        DiagnosticSeverity::Fail => 2,
    }
}

fn focused_app_identity(app: &TuiApp) -> (Option<u32>, Option<String>) {
    let roles = infer_tgid_roles(&app.task_rows);
    focused_app_with_total(app, &roles)
        .map(|(row, _)| (Some(row.tgid), Some(row.comm.clone())))
        .unwrap_or((None, None))
}

fn format_cpu_list(cpus: &[u16]) -> String {
    if cpus.is_empty() {
        "-".to_string()
    } else {
        cpus.iter()
            .take(12)
            .map(|cpu| format!("C{:02}", cpu))
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn format_task_list(tasks: &[u32]) -> String {
    if tasks.is_empty() {
        "-".to_string()
    } else {
        tasks
            .iter()
            .take(12)
            .map(|task| task.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn format_metrics(metrics: &[Metric]) -> String {
    if metrics.is_empty() {
        return "-".to_string();
    }
    metrics
        .iter()
        .take(8)
        .map(|metric| {
            if metric.unit.is_empty() {
                format!("{}={}", metric.name, metric.value)
            } else {
                format!("{}={}{}", metric.name, metric.value, metric.unit)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn append_history_text(out: &mut String, label: &str, buckets: &[HistoryBucket], max_rows: usize) {
    out.push_str(&format!("{}: buckets={}\n", label, buckets.len()));
    if buckets.is_empty() {
        out.push_str("  none\n");
        return;
    }
    let start = buckets.len().saturating_sub(max_rows);
    for bucket in &buckets[start..] {
        out.push_str(&format!(
            "  ago={}..{}s span={:.1}s samples={} route={}/{}/{}({:.1}%) trust={}/{}/{}({:.1}%) native={}({:.1}/s) wake_ge5ms={} cbns[sel/enq]={}/{}\n",
            bucket.start_ago_secs,
            bucket.end_ago_secs,
            bucket.sample_secs,
            bucket.samples,
            bucket.route_pred_attempts,
            bucket.route_pred_hits,
            bucket.route_pred_misses,
            bucket.route_pred_hit_pct,
            bucket.trust_prev_attempts,
            bucket.trust_prev_hits,
            bucket.trust_prev_misses,
            bucket.trust_prev_hit_pct,
            bucket.native_fallbacks,
            bucket.native_fallback_per_sec,
            bucket.wake_ge5ms,
            bucket.select_avg_ns,
            bucket.enqueue_avg_ns,
        ));
    }
}

fn service_status_style(status: ServiceStatus) -> Style {
    match status {
        ServiceStatus::Ok => Style::default().fg(Color::Green),
        ServiceStatus::Warn => Style::default().fg(Color::Yellow),
        ServiceStatus::Fail => Style::default().fg(Color::LightRed),
    }
}

fn service_status_user_label(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Ok => "ok",
        ServiceStatus::Warn => "warn",
        ServiceStatus::Fail => "action",
    }
}

fn monitor_count(service: &ServiceReport, state: MonitorState) -> usize {
    service
        .monitors
        .iter()
        .filter(|monitor| monitor.state == state)
        .count()
}

fn monitor_state_user_label(state: MonitorState) -> &'static str {
    match state {
        MonitorState::Pass => "pass",
        MonitorState::Warn => "warn",
        MonitorState::Fail => "action",
        MonitorState::NotReady => "warmup",
    }
}

fn monitor_label(id: MonitorId) -> &'static str {
    match id {
        MonitorId::Telemetry => "Data Source",
        MonitorId::Prediction => "Prediction",
        MonitorId::FloorPath => "Floor Path",
        MonitorId::TrustPrevDirect => "Prev Direct",
        MonitorId::Scoreboard => "Scoreboard",
        MonitorId::Fallback => "Fallback",
        MonitorId::WakeLatency => "Wake Latency",
        MonitorId::CallbackCost => "Callback Cost",
        MonitorId::History => "History",
    }
}

fn monitor_checks(id: MonitorId) -> &'static str {
    match id {
        MonitorId::Telemetry => "telemetry coverage and timeline",
        MonitorId::Prediction => "route predictor hit rate",
        MonitorId::FloorPath => "CPUs ready for fastest floor",
        MonitorId::TrustPrevDirect => "prev-CPU direct-route trust",
        MonitorId::Scoreboard => "predicted slot claim failures",
        MonitorId::Fallback => "native/kernel fallback rate",
        MonitorId::WakeLatency => "wake-to-run latency tail",
        MonitorId::CallbackCost => "BPF callback average cost",
        MonitorId::History => "rolling sample coverage",
    }
}

fn monitor_read_as(monitor: &MonitorSnapshot) -> String {
    let mut read = match monitor.id {
        MonitorId::Telemetry => telemetry_summary_for_user(&monitor.summary),
        _ => monitor.summary.clone(),
    };
    if !monitor.affected_cpus.is_empty() {
        read.push_str(&format!(
            " cpus={}",
            format_cpu_list(&monitor.affected_cpus)
        ));
    }
    if !monitor.affected_tasks.is_empty() {
        read.push_str(&format!(
            " tasks={}",
            format_task_list(&monitor.affected_tasks)
        ));
    }
    read
}

fn monitor_next_step(monitor: &MonitorSnapshot) -> String {
    match monitor.state {
        MonitorState::Pass => "no action; use Trends for longer comparisons".to_string(),
        MonitorState::NotReady => "warmup or too few samples; wait before tuning".to_string(),
        MonitorState::Warn | MonitorState::Fail => match monitor.id {
            MonitorId::Telemetry => {
                "check Codes/coverage before trusting every section".to_string()
            }
            MonitorId::Prediction => {
                "compare route/floor readiness and fallback pressure".to_string()
            }
            MonitorId::FloorPath => {
                if monitor.affected_cpus.is_empty() {
                    "raise floor_ready by improving prediction confidence".to_string()
                } else {
                    format!(
                        "inspect confidence lanes on {}",
                        format_cpu_list(&monitor.affected_cpus)
                    )
                }
            }
            MonitorId::TrustPrevDirect => {
                "watch demotions; compare prev-direct with scoreboard".to_string()
            }
            MonitorId::Scoreboard => "claim misses mean predicted CPUs are contested".to_string(),
            MonitorId::Fallback => {
                "slow safe path is frequent; find why fast path rejects".to_string()
            }
            MonitorId::WakeLatency => "inspect Apps wake chains and Topology pressure".to_string(),
            MonitorId::CallbackCost => {
                "callback cost is high; avoid extra hot-path work".to_string()
            }
            MonitorId::History => {
                "history is sparse; let capture run or check refresh stalls".to_string()
            }
        },
    }
}

fn top_active_code_label(service: &ServiceReport) -> String {
    service
        .active_codes
        .iter()
        .max_by_key(|code| code.severity)
        .map(|code| format!("{} {}", code.code, code.summary))
        .unwrap_or_else(|| "none".to_string())
}

fn top_active_code_style(service: &ServiceReport) -> Style {
    service
        .active_codes
        .iter()
        .max_by_key(|code| code.severity)
        .map(|code| severity_style(code.severity))
        .unwrap_or_else(|| Style::default().fg(Color::Green))
}

fn monitor_state(service: &ServiceReport, id: MonitorId) -> Option<MonitorState> {
    service
        .monitors
        .iter()
        .find(|monitor| monitor.id == id)
        .map(|monitor| monitor.state)
}

fn data_source_label(service: &ServiceReport) -> String {
    service
        .monitors
        .iter()
        .find(|monitor| monitor.id == MonitorId::Telemetry)
        .map(|monitor| {
            format!(
                "{} - {}",
                monitor.state,
                telemetry_summary_for_user(&monitor.summary)
            )
        })
        .unwrap_or_else(|| "not_ready - telemetry monitor has no sample yet".to_string())
}

fn telemetry_summary_for_user(summary: &str) -> String {
    if summary.contains("degraded=0") {
        "all expected telemetry sources are present".to_string()
    } else if summary.contains("degraded=") {
        let degraded = summary
            .split_whitespace()
            .find(|part| part.starts_with("degraded="))
            .unwrap_or("degraded=?");
        format!("coverage {}; check Monitors/Codes", degraded)
    } else {
        summary.to_string()
    }
}

fn service_status_meaning(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Ok => "ok means no active monitor is warning or failing",
        ServiceStatus::Warn => "warn means usable, but at least one monitor is degraded",
        ServiceStatus::Fail => {
            "action means one or more monitors found slow-path risk; data can still be valid"
        }
    }
}

fn readiness_style(live: &LiveData) -> Style {
    if live.trained_cpus == 0 {
        return Style::default().fg(Color::DarkGray);
    }
    let trained = live.trained_cpus as u64;
    let floor_pct = pct(live.floor_ready_cpus, trained);
    if live.floor_ready_cpus == trained
        && live.route_ready_cpus == trained
        && live.route_pred_hit_pct_60s >= 98.0
    {
        Style::default().fg(Color::Green)
    } else if floor_pct >= 75.0 && live.route_pred_hit_pct_60s >= 95.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    }
}

fn trust_prev_style(live: &LiveData) -> Style {
    if live.trust_prev_attempts_60s < 100 && live.trust_prev_active_cpus == 0 {
        Style::default().fg(Color::DarkGray)
    } else if live.trust_prev_hit_pct_60s < 95.0 || live.trust_prev_demotions_per_sec > 1.0 {
        Style::default().fg(Color::LightRed)
    } else if live.trust_prev_hit_pct_60s < 99.0 || live.trust_prev_demotions_per_sec > 0.25 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn callback_style(live: &LiveData) -> Style {
    let max_avg = [
        live.select_avg_ns_60s,
        live.enqueue_avg_ns_60s,
        live.running_avg_ns_60s,
        live.stopping_avg_ns_60s,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    low_is_good_style(max_avg, 1_000, 5_000)
}

fn readiness_takeaway(live: &LiveData) -> String {
    if live.trained_cpus == 0 {
        return "warming up; wait for trained CPUs before tuning".to_string();
    }
    let trained = live.trained_cpus as u64;
    let floor_gap = trained.saturating_sub(live.floor_ready_cpus);
    let route_gap = trained.saturating_sub(live.route_ready_cpus);
    if floor_gap == 0 && route_gap == 0 && live.route_pred_hit_pct_60s >= 98.0 {
        "all trained CPUs are ready for the fastest confidence floor".to_string()
    } else if floor_gap > 0 {
        format!(
            "{} CPUs are below the fastest floor; route hit is {:.1}%",
            floor_gap, live.route_pred_hit_pct_60s
        )
    } else if route_gap > 0 {
        format!(
            "{} CPUs lack route confidence; floor is ready where trained",
            route_gap
        )
    } else {
        format!(
            "route predictor is usable but below peak target at {:.1}%",
            live.route_pred_hit_pct_60s
        )
    }
}

fn fast_path_takeaway(live: &LiveData) -> String {
    if live.native_fallback_per_sec > 2_000.0 {
        return "native fallback is dominating; confidence is not avoiding enough work".to_string();
    }
    if live.trust_prev_demotions_per_sec > 1.0 {
        return "prev-direct works but demotes too often; confidence is unstable".to_string();
    }
    if live.scoreboard_claim_fail_pct_60s > 15.0 {
        return "scoreboard claims are failing often; predicted slots are too contested"
            .to_string();
    }
    if live.native_fallback_per_sec > 500.0 || live.scoreboard_claim_fail_pct_60s > 5.0 {
        return "fast path is useful, but fallback/claim misses still cost work".to_string();
    }
    "fast path is carrying the workload with low slow-path pressure".to_string()
}

fn latency_takeaway(live: &LiveData) -> String {
    if live.wake_ge5ms_60s > 0 || live.wake_wait_max_us > 10_000 {
        return "wake latency tail is bad; inspect Apps wake chains and CPU pressure".to_string();
    }
    if live.wake_wait_max_us > 5_000 {
        return "wake latency is usable but the tail is worth watching".to_string();
    }
    let max_avg = [
        live.select_avg_ns_60s,
        live.enqueue_avg_ns_60s,
        live.running_avg_ns_60s,
        live.stopping_avg_ns_60s,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    if max_avg > 1_000 {
        "wake tail is clean, but callback cost is above the preferred band".to_string()
    } else {
        "wake tail and callback overhead are healthy in this window".to_string()
    }
}

fn compact_count(value: u64) -> String {
    if value >= 1_000_000_000 {
        format!("{:.1}B", value as f64 / 1_000_000_000.0)
    } else if value >= 1_000_000 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if value >= 10_000 {
        format!("{:.1}K", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn monitor_state_style(state: MonitorState) -> Style {
    match state {
        MonitorState::Pass => Style::default().fg(Color::Green),
        MonitorState::Warn => Style::default().fg(Color::Yellow),
        MonitorState::Fail => Style::default().fg(Color::LightRed),
        MonitorState::NotReady => Style::default().fg(Color::DarkGray),
    }
}

fn severity_style(severity: DiagnosticSeverity) -> Style {
    match severity {
        DiagnosticSeverity::Info => Style::default().fg(Color::Cyan),
        DiagnosticSeverity::Warn => Style::default().fg(Color::Yellow),
        DiagnosticSeverity::Fail => Style::default().fg(Color::LightRed),
    }
}

fn pct_style(value: f64, pass_min: f64, warn_min: f64) -> Style {
    if value >= pass_min {
        Style::default().fg(Color::Green)
    } else if value >= warn_min {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn diagnostic_enums_have_obd_style_labels() {
        assert_eq!(DiagnosticCodeId::CakeTrust010.to_string(), "CAKE-TRUST-010");
        assert!(MonitorId::iter().any(|id| id == MonitorId::TrustPrevDirect));
        assert_eq!(MonitorState::Pass.to_string(), "pass");
    }

    #[test]
    fn service_report_json_uses_schema_v7() {
        let report = ServiceReport {
            schema_version: SERVICE_SCHEMA_VERSION,
            text_version: SERVICE_TEXT_VERSION,
            status: ServiceStatus::Warn,
            degraded_count: 1,
            uptime_secs: 10,
            health: HealthSummary::default(),
            lifecycle: LifecycleSummary::default(),
            accelerator: AcceleratorSummary::default(),
            graph: GraphSummary::default(),
            coverage: Vec::new(),
            live_data: LiveData::default(),
            monitors: vec![monitor(
                MonitorId::TrustPrevDirect,
                MonitorState::Warn,
                monitor_input(
                    "60s",
                    "test",
                    "trust unstable",
                    vec![2],
                    Vec::new(),
                    vec![metric("hit_pct", "98.0", "%")],
                ),
            )],
            active_codes: Vec::new(),
            code_history: Vec::new(),
            freeze_frames: Vec::new(),
            history: DiagnosticHistory::default(),
        };

        let json: serde_json::Value =
            serde_json::from_str(&format_service_report_json(&report)).unwrap();
        assert_eq!(json["schema_version"], SERVICE_SCHEMA_VERSION);
        assert_eq!(json["monitors"][0]["id"], "trust_prev_direct");
        assert_eq!(json["monitors"][0]["affected_cpus"][0], 2);
    }

    #[test]
    fn projected_active_codes_use_current_severity_and_freeze_frame() {
        let stale = DiagnosticCode {
            code: DiagnosticCodeId::CakeFloor002,
            severity: DiagnosticSeverity::Fail,
            active: true,
            first_seen_secs: 1,
            last_seen_secs: 10,
            count: 7,
            summary: "floor path readiness failed".to_string(),
            detail: "floor_ready=10/16 route_ready=13".to_string(),
            affected_cpus: vec![1, 2, 5, 7, 13, 14],
            affected_tasks: Vec::new(),
            freeze_frame: FreezeFrame {
                code: DiagnosticCodeId::CakeFloor002,
                elapsed_secs: 10,
                cpu: Some(1),
                tgid: None,
                comm: None,
                summary: "floor_ready=10/16 route_ready=13".to_string(),
                metrics: Vec::new(),
            },
        };
        let current = DiagnosticCode {
            severity: DiagnosticSeverity::Warn,
            last_seen_secs: 11,
            detail: "floor_ready=13/16 route_ready=14".to_string(),
            affected_cpus: vec![0, 8, 13],
            freeze_frame: FreezeFrame {
                code: DiagnosticCodeId::CakeFloor002,
                elapsed_secs: 11,
                cpu: Some(0),
                tgid: None,
                comm: None,
                summary: "floor_ready=13/16 route_ready=14".to_string(),
                metrics: Vec::new(),
            },
            ..stale.clone()
        };
        let mut recorder = DiagnosticRecorder::default();
        recorder.active.insert(stale.code, stale);

        let projected = projected_active_codes(&[current], &recorder);

        assert_eq!(projected[0].severity, DiagnosticSeverity::Warn);
        assert_eq!(projected[0].first_seen_secs, 1);
        assert_eq!(projected[0].count, 7);
        assert_eq!(projected[0].last_seen_secs, 11);
        assert_eq!(projected[0].detail, "floor_ready=13/16 route_ready=14");
        assert_eq!(projected[0].affected_cpus, vec![0, 8, 13]);
        assert_eq!(
            projected[0].freeze_frame.summary,
            "floor_ready=13/16 route_ready=14"
        );
    }

    #[test]
    fn wake_tail_max_uses_same_exact_source_as_tail_bucket() {
        let mut stats: cake_stats = unsafe { std::mem::zeroed() };
        stats.wake_reason_bucket_count[1][WAKE_BUCKET_MAX - 1] = 1;
        stats.wake_reason_wait_all_max_ns[1] = 5_014_000;
        stats.wake_reason_wait_max_ns[1] = 2_008_000;

        assert_eq!(wake_ge5ms(&stats), 1);
        assert_eq!(wake_wait_all_max_us(&stats), 5_014);
    }

    #[test]
    fn native_fallback_live_data_counts_entries_not_abi_branch_sum() {
        let mut stats: cake_stats = unsafe { std::mem::zeroed() };
        stats.accel_native_fallback_count[0] = 10;
        stats.accel_native_fallback_count[2] = 10;

        assert_eq!(native_fallback_entries(&stats), 10);
    }
}
