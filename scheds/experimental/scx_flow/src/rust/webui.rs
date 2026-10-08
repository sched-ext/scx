// SPDX-License-Identifier: GPL-2.0
//! Loopback dashboard for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Serves the embedded page plus the live snapshot as JSON on loopback.
//! Uses tiny_http 0.12 pinned in Cargo.toml with loopback only plus no
//! TLS plus no store. Binds IPv6 loopback first with IPv4 fallback and
//! serves no WAN route, so the page plus JSON never leave the host.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crossbeam::channel::Receiver;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;

use crate::stats::WebMetrics;

/* Loopback TCP port of the dashboard. */
const PORT: u16 = 50005;
/* Poll bound of the snapshot channel. */
const POLL: Duration = Duration::from_millis(200);
/* JSON content type value. */
const JSON: &str = "application/json";
/* HTML content type value. */
const HTML: &str = "text/html";

/* Newest snapshot behind a lock for the handlers. */
struct WebState {
    metrics: WebMetrics,
}

/* JSON value of a serializable item. */
fn jv<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_default()
}

/* JSON text of a value with an empty object on failure. */
fn jt(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or("{}".into())
}

/* Merged dashboard object for one snapshot. */
/* Full log with version plus timestamp plus topology plus stats */
/* plus per CPU. Same object serves stats polling plus snapshot */
/* download on loopback with no new exposure. */
fn merged(snap: &WebMetrics) -> Value {
    json!({
        "version": snap.version.clone(),
        "timestamp_ns": snap.timestamp_ns,
        "topology": snap.topology.clone(),
        "stats": jv(&snap.stats),
        "per_cpu": jv(&snap.per_cpu),
    })
}

/* Start the dashboard thread. */
/* Consumes snapshots plus exits when the shutdown flag is set */
/* or the channel closes. Serves the page on the root plus the */
/* same JSON on the stats plus snapshot paths with loopback only */
/* plus no store plus unknown paths get not found. Binds one */
/* loopback only with IPv6 first plus IPv4 fallback plus no */
/* serve when both fail. One thread plus one lock per poll */
/* stays cheap beside the page poll with no backlog. */
pub fn start(rx: Receiver<WebMetrics>, shutdown: Arc<AtomicBool>) {
    log::info!("web thread started");
    let html = include_str!("../../ui/index.html").to_string();
    let state = Arc::new(Mutex::new(WebState {
        metrics: WebMetrics::default(),
    }));
    let keep = state.clone();
    let done = shutdown.clone();
    std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match rx.recv_timeout(POLL) {
                Ok(m) => {
                    if let Ok(mut s) = keep.lock() {
                        s.metrics = m;
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    });
    let mut server: Option<Server> = None;
    let mut addr = String::new();
    if let Ok(s) = Server::http(format!("[::1]:{PORT}")) {
        addr = format!("[::1]:{PORT}");
        server = Some(s);
    }
    if server.is_none()
        && let Ok(s) = Server::http(format!("127.0.0.1:{PORT}"))
    {
        addr = format!("127.0.0.1:{PORT}");
        server = Some(s);
    }
    let Some(server) = server else {
        log::warn!("web TCP blocked with no serve");
        return;
    };
    log::info!("web on port {addr}");
    let nocache = Header::from_bytes("Cache-Control", "no-store").unwrap();
    let nosniff = Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap();
    let frame = Header::from_bytes("X-Frame-Options", "DENY").unwrap();
    let htype = Header::from_bytes("Content-Type", HTML).unwrap();
    let jtype = Header::from_bytes("Content-Type", JSON).unwrap();
    while !shutdown.load(Ordering::Relaxed) {
        let got = server.recv_timeout(Duration::from_millis(200));
        let req = match got {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let snap = match state.lock() {
            Ok(v) => v.metrics.clone(),
            Err(_) => continue,
        };
        match req.url() {
            "/" => {
                let resp = Response::from_string(&html);
                let resp = resp.with_header(htype.clone());
                let resp = resp.with_header(nocache.clone());
                let resp = resp.with_header(nosniff.clone());
                let resp = resp.with_header(frame.clone());
                let _ = req.respond(resp);
            }
            "/api/stats" | "/api/snapshot" => {
                let txt = jt(&merged(&snap));
                let resp = Response::from_string(txt);
                let resp = resp.with_header(jtype.clone());
                let resp = resp.with_header(nocache.clone());
                let resp = resp.with_header(nosniff.clone());
                let resp = resp.with_header(frame.clone());
                let _ = req.respond(resp);
            }
            _ => {
                let resp = Response::empty(404)
                    .with_header(nocache.clone())
                    .with_header(nosniff.clone())
                    .with_header(frame.clone());
                let _ = req.respond(resp);
            }
        }
    }
    log::info!("web stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Merged keeps the five live keys with no stale keys. */
    #[test]
    fn merged_keeps_live_keys() {
        let snap = WebMetrics::default();
        let v = merged(&snap);
        assert!(v.get("stats").is_some());
        assert!(v.get("per_cpu").is_some());
        assert!(v.get("version").is_some());
        assert!(v.get("timestamp_ns").is_some());
        assert!(v.get("topology").is_some());
        assert_eq!(v.as_object().map(|o| o.len()), Some(5));
        assert!(v.get("governor").is_none());
        assert!(v.get("energy").is_none());
    }

    /* Old snapshots without new fields still decode. */
    #[test]
    fn web_metrics_missing_fields_default() {
        let txt = "{\"stats\":{\"on_cpu\":1},\"version\":\"4.7.0\"}";
        let m: WebMetrics = serde_json::from_str(txt).unwrap();
        assert_eq!(m.stats.on_cpu, 1);
        assert_eq!(m.stats.local_moves, 0);
        assert_eq!(m.stats.gate_rejects, 0);
        assert_eq!(m.stats.preempt_kicks, 0);
        assert_eq!(m.stats.preempt_skipped, 0);
        assert_eq!(m.stats.red_rejects, 0);
        assert_eq!(m.stats.red_reclaims, 0);
        assert!(m.per_cpu.is_empty());
        assert_eq!(m.version, "4.7.0");
        assert_eq!(m.timestamp_ns, 0);
        assert_eq!(m.topology, "");
        let old = "{\"id\":1,\"running_pid\":5,\"slice_ns\":2000000}";
        let card: crate::stats::PerCpuMetrics = serde_json::from_str(old).unwrap();
        assert_eq!(card.id, 1);
        assert!(!card.smt);
        assert_eq!(card.running_pid, 5);
        let v = merged(&m);
        assert_eq!(v.as_object().map(|o| o.len()), Some(5));
        let back: WebMetrics = serde_json::from_value(v).unwrap();
        assert_eq!(back.stats.on_cpu, 1);
        assert_eq!(back.version, "4.7.0");
    }

    /* Full snapshot round trips through JSON with live counters. */
    #[test]
    fn web_metrics_round_trip() {
        let snap = WebMetrics {
            stats: crate::stats::Metrics {
                on_cpu: 2,
                total_runtime: 1_000_000,
                uptime_ns: 2_000_000,
                inserts: 3,
                requeues: 1,
                completions: 2,
                local_moves: 10,
                node_moves: 4,
                machine_moves: 2,
                kicks: 5,
                admits: 3,
                rejects: 1,
                misses: 2,
                gate_rejects: 0,
                preempt_kicks: 1,
                preempt_skipped: 2,
                red_rejects: 1,
                red_reclaims: 1,
            },
            per_cpu: vec![
                crate::stats::PerCpuMetrics {
                    id: 0,
                    smt: false,
                    running_pid: 7,
                    slice_ns: 1_000_000,
                },
                crate::stats::PerCpuMetrics {
                    id: 1,
                    smt: true,
                    running_pid: 0,
                    slice_ns: 1_000_000,
                },
            ],
            version: "4.7.0".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            topology: "cpus=4 seeded".to_string(),
        };
        let txt = serde_json::to_string(&snap).unwrap();
        assert!(txt.contains("local_moves"));
        assert!(txt.contains("node_moves"));
        assert!(txt.contains("machine_moves"));
        assert!(!txt.contains("over_moves"));
        assert!(txt.contains("admits"));
        assert!(txt.contains("rejects"));
        assert!(txt.contains("misses"));
        assert!(!txt.contains("\"parks\""));
        assert!(txt.contains("gate_rejects"));
        assert!(txt.contains("preempt_kicks"));
        assert!(txt.contains("preempt_skipped"));
        assert!(txt.contains("red_rejects"));
        assert!(txt.contains("red_reclaims"));
        assert!(txt.contains("slice_ns"));
        assert!(txt.contains("running_pid"));
        assert!(txt.contains("\"smt\":false"));
        assert!(txt.contains("\"smt\":true"));
        assert!(txt.contains("version"));
        assert!(txt.contains("topology"));
        assert!(txt.contains("timestamp_ns"));
        assert!(!txt.contains("steal_moves"));
        assert!(!txt.contains("slot_moves"));
        assert!(!txt.contains("throttled_ns"));
        assert!(!txt.contains("nr_throttled"));
        assert!(!txt.contains("bw_moves"));
        assert!(!txt.contains("park_moves"));
        assert!(!txt.contains("enq_no_tctx"));
        assert!(!txt.contains("freq_khz"));
        assert!(!txt.contains("cur_freq"));
        assert!(!txt.contains("llc_id"));
        assert!(!txt.contains("governor"));
        assert!(!txt.contains("energy"));
        let back: WebMetrics = serde_json::from_str(&txt).unwrap();
        assert_eq!(back.stats.local_moves, 10);
        assert_eq!(back.stats.node_moves, 4);
        assert_eq!(back.stats.machine_moves, 2);
        assert_eq!(back.stats.admits, 3);
        assert_eq!(back.stats.rejects, 1);
        assert_eq!(back.stats.misses, 2);
        assert_eq!(back.stats.gate_rejects, 0);
        assert_eq!(back.stats.preempt_kicks, 1);
        assert_eq!(back.stats.preempt_skipped, 2);
        assert_eq!(back.stats.red_rejects, 1);
        assert_eq!(back.stats.red_reclaims, 1);
        assert_eq!(back.per_cpu.len(), 2);
        assert!(!back.per_cpu[0].smt);
        assert!(back.per_cpu[1].smt);
        assert_eq!(back.per_cpu[0].running_pid, 7);
        assert_eq!(back.per_cpu[0].slice_ns, 1_000_000);
        assert_eq!(back.per_cpu[1].id, 1);
        assert_eq!(back.version, "4.7.0");
        assert_eq!(back.topology, "cpus=4 seeded");
        let v = merged(&snap);
        assert_eq!(v.as_object().map(|o| o.len()), Some(5));
        assert!(v.get("governor").is_none());
        assert!(v.get("energy").is_none());
    }

    /* Dashboard keeps live ids without stale cards. */
    #[test]
    fn dashboard_keeps_live_layout() {
        let html = include_str!("../../ui/index.html");
        assert!(!html.contains("stale-pill"));
        assert!(!html.contains("core-stale"));
        assert!(html.contains("text-overflow: ellipsis"));
        assert!(html.contains("tabular-nums"));
    }

    /* Download keeps version plus timestamp in the file name. */
    #[test]
    fn dashboard_download_names_versioned_file() {
        let html = include_str!("../../ui/index.html");
        assert!(html.contains("downloadSnapshot"));
        assert!(html.contains("JSON.stringify(data, null, 2)"));
        assert!(html.contains("data.version"));
        assert!(html.contains("data.timestamp_ns"));
        assert!(html.contains("scx_flow_"));
        assert!(html.contains("/api/snapshot"));
    }

    /* Dashboard shows the fifteen live counters plus uptime. */
    #[test]
    fn dashboard_shows_live_counters() {
        let html = include_str!("../../ui/index.html");
        assert!(html.contains("id=\"on-cpu\""));
        assert!(html.contains("id=\"runtime\""));
        assert!(html.contains("id=\"uptime\""));
        assert!(html.contains("id=\"inserts\""));
        assert!(html.contains("id=\"requeues\""));
        assert!(html.contains("id=\"completions\""));
        assert!(html.contains("id=\"local-moves\""));
        assert!(html.contains("id=\"node-moves\""));
        assert!(html.contains("id=\"machine-moves\""));
        assert!(html.contains("id=\"kicks\""));
        assert!(html.contains("id=\"admits\""));
        assert!(html.contains("id=\"rejects\""));
        assert!(html.contains("id=\"misses\""));
        assert!(html.contains("id=\"gate-rejects\""));
        assert!(html.contains("id=\"preempt-kicks\""));
        assert!(html.contains("id=\"preempt-skipped\""));
        assert!(html.contains("id=\"red-rejects\""));
        assert!(html.contains("id=\"red-reclaims\""));
        assert!(html.contains("on_cpu"));
        assert!(html.contains("total_runtime"));
        assert!(html.contains("uptime_ns"));
        assert!(html.contains("local_moves"));
        assert!(html.contains("node_moves"));
        assert!(html.contains("machine_moves"));
        assert!(html.contains("gate_rejects"));
        assert!(html.contains("preempt_kicks"));
        assert!(html.contains("preempt_skipped"));
        assert!(html.contains("red_rejects"));
        assert!(html.contains("red_reclaims"));
        assert!(!html.contains("over_moves"));
        assert!(!html.contains("over-moves"));
        assert!(!html.contains("\"parks\""));
        assert!(!html.contains("id=\"parks\""));
        assert!(!html.contains("global_moves"));
        assert!(!html.contains("global-moves"));
    }

    /* Dashboard hides stale wire fields plus heavy sections. */
    #[test]
    fn dashboard_hides_stale_fields() {
        let html = include_str!("../../ui/index.html");
        assert!(!html.contains("steal_moves"));
        assert!(!html.contains("slot_moves"));
        assert!(!html.contains("throttled_ns"));
        assert!(!html.contains("nr_throttled"));
        assert!(!html.contains("bw_moves"));
        assert!(!html.contains("park_moves"));
        assert!(!html.contains("over_moves"));
        assert!(!html.contains("over-moves"));
        assert!(!html.contains("\"parks\""));
        assert!(!html.contains("id=\"parks\""));
        assert!(!html.contains("enq_no_tctx"));
        assert!(!html.contains("freq_khz"));
        assert!(!html.contains("cur_freq"));
        assert!(!html.contains("llc_id"));
        assert!(!html.contains("core-freq"));
        assert!(!html.contains("core-llc"));
        assert!(!html.contains("governor"));
        assert!(!html.contains("energy"));
        assert!(!html.contains("id=\"energy-since\""));
        assert!(!html.contains("id=\"mode-badge\""));
        assert!(!html.contains("no-tctx"));
        assert!(!html.contains("id=\"steal\""));
        assert!(!html.contains("id=\"throttled-ns\""));
    }

    /* Dashboard marks the second thread cards with SMT. */
    #[test]
    fn dashboard_shows_smt_badge() {
        let html = include_str!("../../ui/index.html");
        assert!(html.contains("core-smt"));
        assert!(html.contains("smtLabel"));
        assert!(html.contains("cpu.smt"));
        assert!(html.contains(">SMT<"));
        assert!(html.contains("var(--warning)"));
    }

    /* Dashboard clamps on CPU plus shows the live pid count. */
    #[test]
    fn dashboard_shows_live_pids_cell() {
        let html = include_str!("../../ui/index.html");
        assert!(html.contains("id=\"on-cpu\""));
        assert!(html.contains("id=\"running-pids\""));
        assert!(html.contains("livePids"));
        assert!(html.contains("shownOnCpu"));
        assert!(html.contains("running_pid"));
    }

    /* Header capsules plus the per CPU pill center text by height plus width. */
    #[test]
    fn dashboard_centers_header_capsules() {
        let html = include_str!("../../ui/index.html");
        assert!(html.contains("#status-badge"));
        assert!(html.contains("#download"));
        assert!(html.contains(".run-badge"));
        assert!(html.contains("display: inline-flex"));
        assert!(html.contains("align-items: center"));
        assert!(html.contains("justify-content: center"));
        assert!(html.contains("line-height: 1.4"));
        assert!(!html.contains("#mode-badge"));
    }

    /* Dashboard polls once per second with no stored history. */
    #[test]
    fn dashboard_polls_once_per_second() {
        let html = include_str!("../../ui/index.html");
        assert_eq!(html.matches("setInterval").count(), 1);
        assert!(!html.contains("localStorage"));
        assert!(html.contains("/api/stats"));
        assert!(html.contains("slice_ns"));
    }
}
