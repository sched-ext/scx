/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Loopback dashboard for the flow scheduler. Serves the
 * embedded page and the live snapshot as JSON. Prefers
 * the loopback TCP port and falls back to a unix socket
 * when the sandbox blocks TCP. No auth is used. The
 * loopback address is the trust boundary.
 */
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
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
/* Unix socket path used when TCP is blocked. */
const SOCK: &str = "/tmp/scx_flow.sock";
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

/* JSON text of a value. Empty object on failure. */
fn jt(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or("{}".into())
}

/* Merged dashboard object for one snapshot. */
/* Full log with version plus timestamp plus topology */
/* plus depths plus allowance plus stats plus per-CPU. */
/* Same object serves stats polling plus snapshot */
/* download on loopback with no new exposure. */
fn merged(snap: &WebMetrics) -> Value {
    json!({
        "version": snap.version.clone(),
        "timestamp_ns": snap.timestamp_ns,
        "topology": snap.topology.clone(),
        "light_depth": snap.light_depth,
        "hog_depth": snap.hog_depth,
        "burst_allowance_ns": snap.burst_allowance_ns,
        "stats": jv(&snap.stats),
        "per_cpu": jv(&snap.per_cpu),
    })
}

/*
 * Serve one unix client. Routes mirror the TCP server.
 * The root serves the page. The stats plus snapshot
 * paths serve the same full JSON with loopback only.
 * Unknown paths get a short not found reply.
 */
fn unix_client(
    mut stream: std::os::unix::net::UnixStream,
    state: &Arc<Mutex<WebState>>,
    html: &str,
) {
    let dup = match stream.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut rd = BufReader::new(dup);
    let mut line = String::new();
    if rd.read_line(&mut line).is_err() {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let path = parts[1];
    let snap = match state.lock() {
        Ok(v) => v.metrics.clone(),
        Err(_) => return,
    };
    let (body, ctype) = match path {
        "/" => (html.as_bytes().to_vec(), HTML),
        "/api/stats" | "/api/snapshot" => {
            let txt = jt(&merged(&snap));
            (txt.into_bytes(), JSON)
        }
        _ => {
            let _ = write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            );
            return;
        }
    };
    let len = body.len();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        ctype, len
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

/*
 * Start the dashboard thread. Consumes snapshots and
 * exits when the shutdown flag is set or the channel
 * closes.
 */
pub fn start(rx: Receiver<WebMetrics>, shutdown: Arc<AtomicBool>) {
    log::info!("web thread started");
    let html = include_str!("../ui/index.html").to_string();
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
    let unix_html = html.clone();
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
    if let Some(server) = server {
        log::info!("web on port {addr}");
        let nocache = Header::from_bytes("Cache-Control", "no-store").unwrap();
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
                    let _ = req.respond(resp);
                }
                "/api/stats" | "/api/snapshot" => {
                    let txt = jt(&merged(&snap));
                    let resp = Response::from_string(txt);
                    let resp = resp.with_header(jtype.clone());
                    let resp = resp.with_header(nocache.clone());
                    let _ = req.respond(resp);
                }
                _ => {
                    let _ = req.respond(Response::empty(404));
                }
            }
        }
    } else {
        log::warn!("web TCP blocked, unix fallback");
        if let Ok(m) = std::fs::symlink_metadata(SOCK)
            && m.file_type().is_socket()
        {
            let _ = std::fs::remove_file(SOCK);
        }
        let lis = match UnixListener::bind(SOCK) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("unix bind failed: {e}");
                return;
            }
        };
        let mode = PermissionsExt::from_mode(0o600);
        if std::fs::set_permissions(SOCK, mode).is_err() {
            log::warn!("socket mode failed");
        }
        log::info!("web on unix socket");
        if lis.set_nonblocking(true).is_err() {
            log::warn!("nonblock failed");
            return;
        }
        while !shutdown.load(Ordering::Relaxed) {
            match lis.accept() {
                Ok((s, _)) => {
                    let st = state.clone();
                    let h = unix_html.clone();
                    std::thread::spawn(move || unix_client(s, &st, &h));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    log::warn!("accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    log::info!("web stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Dashboard keeps the per-CPU array names. */
    #[test]
    fn merged_keeps_per_cpu_fields() {
        let snap = WebMetrics::default();
        let v = merged(&snap);
        assert!(v.get("stats").is_some());
        assert!(v.get("per_cpu").is_some());
        assert!(v.get("version").is_some());
        assert!(v.get("timestamp_ns").is_some());
        assert!(v.get("topology").is_some());
        assert!(v.get("light_depth").is_some());
        assert!(v.get("hog_depth").is_some());
        assert!(v.get("burst_allowance_ns").is_some());
        assert_eq!(v.as_object().map(|o| o.len()), Some(8));
    }

    /* Old snapshots without new fields still decode. */
    #[test]
    fn web_metrics_missing_fields_default() {
        let txt = "{\"stats\":{\"on_cpu\":1,\"total_runtime\":0,\
            \"uptime_ns\":0,\"inserts\":0,\
            \"requeues\":0,\"completions\":0,\
            \"park_moves\":0,\"steal_moves\":0,\
            \"kicks\":0,\"enq_no_tctx\":0}}";
        let m: WebMetrics = serde_json::from_str(txt).unwrap();
        assert_eq!(m.stats.on_cpu, 1);
        assert_eq!(m.stats.edf_enqueued, 0);
        assert_eq!(m.stats.edf_clamped, 0);
        assert_eq!(m.stats.edf_ordered, 0);
        assert_eq!(m.stats.group_demote, 0);
        assert_eq!(m.stats.group_promote, 0);
        assert_eq!(m.stats.group_wake_promote, 0);
        assert_eq!(m.stats.pinned_hog_inflated, 0);
        assert_eq!(m.stats.group_steal_skipped, 0);
        assert_eq!(m.stats.preempt_kicks, 0);
        assert_eq!(m.stats.preempt_skipped, 0);
        assert_eq!(m.stats.kick_coalesced, 0);
        assert!(m.per_cpu.is_empty());
        assert_eq!(m.version, "");
        assert_eq!(m.timestamp_ns, 0);
        assert_eq!(m.topology, "");
        assert_eq!(m.light_depth, 0);
        assert_eq!(m.hog_depth, 0);
        assert_eq!(m.burst_allowance_ns, 0);
        let txt2 = "{\"stats\":{},\"per_cpu\":[{\"id\":0}]}";
        let m2: WebMetrics = serde_json::from_str(txt2).unwrap();
        assert_eq!(m2.per_cpu[0].id, 0);
        assert_eq!(m2.per_cpu[0].slice_ns, 0);
        assert_eq!(m2.per_cpu[0].group, 0);
        assert_eq!(m2.per_cpu[0].running_nice, 0);
        assert_eq!(m2.per_cpu[0].running_weight, 0);
        assert_eq!(m2.per_cpu[0].delay_win, 0);
        assert!(!m2.per_cpu[0].delay_armed);
        let txt3 = "{\"stats\":{},\"per_cpu\":[{\"id\":0,\"tq_ns\":1000000}]}";
        let m3: WebMetrics = serde_json::from_str(txt3).unwrap();
        assert_eq!(m3.per_cpu[0].slice_ns, 1_000_000);
    }

    /* Full snapshot round trips through JSON. */
    #[test]
    fn web_metrics_round_trip() {
        let snap = WebMetrics {
            stats: crate::stats::Metrics {
                inserts: 3,
                requeues: 1,
                completions: 2,
                park_moves: 1,
                steal_moves: 0,
                kicks: 4,
                edf_enqueued: 8,
                edf_clamped: 1,
                edf_ordered: 8,
                group_demote: 1,
                group_promote: 2,
                group_wake_promote: 1,
                pinned_hog_inflated: 2,
                group_steal_skipped: 5,
                preempt_kicks: 6,
                preempt_skipped: 7,
                kick_coalesced: 2,
                ..Default::default()
            },
            per_cpu: vec![crate::stats::PerCpuMetrics {
                id: 0,
                group: 1,
                slice_ns: 1_000_000,
                running_est_ns: 1_000_000,
                running_pid: 7,
                running_nice: -5,
                running_weight: 1218,
                delay_win: 16,
                delay_armed: true,
                ..Default::default()
            }],
            version: "4.2.16".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            topology: "topology: 4 CPUs, no SMT, freq known".to_string(),
            light_depth: 1,
            hog_depth: 2,
            burst_allowance_ns: 2_000_000,
        };
        let txt = serde_json::to_string(&snap).unwrap();
        assert!(txt.contains("slice_ns"));
        assert!(txt.contains("group"));
        assert!(txt.contains("running_nice"));
        assert!(txt.contains("running_weight"));
        assert!(txt.contains("delay_win"));
        assert!(txt.contains("delay_armed"));
        assert!(txt.contains("group_demote"));
        assert!(txt.contains("group_wake_promote"));
        assert!(txt.contains("preempt_kicks"));
        assert!(txt.contains("preempt_skipped"));
        assert!(txt.contains("kick_coalesced"));
        assert!(txt.contains("version"));
        assert!(txt.contains("topology"));
        assert!(txt.contains("light_depth"));
        assert!(txt.contains("burst_allowance_ns"));
        let back: WebMetrics = serde_json::from_str(&txt).unwrap();
        assert_eq!(back.stats.inserts, 3);
        assert_eq!(back.stats.edf_enqueued, 8);
        assert_eq!(back.stats.edf_clamped, 1);
        assert_eq!(back.stats.edf_ordered, 8);
        assert_eq!(back.stats.group_demote, 1);
        assert_eq!(back.stats.group_promote, 2);
        assert_eq!(back.stats.group_wake_promote, 1);
        assert_eq!(back.stats.pinned_hog_inflated, 2);
        assert_eq!(back.stats.group_steal_skipped, 5);
        assert_eq!(back.stats.preempt_kicks, 6);
        assert_eq!(back.stats.preempt_skipped, 7);
        assert_eq!(back.stats.kick_coalesced, 2);
        assert_eq!(back.per_cpu[0].slice_ns, 1_000_000);
        assert_eq!(back.per_cpu[0].group, 1);
        assert_eq!(back.per_cpu[0].running_nice, -5);
        assert_eq!(back.per_cpu[0].running_weight, 1218);
        assert_eq!(back.per_cpu[0].delay_win, 16);
        assert!(back.per_cpu[0].delay_armed);
        assert_eq!(back.version, "4.2.16");
        assert_eq!(back.topology, "topology: 4 CPUs, no SMT, freq known");
        assert_eq!(back.light_depth, 1);
        assert_eq!(back.hog_depth, 2);
        assert_eq!(back.burst_allowance_ns, 2_000_000);
    }

    /* Dashboard shows stale next to delay when idle. */
    #[test]
    fn dashboard_shows_stale_when_idle() {
        let html = include_str!("../ui/index.html");
        assert!(html.contains("(idle ? ' stale' : '')"));
    }

    /* Dashboard shows the coalesced cells. */
    #[test]
    fn dashboard_shows_coalesced_cells() {
        let html = include_str!("../ui/index.html");
        assert!(html.contains("id=\"kcoal\""));
        assert!(html.contains("id=\"coalesce-rate\""));
        assert!(html.contains("kick_coalesced"));
    }
}
