// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// Web UI — lightweight HTTP server for realtime scx_flow metrics.
// Uses tiny_http for TCP (when run manually) and falls back to a
// Unix domain socket (when spawned by scx_loader which blocks TCP
// via systemd hardening RestrictAddressFamilies/SocketBindDeny).
// Starts automatically; no CLI flags required.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tiny_http::{Header, Response, Server};

use crate::stats::Metrics;

const PORT: u16 = 50005;
const UNIX_SOCKET_PATH: &str = "/tmp/scx_flow.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const HISTORY_CAP: usize = 300;

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

struct RingBuf {
    buf: Vec<Metrics>,
    head: usize,
    count: usize,
}

impl RingBuf {
    fn new(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap), head: 0, count: 0 }
    }
    fn push(&mut self, m: Metrics) {
        if self.count < self.buf.capacity() {
            self.buf.push(m);
            self.count += 1;
        } else {
            self.buf[self.head] = m;
            self.head = (self.head + 1) % self.buf.capacity();
        }
    }
    fn snapshot(&self) -> Vec<Metrics> {
        let cap = self.buf.capacity();
        let mut out = Vec::with_capacity(self.count);
        if self.count == 0 { return out; }
        let start = if self.count < cap { 0 } else { self.head };
        for i in 0..self.count {
            out.push(self.buf[(start + i) % cap].clone());
        }
        out
    }
}

struct WebState {
    metrics: Metrics,
    history: RingBuf,
}

// ---------------------------------------------------------------------------
// Raw HTTP handler for Unix socket (tiny_http doesn't support Unix sockets)
// ---------------------------------------------------------------------------

fn unix_handle_client(
    mut stream: std::os::unix::net::UnixStream,
    state: &Arc<Mutex<WebState>>,
    html: &str,
) {
    let clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() { return; }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let path = parts[1];

    // Snapshot state under lock, then release before serialization.
    let (metrics, history_snap) = {
        let st = match state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        (st.metrics.clone(), st.history.snapshot())
    };

    let (body, content_type) = match path {
        "/" => (html.as_bytes().to_vec(), "text/html; charset=utf-8"),
        "/api/stats" => {
            let j = serde_json::to_string(&metrics).unwrap_or_else(|_| "{}".into());
            (j.into_bytes(), "application/json")
        }
        "/api/history" => {
            let j = serde_json::to_string(&history_snap).unwrap_or_else(|_| "[]".into());
            (j.into_bytes(), "application/json")
        }
        _ => {
            let _ = write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    let len = body.len();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        content_type, len
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn start(
    metrics_rx: crossbeam::channel::Receiver<Metrics>,
    shutdown: Arc<AtomicBool>,
) {
    log::info!("Web UI thread started");

    let html = include_str!("../ui/index.html").to_string();
    let state = Arc::new(Mutex::new(WebState {
        metrics: Metrics::default(),
        history: RingBuf::new(HISTORY_CAP),
    }));

    // Poller thread
    let state_clone = state.clone();
    let shutdown_clone = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_clone.load(Ordering::Relaxed) {
            match metrics_rx.recv_timeout(POLL_INTERVAL) {
                Ok(m) => {
                    if let Ok(mut st) = state_clone.lock() {
                        st.metrics = m.clone();
                        st.history.push(m);
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    });

    // Try TCP first (works when run manually from terminal).
    // Falls back to Unix socket (when spawned by scx_loader which
    // has systemd hardening: RestrictAddressFamilies, SocketBindDeny).
    let tcp_addr = format!("[::1]:{}", PORT);
    let html_for_unix = html.to_owned();

    if let Ok(server) = Server::http(&tcp_addr) {
        log::info!("Web UI listening on http://{}/ — disable with --no-webui", tcp_addr);

        let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
        let no_cache = Header::from_bytes("Cache-Control", "no-store").unwrap();
        let html_type = Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap();
        let json_type = Header::from_bytes("Content-Type", "application/json").unwrap();

        while !shutdown.load(Ordering::Relaxed) {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(200)) {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                match request.url() {
                    "/" => {
                        let resp = Response::from_string(&html)
                            .with_header(cors.clone())
                            .with_header(html_type.clone());
                        let _ = request.respond(resp);
                    }
                    "/api/stats" => {
                        let json = serde_json::to_string(&st.metrics).unwrap_or_else(|_| "{}".into());
                        let resp = Response::from_string(json)
                            .with_header(cors.clone()).with_header(json_type.clone()).with_header(no_cache.clone());
                        let _ = request.respond(resp);
                    }
                    "/api/history" => {
                        let snap = st.history.snapshot();
                        let json = serde_json::to_string(&snap).unwrap_or_else(|_| "[]".into());
                        let resp = Response::from_string(json)
                            .with_header(cors.clone()).with_header(json_type.clone()).with_header(no_cache.clone());
                        let _ = request.respond(resp);
                    }
                    _ => { let _ = request.respond(Response::empty(404).with_header(cors.clone())); }
                }
            }
        }
    } else {
        // TCP blocked — use Unix socket (scx_loader's systemd hardening)
        log::warn!("Web UI: TCP blocked (spawned by scx_loader?), falling back to {}", UNIX_SOCKET_PATH);
        let _ = std::fs::remove_file(UNIX_SOCKET_PATH);

        let listener = match UnixListener::bind(UNIX_SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("Web UI: Unix socket bind failed: {}", e);
                log::warn!("Web UI disabled. Use --no-webui to silence.");
                return;
            }
        };

        log::info!("Web UI listening on unix:{} — access via: sudo socat TCP-LISTEN:{} UNIX-CONNECT:{}", UNIX_SOCKET_PATH, PORT, UNIX_SOCKET_PATH);
        log::info!("Or run: sudo /usr/bin/scx_flow for direct TCP access");

        listener.set_nonblocking(true).expect("set_nonblocking");
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = state.clone();
                    let html = html_for_unix.clone();
                    std::thread::spawn(move || unix_handle_client(stream, &state, &html));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    }

    log::info!("Web UI stopped");
}
