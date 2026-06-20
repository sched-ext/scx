// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tiny_http::{Header, Response, Server};

use crate::stats::WebMetrics;

const PORT: u16 = 50005;
const UNIX_SOCKET_PATH: &str = "/tmp/scx_flow.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(200);

struct WebState {
    metrics: WebMetrics,
}

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
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let path = parts[1];

    let metrics = {
        let st = match state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        st.metrics.clone()
    };

    let (body, content_type) = match path {
        "/" => (html.as_bytes().to_vec(), "text/html; charset=utf-8"),
        "/api/stats" => {
            let stats = serde_json::to_value(&metrics.stats).unwrap_or_default();
            let per_cpu = serde_json::to_value(&metrics.per_cpu).unwrap_or_default();
            let merged = json!({
                "stats": stats,
                "per_cpu": per_cpu,
                "carriage_filling_count": metrics.carriage_filling_count,
            });
            let j = serde_json::to_string(&merged).unwrap_or_else(|_| "{}".into());
            (j.into_bytes(), "application/json")
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
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        content_type, len
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

pub fn start(metrics_rx: crossbeam::channel::Receiver<WebMetrics>, shutdown: Arc<AtomicBool>) {
    log::info!("Web UI thread started");

    let html = include_str!("../ui/index.html").to_string();
    let state = Arc::new(Mutex::new(WebState {
        metrics: WebMetrics::default(),
    }));

    let state_clone = state.clone();
    let shutdown_clone = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_clone.load(Ordering::Relaxed) {
            match metrics_rx.recv_timeout(POLL_INTERVAL) {
                Ok(m) => {
                    if let Ok(mut st) = state_clone.lock() {
                        st.metrics = m;
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    });

    let html_for_unix = html.to_owned();
    let mut server: Option<tiny_http::Server> = None;
    let mut tcp_addr = String::new();

    if let Ok(s) = Server::http(&format!("[::1]:{}", PORT)) {
        tcp_addr = format!("[::1]:{}", PORT);
        server = Some(s);
    }

    if server.is_none() {
        if let Ok(s) = Server::http(&format!("127.0.0.1:{}", PORT)) {
            tcp_addr = format!("127.0.0.1:{}", PORT);
            server = Some(s);
        }
    }

    if let Some(server) = server {
        log::info!(
            "Web UI listening on http://{}/ — disable with --no-webui",
            tcp_addr
        );

        let no_cache = Header::from_bytes("Cache-Control", "no-store").unwrap();
        let html_type = Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap();
        let json_type = Header::from_bytes("Content-Type", "application/json").unwrap();

        while !shutdown.load(Ordering::Relaxed) {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(200)) {
                let metrics = {
                    let st = match state.lock() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    st.metrics.clone()
                };
                match request.url() {
                    "/" => {
                        let resp = Response::from_string(&html)
                            .with_header(html_type.clone())
                            .with_header(no_cache.clone());
                        let _ = request.respond(resp);
                    }
                    "/api/stats" => {
                        let stats = serde_json::to_value(&metrics.stats).unwrap_or_default();
                        let per_cpu = serde_json::to_value(&metrics.per_cpu).unwrap_or_default();
                        let merged = json!({
                            "stats": stats,
                            "per_cpu": per_cpu,
                            "carriage_filling_count": metrics.carriage_filling_count,
                        });
                        let json = serde_json::to_string(&merged).unwrap_or_else(|_| "{}".into());
                        let resp = Response::from_string(json)
                            .with_header(json_type.clone())
                            .with_header(no_cache.clone());
                        let _ = request.respond(resp);
                    }
                    _ => {
                        let _ = request.respond(Response::empty(404));
                    }
                }
            }
        }
    } else {
        log::warn!(
            "Web UI: TCP blocked (spawned by scx_loader?), falling back to {}",
            UNIX_SOCKET_PATH
        );
        if let Ok(meta) = std::fs::symlink_metadata(UNIX_SOCKET_PATH) {
            if meta.file_type().is_socket() {
                let _ = std::fs::remove_file(UNIX_SOCKET_PATH);
            }
        }

        let listener = match UnixListener::bind(UNIX_SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("Web UI: Unix socket bind failed: {}", e);
                log::warn!("Web UI disabled. Use --no-webui to silence.");
                return;
            }
        };

        log::info!(
            "Web UI listening on unix:{} — access via: sudo socat TCP-LISTEN:{} UNIX-CONNECT:{}",
            UNIX_SOCKET_PATH,
            PORT,
            UNIX_SOCKET_PATH
        );
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
