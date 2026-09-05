// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Loopback web UI: live scheduler metrics as a small HTTP server.
//!
//! The server binds `[::1]:50005` first and falls back to
//! `127.0.0.1:50005`. When both TCP binds fail (for example when the
//! loader sandbox denies inet sockets), the same routes are served over
//! the unix socket `/tmp/scx_mlfq.sock` with a minimal hand-rolled
//! HTTP/1.1 responder. The socket is created mode 0600, so only root
//! can connect to it (socat needs sudo), matching the loopback trust
//! boundary of the TCP path. There is no authentication: the loopback
//! address is the trust boundary, and the counters are already
//! world-readable through the stats server. `--no-webui` disables the
//! thread entirely (see main.rs), so no bind is attempted.
//!
//! The loader's network sandbox is seccomp-based: the restriction is a
//! per-process filter inherited by scheduler children, so a running
//! scheduler cannot lift its own. When both TCP binds fail with a
//! seccomp-style errno, this thread therefore writes the scheduler's own
//! runtime drop-in under `/run/systemd/system` so the *next* loader
//! start lifts the sandbox for the web UI (the current run serves the
//! unix socket), and `main` removes the drop-in again on exit. The
//! lifecycle is implemented in `try_unblock_loader_sandbox`,
//! `restore_loader_sandbox` and the pure classification helpers below.
//!
//! The metrics pipeline is push-based: the run loop sends one `WebMetrics`
//! snapshot per iteration over a small bounded channel (capacity 16).
//! `try_send` drops a frame when the buffer is full, instead of
//! stalling the
//! scheduler or growing the buffer), and this thread keeps the newest
//! snapshot behind a mutex for the HTTP handlers. The thread exits when
//! the shared shutdown flag is set.

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
const UNIX_SOCKET_PATH: &str = "/tmp/scx_mlfq.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// systemd's runtime unit directory. The root-owned tree under `/run`
/// (tmpfs) that PID 1 maintains for the current boot; runtime drop-ins
/// written below it are picked up by `systemctl daemon-reload` and
/// disappear on reboot.
const RUNTIME_SYSTEM_DIR: &str = "/run/systemd/system";

/// Runtime drop-in directory for the loader unit, where the scheduler
/// writes its own per-boot network-sandbox unblock. This is separate
/// from the installer's persistent `/etc/systemd/system` drop-in, which
/// the scheduler never touches.
const RUNTIME_DROPIN_DIR: &str = "/run/systemd/system/scx_loader.service.d";

/// The runtime drop-in file the scheduler owns for the current boot.
const RUNTIME_DROPIN: &str = "/run/systemd/system/scx_loader.service.d/mlfq-webui.conf";

/*
 * Linux errno values used to classify a TCP bind failure. The loader's
 * seccomp filters surface as EPERM (SocketBindDeny), EAFNOSUPPORT
 * (RestrictAddressFamilies) or EACCES; a taken port is EADDRINUSE, the
 * common bind failure that must never trigger the unblock.
 */
const EPERM: i32 = 1;
const EAFNOSUPPORT: i32 = 97;
const EACCES: i32 = 13;

/// Set once this run actually wrote the runtime drop-in (not merely
/// attempted it), so the exit path knows a sandbox restore is owed. The
/// webui thread stores it; `main` reads it after the run loop ends.
/// SeqCst orders the drop-in write before the main-thread restore
/// decision regardless of which core each ran on.
static UNBLOCK_WRITTEN: AtomicBool = AtomicBool::new(false);

/// Latest metrics snapshot, kept behind a mutex for the HTTP handlers.
/// The snapshot already carries the per-CPU current frequencies,
/// refreshed in the run loop, so serving never touches sysfs.
struct WebState {
    metrics: WebMetrics,
}

/// Serve one unix-socket client with a minimal HTTP/1.1 response. The
/// two routes mirror the tiny_http server: `/` serves the embedded HTML
/// (no-store), `/api/stats` the live metrics JSON, everything else a
/// 404. A malformed request is dropped silently.
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
                "queue_runnable": metrics.queue_runnable,
                "llc_runnable": metrics.llc_runnable,
                "gpu_submit_total": metrics.gpu_submit_total,
                "gpu_trace_mask": metrics.gpu_trace_mask,
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

/// The exact bytes the scheduler owns for its runtime (per-boot)
/// network-sandbox unblock. Mirrors the installer's `/etc` drop-in
/// shape. An `[Service]` section whose empty assignments reset the
/// loader's `RestrictAddressFamilies=`/`SocketBindDeny=` for the next
/// start carries the scheduler's own marker, so the restore path can
/// prove a file is ours byte-for-byte before removing it.
fn runtime_dropin_content() -> String {
    "# scx_mlfq Web UI: runtime unblock of the loader network sandbox.\n\
     # Owned by the scx_mlfq scheduler; removed on exit.\n\
     # This run stays on the unix socket; the unblock serves the next start.\n\
     [Service]\n\
     RestrictAddressFamilies=\n\
     SocketBindDeny=\n"
        .to_string()
}

/// True when `content` is byte-identical to the scheduler's own runtime
/// drop-in. Pure, so the ownership decision is unit-tested without a
/// filesystem.
fn dropin_matches(content: &str) -> bool {
    content == runtime_dropin_content()
}

/// Classify a TCP bind failure. Only a seccomp-style errno means the
/// loader sandbox is in effect. A taken port (EADDRINUSE) is a plain
/// "something else owns the port" and must never trigger the runtime
/// unblock, and an unclassified error is conservatively treated as not
/// a sandbox failure.
fn sandbox_failure(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(EPERM) | Some(EAFNOSUPPORT) | Some(EACCES)
    )
}

/// Recover the errno-bearing `io::Error` behind the boxed error tiny_http
/// reports for a failed `Server::http` bind. tiny_http surfaces the
/// `TcpListener::bind` `io::Error` itself (its `?` boxes it directly), so
/// the top-level downcast is the real path. The source walk guards
/// against a future wrapper. `io::Error`'s `source()` skips a custom
/// payload (the payload is the error, not its cause), so an errno hidden
/// under a wrapper is still found when the wrapper exposes it through its
/// own `source()` chain.
fn boxed_io_error<'a>(
    err: &'a (dyn std::error::Error + Send + Sync + 'static),
) -> Option<&'a std::io::Error> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
            if ioe.raw_os_error().is_some() {
                return Some(ioe);
            }
        }
        cur = e.source();
    }
    None
}

/// Try to lift the loader's network sandbox for the *next* scheduler
/// start by writing the scheduler's own runtime drop-in under
/// `/run/systemd/system`.
///
/// The seccomp filter the loader installed is per-process and
/// inherited: this process cannot lift its own, but systemd loads the
/// runtime drop-in at the next daemon-reload and unit start, so the
/// next loader-spawned scheduler gets the TCP dashboard while this run
/// serves the unix socket. Returns true when the drop-in was actually
/// written (the exit path then restores it).
fn try_unblock_loader_sandbox() -> bool {
    // The systemd runtime tree must already exist: it is root-owned and
    // maintained by PID 1, so without it no runtime unit manager would
    // ever load a drop-in written below it. Everything after this point
    // needs root, so the create/write failures below also serve as the
    // effective-uid guard for a non-root run.
    if !std::path::Path::new(RUNTIME_SYSTEM_DIR).is_dir() {
        log::warn!(
            "Web UI: {} is not a directory; runtime loader-sandbox unblock skipped",
            RUNTIME_SYSTEM_DIR
        );
        return false;
    }
    if let Err(e) = std::fs::create_dir_all(RUNTIME_DROPIN_DIR) {
        log::warn!(
            "Web UI: cannot create {}: {e}; runtime loader-sandbox unblock skipped (are we root?)",
            RUNTIME_DROPIN_DIR
        );
        return false;
    }

    // Atomic write: a temp file in the target directory, chmod 0644,
    // then rename over the final path. A leftover tmp file (on failure)
    // is removed; systemd ignores non-.conf files in the drop-in dir
    // anyway.
    let content = runtime_dropin_content();
    let tmp = format!("{RUNTIME_DROPIN}.tmp.{}", std::process::id());
    if let Err(e) = std::fs::write(&tmp, &content) {
        log::warn!(
            "Web UI: cannot write {}: {e}; runtime loader-sandbox unblock skipped",
            tmp
        );
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    if let Err(e) =
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))
    {
        log::warn!(
            "Web UI: cannot chmod {}: {e}; runtime loader-sandbox unblock skipped",
            tmp
        );
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    if let Err(e) = std::fs::rename(&tmp, RUNTIME_DROPIN) {
        log::warn!(
            "Web UI: cannot install {}: {e}; runtime loader-sandbox unblock skipped",
            RUNTIME_DROPIN
        );
        let _ = std::fs::remove_file(&tmp);
        return false;
    }

    // Best-effort reload: the file itself is the state, and systemd
    // picks it up at the next daemon-reload or boot even when the
    // reload below fails. systemctl talks to PID 1 over a unix socket,
    // which the sandbox keeps available; the absolute path sidesteps a
    // minimal loader PATH.
    match std::process::Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .status()
    {
        Ok(st) if st.success() => {}
        Ok(st) => log::warn!(
            "Web UI: systemctl daemon-reload exited with {st}; the runtime unblock applies at the next daemon-reload or boot"
        ),
        Err(e) => log::warn!(
            "Web UI: cannot run systemctl daemon-reload: {e}; the runtime unblock applies at the next daemon-reload or boot"
        ),
    }

    log::warn!(
        "Web UI: wrote {} — the loader network sandbox is lifted for the NEXT scheduler start; this run stays on the unix socket because the seccomp filter cannot be lifted in-place",
        RUNTIME_DROPIN
    );
    true
}

/// Restore the loader's network sandbox after a run that wrote the
/// runtime unblock. Called once from `main` after the run loop ends.
/// Idempotent (safe to call twice).
///
/// Only the byte-identical file this process wrote is ever removed: a
/// foreign or user-edited drop-in is logged and left untouched. `/run`
/// is tmpfs, so even an exit that skips this restore self-heals at the
/// next reboot.
pub fn restore_loader_sandbox() {
    if !UNBLOCK_WRITTEN.load(Ordering::SeqCst) {
        return;
    }

    let content = match std::fs::read_to_string(RUNTIME_DROPIN) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::info!(
                "Web UI: {} is already absent; the loader network restriction is already restored",
                RUNTIME_DROPIN
            );
            return;
        }
        Err(e) => {
            log::warn!(
                "Web UI: cannot read {}: {e}; leaving it in place",
                RUNTIME_DROPIN
            );
            return;
        }
    };
    if !dropin_matches(&content) {
        log::warn!(
            "Web UI: {} differs from the file this run wrote; leaving the foreign edit untouched",
            RUNTIME_DROPIN
        );
        return;
    }
    if let Err(e) = std::fs::remove_file(RUNTIME_DROPIN) {
        log::warn!(
            "Web UI: cannot remove {}: {e}; the runtime unblock stays in effect",
            RUNTIME_DROPIN
        );
        return;
    }

    // Best-effort reload, as in the unblock path: the removal is the
    // state, and systemd applies it at the next daemon-reload or boot.
    match std::process::Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .status()
    {
        Ok(st) if st.success() => {}
        Ok(st) => log::warn!(
            "Web UI: systemctl daemon-reload exited with {st}; the restore applies at the next daemon-reload or boot"
        ),
        Err(e) => log::warn!(
            "Web UI: cannot run systemctl daemon-reload: {e}; the restore applies at the next daemon-reload or boot"
        ),
    }

    log::info!(
        "Web UI: removed {} — the loader network restriction is restored for the next scheduler start",
        RUNTIME_DROPIN
    );
    UNBLOCK_WRITTEN.store(false, Ordering::SeqCst);
}

/// Start the web UI thread. Consumes the metrics channel and exits when
/// the shared shutdown flag is set (or the channel is closed).
pub fn start(metrics_rx: crossbeam::channel::Receiver<WebMetrics>, shutdown: Arc<AtomicBool>) {
    log::info!("Web UI thread started");

    let html = include_str!("../ui/index.html").to_string();
    let state = Arc::new(Mutex::new(WebState {
        metrics: WebMetrics::default(),
    }));

    // The metrics consumer: keep the newest snapshot behind the mutex.
    // A timeout keeps the loop parked for at most POLL_INTERVAL, so the
    // shutdown flag is observed within that budget.
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

    // Keep the last TCP bind error: when both binds fail, its errno
    // decides whether the loader sandbox caused it (and the runtime
    // unblock may help) or whether the port is simply taken.
    let mut bind_err: Option<Box<dyn std::error::Error + Send + Sync + 'static>> = None;

    match Server::http(format!("[::1]:{}", PORT)) {
        Ok(s) => {
            tcp_addr = format!("[::1]:{}", PORT);
            server = Some(s);
        }
        Err(e) => bind_err = Some(e),
    }

    if server.is_none() {
        match Server::http(format!("127.0.0.1:{}", PORT)) {
            Ok(s) => {
                tcp_addr = format!("127.0.0.1:{}", PORT);
                server = Some(s);
            }
            Err(e) => bind_err = Some(e),
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
                            "queue_runnable": metrics.queue_runnable,
                            "llc_runnable": metrics.llc_runnable,
                            "gpu_submit_total": metrics.gpu_submit_total,
                            "gpu_trace_mask": metrics.gpu_trace_mask,
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
        // TCP is blocked (the loader sandbox denies inet sockets), so
        // serve the same routes over the unix socket, which AF_UNIX
        // keeps available. Before the fallback, classify the last bind
        // error: only a seccomp-style errno (a sandbox denial, not a
        // busy port) earns the runtime unblock for the NEXT scheduler
        // start. This run stays on the unix socket. The seccomp filter
        // is per-process and inherited, so it cannot be lifted in place,
        // and the drop-in takes effect when the loader next starts the
        // unit.
        let sandboxed = bind_err
            .as_deref()
            .and_then(boxed_io_error)
            .is_some_and(sandbox_failure);
        if sandboxed && try_unblock_loader_sandbox() {
            UNBLOCK_WRITTEN.store(true, Ordering::SeqCst);
        }

        log::warn!(
            "Web UI: TCP blocked (spawned by scx_loader?), falling back to {}",
            UNIX_SOCKET_PATH
        );
        // Remove a stale socket file left by a previous run before
        // binding, so the bind cannot fail on the leftover path.
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

        // Root-only connect: the socket is the same trust boundary as
        // the loopback TCP binds, so only root (or whatever root lets
        // in) may read the scheduler's metrics through it.
        if let Err(e) = std::fs::set_permissions(
            UNIX_SOCKET_PATH,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        ) {
            log::warn!("Web UI: failed to set the unix socket mode to 0600: {e}");
        }

        log::info!(
            "Web UI listening on unix:{} (mode 0600, root-only) — access via: sudo socat TCP-LISTEN:{} UNIX-CONNECT:{}",
            UNIX_SOCKET_PATH,
            PORT,
            UNIX_SOCKET_PATH
        );

        if let Err(e) = listener.set_nonblocking(true) {
            // Nonblocking accept is required by the poll loop below.
            // Without it the thread could not observe the shutdown flag
            // while idle. Log and exit the serving thread gracefully.
            // The UI simply shows disconnected.
            log::error!("Web UI: failed to set the unix socket nonblocking: {e}");
            log::warn!("Web UI disabled. Use --no-webui to silence.");
            return;
        }
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Bound the first read: a client that connects and
                    // sends nothing must not hold a handler thread
                    // forever, so the 5 s read timeout on the request
                    // line ends the handler (the error path in
                    // unix_handle_client drops the connection).
                    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
                        log::warn!("Web UI: failed to set the unix-socket read timeout: {e}");
                    }
                    let state = state.clone();
                    let html = html_for_unix.clone();
                    std::thread::spawn(move || unix_handle_client(stream, &state, &html));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    // A transient accept failure (for example a file
                    // descriptor shortage) must not end the dashboard
                    // for the rest of the run. The loop retries at a
                    // bounded rate and only the shutdown flag exits it.
                    log::warn!("Web UI: unix-socket accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    log::info!("Web UI stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dropin_content_bytes() {
        let content = runtime_dropin_content();

        // The scheduler's own marker: ownership and the remove-on-exit
        // contract are stated in the file itself.
        assert!(content.contains("Owned by the scx_mlfq scheduler"));
        assert!(content.contains("removed on exit"));

        // The [Service] section and the two empty assignments that reset
        // the loader's RestrictAddressFamilies=AF_UNIX and
        // SocketBindDeny=... for the next start, as a contiguous block.
        assert!(content.contains("[Service]\n"));
        assert!(content.contains("[Service]\nRestrictAddressFamilies=\nSocketBindDeny=\n"));

        // The file ends with a newline, like the installer's drop-in.
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn sandbox_failure_classification_table() {
        // Sandbox-like errnos: EPERM (SocketBindDeny), EAFNOSUPPORT
        // (RestrictAddressFamilies) and EACCES.
        assert!(sandbox_failure(&std::io::Error::from_raw_os_error(EPERM)));
        assert!(sandbox_failure(&std::io::Error::from_raw_os_error(
            EAFNOSUPPORT
        )));
        assert!(sandbox_failure(&std::io::Error::from_raw_os_error(EACCES)));

        // A busy port (EADDRINUSE) must never trigger the unblock.
        assert!(!sandbox_failure(&std::io::Error::from_raw_os_error(98)));

        // Any other or errno-less error is conservatively not a sandbox
        // failure.
        assert!(!sandbox_failure(&std::io::Error::from_raw_os_error(110)));
        assert!(!sandbox_failure(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "no errno"
        )));
    }

    #[test]
    fn dropin_matches_is_byte_exact() {
        assert!(dropin_matches(&runtime_dropin_content()));

        // Any deviation — an empty file, a reset kept but a marker
        // edited, a restriction left in place — breaks the byte match,
        // so a foreign edit is never removed by the restore path.
        assert!(!dropin_matches(""));
        assert!(!dropin_matches(&runtime_dropin_content().replace(
            "RestrictAddressFamilies=",
            "RestrictAddressFamilies=AF_UNIX"
        )));
        let foreign_marker = runtime_dropin_content().replace("removed on exit", "edited by admin");
        assert!(!dropin_matches(&foreign_marker));
    }

    #[test]
    fn boxed_io_error_walks_source_chain() {
        // The real path: tiny_http surfaces the TcpListener::bind
        // io::Error directly, so the top-level downcast recovers it.
        let direct: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(std::io::Error::from_raw_os_error(EPERM));
        let ioe = boxed_io_error(direct.as_ref()).expect("the direct io::Error is recovered");
        assert!(sandbox_failure(ioe));

        // A non-io wrapper that exposes the errno-bearing io::Error
        // through its source chain still classifies, so a future
        // tiny_http error change cannot silently disable the unblock.
        #[derive(Debug)]
        struct Wrapper(Box<dyn std::error::Error + Send + Sync>);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "wraps: {}", self.0)
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
        let wrapped: Box<dyn std::error::Error + Send + Sync + 'static> = Box::new(Wrapper(
            Box::new(std::io::Error::from_raw_os_error(EAFNOSUPPORT)),
        ));
        let ioe = boxed_io_error(wrapped.as_ref()).expect("the wrapped io::Error is recovered");
        assert!(sandbox_failure(ioe));

        // An io::Error without an errno (a custom error payload) yields
        // None, so the classification stays off rather than guessing.
        let no_errno: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, "no errno"));
        assert!(boxed_io_error(no_errno.as_ref()).is_none());

        // A non-io error with no io::Error in the source chain yields
        // None.
        #[derive(Debug)]
        struct PlainErr;
        impl std::fmt::Display for PlainErr {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "plain error")
            }
        }
        impl std::error::Error for PlainErr {}
        let unrelated: Box<dyn std::error::Error + Send + Sync + 'static> = Box::new(PlainErr);
        assert!(boxed_io_error(unrelated.as_ref()).is_none());
    }
}
