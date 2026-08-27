// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Arena library setup utilities
//!
//! Crate for setting up the BPF arena library for sched-ext schedulers.

mod bpf_skel;

mod arenalib;
pub use arenalib::ArenaLib;

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::libbpf_sys;
use libbpf_rs::AsRawLibbpf as _;
use libbpf_rs::MapCore as _;

/// Cacheline size assumed by the arena allocator's alignment parameter.
/// Mirrors scheds/include/lib/const-defs.h, keep in sync.
#[cfg(target_arch = "s390x")]
pub const CACHELINE_SIZE: usize = 256;
#[cfg(target_arch = "powerpc64")]
pub const CACHELINE_SIZE: usize = 128;
#[cfg(not(any(target_arch = "s390x", target_arch = "powerpc64")))]
pub const CACHELINE_SIZE: usize = 64;

const MEMBARRIER_CMD_GLOBAL: libc::c_long = 1;
const URCU_DOORBELL: &str = "scx_urcu_doorbell";
const URCU_MIN_INTERVAL: Duration = Duration::from_millis(1);

/// One background thread and the eventfd that stops it. Dropping writes the
/// eventfd and joins the thread.
#[derive(Debug)]
pub(crate) struct Daemon {
    stop: OwnedFd,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let one: u64 = 1;
        let ret = unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        /* on a failed wakeup, leak the thread rather than hang the join */
        if ret != std::mem::size_of::<u64>() as isize {
            return;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Create the eventfd a Daemon is stopped through.
fn stop_eventfd() -> Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        bail!(
            "creating daemon stop eventfd failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Duplicate @prog's fd, None for programs that were not loaded and thus have
/// no fd, prog.as_fd() on those would construct a BorrowedFd from an invalid
/// fd. Errors only when a loaded program's fd cannot be duplicated.
fn prog_fd_clone(prog: &libbpf_rs::Program<'_>) -> Result<Option<OwnedFd>> {
    let raw_fd = unsafe { libbpf_sys::bpf_program__fd(prog.as_libbpf_object().as_ptr()) };
    if raw_fd < 0 {
        return Ok(None);
    }
    let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) }
        .try_clone_to_owned()
        .with_context(|| format!("cloning the fd of BPF prog {:?}", prog.name()))?;
    Ok(Some(fd))
}

/// Userspace half of the scx_urcu machinery, see the BPF side in
/// lib/sdt_alloc.bpf.c. ArenaLib::setup() spawns the daemon when the object
/// carries the scx_urcu doorbell. The returned ArenaLib owns it and stops and
/// joins it on drop, so nothing else is visible to the scheduler: its whole
/// runtime surface is calling the scx_*_free_rcu() variants from its free
/// path hooks.
///
/// The daemon sleeps on the doorbell and, when woken, waits an RCU grace
/// period, membarrier(MEMBARRIER_CMD_GLOBAL) is synchronize_rcu(), and runs
/// the lib-provided scx_urcu_<storage>_pending/reclaim driver programs until
/// nothing is awaiting reclaim, one grace period per cycle shared across the
/// storages and at least URCU_MIN_INTERVAL between the side flips.
fn urcu_run_prog(fd: &OwnedFd) -> Result<u32> {
    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { std::mem::zeroed() };

    opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as _;
    let ret = unsafe { libbpf_sys::bpf_prog_test_run_opts(fd.as_raw_fd(), &mut opts) };
    if ret != 0 {
        bail!("urcu driver program run failed: {}", ret);
    }
    Ok(opts.retval)
}

fn urcu_daemon(
    stop: OwnedFd,
    doorbell: libbpf_rs::MapHandle,
    pairs: Vec<(OwnedFd, OwnedFd)>,
) -> Result<()> {
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&doorbell, |_| 0)
        .context("adding urcu doorbell to ring buffer")?;
    let rb = builder
        .build()
        .context("building urcu doorbell ring buffer")?;

    let mut last: Option<Instant> = None;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: doorbell.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("urcu doorbell poll failed: {}", err);
        }

        /* run one final drain below before honoring a stop request */
        let stopping = fds[1].revents != 0;

        /* drain until nothing is awaiting reclaim */
        loop {
            if let Some(last) = last {
                let elapsed = last.elapsed();
                if elapsed < URCU_MIN_INTERVAL {
                    std::thread::sleep(URCU_MIN_INTERVAL - elapsed);
                }
            }

            /*
             * Consume before the pending checks. A free landing afterwards is
             * either seen by the checks or leaves its ring behind and the poll
             * returns immediately. The reverse order can consume the ring of a
             * free the checks missed and sleep on it.
             */
            rb.consume().context("consuming urcu doorbell")?;

            let mut reclaims = Vec::new();
            for (pending, reclaim) in &pairs {
                if urcu_run_prog(pending)? != 0 {
                    reclaims.push(reclaim);
                }
            }
            if reclaims.is_empty() {
                break;
            }
            last = Some(Instant::now());

            let ret = unsafe { libc::syscall(libc::SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) };
            if ret != 0 {
                bail!(
                    "membarrier(GLOBAL) failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            for reclaim in reclaims {
                while urcu_run_prog(reclaim)? != 0 {}
            }
        }

        if stopping {
            return Ok(());
        }
    }
}

/// Spawn the urcu reclaim daemon if @obj carries the scx_urcu doorbell and
/// driver programs. Called from ArenaLib::setup(), the daemon is owned by
/// the returned ArenaLib.
pub(crate) fn urcu_spawn(obj: &libbpf_rs::Object) -> Result<Option<Daemon>> {
    let Some(doorbell) = obj.maps().find(|m| m.name() == URCU_DOORBELL) else {
        return Ok(None);
    };
    let doorbell =
        libbpf_rs::MapHandle::try_from(&doorbell).context("cloning urcu doorbell handle")?;

    let mut pairs = Vec::new();
    for prog in obj.progs() {
        let Some(name) = prog.name().to_str() else {
            continue;
        };
        let Some(base) = name.strip_suffix("_pending") else {
            continue;
        };
        if !name.starts_with("scx_urcu_") {
            continue;
        }

        let reclaim_name = format!("{}_reclaim", base);
        let reclaim = obj
            .progs()
            .find(|p| p.name() == reclaim_name.as_str())
            .with_context(|| format!("urcu driver program {} not found", reclaim_name))?;

        let Some(pending_fd) = prog_fd_clone(&prog)? else {
            bail!("urcu driver program {} is not loaded", name);
        };
        let Some(reclaim_fd) = prog_fd_clone(&reclaim)? else {
            bail!("urcu driver program {} is not loaded", reclaim_name);
        };
        pairs.push((pending_fd, reclaim_fd));
    }
    if pairs.is_empty() {
        return Ok(None);
    }

    let stop = stop_eventfd()?;
    let daemon_stop = stop.try_clone().context("cloning urcu stop eventfd")?;
    let thread = std::thread::Builder::new()
        .name("scx-urcu".into())
        .spawn(move || {
            if let Err(e) = urcu_daemon(daemon_stop, doorbell, pairs) {
                eprintln!("scx-urcu daemon exiting on error: {:#}", e);
            }
        })
        .context("spawning urcu daemon thread")?;

    Ok(Some(Daemon {
        stop,
        thread: Some(thread),
    }))
}

const BPF_STDOUT: u32 = 1;
const BPF_STDERR: u32 = 2;
const BPF_STREAMS: [(u32, &str); 2] = [(BPF_STDOUT, "stdout"), (BPF_STDERR, "stderr")];
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

fn stream_read(fd: &OwnedFd, stream_id: u32, buf: &mut [u8]) -> i32 {
    unsafe {
        libbpf_sys::bpf_prog_stream_read(
            fd.as_raw_fd(),
            stream_id,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    }
}

/// The kernel prefixes the errors it reports on a program's BPF stderr
/// stream with "ERROR: ".
fn stream_is_fatal(lines: &[String]) -> bool {
    lines.iter().any(|l| l.starts_with("ERROR: "))
}

/// Split the complete lines out of @carry, keeping a trailing partial for the
/// next read. Stream elements are concatenated without separators and reads
/// split lines arbitrarily, so prefixes may only be matched on complete lines.
/// @new_data says whether this poll read anything: a partial with no
/// continuation after a full poll interval is flushed as a line of its own.
fn stream_extract_lines(carry: &mut String, new_data: bool) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();

    if let Some(pos) = carry.rfind('\n') {
        lines = carry[..pos].split('\n').map(str::to_string).collect();
        carry.drain(..=pos);
    }
    if !new_data && !carry.is_empty() {
        lines.push(std::mem::take(carry));
    }

    lines
}

/// Forward the BPF stdout/stderr streams of every program in the object to
/// the scheduler's stdout and stderr respectively, and abort when the
/// kernel reports an error on a stderr stream. Nothing reads these streams
/// otherwise, so messages would be silently dropped. Lines prefixed "IGN: "
/// are dropped instead of forwarded, for prints with side effects that
/// nobody needs to see, the arena association print in
/// scx_arena_subprog_init() for example. Called from ArenaLib::setup(), the
/// watcher is owned by the returned ArenaLib.
pub(crate) fn stream_watcher_spawn(obj: &libbpf_rs::Object) -> Result<Daemon> {
    let mut progs = Vec::new();

    for prog in obj.progs() {
        let Some(name) = prog.name().to_str() else {
            continue;
        };
        /* feature-gated programs may not be loaded and then have no fd */
        let Some(fd) = prog_fd_clone(&prog)? else {
            continue;
        };
        progs.push((name.to_string(), fd));
    }

    let stop = stop_eventfd()?;
    let daemon_stop = stop
        .try_clone()
        .context("cloning stream watcher stop eventfd")?;
    let thread = std::thread::Builder::new()
        .name("scx-bpf-stream".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut carries: Vec<[String; 2]> = (0..progs.len())
                .map(|_| [String::new(), String::new()])
                .collect();

            loop {
                let mut fds = [libc::pollfd {
                    fd: daemon_stop.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                }];
                let ret = unsafe {
                    libc::poll(fds.as_mut_ptr(), 1, STREAM_POLL_INTERVAL.as_millis() as i32)
                };
                /* run one final scan below before honoring a stop request */
                let stopping = if ret < 0 {
                    std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                } else {
                    ret > 0
                };

                for (pidx, (name, fd)) in progs.iter().enumerate() {
                    for (sidx, (stream_id, label)) in BPF_STREAMS.iter().enumerate() {
                        let carry = &mut carries[pidx][sidx];
                        let mut new_data = false;

                        /* drain fully, a backlog can exceed the buffer */
                        loop {
                            let n = stream_read(fd, *stream_id, &mut buf);
                            if n <= 0 {
                                break;
                            }
                            carry.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
                            new_data = true;
                            if (n as usize) < buf.len() {
                                break;
                            }
                        }

                        let lines = stream_extract_lines(carry, new_data);
                        if lines.is_empty() {
                            continue;
                        }

                        let kept: Vec<&str> = lines
                            .iter()
                            .map(String::as_str)
                            .filter(|l| !l.starts_with("IGN: "))
                            .collect();
                        if !kept.is_empty() {
                            let msg = kept.join("\n");
                            let out = format!("BPF {} of prog {}:\n{}\n", label, name, msg);
                            if *stream_id == BPF_STDOUT {
                                print!("{}", out);
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            } else {
                                eprint!("{}", out);
                            }
                        }
                        if *stream_id == BPF_STDERR && stream_is_fatal(&lines) {
                            eprintln!("FATAL: aborting on BPF error report");
                            std::process::exit(1);
                        }
                    }
                }

                if stopping {
                    break;
                }
            }
        })
        .context("spawning BPF stream watcher")?;

    Ok(Daemon {
        stop,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::stream_extract_lines;
    use super::stream_is_fatal;

    #[test]
    fn test_stream_extract_lines() {
        let mut carry = String::new();

        /* empty carry, quiet tick */
        assert!(stream_extract_lines(&mut carry, false).is_empty());

        /* one complete line plus a partial */
        carry.push_str("ERROR: whole line\npartial");
        assert_eq!(
            stream_extract_lines(&mut carry, true),
            ["ERROR: whole line"]
        );
        assert_eq!(carry, "partial");

        /* the partial is not flushed while data keeps arriving */
        assert!(stream_extract_lines(&mut carry, true).is_empty());
        assert_eq!(carry, "partial");

        /* a line split across reads is reassembled */
        carry.push_str(" continued\nnext");
        assert_eq!(
            stream_extract_lines(&mut carry, true),
            ["partial continued"]
        );
        assert_eq!(carry, "next");

        /* a stale partial flushes on a quiet tick, exactly once */
        assert_eq!(stream_extract_lines(&mut carry, false), ["next"]);
        assert!(carry.is_empty());
        assert!(stream_extract_lines(&mut carry, false).is_empty());

        /* multiple lines per chunk, blank lines forwarded */
        carry.push_str("a\n\nb\ntail");
        assert_eq!(stream_extract_lines(&mut carry, true), ["a", "", "b"]);
        assert_eq!(carry, "tail");
        carry.clear();

        /* multi-byte UTF-8 split across reads stays on char boundaries */
        carry.push_str("caf");
        assert!(stream_extract_lines(&mut carry, true).is_empty());
        carry.push_str("\u{e9}\n");
        assert_eq!(stream_extract_lines(&mut carry, true), ["caf\u{e9}"]);
        assert!(carry.is_empty());
    }

    #[test]
    fn test_stream_is_fatal() {
        let fatal = ["noise".to_string(), "ERROR: Arena READ access".to_string()];
        assert!(stream_is_fatal(&fatal));

        /* the prefix only counts at the start of a line */
        let glued = ["no task dataERROR: Arena READ access".to_string()];
        assert!(!stream_is_fatal(&glued));
        assert!(!stream_is_fatal(&[]));
    }
}
