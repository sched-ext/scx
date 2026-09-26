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

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use libbpf_rs::AsRawLibbpf as _;
use libbpf_rs::MapCore as _;
use libbpf_rs::libbpf_sys;

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
/* the fallback grace period is expedited and IPIs every CPU in the kernel */
const URCU_FALLBACK_INTERVAL: Duration = Duration::from_millis(100);
/* membarrier retries under a hotplug storm before the fallback takes over */
const URCU_MEMBARRIER_RETRIES: u32 = 4;

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
/// storages and at least URCU_MIN_INTERVAL between the side flips. See
/// UrcuGracePeriod for the cases membarrier cannot cover.
fn urcu_run_prog(fd: &OwnedFd) -> Result<u32> {
    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { std::mem::zeroed() };

    opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as _;
    let ret = unsafe { libbpf_sys::bpf_prog_test_run_opts(fd.as_raw_fd(), &mut opts) };
    if ret != 0 {
        bail!("urcu driver program run failed: {}", ret);
    }
    Ok(opts.retval)
}

/// membarrier(MEMBARRIER_CMD_GLOBAL) is synchronize_rcu() except in two cases:
/// it fails with EINVAL when nohz_full is active and it returns without
/// waiting when only one CPU is online. Both fall back to updating a private
/// map-in-map slot, which the kernel documents as waiting for the running
/// non-sleepable programs. That wait is an expedited grace period and IPIs
/// every CPU in the kernel, so the daemon spaces those rounds out.
struct UrcuGracePeriod {
    membarrier: bool,
    outer: libbpf_rs::MapHandle,
    inner: libbpf_rs::MapHandle,
    warned: bool,
}

fn membarrier_global() -> std::io::Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/* bumped by the kernel for every CPU online and offline transition */
fn hotplug_seq() -> Result<u64> {
    let seq = std::fs::read_to_string("/sys/kernel/sched_ext/hotplug_seq")
        .context("reading /sys/kernel/sched_ext/hotplug_seq")?;
    seq.trim()
        .parse()
        .with_context(|| format!("parsing hotplug_seq {:?}", seq))
}

fn online_cpus() -> Result<libc::c_long> {
    let ret = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if ret < 0 {
        bail!(
            "reading the online CPU count failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ret)
}

impl UrcuGracePeriod {
    fn new() -> Result<Self> {
        let membarrier = match membarrier_global() {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => false,
            Err(e) => bail!("membarrier(GLOBAL) failed: {}", e),
        };

        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let inner = libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Array,
            Some("scx_urcu_inner"),
            4,
            4,
            1,
            &opts,
        )
        .context("creating urcu inner map")?;
        let opts = libbpf_sys::bpf_map_create_opts {
            inner_map_fd: inner.as_fd().as_raw_fd() as u32,
            ..opts
        };
        let outer = libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::ArrayOfMaps,
            Some("scx_urcu_outer"),
            4,
            4,
            1,
            &opts,
        )
        .context("creating urcu outer map")?;
        let gp = Self {
            membarrier,
            outer,
            inner,
            warned: false,
        };
        gp.map_update()
            .context("probing urcu map-update grace period")?;
        Ok(gp)
    }

    fn map_update(&self) -> Result<()> {
        /*
         * A successful map-in-map update waits for the running non-sleepable
         * programs, see maybe_wait_bpf_programs(), even when the slot keeps the
         * same inner map.
         */
        self.outer
            .update(
                &0u32.to_ne_bytes(),
                &self.inner.as_fd().as_raw_fd().to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .context("waiting for urcu map-update grace period")
    }

    /// Wait for a grace period. Returns whether the expedited fallback was used.
    fn synchronize(&mut self) -> Result<bool> {
        if self.membarrier {
            /*
             * membarrier(GLOBAL) does not wait when only one CPU is online, so
             * the count is checked before and after the call and the hotplug
             * counter is compared across it. That still has a hole because the
             * counter moves at the active transitions, not when the online mask
             * changes: a CPU going offline bumps it before leaving the mask, a
             * CPU coming online after entering. Example with A and B online
             * while B goes offline and C comes online:
             *
             *  1. B bumps the counter, still in the mask.
             *  2. Read count 2 and the counter.
             *  3. B leaves the mask, one CPU online.
             *  4. membarrier() sees one CPU and returns without waiting.
             *  5. Descheduled. B finishes, C starts and enters the mask.
             *  6. Read count 2 and the counter, unchanged. Trusted.
             *  7. C bumps the counter.
             *
             * That needs this thread descheduled mid-call during two
             * back-to-back hotplugs. A moved counter with CPUs left means a
             * hotplug raced the call, so retry. This is best effort: the hole
             * stays open for a scheduler that runs through hotplug, and for a
             * restarting one until its asynchronous disable completes.
             */
            for _ in 0..URCU_MEMBARRIER_RETRIES {
                if online_cpus()? <= 1 {
                    break;
                }
                let seq = hotplug_seq()?;

                membarrier_global().context("membarrier(GLOBAL) failed")?;
                if online_cpus()? <= 1 {
                    break;
                }
                if hotplug_seq()? == seq {
                    return Ok(false);
                }
            }
        }

        if !self.warned {
            self.warned = true;
            eprintln!(
                "scx-urcu: {}, waiting for grace periods through expedited map-in-map updates at least {:?} apart",
                if self.membarrier {
                    "a single CPU is online"
                } else {
                    "membarrier is unavailable with nohz_full"
                },
                URCU_FALLBACK_INTERVAL
            );
        }
        self.map_update()?;
        Ok(true)
    }
}

fn urcu_daemon(
    stop: OwnedFd,
    doorbell: libbpf_rs::MapHandle,
    pairs: Vec<(OwnedFd, OwnedFd)>,
    mut gp: UrcuGracePeriod,
) -> Result<()> {
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&doorbell, |_| 0)
        .context("adding urcu doorbell to ring buffer")?;
    let rb = builder
        .build()
        .context("building urcu doorbell ring buffer")?;

    let mut last: Option<Instant> = None;
    let mut interval = URCU_MIN_INTERVAL;
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

        /* drain until nothing is awaiting reclaim, unpaced once stopping */
        loop {
            let pace = if stopping { Duration::ZERO } else { interval };
            if let Some(last) = last {
                let elapsed = last.elapsed();
                if elapsed < pace {
                    std::thread::sleep(pace - elapsed);
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

            interval = if gp.synchronize()? {
                URCU_FALLBACK_INTERVAL
            } else {
                URCU_MIN_INTERVAL
            };

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

    let gp = UrcuGracePeriod::new().context("setting up urcu grace periods")?;
    let stop = stop_eventfd()?;
    let daemon_stop = stop.try_clone().context("cloning urcu stop eventfd")?;
    let thread = std::thread::Builder::new()
        .name("scx-urcu".into())
        .spawn(move || {
            if let Err(e) = urcu_daemon(daemon_stop, doorbell, pairs, gp) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!("FATAL: scx-urcu daemon failed: {:#}\n", e),
                );
                std::process::exit(1);
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

/// Forward a batch of complete lines from one stream to the matching standard
/// stream of the scheduler, and abort when the kernel reports an error on a
/// stderr stream. Lines prefixed "IGN: " are dropped instead of
/// forwarded, for prints with side effects that nobody needs to see, the arena
/// association print in scx_arena_subprog_init() for example.
fn stream_forward(name: &str, stream_id: u32, label: &str, lines: &[String]) {
    let kept: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| !l.starts_with("IGN: "))
        .collect();
    if !kept.is_empty() {
        let msg = kept.join("\n");
        let out = format!("BPF {} of prog {}:\n{}\n", label, name, msg);
        if stream_id == BPF_STDOUT {
            print!("{}", out);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        } else {
            eprint!("{}", out);
        }
    }
    if stream_id == BPF_STDERR && stream_is_fatal(lines) {
        eprintln!("FATAL: aborting on BPF error report");
        std::process::exit(1);
    }
}

/// A stream opened as a descriptor. `reader` splits the lines and `pending`
/// carries the partial line a read ends in over to the next read.
struct StreamFd {
    name: String,
    stream_id: u32,
    label: &'static str,
    reader: BufReader<File>,
    pending: Vec<u8>,
    eof: bool,
}

impl StreamFd {
    /// Forward what the descriptor holds. EOF comes once the program is gone
    /// and the buffered data is out. A partial line is flushed at EOF and on
    /// `last`, the final read before the watcher stops.
    fn read_lines(&mut self, last: bool) {
        let mut lines = Vec::new();

        loop {
            match self.reader.read_until(b'\n', &mut self.pending) {
                Ok(0) => self.eof = true,
                Ok(_) if self.pending.ends_with(b"\n") => {
                    self.pending.pop();
                    lines.push(String::from_utf8_lossy(&self.pending).into_owned());
                    self.pending.clear();
                    continue;
                }
                /* only EOF returns without the delimiter */
                Ok(_) => self.eof = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("reading BPF {} of prog {}: {}", self.label, self.name, e);
                    self.eof = true;
                }
            }
            break;
        }
        if (self.eof || last) && !self.pending.is_empty() {
            lines.push(String::from_utf8_lossy(&self.pending).into_owned());
            self.pending.clear();
        }
        if !lines.is_empty() {
            stream_forward(&self.name, self.stream_id, self.label, &lines);
        }
    }
}

/// poll(2) the stream descriptors and the stop eventfd. A stream is dropped at
/// EOF and a stop request gets one last read of every stream.
fn stream_watch_fds(mut streams: Vec<StreamFd>, stop: OwnedFd) {
    while !streams.is_empty() {
        let mut fds: Vec<libc::pollfd> = std::iter::once(stop.as_raw_fd())
            .chain(streams.iter().map(|s| s.reader.get_ref().as_raw_fd()))
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            eprintln!("BPF stream watcher stopping, poll failed: {}", err);
            break;
        }

        let stopping = fds[0].revents != 0;
        for (i, stream) in streams.iter_mut().enumerate() {
            if stopping || fds[i + 1].revents != 0 {
                stream.read_lines(stopping);
            }
        }
        streams.retain(|s| !s.eof);
        if stopping {
            break;
        }
    }
}

/// Read every stream once per STREAM_POLL_INTERVAL through the read command
/// and assemble the lines here, for kernels without stream descriptors.
fn stream_watch_periodic(progs: Vec<(String, OwnedFd)>, stop: OwnedFd) {
    let mut buf = vec![0u8; 65536];
    let mut carries: Vec<[String; 2]> = (0..progs.len())
        .map(|_| [String::new(), String::new()])
        .collect();

    loop {
        let mut fds = [libc::pollfd {
            fd: stop.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let ret =
            unsafe { libc::poll(fds.as_mut_ptr(), 1, STREAM_POLL_INTERVAL.as_millis() as i32) };
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

                /* the final scan flushes a trailing partial like the fd path */
                let lines = stream_extract_lines(carry, new_data && !stopping);
                if !lines.is_empty() {
                    stream_forward(name, *stream_id, label, &lines);
                }
            }
        }

        if stopping {
            break;
        }
    }
}

/// Forward the BPF stdout/stderr streams of every program in the object to
/// the scheduler's stdout and stderr. Nothing reads these streams otherwise,
/// so messages would be silently dropped. On a kernel with stream descriptors
/// the watcher poll(2)s them and forwards each line as it is written.
/// Elsewhere it reads the streams periodically. Called from ArenaLib::setup(),
/// the watcher is owned by the returned ArenaLib.
pub(crate) fn stream_watcher_spawn(obj: &libbpf_rs::Object) -> Result<Daemon> {
    let with_fds = *scx_utils::compat::PROG_STREAM_OPEN_SUPPORTED;
    let mut progs = Vec::new();
    let mut streams = Vec::new();

    for prog in obj.progs() {
        let Some(name) = prog.name().to_str() else {
            continue;
        };
        /* feature-gated programs may not be loaded and then have no fd */
        let Some(fd) = prog_fd_clone(&prog)? else {
            continue;
        };
        if !with_fds {
            progs.push((name.to_string(), fd));
            continue;
        }
        for (stream_id, label) in BPF_STREAMS {
            let sfd = scx_utils::compat::prog_stream_open(fd.as_fd(), stream_id, true)
                .with_context(|| format!("opening BPF {} of prog {}", label, name))?;
            streams.push(StreamFd {
                name: name.to_string(),
                stream_id,
                label,
                reader: BufReader::new(File::from(sfd)),
                pending: Vec::new(),
                eof: false,
            });
        }
    }

    let stop = stop_eventfd()?;
    let daemon_stop = stop
        .try_clone()
        .context("cloning stream watcher stop eventfd")?;
    let thread = std::thread::Builder::new()
        .name("scx-bpf-stream".into())
        .spawn(move || {
            if with_fds {
                stream_watch_fds(streams, daemon_stop);
            } else {
                stream_watch_periodic(progs, daemon_stop);
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
