// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf::{BpfSkel, BpfSkelBuilder};
use crate::bpf_intf::hints_event;
use crate::Context;
use anyhow::{bail, Context as _, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{OpenObject, RingBufferBuilder};
use serde::Serialize;
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
pub struct RecordOpts {
    /// Output directory for recording
    #[clap(short, long, default_value = "scxprof.out")]
    pub output: PathBuf,

    /// Recording duration in seconds
    #[clap(short = 't', long, default_value = "30")]
    pub timeout: u64,

    /// Path to the SCX scheduler's task hint map
    #[clap(long)]
    pub hints_map: Option<PathBuf>,

    /// Size of the hints ring buffer in MB
    #[clap(long, default_value = "1")]
    pub hints_map_ring_sz: u32,

    /// Disable creating a tar.gz archive after recording
    #[clap(long)]
    pub disable_archive: bool,
}

struct SpawnedProcess {
    child: Child,
    pidfd: OwnedFd,
    waited: bool,
}

impl SpawnedProcess {
    fn spawn(cmd: &[String]) -> Result<Self> {
        let child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn command")?;

        let pid = child.id() as i32;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
        if fd < 0 {
            bail!("pidfd_open failed: {}", std::io::Error::last_os_error());
        }

        Ok(Self {
            child,
            pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            waited: false,
        })
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }

    fn signal(&self, sig: i32) {
        unsafe {
            libc::kill(self.pid(), sig);
        }
    }

    fn wait(&mut self) -> Result<()> {
        if self.waited {
            return Ok(());
        }
        self.waited = true;
        let status = self.child.wait().context("failed to wait for child")?;
        if !status.success() {
            if matches!(status.signal(), Some(libc::SIGINT) | Some(libc::SIGKILL)) {
                return Ok(());
            }
            bail!("perf exited with status: {}", status);
        }
        Ok(())
    }
}

impl Drop for SpawnedProcess {
    fn drop(&mut self) {
        if !self.waited {
            self.signal(libc::SIGINT);
            let _ = self.child.wait();
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct HintsEventRecord {
    pid: i32,
    tgid: i32,
    hints: u64,
    timestamp: u64,
}

struct HintsRecorder<'a> {
    _open_object: Box<MaybeUninit<OpenObject>>,
    skel: BpfSkel<'a>,
    link: Option<libbpf_rs::Link>,
    ringbuf: libbpf_rs::RingBuffer<'a>,
    events: Rc<RefCell<Vec<HintsEventRecord>>>,
    writer: BufWriter<File>,
}

impl HintsRecorder<'static> {
    fn new(hints_path: PathBuf, ring_sz: u32) -> Result<Self> {
        let open_object = Box::new(MaybeUninit::uninit());
        let open_object_ptr = Box::into_raw(open_object);

        let open_object_ref: &'static mut MaybeUninit<OpenObject> =
            unsafe { &mut *open_object_ptr };

        let builder = BpfSkelBuilder::default();
        let mut open_skel = builder
            .open(open_object_ref)
            .context("failed to open BPF skeleton")?;

        open_skel
            .maps
            .ringbuf
            .set_max_entries(ring_sz * 1024 * 1024)
            .context("failed to set ringbuf size")?;

        let skel = open_skel.load().context("failed to load BPF skeleton")?;

        let link = skel
            .progs
            .trace_map_update
            .attach()
            .context("failed to attach BPF program")?;

        let events: Rc<RefCell<Vec<HintsEventRecord>>> = Rc::new(RefCell::new(Vec::new()));
        let events_clone = events.clone();

        let mut ringbuf_builder = RingBufferBuilder::new();
        ringbuf_builder
            .add(&skel.maps.ringbuf, move |data: &[u8]| {
                if data.len() >= std::mem::size_of::<hints_event>() {
                    let ev: hints_event =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const hints_event) };
                    events_clone.borrow_mut().push(HintsEventRecord {
                        pid: ev.pid,
                        tgid: ev.tgid,
                        hints: ev.hints,
                        timestamp: ev.timestamp,
                    });
                }
                0
            })
            .context("failed to add ringbuf callback")?;

        let ringbuf = ringbuf_builder
            .build()
            .context("failed to build ring buffer")?;

        let file = File::create(&hints_path).context("failed to create hints output file")?;
        let writer = BufWriter::new(file);

        Ok(Self {
            _open_object: unsafe { Box::from_raw(open_object_ptr) },
            skel,
            link: Some(link),
            ringbuf,
            events,
            writer,
        })
    }

    fn ringbuf_fd(&self) -> RawFd {
        self.ringbuf.epoll_fd()
    }

    fn consume_and_write(&mut self) -> Result<()> {
        self.ringbuf.consume().context("failed to consume ringbuf")?;
        let events: Vec<_> = self.events.borrow_mut().drain(..).collect();
        for ev in &events {
            let json = serde_json::to_string(ev).context("failed to serialize event")?;
            writeln!(self.writer, "{}", json)?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl Drop for HintsRecorder<'_> {
    fn drop(&mut self) {
        self.link.take();
        let _ = self.ringbuf.consume();
        let events: Vec<_> = self.events.borrow_mut().drain(..).collect();
        for ev in &events {
            if let Ok(json) = serde_json::to_string(ev) {
                let _ = writeln!(self.writer, "{}", json);
            }
        }
        let _ = self.writer.flush();

        let dropped = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .map(|bss| bss.dropped_events)
            .unwrap_or(0);
        if dropped > 0 {
            eprintln!(
                "warning: {} hints events were dropped due to full ring buffer, \
                 consider increasing --hints-map-ring-sz",
                dropped
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PollResult {
    Shutdown,
    ProcessExited,
    RingbufReady,
    Timeout,
}

fn poll_fds(fds: &[RawFd], timeout_ms: i32) -> Result<PollResult> {
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return Ok(PollResult::Shutdown);
        }
        bail!("poll failed: {}", err);
    }

    if ret == 0 {
        return Ok(PollResult::Timeout);
    }

    if pollfds[0].revents & libc::POLLIN != 0 {
        return Ok(PollResult::Shutdown);
    }
    if pollfds[1].revents & libc::POLLIN != 0 {
        return Ok(PollResult::ProcessExited);
    }
    if fds.len() > 2 && pollfds[2].revents & libc::POLLIN != 0 {
        return Ok(PollResult::RingbufReady);
    }

    Ok(PollResult::Timeout)
}

pub fn cmd_record(ctx: &Context, opts: RecordOpts) -> Result<()> {
    if opts.output.exists() {
        bail!(
            "output directory '{}' already exists",
            opts.output.display()
        );
    }

    fs::create_dir_all(&opts.output).context("failed to create output directory")?;

    let completed = match run_recording(ctx, &opts) {
        Ok(completed) => completed,
        Err(e) => {
            let _ = fs::remove_dir_all(&opts.output);
            return Err(e);
        }
    };

    if !completed {
        let _ = fs::remove_dir_all(&opts.output);
        return Ok(());
    }

    if !opts.disable_archive {
        create_archive(&opts.output)?;
        fs::remove_dir_all(&opts.output).context("failed to remove output directory")?;
    }

    Ok(())
}

fn run_recording(ctx: &Context, opts: &RecordOpts) -> Result<bool> {
    let perf_data_path = opts.output.join("perf.data");
    let perf_args = vec![
        "perf".to_string(),
        "mem".to_string(),
        "record".to_string(),
        "--all-cgroups".to_string(),
        "-p".to_string(),
        "--data-page-size".to_string(),
        "-o".to_string(),
        perf_data_path.to_string_lossy().to_string(),
    ];

    let mut perf = SpawnedProcess::spawn(&perf_args)?;

    let hints_recorder = if opts.hints_map.is_some() {
        let hints_path = opts.output.join("hints.jsonl");
        Some(HintsRecorder::new(hints_path, opts.hints_map_ring_sz)?)
    } else {
        None
    };

    let mut fds = vec![ctx.shutdown_fd(), perf.pidfd()];
    if let Some(ref recorder) = hints_recorder {
        fds.push(recorder.ringbuf_fd());
    }

    let mut hints_recorder = hints_recorder;
    let timeout = Duration::from_secs(opts.timeout);
    let start = Instant::now();
    let mut completed = true;

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            perf.signal(libc::SIGINT);
            perf.wait()?;
            break;
        }

        let remaining_ms = (timeout - elapsed).as_millis().min(100) as i32;

        match poll_fds(&fds, remaining_ms)? {
            PollResult::Shutdown => {
                perf.signal(libc::SIGKILL);
                perf.wait()?;
                completed = false;
                break;
            }
            PollResult::ProcessExited => {
                perf.wait()?;
                break;
            }
            PollResult::RingbufReady | PollResult::Timeout => {
                if let Some(ref mut recorder) = hints_recorder {
                    recorder.consume_and_write()?;
                }
            }
        }
    }

    drop(hints_recorder);

    Ok(completed)
}

fn create_archive(output_dir: &PathBuf) -> Result<()> {
    let archive_name = format!("{}.tar.gz", output_dir.display());
    let dir_name = output_dir
        .file_name()
        .context("invalid output directory name")?;

    let parent = output_dir.parent().unwrap_or(std::path::Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };

    let status = Command::new("tar")
        .args([
            "-czf",
            &archive_name,
            "-C",
            parent.to_str().context("invalid parent path")?,
            dir_name.to_str().context("invalid directory name")?,
        ])
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        bail!("tar failed with status: {}", status);
    }

    Ok(())
}
