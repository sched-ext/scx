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
use libbpf_rs::{MapCore, MapHandle, OpenObject, RingBufferBuilder};
use serde::Serialize;
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

pub fn perf_binary() -> String {
    std::env::var("SCX_CHARACTERIZE_PERF").unwrap_or_else(|_| "perf".to_string())
}

const SCHED_TRACE_EVENTS: &[&str] = &[
    "sched:sched_switch",
    "sched:sched_wakeup",
    "sched:sched_wakeup_new",
    "sched:sched_waking",
    "sched:sched_stat_runtime",
    "irq:irq_handler_entry",
    "irq:irq_handler_exit",
    "irq:softirq_entry",
    "irq:softirq_exit",
    "irq:softirq_raise",
    "irq_vectors:local_timer_entry",
    "irq_vectors:local_timer_exit",
    "irq_vectors:reschedule_entry",
    "irq_vectors:reschedule_exit",
    "nmi:nmi_handler",
];

pub const PERF_MEM_DATA_FILE: &str = "perf.mem.data";
pub const PERF_MEM_SCRIPT_FILE: &str = "perf.mem.script";
pub const PERF_SCHED_DATA_FILE: &str = "perf.sched.data";
pub const PERF_SCHED_SCRIPT_FILE: &str = "perf.sched.script";
const DEFAULT_PERF_MMAP_SIZE: &str = "8M";
const PERF_SCHED_CLOCKID: &str = "CLOCK_MONOTONIC";

#[derive(Debug, Parser)]
#[command(
    after_help = "Trace cost notes:\n  hints trace < mem trace < sched trace\n\n  sched trace produces a much higher volume of data than hints or mem trace and can be quite costly. On some workloads it can materially perturb the host, especially for longer recordings or when writing to slower / write-amplifying filesystems. Prefer shorter durations when sched trace is enabled."
)]
pub struct RecordOpts {
    /// Output directory for recording
    #[clap(short, long, default_value = "scx_characterize.out")]
    pub output: PathBuf,

    /// Output archive path for the recording
    #[clap(short = 'f', long)]
    pub file: Option<PathBuf>,

    /// Recording duration in seconds
    #[clap(short = 't', long, default_value = "30")]
    pub timeout: u64,

    /// Load latency threshold in cycles
    #[clap(short = 'l', long, default_value = "10")]
    pub ldlat: u32,

    /// Path to the SCX scheduler's task hint map
    #[clap(long)]
    pub hints_map: Option<PathBuf>,

    /// Size of the hints ring buffer in MB
    #[clap(long, default_value = "8")]
    pub hints_map_ring_sz: u32,

    /// Disable creating a tar.gz archive after recording
    #[clap(long)]
    pub disable_archive: bool,

    /// Generate perf.mem.script and perf.sched.script during recording
    #[clap(long)]
    pub enable_perf_script: bool,

    /// Disable recording sched/irq trace events into perf.sched.data
    #[clap(long)]
    pub disable_sched_trace: bool,

    /// Disable recording perf mem trace into perf.mem.data
    #[clap(long)]
    pub disable_mem_trace: bool,
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
    link: Option<libbpf_rs::Link>,
    ringbuf: libbpf_rs::RingBuffer<'a>,
    events: Rc<RefCell<Vec<HintsEventRecord>>>,
    writer: BufWriter<File>,
    skel: BpfSkel<'a>,
    _open_object: Box<MaybeUninit<OpenObject>>,
}

impl HintsRecorder<'static> {
    fn new(hints_path: PathBuf, hints_map_path: PathBuf, ring_sz: u32) -> Result<Self> {
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

        let hints_map = MapHandle::from_pinned_path(&hints_map_path).with_context(|| {
            format!(
                "failed to open pinned hints map '{}'",
                hints_map_path.display()
            )
        })?;
        let hints_map_id = hints_map
            .info()
            .context("failed to query hints map info")?
            .info
            .id;
        open_skel
            .maps
            .bss_data
            .as_mut()
            .context("missing BPF bss data")?
            .hints_bss
            .target_map_id = hints_map_id;

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
            link: Some(link),
            ringbuf,
            events,
            writer,
            skel,
            _open_object: unsafe { Box::from_raw(open_object_ptr) },
        })
    }

    fn ringbuf_fd(&self) -> RawFd {
        self.ringbuf.epoll_fd()
    }

    fn consume_and_write(&mut self) -> Result<()> {
        self.ringbuf
            .consume()
            .context("failed to consume ringbuf")?;
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
            .map(|bss| bss.hints_bss.dropped_events)
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
    ProcessExited(usize),
    RingbufReady,
    Timeout,
}

fn poll_fds(
    shutdown_fd: RawFd,
    process_fds: &[RawFd],
    ringbuf_fd: Option<RawFd>,
    timeout_ms: i32,
) -> Result<PollResult> {
    let mut pollfds = Vec::with_capacity(1 + process_fds.len() + usize::from(ringbuf_fd.is_some()));
    pollfds.push(libc::pollfd {
        fd: shutdown_fd,
        events: libc::POLLIN,
        revents: 0,
    });
    pollfds.extend(process_fds.iter().map(|&fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }));
    if let Some(fd) = ringbuf_fd {
        pollfds.push(libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
    }

    let ret = unsafe {
        libc::poll(
            pollfds.as_mut_ptr(),
            pollfds.len() as libc::nfds_t,
            timeout_ms,
        )
    };

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
    for (idx, pollfd) in pollfds[1..=process_fds.len()].iter().enumerate() {
        if pollfd.revents & libc::POLLIN != 0 {
            return Ok(PollResult::ProcessExited(idx));
        }
    }
    if ringbuf_fd.is_some() && pollfds.last().unwrap().revents & libc::POLLIN != 0 {
        return Ok(PollResult::RingbufReady);
    }

    Ok(PollResult::Timeout)
}

fn build_sched_perf_args(sched_data_path: &Path) -> Vec<String> {
    let mut sched_perf_args = vec![
        perf_binary(),
        "record".to_string(),
        "-a".to_string(),
        "-k".to_string(),
        PERF_SCHED_CLOCKID.to_string(),
        "-m".to_string(),
        DEFAULT_PERF_MMAP_SIZE.to_string(),
        "-o".to_string(),
        sched_data_path.to_string_lossy().to_string(),
    ];
    for event in SCHED_TRACE_EVENTS {
        sched_perf_args.push("-e".to_string());
        sched_perf_args.push((*event).to_string());
    }
    sched_perf_args
}

fn stop_hints_recorder(hints_recorder: &mut Option<HintsRecorder<'static>>) {
    if let Some(recorder) = hints_recorder.take() {
        drop(recorder);
    }
}

pub fn cmd_record(ctx: &Context, opts: RecordOpts) -> Result<()> {
    if opts.output.exists() {
        bail!(
            "output directory '{}' already exists",
            opts.output.display()
        );
    }

    if opts.disable_archive && opts.file.is_some() {
        bail!("--file cannot be used with --disable-archive");
    }

    fs::create_dir_all(&opts.output).context("failed to create output directory")?;

    save_perf_version(&opts.output)?;

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

    if opts.enable_perf_script {
        println!("Generating perf.mem.script...");
        if let Err(e) = generate_perf_script(
            ctx,
            &opts.output.join(PERF_MEM_DATA_FILE),
            &opts.output.join(PERF_MEM_SCRIPT_FILE),
            PERF_MEM_SCRIPT_FIELDS,
        ) {
            eprintln!("warning: failed to generate perf.mem.script: {}", e);
        }

        if !opts.disable_sched_trace && opts.output.join(PERF_SCHED_DATA_FILE).exists() {
            println!("Generating perf.sched.script...");
            if let Err(e) = generate_perf_script(
                ctx,
                &opts.output.join(PERF_SCHED_DATA_FILE),
                &opts.output.join(PERF_SCHED_SCRIPT_FILE),
                PERF_SCHED_SCRIPT_FIELDS,
            ) {
                eprintln!("warning: failed to generate perf.sched.script: {}", e);
            }
        }
    }

    if !opts.disable_archive {
        let archive_path = opts
            .file
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{}.tar.gz", opts.output.display())));
        create_archive(&opts.output, &archive_path)?;
        fs::remove_dir_all(&opts.output).context("failed to remove output directory")?;
    }

    Ok(())
}

fn run_recording(ctx: &Context, opts: &RecordOpts) -> Result<bool> {
    let hints_trace_enabled = opts.hints_map.is_some();
    if opts.disable_mem_trace && opts.disable_sched_trace && !hints_trace_enabled {
        bail!("at least one of mem trace, sched trace, or hints trace must be enabled");
    }

    let mut processes = Vec::new();

    if !opts.disable_mem_trace {
        let perf_data_path = opts.output.join(PERF_MEM_DATA_FILE);
        let mem_perf_args = vec![
            perf_binary(),
            "mem".to_string(),
            "record".to_string(),
            "--all-cgroups".to_string(),
            "-p".to_string(),
            "--data-page-size".to_string(),
            "--ldlat".to_string(),
            opts.ldlat.to_string(),
            "-m".to_string(),
            format!("{0},{0}", DEFAULT_PERF_MMAP_SIZE),
            "-o".to_string(),
            perf_data_path.to_string_lossy().to_string(),
        ];
        processes.push(SpawnedProcess::spawn(&mem_perf_args)?);
    }

    if !opts.disable_sched_trace {
        let sched_data_path = opts.output.join(PERF_SCHED_DATA_FILE);
        let sched_perf_args = build_sched_perf_args(&sched_data_path);
        processes.push(SpawnedProcess::spawn(&sched_perf_args)?);
    }

    let hints_recorder = if opts.hints_map.is_some() {
        let hints_path = opts.output.join("hints.jsonl");
        Some(HintsRecorder::new(
            hints_path,
            opts.hints_map.clone().unwrap(),
            opts.hints_map_ring_sz,
        )?)
    } else {
        None
    };

    let mut hints_recorder = hints_recorder;
    let timeout = Duration::from_secs(opts.timeout);
    let start = Instant::now();
    let mut completed = true;

    loop {
        let process_fds: Vec<_> = processes.iter().map(SpawnedProcess::pidfd).collect();
        let ringbuf_fd = hints_recorder.as_ref().map(HintsRecorder::ringbuf_fd);
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            /*
             * Stop tracing hint updates before waiting for perf to flush and
             * exit. Otherwise hints.jsonl keeps accumulating updates during
             * perf teardown and no longer matches the perf capture window.
             */
            stop_hints_recorder(&mut hints_recorder);
            for process in &processes {
                process.signal(libc::SIGINT);
            }
            for process in &mut processes {
                process.wait()?;
            }
            break;
        }

        let remaining_ms = (timeout - elapsed).as_millis().min(100) as i32;

        match poll_fds(ctx.shutdown_fd(), &process_fds, ringbuf_fd, remaining_ms)? {
            PollResult::Shutdown => {
                stop_hints_recorder(&mut hints_recorder);
                for process in &processes {
                    process.signal(libc::SIGKILL);
                }
                for process in &mut processes {
                    process.wait()?;
                }
                completed = false;
                break;
            }
            PollResult::ProcessExited(exited_idx) => {
                stop_hints_recorder(&mut hints_recorder);
                let exited_result = processes[exited_idx].wait();
                for (idx, process) in processes.iter().enumerate() {
                    if idx != exited_idx {
                        process.signal(libc::SIGINT);
                    }
                }
                for (idx, process) in processes.iter_mut().enumerate() {
                    if idx != exited_idx {
                        process.wait()?;
                    }
                }
                exited_result?;
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

fn save_perf_version(output_dir: &Path) -> Result<()> {
    let version_path = output_dir.join("perf.version");

    let output = Command::new(perf_binary())
        .arg("version")
        .output()
        .context("failed to run perf version")?;

    if !output.status.success() {
        bail!("perf version failed");
    }

    fs::write(&version_path, &output.stdout).context("failed to write perf.version")?;

    Ok(())
}

fn create_archive(output_dir: &Path, archive_path: &Path) -> Result<()> {
    let archive_root = archive_root_name(archive_path)?;
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
            archive_path
                .to_str()
                .context("invalid archive output path")?,
            "-C",
            parent.to_str().context("invalid parent path")?,
            "--transform",
            &format!("s,^{},{},", dir_name.to_string_lossy(), archive_root),
            dir_name.to_str().context("invalid directory name")?,
        ])
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        bail!("tar failed with status: {}", status);
    }

    Ok(())
}

fn archive_root_name(archive_path: &Path) -> Result<String> {
    let file_name = archive_path
        .file_name()
        .context("invalid archive output path")?
        .to_string_lossy();

    let archive_root = file_name
        .strip_suffix(".tar.gz")
        .context("archive path must end with .tar.gz")?;

    if archive_root.is_empty() {
        bail!("archive path must include a basename before .tar.gz");
    }

    Ok(archive_root.to_string())
}

pub(crate) fn perf_script_output_exists(output_len: u64) -> bool {
    output_len > 0
}

pub(crate) fn report_perf_script_stderr(context: &str, stderr: &str) {
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        eprintln!("warning: perf script reported diagnostics for {context}:\n{stderr}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sched_perf_args_use_explicit_monotonic_clock() {
        let args = build_sched_perf_args(Path::new("/tmp/perf.sched.data"));

        assert!(
            args.windows(2)
                .any(|window| window == ["-k", PERF_SCHED_CLOCKID]),
            "expected perf record args to include an explicit clockid"
        );
        assert!(
            args.windows(2)
                .any(|window| window == ["-o", "/tmp/perf.sched.data"]),
            "expected perf record args to include the output path"
        );
        for event in SCHED_TRACE_EVENTS {
            assert!(
                args.windows(2).any(|window| window == ["-e", *event]),
                "missing sched trace event {event}"
            );
        }
    }

    #[test]
    fn perf_script_output_exists_requires_nonempty_file() {
        assert!(perf_script_output_exists(1));
        assert!(perf_script_output_exists(4096));
        assert!(!perf_script_output_exists(0));
    }
}

/// Fields to extract from perf mem script output
pub const PERF_MEM_SCRIPT_FIELDS: &str =
    "comm,tid,pid,time,cgroup,ip,addr,phys_addr,data_page_size,dso,sym";

/// Fields to extract from sched trace perf script output
pub const PERF_SCHED_SCRIPT_FIELDS: &str = "comm,pid,tid,cpu,time,event,trace";

fn generate_perf_script(
    ctx: &Context,
    perf_data_path: &Path,
    perf_script_path: &Path,
    fields: &str,
) -> Result<()> {
    if !perf_data_path.exists() {
        bail!("perf data file '{}' not found", perf_data_path.display());
    }

    let output_file = File::create(&perf_script_path)
        .with_context(|| format!("failed to create {}", perf_script_path.display()))?;

    let child = Command::new(perf_binary())
        .args([
            "script",
            "-F",
            fields,
            "-i",
            perf_data_path.to_str().context("invalid perf.data path")?,
        ])
        .stdout(output_file)
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn perf script")?;

    let pid = child.id() as i32;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
    if fd < 0 {
        bail!("pidfd_open failed: {}", std::io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut child = child;

    loop {
        match poll_fds(ctx.shutdown_fd(), &[pidfd.as_raw_fd()], None, 100)? {
            PollResult::Shutdown => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let _ = child.wait();
                let _ = fs::remove_file(&perf_script_path);
                bail!("perf script interrupted");
            }
            PollResult::ProcessExited(_) => {
                let output = child
                    .wait_with_output()
                    .context("failed to wait for perf script")?;
                let stderr = String::from_utf8_lossy(&output.stderr);
                let output_len = fs::metadata(perf_script_path)
                    .map(|meta| meta.len())
                    .unwrap_or(0);
                if !output.status.success() {
                    if perf_script_output_exists(output_len) {
                        eprintln!(
                            "warning: perf script exited with status {} after writing {} bytes to {}. Continuing with the generated output because the output file is non-empty.",
                            output.status,
                            output_len,
                            perf_script_path.display()
                        );
                        report_perf_script_stderr(&perf_script_path.display().to_string(), &stderr);
                        break;
                    }
                    let _ = fs::remove_file(&perf_script_path);
                    let stderr = stderr.trim();
                    if stderr.is_empty() {
                        bail!("perf script failed with status: {}", output.status);
                    }
                    bail!(
                        "perf script failed with status: {}: {}",
                        output.status,
                        stderr
                    );
                }
                report_perf_script_stderr(&perf_script_path.display().to_string(), &stderr);
                break;
            }
            PollResult::RingbufReady | PollResult::Timeout => {}
        }
    }

    Ok(())
}
