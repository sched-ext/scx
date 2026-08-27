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
