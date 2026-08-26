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
use std::os::fd::OwnedFd;
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::libbpf_sys;
use libbpf_rs::MapCore as _;

const MEMBARRIER_CMD_GLOBAL: libc::c_long = 1;
const URCU_DOORBELL: &str = "scx_urcu_doorbell";
const URCU_MIN_INTERVAL: Duration = Duration::from_millis(1);

/// Userspace half of the scx_urcu machinery, see the BPF side in
/// lib/sdt_alloc.bpf.c. ArenaLib::setup() spawns the daemon when the object
/// carries the scx_urcu doorbell and it runs detached for the rest of the
/// process, so nothing is visible to the scheduler: its whole surface is
/// calling the scx_*_free_rcu() variants from its free path hooks.
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

fn urcu_daemon(doorbell: libbpf_rs::MapHandle, pairs: Vec<(OwnedFd, OwnedFd)>) -> Result<()> {
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&doorbell, |_| 0)
        .context("adding urcu doorbell to ring buffer")?;
    let rb = builder
        .build()
        .context("building urcu doorbell ring buffer")?;

    let mut last: Option<Instant> = None;
    loop {
        let mut fds = [libc::pollfd {
            fd: doorbell.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("urcu doorbell poll failed: {}", err);
        }

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
    }
}

/// Spawn the detached urcu reclaim daemon if @obj carries the scx_urcu
/// doorbell and driver programs. Called from ArenaLib::setup().
pub(crate) fn urcu_spawn(obj: &libbpf_rs::Object) -> Result<()> {
    let Some(doorbell) = obj.maps().find(|m| m.name() == URCU_DOORBELL) else {
        return Ok(());
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

        pairs.push((
            prog.as_fd().try_clone_to_owned()?,
            reclaim.as_fd().try_clone_to_owned()?,
        ));
    }
    if pairs.is_empty() {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("scx-urcu".into())
        .spawn(move || {
            if let Err(e) = urcu_daemon(doorbell, pairs) {
                eprintln!("scx-urcu daemon exiting on error: {:#}", e);
            }
        })
        .context("spawning urcu daemon thread")?;

    Ok(())
}
