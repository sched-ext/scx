// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The per-CID queues, observed from the loader. The arena the BPF program
//! keeps them in is mapped into this process too, at the addresses the
//! program itself uses, so the loader reads a queue through the same
//! `edq` code the program runs, over a memory that can only load.
//!
//! Nothing is added to the scheduling paths for this. A queue already
//! counts the tasks it holds and the tasks ever queued on it, and both
//! are read without its lock. The time a task waits in a queue follows
//! from the two: by Little's law the average wait is the average depth
//! over the arrival rate. The arrivals are exact, and the depth is
//! sampled by a thread that runs only while a stats client is polling.

use std::{
    ffi::OsStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use libbpf_rs::{AsRawLibbpf, MapCore, MapFlags};

use crate::{
    Loaded, OpsProfiler,
    edq::{self, View},
};

/// The arena, read through the mapping libbpf made when it created the
/// map. The addresses the BPF program stores are user addresses in that
/// mapping, so they are read as they are. An address outside of it reads
/// as 0. The view keeps the object, and with it the mapping, alive.
#[derive(Clone)]
pub struct ArenaView {
    base: u64,
    bytes: u64,
    _object: Loaded,
}

impl ArenaView {
    /// The arena of `object`.
    pub fn new(object: &Loaded) -> Result<Self> {
        let map = object
            .maps()
            .find(|map| map.name() == OsStr::new("arena"))
            .context("find arena map")?;
        let mut size = 0;
        // SAFETY: the map belongs to `object`, which is alive.
        let base = unsafe {
            libbpf_rs::libbpf_sys::bpf_map__initial_value(
                map.as_libbpf_object().as_ptr(),
                &mut size,
            )
        };
        ensure!(!base.is_null(), "the arena is not mapped");
        // SAFETY: sysconf() has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
        Ok(Self {
            base: base as u64,
            bytes: u64::from(map.max_entries()) * page,
            _object: object.clone(),
        })
    }

    fn contains(&self, address: u64, bytes: u64) -> bool {
        address >= self.base && bytes <= self.bytes && address - self.base <= self.bytes - bytes
    }

    /// The word at arena address `address`, or 0 for an address that is
    /// not an aligned word of the arena. The BPF program may write the
    /// word at the same time: the read is atomic, of no particular order.
    pub fn read(&self, address: u64) -> u64 {
        if !address.is_multiple_of(8) || !self.contains(address, 8) {
            return 0;
        }
        // SAFETY: the word is aligned and inside the arena's mapping,
        // which lives as long as the object this view keeps.
        unsafe { (*(address as *const AtomicU64)).load(Ordering::Relaxed) }
    }
}

impl View for ArenaView {
    fn load(&self, address: u64) -> u64 {
        self.read(address)
    }
}

/// A per-CID table of the scheduler's, read from the loader: the one whose
/// header is in the `.data` section `section`, see scx_rustsched's `cid_slot!`,
/// with `words` 64-bit words per CID. For counters each CPU keeps for
/// itself, which cost the scheduling paths no shared write.
pub struct CidTableReader {
    view: ArenaView,
    table: u64,
    count: u64,
    words: u64,
}

impl CidTableReader {
    /// The table of the attached scheduler in `object`.
    pub fn new(object: &Loaded, section: &str, words: usize) -> Result<Self> {
        let view = ArenaView::new(object)?;
        let header = object
            .maps()
            .find(|map| map.name() == OsStr::new(section))
            .with_context(|| format!("find the table {section}"))?;
        let mut data = [0_u8; 16];
        ensure!(
            header.lookup_into(&0_u32.to_ne_bytes(), &mut data, MapFlags::ANY)?,
            "read the header of {section}"
        );
        let table = u64::from_ne_bytes(data[..8].try_into()?);
        let count = u64::from_ne_bytes(data[8..].try_into()?);
        let words = words as u64;
        ensure!(
            count != 0 && count <= u64::from(u32::MAX) && view.contains(table, count * words * 8),
            "the table {section} is not in the arena"
        );
        Ok(Self {
            view,
            table,
            count,
            words,
        })
    }

    /// Each word of the entry, summed over the CIDs.
    pub fn sum(&self) -> Vec<u64> {
        let mut sums = vec![0_u64; self.words as usize];
        for cid in 0..self.count {
            for (word, sum) in sums.iter_mut().enumerate() {
                let address = self.table + (cid * self.words + word as u64) * 8;
                *sum = sum.wrapping_add(self.view.read(address));
            }
        }
        sums
    }
}

/// What the sampler saw of one CID's queue, cumulative.
#[derive(Clone, Copy, Debug, Default)]
pub struct QueueStats {
    /// Tasks ever queued, the queue's own count.
    pub inserts: u64,
    /// Sum of the depths sampled.
    pub depth_sum: u64,
    /// Samples that found tasks queued.
    pub busy: u64,
    /// Samples that found the queue's lock held.
    pub locked: u64,
}

struct State {
    last_read: Instant,
    passes: u64,
    queues: Vec<QueueStats>,
}

struct Shared {
    view: ArenaView,
    table: u64,
    stop: AtomicBool,
    state: Mutex<State>,
}

impl Shared {
    fn queue(&self, cid: usize) -> u64 {
        self.table + cid as u64 * edq::QUEUE_BYTES
    }

    /// Sample every queue once.
    fn pass(&self) {
        let mut state = self.state.lock().unwrap();
        for (cid, queue) in state.queues.iter_mut().enumerate() {
            let address = self.queue(cid);
            let depth = edq::nr_queued(&self.view, address);
            queue.depth_sum += depth;
            queue.busy += u64::from(depth != 0);
            queue.locked += u64::from(edq::locked(&self.view, address));
        }
        state.passes += 1;
    }

    fn run(&self) {
        // xorshift, seeded with anything nonzero.
        let mut random = self.table | 1;
        while !self.stop.load(Ordering::Relaxed) {
            let idle = self.state.lock().unwrap().last_read.elapsed() > OpsProfiler::IDLE;
            if idle {
                thread::park();
                continue;
            }
            self.pass();
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            thread::sleep(
                QueueSampler::PERIOD_MIN
                    + QueueSampler::PERIOD_SPREAD
                        .mul_f64((random >> 11) as f64 / (1_u64 << 53) as f64),
            );
        }
    }
}

/// Samples the depth of every CID's queue while a stats client is polling,
/// and parks once nobody has asked for a while, as the callback profiler
/// drops its accounting.
pub struct QueueSampler {
    shared: Arc<Shared>,
    thread: Option<thread::JoinHandle<()>>,
}

impl QueueSampler {
    /// The time between two passes is uniform between PERIOD_MIN and
    /// PERIOD_MIN + PERIOD_SPREAD. A fixed period would beat against the
    /// tick and against periodic workloads, and see the same phase of
    /// them every time.
    const PERIOD_MIN: Duration = Duration::from_millis(5);
    const PERIOD_SPREAD: Duration = Duration::from_millis(10);

    /// Start sampling the queues of the attached scheduler in `object`.
    pub fn new(object: &Loaded) -> Result<Self> {
        let view = ArenaView::new(object)?;
        let queues = object
            .maps()
            .find(|map| map.name() == OsStr::new(".data.queues"))
            .context("find the queue table")?;
        let mut data = [0_u8; 24];
        ensure!(
            queues.lookup_into(&0_u32.to_ne_bytes(), &mut data, MapFlags::ANY)?,
            "read the queue table"
        );
        let table = u64::from_ne_bytes(data[..8].try_into()?);
        let count = u64::from_ne_bytes(data[8..16].try_into()?);
        ensure!(
            count != 0
                && count <= u64::from(u32::MAX)
                && view.contains(table, count * edq::QUEUE_BYTES),
            "the queue table is not in the arena"
        );
        let shared = Arc::new(Shared {
            view,
            table,
            stop: AtomicBool::new(false),
            state: Mutex::new(State {
                // Parked until the first client asks.
                last_read: Instant::now() - OpsProfiler::IDLE * 2,
                passes: 0,
                queues: vec![QueueStats::default(); count as usize],
            }),
        });
        let sampler = shared.clone();
        let thread = thread::Builder::new()
            .name("edq-sampler".into())
            .spawn(move || sampler.run())
            .context("start the queue sampler")?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// The number of sampling passes so far and every queue's statistics,
    /// indexed by CID, with the insert counts read now.
    pub fn sample(&self) -> (u64, Vec<QueueStats>) {
        let (passes, mut queues) = {
            let mut state = self.shared.state.lock().unwrap();
            state.last_read = Instant::now();
            (state.passes, state.queues.clone())
        };
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        for (cid, queue) in queues.iter_mut().enumerate() {
            queue.inserts = edq::nr_inserted(&self.shared.view, self.shared.queue(cid));
        }
        (passes, queues)
    }
}

impl Drop for QueueSampler {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}
