// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>

//! # Intent-Based Preemptive Linux Kernel Scheduler using sched_ext
//!
//! ## Overview
//!
//! `scx_intent` ports the 5-class intent-based preemptive scheduling architecture
//! from the Exploidus Operating System kernel into Linux via `sched_ext` and
//! `scx_rustland_core`.
//!
//! Tasks are classified into five explicit intent tiers with distinct time slices:
//! - **Audit / Security (`INTENT_AUDIT`)**: 10 ms slice (highest priority)
//! - **Interactive (`INTENT_INTERACTIVE`)**: 4 ms slice (UI, audio, compositors)
//! - **I/O (`INTENT_IO`)**: 5 ms slice (storage daemons, rapid wakeup)
//! - **Network (`INTENT_NETWORK`)**: 8 ms slice (socket & packet handlers)
//! - **Compute (`INTENT_COMPUTE`)**: 20 ms slice (compilers, heavy throughput)

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

#[rustfmt::skip]
mod bpf;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use anyhow::Result;
use bpf::*;
use libbpf_rs::OpenObject;
use scx_utils::UserExitInfo;
use scx_utils::libbpf_clap_opts::LibbpfOpts;

// Timeslices per intent in nanoseconds (ported from Exploidus SLICE_* ticks)
const SLICE_INTERACTIVE_NS: u64 = 4_000_000;  // 4 ms
const SLICE_IO_NS: u64 = 5_000_000;           // 5 ms
const SLICE_NETWORK_NS: u64 = 8_000_000;      // 8 ms
const SLICE_AUDIT_NS: u64 = 10_000_000;       // 10 ms
const SLICE_COMPUTE_NS: u64 = 20_000_000;     // 20 ms

// Maximum passes higher queues can preempt compute before forced starvation relief
const STARVATION_THRESHOLD: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Audit = 0,
    Interactive = 1,
    Io = 2,
    Network = 3,
    Compute = 4,
}

const INTENT_COUNT: usize = 5;

// Dispatch priority order from Exploidus QUEUE_ORDER:
// Audit -> Interactive -> IO -> Network -> Compute
const QUEUE_ORDER: [Intent; INTENT_COUNT] = [
    Intent::Audit,
    Intent::Interactive,
    Intent::Io,
    Intent::Network,
    Intent::Compute,
];

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
    queues: [VecDeque<QueuedTask>; INTENT_COUNT],
    stats: [u64; INTENT_COUNT],
    starvation_counter: u32,
}

impl<'a> Scheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let open_opts = LibbpfOpts::default();
        let bpf = BpfScheduler::init(
            open_object,
            open_opts.clone().into_bpf_open_opts(),
            0,                 // exit_dump_len
            false,             // partial
            false,             // debug
            true,              // builtin_idle
            false,             // numa_local
            SLICE_COMPUTE_NS,  // default fallback slice
            "intent",          // name of scx ops
        )?;

        Ok(Self {
            bpf,
            queues: [
                VecDeque::new(), // Audit
                VecDeque::new(), // Interactive
                VecDeque::new(), // Io
                VecDeque::new(), // Network
                VecDeque::new(), // Compute
            ],
            stats: [0; INTENT_COUNT],
            starvation_counter: 0,
        })
    }

    fn task_comm_str(task: &QueuedTask) -> &str {
        let len = task
            .comm
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(task.comm.len());
        let bytes = unsafe { std::slice::from_raw_parts(task.comm.as_ptr() as *const u8, len) };
        std::str::from_utf8(bytes).unwrap_or("")
    }

    /// Classify a queued task into an Exploidus Intent tier
    fn classify_task(task: &QueuedTask) -> Intent {
        let comm = Self::task_comm_str(task);

        // 1. Audit & Security Intent
        if comm.starts_with("auditd")
            || comm.starts_with("systemd-journal")
            || comm.starts_with("falco")
            || comm.starts_with("osquery")
            || comm.starts_with("apparmor")
        {
            return Intent::Audit;
        }

        // 2. Interactive & Low-Latency UI / Audio Intent
        if comm.starts_with("pipewire")
            || comm.starts_with("wireplumber")
            || comm.starts_with("pulseaudio")
            || comm.starts_with("wayland")
            || comm.starts_with("hyprland")
            || comm.starts_with("sway")
            || comm.starts_with("kwin")
            || comm.starts_with("gnome-shell")
            || comm.starts_with("Xorg")
            || comm.starts_with("alacritty")
            || comm.starts_with("kitty")
            || task.weight > 150
        {
            return Intent::Interactive;
        }

        // 3. Network Intent
        if comm.starts_with("sshd")
            || comm.starts_with("nginx")
            || comm.starts_with("caddy")
            || comm.starts_with("wpa_supplicant")
            || comm.starts_with("wireguard")
        {
            return Intent::Network;
        }

        // 4. Compute Intent (compilers, heavy throughput)
        if comm.starts_with("gcc")
            || comm.starts_with("cc1")
            || comm.starts_with("clang")
            || comm.starts_with("rustc")
            || comm.starts_with("make")
            || comm.starts_with("ninja")
            || comm.starts_with("cargo")
            || comm.starts_with("ffmpeg")
            || task.weight < 60
        {
            return Intent::Compute;
        }

        // 5. Default balanced tier based on nice/weight
        if task.weight > 100 {
            Intent::Interactive
        } else if task.weight >= 80 {
            Intent::Io
        } else {
            Intent::Compute
        }
    }

    fn slice_for_intent(intent: Intent) -> u64 {
        match intent {
            Intent::Audit => SLICE_AUDIT_NS,
            Intent::Interactive => SLICE_INTERACTIVE_NS,
            Intent::Io => SLICE_IO_NS,
            Intent::Network => SLICE_NETWORK_NS,
            Intent::Compute => SLICE_COMPUTE_NS,
        }
    }

    fn dispatch_one(&mut self, intent: Intent) -> bool {
        let idx = intent as usize;
        let Some(task) = self.queues[idx].pop_front() else {
            return false;
        };

        let mut dispatched_task = DispatchedTask::new(&task);
        let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
        dispatched_task.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };
        dispatched_task.slice_ns = Self::slice_for_intent(intent);

        if self.bpf.dispatch_task(&dispatched_task).is_err() {
            // Re-enqueue task at front so it is not dropped under congestion
            self.queues[idx].push_front(task);
            return false;
        }

        self.stats[idx] += 1;
        true
    }

    fn dispatch_tasks(&mut self) {
        // Dequeue tasks from BPF backend and classify them into intent queues
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            let intent = Self::classify_task(&task);
            self.queues[intent as usize].push_back(task);
        }

        // Check anti-starvation: if high-priority queues dominated while compute was waiting
        if self.starvation_counter >= STARVATION_THRESHOLD {
            if self.dispatch_one(Intent::Compute) {
                self.starvation_counter = 0;
            }
        }

        // Drain queues in strict Exploidus intent order:
        // Audit -> Interactive -> IO -> Network -> Compute
        let has_pending_compute = !self.queues[Intent::Compute as usize].is_empty();
        let mut higher_dispatched = false;

        for &intent in &QUEUE_ORDER {
            let idx = intent as usize;
            while !self.queues[idx].is_empty() {
                if !self.dispatch_one(intent) {
                    // Dispatch buffer congested, stop draining for now
                    break;
                }
                if intent != Intent::Compute {
                    higher_dispatched = true;
                } else {
                    self.starvation_counter = 0;
                }
            }
        }

        if higher_dispatched && has_pending_compute {
            self.starvation_counter = self.starvation_counter.saturating_add(1);
        }

        // Report remaining pending tasks to BPF engine
        let pending: usize = self.queues.iter().map(|q| q.len()).sum();
        self.bpf.notify_complete(pending as u64);
    }

    fn print_stats(&mut self) {
        let running = *self.bpf.nr_running_mut();
        let queued = *self.bpf.nr_queued_mut();

        println!(
            "[scx_intent] audit={} interactive={} io={} net={} compute={} | running={} queued={}",
            self.stats[Intent::Audit as usize],
            self.stats[Intent::Interactive as usize],
            self.stats[Intent::Io as usize],
            self.stats[Intent::Network as usize],
            self.stats[Intent::Compute as usize],
            running,
            queued,
        );
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        println!("scx_intent: Exploidus 5-class intent preemptive scheduler active.");
        println!("Prioritizing Audit & Interactive workloads with dynamic timeslices.");
        println!("Press Ctrl-C to exit.");

        while !self.bpf.exited() {
            self.dispatch_tasks();

            let curr_ts = Self::now();
            if curr_ts > prev_ts {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }

        self.bpf.shutdown_and_report()
    }
}

fn main() -> Result<()> {
    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_slices() {
        assert_eq!(Scheduler::slice_for_intent(Intent::Audit), 10_000_000);
        assert_eq!(Scheduler::slice_for_intent(Intent::Interactive), 4_000_000);
        assert_eq!(Scheduler::slice_for_intent(Intent::Io), 5_000_000);
        assert_eq!(Scheduler::slice_for_intent(Intent::Network), 8_000_000);
        assert_eq!(Scheduler::slice_for_intent(Intent::Compute), 20_000_000);
    }

    #[test]
    fn test_queue_precedence_order() {
        assert_eq!(QUEUE_ORDER[0], Intent::Audit);
        assert_eq!(QUEUE_ORDER[1], Intent::Interactive);
        assert_eq!(QUEUE_ORDER[2], Intent::Io);
        assert_eq!(QUEUE_ORDER[3], Intent::Network);
        assert_eq!(QUEUE_ORDER[4], Intent::Compute);
    }
}

