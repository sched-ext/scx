// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>

//! # Intent-Based Preemptive Linux Kernel Scheduler using sched_ext
//!
//! ## Overview
//!
//! `scx_intent` ports the 5-class intent-based preemptive scheduling architecture
//! from the Exploidus Operating System directly into the Linux kernel via `sched_ext`
//! using 5 dedicated BPF Dispatch Queues (DSQs).
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
pub use bpf_intf::*;

use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{MapCore, OpenObject};
use log::info;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::{
    UserExitInfo, compat, scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity,
    uei_exited, uei_report,
};
use serde::{Deserialize, Serialize};

const SCHEDULER_NAME: &str = "scx_intent";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConfig {
    #[serde(default)]
    pub audit: Vec<String>,
    #[serde(default)]
    pub interactive: Vec<String>,
    #[serde(default)]
    pub io: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub compute: Vec<String>,
}

impl IntentConfig {
    pub fn desktop() -> Self {
        Self {
            audit: vec![
                "auditd".into(),
                "systemd-journ".into(),
                "pipewire".into(),
                "wireplumber".into(),
                "pulseaudio".into(),
            ],
            interactive: vec![
                "wayland".into(),
                "hyprland".into(),
                "sway".into(),
                "kwin".into(),
                "gnome-shell".into(),
                "Xorg".into(),
                "alacritty".into(),
                "kitty".into(),
                "firefox".into(),
                "chrome".into(),
                "steam".into(),
                "discord".into(),
            ],
            io: vec![
                "systemd-resolved".into(),
                "dbus-broker".into(),
                "dbus-daemon".into(),
            ],
            network: vec![
                "sshd".into(),
                "nginx".into(),
                "caddy".into(),
                "wpa_supplicant".into(),
                "wireguard".into(),
            ],
            compute: vec![
                "gcc".into(),
                "clang".into(),
                "rustc".into(),
                "make".into(),
                "ninja".into(),
                "cargo".into(),
                "ffmpeg".into(),
            ],
        }
    }

    pub fn gaming() -> Self {
        Self {
            audit: vec!["pipewire".into(), "wireplumber".into()],
            interactive: vec![
                "steam".into(),
                "wine".into(),
                "proton".into(),
                "gamescope".into(),
                "vulkan".into(),
                "wayland".into(),
                "kwin".into(),
                "hyprland".into(),
                "gamemoded".into(),
                "mangohud".into(),
            ],
            io: vec![],
            network: vec!["sshd".into()],
            compute: vec!["rustc".into(), "gcc".into(), "make".into()],
        }
    }

    pub fn server() -> Self {
        Self {
            audit: vec!["auditd".into(), "falco".into(), "osquery".into()],
            interactive: vec!["sshd".into(), "bash".into(), "zsh".into()],
            io: vec![
                "postgres".into(),
                "mysqld".into(),
                "redis-server".into(),
                "etcd".into(),
            ],
            network: vec![
                "nginx".into(),
                "envoy".into(),
                "haproxy".into(),
                "caddy".into(),
            ],
            compute: vec![
                "ffmpeg".into(),
                "python3".into(),
                "java".into(),
                "rustc".into(),
            ],
        }
    }
}

#[derive(Debug, Parser)]
#[clap(
    name = SCHEDULER_NAME,
    about = "Exploidus 5-class intent-based preemptive CPU scheduler"
)]
struct Opts {
    /// Starvation threshold before lower queues are boosted (default: 32).
    #[clap(short = 's', long, default_value = "32")]
    starvation_threshold: u32,

    /// Built-in configuration preset (desktop, gaming, server).
    #[clap(short = 'p', long, default_value = "desktop")]
    preset: String,

    /// Path to user-defined JSON configuration file.
    #[clap(short = 'c', long)]
    config: Option<PathBuf>,

    /// Stats reporting interval in seconds (0 = disabled).
    #[clap(short = 'i', long, default_value = "1")]
    stats_interval: u64,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable debug mode.
    #[clap(short = 'd', long)]
    debug: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    _struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, intent_ops, open_opts)?;

        skel.struct_ops.intent_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Configure BPF tunables
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.debug = opts.debug;
        rodata.starvation_threshold = opts.starvation_threshold;

        // Scheduler flags: enforce explicit enqueue and bypass disabling
        skel.struct_ops.intent_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        let mut skel = scx_ops_load!(skel, intent_ops, uei)?;

        // Load configuration from user-defined JSON file or built-in preset
        let config = if let Some(path) = &opts.config {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str(&data)?
        } else {
            match opts.preset.to_lowercase().as_str() {
                "gaming" => IntentConfig::gaming(),
                "server" => IntentConfig::server(),
                _ => IntentConfig::desktop(),
            }
        };

        // Populate dynamic BPF intent_map
        let intent_map = &skel.maps.intent_map;
        let entries = [
            (config.audit, 0u32),       // INTENT_AUDIT
            (config.interactive, 1u32), // INTENT_INTERACTIVE
            (config.io, 2u32),          // INTENT_IO
            (config.network, 3u32),     // INTENT_NETWORK
            (config.compute, 4u32),     // INTENT_COMPUTE
        ];

        for (names, intent_val) in entries {
            for name in names {
                let mut key = [0u8; 16];
                let bytes = name.as_bytes();
                let len = bytes.len().min(15);
                key[..len].copy_from_slice(&bytes[..len]);
                let val_bytes = intent_val.to_ne_bytes();
                let _ = intent_map.update(&key, &val_bytes, libbpf_rs::MapFlags::ANY);
            }
        }

        let struct_ops = Some(scx_ops_attach!(skel, intent_ops)?);

        Ok(Self {
            skel,
            _struct_ops: struct_ops,
            opts,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        println!("scx_intent: Exploidus 5-class pure BPF scheduler loaded.");
        println!(
            "Operating with 5 dedicated DSQs (Audit: 10ms, Interactive: 4ms, IO: 5ms, Net: 8ms, Compute: 20ms)."
        );
        println!("Press Ctrl-C to exit.");

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            if self.opts.stats_interval > 0 {
                sleep(Duration::from_secs(self.opts.stats_interval));
                self.print_stats();
            } else {
                sleep(Duration::from_millis(500));
            }
        }

        uei_report!(&self.skel, uei)
    }

    fn print_stats(&self) {
        if let Some(bss) = self.skel.maps.bss_data.as_ref() {
            let stats = bss.stats;
            println!(
                "[scx_intent] enq: [aud={} int={} io={} net={} comp={}] | dsp: [aud={} int={} io={} net={} comp={}] | starved: [int={} io={} net={} comp={}]",
                stats.enqueued[intent_type_INTENT_AUDIT as usize],
                stats.enqueued[intent_type_INTENT_INTERACTIVE as usize],
                stats.enqueued[intent_type_INTENT_IO as usize],
                stats.enqueued[intent_type_INTENT_NETWORK as usize],
                stats.enqueued[intent_type_INTENT_COMPUTE as usize],
                stats.dispatched[intent_type_INTENT_AUDIT as usize],
                stats.dispatched[intent_type_INTENT_INTERACTIVE as usize],
                stats.dispatched[intent_type_INTENT_IO as usize],
                stats.dispatched[intent_type_INTENT_NETWORK as usize],
                stats.dispatched[intent_type_INTENT_COMPUTE as usize],
                stats.starved_dispatches[intent_type_INTENT_INTERACTIVE as usize],
                stats.starved_dispatches[intent_type_INTENT_IO as usize],
                stats.starved_dispatches[intent_type_INTENT_NETWORK as usize],
                stats.starved_dispatches[intent_type_INTENT_COMPUTE as usize],
            );
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    simplelog::TermLogger::init(
        if opts.debug {
            simplelog::LevelFilter::Debug
        } else {
            simplelog::LevelFilter::Info
        },
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let s = shutdown.clone();
    ctrlc::set_handler(move || {
        s.store(true, Ordering::Relaxed);
    })?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    let uei = sched.run(shutdown)?;
    info!("Scheduler stopped: {:?}", uei);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_consts() {
        assert_eq!(intent_type_INTENT_AUDIT, 0);
        assert_eq!(intent_type_INTENT_INTERACTIVE, 1);
        assert_eq!(intent_type_INTENT_IO, 2);
        assert_eq!(intent_type_INTENT_NETWORK, 3);
        assert_eq!(intent_type_INTENT_COMPUTE, 4);
    }
}
