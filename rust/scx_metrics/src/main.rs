// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

// TODO:
// 1. Make work-conservation accounting affinity-aware so restricted tasks do
//    not create demand for CPUs on which they cannot run.
// 2. Support grouping metrics by tasks in user-specified cgroups.
// 3. Add more metrics needed to monitor the health and behavior of sched_ext
//    schedulers in production.

use anyhow::Result;
use clap::{Parser, ValueEnum};
use scx_metrics::{Collector, MetricsSnapshot};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Openmetrics,
}

#[derive(Debug, Parser)]
#[command(about = "Print and export low-overhead sched_ext metrics")]
struct Args {
    /// Output format for periodic snapshots.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Listen for Prometheus scrapes and serve cumulative stats at /metrics.
    #[arg(long = "web-listen", alias = "listen")]
    web_listen: Option<String>,

    /// Measurement and output interval.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,

    /// Suppress periodic stdout while serving /metrics.
    #[arg(long)]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut collector = Collector::start()?;
    let listener = if let Some(address) = &args.web_listen {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        eprintln!("scx_metrics listening on http://{address}/metrics");
        Some(listener)
    } else {
        None
    };
    let mut previous = MetricsSnapshot::default();
    let report_interval = Duration::from_millis(args.interval_ms);

    loop {
        thread::sleep(report_interval);
        collector.collect()?;
        let snapshot = collector.snapshot()?;
        if !args.quiet {
            match args.format {
                Format::Text => println!("{}", snapshot.delta_from(&previous).to_text()),
                Format::Openmetrics => print!("{}", snapshot.to_openmetrics()),
            }
        }
        if let Some(listener) = &listener {
            while let Ok((stream, _)) = listener.accept() {
                respond(stream, &snapshot.to_openmetrics())?;
            }
        }
        previous = snapshot;
    }
}

fn respond(mut stream: TcpStream, body: &str) -> Result<()> {
    let mut request = [0_u8; 1024];
    let _ = stream.read(&mut request)?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )?;
    Ok(())
}
