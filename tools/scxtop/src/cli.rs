// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use crate::APP;
use crate::STATS_SOCKET_PATH;
use crate::TRACE_FILE_PREFIX;

use anyhow::Result;
use clap::{Command, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::fs::File;
use std::io;

use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[clap(flatten)]
    pub tui: TuiArgs,
}

#[derive(Clone, Parser, Debug)]
#[command(about = APP)]
pub struct TuiArgs {
    /// App tick rate in milliseconds.
    #[arg(short = 'r', long, default_missing_value = "250")]
    pub tick_rate_ms: Option<usize>,
    /// App render rate in milliseconds (min=15).
    #[arg(short = 'f', long, default_missing_value = "250")]
    pub frame_rate_ms: Option<usize>,
    /// Extra verbose output.
    #[arg(short, long, default_missing_value = "false")]
    pub debug: Option<bool>,
    /// Exclude bpf event tracking.
    #[arg(short, long, default_missing_value = "false")]
    pub exclude_bpf: Option<bool>,
    /// Stats unix socket path.
    #[arg(short, long, default_missing_value = STATS_SOCKET_PATH.to_string())]
    pub stats_socket_path: Option<String>,
    /// Trace file prefix for perfetto traces.
    #[arg(short, long, default_missing_value = TRACE_FILE_PREFIX.to_string())]
    pub trace_file_prefix: Option<String>,
    /// DEPRECATED: Number of ticks for traces. Use --trace-duration-ms instead.
    #[arg(long, default_missing_value = "5")]
    pub trace_ticks: Option<usize>,
    /// Duration of trace in ms.
    #[arg(long)]
    pub trace_duration_ms: Option<u64>,
    /// Number of worker threads.
    #[arg(long, default_missing_value = "4", value_parser = clap::value_parser!(u16).range(2..128))]
    pub worker_threads: Option<u16>,
    /// DEPRECATED: Number of ticks to warmup before collecting traces. Use --trace-warmup-ms instead.
    #[arg(long, default_missing_value = "3")]
    pub trace_tick_warmup: Option<usize>,
    /// Duration to warmup a trace before collecting in ms.
    #[arg(long)]
    pub trace_warmup_ms: Option<u64>,
    /// Process to monitor or all.
    #[arg(long, default_value_t = -1)]
    pub process_id: i32,
    /// Custom perf events colon delimited (ex: "<event_name>:<event and umask ex: 0x023>:<event_type ex: 4>")
    #[arg(long, num_args = 1.., value_parser)]
    pub perf_events: Vec<String>,
    /// Default profiling event colon delimited (ex: "<source>:<event>")
    /// where source is one of 'kprobe', 'perf', 'cpu'. Ex: "cpu:cpu_total_util_percent", "perf:hw:cycles"
    #[arg(long, default_value = "cpu:cpu_total_util_percent")]
    pub default_profiling_event: String,
    /// Show scx_layered data (process level layer_id's)
    #[arg(long)]
    pub layered: bool,

    /// Automatically start a trace when a function takes too long to return.
    #[arg(
        long,
        default_value_t = false,
        requires("experimental_long_tail_tracing_symbol"),
        requires("experimental_long_tail_tracing_binary")
    )]
    pub experimental_long_tail_tracing: bool,
    /// Symbol to automatically trace the long tail of.
    #[arg(long)]
    pub experimental_long_tail_tracing_symbol: Option<String>,
    /// Binary to attach the uprobe and uretprobe to.
    #[arg(long)]
    pub experimental_long_tail_tracing_binary: Option<String>,
    /// Minimum latency to trigger a trace.
    #[arg(long, default_value_t = 100000000)]
    pub experimental_long_tail_tracing_min_latency_ns: u64,

    /// Trace mangoapp applications
    #[arg(long, default_value_t = false)]
    pub mangoapp_tracing: bool,
    /// Mangoapp poll interval in ms
    #[arg(long, default_value_t = 1000)]
    pub mangoapp_poll_intvl_ms: u64,
    /// Mangoapp path for System V IPC key
    #[arg(long, default_value = "mangoapp")]
    pub mangoapp_path: String,
}

#[derive(Clone, Parser, Debug)]
#[command(about = "Collects a trace")]
pub struct TraceArgs {
    /// Trace duration.
    #[arg(short = 'd', long, default_value_t = 1000)]
    pub trace_ms: u64,
    /// Trace output file.
    #[arg(short = 'o', long)]
    pub output_file: Option<String>,
    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Add a list of kprobe events to the trace.
    #[clap(short = 'k', long, num_args = 1.., value_parser)]
    pub kprobes: Vec<String>,
    /// Collect system statistics (CPU, memory, etc).
    #[clap(short = 's', long)]
    pub system_stats: bool,
}

#[derive(Clone, Parser, Debug)]
#[command(about = "Runs the MCP server for scheduler data access")]
pub struct McpArgs {
    /// Run in daemon mode (persistent, continuously collecting data).
    /// Without this flag, the server runs in one-shot mode (query-response per invocation).
    #[arg(short = 'd', long)]
    pub daemon: bool,

    /// Enable MCP logging capability (sends logs to client).
    #[arg(short = 'l', long)]
    pub enable_logging: bool,

    /// Enable verbose output for debugging MCP protocol.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Stats unix socket path for scx_stats integration.
    #[arg(long, default_value = STATS_SOCKET_PATH)]
    pub stats_socket_path: String,

    /// Process ID to monitor (or -1 for all processes).
    #[arg(long, default_value_t = -1)]
    pub process_id: i32,

    /// Show scx_layered data (process level layer_id's).
    #[arg(long)]
    pub layered: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Commands {
    /// Runs the scxtop TUI.
    Tui(TuiArgs),

    /// Collects a trace.
    Trace(TraceArgs),

    /// Runs the MCP (Model Context Protocol) server.
    Mcp(McpArgs),

    #[clap(hide = true)]
    GenerateCompletions {
        /// The shell type
        #[clap(short, long, default_value = "bash")]
        shell: Shell,
        /// Output file, stdout if not present
        #[arg(long, value_parser(clap::value_parser!(PathBuf)))]
        output: Option<PathBuf>,
    },
}

/// Generates clap completions
pub fn generate_completions(mut app: Command, shell: Shell, output: Option<PathBuf>) -> Result<()> {
    let mut file: Box<dyn io::Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };

    generate(shell, &mut app, "scxtop", &mut file);
    Ok(())
}
