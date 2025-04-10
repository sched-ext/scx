// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use scx_chaos::Builder;
use scx_chaos::RequiresPpid;
use scx_chaos::Scheduler;
use scx_chaos::Trait;

use scx_p2dq::SchedulerOpts as P2dqOpts;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::info;
use nix::unistd::Pid;

use std::panic;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Randomly delay a process.
#[derive(Debug, Parser)]
pub struct RandomDelayArgs {
    /// Chance of randomly delaying a process.
    #[clap(long, requires = "random_delay_min_us")]
    pub random_delay_frequency: Option<f64>,

    /// Minimum time to add for random delay.
    #[clap(long, requires = "random_delay_max_us")]
    pub random_delay_min_us: Option<u64>,

    /// Maximum time to add for random delay.
    #[clap(long, requires = "random_delay_frequency")]
    pub random_delay_max_us: Option<u64>,
}

/// scx_chaos: A general purpose sched_ext scheduler designed to amplify race conditions
///
/// WARNING: This scheduler is a very early alpha, and hasn't been production tested yet. The CLI
/// in particular is likely very unstable and does not guarantee compatibility between versions.
///
/// scx_chaos is a general purpose scheduler designed to run apps with acceptable performance. It
/// has a series of features designed to add latency in paths in an application. All control is
/// through the CLI. Running without arguments will not attempt to introduce latency and can set a
/// baseline for performance impact. The other command line arguments allow for specifying latency
/// inducing behaviours which attempt to induce a crash.
///
/// Unlike most other schedulers, you can also run scx_chaos with a named target. For example:
///     scx_chaos -- ./app_that_might_crash --arg1 --arg2
/// In this mode the scheduler will automatically detach after the application exits, unless run
/// with `--repeat-failure` where it will restart the application on failure.
#[derive(Debug, Parser)]
pub struct Args {
    /// Whether to continue on failure of the command under test.
    #[clap(long, action = clap::ArgAction::SetTrue, requires = "args")]
    pub repeat_failure: bool,

    /// Whether to continue on successful exit of the command under test.
    #[clap(long, action = clap::ArgAction::SetTrue, requires = "args")]
    pub repeat_success: bool,

    /// Whether to focus on the named task and its children instead of the entire system. Only
    /// takes effect if pid or args provided.
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    pub ppid_targeting: bool,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(flatten, next_help_heading = "Random Delays")]
    pub random_delay: RandomDelayArgs,

    #[command(flatten, next_help_heading = "General Scheduling")]
    pub p2dq: P2dqOpts,

    /// Stop the scheduler if specified process terminates
    #[arg(
        long,
        short = 'p',
        help_heading = "Test Command",
        conflicts_with = "args"
    )]
    pub pid: Option<libc::pid_t>,

    /// Program to run under the chaos scheduler
    ///
    /// Runs a program under test and tracks when it terminates, similar to most debuggers. Note
    /// that the scheduler still attaches for every process on the system.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help_heading = "Test Command"
    )]
    pub args: Vec<String>,
}

struct BuilderIterator<'a> {
    args: &'a Args,
    idx: u32,
}

impl<'a> From<&'a Args> for BuilderIterator<'a> {
    fn from(args: &'a Args) -> BuilderIterator<'a> {
        BuilderIterator { args, idx: 0 }
    }
}

impl<'a> Iterator for BuilderIterator<'a> {
    type Item = Builder<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.idx += 1;

        if self.idx > 1 {
            None
        } else {
            let mut traits = vec![];

            if let RandomDelayArgs {
                random_delay_frequency: Some(frequency),
                random_delay_min_us: Some(min_us),
                random_delay_max_us: Some(max_us),
            } = self.args.random_delay
            {
                traits.push(Trait::RandomDelays {
                    frequency,
                    min_us,
                    max_us,
                });
            };

            let requires_ppid = if self.args.ppid_targeting {
                if let Some(p) = self.args.pid {
                    Some(RequiresPpid::IncludeParent(Pid::from_raw(p)))
                } else if !self.args.args.is_empty() {
                    Some(RequiresPpid::ExcludeParent(Pid::this()))
                } else {
                    None
                }
            } else {
                None
            };

            Some(Builder {
                traits,
                verbose: self.args.verbose,
                p2dq_opts: &self.args.p2dq,
                requires_ppid,
            })
        }
    }
}

fn main() -> Result<()> {
    let args = Arc::new(Args::parse());

    let llv = match &args.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    simplelog::TermLogger::init(
        llv,
        simplelog::ConfigBuilder::new()
            .set_time_level(simplelog::LevelFilter::Error)
            .set_location_level(simplelog::LevelFilter::Off)
            .set_target_level(simplelog::LevelFilter::Off)
            .set_thread_level(simplelog::LevelFilter::Off)
            .build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    if args.pid.is_some() {
        return Err(anyhow!("args.pid is not yet implemented"));
    }

    let shutdown = Arc::new((Mutex::new(false), Condvar::new()));

    ctrlc::set_handler({
        let shutdown = shutdown.clone();
        move || {
            let (lock, cvar) = &*shutdown;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
    })
    .context("Error setting Ctrl-C handler")?;

    let scheduler_thread = thread::spawn({
        let args = args.clone();
        let shutdown = shutdown.clone();

        move || -> Result<()> {
            for builder in BuilderIterator::from(&*args) {
                info!("{:?}", &builder);

                let sched: Pin<Box<Scheduler>> = builder.try_into()?;

                sched.observe(&shutdown, None)?;
            }

            Ok(())
        }
    });

    let mut should_run_app = !args.args.is_empty();
    while should_run_app {
        let (cmd, vargs) = args.args.split_first().unwrap();

        let mut child = Command::new(cmd).args(vargs).spawn()?;
        loop {
            should_run_app &= !*shutdown.0.lock().unwrap();

            if scheduler_thread.is_finished() {
                child.kill()?;
                break;
            }
            if let Some(s) = child.try_wait()? {
                if s.success() && args.repeat_success {
                    should_run_app &= !*shutdown.0.lock().unwrap();
                    if should_run_app {
                        info!("app under test terminated successfully, restarting...");
                    };
                } else if s.success() {
                    info!("app under test terminated successfully, exiting...");
                    should_run_app = false;
                } else {
                    info!("TODO: report what the scheduler was doing when it crashed");
                    should_run_app &= !*shutdown.0.lock().unwrap() && args.repeat_failure;
                };

                break;
            };

            thread::sleep(Duration::from_millis(100));
        }
    }

    if !args.args.is_empty() {
        let (lock, cvar) = &*shutdown;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }

    match scheduler_thread.join() {
        Ok(_) => {}
        Err(e) => panic::resume_unwind(e),
    };

    Ok(())
}
