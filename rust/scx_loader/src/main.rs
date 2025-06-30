// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Vladislav Nepogodin <vnepogodin@cachyos.org>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod logger;

use scx_loader::dbus::LoaderClientProxy;
use scx_loader::*;

use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use sysinfo::System;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Duration;
use tokio::time::Instant;
use zbus::interface;
use zbus::Connection;

#[derive(Debug, PartialEq)]
enum ScxMessage {
    /// Quit the scx_loader
    Quit,
    /// Stop the scheduler, if any
    StopSched,
    /// Start the scheduler with the given mode
    StartSched((SupportedSched, SchedMode)),
    /// Start the scheduler with the given scx arguments
    StartSchedArgs((SupportedSched, Vec<String>)),
    /// Switch to another scheduler with the given mode
    SwitchSched((SupportedSched, SchedMode)),
    /// Switch to another scheduler with the given scx arguments
    SwitchSchedArgs((SupportedSched, Vec<String>)),
}

#[derive(Debug, PartialEq)]
enum RunnerMessage {
    /// Switch to another scheduler with the given scx arguments
    Switch((SupportedSched, Vec<String>)),
    /// Start the scheduler with the given scx arguments
    Start((SupportedSched, Vec<String>)),
    /// Stop the scheduler, if any
    Stop,
}

struct ScxLoader {
    current_scx: Option<SupportedSched>,
    current_mode: SchedMode,
    channel: UnboundedSender<ScxMessage>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, short, action)]
    auto: bool,
}

#[interface(name = "org.scx.Loader")]
impl ScxLoader {
    /// Get currently running scheduler, in case non is running return "unknown"
    #[zbus(property)]
    async fn current_scheduler(&self) -> String {
        if let Some(current_scx) = &self.current_scx {
            let current_scx: &str = current_scx.clone().into();
            log::info!("called {current_scx:?}");
            return current_scx.to_owned();
        }
        "unknown".to_owned()
    }

    /// Get scheduler mode
    #[zbus(property)]
    async fn scheduler_mode(&self) -> SchedMode {
        self.current_mode.clone()
    }

    /// Get list of supported schedulers
    #[zbus(property)]
    async fn supported_schedulers(&self) -> Vec<&str> {
        vec![
            "scx_bpfland",
            "scx_flash",
            "scx_lavd",
            "scx_p2dq",
            "scx_tickless",
            "scx_rustland",
            "scx_rusty",
            "scx_spark",
        ]
    }

    async fn start_scheduler(
        &mut self,
        scx_name: SupportedSched,
        sched_mode: SchedMode,
    ) -> zbus::fdo::Result<()> {
        log::info!("starting {scx_name:?} with mode {sched_mode:?}..");

        let _ = self.channel.send(ScxMessage::StartSched((
            scx_name.clone(),
            sched_mode.clone(),
        )));
        self.current_scx = Some(scx_name);
        self.current_mode = sched_mode;

        Ok(())
    }

    async fn start_scheduler_with_args(
        &mut self,
        scx_name: SupportedSched,
        scx_args: Vec<String>,
    ) -> zbus::fdo::Result<()> {
        log::info!("starting {scx_name:?} with args {scx_args:?}..");

        let _ = self
            .channel
            .send(ScxMessage::StartSchedArgs((scx_name.clone(), scx_args)));
        self.current_scx = Some(scx_name);
        // reset mode to auto
        self.current_mode = SchedMode::Auto;

        Ok(())
    }

    async fn switch_scheduler(
        &mut self,
        scx_name: SupportedSched,
        sched_mode: SchedMode,
    ) -> zbus::fdo::Result<()> {
        log::info!("switching {scx_name:?} with mode {sched_mode:?}..");

        let _ = self.channel.send(ScxMessage::SwitchSched((
            scx_name.clone(),
            sched_mode.clone(),
        )));
        self.current_scx = Some(scx_name);
        self.current_mode = sched_mode;

        Ok(())
    }

    async fn switch_scheduler_with_args(
        &mut self,
        scx_name: SupportedSched,
        scx_args: Vec<String>,
    ) -> zbus::fdo::Result<()> {
        log::info!("switching {scx_name:?} with args {scx_args:?}..");

        let _ = self
            .channel
            .send(ScxMessage::SwitchSchedArgs((scx_name.clone(), scx_args)));
        self.current_scx = Some(scx_name);
        // reset mode to auto
        self.current_mode = SchedMode::Auto;

        Ok(())
    }

    async fn stop_scheduler(&mut self) -> zbus::fdo::Result<()> {
        if let Some(current_scx) = &self.current_scx {
            let scx_name: &str = current_scx.clone().into();

            log::info!("stopping {scx_name:?}..");
            let _ = self.channel.send(ScxMessage::StopSched);
            self.current_scx = None;
        }

        Ok(())
    }
}

// Monitors CPU utilization and enables scx_lavd when utilization of any CPUs is > 90%
async fn monitor_cpu_util() -> Result<()> {
    let mut system = System::new_all();
    let mut running_sched: Option<Child> = None;
    let mut cpu_above_threshold_since: Option<Instant> = None;
    let mut cpu_below_threshold_since: Option<Instant> = None;

    let high_utilization_threshold = 90.0;
    let low_utilization_threshold_duration = Duration::from_secs(30);
    let high_utilization_trigger_duration = Duration::from_secs(5);

    loop {
        system.refresh_cpu_all();

        let any_cpu_above_threshold = system
            .cpus()
            .iter()
            .any(|cpu| cpu.cpu_usage() > high_utilization_threshold);

        if any_cpu_above_threshold {
            if cpu_above_threshold_since.is_none() {
                cpu_above_threshold_since = Some(Instant::now());
            }

            if cpu_above_threshold_since.unwrap().elapsed() > high_utilization_trigger_duration {
                if running_sched.is_none() {
                    log::info!("CPU Utilization exceeded 90% for 5 seconds, starting scx_lavd");

                    let scx_name: &str = SupportedSched::Lavd.into();
                    running_sched = Some(
                        Command::new(scx_name)
                            .spawn()
                            .expect("Failed to start scx_lavd"),
                    );
                }

                cpu_below_threshold_since = None;
            }
        } else {
            cpu_above_threshold_since = None;

            if cpu_below_threshold_since.is_none() {
                cpu_below_threshold_since = Some(Instant::now());
            }

            if cpu_below_threshold_since.unwrap().elapsed() > low_utilization_threshold_duration {
                if let Some(mut running_sched_loc) = running_sched.take() {
                    log::info!(
                        "CPU utilization dropped below 90% for more than 30 seconds, exiting latency-aware scheduler"
                    );
                    running_sched_loc
                        .kill()
                        .await
                        .expect("Failed to kill scx_lavd");
                    let lavd_exit_status = running_sched_loc
                        .wait()
                        .await
                        .expect("Failed to wait on scx_lavd");
                    log::info!("scx_lavd exited with status: {}", lavd_exit_status);
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialize the logger
    logger::init_logger().expect("Failed to initialize logger");

    let args = Args::parse();

    // initialize the config
    let config = config::init_config().context("Failed to initialize config")?;

    // If --auto is passed, start scx_loader as a standard background process
    // that swaps schedulers out automatically
    // based on CPU utilization without registering a dbus interface.
    if args.auto {
        log::info!("Starting scx_loader monitor as standard process without dbus interface");
        monitor_cpu_util().await?;
        return Ok(());
    }

    log::info!("Starting as dbus interface");
    // setup channel
    let (channel, rx) = tokio::sync::mpsc::unbounded_channel::<ScxMessage>();

    let channel_clone = channel.clone();
    ctrlc::set_handler(move || {
        log::info!("shutting down..");
        let _ = channel_clone.send(ScxMessage::Quit);
    })
    .context("Error setting Ctrl-C handler")?;

    // register dbus interface
    let connection = Connection::system().await?;
    connection
        .object_server()
        .at(
            "/org/scx/Loader",
            ScxLoader {
                current_scx: None,
                current_mode: SchedMode::Auto,
                channel: channel.clone(),
            },
        )
        .await?;

    connection.request_name("org.scx.Loader").await?;

    // if user set default scheduler, then start it
    if let Some(default_sched) = &config.default_sched {
        log::info!("Starting default scheduler: {default_sched:?}");

        let default_mode = config.default_mode.clone().unwrap_or(SchedMode::Auto);

        let loader_client = LoaderClientProxy::new(&connection).await?;
        loader_client
            .switch_scheduler(default_sched.clone(), default_mode)
            .await?;
    }

    // run worker/receiver loop
    worker_loop(config, rx).await?;

    Ok(())
}

async fn worker_loop(
    config: config::Config,
    mut receiver: UnboundedReceiver<ScxMessage>,
) -> Result<()> {
    // setup channel for scheduler runner
    let (runner_tx, runner_rx) = tokio::sync::mpsc::channel::<RunnerMessage>(1);

    let run_sched_future = tokio::spawn(async move { handle_child_process(runner_rx).await });

    // prepare future for tokio
    tokio::pin!(run_sched_future);

    loop {
        // handle each future here
        let msg = tokio::select! {
            msg = receiver.recv() => {
                match msg {
                    None => return Ok(()),
                    Some(m) => m,
                }
            }
            res = &mut run_sched_future => {
                log::info!("Sched future finished");
                let _ = res?;
                continue;
            }
        };
        log::debug!("Got msg : {msg:?}");

        match msg {
            ScxMessage::Quit => return Ok(()),
            ScxMessage::StopSched => {
                log::info!("Got event to stop scheduler!");

                // send stop message to the runner
                runner_tx.send(RunnerMessage::Stop).await?;
            }
            ScxMessage::StartSched((scx_sched, sched_mode)) => {
                log::info!("Got event to start scheduler!");

                // get scheduler args for the mode
                let args = config::get_scx_flags_for_mode(&config, &scx_sched, sched_mode);

                // send message with scheduler and asociated args to the runner
                runner_tx
                    .send(RunnerMessage::Start((scx_sched, args)))
                    .await?;
            }
            ScxMessage::StartSchedArgs((scx_sched, sched_args)) => {
                log::info!("Got event to start scheduler with args!");

                // send message with scheduler and asociated args to the runner
                runner_tx
                    .send(RunnerMessage::Start((scx_sched, sched_args)))
                    .await?;
            }
            ScxMessage::SwitchSched((scx_sched, sched_mode)) => {
                log::info!("Got event to switch scheduler!");

                // get scheduler args for the mode
                let args = config::get_scx_flags_for_mode(&config, &scx_sched, sched_mode);

                // send message with scheduler and asociated args to the runner
                runner_tx
                    .send(RunnerMessage::Switch((scx_sched, args)))
                    .await?;
            }
            ScxMessage::SwitchSchedArgs((scx_sched, sched_args)) => {
                log::info!("Got event to switch scheduler with args!");

                // send message with scheduler and asociated args to the runner
                runner_tx
                    .send(RunnerMessage::Switch((scx_sched, sched_args)))
                    .await?;
            }
        }
    }
}

async fn handle_child_process(mut rx: tokio::sync::mpsc::Receiver<RunnerMessage>) -> Result<()> {
    let mut task: Option<tokio::task::JoinHandle<Result<Option<ExitStatus>>>> = None;
    let mut cancel_token = Arc::new(tokio_util::sync::CancellationToken::new());

    while let Some(message) = rx.recv().await {
        match message {
            RunnerMessage::Switch((scx_sched, sched_args)) => {
                // stop the sched if its running
                stop_scheduler(&mut task, &mut cancel_token).await;

                // overwise start scheduler
                match start_scheduler(scx_sched, sched_args, cancel_token.clone()).await {
                    Ok(handle) => {
                        task = Some(handle);
                        log::debug!("Scheduler started");
                    }
                    Err(err) => {
                        log::error!("Failed to start scheduler: {err}");
                    }
                }
            }
            RunnerMessage::Start((scx_sched, sched_args)) => {
                // check if sched is running or not
                if task.is_some() {
                    log::error!("Scheduler wasn't finished yet. Stop already running scheduler!");
                    continue;
                }
                // overwise start scheduler
                match start_scheduler(scx_sched, sched_args, cancel_token.clone()).await {
                    Ok(handle) => {
                        task = Some(handle);
                        log::debug!("Scheduler started");
                    }
                    Err(err) => {
                        log::error!("Failed to start scheduler: {err}");
                    }
                }
            }
            RunnerMessage::Stop => {
                stop_scheduler(&mut task, &mut cancel_token).await;
            }
        }
    }

    Ok(())
}

/// Start the scheduler with the given arguments
async fn start_scheduler(
    scx_crate: SupportedSched,
    args: Vec<String>,
    cancel_token: Arc<tokio_util::sync::CancellationToken>,
) -> Result<tokio::task::JoinHandle<Result<Option<ExitStatus>>>> {
    // Ensure the child process exit is handled correctly in the runtime
    let handle = tokio::spawn(async move {
        let mut retries = 0u32;
        let max_retries = 5u32;

        let mut last_status: Option<ExitStatus> = None;

        while retries < max_retries {
            let child = spawn_scheduler(scx_crate.clone(), args.clone()).await;

            let mut failed = false;
            if let Ok(mut child) = child {
                tokio::select! {
                    status = child.wait() => {
                        let status = status.expect("child process encountered an error");
                        last_status = Some(status);
                        if !status.success() {
                            failed = true;
                        }
                        log::debug!("Child process exited with status: {status:?}");
                    }

                    _ = cancel_token.cancelled() => {
                        log::debug!("Received cancellation signal");
                        // Send SIGINT
                        if let Some(child_id) = child.id() {
                            nix::sys::signal::kill(
                                nix::unistd::Pid::from_raw(child_id as i32),
                                nix::sys::signal::SIGINT,
                            ).context("Failed to send termination signal to the child")?;
                        }
                        let status = child.wait().await.expect("child process encountered an error");
                        last_status = Some(status);
                        break;
                    }
                };
            } else {
                log::debug!("Failed to spawn child process");
                failed = true;
            }

            // retrying if failed, otherwise exit
            if !failed {
                break;
            }

            retries += 1;
            log::error!(
                "Failed to start scheduler (attempt {}/{})",
                retries,
                max_retries,
            );
        }

        Ok(last_status)
    });

    Ok(handle)
}

/// Starts the scheduler as a child process and returns child object to manage lifecycle by the
/// caller.
async fn spawn_scheduler(scx_crate: SupportedSched, args: Vec<String>) -> Result<Child> {
    let sched_bin_name: &str = scx_crate.into();
    log::info!("starting {sched_bin_name} command");

    let mut cmd = Command::new(sched_bin_name);
    // set arguments
    cmd.args(args);

    // by default child IO handles are inherited from parent process

    // pipe stdin of child proc to /dev/null
    cmd.stdin(Stdio::null());

    // spawn process
    let child = cmd.spawn().expect("failed to spawn command");

    Ok(child)
}

async fn stop_scheduler(
    task: &mut Option<tokio::task::JoinHandle<Result<Option<ExitStatus>>>>,
    cancel_token: &mut Arc<tokio_util::sync::CancellationToken>,
) {
    if let Some(task) = task.take() {
        log::debug!("Stopping already running scheduler..");
        cancel_token.cancel();
        let status = task.await;
        log::debug!("Scheduler was stopped with status: {:?}", status);
        // Create a new cancellation token
        *cancel_token = Arc::new(tokio_util::sync::CancellationToken::new());
    }
}
