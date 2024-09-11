// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Vladislav Nepogodin <vnepogodin@cachyos.org>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod logger;

use std::process::Stdio;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use zbus::interface;
use zbus::Connection;
use zvariant::Type;
use zvariant::Value;

#[derive(Debug, Clone, PartialEq)]
enum SupportedSched {
    Bpfland,
    Rusty,
    Lavd,
}

#[derive(Debug, PartialEq)]
enum ScxMessage {
    Quit,
    StopSched,
    StartSched((SupportedSched, SchedMode)),
    StartSchedArgs((SupportedSched, Vec<String>)),
}

#[derive(Debug, PartialEq)]
enum RunnerMessage {
    Start((SupportedSched, Vec<String>)),
    Stop,
}

#[derive(Debug, Clone, Deserialize, Serialize, Type, Value, PartialEq)]
enum SchedMode {
    /// Default values for the scheduler
    Auto = 0,
    /// Applies flags for better gaming experience
    Gaming = 1,
    /// Applies flags for lower power usage
    PowerSave = 2,
    /// Starts scheduler in low latency mode
    LowLatency = 3,
}

struct ScxLoader {
    current_scx: Option<SupportedSched>,
    current_mode: SchedMode,
    channel: UnboundedSender<ScxMessage>,
}

#[interface(name = "org.scx.Loader")]
impl ScxLoader {
    /// Get currently running scheduler, in case non is running return "unknown"
    #[zbus(property)]
    async fn current_scheduler(&self) -> String {
        if let Some(current_scx) = &self.current_scx {
            let current_scx = get_name_from_scx(&current_scx).into();
            log::info!("called {current_scx:?}");
            return current_scx;
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
        vec!["scx_bpfland", "scx_rusty", "scx_lavd"]
    }

    async fn start_scheduler(
        &mut self,
        scx_name: &str,
        sched_mode: SchedMode, /*, scx_flags: Vec<String>*/
    ) -> zbus::fdo::Result<()> {
        let scx_name = get_scx_from_str(scx_name)?;

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
        scx_name: &str,
        scx_args: Vec<String>,
    ) -> zbus::fdo::Result<()> {
        let scx_name = get_scx_from_str(scx_name)?;

        log::info!("starting {scx_name:?} with args {scx_args:?}..");

        let _ = self
            .channel
            .send(ScxMessage::StartSchedArgs((scx_name.clone(), scx_args)));
        self.current_scx = Some(scx_name);
        // reset mode to auto
        self.current_mode = SchedMode::Auto;

        Ok(())
    }

    async fn stop_scheduler(&mut self) -> zbus::fdo::Result<()> {
        if let Some(current_scx) = &self.current_scx {
            let scx_name = get_name_from_scx(&current_scx);

            log::info!("stopping {scx_name:?}..");
            let _ = self.channel.send(ScxMessage::StopSched);
            self.current_scx = None;
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialize the logger
    logger::init_logger().expect("Failed to initialize logger");

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

    // run worker/receiver loop
    worker_loop(rx).await?;

    Ok(())
}

async fn worker_loop(mut receiver: UnboundedReceiver<ScxMessage>) -> Result<()> {
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
                let args: Vec<_> = get_scx_flags_for_mode(&scx_sched, sched_mode)
                    .into_iter()
                    .map(String::from)
                    .collect();

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
        }
    }
}

async fn handle_child_process(mut rx: tokio::sync::mpsc::Receiver<RunnerMessage>) -> Result<()> {
    let child_id = Arc::new(AtomicU32::new(0));

    while let Some(message) = rx.recv().await {
        match message {
            RunnerMessage::Start((scx_sched, sched_args)) => {
                // check if sched is running or not
                if child_id.load(Ordering::Relaxed) != 0 {
                    log::error!("Scheduler wasn't finished yet. Stop already running scheduler!");
                    continue;
                }
                // overwise start scheduler
                if let Err(sched_err) =
                    start_scheduler(scx_sched, sched_args, child_id.clone()).await
                {
                    log::error!("Scheduler exited with err: {sched_err}");
                } else {
                    log::debug!("Scheduler exited");
                }
            }
            RunnerMessage::Stop => {
                // if child_proc is 0, then we assume the child process is terminated
                let child_proc = child_id.load(Ordering::Relaxed);
                if child_proc > 0 {
                    // send SIGINT signal to child
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child_proc as i32),
                        nix::sys::signal::SIGINT,
                    )
                    .context("Failed to send termination signal to the child")?;
                }
            }
        }
    }

    Ok(())
}

/// Start the scheduler with the given arguments
async fn start_scheduler(
    scx_crate: SupportedSched,
    args: Vec<String>,
    child_id: Arc<AtomicU32>,
) -> Result<()> {
    let sched_bin_name = get_name_from_scx(&scx_crate);
    log::info!("starting {sched_bin_name} command");

    let mut cmd = Command::new(sched_bin_name);
    // set arguments
    cmd.args(args);

    // by default child IO handles are inherited from parent process

    // pipe stdin of child proc to /dev/null
    cmd.stdin(Stdio::null());

    // spawn process
    let mut child = cmd.spawn().expect("failed to spawn command");

    // NOTE: unsafe because the child might not exist, when we will try to stop it
    // set child id
    child_id.store(
        child
            .id()
            .ok_or(anyhow::anyhow!("Failed to get child id"))?,
        Ordering::Relaxed,
    );

    // Ensure the child process is exit is handled correctly in the runtime
    tokio::spawn(async move {
        let status = child
            .wait()
            .await
            .expect("child process encountered an error");

        log::debug!("Child process exited with status: {status:?}");
        child_id.store(0, Ordering::Relaxed);
    });

    Ok(())
}

/// Get the scx trait from the given scx name or return error if the given scx name is not supported
fn get_scx_from_str(scx_name: &str) -> zbus::fdo::Result<SupportedSched> {
    match scx_name {
        "scx_bpfland" => Ok(SupportedSched::Bpfland),
        "scx_rusty" => Ok(SupportedSched::Rusty),
        "scx_lavd" => Ok(SupportedSched::Lavd),
        _ => Err(zbus::fdo::Error::Failed(format!(
            "{scx_name} is not supported"
        ))),
    }
}

/// Get the scx name from the given scx trait
fn get_name_from_scx(supported_sched: &SupportedSched) -> &'static str {
    match supported_sched {
        SupportedSched::Bpfland => "scx_bpfland",
        SupportedSched::Rusty => "scx_rusty",
        SupportedSched::Lavd => "scx_lavd",
    }
}

/// Get the scx flags for the given sched mode
fn get_scx_flags_for_mode(scx_sched: &SupportedSched, sched_mode: SchedMode) -> Vec<&str> {
    match scx_sched {
        SupportedSched::Bpfland => match sched_mode {
            SchedMode::Gaming => vec!["-c", "0", "-k", "-m", "performance"],
            SchedMode::LowLatency => vec!["--lowlatency"],
            SchedMode::PowerSave => vec!["-m", "powersave"],
            SchedMode::Auto => vec![],
        },
        SupportedSched::Lavd => match sched_mode {
            SchedMode::Gaming | SchedMode::LowLatency => vec!["--performance"],
            SchedMode::PowerSave => vec!["--powersave"],
            // NOTE: potentially adding --auto in future
            SchedMode::Auto => vec![],
        },
        // scx_rusty doesn't support any of these modes
        SupportedSched::Rusty => match sched_mode {
            _ => vec![],
        },
    }
}
