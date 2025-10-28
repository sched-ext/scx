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

// Default values for resource limits (used when config is 0 or unset)
const DEFAULT_MAX_CONCURRENT_STARTS: usize = 3;
const DEFAULT_RETRY_DELAY_MS: u64 = 500;
use sysinfo::System;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Duration;
use tokio::time::Instant;
use zbus::interface;
use zbus::object_server::SignalEmitter;
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
    /// Restart the currently running scheduler with original configuration
    RestartSched((SupportedSched, Option<Vec<String>>, SchedMode)),
}

#[derive(Debug, PartialEq)]
enum RunnerMessage {
    /// Switch to another scheduler with the given scx arguments
    Switch((SupportedSched, Vec<String>)),
    /// Start the scheduler with the given scx arguments
    Start((SupportedSched, Vec<String>)),
    /// Stop the scheduler, if any
    Stop,
    /// Restart the currently running scheduler with same arguments
    Restart((SupportedSched, Vec<String>)),
}

struct ScxLoader {
    current_scx: Option<SupportedSched>,
    current_mode: SchedMode,
    current_args: Option<Vec<String>>,
    channel: UnboundedSender<ScxMessage>,
    auth: Arc<auth::AuthChecker>,
    audit: Arc<audit::AuditLogger>,
}

/// Holds worker state for resource limits
struct WorkerState {
    active_starts: Arc<tokio::sync::Semaphore>,
    retry_delay_ms: u64,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Option<SubCommand>,

    #[clap(long, short, action)]
    auto: bool,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Generate a configuration file
    InitConfig {
        /// Generate a secure configuration with hardened defaults
        #[clap(long)]
        secure: bool,

        /// Authorization mode: permissive, group, or polkit
        #[clap(long, default_value = "group")]
        auth_mode: String,

        /// Required group for group-based authorization
        #[clap(long, default_value = "wheel")]
        required_group: String,

        /// Output file path (prints to stdout if not specified)
        #[clap(long, short)]
        output: Option<String>,
    },
}

impl ScxLoader {
    async fn check_auth(
        &self,
        method: &str,
        hdr: &zbus::message::Header<'_>,
        signal_ctxt: &SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        // Get caller UID and bus name from D-Bus message header
        let caller_uid = Self::get_caller_uid(hdr, signal_ctxt.connection())
            .await
            .map_err(|e| {
                let msg = format!("Failed to get caller UID: {}", e);
                log::error!("{}", msg);
                zbus::fdo::Error::Failed(msg)
            })?;

        // Get bus name for Polkit
        let bus_name = hdr.sender().map(|s| s.as_str());

        log::debug!("Caller UID: {:?}, Bus name: {:?}", caller_uid, bus_name);

        // Map method name to Polkit action ID
        let action_id = format!(
            "org.scx.Loader.{}",
            method.strip_prefix("org.scx.Loader.").unwrap_or(method)
        );

        let authorized = match self
            .auth
            .check_authorization(
                caller_uid,
                bus_name,
                &action_id,
                Some(signal_ctxt.connection()),
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let msg = format!("Authorization check failed: {}", e);

                // Log audit event
                self.audit.log(audit::AuditEvent::AuthorizationCheck {
                    method: method.to_string(),
                    authorized: false,
                    reason: Some(e.to_string()),
                });

                // Emit D-Bus signal
                let _ =
                    Self::security_violation(signal_ctxt, "authorization_failure", &msg, method)
                        .await;

                return Err(zbus::fdo::Error::Failed(msg));
            }
        };

        if !authorized {
            let msg = "Insufficient permissions to control schedulers".to_string();

            // Log audit event
            self.audit.log(audit::AuditEvent::AuthorizationCheck {
                method: method.to_string(),
                authorized: false,
                reason: Some(msg.clone()),
            });

            // Emit D-Bus signal (best effort, ignore errors)
            let _ =
                Self::security_violation(signal_ctxt, "authorization_denied", &msg, method).await;

            return Err(zbus::fdo::Error::AccessDenied(msg));
        }

        // Log successful authorization
        self.audit.log(audit::AuditEvent::AuthorizationCheck {
            method: method.to_string(),
            authorized: true,
            reason: None,
        });

        Ok(())
    }

    /// Get the UID of the D-Bus caller from message header
    async fn get_caller_uid(
        hdr: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
    ) -> zbus::Result<Option<u32>> {
        // Get the sender from the message header
        let sender = match hdr.sender() {
            Some(name) => name,
            None => return Ok(None),
        };

        // Query D-Bus daemon for the sender's UID
        let dbus_proxy = zbus::fdo::DBusProxy::new(connection).await?;
        // Convert UniqueName to BusName
        let bus_name = zbus::names::BusName::from(sender.clone());
        let uid = dbus_proxy.get_connection_unix_user(bus_name).await?;

        Ok(Some(uid))
    }
}

#[interface(name = "org.scx.Loader")]
impl ScxLoader {
    /// Signal emitted when a security violation occurs
    #[zbus(signal)]
    async fn security_violation(
        ctxt: &SignalEmitter<'_>,
        violation_type: &str,
        message: &str,
        details: &str,
    ) -> zbus::Result<()>;

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

    /// Get arguments used for currently running scheduler
    #[zbus(property)]
    async fn current_scheduler_args(&self) -> Vec<String> {
        self.current_args.clone().unwrap_or_default()
    }

    /// Get list of supported schedulers
    #[zbus(property)]
    async fn supported_schedulers(&self) -> Vec<&str> {
        vec![
            "scx_bpfland",
            "scx_cosmos",
            "scx_flash",
            "scx_lavd",
            "scx_p2dq",
            "scx_tickless",
            "scx_rustland",
            "scx_rusty",
        ]
    }
    async fn start_scheduler(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        scx_name: SupportedSched,
        sched_mode: SchedMode,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("start_scheduler", &hdr, &ctxt).await?;

        log::info!("starting {scx_name:?} with mode {sched_mode:?}..");

        let _ = self.channel.send(ScxMessage::StartSched((
            scx_name.clone(),
            sched_mode.clone(),
        )));

        // Log audit event
        self.audit.log(audit::AuditEvent::SchedulerStarted {
            scheduler: scx_name.clone(),
            args: vec![], // Mode-based start doesn't expose args
            success: true,
        });

        self.current_scx = Some(scx_name);
        self.current_mode = sched_mode;
        self.current_args = None;

        Ok(())
    }

    async fn start_scheduler_with_args(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        scx_name: SupportedSched,
        scx_args: Vec<String>,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("start_scheduler_with_args", &hdr, &ctxt)
            .await?;

        log::info!("starting {scx_name:?} with args {scx_args:?}..");

        let _ = self.channel.send(ScxMessage::StartSchedArgs((
            scx_name.clone(),
            scx_args.clone(),
        )));

        // Log audit event
        self.audit.log(audit::AuditEvent::SchedulerStarted {
            scheduler: scx_name.clone(),
            args: scx_args.clone(),
            success: true,
        });

        self.current_scx = Some(scx_name);
        // reset mode to auto
        self.current_mode = SchedMode::Auto;
        self.current_args = Some(scx_args);

        Ok(())
    }

    async fn switch_scheduler(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        scx_name: SupportedSched,
        sched_mode: SchedMode,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("switch_scheduler", &hdr, &ctxt).await?;

        log::info!("switching {scx_name:?} with mode {sched_mode:?}..");

        let _ = self.channel.send(ScxMessage::SwitchSched((
            scx_name.clone(),
            sched_mode.clone(),
        )));

        // Log audit event
        self.audit.log(audit::AuditEvent::SchedulerSwitched {
            from: self.current_scx.clone(),
            to: scx_name.clone(),
            args: vec![], // Mode-based switch doesn't expose args
            success: true,
        });

        self.current_scx = Some(scx_name);
        self.current_mode = sched_mode;
        self.current_args = None;

        Ok(())
    }

    async fn switch_scheduler_with_args(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        scx_name: SupportedSched,
        scx_args: Vec<String>,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("switch_scheduler_with_args", &hdr, &ctxt)
            .await?;

        log::info!("switching {scx_name:?} with args {scx_args:?}..");

        let _ = self.channel.send(ScxMessage::SwitchSchedArgs((
            scx_name.clone(),
            scx_args.clone(),
        )));

        // Log audit event
        self.audit.log(audit::AuditEvent::SchedulerSwitched {
            from: self.current_scx.clone(),
            to: scx_name.clone(),
            args: scx_args.clone(),
            success: true,
        });

        self.current_scx = Some(scx_name);
        // reset mode to auto
        self.current_mode = SchedMode::Auto;
        self.current_args = Some(scx_args);

        Ok(())
    }

    async fn stop_scheduler(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("stop_scheduler", &hdr, &ctxt).await?;

        if let Some(current_scx) = &self.current_scx {
            let scx_name: &str = current_scx.clone().into();

            log::info!("stopping {scx_name:?}..");
            let _ = self.channel.send(ScxMessage::StopSched);

            // Log audit event
            self.audit.log(audit::AuditEvent::SchedulerStopped {
                scheduler: current_scx.clone(),
            });

            self.current_scx = None;
            self.current_args = None;
        }

        Ok(())
    }

    async fn restart_scheduler(
        &mut self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.check_auth("restart_scheduler", &hdr, &ctxt).await?;

        if let Some(current_scx) = &self.current_scx {
            let scx_name: &str = current_scx.clone().into();

            log::info!("restarting {scx_name:?}..");
            let _ = self.channel.send(ScxMessage::RestartSched((
                current_scx.clone(),
                self.current_args.clone(),
                self.current_mode.clone(),
            )));

            // Log audit event
            self.audit.log(audit::AuditEvent::SchedulerRestarted {
                scheduler: current_scx.clone(),
                args: self.current_args.clone().unwrap_or_default(),
                success: true,
            });

            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(
                "No scheduler is currently running to restart".to_string(),
            ))
        }
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

    // Handle init-config subcommand
    if let Some(SubCommand::InitConfig {
        secure,
        auth_mode,
        required_group,
        output,
    }) = args.command
    {
        return generate_config(secure, &auth_mode, &required_group, output.as_deref());
    }

    // initialize the config
    let config = config::init_config().context("Failed to initialize config")?;

    // If --auto is passed, start scx_loader as a standard background process
    // that swaps schedulers out automatically
    // based on CPU utilization without registering a dbus interface.
    if args.auto {
        if !config.security.allow_auto_mode {
            log::error!("Auto-mode is disabled in configuration");
            std::process::exit(1);
        }

        log::warn!("╔═══════════════════════════════════════════════════════════════╗");
        log::warn!("║ WARNING: Starting in AUTO mode                                ║");
        log::warn!("║ Scheduler will launch automatically on high CPU usage         ║");
        log::warn!("║ This bypasses D-Bus authorization checks                      ║");
        log::warn!("║ Consider using D-Bus interface for better security            ║");
        log::warn!("╚═══════════════════════════════════════════════════════════════╝");

        log::info!("Starting scx_loader monitor as standard process without dbus interface");
        monitor_cpu_util().await?;
        return Ok(());
    }

    log::info!("Starting as dbus interface");

    // Create auth checker
    let auth = Arc::new(auth::AuthChecker::new(Arc::new(config.security.clone())));

    // Create audit logger (enabled by default)
    let audit = Arc::new(audit::AuditLogger::new(true));

    // Print security warnings
    auth.print_security_warnings();

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
                current_args: None,
                channel: channel.clone(),
                auth: auth.clone(),
                audit: audit.clone(),
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
    // Create argument validator
    let validator = Arc::new(validator::ArgumentValidator::new(config.security.clone()));

    // Use defaults if config values are 0 (unset)
    let max_concurrent_starts = if config.security.max_concurrent_starts == 0 {
        DEFAULT_MAX_CONCURRENT_STARTS
    } else {
        config.security.max_concurrent_starts
    };

    let retry_delay_ms = if config.security.retry_delay_ms == 0 {
        DEFAULT_RETRY_DELAY_MS
    } else {
        config.security.retry_delay_ms
    };

    // Log resource limit configuration
    log::info!(
        "Resource limits: max_concurrent_starts={}{}, retry_delay_ms={}{}",
        max_concurrent_starts,
        if config.security.max_concurrent_starts == 0 {
            " (default)"
        } else {
            ""
        },
        retry_delay_ms,
        if config.security.retry_delay_ms == 0 {
            " (default)"
        } else {
            ""
        }
    );

    // Create semaphore to limit concurrent starts (from config)
    let state = Arc::new(WorkerState {
        active_starts: Arc::new(tokio::sync::Semaphore::new(max_concurrent_starts)),
        retry_delay_ms,
    });

    // setup channel for scheduler runner
    let (runner_tx, runner_rx) = tokio::sync::mpsc::channel::<RunnerMessage>(1);

    let validator_clone = validator.clone();
    let state_clone = state.clone();
    let run_sched_future =
        tokio::spawn(
            async move { handle_child_process(runner_rx, validator_clone, state_clone).await },
        );

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
            ScxMessage::RestartSched((scx_sched, current_args, current_mode)) => {
                log::info!("Got event to restart scheduler!");

                // Determine the arguments to use for restart
                let args = if let Some(args) = current_args {
                    // Use custom arguments if they were set
                    args
                } else {
                    // Use mode-based arguments
                    config::get_scx_flags_for_mode(&config, &scx_sched, current_mode)
                };

                // send restart message to the runner
                runner_tx
                    .send(RunnerMessage::Restart((scx_sched, args)))
                    .await?;
            }
        }
    }
}

async fn handle_child_process(
    mut rx: tokio::sync::mpsc::Receiver<RunnerMessage>,
    validator: Arc<validator::ArgumentValidator>,
    state: Arc<WorkerState>,
) -> Result<()> {
    let mut task: Option<tokio::task::JoinHandle<Result<Option<ExitStatus>>>> = None;
    let mut cancel_token = Arc::new(tokio_util::sync::CancellationToken::new());

    while let Some(message) = rx.recv().await {
        match message {
            RunnerMessage::Switch((scx_sched, sched_args)) => {
                // stop the sched if its running
                stop_scheduler(&mut task, &mut cancel_token).await;

                // overwise start scheduler
                match start_scheduler(
                    scx_sched,
                    sched_args,
                    cancel_token.clone(),
                    validator.clone(),
                    state.clone(),
                )
                .await
                {
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
                match start_scheduler(
                    scx_sched,
                    sched_args,
                    cancel_token.clone(),
                    validator.clone(),
                    state.clone(),
                )
                .await
                {
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
            RunnerMessage::Restart((scx_sched, sched_args)) => {
                log::info!("Got event to restart scheduler!");

                // stop the sched if its running
                stop_scheduler(&mut task, &mut cancel_token).await;

                // restart scheduler with the same configuration
                match start_scheduler(
                    scx_sched,
                    sched_args,
                    cancel_token.clone(),
                    validator.clone(),
                    state.clone(),
                )
                .await
                {
                    Ok(handle) => {
                        task = Some(handle);
                        log::debug!("Scheduler restarted");
                    }
                    Err(err) => {
                        log::error!("Failed to restart scheduler: {err}");
                    }
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
    cancel_token: Arc<tokio_util::sync::CancellationToken>,
    validator: Arc<validator::ArgumentValidator>,
    state: Arc<WorkerState>,
) -> Result<tokio::task::JoinHandle<Result<Option<ExitStatus>>>> {
    // Validate arguments before spawning
    validator
        .validate_args(&scx_crate, &args)
        .context("Argument validation failed")?;

    // Acquire semaphore permit to limit concurrent starts
    let _permit = state
        .active_starts
        .acquire()
        .await
        .context("Failed to acquire semaphore permit")?;

    log::debug!(
        "Acquired semaphore permit for scheduler start (available: {})",
        state.active_starts.available_permits()
    );

    // Ensure the child process exit is handled correctly in the runtime
    let retry_delay_ms = state.retry_delay_ms;
    let handle = tokio::spawn(async move {
        let mut retries = 0u32;
        let max_retries = 5u32;

        let mut last_status: Option<ExitStatus> = None;

        while retries < max_retries {
            // Add delay between retries (except for first attempt)
            if retries > 0 {
                log::info!(
                    "Waiting {}ms before retry attempt {}/{}",
                    retry_delay_ms,
                    retries + 1,
                    max_retries
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(retry_delay_ms)).await;
            }

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

/// Generate a configuration file based on the provided options
fn generate_config(
    secure: bool,
    auth_mode_str: &str,
    required_group: &str,
    output: Option<&str>,
) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    // Parse authorization mode
    let auth_mode = match auth_mode_str {
        "permissive" => config::AuthorizationMode::Permissive,
        "group" => config::AuthorizationMode::Group,
        "polkit" => config::AuthorizationMode::Polkit,
        _ => anyhow::bail!(
            "Invalid authorization mode: {}. Must be 'permissive', 'group', or 'polkit'",
            auth_mode_str
        ),
    };

    // Create security config based on secure flag
    let security = if secure {
        config::SecurityConfig {
            authorization_mode: auth_mode.clone(),
            required_group: Some(required_group.to_string()),
            validate_arguments: true,
            strict_allowlist: false, // Optional, users can enable in config
            max_arguments: 128,
            max_argument_length: 4096,
            allow_auto_mode: false,   // Disabled in secure mode
            max_concurrent_starts: 0, // 0 = use default
            retry_delay_ms: 0,        // 0 = use default
        }
    } else {
        config::SecurityConfig {
            authorization_mode: auth_mode.clone(),
            required_group: Some(required_group.to_string()),
            validate_arguments: true,
            strict_allowlist: false,
            max_arguments: 128,
            max_argument_length: 4096,
            allow_auto_mode: true,
            max_concurrent_starts: 0, // 0 = use default
            retry_delay_ms: 0,        // 0 = use default
        }
    };

    // Create the full config with default schedulers and the security config
    let mut config = config::get_default_config();
    config.security = security;

    // Serialize to TOML
    let toml_string =
        toml::to_string_pretty(&config).context("Failed to serialize configuration to TOML")?;

    // Add helpful comments at the top
    let header = format!(
        "# scx_loader configuration file\n\
        # Generated with scx_loader init-config{}\n\
        #\n\
        # This file configures the scx_loader D-Bus service for managing\n\
        # sched_ext schedulers. Place this file at /etc/scx_loader.toml\n\
        #\n\
        # Security Configuration:\n\
        #   authorization_mode = \"{}\"\n\
        {}\
        #   validate_arguments = {}\n\
        #   allow_auto_mode = {}\n\
        #\n",
        if secure { " --secure" } else { "" },
        auth_mode_str,
        if auth_mode == config::AuthorizationMode::Group {
            format!("#   required_group = \"{}\"\n", required_group)
        } else {
            String::new()
        },
        config.security.validate_arguments,
        config.security.allow_auto_mode,
    );

    let full_output = format!("{}\n{}", header, toml_string);

    // Output to file or stdout
    if let Some(output_path) = output {
        let mut file = File::create(output_path)
            .context(format!("Failed to create output file: {}", output_path))?;
        file.write_all(full_output.as_bytes())
            .context("Failed to write configuration to file")?;

        println!("✓ Configuration written to: {}", output_path);
        println!("\nNext steps:");
        println!("  1. Review the configuration: cat {}", output_path);
        println!(
            "  2. Copy to system location: sudo cp {} /etc/scx_loader.toml",
            output_path
        );
        println!("  3. Restart scx_loader: sudo systemctl restart scx_loader");

        if secure {
            println!("\n⚠ Secure mode enabled:");
            println!("  - Auto-mode is DISABLED");
            println!("  - Authorization required: {} members", required_group);
            println!("  - Argument validation ENABLED");
        }
    } else {
        println!("{}", full_output);
    }

    Ok(())
}
