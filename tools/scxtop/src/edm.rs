// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_skel::types::bpf_event;
use crate::Action;
use anyhow::{Error, Result};
use tokio::sync::mpsc::UnboundedSender;

/// Handler of Actions
pub trait ActionHandler {
    fn on_action(&mut self, action: &Action) -> Result<()>;
}

/// Handler of BPF events
pub trait BpfEventHandler {
    fn on_event(&mut self, event: &bpf_event) -> Result<()>;
}

/// EventDispatchManager handles bpf events
pub struct EventDispatchManager {
    action_handlers: Vec<Box<dyn ActionHandler>>,
    /// Callback on action handler errors. If it returns an error then action handler processing
    /// will stop.
    action_error_callback: Option<Box<dyn Fn(Error) -> Result<()>>>,

    bpf_handlers: Vec<Box<dyn BpfEventHandler>>,
    /// Callback on bpf handler errors. If it returns an error then bpf handler processing will
    /// stop.
    bpf_error_callback: Option<Box<dyn Fn(Error) -> Result<()>>>,
}

impl EventDispatchManager {
    /// Returns a new EventDispatchManager
    pub fn new(
        action_error_callback: Option<Box<dyn Fn(Error) -> Result<()>>>,
        bpf_error_callback: Option<Box<dyn Fn(Error) -> Result<()>>>,
    ) -> Self {
        Self {
            action_handlers: vec![],
            action_error_callback,
            bpf_handlers: vec![],
            bpf_error_callback,
        }
    }

    pub fn register_action_handler(&mut self, handler: Box<dyn ActionHandler>) {
        self.action_handlers.push(handler);
    }

    pub fn register_bpf_handler(&mut self, handler: Box<dyn BpfEventHandler>) {
        self.bpf_handlers.push(handler);
    }
}

impl ActionHandler for EventDispatchManager {
    fn on_action(&mut self, action: &Action) -> Result<()> {
        for handler in &mut self.action_handlers {
            let result = handler.on_action(action);
            if let Err(err) = result {
                if let Some(action_error_callback) = &self.action_error_callback {
                    action_error_callback(err)?;
                }
            }
        }
        Ok(())
    }
}

impl BpfEventHandler for EventDispatchManager {
    fn on_event(&mut self, bpf_event: &bpf_event) -> Result<()> {
        for handler in &mut self.bpf_handlers {
            let result = handler.on_event(bpf_event);
            if let Err(err) = result {
                if let Some(bpf_error_callback) = &self.bpf_error_callback {
                    bpf_error_callback(err)?;
                }
            }
        }
        Ok(())
    }
}

/// BpfEventActionPublisher converts BPF events to Actions and publishes them via a Sender for
/// further processing.
pub struct BpfEventActionPublisher {
    tx: UnboundedSender<Action>,
}

impl BpfEventActionPublisher {
    /// Returns a new BpfEventActionPublisher.
    pub fn new(tx: UnboundedSender<Action>) -> Self {
        Self { tx }
    }
}

impl BpfEventHandler for BpfEventActionPublisher {
    fn on_event(&mut self, bpf_event: &bpf_event) -> Result<()> {
        // Convert BPF event to Action, gracefully handling conversion failures
        let action: Action = match bpf_event.try_into() {
            Ok(a) => a,
            Err(_) => {
                // Log and skip malformed events rather than crashing
                log::debug!(
                    "Failed to convert BPF event type {} at ts {}, skipping",
                    bpf_event.r#type,
                    bpf_event.ts
                );
                return Ok(());
            }
        };

        Ok(self.tx.send(action)?)
    }
}
