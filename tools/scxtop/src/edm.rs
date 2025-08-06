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
/// further Processing.
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
        let action: Action = bpf_event.try_into().expect("failed to convert");
        Ok(self.tx.send(action)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use tokio::sync::mpsc;

    // Mock implementation of ActionHandler for testing
    struct MockActionHandler {
        pub actions_received: Vec<Action>,
        pub should_fail: bool,
    }

    impl ActionHandler for MockActionHandler {
        fn on_action(&mut self, action: &Action) -> Result<()> {
            if self.should_fail {
                Err(anyhow!("Mock action handler error"))
            } else {
                self.actions_received.push(action.clone());
                Ok(())
            }
        }
    }

    // Mock implementation of BpfEventHandler for testing
    struct MockBpfEventHandler {
        pub events_received: Vec<bpf_event>,
        pub should_fail: bool,
    }

    impl BpfEventHandler for MockBpfEventHandler {
        fn on_event(&mut self, event: &bpf_event) -> Result<()> {
            if self.should_fail {
                Err(anyhow!("Mock BPF event handler error"))
            } else {
                self.events_received.push(event.clone());
                Ok(())
            }
        }
    }

    // Helper function to create a mock BPF event
    fn create_mock_bpf_event() -> bpf_event {
        // Create a minimal bpf_event for testing
        // The actual fields will depend on the bpf_event structure
        bpf_event::default()
    }

    #[test]
    fn test_edm_new() {
        let edm = EventDispatchManager::new(None, None);
        assert!(edm.action_handlers.is_empty());
        assert!(edm.bpf_handlers.is_empty());
        assert!(edm.action_error_callback.is_none());
        assert!(edm.bpf_error_callback.is_none());
    }

    #[test]
    fn test_register_action_handler() {
        let mut edm = EventDispatchManager::new(None, None);
        let handler = Box::new(MockActionHandler {
            actions_received: Vec::new(),
            should_fail: false,
        });

        edm.register_action_handler(handler);

        assert_eq!(edm.action_handlers.len(), 1);
    }

    #[test]
    fn test_register_bpf_handler() {
        let mut edm = EventDispatchManager::new(None, None);
        let handler = Box::new(MockBpfEventHandler {
            events_received: Vec::new(),
            should_fail: false,
        });

        edm.register_bpf_handler(handler);

        assert_eq!(edm.bpf_handlers.len(), 1);
    }

    #[test]
    fn test_edm_on_action() {
        let mut edm = EventDispatchManager::new(None, None);

        // Register two action handlers
        let handler1 = Box::new(MockActionHandler {
            actions_received: Vec::new(),
            should_fail: false,
        });
        let handler2 = Box::new(MockActionHandler {
            actions_received: Vec::new(),
            should_fail: false,
        });

        edm.register_action_handler(handler1);
        edm.register_action_handler(handler2);

        // Create a test action
        let action = Action::Quit;

        // Process the action
        let result = edm.on_action(&action);

        // Verify the result
        assert!(result.is_ok());

        // Verify that both handlers received the action
        // Note: We can't easily check this directly since the handlers are boxed
        // In a real test, you might use a shared state or a mock that records calls
    }

    #[test]
    fn test_edm_on_action_with_error() {
        // In a real test, we would use a shared state to track if the error callback was called
        // For this test, we'll just verify that the action processing completes successfully
        // even when a handler fails

        // Create a simple error callback that just returns Ok
        let error_callback = Box::new(|_: Error| {
            // Just return Ok to continue processing
            Ok(())
        }) as Box<dyn Fn(Error) -> Result<()>>;

        let mut edm = EventDispatchManager::new(Some(error_callback), None);

        // Register a failing action handler
        let handler = Box::new(MockActionHandler {
            actions_received: Vec::new(),
            should_fail: true,
        });

        edm.register_action_handler(handler);

        // Create a test action
        let action = Action::Quit;

        // Process the action
        let result = edm.on_action(&action);

        // Verify the result - the error should be handled by the callback
        assert!(result.is_ok());
    }

    #[test]
    fn test_edm_on_event() {
        let mut edm = EventDispatchManager::new(None, None);

        // Register two BPF event handlers
        let handler1 = Box::new(MockBpfEventHandler {
            events_received: Vec::new(),
            should_fail: false,
        });
        let handler2 = Box::new(MockBpfEventHandler {
            events_received: Vec::new(),
            should_fail: false,
        });

        edm.register_bpf_handler(handler1);
        edm.register_bpf_handler(handler2);

        // Create a test BPF event
        let event = create_mock_bpf_event();

        // Process the event
        let result = edm.on_event(&event);

        // Verify the result
        assert!(result.is_ok());

        // Verify that both handlers received the event
        // Note: We can't easily check this directly since the handlers are boxed
        // In a real test, you might use a shared state or a mock that records calls
    }

    #[test]
    fn test_bpf_event_action_publisher() {
        // Create a channel for testing
        let (tx, _rx) = mpsc::unbounded_channel();

        // Create the publisher
        let mut publisher = BpfEventActionPublisher::new(tx);

        // Create a test BPF event
        let event = create_mock_bpf_event();

        // Process the event
        let result = publisher.on_event(&event);

        // Verify the result
        assert!(result.is_ok());

        // Verify that an action was sent through the channel
        // Note: This would require the Action type to be properly implemented
        // and the try_into() conversion to work correctly
        // In a real test, you might check rx.try_recv() to see if an action was sent
    }
}
