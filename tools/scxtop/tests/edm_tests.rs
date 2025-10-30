// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Error, Result};
use scxtop::bpf_skel::types::bpf_event;
use scxtop::edm::{ActionHandler, BpfEventActionPublisher, BpfEventHandler, EventDispatchManager};
use scxtop::Action;
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
            self.events_received.push(*event);
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
    // EDM should start with empty handler lists
    // (We can't directly test the private fields, but construction should succeed)
    drop(edm); // Ensure it was created successfully
}

#[test]
fn test_register_action_handler() {
    let mut edm = EventDispatchManager::new(None, None);
    let handler = Box::new(MockActionHandler {
        actions_received: Vec::new(),
        should_fail: false,
    });

    edm.register_action_handler(handler);
    // Handler registration should succeed without panic
}

#[test]
fn test_register_bpf_handler() {
    let mut edm = EventDispatchManager::new(None, None);
    let handler = Box::new(MockBpfEventHandler {
        events_received: Vec::new(),
        should_fail: false,
    });

    edm.register_bpf_handler(handler);
    // Handler registration should succeed without panic
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
}

#[test]
fn test_edm_on_action_with_error() {
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
}

#[test]
fn test_bpf_event_action_publisher_handles_conversion_error() {
    // Create a channel for testing
    let (tx, mut rx) = mpsc::unbounded_channel();

    // Create the publisher
    let mut publisher = BpfEventActionPublisher::new(tx);

    // Create a malformed BPF event with an invalid type that won't convert
    let mut event = create_mock_bpf_event();
    event.r#type = i32::MAX; // Invalid event type that won't convert to Action

    // Process the event - should not panic, should gracefully skip
    let result = publisher.on_event(&event);

    // Verify the result is Ok (not an error, just skipped)
    assert!(result.is_ok());

    // Verify that no action was sent (since conversion failed)
    assert!(rx.try_recv().is_err());
}
