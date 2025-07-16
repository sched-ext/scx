#![allow(unused, reason = "tmp")]

use ::alloc::sync::Arc;
use ::core::{mem::MaybeUninit, sync::atomic::AtomicU32};
use ::linux_raw_sys::io_uring::io_uring_buf;
use ::neli::socket::NlSocket;
use ::std::thread::Thread;

use crate::{
    data::EventReactorData,
    reactor::{buffer::BufferRing, phase::ReactorPhase},
};

/// The run-loop-thread interface for [`EventReactor`].
///
/// This structure is the internal half of [`ReactorState`].
///
/// The parent-thread retains [`ReactorApi`] while [`ReactorState`] is moved
/// into the run-loop thread.
///
/// [`EventReactor`]: crate::EventReactor
/// [`ReactorApi`]: crate::reactor::api::ReactorApi
pub struct ReactorState {
    /// The signifier for whether the run-loop should stop on next iteration.
    pub stop: bool,
    /// The current step of the reactor.
    pub step: ReactorPhase,
    /// The wake futex for the reactor.
    pub wake: Arc<AtomicU32>,
    /// The data collected by the reactor.
    pub data: EventReactorData,
    /// The parent-thread that spawned the run-loop thread.
    pub parent: Thread,
}

impl ReactorState {
    /// Create a new [`ReactorState`].
    pub const fn new(step: ReactorPhase, wake: Arc<AtomicU32>, parent: Thread, data: EventReactorData) -> Self {
        let stop = false;
        Self {
            stop,
            step,
            wake,
            data,
            parent,
        }
    }
}
