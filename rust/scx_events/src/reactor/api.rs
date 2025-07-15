use ::alloc::sync::Arc;
use ::core::sync::atomic::AtomicU32;
use ::std::thread::Thread;

use crate::{
    data::EventReactorData,
    reactor::{phase::ReactorPhase, state::ReactorState},
};

/// The parent-thread interface for [`EventReactor`].
///
/// This structure is the external half of [`ReactorState`].
///
/// The parent-thread retains [`ReactorApi`] while [`ReactorState`] is moved
/// into the run-loop thread.
///
/// [`EventReactor`]: crate::EventReactor
pub struct ReactorApi {
    /// Shared access to the current reactor step.
    pub step: ReactorPhase,
    /// The wake futex for the reactor.
    wake: Arc<AtomicU32>,
}
impl ReactorApi {
    /// Creates a new [`ReactorApi`] and [`ReactorState`] pair.
    pub fn create(parent: Thread, data: EventReactorData) -> (Self, ReactorState) {
        let api = Self::new();
        let ctx = {
            let step = api.step.clone();
            let wake = Arc::clone(&api.wake);
            ReactorState::new(step, wake, parent, data)
        };
        (api, ctx)
    }

    /// Creates a new [`ReactorApi`].
    fn new() -> Self {
        let step = ReactorPhase::new();
        let wake = Arc::<AtomicU32>::default();
        Self { step, wake }
    }
}
