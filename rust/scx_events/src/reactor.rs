/// Definitions related to the [`EventReactor`] API.
pub(in crate::reactor) mod api;
/// Definitions related to the [`EventReactor`] buffer rings.
pub(in crate::reactor) mod buffer;
/// Definitions related to the [`EventReactor`] phases.
pub(in crate::reactor) mod phase;
/// Definitions related to the [`EventReactor`] state.
pub(in crate::reactor) mod state;
/// Definitions related to the [`EventReactor`] data store.
pub(in crate::reactor) mod store;
/// Definitions related to the [`EventReactor`] tasks.
pub(in crate::reactor) mod task;
/// Definitions related to the [`EventReactor`] run-loop thread.
pub(in crate::reactor) mod thread;

use ::alloc::sync::Arc;
use ::anyhow::bail;
use ::core::{
    any::Any,
    sync::atomic::{AtomicBool, Ordering},
};
use ::std::thread::JoinHandle;

use crate::{
    arena::ArenaBump,
    data::EventReactorData,
    reactor::{
        api::ReactorApi,
        phase::{ReactorPhase, ReactorPhaseKind},
        thread::EventReactorThread,
    },
};

/// An error type for the [`EventReactor`] thread handle.
pub enum EventReactorHandleError {
    /// An error from a panic in the [`EventReactor`] thread.
    Panic(Box<dyn Any + Send + 'static>),
    /// An error from the [`EventReactor`].
    Error(anyhow::Error),
}

/// An io_uring-based event reactor.
pub struct EventReactor {
    /// The API structure for interacting with the [`EventReactor`].
    api: ReactorApi,
    /// The thread handle for the [`EventReactor`] run-loop.
    handle: Option<JoinHandle<crate::Result<()>>>,
}

impl Drop for EventReactor {
    fn drop(&mut self) {
        #[allow(clippy::unwrap_used, reason = "should panic")]
        self.shutdown().unwrap();
    }
}

impl EventReactor {
    /// Create a new [`EventReactor`].
    ///
    /// # Errors
    ///
    /// * Creating the local `ArenaBump` may error.
    /// * Creating the `EventReactorThread` may error.
    /// * Any panic from `EventReactorThread::new` will surface an error.
    pub fn new(scx_shutdown: Arc<AtomicBool>, data: EventReactorData) -> crate::Result<Self> {
        let parent = ::std::thread::current();
        let (api, state) = ReactorApi::create(parent.clone(), data);

        // Spawn and run the EventReactor in a thread and store its handle.
        let handle = Some(::std::thread::spawn({
            move || -> crate::Result<()> {
                // Catch any panics from the event loop.
                ::std::panic::catch_unwind(|| {
                    let arena = ArenaBump::try_new().map_err(crate::Error::msg)?;
                    let reactor = EventReactorThread::new(&arena, state)?;
                    reactor.run()
                })
                // Repackage error info from caught panics.
                .map_err(EventReactorHandleError::Panic)
                // Repackage EventReactor errors.
                .and_then(|res| res.map_err(EventReactorHandleError::Error))
                // Trigger shutdown and unpark parent on panic or error.
                .map_err(|err| {
                    scx_shutdown.store(true, Ordering::Release);
                    parent.unpark();
                    match err {
                        EventReactorHandleError::Panic(panic) => ::std::panic::resume_unwind(panic),
                        EventReactorHandleError::Error(error) => error,
                    }
                })
                // Display error info for Reactor errors immediately.
                .inspect_err(|err| {
                    ::log::error!("reactor[error]: {err}");
                })
            }
        }));

        // Park the current thread and wait for one of the following:
        //   1. EventReactor finishes startup and unparks us when ready.
        //   2. A panic occurs during EventReactor initialization.
        ::std::thread::park();

        // Once unparked, check whether the EventReactor is still in `Starting`
        // step. If so, that means initialization failed, so throw an error.
        if let ReactorPhaseKind::Starting = api.step.load(Ordering::Acquire) {
            if let Some(handle) = handle {
                // TODO: collapse once Rust version bumps.
                if handle.is_finished() {
                    match handle.join() {
                        Ok(res) => {
                            res?;
                        },
                        Err(panic) => {
                            ::std::panic::resume_unwind(panic);
                        },
                    }
                }
            }
            bail!("reactor[ctrl]: failed to create loop");
        }

        Ok(Self { api, handle })
    }

    /// Shutdown the [`EventReactor`] and join the run-loop thread.
    ///
    /// # Errors
    ///
    /// * The syscall to wake the `EventReactorThread` futex may error.
    /// * Any panic from `EventReactorThread::run` will surface an error.
    pub fn shutdown(&mut self) -> crate::Result<()> {
        // Atomically set the EventReactor state to `Stopping`.
        if self
            .api
            .step
            .compare_exchange(
                ReactorPhaseKind::Handling,
                ReactorPhaseKind::Stopping,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            ::log::warn!("reactor[ctrl]: failed to set step: shutdown");
        }

        // Signal the EventReactor to wake on the `ring_step` futex.
        ::log::debug!("reactor[ctrl]: wake: shutdown");
        let futex = self.api.step.as_ref();
        ::rustix::thread::futex::wake(
            futex,
            ::rustix::thread::futex::Flags::PRIVATE,
            ReactorPhase::kind_into(ReactorPhaseKind::Handling),
        )?;

        // Wait for the EventReactor thread to finish and unpack the result.
        if let Some(handle) = self.handle.take() {
            match handle.join() {
                Ok(res) => {
                    res?;
                },
                Err(err) => {
                    ::std::panic::resume_unwind(err);
                },
            }
        }

        Ok(())
    }
}
