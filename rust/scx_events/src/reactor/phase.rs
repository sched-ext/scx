use ::alloc::sync::Arc;
use ::core::sync::atomic::{AtomicU32, Ordering};

/// The phase of the [`EventReactor`].
///
/// [`EventReactor`]: crate::EventReactor
#[derive(Clone)]
#[repr(transparent)]
pub struct ReactorPhase(Arc<AtomicU32>);

impl ReactorPhase {
    /// Create a new [`ReactorPhase`].
    pub fn new() -> Self {
        let value = Self::kind_into(ReactorPhaseKind::Starting);
        Self(Arc::new(AtomicU32::new(value)))
    }

    /// Access the underlying atomic phase var as a pointer.
    pub fn as_ptr(&self) -> *const u32 {
        self.0.as_ptr().cast()
    }

    /// Access the underlying atomic phase var as a reference.
    pub fn as_ref(&self) -> &AtomicU32 {
        &self.0
    }

    /// Load the atomic phase var with specified ordering.
    pub fn load(&self, order: Ordering) -> ReactorPhaseKind {
        let val = self.0.load(order);
        // SAFETY: interface ensures `kind_from` is total.
        unsafe { Self::kind_from(val) }
    }

    /// Store the a new phase in the atomic phase var with specified ordering.
    pub fn store(&self, kind: ReactorPhaseKind, order: Ordering) {
        let val = Self::kind_into(kind);
        self.0.store(val, order);
    }

    /// Perform an atomic compare and exchange operation for updating the phase.
    pub fn compare_exchange(
        &self,
        current: ReactorPhaseKind,
        new: ReactorPhaseKind,
        success: Ordering,
        failure: Ordering,
    ) -> Result<ReactorPhaseKind, ReactorPhaseKind> {
        let current = Self::kind_into(current);
        let new = Self::kind_into(new);
        self.0
            .compare_exchange(current, new, success, failure)
            // SAFETY: interface ensures `kind_from` is total.
            .map(|ok| unsafe { Self::kind_from(ok) })
            // SAFETY: interface ensures `kind_from` is total.
            .map_err(|err| unsafe { Self::kind_from(err) })
    }

    /// Convert the reactor phase kind into a u32.
    pub const fn kind_into(kind: ReactorPhaseKind) -> u32 {
        match kind {
            ReactorPhaseKind::Starting => REACTOR_PHASE_STARTING,
            ReactorPhaseKind::Handling => REACTOR_PHASE_HANDLING,
            ReactorPhaseKind::Stopping => REACTOR_PHASE_STOPPING,
            ReactorPhaseKind::Finished => REACTOR_PHASE_FINISHED,
        }
    }

    /// SAFETY: caller must ensure `value` maps into `ReactorStepKind`.
    const unsafe fn kind_from(value: u32) -> ReactorPhaseKind {
        match value {
            REACTOR_PHASE_STARTING => ReactorPhaseKind::Starting,
            REACTOR_PHASE_HANDLING => ReactorPhaseKind::Handling,
            REACTOR_PHASE_STOPPING => ReactorPhaseKind::Stopping,
            REACTOR_PHASE_FINISHED => ReactorPhaseKind::Finished,
            // SAFETY: unreachable because `value` always originates from enum.
            _ => unsafe { ::core::hint::unreachable_unchecked() },
        }
    }
}

/// Enum classifying the reactor phases.
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum ReactorPhaseKind {
    /// Constant for the reactor starting phase.
    Starting = REACTOR_PHASE_STARTING,
    /// Constant for the reactor handling phase.
    Handling = REACTOR_PHASE_HANDLING,
    /// Constant for the reactor stopping phase.
    Stopping = REACTOR_PHASE_STOPPING,
    /// Constant for the reactor finished phase.
    Finished = REACTOR_PHASE_FINISHED,
}

/// Constant for the reactor starting phase.
const REACTOR_PHASE_STARTING: u32 = 0;
/// Constant for the reactor handling phase.
const REACTOR_PHASE_HANDLING: u32 = 1;
/// Constant for the reactor stopping phase.
const REACTOR_PHASE_STOPPING: u32 = 2;
/// Constant for the reactor finished phase.
const REACTOR_PHASE_FINISHED: u32 = 3;
