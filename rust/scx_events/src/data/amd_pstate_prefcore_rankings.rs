use ::alloc::sync::Arc;
use ::arc_swap::ArcSwapAny;
use ::core::{
    ops::{Deref, DerefMut},
    sync::atomic::AtomicU8,
};
use ::triomphe::ThinArc;

/// Data for AMD P-State Preferred Core Rankings.
#[repr(transparent)]
#[non_exhaustive]
pub struct AmdPstatePrefcoreRankings {
    /// The slice of rankings presented through an RCU interface.
    pub arc: Arc<ArcSwapAny<ThinArc<(), AtomicU8>>>,
}

impl AmdPstatePrefcoreRankings {
    /// Create a new [`AmdPstatePrefcoreRankings`].
    #[must_use]
    pub fn new(cpu_count: usize) -> Self {
        let iter = ::core::iter::repeat_n(0, cpu_count).map(AtomicU8::new);
        let arc = ThinArc::from_header_and_iter((), iter);
        let arc = Arc::new(ArcSwapAny::new(arc));
        Self { arc }
    }
}

impl Deref for AmdPstatePrefcoreRankings {
    type Target = Arc<ArcSwapAny<ThinArc<(), AtomicU8>>>;

    fn deref(&self) -> &Self::Target {
        &self.arc
    }
}

impl DerefMut for AmdPstatePrefcoreRankings {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.arc
    }
}
