/// Definitions related to AMD P-State Preferred Core Rankings.
pub(in crate::data) mod amd_pstate_prefcore_rankings;

/// Definitions related to data validation.
pub(crate) mod validation;

use self::amd_pstate_prefcore_rankings::AmdPstatePrefcoreRankings;

/// Shared data computed by the [`EventReactor`].
///
/// [`EventReactor`]: crate::EventReactor
#[non_exhaustive]
pub struct EventReactorData {
    /// AMD P-State Preferred Core Rankings data.
    pub amd_pstate_prefcore_rankings: AmdPstatePrefcoreRankings,
}

impl EventReactorData {
    #[must_use]
    pub fn new(cpu_count: usize) -> Self {
        let amd_pstate_prefcore_rankings = AmdPstatePrefcoreRankings::new(cpu_count);
        Self {
            amd_pstate_prefcore_rankings,
        }
    }
}
