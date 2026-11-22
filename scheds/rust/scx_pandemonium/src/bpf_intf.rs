#![allow(dead_code)]
// MIRROR OF src/bpf/intf.h CONSTANTS. KEEP IN SYNC WITH THE C HEADER.
// THE STATIC ASSERT IN scheduler.rs CATCHES MAX_AFFINITY_CANDIDATES
// DRIFT AT COMPILE TIME.

pub const MAX_CPUS: u32 = 1024;
pub const MAX_AFFINITY_CANDIDATES: u32 = MAX_CPUS >> 3;

// THE BASE COST's RAIL (intf.h PHI_BASE_MIN_NS, PHI_BASE_MAX_NS): BPF HOLDS tau's
// COST AND THE KNOB TO IT, AND THE LAYER HOLDS WHAT IT WRITES TO THE SAME PAIR.
pub const PHI_BASE_MIN_NS: u64 = 5_000;
pub const PHI_BASE_MAX_NS: u64 = 100_000;

#[cfg(test)]
mod tests {
    // ONE RAIL AND ONE RING ON BOTH SIDES: THE MIRRORS ARE READ AGAINST THE
    // HEADER BPF BUILDS FROM.
    #[test]
    fn mirrors_match_intf_h() {
        let h = include_str!("bpf/intf.h");
        let define = |name: &str| -> u64 {
            h.lines()
                .filter_map(|l| l.trim().strip_prefix("#define "))
                .filter_map(|l| l.strip_prefix(name))
                .filter_map(|v| v.split_whitespace().next())
                .find_map(|v| v.trim_end_matches("ULL").parse().ok())
                .unwrap()
        };
        assert_eq!(define("PHI_BASE_MIN_NS"), super::PHI_BASE_MIN_NS);
        assert_eq!(define("PHI_BASE_MAX_NS"), super::PHI_BASE_MAX_NS);
        assert_eq!(define("SLICE_MIN_NS"), crate::tuning::SLICE_MIN_NS);
        assert_eq!(
            define("SLICE_STANDING_TARGETS"),
            crate::tuning::STANDING_TARGETS
        );
        assert_eq!(
            define("REFILL_RING_SLOTS") as usize,
            crate::scheduler::REFILL_RING_SLOTS
        );
    }

    // WHAT THE LAYER WRITES IS WHAT BPF APPLIES: A SLICE OR CEILING UNDER THE
    // FLOOR IS WRITTEN AT IT, AN UNWRITTEN HOLD AS THE HOLD BPF STANDS FOR IT,
    // AND A SET INSIDE THE RAILS PASSES UNCHANGED.
    #[test]
    fn written_knobs_are_the_applied_ones() {
        use crate::tuning::TuningKnobs;
        let k = TuningKnobs {
            slice_ns: 0,
            batch_slice_ns: 50_000,
            standing_targets: 0,
            ..Default::default()
        }
        .applied();
        let floor = crate::tuning::SLICE_MIN_NS;
        assert_eq!(
            (k.slice_ns, k.batch_slice_ns, k.standing_targets),
            (floor, floor, crate::tuning::STANDING_TARGETS)
        );
        let d = TuningKnobs {
            standing_targets: 2,
            waker_leave_ns: 25_000,
            ..Default::default()
        };
        let a = d.applied();
        assert_eq!(
            (
                a.slice_ns,
                a.batch_slice_ns,
                a.codel_thresh_ns,
                a.standing_targets,
                a.waker_leave_ns
            ),
            (
                d.slice_ns,
                d.batch_slice_ns,
                d.codel_thresh_ns,
                d.standing_targets,
                d.waker_leave_ns
            )
        );
    }
}
