// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// THE KERNEL'S OWN sched_ext EVENT COUNTERS, READ FROM SYSFS. THE KERNEL
// COUNTS WHAT THE PROGRAM CANNOT SEE: A select_cpu RETURN THE TASK COULD NOT
// USE, A SLICE REFILLED TO THE DEFAULT, A TASK SEATED PAST ops.enqueue. ONE
// LINE PER COUNTER, "NAME VALUE", PER LOADED SCHEDULER.

use std::collections::BTreeMap;

pub const EVENTS_PATH: &str = "/sys/kernel/sched_ext/root/events";

// THE COUNTERS THE PER-SECOND LINE CARRIES, IN ORDER, WITH THEIR SHORT NAMES.
pub const DELTA_KEYS: [(&str, &str); 6] = [
    ("SCX_EV_SELECT_CPU_FALLBACK", "fallback"),
    ("SCX_EV_REFILL_SLICE_DFL", "refill"),
    ("SCX_EV_ENQ_SKIP_MIGRATION_DISABLED", "migdis"),
    ("SCX_EV_ENQ_SKIP_EXITING", "exiting"),
    ("SCX_EV_DISPATCH_KEEP_LAST", "keeplast"),
    ("SCX_EV_REENQ_IMMED", "reenq"),
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScxEvents(pub BTreeMap<String, u64>);

impl ScxEvents {
    pub fn read() -> Option<Self> {
        std::fs::read_to_string(EVENTS_PATH)
            .ok()
            .map(|s| Self::parse(&s))
    }

    // A LINE THAT IS NOT "NAME VALUE" WITH AN INTEGER VALUE IS SKIPPED.
    pub fn parse(text: &str) -> Self {
        let mut m = BTreeMap::new();
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(k), Some(v)) = (it.next(), it.next()) else {
                continue;
            };
            if let Ok(n) = v.parse::<u64>() {
                m.insert(k.to_string(), n);
            }
        }
        Self(m)
    }

    pub fn get(&self, key: &str) -> u64 {
        self.0.get(key).copied().unwrap_or(0)
    }

    // THE SHORT FORM FOR THE PER-SECOND LINE: THE SIX DELTAS SINCE prev.
    pub fn delta_line(&self, prev: &ScxEvents) -> String {
        DELTA_KEYS
            .iter()
            .map(|(k, short)| format!("{}={}", short, self.get(k).wrapping_sub(prev.get(k))))
            .collect::<Vec<_>>()
            .join(" ")
    }

    // EVERY COUNTER, FOR THE EXIT SUMMARY.
    pub fn total_line(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{}={}", k.trim_start_matches("SCX_EV_"), v))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
