use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_mitosis
scheduler_tests!(|nr_cpus| DynamicScheduler::mitosis(nr_cpus));
