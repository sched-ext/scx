use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_cosmos
scheduler_tests!(|nr_cpus| DynamicScheduler::cosmos(nr_cpus));
