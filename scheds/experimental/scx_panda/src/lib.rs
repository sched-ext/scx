// scx_panda LIBRARY ROOT. THE LOADER, THE TOPOLOGY FILL AND THE SKELETON LIVE
// HERE SO THE BINARY AND THE TESTS SHARE ONE IMPLEMENTATION.

#[macro_use]
pub mod log;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod bpf_skel;

pub mod bpf_intf;
pub mod events;
pub mod scheduler;
pub mod topology;
