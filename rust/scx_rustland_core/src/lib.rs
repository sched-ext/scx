pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod alloc;
pub use alloc::ALLOCATOR;

mod rustland_builder;
pub use rustland_builder::RustLandBuilder;
