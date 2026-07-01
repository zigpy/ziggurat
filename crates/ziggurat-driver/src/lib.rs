#![no_std]

extern crate alloc;

// The host bridge spawns an OS thread for the embassy executor; that path alone needs std.
#[cfg(feature = "embassy-host")]
extern crate std;

pub mod rng;
pub mod runtime;
pub mod signal;
pub mod sync;
pub mod zigbee_stack;

pub use ziggurat_ieee_802154;
pub use ziggurat_zigbee;
