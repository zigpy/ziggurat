//! The async runtime seam shared by the driver and the radio backends.

#![no_std]

extern crate alloc;

// The host bridge spawns an OS thread for the embassy executor; that path alone needs std.
#[cfg(feature = "embassy-host")]
extern crate std;

pub mod runtime;
pub mod sync;
