//! The Ziggurat binary control protocol: a request/response surface with streamed
//! events and unsolicited notifications, spoken over whatever transport frames it
//! (a Spinel vendor-property tunnel, a COBS-framed byte stream, or WebSocket binary
//! frames). Shared by the embedded firmware and the host server.
//!
//! [`wire`] is the pure codec (enums, headers, payload structs, frame builders);
//! [`bridge`] maps those payloads to and from a live `ZigbeeStack`.

#![no_std]

extern crate alloc;

pub mod bridge;
pub mod send_tracker;
pub mod wire;

pub use bridge::*;
pub use send_tracker::*;
pub use wire::*;

/// Reported by `GetFirmwareInfo`, e.g. `ziggurat/0.1.0+0490795-dirty`.
pub const VERSION: &str = concat!(
    "ziggurat/",
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("ZIGGURAT_GIT_VERSION")
);
