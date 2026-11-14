//! The Ziggurat binary control protocol: a request/response surface with streamed
//! events and unsolicited notifications, spoken over whatever transport frames it
//! (a Spinel vendor-property tunnel, a COBS-framed byte stream, or WebSocket binary
//! frames). Shared by the embedded firmware and the host server.
//!
//! [`wire`] is the pure codec (enums, headers, payload structs, frame builders);
//! [`bridge`] maps those payloads to and from a live `ZigbeeStack`.

#![no_std]

extern crate alloc;

use alloc::string::String;

pub mod bridge;
pub mod send_tracker;
pub mod wire;

pub use bridge::*;
pub use send_tracker::*;
pub use wire::*;

pub fn version_string(platform: &str) -> String {
    [
        "ziggurat/",
        env!("ZIGGURAT_VERSION"),
        "; ",
        platform,
        "; ",
        env!("ZIGGURAT_BUILD_DATETIME"),
    ]
    .concat()
}
