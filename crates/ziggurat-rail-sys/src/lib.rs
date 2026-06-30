//! FFI bindings to Silicon Labs RAIL for the EFR32MG24.
//!
//! The C glue is compiled from the Simplicity SDK by `build.rs` and linked against the
//! precompiled `librail_efr32xg24_gcc_release.a`; the `sl_rail` / `sl_rail_ieee802154`
//! API is bound with bindgen. Safe wrappers live in `ziggurat-phy-efr32`; this crate is
//! the raw `-sys` layer.

#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
