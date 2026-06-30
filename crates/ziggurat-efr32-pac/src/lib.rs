// svd2rust-generated PAC, produced at build time from the EFR32MG24 SVD (see build.rs).
// build.rs strips the generated crate-level inner attributes; they're re-declared here so
// the code can be `include!`d at the crate root.
#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

include!(concat!(env!("OUT_DIR"), "/pac.rs"));
