#![no_main]

use libfuzzer_sys::fuzz_target;
use zigbee::aps::frame::parse_aps_frame;

fuzz_target!(|data: &[u8]| {
    let _ = parse_aps_frame(data);
});
