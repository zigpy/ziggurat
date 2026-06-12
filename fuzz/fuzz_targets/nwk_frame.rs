#![no_main]

use libfuzzer_sys::fuzz_target;
use zigbee::nwk::frame::EncryptedNwkFrame;

fuzz_target!(|data: &[u8]| {
    let _ = EncryptedNwkFrame::from_bytes(data);
});
