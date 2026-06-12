#![no_main]

use libfuzzer_sys::fuzz_target;
use zigbee::nwk::frame::EncryptedNwkFrame;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = EncryptedNwkFrame::from_bytes(data) {
        let reencoded = frame.to_bytes();
        let reparsed = EncryptedNwkFrame::from_bytes(&reencoded)
            .expect("re-parsing our own serialization must succeed");
        assert_eq!(frame, reparsed, "round-trip changed the frame");
    }
});
