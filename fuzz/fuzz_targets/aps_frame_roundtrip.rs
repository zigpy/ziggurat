#![no_main]

use libfuzzer_sys::fuzz_target;
use ziggurat_zigbee::aps::frame::{ApsFrame, parse_aps_frame};
use ziggurat_zigbee::nwk::frame::{MAX_NSDU_SIZE, Nsdu};

// ApsFrame has no PartialEq or unified to_bytes, so assert the weaker but
// still-useful property that serialize-then-parse is a fixed point: encoding a
// parsed frame and re-parsing must yield the same bytes on a second encode.
fn to_bytes(frame: &ApsFrame) -> Nsdu {
    match frame {
        ApsFrame::Data(f) => f.to_bytes(),
        ApsFrame::EncryptedData(f) => f.to_bytes(),
        ApsFrame::Ack(f) => f.to_bytes(),
        ApsFrame::EncryptedAck(f) => f.to_bytes(),
        ApsFrame::Command(f) => f.to_bytes(),
        ApsFrame::EncryptedCommand(f) => f.to_bytes(),
    }
}

fuzz_target!(|data: &[u8]| {
    // An APS frame is the payload of a NWK frame
    if data.len() > MAX_NSDU_SIZE {
        return;
    }

    if let Ok(frame) = parse_aps_frame(data) {
        let once = to_bytes(&frame);
        let reparsed =
            parse_aps_frame(&once).expect("re-parsing our own serialization must succeed");
        let twice = to_bytes(&reparsed);
        assert_eq!(once, twice, "serialize/parse is not a fixed point");
    }
});
