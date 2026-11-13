#![no_main]

use libfuzzer_sys::fuzz_target;
use ziggurat_ieee_802154::{FrameBytes, MAX_PHY_PACKET_SIZE};
use ziggurat_zigbee::aps::frame::{ApsFrame, parse_aps_frame};

// ApsFrame has no PartialEq or unified to_bytes, so assert the weaker but
// still-useful property that serialize-then-parse is a fixed point: encoding a
// parsed frame and re-parsing must yield the same bytes on a second encode.
fn to_bytes(frame: &ApsFrame) -> FrameBytes {
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
    // An APS frame rides inside one 802.15.4 frame
    if data.len() > MAX_PHY_PACKET_SIZE {
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
