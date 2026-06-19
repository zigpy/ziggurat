#![no_main]

use libfuzzer_sys::fuzz_target;

// serialize-then-parse must be a fixed point: encoding a parsed frame and
// re-parsing yields the same bytes on a second encode. Uses the FCS-free
// encoding because the `fcs` field is a checksum recomputed from the byte body,
// not part of the frame's logical identity — comparing it would false-fail on
// non-canonical inputs whose trailing bytes change the checksum.
fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = ziggurat_ieee_802154::Ieee802154Frame::from_bytes_without_fcs(data) {
        let once = frame.to_bytes_without_fcs();
        let reparsed = ziggurat_ieee_802154::Ieee802154Frame::from_bytes_without_fcs(&once)
            .expect("re-parsing our own serialization must succeed");
        let twice = reparsed.to_bytes_without_fcs();
        assert_eq!(once, twice, "serialize/parse is not a fixed point");
    }
});
