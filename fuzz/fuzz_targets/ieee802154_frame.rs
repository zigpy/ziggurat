#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `from_bytes_without_fcs` computes a valid FCS, so the parser proper is
    // exercised instead of the checksum gate rejecting almost every input
    let _ = ieee_802154::Ieee802154Frame::from_bytes_without_fcs(data);
    let _ = ieee_802154::Ieee802154Frame::from_bytes(data);
});
