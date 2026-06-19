#![no_main]

use abstract_bits::{AbstractBits, BitReader};
use libfuzzer_sys::fuzz_target;
use ziggurat_zigbee::beacon::ZigbeeBeacon;

fuzz_target!(|data: &[u8]| {
    let mut reader = BitReader::from(data);
    let _ = ZigbeeBeacon::read_abstract_bits(&mut reader);
});
