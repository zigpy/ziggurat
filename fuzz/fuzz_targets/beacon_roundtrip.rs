#![no_main]

use abstract_bits::{AbstractBits, BitReader};
use libfuzzer_sys::fuzz_target;
use zigbee::beacon::ZigbeeBeacon;

fuzz_target!(|data: &[u8]| {
    let mut reader = BitReader::from(data);
    if let Ok(beacon) = ZigbeeBeacon::read_abstract_bits(&mut reader) {
        let reencoded = beacon.to_abstract_bits().unwrap();
        let mut reader = BitReader::from(reencoded.as_slice());
        let reparsed = ZigbeeBeacon::read_abstract_bits(&mut reader)
            .expect("re-parsing our own serialization must succeed");
        assert_eq!(beacon, reparsed, "round-trip changed the beacon");
    }
});
