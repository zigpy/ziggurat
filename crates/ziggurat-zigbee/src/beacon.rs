use abstract_bits::abstract_bits;
use arbitrary_int::{u2, u4, u24};
use ziggurat_ieee_802154::types::Eui64;

#[derive(Debug, Eq, PartialEq)]
#[abstract_bits]
pub struct ZigbeeBeacon {
    pub protocol_id: u8,
    pub stack_profile: u4,
    pub protocol_version: u4,
    pub reserved1: u2,
    pub router_capacity: bool,
    pub device_depth: u4,
    pub end_device_capacity: bool,
    pub extended_pan_id: Eui64,
    pub tx_offset: u24,
    pub update_id: u8,
}

#[cfg(test)]
mod test {
    use super::*;
    use abstract_bits::{AbstractBits, BitReader};
    use hex_literal::hex;

    #[test]
    fn test_zigbee_beacon_round_trip() {
        let beacon = ZigbeeBeacon {
            protocol_id: 0,
            stack_profile: 2,
            protocol_version: 2,
            reserved1: 0b00,
            router_capacity: true,
            device_depth: 0,
            end_device_capacity: true,
            extended_pan_id: Eui64::from_hex("3a:9f:44:01:0b:3c:cb:93"),
            tx_offset: 0xFFFFFF,
            update_id: 0,
        };

        // The Zigbee beacon payload is exactly 15 bytes
        let bytes = beacon.to_abstract_bytes().unwrap();
        assert_eq!(bytes, hex!("00 22 84 93cb3c0b 01449f3a ffffff 00").to_vec());

        let mut reader = BitReader::from(bytes.as_slice());
        assert_eq!(
            ZigbeeBeacon::read_abstract_bits(&mut reader).unwrap(),
            beacon
        );
    }
}
