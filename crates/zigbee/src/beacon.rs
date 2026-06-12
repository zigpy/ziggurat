use abstract_bits::{
    AbstractBits, BitReader, BitWriter, FromBytesError, ToBytesError, abstract_bits,
};
use arbitrary_int::{u2, u4, u24};
use ieee_802154::types::Eui64;

// TODO: report this bug to abstract-bits
#[derive(Debug, Eq, PartialEq)]
pub struct RenamedU24(pub u24);

impl AbstractBits for RenamedU24 {
    const MIN_BITS: usize = 24;
    const MAX_BITS: usize = 24;

    fn write_abstract_bits(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
        // `u24::value()` widens to a `u32`, whose fourth byte must not be written
        let [b0, b1, b2, _] = self.0.value().to_le_bytes();
        b0.write_abstract_bits(writer)?;
        b1.write_abstract_bits(writer)?;
        b2.write_abstract_bits(writer)?;

        Ok(())
    }

    fn read_abstract_bits(reader: &mut BitReader) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        Ok(Self(u24::from_le_bytes([
            u8::read_abstract_bits(reader)?,
            u8::read_abstract_bits(reader)?,
            u8::read_abstract_bits(reader)?,
        ])))
    }
}

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
    pub tx_offset: RenamedU24,
    pub update_id: u8,
}

#[cfg(test)]
mod test {
    use super::*;
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
            tx_offset: RenamedU24(u24::new(0xFFFFFF)),
            update_id: 0,
        };

        // The Zigbee beacon payload is exactly 15 bytes
        let bytes = beacon.to_abstract_bits().unwrap();
        assert_eq!(bytes, hex!("00 22 84 93cb3c0b 01449f3a ffffff 00").to_vec());

        let mut reader = BitReader::from(bytes.as_slice());
        assert_eq!(
            ZigbeeBeacon::read_abstract_bits(&mut reader).unwrap(),
            beacon
        );
    }
}
