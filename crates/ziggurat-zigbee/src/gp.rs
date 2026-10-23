use abstract_bits::abstract_bits;
use num_enum::TryFromPrimitive;

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum GpFrameType {
    Data = 0b00,
    Maintenance = 0b01,
}

/// The NWK Frame Control field of a GPDF (GP A.1.4.1.2). It shares the position of
/// the protocol version with the NWK frame control of a Zigbee frame.
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpNwkFrameControl {
    pub frame_type: GpFrameType,
    pub protocol_version: u4,
    pub auto_commissioning: bool,
    pub extended: bool,
}

#[cfg(test)]
mod test {
    use super::*;
    use abstract_bits::{AbstractBits, BitReader};
    use hex_literal::hex;

    #[test]
    fn test_gp_nwk_frame_control() {
        // The transmitted packet for SecurityLevel 0b10 (GP A.1.5.4.2.1)
        let bytes = hex!("8C 10 21436587 02000000 20 CF787E72");

        let mut reader = BitReader::from(&bytes[..]);
        assert_eq!(
            GpNwkFrameControl::read_abstract_bits(&mut reader).unwrap(),
            GpNwkFrameControl {
                frame_type: GpFrameType::Data,
                protocol_version: 3,
                auto_commissioning: false,
                extended: true,
            }
        );
    }
}
