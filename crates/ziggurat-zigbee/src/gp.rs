use abstract_bits::{AbstractBits, BitReader, abstract_bits};
use num_enum::TryFromPrimitive;

use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_ieee_802154::{
    FCS_LENGTH, FrameWriter, Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame,
    Ieee802154Frame, Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
    Ieee802154FrameVersion, MAX_MAC_PAYLOAD_SIZE, MAX_PHY_PACKET_SIZE, TooLong, write_frame,
};

use crate::ParseError;
use crate::constants::GP_PROTOCOL_VERSION;

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

#[abstract_bits(bits = 3)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum GpApplicationId {
    SrcId = 0b000,
    Ieee = 0b010,
}

#[abstract_bits(bits = 2)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum GpSecurityLevel {
    None = 0b00,
    FrameCounterMic = 0b10,
    EncryptedMic = 0b11,
}

/// The Extended NWK Frame Control field of a GPDF (GP A.1.4.1.3)
#[abstract_bits]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpExtendedNwkFrameControl {
    pub application_id: GpApplicationId,
    pub security_level: GpSecurityLevel,
    /// Set for an individual key, cleared for a shared one (GP Table 12)
    pub individual_key: bool,
    pub rx_after_tx: bool,
    /// Set if the GPDF is sent to the GPD
    pub to_gpd: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GpdId {
    SrcId(u32),
    Ieee { ieee: Eui64, endpoint: u8 },
}

/// Who a GPDF is for. A Maintenance frame carries no GPD ID, so it reaches whichever
/// GPD listens (GP A.1.4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GpdfTarget {
    Gpd(GpdId),
    Maintenance,
}

/// The stub NWK header of a GPDF (GP A.1.4.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpdfHeader {
    pub frame_control: GpNwkFrameControl,
    pub extended_frame_control: Option<GpExtendedNwkFrameControl>,
    /// Absent in a Maintenance frame
    pub gpd: Option<GpdId>,
    pub frame_counter: Option<u32>,
}

impl GpdfHeader {
    /// Parse the stub NWK header at the start of a GPDF's MAC payload. `source_ieee` is
    /// the MAC source address, which identifies the GPD for ApplicationID 0b010.
    pub fn deserialize(
        bytes: &[u8],
        source_ieee: Option<Eui64>,
    ) -> Result<(Self, &[u8]), ParseError> {
        let mut reader = BitReader::from(bytes);
        let frame_control = GpNwkFrameControl::read_abstract_bits(&mut reader)?;
        let extended_frame_control = match frame_control.extended {
            true => Some(GpExtendedNwkFrameControl::read_abstract_bits(&mut reader)?),
            false => None,
        };
        let mut remaining = &bytes[reader.bytes_read()..];

        let application_id = extended_frame_control
            .as_ref()
            .map_or(GpApplicationId::SrcId, |control| control.application_id);

        let gpd = match (frame_control.frame_type, application_id) {
            (GpFrameType::Maintenance, _) => None,
            (GpFrameType::Data, GpApplicationId::SrcId) => {
                let (src_id, rest) = remaining
                    .split_first_chunk()
                    .ok_or(ParseError::UnexpectedEnd { ty: "GPD SrcID" })?;
                remaining = rest;
                Some(GpdId::SrcId(u32::from_le_bytes(*src_id)))
            }
            (GpFrameType::Data, GpApplicationId::Ieee) => {
                let ieee = source_ieee.ok_or(ParseError::UnexpectedEnd {
                    ty: "GPD IEEE address",
                })?;
                let (&endpoint, rest) = remaining
                    .split_first()
                    .ok_or(ParseError::UnexpectedEnd { ty: "GPD endpoint" })?;
                remaining = rest;
                Some(GpdId::Ieee { ieee, endpoint })
            }
        };

        let mut header = Self {
            frame_control,
            extended_frame_control,
            gpd,
            frame_counter: None,
        };

        if header.security_level() != GpSecurityLevel::None {
            let (frame_counter, rest) =
                remaining
                    .split_first_chunk()
                    .ok_or(ParseError::UnexpectedEnd {
                        ty: "GPDF security frame counter",
                    })?;
            remaining = rest;
            header.frame_counter = Some(u32::from_le_bytes(*frame_counter));
        }

        Ok((header, remaining))
    }

    pub fn serialize(&self, writer: &mut FrameWriter) -> Result<(), TooLong> {
        writer.bits(&self.frame_control)?;

        if let Some(control) = &self.extended_frame_control {
            writer.bits(control)?;
        }

        match self.gpd {
            Some(GpdId::SrcId(src_id)) => writer.extend(&src_id.to_le_bytes())?,
            Some(GpdId::Ieee { endpoint, .. }) => writer.push(endpoint)?,
            None => (),
        }

        if let Some(frame_counter) = self.frame_counter {
            writer.extend(&frame_counter.to_le_bytes())?;
        }

        Ok(())
    }

    pub fn target(&self) -> GpdfTarget {
        self.gpd.map_or(GpdfTarget::Maintenance, GpdfTarget::Gpd)
    }

    /// A Maintenance frame is always unprotected (GP A.1.4.2.1)
    pub const fn security_level(&self) -> GpSecurityLevel {
        match (self.frame_control.frame_type, &self.extended_frame_control) {
            (GpFrameType::Data, Some(control)) => control.security_level,
            _ => GpSecurityLevel::None,
        }
    }

    /// Whether the GPD listens after sending this GPDF (GP A.1.4.1.2, A.1.4.1.3)
    pub fn rx_after_tx(&self) -> bool {
        match self.frame_control.frame_type {
            GpFrameType::Maintenance => !self.frame_control.auto_commissioning,
            GpFrameType::Data => self
                .extended_frame_control
                .as_ref()
                .is_some_and(|control| control.rx_after_tx),
        }
    }
}

/// Build a GPDF sent to a GPD (GP A.1.4.1, A.1.5.2.2), unprotected: a Basic Combo need
/// not send secured GPDFs (GP A.1.5.2.1.1). The driver assigns the MAC sequence number.
pub fn build_gpdf_to_gpd(
    target: GpdfTarget,
    command_id: u8,
    command_payload: &[u8],
) -> Result<Ieee802154Frame, TooLong> {
    let header = match target {
        GpdfTarget::Maintenance => GpdfHeader {
            frame_control: GpNwkFrameControl {
                frame_type: GpFrameType::Maintenance,
                protocol_version: GP_PROTOCOL_VERSION,
                auto_commissioning: false,
                extended: false,
            },
            extended_frame_control: None,
            gpd: None,
            frame_counter: None,
        },
        GpdfTarget::Gpd(gpd) => GpdfHeader {
            frame_control: GpNwkFrameControl {
                frame_type: GpFrameType::Data,
                protocol_version: GP_PROTOCOL_VERSION,
                auto_commissioning: false,
                extended: true,
            },
            extended_frame_control: Some(GpExtendedNwkFrameControl {
                application_id: match gpd {
                    GpdId::SrcId(_) => GpApplicationId::SrcId,
                    GpdId::Ieee { .. } => GpApplicationId::Ieee,
                },
                security_level: GpSecurityLevel::None,
                individual_key: false,
                rx_after_tx: false,
                to_gpd: true,
            }),
            gpd: Some(gpd),
            frame_counter: None,
        },
    };

    let mac_payload = write_frame::<MAX_MAC_PAYLOAD_SIZE>(|writer| {
        header.serialize(writer)?;
        writer.push(command_id)?;
        writer.extend(command_payload)
    })?;

    // A GPDF for an IEEE-addressed GPD carries its address as the MAC destination
    // (GP A.1.4.1.1); everything else is broadcast
    let dest_address = match target {
        GpdfTarget::Gpd(GpdId::Ieee { ieee, .. }) => Ieee802154Address::Eui64(ieee),
        _ => Ieee802154Address::Nwk(Nwk(0xFFFF)),
    };

    let frame = Ieee802154Frame::Data(Ieee802154DataFrame {
        header: Ieee802154FrameHeader {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: false,
                pan_id_compression: false,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: match dest_address {
                    Ieee802154Address::Nwk(_) => Ieee802154AddressingMode::Short,
                    Ieee802154Address::Eui64(_) => Ieee802154AddressingMode::Long,
                },
                frame_version: Ieee802154FrameVersion::Ieee2003,
                src_addr_mode: Ieee802154AddressingMode::None,
            },
            sequence_number: Some(0),
            dest_pan_id: Some(PanId(0xFFFF)),
            dest_address: Some(dest_address),
            src_pan_id: None,
            src_address: None,
        },
        payload: mac_payload,
        fcs: 0x0000,
    });

    // The payload fits in the MAC payload limit, but the MAC header may leave less room
    write_frame::<{ MAX_PHY_PACKET_SIZE - FCS_LENGTH }>(|writer| frame.serialize(writer))?;

    Ok(frame)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use hex_literal::hex;

    const SRC_ID: u32 = 0x87654321;

    /// The stub NWK header and the rest of a received GPDF
    fn received(psdu: &[u8]) -> (GpdfHeader, Vec<u8>) {
        let Ieee802154Frame::Data(frame) = Ieee802154Frame::from_bytes_without_fcs(psdu).unwrap()
        else {
            panic!("not a data frame");
        };
        let source_ieee = match frame.header.src_address {
            Some(Ieee802154Address::Eui64(ieee)) => Some(ieee),
            _ => None,
        };
        let (header, rest) = GpdfHeader::deserialize(frame.payload, source_ieee).unwrap();

        (header, rest.to_vec())
    }

    /// A Channel Configuration (0xF3) for channel 11, with the spec's MAC sequence number
    fn channel_configuration(target: GpdfTarget) -> Vec<u8> {
        let mut frame = build_gpdf_to_gpd(target, 0xF3, &[0x00]).unwrap();
        frame.header_mut().sequence_number = Some(0x39);
        frame.to_bytes_without_fcs().to_vec()
    }

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

    #[test]
    fn test_gpdf_header_deserialize() {
        // GP A.1.5.6.2.1, incoming frame
        let (header, rest) = received(&hex!(
            "0108 01 FFFF FFFF 8C 50 21436587 11223344 20 F636789E"
        ));

        assert_eq!(
            header,
            GpdfHeader {
                frame_control: GpNwkFrameControl {
                    frame_type: GpFrameType::Data,
                    protocol_version: 3,
                    auto_commissioning: false,
                    extended: true,
                },
                extended_frame_control: Some(GpExtendedNwkFrameControl {
                    application_id: GpApplicationId::SrcId,
                    security_level: GpSecurityLevel::FrameCounterMic,
                    individual_key: false,
                    rx_after_tx: true,
                    to_gpd: false,
                }),
                gpd: Some(GpdId::SrcId(SRC_ID)),
                frame_counter: Some(0x44332211),
            }
        );
        assert_eq!(rest, hex!("20 F636789E"));
        assert!(header.rx_after_tx());

        let serialized =
            write_frame::<MAX_MAC_PAYLOAD_SIZE>(|writer| header.serialize(writer)).unwrap();
        assert_eq!(serialized, hex!("8C 50 21436587 11223344"));
    }

    #[test]
    fn test_unprotected() {
        let (header, rest) = received(&hex!("0108 01 FFFF FFFF 8C 40 21436587 20"));
        assert!(header.rx_after_tx());
        assert_eq!(header.security_level(), GpSecurityLevel::None);
        assert_eq!(rest, hex!("20"));

        assert_eq!(
            channel_configuration(header.target()),
            hex!("0108 39 FFFF FFFF 8C 80 21436587 F3 00")
        );
    }

    #[test]
    fn test_ieee() {
        // ApplicationID 0b010 from the GPD's IEEE address, endpoint 0x01
        let (header, _) = received(&hex!("41C8 01 FFFF FFFF 1122334455667788 8C 42 01 20"));
        assert!(header.rx_after_tx());
        assert_eq!(
            header.target(),
            GpdfTarget::Gpd(GpdId::Ieee {
                ieee: Eui64::from_hex("8877665544332211"),
                endpoint: 0x01,
            })
        );

        assert_eq!(
            channel_configuration(header.target()),
            hex!("010C 39 FFFF 1122334455667788 8C 82 01 F3 00")
        );
    }

    #[test]
    fn test_maintenance() {
        // Channel Request (0xE3) in a Maintenance frame, the GPD then listens
        let (header, _) = received(&hex!("0108 01 FFFF FFFF 0D E3 55"));
        assert!(header.rx_after_tx());
        assert_eq!(header.target(), GpdfTarget::Maintenance);

        assert_eq!(
            channel_configuration(header.target()),
            hex!("0108 39 FFFF FFFF 0D F3 00")
        );

        // With Auto-Commissioning set, the GPD does not listen
        let (header, _) = received(&hex!("0108 01 FFFF FFFF 4D E3 55"));
        assert!(!header.rx_after_tx());
    }
}
