use num_enum::TryFromPrimitive;
use crate::ieee_802154::{Ieee802154Frame, Ieee802154FrameType};
use crate::types::{Eui64, Key, Nwk, PanId};
use std::convert::TryFrom;
use crate::zigbee_nwk::{NwkFrame, NwkSecurityHeaderKeyId, NwkSecurityLevel, NwkFrameType};
use std::collections::HashMap;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum NwkCommandId {
    RouteRequest = 0x01,
    RouteReply = 0x02,
    NetworkStatus = 0x03,
    Leave = 0x04,
    RouteRecord = 0x05,
    RejoinRequest = 0x06,
    RejoinResponse = 0x07,
    LinkStatus = 0x08,
    NetworkReport = 0x09
    NetworkUpdate = 0x0a,
    EndDeviceTimeoutRequest = 0x0b,
    EndDeviceTimeoutResponse = 0x0c,
    LinkPowerDelta = 0x0d,
    NetworkCommissioningRequest = 0x0e,
    NetworkCommissioningResponse = 0x0f,
}


#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
pub enum NwkRouteRequestManyToOne {
    NotManyToOne = 0,
    ManyToOneSenderSupportsRouteRecordTable = 1,
    ManyToOneSenderDoesntSupportRouteRecordTable = 2,
    Reserved = 3,
}


#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteRequestCommand {
    pub multicast: bool,
    pub many_to_one: NwkRouteRequestManyToOne,
    pub route_request_identifier: u8,
    pub destination_address: Nwk,
    pub path_cost: u8,
    pub destination_eui64: Option<Eui64>,
    pub tlvs: Vec<u8>,
}

impl NwkRouteRequestCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 5 {
            return Err("Not enough data to parse NwkRouteRequestCommand");
        }

        let multicast = (bytes[0] & 0b01000000) != 0;
        let has_destination_eui64 = (bytes[0] & 0b00100000 != 0);

        if has_destination_eui64 && bytes.len() < 5 + 8 {
            return Err("Not enough data to parse NwkRouteRequestCommand destination EUI64");
        }

        // This cannot fail, `NwkRouteRequestManyToOne` is a complete 2 bit enum
        let many_to_one = NwkRouteRequestManyToOne::try_from((bytes[0] & 0b00011000) >> 3).unwrap();

        let route_request_identifier = bytes[1];
        let destination_address = Nwk(u16::from_le_bytes([bytes[2], bytes[3]));
        let path_cost = bytes[4];

        let destination_eui64 = None;
        let tlvs;

        if has_destination_eui64 {
            (destination_eui64, tlvs) = Eui64::deserialize(&bytes[5..]);
        } else {
            tlvs = &bytes[5..];
        }

        Ok(
            Self {
                multicast,
                many_to_one,
                route_request_identifier,
                destination_address,
                path_cost,
                destination_eui64,
                tlvs: tlvs.to_vec(),
            },
        )
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let mut byte = 0u8;
        byte |= (self.multicast as u8) << 6;
        byte |= (!self.destination_eui64.is_none() as u8) << 5;
        byte |= (self.many_to_one as u8) << 3;
        bytes.push(byte);

        bytes.push(self.route_request_identifier);
        bytes.extend_from_slice(&self.destination_address.to_bytes());
        bytes.push(self.path_cost);

        if let Some(destination_eui64) = self.destination_eui64 {
            bytes.extend_from_slice(&destination_eui64.to_bytes());
        }

        bytes.extend_from_slice(&self.tlvs);

        bytes
    }
}


pub struct NwkRouteRecordCommand {
    pub relays: Vec<Nwk>,
}

impl NwkRouteRecordCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse NwkRouteRecordCommand");
        }

        let num_relays = bytes[0] as usize;
        let relays = Vec::with_capacity(num_relays);

        let mut remaining = &bytes[1..];

        for _ in 0..num_relays {
            let (nwk, remaining) = Nwk::deserialize(remaining)?;
            relays.push(nwk);
        }

        Ok(Self { relays })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let num_relays = self.relays.len();
        let mut bytes = Vec::with_capacity(1 + num_relays * 2);

        bytes.push(num_relays as u8);

        for relay in &self.relays {
            bytes.extend_from_slice(&relay.to_bytes());
        }

        bytes
    }
}


pub struct NwkLinkStatus {
    pub address: NWK,
    pub incoming_cost: u8,
    pub outgoing_cost: u8,
}

impl NwkLinkStatus {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 3 {
            return Err("Not enough data to parse NwkLinkStatus");
        }

        let address = Nwk::from_bytes(&bytes[0..2]);
        let incoming_cost = (bytes[2] & 0b00000111) >> 0;
        let outgoing_cost = (bytes[2] & 0b01110000) >> 4;

        Ok(Self {
            address,
            incoming_cost,
            outgoing_cost,
        })
    }

    pub fn serialize(&self) -> [u8; 3] {
        let mut result = [0x00; 3];
        self.address.to_bytes().copy_to_slice(&result[0..2]);
        result[2] |= self.incoming_cost << 0;
        result[2] |= self.outgoing_cost << 4;

        result
    }
}


pub struct NwkLinkStatusCommand {
    // Flag: 0b01000000
    pub is_first_frame: bool,
    // Flag: 0b00100000
    pub is_last_frame: bool,
    // Count: 0b00011111
    // Appended:
    pub link_statuses: Vec<NwkLinkStatus>,
}

impl NwkLinkStatusCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data to parse NwkLinkStatusCommand");
        }

        let is_first_frame = (bytes[0] & 0b01000000) != 0;
        let is_last_frame = (bytes[0] & 0b00100000) != 0;
        let count = (bytes[0] & 0b00011111) as usize;

        if bytes.len() < 1 + count * 3 {
            return Err("Not enough data to parse NwkLinkStatusCommand link statuses");
        }

        let mut link_statuses = Vec::with_capacity(count);
        let mut remaining = &bytes[1..];

        for _ in 0..count {
            let link_status = NwkLinkStatus::from_bytes(remaining)?;
            link_statuses.push(link_status);
            remaining = &remaining[3..];
        }

        Ok(Self {
            is_first_frame,
            is_last_frame,
            link_statuses,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        if self.link_statuses.len() > 31 {
            panic!("Cannot encode more than 31 link statuses");
        }

        let mut result = Vec::with_capacity(1 + self.link_statuses.len() * 3);

        let mut byte = 0u8;
        byte |= (self.is_first_frame as u8) << 6;
        byte |= (self.is_last_frame as u8) << 5;
        byte |= (self.link_statuses.len() as u8) & 0b00011111;
        result.push(byte);

        for link_status in &self.link_statuses {
            result.extend_from_slice(&link_status.serialize());
        }

        result
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_nwk_route_request_command() {
        let bytes = hex!("10defcff00");
        let command = NwkRouteRequestCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkRouteRequestCommand {
                multicast: false,
                many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                route_request_identifier: 222,
                destination_address: Nwk(0xFFFC),
                path_cost: 0,
                destination_eui64: None,
                tlvs: vec![],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_route_record_command_empty() {
        let bytes = hex!("00");
        let command = NwkRouteRecordCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkRouteRecordCommand {
                relays: vec![Nwk()],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_route_record_command() {
        let bytes = hex!("01eb1c");
        let command = NwkRouteRecordCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkRouteRecordCommand {
                relays: vec![Nwk(0x1CEB)],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_link_status_command() {
        let bytes = hex!("69000011130711ae0e77eb1c13c58816fe9411599e13ff9f11e1e111");
        let command = NwkLinkStatusCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkLinkStatusCommand {
                is_first_frame: true,
                is_last_frame: true,
                link_statuses: vec![
                    NwkLinkStatus {
                        address: Nwk(0x0000),
                        incoming_cost: 1,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x0713),
                        incoming_cost: 1,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x0EAE),
                        incoming_cost: 7,
                        outgoing_cost: 7,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x1CEB),
                        incoming_cost: 3,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x88C5),
                        incoming_cost: 6,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x94FE),
                        incoming_cost: 1,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x9E59),
                        incoming_cost: 3,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0x9FFF),
                        incoming_cost: 1,
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0xE1E1),
                        incoming_cost: 1,
                        outgoing_cost: 1,
                    },
                ],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }
}