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
}