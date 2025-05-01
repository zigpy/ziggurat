use crate::types::{Eui64, Nwk};
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum NwkCommandId {
    RouteRequest = 0x01,
    RouteReply = 0x02,
    //NetworkStatus = 0x03,
    Leave = 0x04,
    RouteRecord = 0x05,
    //RejoinRequest = 0x06,
    //RejoinResponse = 0x07,
    LinkStatus = 0x08,
    //NetworkReport = 0x09
    //NetworkUpdate = 0x0a,
    EndDeviceTimeoutRequest = 0x0b,
    EndDeviceTimeoutResponse = 0x0c,
    //LinkPowerDelta = 0x0d,
    //NetworkCommissioningRequest = 0x0e,
    //NetworkCommissioningResponse = 0x0f,
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
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
        if bytes.len() < 1 {
            return Err("Not enough data for command ID");
        }
        if bytes[0] != NwkCommandId::RouteRequest as u8 {
            return Err("Invalid command ID for NwkRouteRequestCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        if payload.len() < 5 {
            return Err("Not enough data to parse NwkRouteRequestCommand payload");
        }

        let multicast = payload[0] & 0b01000000 != 0;
        let has_destination_eui64 = payload[0] & 0b00100000 != 0;

        if has_destination_eui64 && payload.len() < 5 + 8 {
            return Err("Not enough data to parse NwkRouteRequestCommand destination EUI64");
        }

        // This cannot fail, `NwkRouteRequestManyToOne` is a complete 2 bit enum
        let many_to_one =
            NwkRouteRequestManyToOne::try_from((payload[0] & 0b00011000) >> 3).unwrap();

        let route_request_identifier = payload[1];
        let destination_address = Nwk(u16::from_le_bytes([payload[2], payload[3]]));
        let path_cost = payload[4];

        let (destination_eui64, tlvs) = if has_destination_eui64 {
            let (eui64, remaining) = Eui64::deserialize(&payload[5..])?;
            (Some(eui64), remaining)
        } else {
            (None, &payload[5..])
        };

        Ok(Self {
            multicast,
            many_to_one,
            route_request_identifier,
            destination_address,
            path_cost,
            destination_eui64,
            tlvs: tlvs.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(NwkCommandId::RouteRequest as u8);

        let mut byte = 0u8;
        byte |= (self.multicast as u8) << 6;
        byte |= (self.destination_eui64.is_some() as u8) << 5;
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

#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteReplyCommand {
    pub multicast: bool,
    pub route_request_identifier: u8,
    pub originator_nwk: Nwk,
    pub responder_nwk: Nwk,
    pub path_cost: u8,
    pub originator_eui64: Option<Eui64>,
    pub responder_eui64: Option<Eui64>,
    pub tlvs: Vec<u8>,
}

impl NwkRouteReplyCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data for command ID");
        }
        if bytes[0] != NwkCommandId::RouteReply as u8 {
            return Err("Invalid command ID for NwkRouteReplyCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        if payload.len() < 7 {
            return Err("Not enough data to parse NwkRouteReplyCommand payload");
        }

        let multicast = payload[0] & 0b01000000 != 0;
        let has_originator_eui64 = payload[0] & 0b00010000 != 0;
        let has_responder_eui64 = payload[0] & 0b00100000 != 0;

        // Adjust length checks relative to payload length and base size (7)
        let mut required_len = 7;
        if has_originator_eui64 {
            required_len += 8;
        }
        if payload.len() < required_len {
            return Err("Not enough data to parse NwkRouteReplyCommand originator EUI64");
        }

        if has_responder_eui64 {
            required_len += 8;
        }
        if payload.len() < required_len {
            return Err("Not enough data to parse NwkRouteReplyCommand responder EUI64");
        }

        let route_request_identifier = payload[1];
        let originator_nwk = Nwk(u16::from_le_bytes([payload[2], payload[3]]));
        let responder_nwk = Nwk(u16::from_le_bytes([payload[4], payload[5]]));
        let path_cost = payload[6];

        let mut originator_eui64 = None;
        let mut responder_eui64 = None;
        let mut remaining = &payload[7..];

        if has_originator_eui64 {
            let eui64;
            (eui64, remaining) = Eui64::deserialize(remaining)?;
            originator_eui64 = Some(eui64);
        }

        if has_responder_eui64 {
            let eui64;
            (eui64, remaining) = Eui64::deserialize(remaining)?;
            responder_eui64 = Some(eui64);
        }

        Ok(Self {
            multicast,
            route_request_identifier,
            originator_nwk,
            responder_nwk,
            path_cost,
            originator_eui64,
            responder_eui64,
            tlvs: remaining.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(NwkCommandId::RouteReply as u8);

        let mut byte = 0u8;
        byte |= (self.multicast as u8) << 6;
        byte |= (self.originator_eui64.is_some() as u8) << 4;
        byte |= (self.responder_eui64.is_some() as u8) << 5;
        bytes.push(byte);

        bytes.push(self.route_request_identifier);
        bytes.extend_from_slice(&self.originator_nwk.to_bytes());
        bytes.extend_from_slice(&self.responder_nwk.to_bytes());
        bytes.push(self.path_cost);

        if let Some(originator_eui64) = self.originator_eui64 {
            bytes.extend_from_slice(&originator_eui64.to_bytes());
        }

        if let Some(responder_eui64) = self.responder_eui64 {
            bytes.extend_from_slice(&responder_eui64.to_bytes());
        }

        bytes.extend_from_slice(&self.tlvs);

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkRouteRecordCommand {
    pub relays: Vec<Nwk>,
}

impl NwkRouteRecordCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data for command ID");
        }
        if bytes[0] != NwkCommandId::RouteRecord as u8 {
            return Err("Invalid command ID for NwkRouteRecordCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        if payload.len() < 1 {
            return Err("Not enough data to parse NwkRouteRecordCommand payload");
        }

        let num_relays = payload[0] as usize;
        let mut relays = Vec::with_capacity(num_relays);

        if payload.len() < 1 + num_relays * 2 {
            return Err("Not enough data for NwkRouteRecordCommand relays");
        }

        let mut remaining = &payload[1..];

        for _ in 0..num_relays {
            let nwk;
            // Need to ensure Nwk::deserialize doesn't consume more than available
            if remaining.len() < 2 {
                return Err("Not enough data for Nwk address in NwkRouteRecordCommand");
            }
            (nwk, remaining) = Nwk::deserialize(remaining)?;
            relays.push(nwk);
        }

        Ok(Self { relays })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let num_relays = self.relays.len();
        // Capacity calculation includes command ID byte
        let mut bytes = Vec::with_capacity(1 + 1 + num_relays * 2);

        bytes.push(NwkCommandId::RouteRecord as u8);
        bytes.push(num_relays as u8);

        for relay in &self.relays {
            bytes.extend_from_slice(&relay.to_bytes());
        }

        bytes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatus {
    pub address: Nwk,
    pub incoming_cost: u8,
    pub outgoing_cost: u8,
}

impl NwkLinkStatus {
    // This struct is a sub-component, its serialization doesn't include the command ID
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 3 {
            return Err("Not enough data to parse NwkLinkStatus");
        }

        let address = Nwk(u16::from_le_bytes([bytes[0], bytes[1]]));
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
        result[0..2].copy_from_slice(&self.address.to_bytes());
        result[2] |= self.incoming_cost << 0;
        result[2] |= self.outgoing_cost << 4;

        result
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatusCommand {
    pub is_first_frame: bool,
    pub is_last_frame: bool,
    pub link_statuses: Vec<NwkLinkStatus>,
}

impl NwkLinkStatusCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 {
            return Err("Not enough data for command ID");
        }
        if bytes[0] != NwkCommandId::LinkStatus as u8 {
            return Err("Invalid command ID for NwkLinkStatusCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        if payload.len() < 1 {
            return Err("Not enough data to parse NwkLinkStatusCommand payload");
        }

        let is_first_frame = payload[0] & 0b01000000 != 0;
        let is_last_frame = payload[0] & 0b00100000 != 0;
        let count = (payload[0] & 0b00011111) as usize;

        if payload.len() < 1 + count * 3 {
            return Err("Not enough data to parse NwkLinkStatusCommand link statuses");
        }

        let mut link_statuses = Vec::with_capacity(count);
        let mut remaining = &payload[1..];

        for _ in 0..count {
            // Need to ensure NwkLinkStatus::from_bytes doesn't consume more than available
            if remaining.len() < 3 {
                return Err("Not enough data for NwkLinkStatus entry in NwkLinkStatusCommand");
            }
            let link_status = NwkLinkStatus::from_bytes(&remaining[..3])?; // Parse only 3 bytes
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

        // Capacity calculation includes command ID byte
        let mut result = Vec::with_capacity(1 + 1 + self.link_statuses.len() * 3);

        result.push(NwkCommandId::LinkStatus as u8);

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

#[derive(Debug, Clone, PartialEq)]
pub struct NwkLeaveCommand {
    pub rejoin: bool,
    pub request: bool,
    pub remove_children: bool,
}

impl NwkLeaveCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Requires 1 byte for ID + 1 byte for payload
        if bytes.len() < 2 {
            return Err("Not enough data to parse NwkLeaveCommand");
        }
        if bytes[0] != NwkCommandId::Leave as u8 {
            return Err("Invalid command ID for NwkLeaveCommand");
        }

        let payload_byte = bytes[1]; // Get the payload byte

        let rejoin = payload_byte & 0b00100000 != 0;
        let request = payload_byte & 0b01000000 != 0;
        let remove_children = payload_byte & 0b10000000 != 0;

        Ok(Self {
            rejoin,
            request,
            remove_children,
        })
    }

    // Returns command ID + payload byte
    pub fn serialize(&self) -> [u8; 2] {
        let mut payload_byte = 0x00;
        payload_byte |= (self.rejoin as u8) << 5;
        payload_byte |= (self.request as u8) << 6;
        payload_byte |= (self.remove_children as u8) << 7;

        [NwkCommandId::Leave as u8, payload_byte]
    }
}

#[derive(Debug, Eq, PartialEq, Clone, TryFromPrimitive, Copy)]
#[repr(u8)]
pub enum EndDeviceTimeout {
    Seconds10 = 0,
    Minutes2 = 1,
    Minutes4 = 2,
    Minutes8 = 3,
    Minutes16 = 4,
    Minutes32 = 5,
    Minutes64 = 6,
    Minutes128 = 7,
    Minutes256 = 8,
    Minutes512 = 9,
    Minutes1024 = 10,
    Minutes2048 = 11,
    Minutes4096 = 12,
    Minutes8192 = 13,
    Minutes16384 = 14,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkEndDeviceTimeoutRequestCommand {
    pub request_timeout_enum: EndDeviceTimeout,
    pub end_device_configuration: u8,
}

impl NwkEndDeviceTimeoutRequestCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Requires 1 byte for ID + 2 bytes for payload
        if bytes.len() < 3 {
            return Err("Not enough data to parse NwkEndDeviceTimeoutRequestCommand");
        }
        if bytes[0] != NwkCommandId::EndDeviceTimeoutRequest as u8 {
            return Err("Invalid command ID for NwkEndDeviceTimeoutRequestCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        let request_timeout_enum =
            EndDeviceTimeout::try_from(payload[0]).map_err(|_| "Invalid EndDeviceTimeout value")?;
        let end_device_configuration = payload[1];

        Ok(Self {
            request_timeout_enum,
            end_device_configuration,
        })
    }

    pub fn serialize(&self) -> [u8; 3] {
        let mut payload = [0x00; 2];
        payload[0] = self.request_timeout_enum as u8;
        payload[1] = self.end_device_configuration;

        [
            NwkCommandId::EndDeviceTimeoutRequest as u8,
            payload[0],
            payload[1],
        ]
    }
}

#[derive(Debug, Eq, PartialEq, Clone, TryFromPrimitive, Copy)]
#[repr(u8)]
pub enum NwkEndDeviceTimeoutResponseStatus {
    Success = 0x00,
    IncorrectValue = 0x01,
    UnsupportedFeature = 0x02,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwkEndDeviceTimeoutResponseCommand {
    pub status: NwkEndDeviceTimeoutResponseStatus,
    pub mac_data_poll_keepalive_supported: bool,
    pub end_device_timeout_request_keepalive_supported: bool,
    pub power_negotation_support: bool,
}

impl NwkEndDeviceTimeoutResponseCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Requires 1 byte for ID + 2 bytes for payload
        if bytes.len() < 3 {
            return Err("Not enough data to parse NwkEndDeviceTimeoutResponseCommand");
        }
        if bytes[0] != NwkCommandId::EndDeviceTimeoutResponse as u8 {
            return Err("Invalid command ID for NwkEndDeviceTimeoutResponseCommand");
        }

        let payload = &bytes[1..]; // Skip command ID byte

        let status = NwkEndDeviceTimeoutResponseStatus::try_from(payload[0])
            .map_err(|_| "Invalid NwkEndDeviceTimeoutResponseStatus value")?;
        let mac_data_poll_keepalive_supported = payload[1] & 0b00000001 != 0;
        let end_device_timeout_request_keepalive_supported = payload[1] & 0b00000010 != 0;
        let power_negotation_support = payload[1] & 0b00000100 != 0;

        Ok(Self {
            status,
            mac_data_poll_keepalive_supported,
            end_device_timeout_request_keepalive_supported,
            power_negotation_support,
        })
    }

    pub fn serialize(&self) -> [u8; 3] {
        let mut payload = [0x00; 2];
        payload[0] = self.status as u8;
        payload[1] |= (self.mac_data_poll_keepalive_supported as u8) << 0;
        payload[1] |= (self.end_device_timeout_request_keepalive_supported as u8) << 1;
        payload[1] |= (self.power_negotation_support as u8) << 2;

        [
            NwkCommandId::EndDeviceTimeoutResponse as u8,
            payload[0],
            payload[1],
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_nwk_route_request_command() {
        let bytes = hex!("0100dea30501");
        let command = NwkRouteRequestCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkRouteRequestCommand {
                multicast: false,
                many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
                route_request_identifier: 222,
                destination_address: Nwk(0x05A3),
                path_cost: 1,
                destination_eui64: None,
                tlvs: vec![],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_route_reply_command() {
        let bytes = hex!("02305f375f0a93037138210501881700aed31f0b01881700");
        let command = NwkRouteReplyCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkRouteReplyCommand {
                multicast: false,
                route_request_identifier: 95,
                originator_nwk: Nwk(0x5F37),
                responder_nwk: Nwk(0x930A),
                path_cost: 3,
                originator_eui64: Some(Eui64::from_hex("00:17:88:01:05:21:38:71")),
                responder_eui64: Some(Eui64::from_hex("00:17:88:01:0b:1f:d3:ae")),
                tlvs: vec![],
            }
        );

        assert_eq!(command.serialize(), bytes.to_vec());
    }

    #[test]
    fn test_nwk_route_record_command_empty() {
        let bytes = hex!("0500");
        let command = NwkRouteRecordCommand::from_bytes(&bytes).unwrap();

        assert_eq!(command, NwkRouteRecordCommand { relays: vec![] });

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_route_record_command() {
        let bytes = hex!("0501eb1c");
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
        let bytes = hex!("0862e73c120ac711");
        let command = NwkLinkStatusCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkLinkStatusCommand {
                is_first_frame: true, // byte 0x62 -> 0b01100010
                is_last_frame: true,
                link_statuses: vec![
                    NwkLinkStatus {
                        address: Nwk(0x3CE7), // e7 3c
                        incoming_cost: 2,     // 12 -> 0b00010010 (inc=2, out=1)
                        outgoing_cost: 1,
                    },
                    NwkLinkStatus {
                        address: Nwk(0xC70A), // 0a c7
                        incoming_cost: 1,     // 11 -> 0b00010001 (inc=1, out=1)
                        outgoing_cost: 1,
                    },
                ],
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_leave_command() {
        let bytes = hex!("0400");
        let command = NwkLeaveCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkLeaveCommand {
                rejoin: false,
                request: false,
                remove_children: false,
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_end_device_timeout_request_command() {
        let bytes = hex!("0b0300");
        let command = NwkEndDeviceTimeoutRequestCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkEndDeviceTimeoutRequestCommand {
                request_timeout_enum: EndDeviceTimeout::Minutes8,
                end_device_configuration: 0,
            }
        );

        assert_eq!(command.serialize(), bytes);
    }

    #[test]
    fn test_nwk_end_device_timeout_response_command() {
        let bytes = hex!("0c0003");
        let command = NwkEndDeviceTimeoutResponseCommand::from_bytes(&bytes).unwrap();

        assert_eq!(
            command,
            NwkEndDeviceTimeoutResponseCommand {
                status: NwkEndDeviceTimeoutResponseStatus::Success,
                mac_data_poll_keepalive_supported: true,
                end_device_timeout_request_keepalive_supported: true,
                power_negotation_support: false,
            }
        );

        assert_eq!(command.serialize(), bytes);
    }
}
