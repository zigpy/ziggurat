use std::convert::TryFrom;
use super::*;

impl NwkRouteRequestCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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

        let (destination_eui64, _) = if has_destination_eui64 {
            let (eui64, remaining) = Eui64::deserialize(&payload[5..])?;
            (Some(eui64), remaining)
        } else {
            (None, &payload[5..])
        };

        Ok(Self {
            many_to_one,
            route_request_identifier,
            destination_address,
            path_cost,
            destination_eui64,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let mut bytes = Vec::new();
        bytes.push(NwkCommandId::RouteRequest as u8);

        let mut byte = 0u8;
        byte |= (0u8) << 6;
        byte |= (self.destination_eui64.is_some() as u8) << 5;
        byte |= (self.many_to_one as u8) << 3;
        bytes.push(byte);

        bytes.push(self.route_request_identifier);
        bytes.extend_from_slice(&self.destination_address.to_bytes());
        bytes.push(self.path_cost);

        if let Some(destination_eui64) = self.destination_eui64 {
            bytes.extend_from_slice(&destination_eui64.to_bytes());
        }

        Ok(bytes)
    }
}

impl NwkRouteReplyCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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
            (eui64, _) = Eui64::deserialize(remaining)?;
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
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
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

        Ok(bytes)
    }
}

impl NwkRouteRecordCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let num_relays = self.relays.len();
        // Capacity calculation includes command ID byte
        let mut bytes = Vec::with_capacity(1 + 1 + num_relays * 2);

        bytes.push(NwkCommandId::RouteRecord as u8);
        bytes.push(num_relays as u8);

        for relay in &self.relays {
            bytes.extend_from_slice(&relay.to_bytes());
        }

        Ok(bytes)
    }
}

impl NwkLinkStatusCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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
            // Need to ensure NwkLinkStatus::deserialize doesn't consume more than available
            if remaining.len() < 3 {
                return Err("Not enough data for NwkLinkStatus entry in NwkLinkStatusCommand");
            }
            let link_status = NwkLinkStatus::deserialize(&remaining[..3])?; // Parse only 3 bytes
            link_statuses.push(link_status);
            remaining = &remaining[3..];
        }

        Ok(Self {
            is_first_frame,
            is_last_frame,
            link_statuses,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
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
            result.extend_from_slice(&link_status.serialize().unwrap());
        }

        Ok(result)
    }
}

impl NwkLinkStatus {
    // This struct is a sub-component, its serialization doesn't include the command ID
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let mut result = [0x00; 3];
        result[0..2].copy_from_slice(&self.address.to_bytes());
        result[2] |= self.incoming_cost << 0;
        result[2] |= self.outgoing_cost << 4;

        Ok(result.to_vec())
    }
}

impl NwkLeaveCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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
    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let mut payload_byte = 0x00;
        payload_byte |= (self.rejoin as u8) << 5;
        payload_byte |= (self.request as u8) << 6;
        payload_byte |= (self.remove_children as u8) << 7;

        Ok([NwkCommandId::Leave as u8, payload_byte].to_vec())
    }
}

impl NwkEndDeviceTimeoutRequestCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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

        Ok(Self {
            request_timeout_enum,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let mut payload = [0x00; 2];
        payload[0] = self.request_timeout_enum as u8;

        Ok([
            NwkCommandId::EndDeviceTimeoutRequest as u8,
            payload[0],
            payload[1],
        ].to_vec())
    }
}

impl NwkEndDeviceTimeoutResponseCommand {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
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

    pub fn serialize(&self) -> Result<Vec<u8>, DeserializeError> {
        let mut payload = [0x00; 2];
        payload[0] = self.status as u8;
        payload[1] |= (self.mac_data_poll_keepalive_supported as u8) << 0;
        payload[1] |= (self.end_device_timeout_request_keepalive_supported as u8) << 1;
        payload[1] |= (self.power_negotation_support as u8) << 2;

        Ok([
            NwkCommandId::EndDeviceTimeoutResponse as u8,
            payload[0],
            payload[1],
        ].to_vec())
    }
}
