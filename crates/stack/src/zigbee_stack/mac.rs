use crate::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154CommandFrame, Ieee802154DataFrame,
    Ieee802154Frame, Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use crate::spinel::SpinelStatus;
use crate::spinel_client::SpinelTxFrame;
use crate::types::{RenamedU24, ZigbeeBeacon};
use crate::zigbee_nwk::{
    BROADCAST_ALL_ROUTERS_AND_COORDINATOR, EncryptedNwkFrame, NwkFrame, NwkSecurityHeaderKeyId,
    NwkSecurityLevel,
};
use abstract_bits::AbstractBits;
use arbitrary_int::u24;
use ieee_802154::types::Nwk;

use super::{MAX_LOCK_DURATION, ZigbeeStack, ZigbeeStackError};

impl ZigbeeStack {
    pub fn process_802154_command_frame(&self, command_frame: &Ieee802154CommandFrame) {
        log::debug!(
            "Received 802.15.4 command frame: {:?}",
            command_frame.command_id
        );

        match &command_frame.command_payload {
            ieee_802154::Ieee802154CommandPayload::BeaconRequest(
                _ieee802154_beacon_request_command,
            ) => {
                self.send_802154_beacon();
            }
            ieee_802154::Ieee802154CommandPayload::AssociationRequest(
                ieee802154_association_request_command,
            ) => {
                self.process_802154_association_request(
                    command_frame,
                    ieee802154_association_request_command,
                );
            }
            ieee_802154::Ieee802154CommandPayload::DataRequest(_) => {
                self.handle_data_request(command_frame);
            }
            _ => {
                // Unsupported command frame
            }
        }
    }

    pub fn send_802154_beacon(&self) {
        let permitting_joins = {
            *self
                .state
                .permitting_joins
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
        };
        log::debug!("Sending 802.15.4 beacon frame");
        log::debug!("Permitting joins: {permitting_joins}");

        let end_device_capacity = {
            self.state
                .neighbors
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .child_count()
        } < usize::from(self.constants.max_children);

        let beacon_frame = Ieee802154Frame::Beacon(ieee_802154::Ieee802154BeaconFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Beacon,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: false,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::None,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::Short,
                },
                sequence_number: Some(
                    *self
                        .state
                        .ieee802154_sequence_number
                        .try_lock_for(MAX_LOCK_DURATION)
                        .unwrap(),
                ),
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
                dest_address: None,
                src_pan_id: Some(*self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap()),
                dest_pan_id: None,
            },
            superframe_specification: ieee_802154::SuperframeSpecification {
                beacon_interval: 15,
                superframe_interval: 15,
                final_cap_slot: 15,
                battery_extension: false,
                reserved1: 0,
                pan_coordinator: self.state.network_address == Nwk(0x0000),
                association_permit: permitting_joins,
            },
            beacon_payload: ZigbeeBeacon {
                protocol_id: 0,
                stack_profile: 0x02,
                protocol_version: 2,
                reserved1: 0b00,
                router_capacity: true,
                device_depth: 0,
                end_device_capacity,
                extended_pan_id: self.state.extended_pan_id,
                tx_offset: RenamedU24(u24::new(0xFFFFFF)),
                update_id: *self
                    .state
                    .update_id
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap(),
            }
            .to_abstract_bits()
            .unwrap(),
            gts_specification: 0x00,
            pending_address_specification: 0x00,
            fcs: 0x0000,
        });

        self.background_send_802154_frame(beacon_frame);
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn process_802154_data_frame(
        &self,
        data_frame: &Ieee802154DataFrame,
        lqi: u8,
        rssi: i8,
    ) -> Option<NwkFrame> {
        // 802.15.4 encrypted frames can't be Zigbee NWK
        if data_frame.header.frame_control.security_enabled {
            log::debug!("Ignoring frame, 802.15.4 security bit is enabled");
            return None;
        }

        // Only process packets destined for our PAN ID
        let pan_id = *self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap();

        match data_frame.header.dest_pan_id {
            None => {
                log::debug!("Ignoring frame, destination PAN ID is not present");
                return None;
            }
            Some(dest_pan_id) if dest_pan_id != pan_id => {
                log::debug!("Ignoring frame, PAN ID does not match {dest_pan_id:?} != {pan_id:?}");
                return None;
            }
            Some(_) => (),
        }

        // Promiscuous mode delivers every frame in the PAN; only frames actually
        // addressed to us are processed further, unless we are a passive observer
        if !self.state.hack_disable_tx {
            match data_frame.header.dest_address {
                Some(Ieee802154Address::Nwk(nwk))
                    if nwk == self.state.network_address || nwk == Nwk(0xFFFF) => {}
                Some(Ieee802154Address::Eui64(eui64)) if eui64 == self.state.ieee_address => {}
                _ => {
                    log::debug!("Ignoring frame, not addressed to us at the MAC layer");
                    return None;
                }
            }
        }

        // Next, try to parse the NWK frame
        let nwk_frame = match EncryptedNwkFrame::from_bytes(&data_frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                log::debug!("Ignoring frame, not a NWK frame");
                return None;
            }
        };

        // Unicast frames addressed to other devices are relayed after decryption
        let is_transit = nwk_frame.nwk_header.destination != self.state.network_address
            && nwk_frame.nwk_header.destination.as_u16()
                < BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16();

        // The only unencrypted NWK frames we accept are trust center rejoin requests
        if !nwk_frame.nwk_header.frame_control.security {
            self.handle_unsecured_nwk_frame(&NwkFrame {
                nwk_header: nwk_frame.nwk_header,
                aux_header: None,
                payload: nwk_frame.ciphertext,
            });
            return None;
        }

        let aux_header = match nwk_frame.aux_header {
            None => {
                log::debug!("Ignoring frame, auxiliary header is missing");
                return None;
            }
            Some(ref header) => header,
        };

        // The frame security level is fixed for a given network and transmitted frames will use "0"
        if aux_header.security_control.security_level != NwkSecurityLevel::NoSecurity {
            log::debug!("Ignoring frame, security level is not 0");
            return None;
        }

        // Only the network key is supported for now
        if aux_header.security_control.key_id != NwkSecurityHeaderKeyId::NetworkKey {
            log::debug!("Ignoring frame, key ID is not NetworkKey");
            return None;
        }

        // Validate the network key sequence number
        if aux_header.key_sequence_number != self.state.active_key_seq_number {
            log::debug!("Ignoring frame, key sequence number is unknown");
            return None;
        }

        // Validate the security header frame counter for the relaying EUI64
        let src_eui64 = match aux_header.extended_source {
            None => {
                log::debug!("Ignoring frame, extended source is missing");
                return None;
            }
            Some(eui64) => eui64,
        };

        match self
            .state
            .security_material_primary
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .incoming_frame_counter_set
            .get(&src_eui64)
        {
            None => {
                log::warn!("Unknown sender, not validating frame counter");
            }
            Some(last_stored_frame_counter) => {
                if aux_header.frame_counter <= *last_stored_frame_counter {
                    log::debug!(
                        "Ignoring frame, frame counter has rolled backward from {last_stored_frame_counter} to {}",
                        aux_header.frame_counter
                    );
                    return None;
                }
            }
        };

        log::debug!(
            "Attempting to decrypt {:?} with {:?}",
            nwk_frame,
            self.state.security_material_primary
        );

        let decrypted_nwk_frame = {
            // Finally, attempt decryption
            let key = &self
                .state
                .security_material_primary
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .key;

            match nwk_frame.decrypt(key) {
                Ok(decrypted_frame) => decrypted_frame,
                Err(err) => {
                    log::warn!("Ignoring frame, decryption failed: {err:?}");
                    return None;
                }
            }
        };

        log::info!("Decrypted frame: {decrypted_nwk_frame:#?}");

        // NWK frames are always relayed with 16-bit MAC addressing; anything else is
        // malformed and dropped rather than panicking on remote input
        let source_nwk = match data_frame.header.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => nwk,
            _ => {
                log::warn!(
                    "Ignoring NWK frame without a 16-bit MAC source address: {:?}",
                    data_frame.header.src_address
                );
                return None;
            }
        };

        if is_transit {
            self.relay_unicast_nwk_frame(decrypted_nwk_frame, source_nwk, lqi, rssi);
            return None;
        }

        self.handle_decrypted_frame(&decrypted_nwk_frame, source_nwk, lqi, rssi);

        Some(decrypted_nwk_frame)
    }

    pub(super) async fn send_802154_frame(
        &self,
        frame: Ieee802154Frame,
    ) -> Result<(), ZigbeeStackError> {
        // Increment the 802.15.4 sequence number
        let final_frame = if !frame.header().frame_control.sequence_number_suppression {
            // Hold the lock for the shortest time possible
            let ieee802154_sequence_number = {
                let mut ieee802154_sequence_number = self
                    .state
                    .ieee802154_sequence_number
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap();
                *ieee802154_sequence_number = ieee802154_sequence_number.wrapping_add(1);
                *ieee802154_sequence_number
            };

            match frame {
                Ieee802154Frame::Data(mut data_frame) => {
                    data_frame.header.sequence_number = Some(ieee802154_sequence_number);
                    Ieee802154Frame::Data(data_frame)
                }
                Ieee802154Frame::Beacon(mut beacon_frame) => {
                    beacon_frame.header.sequence_number = Some(ieee802154_sequence_number);
                    Ieee802154Frame::Beacon(beacon_frame)
                }
                Ieee802154Frame::Ack(mut ack_frame) => {
                    ack_frame.header.sequence_number = Some(ieee802154_sequence_number);
                    Ieee802154Frame::Ack(ack_frame)
                }
                Ieee802154Frame::Command(mut command_frame) => {
                    command_frame.header.sequence_number = Some(ieee802154_sequence_number);
                    Ieee802154Frame::Command(command_frame)
                }
            }
        } else {
            frame
        };

        log::info!("Sending 802.15.4 frame: {final_frame:#?}");
        log::info!(
            "Sending 802.15.4 frame bytes: {:02X?}",
            final_frame.to_bytes()
        );

        if self.state.hack_disable_tx {
            log::debug!("Not transmitting the frame, TX is disabled");
            return Ok(());
        }

        let status = self
            .spinel
            .transmit_frame(&SpinelTxFrame {
                psdu: final_frame.to_bytes(),
                channel: { Some(*self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap()) },
                max_csma_backoffs: Some(1),
                max_frame_retries: Some(5),
                enable_csma_ca: Some(true),
                is_header_updated: Some(true),
                is_a_retransmit: Some(false),
                is_security_processed: Some(true),
                // Omit subsequent fields to reduce serial traffic
                tx_delay: None,            // Some(0 as u32),
                tx_delay_base_time: None,  // Some(0 as u32),
                rx_channel_after_tx: None, // Some(channel),
                tx_power: None,            // Some(8),
            })
            .await?;

        if status == SpinelStatus::Ok {
            Ok(())
        } else if status == SpinelStatus::NoAck {
            Err(ZigbeeStackError::NwkNoAck {
                next_hop: final_frame.header().dest_address.unwrap(),
            })
        } else if status == SpinelStatus::CcaFailure {
            Err(ZigbeeStackError::CcaFailure)
        } else {
            Err(ZigbeeStackError::SpinelTransmitFailure(status))
        }
    }

    pub fn background_send_802154_frame(&self, frame: Ieee802154Frame) {
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self
                .send_802154_frame(frame)
                .await
                .unwrap_or_else(|err| {
                    log::error!("Failed to send 802.15.4 frame: {err}");
                });
        });
    }
}
