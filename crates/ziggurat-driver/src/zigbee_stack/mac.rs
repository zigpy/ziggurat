use core::time::Duration;

use crate::runtime::Runtime;
use crate::ziggurat_ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154CommandFrame, Ieee802154DataFrame,
    Ieee802154Frame, Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType,
};
use abstract_bits::AbstractBits;
use alloc::vec::Vec;
use arbitrary_int::u24;
use ziggurat_ieee_802154::types::{Nwk, PanId};
use ziggurat_phy::{RadioPhy, TxFrame, TxResult};
use ziggurat_zigbee::beacon::{RenamedU24, ZigbeeBeacon};
use ziggurat_zigbee::nwk::frame::{
    BROADCAST_ALL_ROUTERS_AND_COORDINATOR, EncryptedNwkFrame, NwkFrame, NwkPayload,
    NwkSecurityHeaderKeyId, NwkSecurityLevel,
};

use super::{
    NwkDeviceType, PROTOCOL_VERSION, STACK_PROFILE, SendKind, TxOutcome, TxPriority, ZigbeeStack,
    ZigbeeStackError,
};

/// Spacing between sprayed beacons while a [`hack_beacon_spam_duration`] window is open.
///
/// [`hack_beacon_spam_duration`]: super::State::hack_beacon_spam_duration
const BEACON_SPAM_INTERVAL: Duration = Duration::from_millis(5);

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    pub fn process_802154_command_frame(&self, command_frame: &Ieee802154CommandFrame) {
        tracing::debug!(
            "Received 802.15.4 command frame: {:?}",
            command_frame.command_payload.command_id()
        );

        match &command_frame.command_payload {
            ziggurat_ieee_802154::Ieee802154CommandPayload::BeaconRequest(_) => {
                let spam = self.state.hack_beacon_spam_duration;
                if spam.is_zero() || !self.permitting_joins() {
                    self.send_802154_beacon();
                } else {
                    // Open/extend the spray window and let the beacon-spam reactor drive
                    // the cadence, so a storm of requests can't exceed one beacon per
                    // BEACON_SPAM_INTERVAL.
                    self.core().beacon_spam_until = Some(self.core_now() + spam);
                    self.beacon_spam_wake.notify_one();
                }
            }
            ziggurat_ieee_802154::Ieee802154CommandPayload::AssociationRequest(
                ieee802154_association_request_command,
            ) => {
                if self.state.role == NwkDeviceType::Coordinator {
                    self.process_802154_association_request(
                        command_frame,
                        ieee802154_association_request_command,
                    );
                } else {
                    tracing::debug!("Ignoring association request: not the coordinator");
                }
            }
            ziggurat_ieee_802154::Ieee802154CommandPayload::DataRequest(_) => {
                self.handle_data_request(command_frame);
            }
            _ => {
                // Unsupported command frame
            }
        }
    }

    pub fn send_802154_beacon(&self) {
        let permitting_joins = self.permitting_joins();
        tracing::trace!("Sending 802.15.4 beacon frame (permitting joins: {permitting_joins})");

        let end_device_capacity =
            { self.core().nib.neighbors.child_count() } < usize::from(self.tunables.max_children);

        let (ieee802154_sequence_number, pan_id, update_id) = {
            let core = self.core();
            (
                core.mac.ieee802154_sequence_number,
                core.mac.pan_id,
                core.nib.update_id,
            )
        };

        let beacon_frame = Ieee802154Frame::Beacon(ziggurat_ieee_802154::Ieee802154BeaconFrame {
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
                sequence_number: Some(ieee802154_sequence_number),
                src_address: Some(Ieee802154Address::Nwk(self.state.network_address)),
                dest_address: None,
                src_pan_id: Some(pan_id),
                dest_pan_id: None,
            },
            superframe_specification: ziggurat_ieee_802154::SuperframeSpecification {
                beacon_interval: 15,
                superframe_interval: 15,
                final_cap_slot: 15,
                battery_extension: false,
                reserved1: 0,
                pan_coordinator: self.state.role == NwkDeviceType::Coordinator,
                association_permit: permitting_joins,
            },
            beacon_payload: ZigbeeBeacon {
                protocol_id: 0,
                stack_profile: STACK_PROFILE,
                protocol_version: PROTOCOL_VERSION,
                reserved1: 0b00,
                router_capacity: true,
                device_depth: 0,
                end_device_capacity,
                extended_pan_id: self.state.extended_pan_id,
                tx_offset: RenamedU24(u24::new(0xFFFFFF)),
                update_id,
            }
            .to_abstract_bytes()
            .unwrap(),
            gts_specification: 0x00,
            pending_address_specification: 0x00,
            fcs: 0x0000,
        });

        let tx_priority = if permitting_joins {
            // We should try to win any beacon races during joins
            TxPriority::STACK_CRITICAL
        } else {
            // Otherwise, unexpected beacon requests should never compete with normal traffic
            TxPriority::BACKGROUND
        };

        self.enqueue_send(
            SendKind::Raw {
                frame: beacon_frame,
            },
            tx_priority,
            TxOutcome::Discard,
        );
    }

    /// The beacon-spam reactor (the [`hack_beacon_spam_duration`] hack): while a spray
    /// window is open and joins are still permitting, send a beacon every
    /// [`BEACON_SPAM_INTERVAL`], then idle on its wake. A beacon request opens or
    /// extends the window; the fixed sleep (rather than racing the wake) is what caps
    /// the rate at one beacon per interval no matter how many requests arrive.
    ///
    /// [`hack_beacon_spam_duration`]: super::State::hack_beacon_spam_duration
    pub(super) async fn beacon_spam_task(&self) {
        loop {
            let until = self.core().beacon_spam_until;
            if until.is_some_and(|deadline| deadline > self.core_now()) {
                if self.permitting_joins() {
                    self.send_802154_beacon();
                }
                R::sleep(BEACON_SPAM_INTERVAL).await;
            } else {
                self.beacon_spam_wake.notified().await;
            }
        }
    }

    pub(super) fn beacon_request_psdu(&self) -> Vec<u8> {
        let sequence_number = {
            let mut core = self.core();
            core.mac.ieee802154_sequence_number =
                core.mac.ieee802154_sequence_number.wrapping_add(1);
            core.mac.ieee802154_sequence_number
        };

        let frame: Ieee802154Frame = Ieee802154Frame::Command(Ieee802154CommandFrame {
            header: Ieee802154FrameHeader {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: false,
                    reserved1: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::None,
                },
                sequence_number: Some(sequence_number),
                dest_pan_id: Some(PanId(0xFFFF)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xFFFF))),
                src_pan_id: None,
                src_address: None,
            },
            command_payload: ziggurat_ieee_802154::Ieee802154CommandPayload::BeaconRequest(
                ziggurat_ieee_802154::commands::Ieee802154BeaconRequestCommand,
            ),
            fcs: 0x0000,
        });

        frame.to_bytes()
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
            tracing::debug!("Ignoring frame, 802.15.4 security bit is enabled");
            return None;
        }

        // Only process packets destined for our PAN ID
        let pan_id = self.core().mac.pan_id;

        match data_frame.header.dest_pan_id {
            None => {
                tracing::debug!("Ignoring frame, destination PAN ID is not present");
                return None;
            }
            Some(dest_pan_id) if dest_pan_id != pan_id => {
                tracing::debug!(
                    "Ignoring frame, PAN ID does not match {dest_pan_id:?} != {pan_id:?}"
                );
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
                    tracing::debug!("Ignoring frame, not addressed to us at the MAC layer");
                    return None;
                }
            }
        }

        // Next, try to parse the NWK frame
        let nwk_frame = match EncryptedNwkFrame::from_bytes(&data_frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                tracing::debug!("Ignoring frame, not a NWK frame");
                return None;
            }
        };

        // Spec 2.2.5/3.x: reserved frame-control bits SHALL be zero on reception; a
        // nonzero value marks a malformed frame, which is discarded.
        if nwk_frame.nwk_header.frame_control.reserved1 != 0 {
            tracing::warn!("Ignoring NWK frame with reserved frame-control bits set");
            return None;
        }

        // Unicast frames addressed to other devices are relayed after decryption
        let is_transit = nwk_frame.nwk_header.destination != self.state.network_address
            && nwk_frame.nwk_header.destination.as_u16()
                < BROADCAST_ALL_ROUTERS_AND_COORDINATOR.as_u16();

        // The only unencrypted NWK frames we accept are trust center rejoin requests
        if !nwk_frame.nwk_header.frame_control.security {
            let payload = NwkPayload::from_bytes(
                nwk_frame.nwk_header.frame_control.frame_type,
                nwk_frame.ciphertext,
            );
            self.handle_unsecured_nwk_frame(&NwkFrame {
                nwk_header: nwk_frame.nwk_header,
                aux_header: None,
                payload,
            });
            return None;
        }

        let aux_header = match nwk_frame.aux_header {
            None => {
                tracing::debug!("Ignoring frame, auxiliary header is missing");
                return None;
            }
            Some(ref header) => header,
        };

        // The frame security level is fixed for a given network and transmitted frames will use "0"
        if aux_header.security_control.security_level != NwkSecurityLevel::NoSecurity {
            tracing::debug!("Ignoring frame, security level is not 0");
            return None;
        }

        // Only the network key is supported for now
        if aux_header.security_control.key_id != NwkSecurityHeaderKeyId::NetworkKey {
            tracing::debug!("Ignoring frame, key ID is not NetworkKey");
            return None;
        }

        let src_eui64 = match aux_header.extended_source {
            None => {
                tracing::debug!("Ignoring frame, extended source is missing");
                return None;
            }
            Some(eui64) => eui64,
        };

        // Validate the key sequence number and the relayer's frame counter, and
        // fetch the decryption key
        let key = self.core().nib.nwk_security.inbound_network_key(
            src_eui64,
            aux_header.key_sequence_number,
            aux_header.frame_counter,
        )?;

        let decrypted_nwk_frame = match nwk_frame.decrypt(&key) {
            Ok(decrypted_frame) => decrypted_frame,
            Err(err) => {
                tracing::warn!("Ignoring frame from {src_eui64:?}: decryption failed: {err:?}");
                return None;
            }
        };

        tracing::debug!("Decrypted frame: {decrypted_nwk_frame:?}");

        // NWK frames are always relayed with 16-bit MAC addressing; anything else is
        // malformed and dropped rather than panicking on remote input
        let source_nwk = match data_frame.header.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => nwk,
            _ => {
                tracing::warn!(
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

    pub(super) async fn send_802154_frame<Payload: ziggurat_ieee_802154::FramePayload>(
        &self,
        frame: Ieee802154Frame<Payload>,
    ) -> Result<(), ZigbeeStackError> {
        // Increment the 802.15.4 sequence number
        let final_frame = if !frame.header().frame_control.sequence_number_suppression {
            // Hold the lock for the shortest time possible
            let ieee802154_sequence_number = {
                let mut core = self.core();
                core.mac.ieee802154_sequence_number =
                    core.mac.ieee802154_sequence_number.wrapping_add(1);

                core.mac.ieee802154_sequence_number
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

        tracing::trace!("Sending 802.15.4 frame: {final_frame:?}");
        tracing::trace!(
            "Sending 802.15.4 frame bytes: {:02X?}",
            final_frame.to_bytes()
        );

        if self.state.hack_disable_tx {
            tracing::debug!("Not transmitting the frame, TX is disabled");
            return Ok(());
        }

        let channel = self.core().mac.channel;
        let result = self
            .radio
            .transmit(TxFrame {
                psdu: final_frame.to_bytes(),
                channel: Some(channel),
                csma_ca: true,
                max_frame_retries: self.tunables.mac_max_frame_retries,
                max_csma_backoffs: self.tunables.mac_max_csma_backoffs,
                security_processed: true,
            })
            .await?;

        match result {
            TxResult::Acked => Ok(()),
            // A frame with no destination (e.g. a beacon) never requested an ACK, so
            // "no ACK" is the expected outcome, not a failure.
            TxResult::NoAck => final_frame
                .header()
                .dest_address
                .map_or(Ok(()), |next_hop| {
                    Err(ZigbeeStackError::NwkNoAck { next_hop })
                }),
            TxResult::ChannelAccessFailure => Err(ZigbeeStackError::CcaFailure),
            other => Err(ZigbeeStackError::TransmitFailed(other)),
        }
    }
}
