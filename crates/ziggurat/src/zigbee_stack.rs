use crate::ieee_802154::{Ieee802154Address, Ieee802154Frame};

use ieee_802154::types::{Eui64, Key, Nwk, PanId};
use spinel::client::{SpinelClient, SpinelError, SpinelRxFrame};
use spinel::{
    SpinelFramePropValueIs, SpinelMacPromiscuousMode, SpinelMacScanState, SpinelPropertyId,
    SpinelStatus,
};
use tokio::time::{sleep, timeout};
use zigbee::aps::frame::{ApsAckFrame, ApsFrame, parse_aps_frame};
use zigbee::nwk::frame::NwkFrameType;

use thiserror::Error;
use tokio::time::error::Elapsed;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex as AsyncMutex, Notify, broadcast, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};

mod aps;
mod indirect;
mod joining;
mod mac;
mod neighbor;
mod nwk;
mod route;
mod zdp;

pub use zigbee::aps::security as aps_security;
pub use zigbee::aps::security::{ApsSecurity, TclkSeed};
pub use zigbee::constants::Constants;
pub use zigbee::indirect::{IndirectQueue, SrcMatchTable};
pub use zigbee::nwk::NwkDeviceType;
pub use zigbee::nwk::addresses::AddressMap;
pub use zigbee::nwk::broadcasts::Broadcasts;
pub use zigbee::nwk::neighbors::Neighbors;
pub use zigbee::nwk::routing::Routing;
pub use zigbee::nwk::security::NwkSecurity;
pub use zigbee::nwk::{neighbors, routing};

// TODO: remove this once all long locks have been found
const MAX_LOCK_DURATION: Duration = Duration::from_millis(10);
const APS_ACK_TIMEOUT: Duration = Duration::from_millis(5000);

/// APS acks from a sleepy child arrive only after it polls for the frame, so the
/// wait must cover a full indirect transaction lifetime (7.68s) plus the ack's trip
/// back.
const APS_ACK_TIMEOUT_INDIRECT: Duration = Duration::from_millis(10000);

/// How long the RCP gets to announce itself after a `CMD_RESET` before we resend.
const RESET_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);
const RESET_ATTEMPTS: u32 = 5;
const RADIO_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How long after the scan period elapses the RCP gets to deliver a scan result.
const ENERGY_SCAN_RESULT_TIMEOUT: Duration = Duration::from_secs(2);

/// How often (in frames) the client is notified of the outgoing NWK security frame
/// counter, so that its persisted copy never lags far behind.
const FRAME_COUNTER_NOTIFY_INTERVAL: u32 = 100;

#[derive(Error, Debug)]
pub enum ZigbeeStackError {
    #[error("route discovery timed out")]
    RouteDiscoveryTimeout(#[from] Elapsed),
    #[error("route discovery unexpectedly failed: {0}")]
    RouteDiscoveryFailure(String),
    #[error("next hop {next_hop:?} did not ACK")]
    NwkNoAck { next_hop: Ieee802154Address },
    #[error("transmit rejected due to CCA failure")]
    CcaFailure,
    #[error("unexpected transmit failure: {0:?}")]
    SpinelTransmitFailure(SpinelStatus),
    #[error("aps ack timeout")]
    ApsAckTimeout,
    #[error("payload does not fit in a single frame")]
    PayloadTooLong,
    #[error("aps security material unavailable or unusable")]
    ApsSecurityFailed,
    #[error("indirect transaction expired before {destination:?} polled")]
    IndirectExpired { destination: Ieee802154Address },
    #[error("spinel error: {0}")]
    SpinelError(#[from] SpinelError),
}

/// How an outgoing NWK frame is secured. Frames carrying the network key to a joining
/// device are sent without NWK security; the APS payload is encrypted instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NwkSecurityMode {
    NetworkKey,
    Unsecured,
}

#[derive(Debug)]
pub enum NwkCapabilityInformationDeviceType {
    EndDevice = 0,
    Router = 1,
}

#[derive(Debug)]
pub enum NwkCapabilityInformationPowerSource {
    MainsPower = 0,
    Battery = 1,
}

#[derive(Debug)]
pub enum NwkSecurityCapability {
    NotCapable = 0,
    Capable = 1,
}

/// `nwkParentInformation` (spec Table 3-62): the keepalive methods and features we
/// advertise to end device children. The spec allows advertising only a single
/// keepalive method (3.6.10.2).
#[derive(Debug, Clone, Copy)]
pub struct ParentInformation {
    pub mac_data_poll_keepalive: bool,
    pub end_device_timeout_request_keepalive: bool,
    pub power_negotiation: bool,
}

#[derive(Debug)]
pub struct NwkCapabilityInformation {
    pub alternate_pan_coordinator: bool,
    pub device_type: NwkCapabilityInformationDeviceType,
    pub power_source: NwkCapabilityInformationPowerSource,
    pub receiver_on_when_idle: bool,
    pub reserved1: bool,
    pub reserved2: bool,
    pub security_capability: NwkSecurityCapability,
    pub allocate_address: bool, // = 1
}

/// Bookkeeping for a network address conflict (spec 3.6.1.10.5).
///
/// Detection re-triggers on every frame from the conflicted devices, so a conflict
/// is handled once per delivery window, and our own notification broadcast is
/// cancelled when another device reported the same conflict first.
#[derive(Debug, Clone, Copy)]
pub struct AddressConflict {
    pub handled_at: Instant,
    pub heard_from_network: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ApsAckData {
    pub src: Nwk,
    pub destination_endpoint: Option<u8>,
    pub cluster_id: Option<u16>,
    pub profile_id: Option<u16>,
    pub source_endpoint: Option<u8>,
    pub counter: u8,
}

impl ApsAckData {
    pub const fn from_aps_ack(src: Nwk, ack: &ApsAckFrame) -> Self {
        Self {
            src,
            destination_endpoint: ack.destination_endpoint,
            cluster_id: ack.cluster_id,
            profile_id: ack.profile_id,
            source_endpoint: ack.source_endpoint,
            counter: ack.counter,
        }
    }
}

/// Resolves an indirect transaction with its transmit result on extraction, or an
/// error on expiry or drop.
pub type IndirectCompletion = oneshot::Sender<Result<(), ZigbeeStackError>>;

/// The end-to-end delivery confirmation of a transmitted APS frame, pending until the
/// destination's APS ack arrives. Resolved via [`ZigbeeStack::wait_aps_ack`].
#[derive(Debug)]
pub struct ApsAckWaiter {
    pub(crate) receiver: oneshot::Receiver<()>,
    pub(crate) timeout: Duration,
    pub(crate) ack_data: ApsAckData,
}

#[derive(Debug)]
pub struct State {
    pub channel: Mutex<u8>,
    pub ieee802154_sequence_number: Mutex<u8>,
    pub aps_counter: Mutex<u8>,

    /// APS-layer security material and operations (`apsDeviceKeyPairSet`, link-key
    /// derivation, command encryption)
    pub aps_security: Mutex<ApsSecurity>,

    pub pending_aps_acks: Mutex<HashMap<ApsAckData, oneshot::Sender<()>>>,
    pub pending_route_notifications: Mutex<HashMap<Nwk, broadcast::Sender<()>>>,
    pub address_conflicts: Mutex<HashMap<Nwk, AddressConflict>>,
    /// Frames awaiting extraction by a polling device. Completions are resolved
    /// with the transmit result on extraction, or an error on expiry or drop.
    pub indirect_queue: Mutex<IndirectQueue<IndirectCompletion>>,
    pub start_time: Instant,
    /// The deadline until which joins are permitted; `None` or a past deadline
    /// means joins are denied. A deadline instead of a flag-plus-disable-timer
    /// makes renewals extend the window instead of being cut short by the
    /// earlier request's timer.
    pub permitting_joins_until: Mutex<Option<Instant>>,

    // We intentionally violate the spec with these options
    //
    /// The spec mandates that broadcasts be deduplicated only after the stack has been
    /// running for at least 10s, to avoid having our own broadcasts be received. This
    /// slows down development so we will allow it to be disabled.
    pub hack_ignore_broadcast_startup_wait_period: bool,
    /// To allow testing deserialization logic with real networks, allow running the
    /// stack without TX abilities. Note that this will still permit the firmware to
    /// auto-ACK, but this is generally innocuous and won't collide with a second
    /// coordinator running at the same time.
    pub hack_disable_tx: bool,
    /// Instead of caching route information, always perform route discovery. This is
    /// much slower but ensures that routing logic is always followed.
    pub hack_force_route_discovery: bool,

    // NIB
    pub sequence_number: Mutex<u8>,

    /// The neighbor table: link quality accounting, link status digestion, aging
    pub neighbors: Mutex<Neighbors>,
    /// NWK routing state and decision logic (route/discovery/record tables)
    pub routing: Mutex<Routing>,
    /// Broadcast deduplication and passive acknowledgment accounting
    pub broadcasts: Mutex<Broadcasts>,

    pub capability_information: NwkCapabilityInformation,
    pub nwk_manager_addr: Nwk,

    pub ieee_address: Eui64,
    pub update_id: Mutex<u8>,
    pub pan_id: Mutex<PanId>,
    pub network_address: Nwk,
    pub extended_pan_id: Eui64,
    /// The network key, its outgoing frame counter, and per-relayer replay protection
    pub nwk_security: Mutex<NwkSecurity>,

    pub is_concentrator: bool,
    pub security_level: u8,

    /// The EUI64-to-network-address map, one owner per network address
    pub address_map: Mutex<AddressMap>,

    /// A flag that determines if a timestamp indication is provided on incoming and
    /// outgoing packets.
    pub time_stamp: bool,

    /// A count of Unicast transmissions made by the NNK layer on this device.
    /// Each time the NWK layer transmits a Unicast frame, by invoking the
    /// MCPS-state.request primitive of the MAC sub-layer, it SHALL increment
    /// this counter. When either the NHL performs an NLME-SET.request on this
    /// attribute or if the value of `tx_total` rolls over past 0xffff the
    /// NWK layer SHALL reset to 0x00 each Transmit Failure field contained in
    /// the neighbor table.
    pub tx_total: Mutex<u16>,

    /// This policy determines whether or not a remote NWK leave request command frame
    /// received by the local device is accepted.
    pub leave_request_allowed: bool,

    pub parent_information: ParentInformation,

    /// This policy determines whether a NWK leave request is accepted when the Rejoin
    /// bit in the message is set to FALSE
    pub leave_request_without_rejoin_allowed: bool,

    // A strictly increasing sequence number included in all route request and route
    // reply command frames to allow other routers to determine the chronological order
    // of such route discovery messages.
    // pub nwk_routing_sequence_number: u16,  // Only needed for R23 TLVs
    //
    /// This indicates whether the router has Hub Connectivity as defined by a higher
    /// level application. The higher level application sets this value and the stack
    /// advertises it.
    pub hub_connectivity: bool,
}

impl State {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel: u8,
        update_id: u8,
        pan_id: PanId,
        extended_pan_id: Eui64,
        network_address: Nwk,
        ieee_address: Eui64,
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
        global_link_key: Key,
        tclk_seed: Option<TclkSeed>,
        route_discovery_time: Duration,
        max_neighbor_age: Duration,
        transaction_persistence_time: Duration,
        broadcast_delivery_time: Duration,
        broadcast_passive_ack_quorum: usize,
        mtorr_route_error_threshold: u8,
        mtorr_delivery_failure_threshold: u8,
        source_routing: bool,
    ) -> Self {
        Self {
            channel: Mutex::new(channel),
            ieee802154_sequence_number: Mutex::new(0),
            aps_counter: Mutex::new(0),
            aps_security: Mutex::new(ApsSecurity::new(global_link_key, ieee_address, tclk_seed)),
            pending_aps_acks: Mutex::new(HashMap::new()),
            pending_route_notifications: Mutex::new(HashMap::new()),
            address_conflicts: Mutex::new(HashMap::new()),
            indirect_queue: Mutex::new(IndirectQueue::new(transaction_persistence_time)),
            start_time: Instant::now(),
            permitting_joins_until: Mutex::new(None),

            hack_ignore_broadcast_startup_wait_period: true,
            hack_disable_tx: false,
            hack_force_route_discovery: false,

            sequence_number: Mutex::new(0),
            neighbors: Mutex::new(Neighbors::new(network_address, max_neighbor_age)),
            routing: Mutex::new(Routing::new(
                network_address,
                route_discovery_time,
                mtorr_route_error_threshold,
                mtorr_delivery_failure_threshold,
            )),
            broadcasts: Mutex::new(Broadcasts::new(
                broadcast_delivery_time,
                broadcast_passive_ack_quorum,
            )),
            capability_information: NwkCapabilityInformation {
                alternate_pan_coordinator: false,
                device_type: NwkCapabilityInformationDeviceType::EndDevice,
                power_source: NwkCapabilityInformationPowerSource::MainsPower,
                receiver_on_when_idle: true,
                reserved1: false,
                reserved2: false,
                security_capability: NwkSecurityCapability::Capable,
                allocate_address: true,
            },
            nwk_manager_addr: Nwk(0x0000),
            update_id: Mutex::new(update_id),
            network_address,
            extended_pan_id,
            is_concentrator: source_routing,
            security_level: 5,
            nwk_security: Mutex::new(NwkSecurity::new(
                key,
                key_seq_number,
                outgoing_frame_counter,
                FRAME_COUNTER_NOTIFY_INTERVAL,
            )),
            address_map: Mutex::new(AddressMap::new(network_address)),
            time_stamp: false,
            pan_id: Mutex::new(pan_id),
            tx_total: Mutex::new(0),
            leave_request_allowed: false,
            parent_information: ParentInformation {
                mac_data_poll_keepalive: true,
                end_device_timeout_request_keepalive: false,
                power_negotiation: false,
            },
            leave_request_without_rejoin_allowed: false,
            ieee_address,
            hub_connectivity: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ZigbeeNotification {
    ReceivedApsCommand {
        source: Nwk,
        destination: Nwk,
        group: Option<u16>,
        profile_id: u16,
        cluster_id: u16,
        src_ep: u8,
        dst_ep: u8,
        lqi: u8,
        rssi: i8,
        data: Vec<u8>,
    },
    /// The outgoing NWK security frame counter has advanced; the client should persist
    /// it to prevent a rollback on restart
    FrameCounterUpdate { frame_counter: u32 },
    /// A unique trust center link key was negotiated with a device; the client should
    /// persist it so the device survives a stack restart
    LinkKeyUpdate { ieee: Eui64, key: Key },
    /// A device joined or rejoined the network, directly or through a router
    DeviceJoined { nwk: Nwk, ieee: Eui64, parent: Nwk },
    /// A device announced that it is leaving the network. The EUI64 is unknown when
    /// the leaving device never made it into the address map.
    DeviceLeft { nwk: Nwk, ieee: Option<Eui64> },
}

#[derive(Debug)]
pub struct ZigbeeStack {
    self_weak: Weak<Self>,

    pub state: State,
    pub constants: Constants,
    /// Shared with the server, which owns the serial port for the process lifetime:
    /// a replaced stack only stops its tasks, the port is never reopened
    pub spinel: Arc<SpinelClient>,
    pub notification_tx: broadcast::Sender<ZigbeeNotification>,
    pub raw_frame_rx: AsyncMutex<mpsc::Receiver<SpinelFramePropValueIs>>,
    pub reset_rx: AsyncMutex<mpsc::Receiver<SpinelStatus>>,
    pub energy_scan_rx: AsyncMutex<mpsc::Receiver<SpinelFramePropValueIs>>,

    /// Wakes the task that rewrites the RCP source address match table whenever the
    /// set of devices with queued indirect transactions changes
    pub(crate) src_match_sync: Notify,
    /// What the RCP source address match table currently holds, i.e. which polling
    /// devices were told (via frame-pending=1) to stay awake
    pub(crate) src_match_written: Mutex<SrcMatchTable>,
    /// When the last parent announcement was received; ours is deferred to avoid a
    /// network-wide broadcast storm (spec 2.4.3.1.12.2)
    pub(crate) parent_annce_received: Mutex<Option<Instant>>,

    /// Wakes the MTORR scheduler before its max interval when accumulated route
    /// errors or delivery failures cross their thresholds
    pub(crate) mtorr_kick: Notify,

    /// Signaled whenever a link status command is digested; the MTORR startup wait
    /// uses it to advertise as soon as a neighbor link is established
    pub(crate) link_status_received: Notify,
    /// Signaled on every recorded broadcast passive ack, so retransmission loops can
    /// re-evaluate completeness reactively instead of sleeping out the window
    pub(crate) broadcast_acked: Notify,
    /// Wakes the maintenance task when a new indirect transaction or child entry
    /// could move the earliest expiry deadline closer
    pub(crate) maintenance_wake: Notify,

    /// All tasks spawned by the stack, so that a replaced stack can be fully stopped:
    /// a leaked background task would keep the replaced stack processing frames and
    /// transmitting alongside its successor
    background_tasks: Mutex<JoinSet<()>>,
}

impl ZigbeeStack {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spinel: Arc<SpinelClient>,
        constants: Constants,
        channel: u8,
        update_id: u8,
        pan_id: PanId,
        extended_pan_id: Eui64,
        network_address: Nwk,
        ieee_address: Eui64,
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
        source_routing: bool,
    ) -> (Arc<Self>, broadcast::Receiver<ZigbeeNotification>) {
        let (notification_tx, notification_rx) = broadcast::channel::<ZigbeeNotification>(32);
        let (raw_frame_tx, raw_frame_rx) = mpsc::channel::<SpinelFramePropValueIs>(32);
        spinel.set_property_update_receiver(SpinelPropertyId::StreamRaw, raw_frame_tx);

        let (reset_tx, reset_rx) = mpsc::channel::<SpinelStatus>(8);
        spinel.set_reset_notification_receiver(reset_tx);

        let (energy_scan_tx, energy_scan_rx) = mpsc::channel::<SpinelFramePropValueIs>(8);
        spinel.set_property_update_receiver(SpinelPropertyId::MacEnergyScanResult, energy_scan_tx);

        let arc_stack = Arc::new_cyclic(|weak_self| Self {
            self_weak: weak_self.clone(),
            state: State::new(
                channel,
                update_id,
                pan_id,
                extended_pan_id,
                network_address,
                ieee_address,
                key,
                key_seq_number,
                outgoing_frame_counter,
                constants.global_link_key.clone(),
                constants.tclk_seed.clone(),
                constants.route_discovery_time,
                u32::from(constants.router_age_limit) * constants.link_status_period,
                constants.transaction_persistence_time,
                constants.broadcast_delivery_time,
                constants.broadcast_passive_ack_quorum,
                constants.mtorr_route_error_threshold,
                constants.mtorr_delivery_failure_threshold,
                source_routing,
            ),
            constants,
            spinel,
            notification_tx,
            raw_frame_rx: AsyncMutex::new(raw_frame_rx),
            reset_rx: AsyncMutex::new(reset_rx),
            energy_scan_rx: AsyncMutex::new(energy_scan_rx),
            src_match_sync: Notify::new(),
            src_match_written: Mutex::new(SrcMatchTable::default()),
            parent_annce_received: Mutex::new(None),
            mtorr_kick: Notify::new(),
            link_status_received: Notify::new(),
            broadcast_acked: Notify::new(),
            maintenance_wake: Notify::new(),
            background_tasks: Mutex::new(JoinSet::new()),
        });

        (arc_stack, notification_rx)
    }

    // This function intentionally holds locks across await points to maintain
    // exclusive access to shared state during frame processing.
    pub async fn run(&self) {
        loop {
            let (packet, ieee802154_frame) = self.recv_frame().await;

            // Ignore our own packets
            if ieee802154_frame.header().src_address
                == Some(Ieee802154Address::Nwk(self.state.network_address))
            {
                log::debug!("Ignoring our own packet");
                continue;
            }

            match ieee802154_frame {
                ieee_802154::Ieee802154Frame::Data(ieee802154_data_frame) => {
                    let maybe_nwk_frame = self.process_802154_data_frame(
                        &ieee802154_data_frame,
                        packet.lqi,
                        packet.rssi,
                    );

                    if maybe_nwk_frame.is_none() {
                        continue;
                    }

                    let nwk_frame = maybe_nwk_frame.unwrap();

                    if nwk_frame.nwk_header.frame_control.frame_type != NwkFrameType::Data {
                        continue;
                    }

                    let (aps_frame, aps_source_eui64) = match parse_aps_frame(&nwk_frame.payload) {
                        Ok(ApsFrame::Data(data)) => (data, None),
                        Ok(ApsFrame::EncryptedData(encrypted)) => {
                            match self.decrypt_aps_data_frame(&nwk_frame, &encrypted) {
                                Some((data, source_eui64)) => (data, Some(source_eui64)),
                                None => {
                                    log::warn!(
                                        "Failed to decrypt APS data frame from {:?}",
                                        nwk_frame.nwk_header.source
                                    );
                                    continue;
                                }
                            }
                        }
                        Ok(ApsFrame::Ack(ack)) => {
                            self.handle_aps_ack(&nwk_frame, &ack);
                            continue;
                        }
                        Ok(ApsFrame::EncryptedAck(encrypted)) => {
                            match self.decrypt_aps_ack_frame(&nwk_frame, &encrypted) {
                                Some(ack) => self.handle_aps_ack(&nwk_frame, &ack),
                                None => log::warn!(
                                    "Failed to decrypt APS ACK from {:?}",
                                    nwk_frame.nwk_header.source
                                ),
                            }
                            continue;
                        }
                        Ok(ApsFrame::Command(cmd)) => {
                            self.handle_aps_command_frame(&nwk_frame, &cmd, None);
                            continue;
                        }
                        Ok(ApsFrame::EncryptedCommand(encrypted_cmd)) => {
                            self.handle_encrypted_aps_command_frame(&nwk_frame, &encrypted_cmd);
                            continue;
                        }
                        Err(e) => {
                            log::warn!("Error parsing APS frame: {e:?}");
                            continue;
                        }
                    };

                    log::debug!("Received APS data frame: {aps_frame:?}");

                    // The ZDP commands that maintain stack state (the neighbor and
                    // address tables live here, not in the client) are consumed by
                    // the stack; the client still observes the frames
                    self.handle_zdp_frame(&nwk_frame, &aps_frame);

                    if aps_frame.frame_control.ack_request {
                        self.handle_aps_ack_request(&aps_frame, &nwk_frame, aps_source_eui64);
                    }

                    let notification = ZigbeeNotification::ReceivedApsCommand {
                        source: nwk_frame.nwk_header.source,
                        destination: nwk_frame.nwk_header.destination,
                        group: aps_frame.group_id,
                        profile_id: aps_frame.profile_id,
                        cluster_id: aps_frame.cluster_id,
                        src_ep: aps_frame.source_endpoint,
                        dst_ep: aps_frame.destination_endpoint.unwrap_or(0),
                        lqi: packet.lqi,
                        rssi: packet.rssi,
                        data: aps_frame.asdu.to_vec(),
                    };
                    let _ = self.notification_tx.send(notification);
                }
                ieee_802154::Ieee802154Frame::Ack(_ack_frame) => {}
                ieee_802154::Ieee802154Frame::Beacon(_beacon_frame) => {}
                ieee_802154::Ieee802154Frame::Command(command_frame) => {
                    self.process_802154_command_frame(&command_frame);
                }
            }
        }
    }

    // We intentionally hold the receiver lock for the entire duration of this function
    // to ensure exclusive access to the raw frame receiver.
    #[allow(clippy::significant_drop_tightening)]
    async fn recv_frame(&self) -> (SpinelRxFrame, Ieee802154Frame) {
        let mut receiver = self
            .raw_frame_rx
            .try_lock()
            .expect("Raw frame receiver is locked");

        loop {
            // The sender lives in the Spinel protocol state and outlives the stack: it
            // hanging up means the transport is gone, not a recoverable condition
            let Some(spinel_frame) = receiver.recv().await else {
                panic!("Spinel raw frame sender hung up");
            };

            let packet = match SpinelRxFrame::from_bytes(&spinel_frame.value) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Error parsing spinel frame: {e:?}");
                    continue;
                }
            };

            if packet.psdu.len() < 2 {
                log::warn!("Packet too short to contain FCS");
                continue;
            }

            let frame_data = &packet.psdu[..packet.psdu.len() - 2];

            match Ieee802154Frame::from_bytes_without_fcs(frame_data) {
                Ok(frame) => {
                    log::debug!("Received 802.15.4 frame: {frame:?}");
                    return (packet, frame);
                }
                Err(e) => {
                    log::warn!("Error parsing IEEE 802.15.4 frame: {e:?}");
                    continue;
                }
            };
        }
    }

    pub async fn start_network(&self) -> Result<(), ZigbeeStackError> {
        // Never inherit whatever state the RCP was left in. The radio lock is held so
        // that a concurrent transmit or scan cannot interleave with the reset and
        // reprogramming; it must be released before the link status broadcast below,
        // which takes it to transmit.
        {
            let _radio_lock = self.spinel.lock_radio().await;
            self.reset_radio().await?;
            self.apply_radio_configuration().await?;
        }

        // To kick things off, send a link status broadcast. Silicon Labs routers will
        // "respond" to empty link status broadcasts proactively, independent of the
        // link status period
        log::info!("Sending initial link status broadcast");
        self.send_link_status_broadcast(true).await;

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        // Start the background link status broadcaster task
        self.spawn_tracked(async move {
            arc_self.periodic_link_status_broadcast_task().await;
        });

        // Advertise many-to-one routes to ourselves so that devices can route inbound
        // traffic without per-device route discoveries
        if self.state.is_concentrator {
            let arc_self = self
                .self_weak
                .upgrade()
                .expect("Unable to upgrade self reference");

            self.spawn_tracked(async move {
                arc_self.periodic_many_to_one_route_request_task().await;
            });
        }

        // Reprogram the radio whenever it resets out from under us
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.radio_recovery_task().await;
        });

        // Mirror the indirect queue state into the RCP source address match table
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.src_match_sync_task().await;
        });

        // Expire undelivered indirect transactions and age out silent children
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.indirect_maintenance_task().await;
        });

        // Announce our end device children to the other routers after boot
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.parent_annce_task().await;
        });

        Ok(())
    }

    /// Reset the RCP and wait for it to announce itself, retrying if it stays silent.
    async fn reset_radio(&self) -> Result<(), ZigbeeStackError> {
        let mut reset_rx = self.reset_rx.try_lock().expect("Reset receiver is locked");

        for attempt in 1..=RESET_ATTEMPTS {
            self.spinel.send_reset().await?;

            match timeout(RESET_NOTIFICATION_TIMEOUT, reset_rx.recv()).await {
                Ok(Some(status)) => {
                    log::info!("RCP reset complete: {status:?}");
                    return Ok(());
                }
                Ok(None) => panic!("Spinel reset notification sender hung up"),
                Err(_) => {
                    log::warn!("No reset notification, attempt {attempt}/{RESET_ATTEMPTS}");
                }
            }
        }

        Err(ZigbeeStackError::SpinelError(SpinelError::Timeout))
    }

    /// Program the radio with our network parameters. An RCP reset wipes all of this,
    /// so it must be re-applied after every reset.
    async fn apply_radio_configuration(&self) -> Result<(), ZigbeeStackError> {
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyEnabled, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        let channel = *self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap();
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyChan, vec![channel])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::PhyTxPower,
                vec![self.constants.tx_power as u8],
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        // RAIL only auto-acknowledges frames that pass address filtering, and
        // promiscuous mode bypasses the filter: with it enabled the radio ACKs nothing
        // and every unicast exchange fails at the MAC layer. Receive-only monitoring
        // still wants every frame.
        let promiscuous_mode = if self.state.hack_disable_tx {
            SpinelMacPromiscuousMode::Full
        } else {
            SpinelMacPromiscuousMode::Off
        };

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacPromiscuousMode,
                vec![promiscuous_mode as u8],
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Laddr,
                spinel::eui64_to_spinel_bytes(self.state.ieee_address).to_vec(),
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::Mac154Saddr,
                self.state.network_address.to_bytes().to_vec(),
            )
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        let pan_id = *self.state.pan_id.try_lock_for(MAX_LOCK_DURATION).unwrap();
        self.spinel
            .prop_value_set(SpinelPropertyId::Mac154Panid, pan_id.to_bytes().to_vec())
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(SpinelPropertyId::MacRxOnWhenIdleMode, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        self.spinel
            .prop_value_set(SpinelPropertyId::MacRawStreamEnabled, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        // The frame pending bit in auto-ACKs to MAC Data Requests comes from the
        // source address match table: with matching enabled, FP=1 only for devices
        // with queued indirect transactions. A reset wipes the table, so it is
        // rebuilt from the queue state rather than merely re-enabled.
        self.spinel
            .prop_value_set(SpinelPropertyId::MacSrcMatchEnabled, vec![true as u8])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;
        self.write_src_match_table().await?;

        Ok(())
    }

    /// Watches for RCP resets (announced or synthesized from persistent command
    /// timeouts) and reprograms the radio. Mesh state survives a radio reset; only the
    /// radio configuration needs to be re-applied.
    #[allow(clippy::significant_drop_tightening)]
    async fn radio_recovery_task(&self) {
        let mut reset_rx = self.reset_rx.try_lock().expect("Reset receiver is locked");

        loop {
            let Some(status) = reset_rx.recv().await else {
                panic!("Spinel reset notification sender hung up");
            };

            log::error!("RCP reset detected ({status:?}), reprogramming the radio");

            // The reset failed every in-flight command, so current lock holders
            // release promptly; holding the lock keeps new transmits and scans off
            // the radio until it is fully reprogrammed
            let _radio_lock = self.spinel.lock_radio().await;

            while let Err(err) = self.apply_radio_configuration().await {
                log::error!("Failed to reprogram the radio: {err}, retrying");
                sleep(RADIO_RECOVERY_RETRY_INTERVAL).await;
            }

            log::info!("Radio reprogrammed, resuming normal operation");
        }
    }

    /// Performs an energy detect scan and returns the maximum RSSI seen on each
    /// channel. The RCP only scans a single channel per request, so channels are
    /// scanned sequentially; reception is suspended for the duration of the scan.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn energy_scan(
        &self,
        channels: &[u8],
        duration_per_channel: Duration,
    ) -> Result<Vec<(u8, i8)>, ZigbeeStackError> {
        let mut energy_scan_rx = self
            .energy_scan_rx
            .try_lock()
            .expect("Energy scan receiver is locked");

        // Discard results of an earlier scan that failed after starting a channel
        while energy_scan_rx.try_recv().is_ok() {}

        let scan_period_ms = u16::try_from(duration_per_channel.as_millis())
            .expect("Scan duration does not fit into a u16");

        let scan = async {
            let mut results = Vec::with_capacity(channels.len());

            for &channel in channels {
                // The RCP rejects a scan start while a transmit is in flight, so the
                // radio is owned exclusively for each channel's scan. Taking the (fair)
                // lock per channel lets transmissions queued during one channel slip
                // out before the next, instead of blacking out transmission for the
                // whole sweep.
                let _radio_lock = self.spinel.lock_radio().await;

                self.spinel
                    .prop_value_set(SpinelPropertyId::MacScanMask, vec![channel])
                    .await?;
                self.spinel
                    .prop_value_set(
                        SpinelPropertyId::MacScanPeriod,
                        scan_period_ms.to_le_bytes().to_vec(),
                    )
                    .await?;

                // A rejected scan start is answered with a `LastStatus` instead of the
                // scan state, and no result would ever arrive
                let (response_property, response_value) = self
                    .spinel
                    .prop_value_set(
                        SpinelPropertyId::MacScanState,
                        vec![SpinelMacScanState::Energy as u8],
                    )
                    .await?;

                if response_property != SpinelPropertyId::MacScanState {
                    return Err(ZigbeeStackError::SpinelError(
                        SpinelError::InvalidResponseError {
                            reason: format!(
                                "Energy scan of channel {channel} was rejected: \
                                 {response_property:?}={response_value:02X?}"
                            ),
                        },
                    ));
                }

                // The single scan result update doubles as the completion notification
                let update = timeout(
                    duration_per_channel + ENERGY_SCAN_RESULT_TIMEOUT,
                    energy_scan_rx.recv(),
                )
                .await
                .map_err(|_| ZigbeeStackError::SpinelError(SpinelError::Timeout))?
                .expect("Spinel energy scan sender hung up");

                let [scanned_channel, max_rssi] = update.value[..] else {
                    panic!("Invalid energy scan result: {:02X?}", update.value);
                };
                assert_eq!(scanned_channel, channel);

                results.push((scanned_channel, max_rssi as i8));
            }

            Ok(results)
        };
        let results = scan.await;

        // The scan leaves the radio tuned to the last scanned channel, even on failure
        let network_channel = *self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap();
        self.spinel
            .prop_value_set(SpinelPropertyId::PhyChan, vec![network_channel])
            .await?;

        results
    }

    /// Retune the radio to a new channel, the coordinator's half of a network-wide
    /// channel migration. Mesh state is untouched; subsequent resets and energy scans
    /// return to the new channel.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn set_channel(&self, channel: u8) -> Result<(), ZigbeeStackError> {
        // The lock keeps transmits and scans off the radio mid-retune; the state
        // update happens under it so a concurrent reset recovery cannot reprogram
        // the old channel
        let _radio_lock = self.spinel.lock_radio().await;

        let (rsp_property, rsp_value) = self
            .spinel
            .prop_value_set(SpinelPropertyId::PhyChan, vec![channel])
            .await
            .map_err(ZigbeeStackError::SpinelError)?;

        // A rejected change (e.g. an out-of-range channel) is answered with a
        // `LastStatus` instead of the property
        if rsp_property != SpinelPropertyId::PhyChan {
            return Err(ZigbeeStackError::SpinelError(
                SpinelError::InvalidResponseError {
                    reason: format!(
                        "Channel change to {channel} was rejected: \
                         {rsp_property:?}={rsp_value:02X?}"
                    ),
                },
            ));
        }

        *self.state.channel.try_lock_for(MAX_LOCK_DURATION).unwrap() = channel;

        Ok(())
    }

    /// Update the `nwkUpdateId` advertised in our beacons, bumped alongside a channel
    /// migration so devices comparing network instances pick the current one.
    pub fn set_nwk_update_id(&self, update_id: u8) {
        *self
            .state
            .update_id
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap() = update_id;
    }

    /// Spawns a task tied to the stack's lifetime: it is aborted on `shutdown`.
    pub fn spawn_tracked<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.background_tasks
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .spawn(future);
    }

    /// Stops all of the stack's tasks and waits for them to terminate, so that a
    /// replaced stack provably stops processing frames and transmitting before its
    /// successor takes over the shared Spinel client.
    pub async fn shutdown(&self) {
        let mut tasks = std::mem::take(
            &mut *self
                .background_tasks
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap(),
        );

        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    pub fn next_aps_counter(&self) -> u8 {
        let mut aps_counter = self
            .state
            .aps_counter
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap();
        *aps_counter = aps_counter.wrapping_add(1);

        *aps_counter
    }

    pub fn next_nwk_frame_counter(&self) -> u32 {
        let advance = self
            .state
            .nwk_security
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .next_outgoing_frame_counter();

        if advance.should_persist {
            let _ = self
                .notification_tx
                .send(ZigbeeNotification::FrameCounterUpdate {
                    frame_counter: advance.value,
                });
        }

        advance.value
    }
}
