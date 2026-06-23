use crate::ziggurat_ieee_802154::{Ieee802154Address, Ieee802154Frame};

use crate::runtime::{Elapsed, RtInstant, Runtime, Spawn};
use crate::signal::{Signal, SignalWaiter};
use abstract_bits::AbstractBits;
use arbitrary_int::prelude::*;
use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_phy::{
    ExclusiveRadio, RadioConfig, RadioError, RadioPhy, Receiver, RxFrame, TxFrame, TxResult,
};
use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::aps::frame::{ApsAckFrame, ApsFrame, parse_aps_frame};
use ziggurat_zigbee::beacon::ZigbeeBeacon;

use thiserror::Error;

use crate::sync::{AsyncMutex, Mutex, MutexGuard, Notify};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use ziggurat_zigbee::nwk::frame::NwkFrame;

mod aps;
mod indirect;
mod joining;
mod mac;
mod neighbor;
mod nwk;
mod route;
mod zdp;

pub use ziggurat_zigbee::aps::security as aps_security;
pub use ziggurat_zigbee::aps::security::{ApsSecurity, TclkSeed};
pub use ziggurat_zigbee::constants::{
    MAX_DEPTH, PROTOCOL_VERSION, STACK_PROFILE, Tunables, WELL_KNOWN_LINK_KEY,
};
pub use ziggurat_zigbee::indirect::{IndirectQueue, SrcMatchTable};
pub use ziggurat_zigbee::nwk::NwkDeviceType;
pub use ziggurat_zigbee::nwk::addresses::AddressMap;
pub use ziggurat_zigbee::nwk::broadcasts::Broadcasts;
pub use ziggurat_zigbee::nwk::neighbors::Neighbors;
pub use ziggurat_zigbee::nwk::routing::Routing;
pub use ziggurat_zigbee::nwk::security::NwkSecurity;
pub use ziggurat_zigbee::nwk::{neighbors, routing};

/// How long the RCP gets to announce itself after a `CMD_RESET` before we resend.
const RESET_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);
const RESET_ATTEMPTS: u32 = 5;
const RADIO_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How often (in frames) the client is notified of the outgoing NWK security frame
/// counter, so that its persisted copy never lags far behind.
const FRAME_COUNTER_NOTIFY_INTERVAL: u32 = 100;

#[derive(Error, Debug)]
pub enum ZigbeeStackError {
    #[error("route discovery timed out")]
    RouteDiscoveryTimeout(#[from] Elapsed),
    #[error("no route discovery entry found for the destination")]
    RouteDiscoveryNoEntry,
    #[error("route not active after discovery completed")]
    RouteInactiveAfterDiscovery,
    #[error("no route to destination and route discovery is suppressed")]
    RouteDiscoverySuppressed,
    #[error("next hop {next_hop:?} did not ACK")]
    NwkNoAck { next_hop: Ieee802154Address },
    #[error("transmit rejected due to CCA failure")]
    CcaFailure,
    #[error("unexpected transmit failure: {0:?}")]
    TransmitFailed(TxResult),
    #[error("aps ack timeout")]
    ApsAckTimeout,
    #[error("payload does not fit in a single frame")]
    PayloadTooLong,
    #[error("aps security material unavailable or unusable")]
    ApsSecurityFailed,
    #[error("indirect transaction expired before {destination:?} polled")]
    IndirectExpired { destination: Ieee802154Address },
    #[error("radio error: {0}")]
    Radio(#[from] RadioError),
}

/// Transmit scheduling priority. Higher transmits first when the radio is contended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxPriority(pub i8);

impl TxPriority {
    pub const BACKGROUND: Self = Self(-2);
    pub const USER_LOW: Self = Self(-1);
    pub const USER_NORMAL: Self = Self(0);
    pub const USER_HIGH: Self = Self(1);
    pub const USER_CRITICAL: Self = Self(2);
    pub const STACK_CRITICAL: Self = Self(3);
}

/// How an outgoing NWK frame is secured. Frames carrying the network key to a joining
/// device are sent without NWK security; the APS payload is encrypted instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NwkSecurityMode {
    NetworkKey,
    Unsecured,
}

/// How the MAC next hop for an outgoing unicast is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    /// The destination is its own next hop: transmit straight to it with no routing
    /// lookup (and route discovery suppressed). Used for frames to a one-hop neighbor,
    /// e.g. delivering the network key to a joining device.
    Direct,
    /// Resolve the next hop through the routing layer — the route table or an applicable
    /// source route, discovering a route first if none is known.
    Route,
}

/// Whether a unicast APS data frame requests an end-to-end acknowledgement. When it
/// does, [`ZigbeeStack::send_aps_command`] returns an [`ApsAckWaiter`] to await it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApsAck {
    Request,
    None,
}

/// Whether a device is attaching fresh or rejoining.
///
/// Selects the link key that protects the transported network key: a fresh joiner only
/// holds the well-known (or install-code) key, while a rejoining device holds the key it
/// was last issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    New,
    Rejoin,
}

/// How an address conflict (spec 3.6.1.10.5) came to our attention: detected locally
/// from a received frame, or reported by another device's network status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrConflictSource {
    Local,
    Network,
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

/// The per-network parameters provided by the application through `configure`, in
/// contrast to the spec-defaulted [`Tunables`].
#[derive(Debug)]
pub struct NetworkConfig {
    pub role: NwkDeviceType,
    pub channel: u8,
    pub update_id: u8,
    pub pan_id: PanId,
    pub extended_pan_id: Eui64,
    pub network_address: Nwk,
    pub ieee_address: Eui64,
    pub network_key: Key,
    pub network_key_seq_number: u8,
    pub network_key_tx_counter: u32,
    /// The trust center link key: [`WELL_KNOWN_LINK_KEY`] unless the network uses a
    /// custom one
    pub tc_link_key: Key,
    /// The TCLK seed of the stack the network was taken over from, if any: unique
    /// link keys are derived from it instead of generated randomly
    pub tclk_seed: Option<TclkSeed>,
    /// The radio transmit power in dBm
    pub tx_power: i8,
    pub source_routing: bool,
}

/// Bookkeeping for a network address conflict (spec 3.6.1.10.5).
///
/// Detection re-triggers on every frame from the conflicted devices, so a conflict
/// is handled once per delivery window, and our own notification broadcast is
/// cancelled when another device reported the same conflict first.
#[derive(Debug, Clone, Copy)]
pub struct AddressConflict {
    pub handled_at: CoreInstant,
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

/// The pending half of a transmit's outcome.
///
/// Resolved `Ok` once the frame leaves the radio (or, for an indirect transaction, once
/// the child extracts it), or `Err` on transmit failure, expiry, or drop. Shared by the
/// sender queue, the indirect queue, and queued frames, since a completion can hand off
/// between them.
pub type TxCompletion = Signal<Result<(), ZigbeeStackError>>;

/// The end-to-end delivery confirmation of a transmitted APS frame, pending until the
/// destination's APS ack arrives. Resolved via [`ZigbeeStack::wait_aps_ack`].
#[derive(Debug)]
pub struct ApsAckWaiter {
    pub(crate) receiver: SignalWaiter<()>,
    pub(crate) timeout: Duration,
    pub(crate) ack_data: ApsAckData,
}

/// A transmit queued for the single sender task ([`ZigbeeStack::sender_task`]). The NWK
/// frame is unencrypted: the sender assigns the frame counter at dequeue, so on-air order
/// always matches frame-counter order regardless of priority reordering in the queue.
#[derive(Debug)]
pub(crate) struct SendRequest {
    seq: u64,
    priority: TxPriority,
    pub(crate) kind: SendKind,
    pub(crate) completion: Option<TxCompletion>,
}

#[derive(Debug)]
pub(crate) enum SendKind {
    Unicast {
        nwk_frame: NwkFrame,
        next_hop: Nwk,
        security: NwkSecurityMode,
    },
    Broadcast {
        nwk_frame: NwkFrame,
        security: NwkSecurityMode,
    },
    /// An already-finished 802.15.4 frame (a beacon response, or an indirect poll
    /// delivery): transmitted as-is, only the MAC sequence number assigned at dequeue.
    Raw { frame: Ieee802154Frame },
}

/// A unicast frame queued because its destination has no known route.
///
/// Held in [`State::pending_routes`] until route discovery resolves. The NWK sequence
/// number is already assigned; the frame counter is still assigned at dequeue.
#[derive(Debug)]
pub struct PendingFrame {
    pub(crate) nwk_frame: NwkFrame,
    pub(crate) security: NwkSecurityMode,
    pub(crate) priority: TxPriority,
    pub(crate) completion: Option<TxCompletion>,
}

/// All frames waiting on one destination's route discovery.
///
/// Discovery is started once per destination and the whole bucket is released or
/// discarded together, so ten frames to one device ride a single discovery.
#[derive(Debug)]
pub struct PendingRoute {
    pub(crate) frames: Vec<PendingFrame>,
    /// Discoveries left before the bucket is discarded. Seeded from
    /// `Tunables::pending_route_discovery_attempts` and decremented on each timeout.
    pub(crate) attempts_remaining: u8,
}

/// A broadcast awaiting retransmission, held by the broadcast-retransmit reactor.
///
/// Spec 3.6.6: a broadcast is rebroadcast until its passive-ack quorum is heard or its
/// attempts run out. This holds the frame to retransmit and the schedule; the passive-ack
/// contract itself lives in the sans-io [`Broadcasts`] table.
#[derive(Debug)]
pub struct PendingBroadcast {
    pub(crate) nwk_frame: NwkFrame,
    pub(crate) security: NwkSecurityMode,
    pub(crate) priority: TxPriority,
    /// Retransmissions left before the broadcast is given up on.
    pub(crate) attempts_remaining: u8,
    /// When the next retransmission is due, unless the quorum is heard first.
    pub(crate) next_attempt: CoreInstant,
}

impl PartialEq for SendRequest {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.seq == other.seq
    }
}
impl Eq for SendRequest {}
impl Ord for SendRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap: higher priority first; within a priority, the earlier (lower) seq
        // wins, so equal-priority frames drain in FIFO order.
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for SendRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The NWK Information Base (spec Table 3-66): the network layer's mutable attributes
/// and decision tables.
#[derive(Debug)]
pub struct Nib {
    pub sequence_number: u8,
    pub update_id: u8,

    /// A count of Unicast transmissions made by the NWK layer on this device.
    /// Each time the NWK layer transmits a Unicast frame, by invoking the
    /// MCPS-state.request primitive of the MAC sub-layer, it SHALL increment
    /// this counter. When either the NHL performs an NLME-SET.request on this
    /// attribute or if the value of `tx_total` rolls over past 0xffff the
    /// NWK layer SHALL reset to 0x00 each Transmit Failure field contained in
    /// the neighbor table.
    pub tx_total: u16,

    /// The neighbor table: link quality accounting, link status digestion, aging
    pub neighbors: Neighbors,
    /// NWK routing state and decision logic (route/discovery/record tables)
    pub routing: Routing,
    /// Broadcast deduplication and passive acknowledgment accounting
    pub broadcasts: Broadcasts,
    /// The network key, its outgoing frame counter, and per-relayer replay protection
    pub nwk_security: NwkSecurity,
    /// The EUI64-to-network-address map, one owner per network address
    pub address_map: AddressMap,
}

/// The APS sub-layer Information Base (spec Table 4-35 and §4.4): the trust-center
/// link-key store and APS-layer counter.
#[derive(Debug)]
pub struct Aib {
    pub aps_counter: u8,
    /// APS-layer security material and operations (`apsDeviceKeyPairSet`, link-key
    /// derivation, command encryption). Holds the non-spec TCLK seed used to derive
    /// keys when the network was taken over from a microcontroller stack.
    pub aps_security: ApsSecurity,
}

/// Host-side mirror of the MAC PIB attributes we drive on the RCP. The MAC sub-layer
/// physically lives on the radio coprocessor; these are our authoritative copies.
#[derive(Debug)]
pub struct MacState {
    pub channel: u8,
    pub ieee802154_sequence_number: u8,
    pub pan_id: PanId,
    /// Frames awaiting extraction by a polling device. Completions are resolved
    /// with the transmit result on extraction, or an error on expiry or drop.
    pub indirect_queue: IndirectQueue<TxCompletion>,
}

/// The driver's unified mutable protocol state, behind a single lock.
///
/// An operation spanning several layers takes one guard instead of juggling a lock per
/// field (and can never deadlock against itself on lock ordering). This is also the
/// shape the eventual no_std core will own directly — there with no lock, here behind
/// one `Mutex` for the threaded driver. Spec attributes are grouped by their
/// information base ([`Nib`],[`Aib`], [`MacState`]); a field directly on the core is,
/// by that absence, one of our own constructs with no spec information-base home.
#[derive(Debug)]
pub struct ZigbeeCore {
    pub nib: Nib,
    pub aib: Aib,
    pub mac: MacState,

    /// Deadline until which the coordinator advertises `association_permit` in its
    /// beacon and accepts direct MAC associations. A deadline rather than a flag lets
    /// renewals extend the window. `None` or past means direct joins are denied.
    pub permitting_joins_until: Option<CoreInstant>,

    /// Deadline until which the trust center authorizes new devices joining through a
    /// router. Opened on every permit, independent of the beacon window, so a steered
    /// join completes while the coordinator's own beacon stays closed. Rejoins are
    /// never gated by this.
    pub trust_center_joins_until: Option<CoreInstant>,
}

/// Guard over the protocol [`ZigbeeCore`], obtained from [`ZigbeeStack::core`]. It encodes
/// the single-lock discipline: it is `!Send`, so holding it across an `.await` is a
/// compile-time error.
pub struct CoreGuard<'a>(MutexGuard<'a, ZigbeeCore>);

impl Deref for CoreGuard<'_> {
    type Target = ZigbeeCore;

    fn deref(&self) -> &ZigbeeCore {
        &self.0
    }
}

impl DerefMut for CoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut ZigbeeCore {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct State {
    /// All mutable protocol state, behind one lock
    pub core: Mutex<ZigbeeCore>,

    pub pending_aps_acks: Mutex<HashMap<ApsAckData, Signal<()>>>,
    pub pending_routes: Mutex<HashMap<Nwk, PendingRoute>>,
    /// Broadcasts awaiting retransmission, keyed by (source, sequence number).
    pub pending_broadcasts: Mutex<HashMap<(Nwk, u8), PendingBroadcast>>,
    pub address_conflicts: Mutex<HashMap<Nwk, AddressConflict>>,

    /// Spec 2.2.8.4.2: APS duplicate rejection. Keyed by (originator, APS counter) with
    /// the receipt time; an inbound data frame matching a live entry is a retransmission
    /// to be acknowledged but not delivered to the application a second time.
    pub aps_duplicates: Mutex<HashMap<(Nwk, u8), CoreInstant>>,

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

    pub role: NwkDeviceType,
    pub capability_information: NwkCapabilityInformation,
    pub nwk_manager_addr: Nwk,

    pub ieee_address: Eui64,
    pub network_address: Nwk,
    pub extended_pan_id: Eui64,

    pub is_concentrator: bool,
    pub security_level: u8,

    /// A flag that determines if a timestamp indication is provided on incoming and
    /// outgoing packets.
    pub time_stamp: bool,

    /// This policy determines whether or not a remote NWK leave request command frame
    /// received by the local device is accepted.
    pub leave_request_allowed: bool,

    pub parent_information: ParentInformation,

    /// This policy determines whether a NWK leave request is accepted when the Rejoin
    /// bit in the message is set to FALSE
    pub leave_request_without_rejoin_allowed: bool,

    /// This indicates whether the router has Hub Connectivity as defined by a higher
    /// level application. The higher level application sets this value and the stack
    /// advertises it.
    pub hub_connectivity: bool,
}

impl State {
    pub fn new(config: &NetworkConfig, tunables: &Tunables) -> Self {
        Self {
            core: Mutex::new(ZigbeeCore {
                nib: Nib {
                    sequence_number: 0,
                    update_id: config.update_id,
                    tx_total: 0,
                    neighbors: Neighbors::new(
                        config.network_address,
                        u32::from(tunables.router_age_limit) * tunables.link_status_period,
                    ),
                    routing: Routing::new(
                        config.network_address,
                        tunables.route_discovery_time,
                        tunables.mtorr_route_error_threshold,
                        tunables.mtorr_delivery_failure_threshold,
                    ),
                    broadcasts: Broadcasts::new(
                        tunables.broadcast_delivery_time,
                        tunables.broadcast_passive_ack_quorum,
                    ),
                    nwk_security: NwkSecurity::new(
                        config.network_key.clone(),
                        config.network_key_seq_number,
                        config.network_key_tx_counter,
                        FRAME_COUNTER_NOTIFY_INTERVAL,
                    ),
                    address_map: AddressMap::new(config.network_address, config.ieee_address),
                },
                aib: Aib {
                    aps_counter: 0,
                    aps_security: ApsSecurity::new(
                        config.tc_link_key.clone(),
                        config.ieee_address,
                        config.tclk_seed.clone(),
                    ),
                },
                mac: MacState {
                    channel: config.channel,
                    ieee802154_sequence_number: 0,
                    pan_id: config.pan_id,
                    indirect_queue: IndirectQueue::new(tunables.transaction_persistence_time),
                },
                permitting_joins_until: None,
                trust_center_joins_until: None,
            }),
            pending_aps_acks: Mutex::new(HashMap::new()),
            pending_routes: Mutex::new(HashMap::new()),
            pending_broadcasts: Mutex::new(HashMap::new()),
            address_conflicts: Mutex::new(HashMap::new()),
            aps_duplicates: Mutex::new(HashMap::new()),

            hack_ignore_broadcast_startup_wait_period: true,
            hack_disable_tx: false,
            hack_force_route_discovery: false,

            role: config.role,
            capability_information: NwkCapabilityInformation {
                alternate_pan_coordinator: false,
                device_type: match config.role {
                    NwkDeviceType::EndDevice => NwkCapabilityInformationDeviceType::EndDevice,
                    NwkDeviceType::Coordinator | NwkDeviceType::Router => {
                        NwkCapabilityInformationDeviceType::Router
                    }
                },
                power_source: NwkCapabilityInformationPowerSource::MainsPower,
                receiver_on_when_idle: true,
                reserved1: false,
                reserved2: false,
                security_capability: NwkSecurityCapability::Capable,
                allocate_address: true,
            },
            nwk_manager_addr: Nwk(0x0000),
            network_address: config.network_address,
            extended_pan_id: config.extended_pan_id,
            is_concentrator: config.source_routing,
            security_level: 5,
            time_stamp: false,
            leave_request_allowed: false,
            parent_information: ParentInformation {
                mac_data_poll_keepalive: true,
                end_device_timeout_request_keepalive: false,
                power_negotiation: false,
            },
            leave_request_without_rejoin_allowed: false,
            ieee_address: config.ieee_address,
            hub_connectivity: true,
        }
    }
}

/// How the stack learned that a device left the network.
#[derive(Debug, Clone, Copy)]
pub enum DeviceLeaveReason {
    /// The device itself broadcast a NWK Leave announcement. `rejoin` mirrors the
    /// Leave command's Rejoin sub-field: `true` means it intends to rejoin.
    Announced { rejoin: bool },
    /// A parent router relayed an APS Update-Device "Device Left" for one of its
    /// children (spec 4.6.3.6.2); the device is out of our radio range. `router_ieee`
    /// is the reporting router's EUI64 when we can resolve it from the address map.
    RouterReported {
        router: Nwk,
        router_ieee: Option<Eui64>,
    },
    /// A sleepy child aged out of the neighbor table without sending a keepalive.
    KeepaliveTimeout,
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
    /// A device left the network. The EUI64 is unknown when the leaving device never
    /// made it into the address map. `reason` records how we learned of the departure.
    DeviceLeft {
        nwk: Nwk,
        ieee: Option<Eui64>,
        reason: DeviceLeaveReason,
    },
    /// An APS command frame from a device could not be decrypted with any key we hold
    /// (its trust center link key, a configured TCLK seed, or the well-known key).
    /// This almost always means the device's link key is wrong/missing and it silently
    /// breaks joins routed through that device, since the trust center can't read its
    /// Update-Device notification.
    ApsDecryptionFailure {
        source: Nwk,
        source_ieee: Eui64,
        frame_counter: u32,
        key_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct NetworkBeacon {
    pub channel: u8,
    pub source: Option<Nwk>,
    pub pan_id: PanId,
    pub extended_pan_id: Eui64,
    pub permit_joining: bool,
    pub stack_profile: u8,
    pub protocol_version: u8,
    pub router_capacity: bool,
    pub end_device_capacity: bool,
    pub device_depth: u8,
    pub update_id: u8,
    // Metadata that isn't part of a beacon
    pub lqi: u8,
    pub rssi: i8,
}

#[derive(Debug)]
pub struct ZigbeeStack<P: RadioPhy, R: Runtime = crate::runtime::TokioRuntime> {
    self_weak: Weak<Self>,

    /// The runtime clock baseline. `now` is converted to the sans-io [`CoreInstant`]
    /// (microseconds since this instant) at the one boundary that reads the clock.
    start_time: R::Instant,

    pub state: State,
    pub config: NetworkConfig,
    pub tunables: Tunables,
    pub radio: Arc<P>,
    notifications: Mutex<VecDeque<ZigbeeNotification>>,
    notification_wake: Notify,
    pub raw_frame_rx: AsyncMutex<P::RxStream>,
    pub reset_rx: AsyncMutex<P::ResetStream>,
    /// Whether a network scan is collecting. The receive loop only queues beacons while
    /// this is set, so stray beacons outside a scan are dropped.
    scan_active: AtomicBool,
    scan_beacons: Mutex<VecDeque<NetworkBeacon>>,
    scan_beacon_wake: Notify,

    /// Wakes the task that rewrites the RCP source address match table whenever the
    /// set of devices with queued indirect transactions changes
    pub(crate) src_match_sync: Notify,
    /// What the RCP source address match table currently holds, i.e. which polling
    /// devices were told (via frame-pending=1) to stay awake
    pub(crate) src_match_written: Mutex<SrcMatchTable>,
    /// When the last parent announcement was received; ours is deferred to avoid a
    /// network-wide broadcast storm (spec 2.4.3.1.12.2)
    pub(crate) parent_annce_received: Mutex<Option<CoreInstant>>,

    /// Wakes the MTORR scheduler before its max interval when accumulated route
    /// errors or delivery failures cross their thresholds
    pub(crate) mtorr_kick: Notify,

    /// Signaled whenever a link status command is digested; the MTORR startup wait
    /// uses it to advertise as soon as a neighbor link is established
    pub(crate) link_status_received: Notify,
    /// Wakes the broadcast-retransmit reactor: signaled on every recorded passive ack
    /// and whenever a broadcast is queued for retransmission.
    pub(crate) broadcast_retransmit_wake: Notify,
    /// Wakes the maintenance task when a new indirect transaction or child entry
    /// could move the earliest expiry deadline closer
    pub(crate) maintenance_wake: Notify,

    /// Outgoing frames awaiting the single sender task, ordered by priority then FIFO.
    /// The sender encrypts at dequeue, so frame-counter order matches on-air order.
    pub(crate) send_queue: Mutex<BinaryHeap<SendRequest>>,
    /// Wakes the sender task when a frame is enqueued.
    pub(crate) send_wake: Notify,
    /// Wakes the pending-route reactor when a frame is queued awaiting a route, or when a
    /// route is established for a destination with queued frames.
    pub(crate) pending_route_wake: Notify,
    /// Monotonic tiebreaker giving equal-priority sends FIFO order in `send_queue`.
    pub(crate) send_seq: AtomicU64,

    /// Spawns and owns the stack's background tasks, so that a replaced stack can be fully
    /// stopped: a leaked background task would keep the replaced stack processing frames
    /// and transmitting alongside its successor.
    spawner: R::Spawner,
}

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Briefly lock the protocol core. See [`CoreGuard`] for the locking discipline the
    /// returned guard encodes.
    fn core(&self) -> CoreGuard<'_> {
        CoreGuard(self.state.core.lock())
    }

    /// The sans-io core's clock reads as microseconds since this stack started. This
    /// converts the runtime clock to it, at the one boundary where the driver reads the
    /// clock; every driver-side deadline is then a [`CoreInstant`] and no reverse
    /// conversion is needed (deadlines are slept as a duration-from-now).
    fn to_core_instant(&self, t: R::Instant) -> CoreInstant {
        let micros = t.saturating_duration_since(self.start_time).as_micros();
        CoreInstant::from_micros(micros as u64)
    }

    fn core_now(&self) -> CoreInstant {
        self.to_core_instant(R::now())
    }

    /// Sleep until a [`CoreInstant`] deadline, computed as the remaining duration from
    /// now. Past deadlines resolve immediately.
    async fn sleep_until_core(&self, deadline: CoreInstant) {
        R::sleep(deadline.saturating_duration_since(self.core_now())).await;
    }

    /// Run `future`, failing with [`Elapsed`] if a [`CoreInstant`] deadline passes first.
    async fn timeout_at_core<F>(
        &self,
        deadline: CoreInstant,
        future: F,
    ) -> Result<F::Output, Elapsed>
    where
        F: Future + Send,
        F::Output: Send,
    {
        R::timeout(deadline.saturating_duration_since(self.core_now()), future).await
    }

    pub fn new(
        radio: Arc<P>,
        config: NetworkConfig,
        tunables: Tunables,
        spawner: R::Spawner,
    ) -> Arc<Self> {
        let raw_frame_rx = radio.subscribe_rx();
        let reset_rx = radio.subscribe_reset();

        Arc::new_cyclic(|weak_self| Self {
            self_weak: weak_self.clone(),
            start_time: R::now(),
            state: State::new(&config, &tunables),
            config,
            tunables,
            radio,
            notifications: Mutex::new(VecDeque::new()),
            notification_wake: Notify::new(),
            raw_frame_rx: AsyncMutex::new(raw_frame_rx),
            reset_rx: AsyncMutex::new(reset_rx),
            scan_active: AtomicBool::new(false),
            scan_beacons: Mutex::new(VecDeque::new()),
            scan_beacon_wake: Notify::new(),
            src_match_sync: Notify::new(),
            src_match_written: Mutex::new(SrcMatchTable::default()),
            parent_annce_received: Mutex::new(None),
            mtorr_kick: Notify::new(),
            link_status_received: Notify::new(),
            broadcast_retransmit_wake: Notify::new(),
            maintenance_wake: Notify::new(),
            send_queue: Mutex::new(BinaryHeap::new()),
            send_wake: Notify::new(),
            pending_route_wake: Notify::new(),
            send_seq: AtomicU64::new(0),
            spawner,
        })
    }

    /// Queue a network event and wake the notification drainer.
    pub(crate) fn push_notification(&self, notification: ZigbeeNotification) {
        self.notifications.lock().push_back(notification);
        self.notification_wake.notify_one();
    }

    /// Wait for and take all queued network events.
    pub async fn next_notifications(&self) -> Vec<ZigbeeNotification> {
        loop {
            let batch: Vec<ZigbeeNotification> = self.notifications.lock().drain(..).collect();
            if !batch.is_empty() {
                return batch;
            }
            self.notification_wake.notified().await;
        }
    }

    // This function intentionally holds locks across await points to maintain
    // exclusive access to shared state during frame processing.
    pub async fn run(&self) {
        loop {
            let (packet, ieee802154_frame) = self.recv_frame().await;

            if !matches!(
                ieee802154_frame,
                ziggurat_ieee_802154::Ieee802154Frame::Beacon(_)
            ) {
                // Allow through all IEEE 802.15.4 beacon frames
            } else if ieee802154_frame.header().src_address
                == Some(Ieee802154Address::Nwk(self.state.network_address))
            {
                tracing::debug!("Ignoring our own packet");
                continue;
            }

            match ieee802154_frame {
                ziggurat_ieee_802154::Ieee802154Frame::Data(ieee802154_data_frame) => {
                    let maybe_nwk_frame = self.process_802154_data_frame(
                        &ieee802154_data_frame,
                        packet.lqi,
                        packet.rssi,
                    );

                    if maybe_nwk_frame.is_none() {
                        continue;
                    }

                    let nwk_frame = maybe_nwk_frame.unwrap();

                    let Some(aps_payload) = nwk_frame.payload.as_opaque() else {
                        continue;
                    };

                    let (aps_frame, aps_source_eui64) = match parse_aps_frame(aps_payload) {
                        Ok(ApsFrame::Data(data)) => (data, None),
                        Ok(ApsFrame::EncryptedData(encrypted)) => {
                            match self.decrypt_aps_data_frame(&nwk_frame, &encrypted) {
                                Some((data, source_eui64)) => (data, Some(source_eui64)),
                                None => {
                                    tracing::warn!(
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
                                None => tracing::warn!(
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
                            tracing::warn!("Error parsing APS frame: {e:?}");
                            continue;
                        }
                    };

                    tracing::debug!("Received APS data frame: {aps_frame:?}");

                    // Spec 2.2.8.4.2: a retransmission is still acknowledged so the
                    // sender stops, but must not be delivered to the application twice.
                    let duplicate =
                        self.is_duplicate_aps_frame(nwk_frame.nwk_header.source, aps_frame.counter);

                    if aps_frame.frame_control.ack_request {
                        self.handle_aps_ack_request(&aps_frame, &nwk_frame, aps_source_eui64);
                    }

                    if duplicate {
                        tracing::debug!(
                            "Dropping duplicate APS frame (counter {}) from {:?}",
                            aps_frame.counter,
                            nwk_frame.nwk_header.source
                        );
                        continue;
                    }

                    // The ZDP commands that maintain stack state (the neighbor and
                    // address tables live here, not in the client) are consumed by
                    // the stack; the client still observes the frames
                    self.handle_zdp_frame(&nwk_frame, &aps_frame);

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
                    self.push_notification(notification);
                }
                ziggurat_ieee_802154::Ieee802154Frame::Ack(_ack_frame) => {}
                ziggurat_ieee_802154::Ieee802154Frame::Beacon(beacon_frame) => {
                    self.handle_beacon(&beacon_frame, packet.channel, packet.lqi, packet.rssi);
                }
                ziggurat_ieee_802154::Ieee802154Frame::Command(command_frame) => {
                    self.process_802154_command_frame(&command_frame);
                }
            }
        }
    }

    // We intentionally hold the receiver lock for the entire duration of this function
    // to ensure exclusive access to the raw frame receiver.
    #[allow(clippy::significant_drop_tightening)]
    async fn recv_frame(&self) -> (RxFrame, Ieee802154Frame) {
        let mut receiver = self
            .raw_frame_rx
            .try_lock()
            .expect("Raw frame receiver is locked");

        loop {
            let Some(packet) = receiver.recv().await else {
                panic!("Radio frame sender hung up");
            };

            match Ieee802154Frame::from_bytes_without_fcs(&packet.psdu) {
                Ok(frame) => {
                    tracing::debug!("Received 802.15.4 frame: {frame:?}");
                    return (packet, frame);
                }
                Err(e) => {
                    tracing::warn!("Error parsing IEEE 802.15.4 frame: {e:?}");
                    continue;
                }
            };
        }
    }

    pub async fn start_network(&self) -> Result<(), ZigbeeStackError> {
        self.reset_radio().await?;
        self.apply_radio_configuration().await?;

        // The single sender task drains the transmit queue; it must run before anything
        // enqueues a frame (the initial link status broadcast below would otherwise
        // block on a completion nobody resolves).
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.sender_task().await;
        });

        // Drains frames queued awaiting route discovery, and discards them when discovery
        // is exhausted. Must run before anything can queue one.
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.pending_route_task().await;
        });

        // Retransmits broadcasts until their passive-ack quorum is heard or attempts run
        // out. Must run before anything can queue a broadcast.
        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self.broadcast_retransmit_task().await;
        });

        // To kick things off, send a link status broadcast. Silicon Labs routers will
        // "respond" to empty link status broadcasts proactively, independent of the
        // link status period
        tracing::info!("Sending initial link status broadcast");
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
            self.radio.reset().await?;

            match R::timeout(RESET_NOTIFICATION_TIMEOUT, reset_rx.recv()).await {
                Ok(Some(event)) => {
                    tracing::info!("Radio reset complete: {:?}", event.reason);
                    return Ok(());
                }
                Ok(None) => return Err(RadioError::TransportClosed.into()),
                Err(_) => {
                    tracing::warn!("No reset notification, attempt {attempt}/{RESET_ATTEMPTS}");
                }
            }
        }

        Err(RadioError::Timeout.into())
    }

    /// Program the radio with our network parameters. A radio reset wipes all of this,
    /// so it must be re-applied after every reset.
    async fn apply_radio_configuration(&self) -> Result<(), ZigbeeStackError> {
        let (config, table) = {
            let core = self.core();
            let table = core
                .mac
                .indirect_queue
                .queued_addresses(core.nib.address_map.map());

            let config = RadioConfig {
                channel: core.mac.channel,
                tx_power: self.config.tx_power,
                short_address: self.state.network_address,
                extended_address: self.state.ieee_address,
                pan_id: core.mac.pan_id,
                promiscuous: self.state.hack_disable_tx,
                rx_on_when_idle: true,
                frame_pending_short: table.short_addresses.iter().copied().collect(),
                frame_pending_extended: table.extended_addresses.iter().copied().collect(),
            };

            drop(core);

            (config, table)
        };

        self.radio.reconfigure(&config).await?;

        *self.src_match_written.lock() = table;

        Ok(())
    }

    /// Watches for radio resets (announced or synthesized from persistent command
    /// timeouts) and reprograms the radio. Mesh state survives a radio reset; only the
    /// radio configuration needs to be re-applied.
    #[allow(clippy::significant_drop_tightening)]
    async fn radio_recovery_task(&self) {
        let mut reset_rx = self.reset_rx.try_lock().expect("Reset receiver is locked");

        loop {
            let Some(event) = reset_rx.recv().await else {
                panic!("Radio reset notification sender hung up");
            };

            tracing::error!(
                "Radio reset detected ({:?}), reinitializing the radio",
                event.reason
            );

            while let Err(err) = self.apply_radio_configuration().await {
                tracing::error!("Failed to reprogram the radio: {err}, retrying");
                R::sleep(RADIO_RECOVERY_RETRY_INTERVAL).await;
            }

            tracing::info!("Radio reprogrammed, resuming normal operation");
        }
    }

    /// Decode a received beacon and, if a network scan is in flight, collect it into
    /// the scan's outbox for the collector to drain. Beacons received outside a scan
    /// are dropped.
    fn handle_beacon(
        &self,
        beacon: &ziggurat_ieee_802154::Ieee802154BeaconFrame,
        channel: u8,
        lqi: u8,
        rssi: i8,
    ) {
        // Skip the decode entirely when no scan is collecting.
        if !self.scan_active.load(AtomicOrdering::Relaxed) {
            return;
        }

        let payload = match ZigbeeBeacon::from_abstract_bits(&beacon.beacon_payload) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::debug!("Ignoring non-Zigbee beacon: {e:?}");
                return;
            }
        };

        let source = match beacon.header.src_address {
            Some(Ieee802154Address::Nwk(nwk)) => Some(nwk),
            Some(Ieee802154Address::Eui64(_)) | None => None,
        };
        let Some(pan_id) = beacon.header.src_pan_id else {
            return;
        };

        let network_beacon = NetworkBeacon {
            channel,
            source,
            pan_id,
            extended_pan_id: payload.extended_pan_id,
            permit_joining: beacon.superframe_specification.association_permit,
            stack_profile: payload.stack_profile.value(),
            protocol_version: payload.protocol_version.value(),
            router_capacity: payload.router_capacity,
            end_device_capacity: payload.end_device_capacity,
            device_depth: payload.device_depth.value(),
            update_id: payload.update_id,
            lqi,
            rssi,
        };

        self.scan_beacons.lock().push_back(network_beacon);
        self.scan_beacon_wake.notify_one();
    }

    /// Open the beacon-collection window for an active scan.
    pub fn begin_network_scan(&self) {
        self.scan_beacons.lock().clear();
        self.scan_active.store(true, AtomicOrdering::Relaxed);
    }

    /// Active scan: broadcast a beacon request on each channel and dwell to collect
    /// beacons.
    pub async fn run_network_scan(
        &self,
        channels: &[u8],
        duration_per_channel: Duration,
    ) -> Result<(), ZigbeeStackError> {
        let beacon_request = self.beacon_request_psdu();
        let home_channel = self.core().mac.channel;

        let result: Result<(), RadioError> = async {
            let radio = self.radio.lock().await;
            for &channel in channels {
                radio.set_channel(channel).await?;
                radio
                    .transmit(TxFrame {
                        psdu: beacon_request.clone(),
                        channel: None,
                        csma_ca: true,
                        max_frame_retries: 0,
                        max_csma_backoffs: self.tunables.mac_max_csma_backoffs,
                        security_processed: true,
                    })
                    .await?;
                R::sleep(duration_per_channel).await;
            }
            // Leave the radio on the home channel before releasing it.
            radio.set_channel(home_channel).await
        }
        .await;

        // Close the window and wake the drainer so it delivers the last beacons and stops.
        self.scan_active.store(false, AtomicOrdering::Relaxed);
        self.scan_beacon_wake.notify_one();

        result.map_err(Into::into)
    }

    /// Wait for and take beacons collected so far by the active scan. Drains any
    /// remaining beacons even after the window closes, then returns empty once both
    /// the window is closed.
    pub async fn next_scan_beacons(&self) -> Vec<NetworkBeacon> {
        loop {
            let batch: Vec<NetworkBeacon> = self.scan_beacons.lock().drain(..).collect();
            if !batch.is_empty() {
                return batch;
            }
            if !self.scan_active.load(AtomicOrdering::Relaxed) {
                return Vec::new();
            }
            self.scan_beacon_wake.notified().await;
        }
    }

    /// One channel of an energy-detect scan: the maximum RSSI seen on `channel`. The
    /// manager loops over channels and streams the results; no radio state is held
    /// between calls.
    pub async fn energy_detect(
        &self,
        channel: u8,
        duration: Duration,
    ) -> Result<i8, ZigbeeStackError> {
        Ok(self.radio.energy_detect(channel, duration).await?)
    }

    /// Retune the radio to a new channel, the coordinator's half of a network-wide
    /// channel migration. Mesh state is untouched; subsequent resets and energy scans
    /// return to the new channel.
    pub async fn set_channel(&self, channel: u8) -> Result<(), ZigbeeStackError> {
        self.radio.lock().await.set_channel(channel).await?;
        self.core().mac.channel = channel;
        Ok(())
    }

    /// Update the `nwkUpdateId` advertised in our beacons, bumped alongside a channel
    /// migration so devices comparing network instances pick the current one.
    pub fn set_nwk_update_id(&self, update_id: u8) {
        self.core().nib.update_id = update_id;
    }

    /// Spawns a task tied to the stack's lifetime: it is stopped on `shutdown`.
    pub fn spawn_tracked<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawner.spawn(Box::pin(future));
    }

    /// Spawns a tracked task that needs an owned handle to the stack.
    fn spawn_tracked_self<F, Fut>(&self, f: F)
    where
        F: FnOnce(Arc<Self>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let this = self
            .self_weak
            .upgrade()
            .expect("stack dropped while running");

        self.spawn_tracked(f(this));
    }

    /// Stops all of the stack's tasks and waits for them to terminate, so that a
    /// replaced stack provably stops processing frames and transmitting before its
    /// successor takes over the shared Spinel client.
    pub async fn shutdown(&self) {
        self.spawner.shutdown().await;
    }

    pub fn next_aps_counter(&self) -> u8 {
        let mut core = self.core();
        core.aib.aps_counter = core.aib.aps_counter.wrapping_add(1);

        core.aib.aps_counter
    }

    pub fn next_nwk_frame_counter(&self) -> u32 {
        let advance = self.core().nib.nwk_security.next_outgoing_frame_counter();

        if advance.should_persist {
            self.push_notification(ZigbeeNotification::FrameCounterUpdate {
                frame_counter: advance.value,
            });
        }

        advance.value
    }
}
