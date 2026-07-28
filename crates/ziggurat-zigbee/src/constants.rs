use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize};
use core::time::Duration;

use num_enum::TryFromPrimitive;

use ziggurat_ieee_802154::types::Key;

use crate::nwk::commands::EndDeviceTimeout;

/// `nwkcProtocolVersion`: the NWK protocol version carried in every frame.
pub const PROTOCOL_VERSION: u8 = 2;

/// The stack profile advertised in beacons: 2 is Zigbee PRO.
pub const STACK_PROFILE: u8 = 2;

/// The maximum network depth in stack profile 2 (Zigbee PRO); the default frame
/// radius is twice this.
pub const MAX_DEPTH: u8 = 15;

/// The well-known global link key most joins encrypt the network key with.
pub const WELL_KNOWN_LINK_KEY: Key = Key::from_string(b"ZigBeeAlliance09");

/// A tunable set that failed: the driver maps these onto a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunableError {
    UnknownName,
    InvalidValue,
    /// The value feeds startup-only sizing (the frame budget) and cannot change on a
    /// live stack.
    StartupOnly,
}

impl fmt::Display for TunableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownName => "unknown tunable",
            Self::InvalidValue => "value out of range",
            Self::StartupOnly => "tunable only applies at configure time",
        })
    }
}

/// A `Duration` stored as atomic microseconds, so tunables need no lock.
///
/// The `u32` backing (the widest atomic on every target, including the 32-bit MCUs)
/// caps it at ~71.6 minutes; every protocol timer is seconds-scale.
pub struct AtomicDuration(AtomicU32);

impl AtomicDuration {
    pub const fn new(duration: Duration) -> Self {
        Self(AtomicU32::new(duration.as_micros() as u32))
    }

    pub fn load(&self) -> Duration {
        Duration::from_micros(self.0.load(Relaxed).into())
    }

    pub fn store(&self, duration: Duration) {
        self.0.store(duration.as_micros() as u32, Relaxed);
    }
}

impl fmt::Debug for AtomicDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.load(), f)
    }
}

/// An enum stored as its `u8` discriminant in an atomic.
pub struct AtomicEnum<T>(AtomicU8, PhantomData<T>);

impl<T: Copy + Into<u8> + TryFromPrimitive<Primitive = u8>> AtomicEnum<T> {
    pub fn new(value: T) -> Self {
        Self(AtomicU8::new(value.into()), PhantomData)
    }

    pub fn load(&self) -> T {
        // Only `store` writes here, so the discriminant is always valid.
        T::try_from_primitive(self.0.load(Relaxed)).unwrap_or_else(|_| unreachable!())
    }

    pub fn store(&self, value: T) {
        self.0.store(value.into(), Relaxed);
    }
}

impl<T: Copy + Into<u8> + TryFromPrimitive<Primitive = u8> + fmt::Debug> fmt::Debug
    for AtomicEnum<T>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.load(), f)
    }
}

/// A [`Tunables`] field type.
///
/// Defines how the type is stored atomically and how it decodes from the wire's
/// `u64` value (bools are 0/1, durations are microseconds, enums are their
/// discriminant). `decode` rejects anything out of range.
pub trait TunableValue: Sized {
    type Atomic;

    fn new_atomic(value: Self) -> Self::Atomic;
    fn load(atomic: &Self::Atomic) -> Self;
    fn store(value: Self, atomic: &Self::Atomic);
    fn decode(raw: u64) -> Option<Self>;
}

impl TunableValue for u8 {
    type Atomic = AtomicU8;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicU8::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load(Relaxed)
    }

    fn store(value: Self, atomic: &Self::Atomic) {
        atomic.store(value, Relaxed);
    }

    fn decode(raw: u64) -> Option<Self> {
        Self::try_from(raw).ok()
    }
}

impl TunableValue for usize {
    type Atomic = AtomicUsize;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicUsize::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load(Relaxed)
    }

    fn store(value: Self, atomic: &Self::Atomic) {
        atomic.store(value, Relaxed);
    }

    fn decode(raw: u64) -> Option<Self> {
        Self::try_from(raw).ok()
    }
}

impl TunableValue for bool {
    type Atomic = AtomicBool;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicBool::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load(Relaxed)
    }

    fn store(value: Self, atomic: &Self::Atomic) {
        atomic.store(value, Relaxed);
    }

    fn decode(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl TunableValue for Duration {
    type Atomic = AtomicDuration;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicDuration::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load()
    }

    fn store(value: Self, atomic: &Self::Atomic) {
        atomic.store(value);
    }

    fn decode(raw: u64) -> Option<Self> {
        // Bound the microseconds to the `AtomicDuration` backing width.
        u32::try_from(raw)
            .ok()
            .map(|micros| Self::from_micros(micros.into()))
    }
}

impl TunableValue for EndDeviceTimeout {
    type Atomic = AtomicEnum<Self>;

    fn new_atomic(value: Self) -> Self::Atomic {
        AtomicEnum::new(value)
    }

    fn load(atomic: &Self::Atomic) -> Self {
        atomic.load()
    }

    fn store(value: Self, atomic: &Self::Atomic) {
        atomic.store(value);
    }

    fn decode(raw: u64) -> Option<Self> {
        Self::try_from_primitive(u8::try_from(raw).ok()?).ok()
    }
}

/// Defines [`Tunables`] once: the struct, its defaults, the typed getters, and the
/// by-field-name `set` used by the `SetTunable` protocol command all come from this
/// single field list.
macro_rules! tunables {
    ($($(#[$attr:meta])* $name:ident: $ty:ty = $default:expr,)*) => {
        /// Protocol parameters and policy knobs, initialized to spec-derived defaults.
        ///
        /// Unlike the module-level constants above, every field here is tweakable at
        /// runtime: values are stored atomically and read at each use, so a `set`
        /// takes effect on the next read (in-flight waits and stamped deadlines
        /// finish under the value they started with).
        #[derive(Debug)]
        pub struct Tunables {
            $($name: <$ty as TunableValue>::Atomic,)*
        }

        impl Default for Tunables {
            fn default() -> Self {
                Self {
                    $($name: <$ty as TunableValue>::new_atomic($default),)*
                }
            }
        }

        impl Tunables {
            $(
                $(#[$attr])*
                pub fn $name(&self) -> $ty {
                    <$ty as TunableValue>::load(&self.$name)
                }
            )*

            /// Set a tunable from its Rust field name and a raw wire value.
            pub fn set(&self, name: &str, raw: u64) -> Result<(), TunableError> {
                match name {
                    $(stringify!($name) => {
                        let value = <$ty as TunableValue>::decode(raw)
                            .ok_or(TunableError::InvalidValue)?;
                        <$ty as TunableValue>::store(value, &self.$name);
                    })*
                    _ => return Err(TunableError::UnknownName),
                }
                Ok(())
            }
        }
    };
}

tunables! {
    concentrator_radius: u8 = 10,
    transaction_persistence_time: Duration = Duration::from_millis(7680),
    max_source_route: u8 = 12,
    max_children: u8 = 32,

    /// Trust center policy: allow an unsecured (trust center) rejoin from a device that
    /// has not established a unique link key. Off by default — such a rejoin
    /// re-delivers the network key encrypted with the well-known key, exposing it to
    /// anyone who knows that key (spec 4.7.3.6).
    allow_unsecured_rejoins: bool = false,

    /// Trust center policy: accept an Update-Device command that is not APS-encrypted
    /// from a router with which we share a unique trust center link key. Off by default
    /// (spec Table 4-7 requires APS encryption in that case).
    allow_unencrypted_router_device_update: bool = false,

    passive_ack_timeout: Duration = Duration::from_millis(500),

    /// The maximum number of retries allowed after a broadcast transmission failure.
    max_broadcast_retries: u8 = 2,

    /// A broadcast with at least this many expected relayers is considered passively
    /// acknowledged once this many of them have been heard, instead of all of them.
    // TODO: replace the fixed quorum with probabilistic modeling of propagation,
    // e.g. per-neighbor estimates of how reliably we hear their rebroadcasts
    broadcast_passive_ack_quorum: usize = 8,

    /// The minimum time between two consecutive many-to-one route requests, even when
    /// error thresholds are crossed.
    mtorr_min_interval: Duration = Duration::from_secs(10),

    /// The maximum time between two consecutive many-to-one route requests; the
    /// baseline advertisement period.
    mtorr_max_interval: Duration = Duration::from_secs(60),

    /// The number of received route-failure network status commands that triggers an
    /// early many-to-one route request.
    mtorr_route_error_threshold: u8 = 3,

    /// The number of locally failed unicast deliveries that triggers an early
    /// many-to-one route request.
    mtorr_delivery_failure_threshold: u8 = 1,

    /// The time between link status command frames.
    link_status_period: Duration = Duration::from_secs(15),

    /// The number of missed link status command frames before resetting the link costs
    /// to zero.
    router_age_limit: u8 = 3,

    route_discovery_time: Duration = Duration::from_millis(10000),
    max_broadcast_jitter: Duration = Duration::from_millis(64),
    initial_rreq_retries: u8 = 3,
    rreq_retries: u8 = 2,
    rreq_retry_interval: Duration = Duration::from_millis(254),
    min_rreq_jitter: Duration = Duration::from_millis(2),
    max_rreq_jitter: Duration = Duration::from_millis(128),
    unicast_retries: u8 = 3,
    unicast_retry_delay: Duration = Duration::from_millis(50),
    broadcast_delivery_time: Duration = Duration::from_millis(9000),

    /// How many route discoveries a frame parked awaiting a route will trigger before
    /// it is discarded. `1` (the default) means a single discovery: if it fails, every
    /// frame waiting on that destination inherits the failure. Higher values keep the
    /// parked frames waiting while discovery is retried, the whole bucket riding along
    /// together.
    pending_route_discovery_attempts: u8 = 1,

    /// The default timeout for any end device child that does not negotiate a
    /// different value via the End Device Timeout Request command (spec 3.6.10.2).
    end_device_timeout_default: EndDeviceTimeout = EndDeviceTimeout::Minutes256,

    /// `apsParentAnnounceBaseTimer`: the base delay before each broadcast parent
    /// announcement.
    parent_annce_base_timer: Duration = Duration::from_secs(10),

    /// `apsParentAnnounceJitterMax`: the maximum random addition to
    /// [`Self::parent_annce_base_timer`].
    parent_annce_jitter_max: Duration = Duration::from_secs(10),

    /// Spec 2.2.8.4.2: how long an (originator, APS counter) pair is remembered for
    /// duplicate rejection. Must cover the sender's full APS retransmission window.
    aps_duplicate_rejection_timeout: Duration = Duration::from_secs(9),

    aps_ack_timeout: Duration = Duration::from_millis(5000),

    /// APS acks from a sleepy child arrive only after it polls for the frame, so the
    /// wait must cover a full indirect transaction lifetime (7.68s) plus the ack's trip
    /// back.
    aps_ack_timeout_indirect: Duration = Duration::from_millis(10000),

    /// `macMaxCSMABackoffs`: how many times the radio backs off on a busy channel
    /// before declaring a transmit failed.
    mac_max_csma_backoffs: u8 = 2,

    /// `macMaxFrameRetries`: how many times the radio retransmits a unicast that goes
    /// unacknowledged before declaring it failed.
    mac_max_frame_retries: u8 = 5,

    /// Bytes of heap the driver may hold in parked frames. 0 derives it from the
    /// platform's heap arena minus a worst-case ceiling for everything else.
    frame_budget_bytes: usize = 0,

    /// Frame tokens only stack-critical traffic may use.
    critical_reserve_frames: usize = 32,

    /// Frame tokens reserved for transit traffic, so a host flood cannot stop the
    /// device from routing.
    forwarding_reserve_frames: usize = 16,

    /// Broadcast admission budget: a token bucket shared across traffic classes,
    /// mirroring the frame budget above but bounding broadcast *rate*.
    broadcast_budget_tokens: u8 = 40,

    /// Time to regenerate one broadcast token; the reciprocal is the sustained
    /// admission rate (~1.48/s here).
    broadcast_token_refill: Duration = Duration::from_millis(675),

    /// Broadcast tokens only stack-critical broadcasts (route discovery, key updates,
    /// leaves, ZDO management) may draw; a host flood can never consume them.
    broadcast_critical_reserve: u8 = 3,

    /// Broadcast tokens reserved for relayed (transit) broadcasts above the host floor,
    /// so a host flood cannot stop us relaying the mesh's own broadcasts.
    broadcast_forwarding_reserve: u8 = 2,
}
