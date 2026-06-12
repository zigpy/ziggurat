use std::time::Duration;

use ieee_802154::types::Key;

use crate::aps::security::TclkSeed;
use crate::nwk::commands::EndDeviceTimeout;

#[derive(Debug)]
pub struct Constants {
    pub concentrator_radius: u8,
    pub stack_profile: u8,
    pub transaction_persistence_time: Duration,
    pub max_source_route: u8,
    pub max_children: u8,

    pub passive_ack_timeout: Duration,

    /// The maximum number of retries allowed after a broadcast transmission failure.
    pub max_broadcast_retries: u8,

    /// A broadcast with at least this many expected relayers is considered passively
    /// acknowledged once this many of them have been heard, instead of all of them.
    // TODO: replace the fixed quorum with probabilistic modeling of propagation,
    // e.g. per-neighbor estimates of how reliably we hear their rebroadcasts
    pub broadcast_passive_ack_quorum: usize,

    /// The minimum time between two consecutive many-to-one route requests, even when
    /// error thresholds are crossed.
    pub mtorr_min_interval: Duration,

    /// The maximum time between two consecutive many-to-one route requests; the
    /// baseline advertisement period.
    pub mtorr_max_interval: Duration,

    /// The number of received route-failure network status commands that triggers an
    /// early many-to-one route request.
    pub mtorr_route_error_threshold: u8,

    /// The number of locally failed unicast deliveries that triggers an early
    /// many-to-one route request.
    pub mtorr_delivery_failure_threshold: u8,

    /// The time between link status command frames.
    pub link_status_period: Duration,

    /// The number of missed link status command frames before resetting the link costs
    /// to zero.
    pub router_age_limit: u8,

    pub protocol_version: u8,
    pub route_discovery_time: Duration,
    pub max_broadcast_jitter: Duration,
    pub initial_rreq_retries: u8,
    pub rreq_retries: u8,
    pub rreq_retry_interval: Duration,
    pub min_rreq_jitter: Duration,
    pub max_rreq_jitter: Duration,
    pub max_depth: u8,
    pub unicast_retries: u8,
    pub unicast_retry_delay: Duration,
    pub min_router_bootstrap_jitter: Duration,
    pub max_router_bootstrap_jitter: Duration,
    pub broadcast_delivery_time: Duration,

    /// The default timeout for any end device child that does not negotiate a
    /// different value via the End Device Timeout Request command (spec 3.6.10.2).
    pub end_device_timeout_default: EndDeviceTimeout,

    /// `apsParentAnnounceBaseTimer`: the base delay before each broadcast parent
    /// announcement.
    pub parent_annce_base_timer: Duration,

    /// `apsParentAnnounceJitterMax`: the maximum random addition to
    /// [`Self::parent_annce_base_timer`].
    pub parent_annce_jitter_max: Duration,

    /// For most joins, the network key is encrypted with the well-known global link key
    pub global_link_key: Key,

    /// The TCLK seed of the stack the network was taken over from, if any: unique link
    /// keys are derived from it instead of generated randomly
    pub tclk_seed: Option<TclkSeed>,
}

impl Default for Constants {
    fn default() -> Self {
        Self::new()
    }
}

impl Constants {
    pub fn new() -> Self {
        Self {
            passive_ack_timeout: Duration::from_millis(500),
            max_broadcast_retries: 2,
            broadcast_passive_ack_quorum: 8,
            max_children: 32,
            max_depth: 15,
            max_source_route: 12,
            transaction_persistence_time: Duration::from_millis(7680),
            stack_profile: 2,
            concentrator_radius: 10,
            mtorr_min_interval: Duration::from_secs(10),
            mtorr_max_interval: Duration::from_secs(60),
            mtorr_route_error_threshold: 3,
            mtorr_delivery_failure_threshold: 1,
            link_status_period: Duration::from_secs(15),
            router_age_limit: 3,
            protocol_version: 2,
            route_discovery_time: Duration::from_millis(10000),
            max_broadcast_jitter: Duration::from_millis(64),
            initial_rreq_retries: 3,
            rreq_retries: 2,
            rreq_retry_interval: Duration::from_millis(254),
            min_rreq_jitter: Duration::from_millis(2),
            max_rreq_jitter: Duration::from_millis(128),
            unicast_retries: 3,
            unicast_retry_delay: Duration::from_millis(50),
            min_router_bootstrap_jitter: Duration::from_millis(500),
            max_router_bootstrap_jitter: Duration::from_millis(1000),
            broadcast_delivery_time: Duration::from_millis(9000),
            end_device_timeout_default: EndDeviceTimeout::Minutes256,
            parent_annce_base_timer: Duration::from_secs(10),
            parent_annce_jitter_max: Duration::from_secs(10),
            global_link_key: Key::from_hex("5a6967426565416c6c69616e63653039"),
            tclk_seed: None,
        }
    }
}
