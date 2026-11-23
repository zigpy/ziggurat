//! PHY abstraction: one 802.15.4 radio, plus secondary PHYs that carry 802.15.4
//! frames over other media.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::time::Duration;

use ziggurat_ieee_802154::Psdu;
use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};

/// A pull-based stream of events the backend delivers spontaneously (received frames,
/// reset notifications). `recv` resolves to `None` once the backend has shut down.
pub trait Receiver<T>: Send {
    fn recv(&mut self) -> impl Future<Output = Option<T>> + Send;
}

/// The MAC defaults of 802.15.4: `macMaxFrameRetries` and `macMaxCSMABackoffs`.
pub const DEFAULT_MAX_FRAME_RETRIES: u8 = 3;
pub const DEFAULT_MAX_CSMA_BACKOFFS: u8 = 4;

/// A frame to transmit. `psdu` is the 802.15.4 frame without the FCS; `channel`
/// overrides the current channel for this frame only.
#[derive(Debug, Clone)]
pub struct TxFrame {
    pub psdu: Psdu,
    pub channel: Option<u8>,
    pub csma_ca: bool,
    pub max_frame_retries: u8,
    pub max_csma_backoffs: u8,
    pub security_processed: bool,
    /// Transmit at a set time instead of as soon as possible
    pub tx_at: Option<TxAt>,
}

impl TxFrame {
    /// An untimed frame on the current channel, with CSMA-CA and the MAC defaults.
    pub const fn new(psdu: Psdu) -> Self {
        Self {
            psdu,
            channel: None,
            csma_ca: true,
            max_frame_retries: DEFAULT_MAX_FRAME_RETRIES,
            max_csma_backoffs: DEFAULT_MAX_CSMA_BACKOFFS,
            security_processed: true,
            tx_at: None,
        }
    }
}

/// When a timed transmit starts.
///
/// The end of its SFD is at `base_us + delay_us` on the radio clock, the clock of
/// [`RxFrame::timestamp_us`]. The radio sends a late frame at once, so the caller must
/// check the time before handing it over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxAt {
    pub base_us: u64,
    pub delay_us: u32,
}

/// A received frame, normalized: `psdu` is the 802.15.4 frame with the FCS stripped.
/// `channel` and `timestamp_us` belong to the radio; a secondary PHY sets them to 0.
#[derive(Debug, Clone)]
pub struct RxFrame {
    pub psdu: Psdu,
    pub channel: u8,
    pub rssi: i8,
    pub lqi: u8,
    pub timestamp_us: u64,
}

/// The outcome of a transmit, after the PHY's own retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxResult {
    /// Every receiver the frame was addressed to confirmed it
    Acked,
    /// A secondary PHY's broadcast that some of its peers did not confirm
    PartiallyAcked,
    /// No receiver the frame was addressed to confirmed it
    NoAck,
    /// Sent, but the medium cannot confirm it: an 802.15.4 frame that requests no ACK
    Sent,
    ChannelAccessFailure,
    Aborted,
    Failed,
}

/// The ACK Request bit of the first 802.15.4 frame control octet.
const ACK_REQUEST: u8 = 0x20;

impl TxResult {
    /// A radio reports every frame it sent as a success, but 802.15.4 confirms only a
    /// frame that requests an ACK: any other frame was only [`TxResult::Sent`].
    pub const fn for_radio_psdu(self, psdu: &[u8]) -> Self {
        match self {
            Self::Acked if psdu[0] & ACK_REQUEST == 0 => Self::Sent,
            other => other,
        }
    }
}

/// The full radio programming. Re-applied verbatim after a reset.
#[derive(Debug, Clone)]
pub struct RadioConfig {
    pub channel: u8,
    pub tx_power: i8,
    pub short_address: Nwk,
    pub extended_address: Eui64,
    pub pan_id: PanId,
    pub promiscuous: bool,
    pub rx_on_when_idle: bool,
    pub frame_pending_short: Vec<Nwk>,
    pub frame_pending_extended: Vec<Eui64>,
}

/// Notification that the radio reset itself. The backend has already reprogrammed it
/// from the last [`RadioConfig`]; this is for the driver's awareness.
#[derive(Debug, Clone)]
pub struct ResetEvent {
    pub reason: String,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RadioError {
    #[error("radio command timed out")]
    Timeout,
    #[error("radio transport closed")]
    TransportClosed,
    #[error("radio rejected the operation: {0}")]
    Rejected(String),
    #[error("radio error: {0}")]
    Other(String),
}

/// A medium that carries 802.15.4 frames: the radio, or a secondary PHY such as a
/// backbone over IP.
///
/// Every secondary PHY is a trusted link (Zigbee R23 4.3.1): it authenticates,
/// protects the integrity of, and encrypts what it carries, with its own replay
/// protection. The NWK frames it carries have no NWK security.
pub trait Phy: Send + Sync + 'static {
    /// The PHY's received-frame stream, handed out by [`subscribe_rx`].
    type RxStream: Receiver<RxFrame>;

    /// Transmit a frame with the PHY's own MAC parameters. `psdu` is without the FCS.
    ///
    /// A secondary PHY delivers a broadcast to every peer it knows, retrying each one,
    /// and reports [`TxResult::Acked`] only if every peer confirmed it. Which peers did
    /// not is the PHY's own business: it ages them out by its own rule.
    fn transmit_psdu(
        &self,
        psdu: Psdu,
    ) -> impl Future<Output = Result<TxResult, RadioError>> + Send;

    /// Open a fresh received-frame stream, redirecting delivery to it. Called once per
    /// driver instance; a later call supersedes the previous stream.
    fn subscribe_rx(&self) -> Self::RxStream;
}

/// The secondary PHY type of a node that has none.
#[derive(Debug)]
pub enum NoPhy {}

impl Receiver<RxFrame> for NoPhy {
    async fn recv(&mut self) -> Option<RxFrame> {
        unreachable!("NoPhy has no values")
    }
}

impl Phy for NoPhy {
    type RxStream = Self;

    async fn transmit_psdu(&self, _psdu: Psdu) -> Result<TxResult, RadioError> {
        unreachable!("NoPhy has no values")
    }

    fn subscribe_rx(&self) -> Self {
        unreachable!("NoPhy has no values")
    }
}

/// The 802.15.4 radio. Every node has one: joins, sleepy children, scans and timed
/// transmits need it.
pub trait RadioPhy: Phy {
    /// Exclusive control of the radio, held for the guard's lifetime.
    type Exclusive<'a>: ExclusiveRadio + Send
    where
        Self: 'a;

    /// The backend's reset-notification stream, handed out by [`subscribe_reset`].
    type ResetStream: Receiver<ResetEvent>;

    /// Reset the radio and wait for it to come back. Clears all configuration.
    fn reset(&self) -> impl Future<Output = Result<(), RadioError>> + Send;

    /// Apply the complete configuration atomically.
    fn reconfigure(
        &self,
        config: &RadioConfig,
    ) -> impl Future<Output = Result<(), RadioError>> + Send;

    fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> impl Future<Output = Result<(), RadioError>> + Send;

    /// Transmit a frame, blocking while the radio is held exclusively (see [`lock`]).
    fn transmit(&self, frame: TxFrame)
    -> impl Future<Output = Result<TxResult, RadioError>> + Send;

    /// Energy-detect one channel for `duration`, returning peak RSSI in dBm. Exclusive;
    /// returns to the home channel when done.
    fn energy_detect(
        &self,
        channel: u8,
        duration: Duration,
    ) -> impl Future<Output = Result<i8, RadioError>> + Send;

    /// Take exclusive control of the radio until the returned guard is dropped.
    fn lock(&self) -> impl Future<Output = Self::Exclusive<'_>> + Send;

    /// Open a fresh reset-notification stream, redirecting delivery to it.
    fn subscribe_reset(&self) -> Self::ResetStream;
}

/// Exclusive radio access, held via [`RadioPhy::lock`].
pub trait ExclusiveRadio: Send {
    fn set_channel(&self, channel: u8) -> impl Future<Output = Result<(), RadioError>> + Send;

    fn transmit(&self, frame: TxFrame)
    -> impl Future<Output = Result<TxResult, RadioError>> + Send;

    fn set_promiscuous(
        &self,
        promiscuous: bool,
    ) -> impl Future<Output = Result<(), RadioError>> + Send {
        async move {
            let _ = promiscuous;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radio_frame_without_ack_request_is_only_sent() {
        // Frame control 0x8841: a data frame without an ACK request
        assert_eq!(
            TxResult::Acked.for_radio_psdu(&[0x41, 0x88]),
            TxResult::Sent
        );
        // Frame control 0x8861: the same frame with an ACK request
        assert_eq!(
            TxResult::Acked.for_radio_psdu(&[0x61, 0x88]),
            TxResult::Acked
        );
        assert_eq!(
            TxResult::NoAck.for_radio_psdu(&[0x61, 0x88]),
            TxResult::NoAck
        );
    }
}
