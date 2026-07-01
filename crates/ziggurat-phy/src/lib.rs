//! Radio PHY abstraction.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::time::Duration;

use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};

/// A pull-based stream of events the backend delivers spontaneously (received frames,
/// reset notifications). `recv` resolves to `None` once the backend has shut down.
pub trait Receiver<T>: Send {
    fn recv(&mut self) -> impl Future<Output = Option<T>> + Send;
}

/// A frame to transmit. `psdu` is the serialized 802.15.4 frame; the backend supplies
/// or recomputes the FCS. `channel` overrides the current channel for this frame only.
#[derive(Debug, Clone)]
pub struct TxFrame {
    pub psdu: Vec<u8>,
    pub channel: Option<u8>,
    pub csma_ca: bool,
    pub max_frame_retries: u8,
    pub max_csma_backoffs: u8,
    pub security_processed: bool,
}

/// A received frame, normalized: `psdu` is the 802.15.4 frame with the FCS stripped.
#[derive(Debug, Clone)]
pub struct RxFrame {
    pub psdu: Vec<u8>,
    pub channel: u8,
    pub rssi: i8,
    pub lqi: u8,
    pub timestamp_us: u64,
}

/// The outcome of a transmit, after the radio's own MAC retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxResult {
    Acked,
    NoAck,
    ChannelAccessFailure,
    Aborted,
    Failed,
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

#[derive(Debug, thiserror::Error)]
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

pub trait RadioPhy: Send + Sync + 'static {
    /// Exclusive control of the radio, held for the guard's lifetime.
    type Exclusive<'a>: ExclusiveRadio + Send
    where
        Self: 'a;

    /// The backend's received-frame stream, handed out by [`subscribe_rx`].
    type RxStream: Receiver<RxFrame>;

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

    /// Open a fresh received-frame stream, redirecting delivery to it. Called once per
    /// driver instance; a later call supersedes the previous stream.
    fn subscribe_rx(&self) -> Self::RxStream;

    /// Open a fresh reset-notification stream, redirecting delivery to it.
    fn subscribe_reset(&self) -> Self::ResetStream;
}

/// Exclusive radio access, held via [`RadioPhy::lock`].
pub trait ExclusiveRadio: Send {
    fn set_channel(&self, channel: u8) -> impl Future<Output = Result<(), RadioError>> + Send;

    fn transmit(&self, frame: TxFrame)
    -> impl Future<Output = Result<TxResult, RadioError>> + Send;
}
