//! [`RadioPhy`] implemented over OpenThread's link-raw API, for Ziggurat embedded inside
//! an OpenThread RCP firmware.
//!
//! The radio itself is owned by OpenThread: TX/RX/filtering go through the `otLinkRaw*`
//! surface of the otInstance handed to Ziggurat. This crate stays FFI-free — the
//! outbound operations enter through [`LinkOps`] (implemented by `ziggurat-ot` over the
//! C glue's import vtable, or by a simulator in host tests), and the inbound completions
//! arrive via [`deliver_rx`] / [`deliver_tx_result`] / [`deliver_energy_result`], called
//! from the firmware's link-raw callbacks. All callbacks run in OpenThread's main-loop
//! context, never from an ISR.
//!
//! FCS normalization (OT frames include the 2-byte FCS, ziggurat PSDUs never do) is the
//! glue's job: PSDUs on both sides of this crate exclude the FCS.
//!
//! Unlike `Efr32Phy` there is no software retry loop: `max_frame_retries` is handed to
//! the OT sub-MAC, which owns CSMA, retries, and ACK timing, so [`deliver_tx_result`]
//! reports the terminal outcome.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use core::time::Duration;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver as ChannelReceiver};
use embassy_sync::mutex::{Mutex, MutexGuard};
use embassy_sync::signal::Signal;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{
    ExclusiveRadio, RadioConfig, RadioError, RadioPhy, Receiver, ResetEvent, RxFrame, TxFrame,
    TxResult,
};

const RX_DEPTH: usize = 16;

/// The outbound radio operations, implemented over `otLinkRaw*` by the firmware glue
/// (or a simulator in host tests). Each call is a synchronous submit; completions come
/// back through the `deliver_*` functions.
pub trait LinkOps: Send + Sync {
    /// Apply the complete radio programming: addresses, PAN, channel, TX power,
    /// promiscuous mode, PAN-coordinator filtering (short address 0x0000), and enable
    /// receive. The frame-pending table is delivered separately via
    /// [`set_frame_pending_table`](Self::set_frame_pending_table).
    fn configure(&self, config: &RadioConfig) -> Result<(), RadioError>;

    /// Retune the receiver.
    fn set_channel(&self, channel: u8) -> Result<(), RadioError>;

    fn set_promiscuous(&self, promiscuous: bool) -> Result<(), RadioError>;

    /// Replace the source-match (frame-pending) table.
    fn set_frame_pending_table(&self, short: &[Nwk], extended: &[Eui64])
    -> Result<(), RadioError>;

    /// Submit one frame (PSDU without FCS). Completion arrives via
    /// [`deliver_tx_result`]; only one transmit is in flight at a time.
    fn transmit(
        &self,
        psdu: &[u8],
        channel: u8,
        csma_ca: bool,
        max_frame_retries: u8,
        max_csma_backoffs: u8,
    ) -> Result<(), RadioError>;

    /// Start an energy scan. Completion arrives via [`deliver_energy_result`].
    fn energy_scan(&self, channel: u8, duration: Duration) -> Result<(), RadioError>;
}

static RX_CHANNEL: Channel<CriticalSectionRawMutex, RxFrame, RX_DEPTH> = Channel::new();
static RESET_CHANNEL: Channel<CriticalSectionRawMutex, ResetEvent, 1> = Channel::new();
static TX_COMPLETE: Signal<CriticalSectionRawMutex, TxResult> = Signal::new();
static ENERGY_COMPLETE: Signal<CriticalSectionRawMutex, i8> = Signal::new();

/// The channel the receiver is currently tuned to, for stamping [`RxFrame::channel`]
/// and resolving per-frame channel overrides.
static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(0);
/// Diagnostics: total received frames handed to the queue, and frames dropped on a full
/// queue.
static RX_TOTAL: AtomicUsize = AtomicUsize::new(0);
static RX_DROPPED: AtomicUsize = AtomicUsize::new(0);

pub fn rx_total() -> usize {
    RX_TOTAL.load(Ordering::Relaxed)
}
pub fn rx_dropped() -> usize {
    RX_DROPPED.load(Ordering::Relaxed)
}

/// A frame was received (PSDU without FCS). Called from the link-raw receive-done path.
pub fn deliver_rx(psdu: &[u8], channel: u8, rssi: i8, lqi: u8, timestamp_us: u64) {
    let frame = RxFrame {
        psdu: psdu.to_vec(),
        channel,
        rssi,
        lqi,
        timestamp_us,
    };
    RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    if RX_CHANNEL.try_send(frame).is_err() {
        RX_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// The in-flight transmit finished. Called from the link-raw transmit-done path.
pub fn deliver_tx_result(result: TxResult) {
    TX_COMPLETE.signal(result);
}

/// The energy scan finished with this peak RSSI. Called from the energy-scan-done path.
pub fn deliver_energy_result(max_rssi_dbm: i8) {
    ENERGY_COMPLETE.signal(max_rssi_dbm);
}

/// Serializes access to the shared radio and tracks the last applied configuration.
struct RadioState {
    config: Option<RadioConfig>,
}

pub struct OtLinkPhy {
    ops: &'static dyn LinkOps,
    state: Mutex<CriticalSectionRawMutex, RadioState>,
    exclusive: Mutex<CriticalSectionRawMutex, ()>,
}

impl OtLinkPhy {
    pub const fn new(ops: &'static dyn LinkOps) -> Self {
        Self {
            ops,
            state: Mutex::new(RadioState { config: None }),
            exclusive: Mutex::new(()),
        }
    }

    async fn transmit_inner(&self, frame: &TxFrame) -> Result<TxResult, RadioError> {
        // Hold the radio lock across the completion wait: one transmit in flight.
        let _state = self.state.lock().await;
        let channel = frame
            .channel
            .unwrap_or_else(|| CURRENT_CHANNEL.load(Ordering::Relaxed));
        TX_COMPLETE.reset();
        self.ops.transmit(
            &frame.psdu,
            channel,
            frame.csma_ca,
            frame.max_frame_retries,
            frame.max_csma_backoffs,
        )?;
        Ok(TX_COMPLETE.wait().await)
    }
}

pub struct OtLinkRx(ChannelReceiver<'static, CriticalSectionRawMutex, RxFrame, RX_DEPTH>);

impl Receiver<RxFrame> for OtLinkRx {
    async fn recv(&mut self) -> Option<RxFrame> {
        Some(self.0.receive().await)
    }
}

pub struct OtLinkResetStream(ChannelReceiver<'static, CriticalSectionRawMutex, ResetEvent, 1>);

impl Receiver<ResetEvent> for OtLinkResetStream {
    async fn recv(&mut self) -> Option<ResetEvent> {
        Some(self.0.receive().await)
    }
}

pub struct OtLinkExclusive<'a> {
    phy: &'a OtLinkPhy,
    _guard: MutexGuard<'a, CriticalSectionRawMutex, ()>,
}

impl ExclusiveRadio for OtLinkExclusive<'_> {
    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let _state = self.phy.state.lock().await;
        CURRENT_CHANNEL.store(channel, Ordering::Relaxed);
        self.phy.ops.set_channel(channel)
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.phy.transmit_inner(&frame).await
    }

    async fn set_promiscuous(&self, promiscuous: bool) -> Result<(), RadioError> {
        let _state = self.phy.state.lock().await;
        self.phy.ops.set_promiscuous(promiscuous)
    }
}

impl RadioPhy for OtLinkPhy {
    type Exclusive<'a> = OtLinkExclusive<'a>;
    type RxStream = OtLinkRx;
    type ResetStream = OtLinkResetStream;

    async fn reset(&self) -> Result<(), RadioError> {
        // OpenThread owns the radio; there is nothing to reset. Synthesize the reset
        // notification the driver waits for.
        let _ = RESET_CHANNEL.try_send(ResetEvent {
            reason: alloc::string::String::from("otlink ready"),
        });
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let mut state = self.state.lock().await;
        CURRENT_CHANNEL.store(config.channel, Ordering::Relaxed);
        self.ops.set_frame_pending_table(
            &config.frame_pending_short,
            &config.frame_pending_extended,
        )?;
        self.ops.configure(config)?;
        state.config = Some(config.clone());
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        self.ops.set_frame_pending_table(short, extended)
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        // Wait behind any exclusive holder (e.g. a scan) so this can't retune mid-operation.
        let _exclusive = self.exclusive.lock().await;
        self.transmit_inner(&frame).await
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        let _state = self.state.lock().await;
        ENERGY_COMPLETE.reset();
        self.ops.energy_scan(channel, duration)?;
        let rssi = ENERGY_COMPLETE.wait().await;
        // Return the receiver to the home channel; OT leaves the radio wherever the
        // scan ended. Skip when no network has been configured yet (channel 0).
        let home = CURRENT_CHANNEL.load(Ordering::Relaxed);
        if home != 0 {
            self.ops.set_channel(home)?;
        }
        Ok(rssi)
    }

    async fn lock(&self) -> OtLinkExclusive<'_> {
        OtLinkExclusive {
            phy: self,
            _guard: self.exclusive.lock().await,
        }
    }

    fn subscribe_rx(&self) -> OtLinkRx {
        OtLinkRx(RX_CHANNEL.receiver())
    }

    fn subscribe_reset(&self) -> OtLinkResetStream {
        OtLinkResetStream(RESET_CHANNEL.receiver())
    }
}

// Compile-time proof that OtLinkPhy satisfies the full RadioPhy contract, including the
// `Send + Sync + 'static` supertrait and the `+ Send` bound on every returned future.
const _: () = {
    fn assert_radiophy<T: RadioPhy>() {}
    let _ = assert_radiophy::<OtLinkPhy>;
};
