//! [`RadioPhy`] implemented over the ESP32-C6/H2 native 802.15.4 radio via esp-radio.
//!
//! esp-radio's driver is blocking + callback-driven and takes `&mut self`; this wraps it
//! in an embassy async mutex (so the trait's `&self` works) and turns its `fn()` TX/RX
//! callbacks into `Signal`s an async future can await.
//!
//! Scaffold status: structure is real (locking, signals, channels, software TX retry).
//! Gaps marked TODO: exact raw-frame field extraction, source-match (frame-pending) table,
//! and energy detect (esp-radio does not expose ED in its public API).

#![no_std]

extern crate alloc;

use alloc::string::String;
use core::time::Duration;

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver as ChannelReceiver};
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use esp_hal::peripherals::IEEE802154;
use esp_radio::ieee802154::{Config, Ieee802154};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{
    ExclusiveRadio, RadioConfig, RadioError, RadioPhy, Receiver, ResetEvent, RxFrame, TxFrame,
    TxResult,
};

const RX_DEPTH: usize = 16;

// There is exactly one IEEE802154 peripheral, so a single set of statics backs it. The
// esp-radio completion callbacks are plain `fn()` (no captures), so they must reach the
// async side through statics.
static RX_CHANNEL: Channel<CriticalSectionRawMutex, RxFrame, RX_DEPTH> = Channel::new();
static RX_AVAILABLE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TX_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TX_FAILED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

fn on_rx_available() {
    RX_AVAILABLE.signal(());
}
fn on_tx_done() {
    TX_DONE.signal(());
}
fn on_tx_failed() {
    TX_FAILED.signal(());
}

struct RadioState {
    radio: Ieee802154<'static>,
    config: Config,
}

pub struct EspPhy {
    state: Mutex<CriticalSectionRawMutex, RadioState>,
}

impl EspPhy {
    pub fn new(peripheral: IEEE802154<'static>) -> Self {
        let mut radio = Ieee802154::new(peripheral);
        radio.set_rx_available_callback_fn(on_rx_available);
        radio.set_tx_done_callback_fn(on_tx_done);
        radio.set_tx_failed_callback_fn(on_tx_failed);
        Self {
            state: Mutex::new(RadioState {
                radio,
                config: Config::default(),
            }),
        }
    }

    /// Drains received frames into the RX channel. The binary spawns this as a task; it
    /// wakes on the rx-available callback rather than busy-polling.
    pub async fn run_rx(&self) -> ! {
        loop {
            RX_AVAILABLE.wait().await;
            let mut state = self.state.lock().await;
            while let Some(raw) = state.radio.raw_received() {
                if let Some(frame) = raw_to_rx_frame(&raw.data, raw.channel) {
                    let _ = RX_CHANNEL.try_send(frame);
                }
            }
        }
    }

    async fn transmit_inner(&self, frame: &TxFrame) -> Result<TxResult, RadioError> {
        let retries = frame.max_frame_retries;
        let mut attempt = 0;
        loop {
            let result = {
                let mut state = self.state.lock().await;
                if let Some(channel) = frame.channel {
                    state.config.channel = channel;
                    let config = state.config;
                    state.radio.set_config(config);
                }
                TX_DONE.reset();
                TX_FAILED.reset();
                state
                    .radio
                    .transmit_raw(&frame.psdu, frame.csma_ca)
                    .map_err(|e| RadioError::Other(String::from(esp_err(e))))?;

                // Holds the radio lock across the completion wait, so RX is blocked for the
                // TX duration. TODO: release and reacquire instead.
                match select(TX_DONE.wait(), TX_FAILED.wait()).await {
                    Either::First(()) => {
                        if state.radio.get_ack_frame().is_some() {
                            TxResult::Acked
                        } else {
                            TxResult::NoAck
                        }
                    }
                    Either::Second(()) => TxResult::ChannelAccessFailure,
                }
            };

            match result {
                TxResult::NoAck if attempt < retries => attempt += 1,
                other => return Ok(other),
            }
        }
    }
}

/// esp-radio RX buffer layout: `data[0]` is the PSDU length, `data[1..][..len]` the PSDU
/// (FCS included), and the final PSDU byte carries the RSSI. We strip the 2-byte FCS.
fn raw_to_rx_frame(data: &[u8], channel: u8) -> Option<RxFrame> {
    let len = data[0] as usize;
    if len < 2 || 1 + len > data.len() {
        return None;
    }
    let psdu = &data[1..1 + len];
    let rssi = psdu[len - 1] as i8;
    Some(RxFrame {
        psdu: psdu[..len - 2].to_vec(),
        channel,
        rssi,
        lqi: esp_radio::ieee802154::rssi_to_lqi(rssi),
        timestamp_us: 0, // TODO: esp-radio does not surface a per-frame timestamp
    })
}

fn esp_config(config: &RadioConfig) -> Config {
    Config {
        channel: config.channel,
        txpower: config.tx_power,
        promiscuous: config.promiscuous,
        rx_when_idle: config.rx_on_when_idle,
        auto_ack_rx: true,
        auto_ack_tx: true,
        pan_id: Some(config.pan_id.0),
        short_addr: Some(config.short_address.as_u16()),
        ext_addr: Some(u64::from_le_bytes(config.extended_address.to_bytes())),
        ..Config::default()
    }
}

const fn esp_err(_e: esp_radio::ieee802154::Error) -> &'static str {
    "esp-radio transmit error"
}

pub struct EspRx(ChannelReceiver<'static, CriticalSectionRawMutex, RxFrame, RX_DEPTH>);

impl Receiver<RxFrame> for EspRx {
    async fn recv(&mut self) -> Option<RxFrame> {
        Some(self.0.receive().await)
    }
}

/// The native radio never spontaneously resets, so this stream never yields.
pub struct NeverReset;

impl Receiver<ResetEvent> for NeverReset {
    async fn recv(&mut self) -> Option<ResetEvent> {
        core::future::pending().await
    }
}

pub struct EspExclusive<'a> {
    phy: &'a EspPhy,
}

impl ExclusiveRadio for EspExclusive<'_> {
    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let mut state = self.phy.state.lock().await;
        state.config.channel = channel;
        let config = state.config;
        state.radio.set_config(config);
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.phy.transmit_inner(&frame).await
    }
}

impl RadioPhy for EspPhy {
    type Exclusive<'a> = EspExclusive<'a>;
    type RxStream = EspRx;
    type ResetStream = NeverReset;

    async fn reset(&self) -> Result<(), RadioError> {
        // No external RCP to reset; reconfigure re-applies all state.
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let mut state = self.state.lock().await;
        state.config = esp_config(config);
        let config = state.config;
        state.radio.set_config(config);
        state.radio.start_receive();
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        _short: &[Nwk],
        _extended: &[Eui64],
    ) -> Result<(), RadioError> {
        // TODO: esp-radio source-match via set_short_address(i, ..) + PendingMode.
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.transmit_inner(&frame).await
    }

    async fn energy_detect(&self, _channel: u8, _duration: Duration) -> Result<i8, RadioError> {
        // TODO: esp-radio does not expose ED scan; needs register access or an upstream PR.
        Err(RadioError::Other(String::from(
            "energy detect not supported by esp-radio",
        )))
    }

    async fn lock(&self) -> EspExclusive<'_> {
        EspExclusive { phy: self }
    }

    fn subscribe_rx(&self) -> EspRx {
        EspRx(RX_CHANNEL.receiver())
    }

    fn subscribe_reset(&self) -> NeverReset {
        NeverReset
    }
}

// Compile-time proof that EspPhy satisfies the full RadioPhy contract, including the
// `Send + Sync + 'static` supertrait and the `+ Send` bound on every returned future.
const _: () = {
    fn assert_radiophy<T: RadioPhy>() {}
    let _ = assert_radiophy::<EspPhy>;
};
