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
use embassy_sync::mutex::{Mutex, MutexGuard};
use embassy_sync::signal::Signal;
use embassy_time::Timer;
use esp_hal::interrupt::{self, Priority};
use esp_hal::peripherals::{IEEE802154, Interrupt};
use esp_hal::system::Cpu;
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
static RESET_CHANNEL: Channel<CriticalSectionRawMutex, ResetEvent, 1> = Channel::new();
static RX_AVAILABLE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TX_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TX_FAILED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Direct IEEE802154 register access. esp-radio exposes neither an energy-detect API nor a
/// coex-disable, so we reach the memory-mapped registers ourselves (offsets/values per
/// ESP-IDF's `components/ieee802154`). esp-radio owns the peripheral, but the register block
/// is at a fixed address; we serialize with everything else through the radio `state` lock.
mod regs {
    const BASE: usize = 0x600A_3000;
    pub const CMD: usize = BASE + 0x00;
    pub const CHANNEL: usize = BASE + 0x48;
    pub const ED_DURATION: usize = BASE + 0x50;
    pub const ED_CFG: usize = BASE + 0x54;
    pub const EVENT_STATUS: usize = BASE + 0x64;
    pub const PTI: usize = BASE + 0x70;

    pub const CMD_RX_START: u32 = 0x42;
    pub const CMD_ED_START: u32 = 0x44;
    pub const CMD_STOP: u32 = 0x45;
    pub const EVENT_ED_DONE: u32 = 1 << 6;
    pub const ALL_EVENTS: u32 = 0x1FFF;
    /// `ed_cfg.ed_sample_mode`: 0 = report the peak (max) sample, 1 = average.
    pub const ED_SAMPLE_MODE: u32 = 1 << 13;
    /// `pti.pti` (bits 0..3) and `pti.hw_ack_pti` (bits 4..7), both set to 1 - ESP-IDF's
    /// `ieee802154_ll_disable_coex`: the radio always wins arbitration, so a non-existent
    /// coex partner can't gate (and starve) RX/TX/ED.
    pub const COEX_DISABLE: u32 = 0x11;

    pub unsafe fn read(addr: usize) -> u32 {
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    pub unsafe fn write(addr: usize, value: u32) {
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
    }
}

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
    exclusive: Mutex<CriticalSectionRawMutex, ()>,
}

impl EspPhy {
    pub fn new(peripheral: IEEE802154<'static>) -> Self {
        let mut radio = Ieee802154::new(peripheral);
        radio.set_rx_available_callback_fn(on_rx_available);
        radio.set_tx_done_callback_fn(on_tx_done);
        radio.set_tx_failed_callback_fn(on_tx_failed);

        // esp-radio enables coex PTI at init but never disables it, and there is no coex
        // partner running here.
        unsafe {
            let pti = regs::read(regs::PTI);
            regs::write(regs::PTI, (pti & !0xFF) | regs::COEX_DISABLE);
        }
        Self {
            state: Mutex::new(RadioState {
                radio,
                config: Config::default(),
            }),
            exclusive: Mutex::new(()),
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

fn raw_to_rx_frame(data: &[u8], channel: u8) -> Option<RxFrame> {
    let len = data[0] as usize;
    if len < 2 || 1 + len > data.len() {
        return None;
    }
    let psdu = &data[1..1 + len];
    let rssi = psdu[len - 2] as i8;
    let lqi = psdu[len - 1];
    Some(RxFrame {
        psdu: psdu[..len - 2].to_vec(),
        channel,
        rssi,
        lqi,
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

/// Force the receiver onto `channel`. esp-radio's `set_config` only updates the deferred
/// PIB (applied later by `pib_update` in rx/tx init), and `start_receive` no-ops while
/// already receiving - so a channel change otherwise never reaches a running receiver, which
/// keeps hearing the old channel. Write the frequency register directly (same mapping as
/// esp-radio's `channel_to_freq`), then stop + restart RX so the radio re-reads it. The RX
/// buffer a prior `start_receive` set up persists across this.
fn retune_rx(channel: u8) {
    let freq = u32::from((channel - 11) * 5 + 3);
    unsafe {
        let chan = regs::read(regs::CHANNEL);
        regs::write(regs::CHANNEL, (chan & !0x7F) | freq);
        regs::write(regs::CMD, regs::CMD_STOP);
        regs::write(regs::CMD, regs::CMD_RX_START);
    }
}

pub struct EspRx(ChannelReceiver<'static, CriticalSectionRawMutex, RxFrame, RX_DEPTH>);

impl Receiver<RxFrame> for EspRx {
    async fn recv(&mut self) -> Option<RxFrame> {
        Some(self.0.receive().await)
    }
}

/// Reset notifications: the native radio never spontaneously resets, so the only events
/// are the ones [`EspPhy::reset`] synthesizes when the driver asks for a reset.
pub struct EspReset(ChannelReceiver<'static, CriticalSectionRawMutex, ResetEvent, 1>);

impl Receiver<ResetEvent> for EspReset {
    async fn recv(&mut self) -> Option<ResetEvent> {
        Some(self.0.receive().await)
    }
}

pub struct EspExclusive<'a> {
    phy: &'a EspPhy,
    _guard: MutexGuard<'a, CriticalSectionRawMutex, ()>,
}

impl ExclusiveRadio for EspExclusive<'_> {
    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let mut state = self.phy.state.lock().await;
        state.config.channel = channel;
        let config = state.config;
        state.radio.set_config(config);
        // start_receive sets up the RX buffer the first time, but esp-radio no-ops it while
        // already receiving, so it won't retune a running receiver. Force the retune below.
        state.radio.start_receive();
        retune_rx(channel);
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.phy.transmit_inner(&frame).await
    }
}

impl RadioPhy for EspPhy {
    type Exclusive<'a> = EspExclusive<'a>;
    type RxStream = EspRx;
    type ResetStream = EspReset;

    async fn reset(&self) -> Result<(), RadioError> {
        // No external RCP to reset; reconfigure re-applies all state. The driver waits for
        // a reset notification afterward, so synthesize one.
        let _ = RESET_CHANNEL.try_send(ResetEvent {
            reason: String::from("esp radio ready"),
        });
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let mut state = self.state.lock().await;
        let channel = config.channel;
        state.config = esp_config(config);

        let esp = state.config;
        state.radio.set_config(esp);
        state.radio.start_receive();
        
        retune_rx(channel);

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
        // Wait behind any exclusive holder (a scan) so this transmit can't retune the radio
        // mid-scan.
        let _exclusive = self.exclusive.lock().await;
        self.transmit_inner(&frame).await
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        use regs::*;

        let mut state = self.state.lock().await;
        let home = state.config.channel;

        // Tune to the target channel (esp-radio maps channel -> RF frequency).
        state.config.channel = channel;
        let config = state.config;
        state.radio.set_config(config);

        // The hardware measures over `duration`, in 16 us symbol periods, latched into a
        // 24-bit field.
        let symbols = ((duration.as_micros() / 16) as u32).min(0x00FF_FFFF);

        // ED_DONE must stay enabled in the event mask for the hardware to latch the
        // completion, but esp-radio's ISR clears every event and has no ED handler, so it
        // would consume the completion (and could restart RX mid-measurement) before we
        // read it. Mask the MAC interrupt at the controller for the measurement instead:
        // the event still latches, we poll it, and the ISR cannot run.
        interrupt::disable(Cpu::current(), Interrupt::ZB_MAC);

        let rss = unsafe {
            write(CMD, CMD_STOP);
            write(EVENT_STATUS, ALL_EVENTS); // write-1-to-clear
            // Peak (max) sampling: report the strongest energy seen over the dwell, so a
            // mostly-idle channel with brief bursts still registers them (averaging would
            // wash them out to the noise floor). The driver wants peak channel energy.
            write(ED_CFG, read(ED_CFG) & !ED_SAMPLE_MODE);
            write(ED_DURATION, symbols);
            write(CMD, CMD_ED_START);

            // Wait out the dwell, then poll for the latched completion.
            Timer::after(embassy_time::Duration::from_micros(u64::from(symbols) * 16)).await;
            let mut remaining = 50;
            while read(EVENT_STATUS) & EVENT_ED_DONE == 0 && remaining > 0 {
                Timer::after(embassy_time::Duration::from_millis(1)).await;
                remaining -= 1;
            }

            let rss = ((read(ED_CFG) >> 16) & 0xFF) as i8;
            write(EVENT_STATUS, ALL_EVENTS);
            rss
        };

        interrupt::enable(Interrupt::ZB_MAC, Priority::Priority1);

        // Restore the home channel and resume receiving.
        state.config.channel = home;
        let config = state.config;
        state.radio.set_config(config);
        state.radio.start_receive();

        Ok(rss)
    }

    async fn lock(&self) -> EspExclusive<'_> {
        EspExclusive {
            phy: self,
            _guard: self.exclusive.lock().await,
        }
    }

    fn subscribe_rx(&self) -> EspRx {
        EspRx(RX_CHANNEL.receiver())
    }

    fn subscribe_reset(&self) -> EspReset {
        EspReset(RESET_CHANNEL.receiver())
    }
}

// Compile-time proof that EspPhy satisfies the full RadioPhy contract, including the
// `Send + Sync + 'static` supertrait and the `+ Send` bound on every returned future.
const _: () = {
    fn assert_radiophy<T: RadioPhy>() {}
    let _ = assert_radiophy::<EspPhy>;
};
