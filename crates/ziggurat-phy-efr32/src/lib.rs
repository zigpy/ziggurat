//! [`RadioPhy`] implemented over Silicon Labs RAIL on the EFR32MG24.
//!
//! RAIL is callback-driven from radio IRQ context: the one `events_callback` registered at
//! [`sl_rail_init`] fires for RX completion and TX/ACK completion. This wraps that in an
//! embassy async layer — the callback copies received frames into a [`Channel`] and posts
//! TX results to a [`Signal`] an async future awaits. Unlike the ESP backend, RAIL performs
//! CSMA-CA and ACK timing in hardware, so no software backoff / `embassy-time` is needed.
//!
//! Prerequisites the board binary must provide before [`Efr32Phy::new`] (mirrors how the ESP
//! backend takes an already-initialized peripheral): the clock tree up (HFXO via the SDK
//! clock manager), the radio IRQ vectors wired to the RAIL blob's `*_IRQHandler`, a global
//! allocator, and an async executor to poll the returned futures.
//!
//! Scaffold status: RX, reconfigure, and transmit are real. Gaps marked TODO: per-frame
//! RSSI/LQI/timestamp extraction, the frame-pending (source-match) table, and energy detect.

#![no_std]

extern crate alloc;

use alloc::string::String;
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
use ziggurat_rail_sys as rail;

const RX_DEPTH: usize = 16;
const TX_FIFO_WORDS: usize = 32; // 128 bytes, RAIL's minimum/typical 802.15.4 TX FIFO

// RAIL event bits (bindgen only emits the `_SHIFT` values; the bitmask macros are skipped).
mod events {
    use ziggurat_rail_sys::sl_rail_events_t_enum as e;
    pub const RX_PACKET_RECEIVED: u64 = 1 << e::SL_RAIL_EVENT_RX_PACKET_RECEIVED_SHIFT as u64;
    pub const TX_PACKET_SENT: u64 = 1 << e::SL_RAIL_EVENT_TX_PACKET_SENT_SHIFT as u64;
    pub const TX_CHANNEL_BUSY: u64 = 1 << e::SL_RAIL_EVENT_TX_CHANNEL_BUSY_SHIFT as u64;
    pub const TX_ABORTED: u64 = 1 << e::SL_RAIL_EVENT_TX_ABORTED_SHIFT as u64;
    pub const TX_BLOCKED: u64 = 1 << e::SL_RAIL_EVENT_TX_BLOCKED_SHIFT as u64;
    pub const TX_UNDERFLOW: u64 = 1 << e::SL_RAIL_EVENT_TX_UNDERFLOW_SHIFT as u64;
    pub const RX_ACK_TIMEOUT: u64 = 1 << e::SL_RAIL_EVENT_RX_ACK_TIMEOUT_SHIFT as u64;
    pub const RX_FIFO_OVERFLOW: u64 = 1 << e::SL_RAIL_EVENT_RX_FIFO_OVERFLOW_SHIFT as u64;
    pub const CAL_NEEDED: u64 = 1 << e::SL_RAIL_EVENT_CAL_NEEDED_SHIFT as u64;

    /// Everything the backend acts on.
    pub const SUBSCRIBED: u64 = RX_PACKET_RECEIVED
        | RX_FIFO_OVERFLOW
        | TX_PACKET_SENT
        | TX_CHANNEL_BUSY
        | TX_ABORTED
        | TX_BLOCKED
        | TX_UNDERFLOW
        | RX_ACK_TIMEOUT
        | CAL_NEEDED;
}

const TX_OPTION_WAIT_FOR_ACK: u64 =
    1 << rail::sl_rail_tx_options_t_enum::SL_RAIL_TX_OPTION_WAIT_FOR_ACK_SHIFT as u64;

const RX_PACKET_HANDLE_OLDEST_COMPLETE: rail::sl_rail_rx_packet_handle_t =
    2 as rail::sl_rail_rx_packet_handle_t;
// sl_rail_rx_packet_status_t values.
const RX_PACKET_NONE: u32 = 0;
const RX_PACKET_READY_SUCCESS: u32 = 7;
// SL_RAIL_RF_STATE_RX: keep the radio receiving after each operation.
const RF_STATE_RX: rail::sl_rail_radio_state_t = 2 as rail::sl_rail_radio_state_t;

/// 802.15.4-2003 2.4 GHz OQPSK CSMA-CA parameters (from the SDK's
/// `SL_RAIL_CSMA_CONFIG_802_15_4_2003_2P4_GHZ_OQPSK_CSMA` initializer).
fn csma_802154() -> rail::sl_rail_csma_config_t {
    rail::sl_rail_csma_config_t {
        csma_min_bo_exp: 3,
        csma_max_bo_exp: 5,
        csma_tries: 5,
        cca_threshold_dbm: -75,
        cca_backoff_us: 320,
        cca_duration_us: 128,
        csma_timeout_us: 0,
    }
}

// One radio, so a single set of statics backs it; the RAIL callback (plain `extern "C"`,
// no captures) reaches the async side only through them.
static RX_CHANNEL: Channel<CriticalSectionRawMutex, RxFrame, RX_DEPTH> = Channel::new();
static RESET_CHANNEL: Channel<CriticalSectionRawMutex, ResetEvent, 1> = Channel::new();
static TX_COMPLETE: Signal<CriticalSectionRawMutex, TxResult> = Signal::new();

/// The real RAIL handle from [`sl_rail_init`], stored as a `usize` so the callback and the
/// async methods can recover it. 0 until initialized.
static RAIL_HANDLE: AtomicUsize = AtomicUsize::new(0);
/// The channel the receiver is currently tuned to, for stamping [`RxFrame::channel`].
static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(0);

/// Static TX FIFO. RAIL requires a persistent, word-aligned backing buffer.
static mut TX_FIFO: [u32; TX_FIFO_WORDS] = [0; TX_FIFO_WORDS];

fn handle() -> rail::sl_rail_handle_t {
    RAIL_HANDLE.load(Ordering::Relaxed) as rail::sl_rail_handle_t
}

/// The initialized RAIL handle, or null before [`Efr32Phy::new`]. Exposed so a board's
/// embassy-time driver can drive RAIL's microsecond timer / multi-timer.
pub fn rail_handle() -> rail::sl_rail_handle_t {
    handle()
}

/// RAIL event callback, invoked from radio IRQ context.
unsafe extern "C" fn on_rail_event(rail_handle: rail::sl_rail_handle_t, events: rail::sl_rail_events_t) {
    let events = events as u64;

    // Drain the ENTIRE RX queue on a receive or FIFO-overflow event. On a busy network the
    // radio queues several packets per interrupt (and the byte FIFO overflows and stalls RX
    // if not drained promptly), so reading a single packet per event drops almost everything.
    if events & (self::events::RX_PACKET_RECEIVED | self::events::RX_FIFO_OVERFLOW) != 0 {
        loop {
            let mut info: rail::sl_rail_rx_packet_info_t = unsafe { core::mem::zeroed() };
            let handle = unsafe {
                rail::sl_rail_get_rx_packet_info(rail_handle, RX_PACKET_HANDLE_OLDEST_COMPLETE, &mut info)
            };
            if info.packet_status as u32 == RX_PACKET_NONE {
                break; // queue drained
            }
            if info.packet_status as u32 == RX_PACKET_READY_SUCCESS && info.packet_bytes >= 1 {
                let mut details: rail::sl_rail_rx_packet_details_t = unsafe { core::mem::zeroed() };
                unsafe { rail::sl_rail_get_rx_packet_details(rail_handle, handle, &mut details) };
                // RAIL hands us [PHR length byte][MAC frame without FCS].
                let mut buf = [0u8; 128];
                let n = core::cmp::min(info.packet_bytes as usize, buf.len());
                unsafe { rail::sl_rail_copy_rx_packet(rail_handle, buf.as_mut_ptr(), &info) };
                let frame = RxFrame {
                    psdu: buf[1..n].to_vec(), // drop the PHR length byte
                    channel: CURRENT_CHANNEL.load(Ordering::Relaxed),
                    rssi: details.rssi_dbm,
                    lqi: details.lqi,
                    timestamp_us: u64::from(details.time_received.packet_time),
                };
                let _ = RX_CHANNEL.try_send(frame);
            }
            // Release to advance the queue and free FIFO space.
            unsafe { rail::sl_rail_release_rx_packet(rail_handle, handle) };
        }
    }

    // TX/ACK completion. RAIL with WAIT_FOR_ACK reports TX_PACKET_SENT only once the ACK is
    // received (success) and RX_ACK_TIMEOUT when none arrives.
    let tx_result = if events & self::events::TX_PACKET_SENT != 0 {
        Some(TxResult::Acked)
    } else if events & self::events::RX_ACK_TIMEOUT != 0 {
        Some(TxResult::NoAck)
    } else if events & self::events::TX_CHANNEL_BUSY != 0 {
        Some(TxResult::ChannelAccessFailure)
    } else if events & (self::events::TX_ABORTED | self::events::TX_BLOCKED) != 0 {
        Some(TxResult::Aborted)
    } else if events & self::events::TX_UNDERFLOW != 0 {
        Some(TxResult::Failed)
    } else {
        None
    };
    if let Some(result) = tx_result {
        TX_COMPLETE.signal(result);
    }

    if events & self::events::CAL_NEEDED != 0 {
        unsafe {
            rail::sl_rail_calibrate(
                rail_handle,
                core::ptr::null_mut(),
                rail::SL_RAIL_CAL_ALL_PENDING as rail::sl_rail_cal_mask_t,
            )
        };
    }
}

/// Serializes access to the shared radio and tracks the last applied configuration.
struct RadioState {
    config: Option<RadioConfig>,
}

pub struct Efr32Phy {
    state: Mutex<CriticalSectionRawMutex, RadioState>,
    exclusive: Mutex<CriticalSectionRawMutex, ()>,
}

impl Efr32Phy {
    /// Initialize RAIL for 2.4 GHz 802.15.4 and register the event callback. The board must
    /// have brought up clocks and wired the radio IRQ vectors first (see module docs).
    pub fn new() -> Self {
        unsafe {
            let mut config: rail::sl_rail_config_t = core::mem::zeroed();
            config.events_callback = Some(on_rail_event);
            config.rx_packet_queue_entries = rail::sl_rail_builtin_rx_packet_queue_entries;
            config.p_rx_packet_queue = rail::sl_rail_builtin_rx_packet_queue_ptr;
            config.rx_fifo_bytes = rail::sl_rail_builtin_rx_fifo_bytes;
            config.p_rx_fifo_buffer = rail::sl_rail_builtin_rx_fifo_ptr;

            let mut h: rail::sl_rail_handle_t = 0xFFFF_FFFF as rail::sl_rail_handle_t;
            rail::sl_rail_init(&mut h, &config, None);
            rail::sl_rail_config_cal(h, rail::SL_RAIL_CAL_ALL as _);

            let mut ieee: rail::sl_rail_ieee802154_config_t = core::mem::zeroed();
            ieee.frames_mask = (rail::SL_RAIL_IEEE802154_ACCEPT_STANDARD_FRAMES
                | rail::SL_RAIL_IEEE802154_ACCEPT_ACK_FRAMES) as u8;
            ieee.timings.idle_to_rx = 100;
            ieee.timings.tx_to_rx = 182;
            ieee.timings.idle_to_tx = 100;
            ieee.timings.rx_to_tx = 192;
            ieee.ack_config.enable = true;
            ieee.ack_config.ack_timeout_us = 672;
            // Stay in RX after every RX/TX/ACK. Left at 0 (INACTIVE) the radio drops to idle
            // after the first received+acked frame and stops receiving — catching almost
            // nothing on a busy network.
            let stay_rx = rail::sl_rail_state_transitions_t {
                success: RF_STATE_RX,
                error: RF_STATE_RX,
            };
            ieee.ack_config.rx_transitions = stay_rx;
            ieee.ack_config.tx_transitions = stay_rx;
            rail::sl_rail_ieee802154_init(h, &ieee);
            rail::sl_rail_ieee802154_config_2p4_ghz_radio(h);
            rail::sl_rail_set_rx_transitions(h, &stay_rx);

            rail::sl_rail_util_pa_init();
            let tx_power_config = rail::sl_rail_tx_power_config_t {
                mode: rail::sl_rail_tx_power_mode_t_enum::SL_RAIL_TX_POWER_MODE_2P4_GHZ_HIGHEST
                    as rail::sl_rail_tx_power_mode_t,
                voltage_mv: 3300,  // SL_RAIL_UTIL_PA_VOLTAGE_MV
                ramp_time_us: 10,  // SL_RAIL_UTIL_PA_RAMP_TIME_US
            };
            rail::sl_rail_config_tx_power(h, &tx_power_config);

            rail::sl_rail_set_tx_fifo(
                h,
                core::ptr::addr_of_mut!(TX_FIFO) as *mut rail::sl_rail_fifo_buffer_align_t,
                (TX_FIFO_WORDS * 4) as u16,
                0,
                0,
            );

            rail::sl_rail_config_events(h, u64::MAX as _, self::events::SUBSCRIBED as _);

            // Enable the RAIL multi-timer so a board can build an embassy-time driver on it.
            rail::sl_rail_config_multi_timer(h, true);

            RAIL_HANDLE.store(h as usize, Ordering::Relaxed);
        }

        Self {
            state: Mutex::new(RadioState { config: None }),
            exclusive: Mutex::new(()),
        }
    }

    /// Drains received frames — kept for API symmetry with the ESP backend; RAIL already
    /// enqueues from the callback, so this is currently a no-op sink.
    pub async fn run_rx(&self) -> ! {
        core::future::pending().await
    }

    async fn transmit_inner(&self, frame: &TxFrame) -> Result<TxResult, RadioError> {
        let ack_requested = frame.psdu.first().is_some_and(|fcf| fcf & 0x20 != 0);
        let channel = u16::from(frame.channel.unwrap_or_else(|| CURRENT_CHANNEL.load(Ordering::Relaxed)));
        let mut tx_options: rail::sl_rail_tx_options_t = 0;
        if ack_requested {
            tx_options |= TX_OPTION_WAIT_FOR_ACK as rail::sl_rail_tx_options_t;
        }

        let mut attempt = 0u8;
        loop {
            let result = {
                let _state = self.state.lock().await;
                let h = handle();
                let phr: u8 = (frame.psdu.len() + 2) as u8; // PHY length includes the 2 FCS bytes
                let csma = csma_802154();
                TX_COMPLETE.reset();
                unsafe {
                    rail::sl_rail_write_tx_fifo(h, &phr, 1, true);
                    rail::sl_rail_write_tx_fifo(h, frame.psdu.as_ptr(), frame.psdu.len() as u16, false);
                    let status = rail::sl_rail_start_cca_csma_tx(
                        h,
                        channel,
                        tx_options,
                        &csma,
                        core::ptr::null(),
                    );
                    if status != 0 {
                        return Err(RadioError::Other(String::from("start_cca_csma_tx failed")));
                    }
                }
                // Hold the radio lock across the completion wait.
                TX_COMPLETE.wait().await
            };

            match result {
                TxResult::NoAck if attempt < frame.max_frame_retries => attempt += 1,
                other => return Ok(other),
            }
        }
    }
}

impl Default for Efr32Phy {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Efr32Rx(ChannelReceiver<'static, CriticalSectionRawMutex, RxFrame, RX_DEPTH>);

impl Receiver<RxFrame> for Efr32Rx {
    async fn recv(&mut self) -> Option<RxFrame> {
        Some(self.0.receive().await)
    }
}

pub struct Efr32ResetStream(ChannelReceiver<'static, CriticalSectionRawMutex, ResetEvent, 1>);

impl Receiver<ResetEvent> for Efr32ResetStream {
    async fn recv(&mut self) -> Option<ResetEvent> {
        Some(self.0.receive().await)
    }
}

pub struct Efr32Exclusive<'a> {
    phy: &'a Efr32Phy,
    _guard: MutexGuard<'a, CriticalSectionRawMutex, ()>,
}

impl ExclusiveRadio for Efr32Exclusive<'_> {
    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let state = self.phy.state.lock().await;
        CURRENT_CHANNEL.store(channel, Ordering::Relaxed);
        let h = handle();
        unsafe {
            if let Some(config) = state.config.as_ref() {
                rail::sl_rail_set_tx_power_dbm(h, rail::sl_rail_tx_power_t::from(config.tx_power) * 10);
            }
            let status = rail::sl_rail_start_rx(h, u16::from(channel), core::ptr::null());
            if status != 0 {
                return Err(RadioError::Other(String::from("start_rx failed")));
            }
        }
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.phy.transmit_inner(&frame).await
    }

    async fn set_promiscuous(&self, promiscuous: bool) -> Result<(), RadioError> {
        let _state = self.phy.state.lock().await;
        unsafe { rail::sl_rail_ieee802154_set_promiscuous_mode(handle(), promiscuous) };
        Ok(())
    }
}

impl RadioPhy for Efr32Phy {
    type Exclusive<'a> = Efr32Exclusive<'a>;
    type RxStream = Efr32Rx;
    type ResetStream = Efr32ResetStream;

    async fn reset(&self) -> Result<(), RadioError> {
        // No external RCP to reset; reconfigure re-applies all state. Synthesize the reset
        // notification the driver waits for.
        let _ = RESET_CHANNEL.try_send(ResetEvent {
            reason: String::from("rail ready"),
        });
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let mut state = self.state.lock().await;
        let h = handle();
        CURRENT_CHANNEL.store(config.channel, Ordering::Relaxed);
        unsafe {
            rail::sl_rail_ieee802154_set_pan_id(h, config.pan_id.0, 0);
            rail::sl_rail_ieee802154_set_short_address(h, config.short_address.as_u16(), 0);
            let ext = config.extended_address.to_bytes();
            rail::sl_rail_ieee802154_set_long_address(h, ext.as_ptr(), 0);
            rail::sl_rail_ieee802154_set_promiscuous_mode(h, config.promiscuous);
            rail::sl_rail_set_tx_power_dbm(h, rail::sl_rail_tx_power_t::from(config.tx_power) * 10);
            let status = rail::sl_rail_start_rx(h, u16::from(config.channel), core::ptr::null());
            if status != 0 {
                return Err(RadioError::Other(String::from("start_rx failed")));
            }
        }
        state.config = Some(config.clone());
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        _short: &[Nwk],
        _extended: &[Eui64],
    ) -> Result<(), RadioError> {
        // TODO: RAIL software source-match table (ot-efr32's soft_source_match_table.c) driving
        // sl_rail_ieee802154_{set_data_req_frame_pending, enable_data_frame_pending}.
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        // Wait behind any exclusive holder (e.g. a scan) so this can't retune mid-operation.
        let _exclusive = self.exclusive.lock().await;
        self.transmit_inner(&frame).await
    }

    async fn energy_detect(&self, _channel: u8, _duration: Duration) -> Result<i8, RadioError> {
        // TODO: real measurement via sl_rail_start_average_rssi over the dwell. For now return
        // 0 dBm; the driver's channel selection treats 0 as "no energy" and falls back to a
        // default channel, which is fine for bring-up (no TX / real scan needed yet).
        Ok(0)
    }

    async fn lock(&self) -> Efr32Exclusive<'_> {
        Efr32Exclusive {
            phy: self,
            _guard: self.exclusive.lock().await,
        }
    }

    fn subscribe_rx(&self) -> Efr32Rx {
        Efr32Rx(RX_CHANNEL.receiver())
    }

    fn subscribe_reset(&self) -> Efr32ResetStream {
        Efr32ResetStream(RESET_CHANNEL.receiver())
    }
}

// Compile-time proof that Efr32Phy satisfies the full RadioPhy contract, including the
// `Send + Sync + 'static` supertrait and the `+ Send` bound on every returned future.
const _: () = {
    fn assert_radiophy<T: RadioPhy>() {}
    let _ = assert_radiophy::<Efr32Phy>;
};
