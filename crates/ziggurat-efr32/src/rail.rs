//! Minimal receive-only 802.15.4 bring-up on the EFR32MG24, driving the RAIL blob
//! directly through the modern `sl_rail_*` API (see `ot-efr32/src/src/radio.c` for the
//! full reference). This is a sniffer: promiscuous, no auto-ack, accept all frame types.
//!
//! RAIL is interrupt-driven — the radio ISRs (FRC/MODEM/RAC/PROTIMER/SYNTH/AGC/BUFC/RFECA)
//! advance the state machine and fill the packet queue, then invoke [`rail_events_callback`]
//! from IRQ context. The callback copies the frame into a static slot; the main loop polls
//! [`take_packet`].

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use ziggurat_rail_sys as rail;

// ---------------------------------------------------------------------------
// Radio interrupt trampolines.
//
// The RAIL blob defines the radio ISRs as `<PERIPH>_IRQHandler`, but the PAC vector table
// names those slots `<PERIPH>` (we injected the SVD-redacted radio IRQs in the PAC build).
// Each `#[no_mangle]` fn below is a strong symbol overriding the weak `PROVIDE(<PERIPH> =
// DefaultHandler)` from device.x, forwarding to the blob's handler.
// ---------------------------------------------------------------------------
macro_rules! radio_irq {
    ($($vector:ident => $handler:ident,)*) => {
        extern "C" { $(fn $handler();)* }
        $(
            #[no_mangle]
            extern "C" fn $vector() { unsafe { $handler() } }
        )*
    };
}

radio_irq! {
    AGC => AGC_IRQHandler,
    BUFC => BUFC_IRQHandler,
    FRC => FRC_IRQHandler,
    FRC_PRI => FRC_PRI_IRQHandler,
    MODEM => MODEM_IRQHandler,
    PROTIMER => PROTIMER_IRQHandler,
    RAC_RSM => RAC_RSM_IRQHandler,
    RAC_SEQ => RAC_SEQ_IRQHandler,
    SYNTH => SYNTH_IRQHandler,
    RFECA0 => RFECA0_IRQHandler,
    RFECA1 => RFECA1_IRQHandler,
}

// ---------------------------------------------------------------------------
// Constants that bindgen skips (cast / shift macros).
// ---------------------------------------------------------------------------
const EFR32_HANDLE: rail::sl_rail_handle_t = 0xFFFF_FFFF as rail::sl_rail_handle_t;
const RX_PACKET_HANDLE_NEWEST: rail::sl_rail_rx_packet_handle_t = 3 as rail::sl_rail_rx_packet_handle_t;
const EVENT_RX_PACKET_RECEIVED: u64 =
    1 << (rail::sl_rail_events_t_enum::SL_RAIL_EVENT_RX_PACKET_RECEIVED_SHIFT as u64);

const RX_SLOT_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// IRQ <-> main-loop handoff: one-packet slot guarded by a ready flag.
// ---------------------------------------------------------------------------
static RX_READY: AtomicBool = AtomicBool::new(false);
static RX_LEN: AtomicU16 = AtomicU16::new(0);
static mut RX_SLOT: [u8; RX_SLOT_BYTES] = [0; RX_SLOT_BYTES];

/// RAIL event callback, invoked from radio IRQ context. On a completed RX packet, copy it
/// into the slot (dropping it if the previous one hasn't been consumed yet).
unsafe extern "C" fn rail_events_callback(rail_handle: rail::sl_rail_handle_t, events: rail::sl_rail_events_t) {
    if (events as u64) & EVENT_RX_PACKET_RECEIVED == 0 {
        return;
    }
    if RX_READY.load(Ordering::Acquire) {
        return; // previous packet still pending; drop this one
    }

    let mut info: rail::sl_rail_rx_packet_info_t = core::mem::zeroed();
    rail::sl_rail_get_rx_packet_info(rail_handle, RX_PACKET_HANDLE_NEWEST, &mut info);
    if info.packet_bytes == 0 {
        return;
    }

    let len = core::cmp::min(info.packet_bytes as usize, RX_SLOT_BYTES);
    // The packet is auto-released when this callback returns, so copy it out now.
    rail::sl_rail_copy_rx_packet(rail_handle, core::ptr::addr_of_mut!(RX_SLOT) as *mut u8, &info);
    RX_LEN.store(len as u16, Ordering::Relaxed);
    RX_READY.store(true, Ordering::Release);
}

/// If a received frame is pending, copy it into `dest` and return its length.
pub fn take_packet(dest: &mut [u8]) -> Option<usize> {
    if !RX_READY.load(Ordering::Acquire) {
        return None;
    }
    let len = RX_LEN.load(Ordering::Relaxed) as usize;
    let n = core::cmp::min(len, dest.len());
    // Safe: RX_READY is set, so the IRQ will not touch RX_SLOT until we clear it.
    unsafe {
        dest[..n].copy_from_slice(&core::ptr::addr_of!(RX_SLOT).as_ref().unwrap()[..n]);
    }
    RX_READY.store(false, Ordering::Release);
    Some(len)
}

/// Bring up the clock tree (HFXO the safe way) via the SDK's clock manager. Returns the
/// two `sl_status_t` values for diagnostics.
pub fn init_clocks() -> (u32, u32) {
    unsafe {
        let init = rail::sl_clock_manager_init();
        let runtime = rail::sl_clock_manager_runtime_init();
        (init as u32, runtime as u32)
    }
}

pub struct Radio {
    handle: rail::sl_rail_handle_t,
}

impl Radio {
    /// Initialize RAIL and configure the 2.4 GHz 802.15.4 PHY for promiscuous RX.
    pub fn new() -> Self {
        unsafe {
            let mut config: rail::sl_rail_config_t = core::mem::zeroed();
            config.events_callback = Some(rail_events_callback);
            config.rx_packet_queue_entries = rail::sl_rail_builtin_rx_packet_queue_entries;
            config.p_rx_packet_queue = rail::sl_rail_builtin_rx_packet_queue_ptr;
            config.rx_fifo_bytes = rail::sl_rail_builtin_rx_fifo_bytes;
            config.p_rx_fifo_buffer = rail::sl_rail_builtin_rx_fifo_ptr;

            let mut handle: rail::sl_rail_handle_t = EFR32_HANDLE;
            rail::sl_rail_init(&mut handle, &config, None);
            rail::sl_rail_config_cal(handle, rail::SL_RAIL_CAL_ALL as _);

            let mut ieee: rail::sl_rail_ieee802154_config_t = core::mem::zeroed();
            ieee.frames_mask = (rail::SL_RAIL_IEEE802154_ACCEPT_STANDARD_FRAMES
                | rail::SL_RAIL_IEEE802154_ACCEPT_ACK_FRAMES) as u8;
            ieee.promiscuous_mode = true;
            ieee.timings.idle_to_rx = 100;
            ieee.timings.tx_to_rx = 182;
            ieee.timings.idle_to_tx = 100;
            ieee.timings.rx_to_tx = 192;
            rail::sl_rail_ieee802154_init(handle, &ieee);
            rail::sl_rail_ieee802154_config_2p4_ghz_radio(handle);

            rail::sl_rail_config_events(handle, u64::MAX as _, EVENT_RX_PACKET_RECEIVED as _);

            Radio { handle }
        }
    }

    /// Start continuous receive on the given 802.15.4 channel (11-26).
    pub fn start_rx(&self, channel: u16) -> u32 {
        unsafe { rail::sl_rail_start_rx(self.handle, channel, core::ptr::null()) as u32 }
    }
}
