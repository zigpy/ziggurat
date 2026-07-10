//! The Ziggurat NCP control protocol: a binary request/response surface with
//! streamed events and unsolicited notifications, spoken over whatever transport
//! frames it (the Spinel vendor-property tunnel of the OpenThread-RCP-embedded
//! build, or a length-prefixed UART).
//!
//! Board specifics (hardware EUI-64, MCU reset, RX diagnostics) enter through
//! [`Platform`]; the transport drains [`OUTBOUND`] and feeds [`handle_frame`].

#![no_std]

extern crate alloc;

pub mod protocol;

use alloc::sync::Arc;
use alloc::vec::Vec;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use ziggurat_driver::runtime::EmbassySpawner;
use ziggurat_driver::zigbee_stack::ZigbeeStack;
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_phy::{RadioConfig, RadioPhy};

pub(crate) const DEFAULT_TX_POWER: i8 = 8;

/// Outbound protocol frames converge here; the transport drains them.
const OUTBOUND_DEPTH: usize = 64;
pub static OUTBOUND: Channel<CriticalSectionRawMutex, Vec<u8>, OUTBOUND_DEPTH> = Channel::new();

/// Cancels an in-progress packet capture (see the `reset` command).
pub type CaptureStop = embassy_sync::signal::Signal<CriticalSectionRawMutex, ()>;

/// Board specifics the protocol surface needs but the transport-agnostic core can't know.
pub trait Platform: Send + Sync {
    /// The factory-programmed EUI-64, used as the coordinator IEEE address.
    fn hw_eui64(&self) -> Eui64;

    /// Reboot the MCU (the hard `reset` request). Divergent: the transport drops
    /// and the client reconnects.
    fn hard_reset(&self) -> !;

    /// RX diagnostics: (total frames, frames dropped on a full queue) since boot.
    fn rx_counters(&self) -> (usize, usize) {
        (0, 0)
    }
}

/// Firmware state, owned by the processor loop.
pub struct App<P: RadioPhy> {
    pub phy: Arc<P>,
    pub spawner: EmbassySpawner,
    pub platform: &'static dyn Platform,
    pub stack: Option<Arc<ZigbeeStack<P>>>,
    /// Whether the configured stack has been started (`configure` -> `load_*` ->
    /// `start_network` are separate phases).
    pub started: bool,
    pub capture_stop: Option<Arc<CaptureStop>>,
}

/// Queue one encoded frame, dropping the oldest queued frame when full. For
/// real-time traffic that must never block the stack; state-transfer streams use
/// [`send_outbound`] instead.
pub(crate) fn push_outbound(mut frame: Vec<u8>) {
    loop {
        match OUTBOUND.try_send(frame) {
            Ok(()) => break,
            Err(embassy_sync::channel::TrySendError::Full(returned)) => {
                frame = returned;
                let _ = OUTBOUND.try_receive();
            }
        }
    }
}

/// Queue one encoded frame, suspending until there is room. Lossless; used by
/// table scans, which iterate snapshots and can afford to wait for a slow host.
pub(crate) async fn send_outbound(frame: Vec<u8>) {
    OUTBOUND.send(frame).await;
}

/// The unsolicited hello, sent once at startup.
pub async fn emit_hello(configured: bool) {
    let frame = protocol::Notification::Hello(protocol::HelloPayload {
        protocol_version: protocol::PROTOCOL_VERSION,
        configured,
    })
    .frame();
    if let Some(frame) = frame {
        push_outbound(frame);
    }
}

/// The unsolicited last-reset diagnostic, sent once after `hello` when the
/// previous reset was abnormal (a fault or a panic). The message is truncated so
/// the frame always fits.
pub async fn emit_last_reset(message: &str) {
    let message = &message.as_bytes()[..message.len().min(255)];
    let frame = protocol::Notification::LastReset(protocol::LastResetPayload {
        message: message.to_vec(),
    })
    .frame();
    if let Some(frame) = frame {
        push_outbound(frame);
    }
}

/// Dispatch one inbound protocol frame.
pub async fn handle_frame<P: RadioPhy>(app: &mut App<P>, frame: &[u8]) {
    protocol::handle_frame(app, frame).await;
}

/// Start the receive loop and the notification pump for a freshly-started stack.
pub(crate) fn spawn_stack_pumps<P: RadioPhy>(stack: &Arc<ZigbeeStack<P>>) {
    let run_stack = stack.clone();
    stack.spawn_tracked(async move {
        run_stack.run().await;
    });

    let notify_stack = stack.clone();
    stack.spawn_tracked(async move {
        loop {
            for notification in notify_stack.next_notifications().await {
                if let Some(frame) = protocol::notification_frame(&notification) {
                    push_outbound(frame);
                }
            }
        }
    });
}

/// Radio programming for promiscuous capture: receive every frame on `channel`, no
/// PAN/address filtering, no network required. Dummy addresses since nothing is
/// addressed to us.
pub(crate) const fn capture_config(channel: u8) -> RadioConfig {
    RadioConfig {
        channel,
        tx_power: DEFAULT_TX_POWER,
        short_address: Nwk(0xFFFF),
        extended_address: Eui64([0; 8]),
        pan_id: PanId(0xFFFF),
        promiscuous: true,
        rx_on_when_idle: true,
        frame_pending_short: Vec::new(),
        frame_pending_extended: Vec::new(),
    }
}
