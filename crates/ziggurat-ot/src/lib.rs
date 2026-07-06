//! Ziggurat as a C staticlib embedded inside OpenThread RCP firmware.
//!
//! The firmware glue (see `include/ziggurat.h`) implements the `ziggurat_platform_*`
//! functions, calls `ziggurat_start` once, then `ziggurat_process` from the OpenThread
//! superloop whenever `ziggurat_platform_wake` requested it. Radio completions, timer
//! expiry, and host tunnel frames enter through the other `ziggurat_*` exports — all
//! from OpenThread's main-loop context, never an ISR.
//!
//! Everything above the FFI boundary is the same machinery as the standalone ESP
//! firmware: `ziggurat-driver` on the embassy runtime, the `ziggurat-ncp-api`
//! protocol, and a `RadioPhy` (here `ziggurat-phy-otlink` over `otLinkRaw*`).

#![no_std]

extern crate alloc;

// Provides the critical-section implementation (PRIMASK, single-core).
#[cfg(all(target_arch = "arm", target_os = "none"))]
use cortex_m as _;

mod crypto;
mod link_ops;
mod platform;
mod time_driver;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;

use ziggurat_driver::rng;
use ziggurat_driver::runtime::EmbassySpawner;
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_ncp_api::{self as api, App, Platform, OUTBOUND};
use ziggurat_phy::TxResult;
use ziggurat_phy_otlink::OtLinkPhy;

use link_ops::LINK_OPS;

/// Complete inbound request lines from the host tunnel.
const INBOUND_DEPTH: usize = 16;
static INBOUND: Channel<CriticalSectionRawMutex, Vec<u8>, INBOUND_DEPTH> = Channel::new();

/// NCP buffer space became available; retry a failed `ziggurat_platform_host_send`.
static HOST_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[cfg(target_os = "none")]
mod heap {
    use embedded_alloc::LlffHeap;

    #[global_allocator]
    static HEAP: LlffHeap = LlffHeap::empty();

    const HEAP_BYTES: usize = 64 * 1024;
    static mut ARENA: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

    pub fn init() {
        unsafe { HEAP.init(core::ptr::addr_of_mut!(ARENA) as usize, HEAP_BYTES) }
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;

    struct Buf {
        bytes: [u8; 256],
        len: usize,
    }
    impl Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.bytes.len() - self.len);
            self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }

    let mut buf = Buf {
        bytes: [0; 256],
        len: 0,
    };
    let _ = write!(buf, "{info}");
    unsafe { platform::ziggurat_platform_panic(buf.bytes.as_ptr(), buf.len) };
    loop {}
}

mod executor {
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicBool, Ordering};

    static mut EXECUTOR: MaybeUninit<embassy_executor::raw::Executor> = MaybeUninit::uninit();
    static PENDING: AtomicBool = AtomicBool::new(false);

    /// The custom pender embassy-executor requires when no arch feature is selected.
    /// Runs whenever a task is readied — possibly from within `poll` itself.
    #[unsafe(export_name = "__pender")]
    fn pender(_context: *mut ()) {
        PENDING.store(true, Ordering::Release);
        unsafe { crate::platform::ziggurat_platform_wake() };
    }

    pub fn init() -> embassy_executor::Spawner {
        unsafe {
            (*core::ptr::addr_of_mut!(EXECUTOR))
                .write(embassy_executor::raw::Executor::new(core::ptr::null_mut()));
            (*core::ptr::addr_of!(EXECUTOR)).assume_init_ref().spawner()
        }
    }

    /// Poll the executor if any task was readied since the last poll.
    pub fn process() {
        if PENDING.swap(false, Ordering::AcqRel) {
            unsafe { (*core::ptr::addr_of!(EXECUTOR)).assume_init_ref().poll() }
        }
    }
}

struct OtPlatform;

impl Platform for OtPlatform {
    fn hw_eui64(&self) -> Eui64 {
        let mut bytes = [0u8; 8];
        unsafe { platform::ziggurat_platform_hw_eui64(bytes.as_mut_ptr()) };
        Eui64(bytes)
    }

    fn hard_reset(&self) -> ! {
        unsafe { platform::ziggurat_platform_hard_reset() };
        loop {
            core::hint::spin_loop();
        }
    }

    fn rx_counters(&self) -> (usize, usize) {
        (
            ziggurat_phy_otlink::rx_total(),
            ziggurat_phy_otlink::rx_dropped(),
        )
    }
}

static PLATFORM: OtPlatform = OtPlatform;

#[embassy_executor::task]
async fn ziggurat_main(spawner: embassy_executor::SendSpawner) {
    let phy = Arc::new(OtLinkPhy::new(&LINK_OPS));

    let mut app = App {
        phy,
        spawner: EmbassySpawner::new(spawner),
        platform: &PLATFORM,
        stack: None,
        started: false,
        capture_stop: None,
    };

    api::emit_hello(false).await;

    let mut reset_info = [0u8; 512];
    let len = unsafe {
        platform::ziggurat_platform_last_reset(reset_info.as_mut_ptr(), reset_info.len())
    };
    if let Ok(message) = core::str::from_utf8(&reset_info[..len]) {
        if !message.is_empty() {
            api::emit_last_reset(message).await;
        }
    }

    loop {
        let frame = INBOUND.receive().await;
        api::handle_frame(&mut app, &frame).await;
    }
}

/// Drain outbound JSON lines into the host tunnel, honoring NCP-buffer backpressure.
#[embassy_executor::task]
async fn host_pump() {
    loop {
        let line = OUTBOUND.receive().await;
        loop {
            HOST_READY.reset();
            if unsafe { platform::ziggurat_platform_host_send(line.as_ptr(), line.len()) } {
                break;
            }
            HOST_READY.wait().await;
        }
    }
}

static STARTED: AtomicBool = AtomicBool::new(false);

/// Initialize and start the embedded stack. Called once, after OpenThread's instance
/// and the NCP exist — there is no stop; switching the firmware back to plain-RCP use
/// is an MCU reset. Idle until the first host frame arrives.
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_start() {
    assert!(!STARTED.swap(true, Ordering::AcqRel));

    #[cfg(target_os = "none")]
    heap::init();

    rng::install(Box::new(|buf: &mut [u8]| unsafe {
        platform::ziggurat_platform_entropy(buf.as_mut_ptr(), buf.len());
    }));
    crypto::init();

    let spawner = executor::init();
    let send_spawner = spawner.make_send();
    spawner.spawn(ziggurat_main(send_spawner).unwrap());
    spawner.spawn(host_pump().unwrap());
}

/// Poll the executor. Call from the superloop whenever `ziggurat_platform_wake` was
/// requested (extra calls are harmless).
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_process() {
    executor::process();
}

/// One inbound control-protocol frame from the host tunnel.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_host_frame(data: *const u8, len: usize) {
    let line = unsafe { core::slice::from_raw_parts(data, len) }.to_vec();
    let _ = INBOUND.try_send(line);
}

/// NCP buffer space became available (VendorHandleFrameRemovedFromNcpBuffer).
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_host_send_ready() {
    HOST_READY.signal(());
}

/// The one-shot timer armed via `ziggurat_platform_timer_arm` fired.
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_timer_fired() {
    time_driver::timer_fired();
}

/// A frame was received on Ziggurat's instance (PSDU without FCS).
///
/// # Safety
/// `psdu` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ziggurat_radio_rx(
    psdu: *const u8,
    len: usize,
    channel: u8,
    rssi: i8,
    lqi: u8,
    timestamp_us: u64,
) {
    let psdu = unsafe { core::slice::from_raw_parts(psdu, len) };
    ziggurat_phy_otlink::deliver_rx(psdu, channel, rssi, lqi, timestamp_us);
}

/// The in-flight transmit finished.
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_radio_tx_done(status: platform::ZigguratTxStatus) {
    let result = match status {
        platform::ZigguratTxStatus::Acked => TxResult::Acked,
        platform::ZigguratTxStatus::NoAck => TxResult::NoAck,
        platform::ZigguratTxStatus::ChannelAccessFailure => TxResult::ChannelAccessFailure,
        platform::ZigguratTxStatus::Aborted => TxResult::Aborted,
        platform::ZigguratTxStatus::Failed => TxResult::Failed,
    };
    ziggurat_phy_otlink::deliver_tx_result(result);
}

/// The energy scan finished with this peak RSSI.
#[unsafe(no_mangle)]
pub extern "C" fn ziggurat_radio_energy_scan_done(max_rssi_dbm: i8) {
    ziggurat_phy_otlink::deliver_energy_result(max_rssi_dbm);
}
