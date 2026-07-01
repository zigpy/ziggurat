//! ESP32-C6 firmware: runs the Ziggurat stack against the native 802.15.4 radio and
//! exposes the same line-delimited JSON API as the host server's `--api stdio` mode, over
//! the built-in USB-Serial-JTAG. One request per inbound line; one JSON object per
//! outbound line.

#![no_std]
#![no_main]

extern crate alloc;

mod api;
mod hw_crypto;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use embedded_io_async::Read;
use embedded_io_async::Write;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::Async;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, UartTx};
use esp_hal::usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};

use ziggurat_driver::rng;
use ziggurat_driver::runtime::EmbassySpawner;
use ziggurat_driver::zigbee_stack::ZigbeeStack;
use ziggurat_phy_esp::EspPhy;

esp_bootloader_esp_idf::esp_app_desc!();

/// Outbound JSON lines (responses, events, notifications) converge here and a single
/// writer task drains them to the serial port.
const OUTBOUND_DEPTH: usize = 256;
pub static OUTBOUND: Channel<CriticalSectionRawMutex, alloc::string::String, OUTBOUND_DEPTH> =
    Channel::new();

/// Complete inbound request lines, produced by `serial_reader_task` and consumed by the
/// processor loop in `main`. Decoupling the read from the (slower) handling keeps the
/// USB RX FIFO drained promptly: a burst of commands fills this queue instead of
/// stalling the FIFO.
const INBOUND_DEPTH: usize = 32;
static INBOUND: Channel<CriticalSectionRawMutex, Vec<u8>, INBOUND_DEPTH> = Channel::new();

/// Cancels the packet-capture task. Each capture gets a fresh one; `stop_packet_capture`
/// signals it so the task exits and frees the radio.
pub type CaptureStop = embassy_sync::signal::Signal<CriticalSectionRawMutex, ()>;

/// The firmware's mutable state, owned by (and only touched from) the processor loop.
pub struct App {
    pub phy: Arc<EspPhy>,
    pub spawner: EmbassySpawner,
    pub stack: Option<Arc<ZigbeeStack<EspPhy>>>,
    /// `Some` while a packet capture is streaming; signalling it stops the capture.
    pub capture_stop: Option<Arc<CaptureStop>>,
}

/// Drain the radio's received frames; the stack reads them off the shared RX channel.
#[embassy_executor::task]
async fn rx_task(phy: Arc<EspPhy>) {
    phy.run_rx().await
}

/// How often the reader re-checks the USB RX FIFO when no byte has arrived. Bounds the
/// recovery latency from a dropped esp-hal RX wakeup (see `serial_reader_task`).
const RX_WATCHDOG: Duration = Duration::from_millis(50);

/// Drains the USB-Serial-JTAG RX continuously, splitting on newlines and queueing each
/// complete line for the processor.
#[embassy_executor::task]
async fn serial_reader_task(mut rx: UsbSerialJtagRx<'static, Async>) {
    let mut buf = [0u8; 256];
    let mut line: Vec<u8> = Vec::with_capacity(2048);
    loop {
        let n = match select(rx.read(&mut buf), Timer::after(RX_WATCHDOG)).await {
            Either::First(result) => result.unwrap_or(0),
            Either::Second(()) => continue,
        };
        for &byte in &buf[..n] {
            match byte {
                b'\n' => {
                    if !line.is_empty() {
                        INBOUND.send(line.clone()).await;
                        line.clear();
                    }
                }
                b'\r' => {}
                _ => line.push(byte),
            }
        }
    }
}

/// How long the writer waits for the USB host to accept a line before giving up on it.
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

#[embassy_executor::task]
async fn serial_writer_task(mut tx: UsbSerialJtagTx<'static, Async>) {
    let mut resync = false;
    loop {
        let line = OUTBOUND.receive().await;
        let write = async {
            if resync {
                let _ = tx.write_all(b"\n").await;
            }
            let _ = tx.write_all(line.as_bytes()).await;
            let _ = tx.write_all(b"\n").await;
            let _ = tx.flush().await;
        };
        match select(write, Timer::after(WRITE_TIMEOUT)).await {
            Either::First(()) => resync = false,
            Either::Second(()) => {
                resync = true;
            }
        }
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // ~100-router network peaks at ~86 KB heap; ceiling is ~408 KB.
    esp_alloc::heap_allocator!(size: 320 * 1024);

    // Configure UART0 for debug logging
    let _debug_uart = UartTx::new(
        peripherals.UART0,
        UartConfig::default().with_baudrate(115200),
    )
    .expect("UART0 config")
    .with_tx(peripherals.GPIO16)
    .into_async();

    // Route Zigbee crypto through the AES accelerator: CCM* runs as two DMA passes
    // (CBC-MAC + CTR) and AES-MMO rides the single-block path. Must happen before the
    // stack processes any frames.
    hw_crypto::init(peripherals.AES, peripherals.DMA_CH0);

    // Install the randomness source the stack pulls jitter, addresses, and keys from. The
    // SoC RNG is true-random once the radio subsystem is up (it is, below).
    rng::install(Box::new(|buf: &mut [u8]| {
        let rng = Rng::new();
        for chunk in buf.chunks_mut(4) {
            let bytes = rng.random().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }));

    let usb = UsbSerialJtag::new(peripherals.USB_DEVICE).into_async();
    let (serial_rx, serial_tx) = usb.split();

    let phy = Arc::new(EspPhy::new(peripherals.IEEE802154));

    spawner.spawn(rx_task(phy.clone()).unwrap());
    spawner.spawn(serial_reader_task(serial_rx).unwrap());
    spawner.spawn(serial_writer_task(serial_tx).unwrap());

    let mut app = App {
        phy,
        spawner: EmbassySpawner::new(spawner.make_send()),
        stack: None,
        capture_stop: None,
    };

    api::emit(api::hello_message(false)).await;

    // The processor loop. `serial_reader_task` owns the RX side and keeps the FIFO
    // drained.
    loop {
        let line = INBOUND.receive().await;
        api::handle_line(&mut app, &line).await;
    }
}
