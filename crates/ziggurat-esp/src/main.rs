//! ESP32-C6 firmware: runs the Ziggurat stack against the native 802.15.4 radio and
//! exposes the same line-delimited JSON API as the host server's `--api stdio` mode, over
//! the built-in USB-Serial-JTAG. One request per inbound line; one JSON object per
//! outbound line.

#![no_std]
#![no_main]

extern crate alloc;

mod api;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embedded_io_async::Read;
use embedded_io_async::Write;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::Async;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagTx};

use ziggurat_driver::rng;
use ziggurat_driver::runtime::EmbassySpawner;
use ziggurat_driver::zigbee_stack::ZigbeeStack;
use ziggurat_phy_esp::EspPhy;

esp_bootloader_esp_idf::esp_app_desc!();

/// Outbound JSON lines (responses, events, notifications) converge here and a single
/// writer task drains them to the serial port.
const OUTBOUND_DEPTH: usize = 16;
pub static OUTBOUND: Channel<CriticalSectionRawMutex, alloc::string::String, OUTBOUND_DEPTH> =
    Channel::new();

/// The firmware's mutable state, owned by (and only touched from) the reader loop.
pub struct App {
    pub phy: Arc<EspPhy>,
    pub spawner: EmbassySpawner,
    pub stack: Option<Arc<ZigbeeStack<EspPhy>>>,
}

/// Drain the radio's received frames; the stack reads them off the shared RX channel.
#[embassy_executor::task]
async fn rx_task(phy: Arc<EspPhy>) {
    phy.run_rx().await
}

/// The single serial writer: every outbound line goes through it, so concurrent
/// producers (request handlers and the notification drainer) never interleave on the bus.
#[embassy_executor::task]
async fn writer_task(mut tx: UsbSerialJtagTx<'static, Async>) {
    loop {
        let line = OUTBOUND.receive().await;
        let _ = tx.write_all(line.as_bytes()).await;
        let _ = tx.write_all(b"\n").await;
        let _ = tx.flush().await;
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    esp_alloc::heap_allocator!(size: 96 * 1024);

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
    let (mut serial_rx, serial_tx) = usb.split();

    let phy = Arc::new(EspPhy::new(peripherals.IEEE802154));

    spawner.spawn(rx_task(phy.clone()).unwrap());
    spawner.spawn(writer_task(serial_tx).unwrap());

    let mut app = App {
        phy,
        spawner: EmbassySpawner::new(spawner.make_send()),
        stack: None,
    };

    api::emit(api::hello_message(false)).await;

    // The reader loop: accumulate bytes into a line, dispatch on newline. `buf` is only
    // the per-read chunk; `line` grows without bound, so a full-network-state `configure`
    // line spanning many reads is reassembled whole.
    let mut buf = [0u8; 256];
    let mut line: Vec<u8> = Vec::with_capacity(2048);
    loop {
        let n = serial_rx.read(&mut buf).await.unwrap_or(0);
        for &byte in &buf[..n] {
            match byte {
                b'\n' => {
                    if !line.is_empty() {
                        api::handle_line(&mut app, &line).await;
                        line.clear();
                    }
                }
                b'\r' => {}
                _ => line.push(byte),
            }
        }
    }
}
