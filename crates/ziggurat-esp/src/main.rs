//! ESP32-C6 firmware: hardware bring-up only, no control API.

#![no_std]
#![no_main]

extern crate alloc;

mod hw_crypto;

use alloc::boxed::Box;
use alloc::sync::Arc;

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, UartTx};

use ziggurat_driver::rng;
use ziggurat_phy_esp::EspPhy;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) -> ! {
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
    // (CBC-MAC + CTR) and AES-MMO rides the single-block path.
    hw_crypto::init(peripherals.AES, peripherals.DMA_CH0);

    // Install the randomness source the stack pulls jitter, addresses, and keys from. The
    // SoC RNG is true-random once the radio subsystem is up.
    rng::install(Box::new(|buf: &mut [u8]| {
        let rng = Rng::new();
        for chunk in buf.chunks_mut(4) {
            let bytes = rng.random().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }));

    let _phy = Arc::new(EspPhy::new(peripherals.IEEE802154));

    panic!("Flash the OpenThread RCP build (firmwares/esp32-c6), this code will be removed");
}
