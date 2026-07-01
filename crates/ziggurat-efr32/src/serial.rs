//! Bidirectional EUSART0 for the JSON API (VCOM: TX PA05, RX PA06, 460800 8N1).
//!
//! Split into [`SerialTx`] (blocking writes) and [`SerialRx`] (async reads that poll the RX
//! FIFO, yielding to the executor between bytes) so the reader and writer can run as separate
//! embassy tasks. RX is poll-based, which is fine for the low, bursty command traffic of
//! network formation; an interrupt-driven RX is a later refinement.

use ziggurat_efr32_pac::{CmuS, Eusart0S, GpioS};

const REF_HZ: u32 = 20_000_000; // FSRCO clocking EM01GRPCCLK -> EUSART0
const BAUD: u32 = 115_200;
const OVS: u32 = 16;
// Rounded (not truncated) fractional divider: at 460800 truncation gives ~0.9% baud error,
// rounding ~0.2%, which the VCOM tolerates.
const CLKDIV: u32 = ((32 * REF_HZ) + (BAUD * OVS) / 2) / (BAUD * OVS) - 32;

fn eusart() -> &'static ziggurat_efr32_pac::eusart0_s::RegisterBlock {
    unsafe { &*Eusart0S::ptr() }
}

/// Configure EUSART0 for bidirectional VCOM and return the split handles.
pub fn init(cmu: &CmuS, gpio: &GpioS, _eusart: Eusart0S) -> (SerialTx, SerialRx) {
    cmu.clken0().modify(|_, w| w.gpio().set_bit());
    cmu.clken1().modify(|_, w| w.eusart0().set_bit());
    cmu.em01grpcclkctrl().write(|w| w.clksel().fsrco());
    cmu.eusart0clkctrl().write(|w| w.clksel().em01grpcclk());

    // PA05 = TX (push-pull output), PA06 = RX (input).
    gpio.porta_model()
        .modify(|_, w| w.mode5().pushpull().mode6().input());
    gpio.eusart0_txroute()
        .write(|w| unsafe { w.port().bits(0).pin().bits(5) });
    gpio.eusart0_rxroute()
        .write(|w| unsafe { w.port().bits(0).pin().bits(6) });
    gpio.eusart0_routeen()
        .write(|w| w.txpen().set_bit().rxpen().set_bit());

    let e = eusart();
    e.framecfg()
        .write(|w| w.databits().eight().stopbits().one().parity().none());
    e.clkdiv().write(|w| unsafe { w.div().bits(CLKDIV) });
    e.en().write(|w| w.en().set_bit());
    e.cmd().write(|w| w.txen().set_bit().rxen().set_bit());

    (SerialTx, SerialRx)
}

pub struct SerialTx;

impl SerialTx {
    pub fn write_all(&mut self, bytes: &[u8]) {
        let e = eusart();
        for &byte in bytes {
            while e.status().read().txfl().bit_is_clear() {}
            e.txdata().write(|w| unsafe { w.txdata().bits(u16::from(byte)) });
        }
    }
}

pub struct SerialRx;

impl SerialRx {
    fn try_read(&self) -> Option<u8> {
        let e = eusart();
        if e.status().read().rxfl().bit_is_set() {
            Some(e.rxdata().read().rxdata().bits() as u8)
        } else {
            None
        }
    }

    /// Await the next received byte, polling the RX FIFO and yielding between checks.
    pub async fn read_byte(&mut self) -> u8 {
        loop {
            if let Some(byte) = self.try_read() {
                return byte;
            }
            embassy_futures::yield_now().await;
        }
    }
}
